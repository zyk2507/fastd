// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Socket handling
*/

#include "fastd.h"
#include "hole_punch.h"
#include "nat_detect.h"
#include "peer.h"
#include "peer_group.h"
#include "polling.h"

#include <netinet/tcp.h>


#define TCP_LISTEN_BACKLOG 128
#define TCP_MAX_CONNECTIONS 1024
#define TCP_MAX_OUTPUT_QUEUE (1024 * 1024)
#define TCP_FRAME_HEADER 4

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif


static void set_bound_address(fastd_socket_t *sock);
static bool tcp_queue(fastd_socket_t *sock, fastd_peer_t *peer, const fastd_buffer_t *buffer, size_t stat_size);


/** Defers freeing a closed dynamic socket until the current poll batch has drained */
static void defer_socket_free(fastd_socket_t *sock) {
	if (!sock || sock->deferred_free)
		return;

	sock->deferred_free = true;
	sock->fd.type = POLL_TYPE_UNSPEC;
	VECTOR_ADD(ctx.deferred_socks, sock);
}

/** Frees a dynamic socket after the current poll batch has drained */
void fastd_socket_free_dynamic(fastd_socket_t *sock) {
	if (!sock)
		return;

	if (sock->type == SOCKET_TYPE_TCP_CONNECTION && sock->tcp_handling) {
		sock->tcp_closed = true;
		return;
	}

	defer_socket_free(sock);
}

/** Frees dynamic sockets whose file descriptors have already been closed */
void fastd_socket_free_deferred(void) {
	while (VECTOR_LEN(ctx.deferred_socks)) {
		fastd_socket_t *sock = VECTOR_INDEX(ctx.deferred_socks, VECTOR_LEN(ctx.deferred_socks) - 1);
		VECTOR_DELETE(ctx.deferred_socks, VECTOR_LEN(ctx.deferred_socks) - 1);
		free(sock);
	}
}


/** Returns true if a transport mode may use TCP */
static inline bool transport_uses_tcp(fastd_peer_transport_t transport) {
	return transport == TRANSPORT_TCP || transport == TRANSPORT_AUTO;
}

/** Returns true if a peer group or one of its children explicitly enables TCP-capable transport */
static bool group_tree_uses_tcp(const fastd_peer_group_t *group) {
	if (transport_uses_tcp(fastd_peer_group_get_transport(group)))
		return true;

	const fastd_peer_group_t *child;
	for (child = group->children; child; child = child->next) {
		if (group_tree_uses_tcp(child))
			return true;
	}

	return false;
}

/** Returns true if the current configuration needs TCP listeners */
static bool tcp_listeners_required(void) {
	if (group_tree_uses_tcp(conf.peer_group))
		return true;

	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
		if (transport_uses_tcp(fastd_peer_get_transport(VECTOR_INDEX(ctx.peers, i))))
			return true;
	}

	return false;
}


/** Returns the sockaddr length for a peer address */
static inline socklen_t address_len(const fastd_peer_address_t *addr) {
	switch (addr->sa.sa_family) {
	case AF_INET:
		return sizeof(struct sockaddr_in);

	case AF_INET6:
		return sizeof(struct sockaddr_in6);

	default:
		exit_bug("invalid address family");
	}
}

/** Sets common TCP socket options */
static void set_tcp_options(int fd) {
	const int one = 1;

	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)))
		pr_warn_errno("setsockopt: unable to set TCP_NODELAY");

	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one)))
		pr_warn_errno("setsockopt: unable to set SO_KEEPALIVE");
}

/** Removes a TCP connection from the global connection list */
static void tcp_connection_unlink(fastd_socket_t *sock) {
	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.tcp_socks); i++) {
		if (VECTOR_INDEX(ctx.tcp_socks, i) == sock) {
			VECTOR_DELETE(ctx.tcp_socks, i);
			return;
		}
	}
}

/** Frees queued TCP output frames */
static void tcp_free_output(fastd_socket_t *sock) {
	while (sock->tcp_output_head) {
		fastd_tcp_frame_t *next = sock->tcp_output_head->next;
		free(sock->tcp_output_head);
		sock->tcp_output_head = next;
	}

	sock->tcp_output_tail = NULL;
	sock->tcp_output_len = 0;
}

/** Frees a dynamically allocated socket if no handler is currently using it */
static void free_dynamic_socket(fastd_socket_t *sock) {
	if (sock->tcp_handling) {
		sock->tcp_closed = true;
		return;
	}

	fastd_socket_free_dynamic(sock);
}

/** Closes a TCP connection and optionally resets its peer */
static void close_tcp_connection(fastd_socket_t *sock, bool reset_peer) {
	if (sock->type != SOCKET_TYPE_TCP_CONNECTION)
		exit_bug("close_tcp_connection called for non-TCP connection");

	fastd_peer_t *peer = sock->peer;
	if (peer && peer->sock == sock) {
		bool established = fastd_peer_is_established(peer);

		peer->sock = NULL;
		sock->peer = NULL;

		if (reset_peer && established) {
			if (!fastd_peer_handle_tcp_connection_lost(peer))
				fastd_peer_reset(peer);
		} else if (reset_peer) {
			fastd_peer_transport_failed(peer, TRANSPORT_TCP);
		}
	} else if (peer && peer->backup_sock == sock) {
		sock->peer = NULL;
		peer->backup_sock = NULL;
		conf.protocol->drop_backup_path(peer);
	}

	fastd_socket_close(sock);
	free_dynamic_socket(sock);
}

/** Sets the port of an address from host byte order */
static void set_address_port(fastd_peer_address_t *addr, uint16_t port) {
	switch (addr->sa.sa_family) {
	case AF_INET:
		addr->in.sin_port = htons(port);
		return;

	case AF_INET6:
		addr->in6.sin6_port = htons(port);
		return;

	default:
		exit_bug("set_address_port: invalid address family");
	}
}

/** Returns the default UDP socket matching an address family */
static const fastd_socket_t *get_default_socket(int af) {
	switch (af) {
	case AF_INET:
		return ctx.sock_default_v4;

	case AF_INET6:
		return ctx.sock_default_v6;

	default:
		return NULL;
	}
}

/** Removes a UDP hole punching socket from the global list */
static void udp_punch_unlink(fastd_socket_t *sock) {
	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.udp_punch_socks); i++) {
		if (VECTOR_INDEX(ctx.udp_punch_socks, i) == sock) {
			VECTOR_DELETE(ctx.udp_punch_socks, i);
			return;
		}
	}
}

/** Returns true if a UDP punch socket is an active reusable public listener */
static bool udp_punch_public_listener_available(const fastd_socket_t *sock) {
	return sock && sock->type == SOCKET_TYPE_UDP && sock->hole_punch && sock->punch_public_listener &&
	       sock->hole_punch_timeout != FASTD_TIMEOUT_INV && !fastd_timed_out(sock->hole_punch_timeout) &&
	       (sock->punch_listener_public_addr.sa.sa_family == AF_INET ||
		sock->punch_listener_public_addr.sa.sa_family == AF_INET6);
}

/** Counts reusable public punch listeners */
static size_t udp_punch_public_listener_count(void) {
	size_t count = 0;
	size_t i;

	for (i = 0; i < VECTOR_LEN(ctx.udp_punch_socks); i++) {
		if (udp_punch_public_listener_available(VECTOR_INDEX(ctx.udp_punch_socks, i)))
			count++;
	}

	return count;
}

/** Returns true if a public listener selection should try opening another listener */
static bool udp_punch_should_create_public_listener(
	size_t current_listener_count, bool has_reusable_listener, bool has_port_mapping_listener, bool force_new,
	bool prefer_port_mapping) {
	if (current_listener_count >= DEFAULT_PUNCH_PUBLIC_LISTENERS)
		return false;
	if (!current_listener_count)
		return true;
	if (force_new)
		return true;
	if (prefer_port_mapping && !has_port_mapping_listener)
		return true;

	return !has_reusable_listener;
}

/** Counts active per-peer UDP punch sockets, excluding reusable public listeners */
static size_t udp_punch_active_socket_count(void) {
	size_t count = 0;
	size_t i;

	for (i = 0; i < VECTOR_LEN(ctx.udp_punch_socks); i++) {
		const fastd_socket_t *sock = VECTOR_INDEX(ctx.udp_punch_socks, i);
		if (!sock || sock->punch_public_listener)
			continue;
		if (sock->type == SOCKET_TYPE_UDP && sock->hole_punch &&
		    sock->hole_punch_timeout != FASTD_TIMEOUT_INV && !fastd_timed_out(sock->hole_punch_timeout))
			count++;
	}

	return count;
}

/** Returns the next non-zero public punch listener ID */
static uint32_t next_udp_punch_public_listener_id(void) {
	ctx.next_punch_listener_id++;
	if (!ctx.next_punch_listener_id)
		ctx.next_punch_listener_id++;

	return ctx.next_punch_listener_id;
}

/** Updates a public punch listener's endpoint when a dynamic port mapping has become available */
static void refresh_udp_punch_public_listener_mapping(fastd_socket_t *sock) {
	if (!sock || sock->type != SOCKET_TYPE_UDP || !sock->punch_public_listener || !sock->bound_addr)
		return;

	if (!sock->punch_listener_mapping_registered)
		fastd_port_mapping_register_socket(sock);

	if (!sock->punch_listener_mapping_registered || sock->punch_listener_port_mapped)
		return;

	fastd_peer_address_t mapped = {};
	if (!fastd_port_mapping_get_external_address(sock, &mapped))
		return;

	if (mapped.sa.sa_family != AF_INET)
		return;

	sock->punch_listener_public_addr = mapped;
	sock->punch_listener_port_mapped = true;
	pr_debug("public UDP punch listener switched to port-mapped endpoint %I", &mapped);
}

/** Closes and frees an unclaimed UDP hole punching socket */
static void close_udp_punch_socket(fastd_socket_t *sock) {
	if (sock->type != SOCKET_TYPE_UDP || !sock->hole_punch)
		exit_bug("close_udp_punch_socket called for non-UDP-punch socket");

	udp_punch_unlink(sock);
	fastd_socket_close(sock);
	defer_socket_free(sock);
}

/** Marks a hole punching socket as claimed by an authenticated peer */
void fastd_hole_punch_claim_socket(fastd_socket_t *sock) {
	if (!sock || !sock->hole_punch)
		return;

	if (sock->type == SOCKET_TYPE_UDP)
		udp_punch_unlink(sock);

	sock->hole_punch_peer = NULL;
	sock->hole_punch_timeout = FASTD_TIMEOUT_INV;
	sock->punch_public_listener = false;
	sock->punch_listener_port_mapped = false;
	sock->punch_listener_id = 0;
	sock->punch_listener_selected = 0;
	sock->punch_listener_public_addr.sa.sa_family = AF_UNSPEC;
}

/** Closes all unclaimed hole punching sockets for a peer */
void fastd_hole_punch_close_peer(fastd_peer_t *peer) {
	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.tcp_socks);) {
		fastd_socket_t *sock = VECTOR_INDEX(ctx.tcp_socks, i);

		if (sock->hole_punch_peer != peer) {
			i++;
			continue;
		}

		close_tcp_connection(sock, false);
	}

	for (i = 0; i < VECTOR_LEN(ctx.udp_punch_socks);) {
		fastd_socket_t *sock = VECTOR_INDEX(ctx.udp_punch_socks, i);

		if (sock->hole_punch_peer != peer) {
			i++;
			continue;
		}

		close_udp_punch_socket(sock);
	}
}

/** Returns an existing TCP hole punch socket for a peer and remote candidate */
static fastd_socket_t *find_tcp_hole_punch_socket(fastd_peer_t *peer, const fastd_peer_address_t *remote_addr) {
	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.tcp_socks); i++) {
		fastd_socket_t *sock = VECTOR_INDEX(ctx.tcp_socks, i);

		if (sock->hole_punch_peer == peer && fastd_peer_address_equal(&sock->peer_addr, remote_addr))
			return sock;
	}

	return NULL;
}

/** Opens a TCP socket for active TCP hole punching */
static fastd_socket_t *open_tcp_hole_punch_socket(fastd_peer_t *peer, const fastd_peer_address_t *remote_addr) {
	if (VECTOR_LEN(ctx.tcp_socks) >= TCP_MAX_CONNECTIONS) {
		pr_debug(
			"not opening TCP hole punch connection for %P because the connection limit has been reached",
			peer);
		return NULL;
	}

	const fastd_socket_t *base_sock = get_default_socket(remote_addr->sa.sa_family);

	int fd = socket(
		remote_addr->sa.sa_family == AF_INET6 ? PF_INET6 : PF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
	if (fd < 0) {
		pr_debug_errno("unable to create TCP hole punch socket");
		return NULL;
	}

#ifdef NO_HAVE_SOCK_NONBLOCK
	fastd_setnonblock(fd);
#endif

	const int one = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)))
		pr_debug_errno("setsockopt: unable to set SO_REUSEADDR on TCP hole punch socket");

#ifdef SO_REUSEPORT
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)))
		pr_debug_errno("setsockopt: unable to set SO_REUSEPORT on TCP hole punch socket");
#endif

	set_tcp_options(fd);

#ifdef USE_BINDTODEVICE
	if (base_sock && base_sock->addr && base_sock->addr->bindtodev &&
	    !fastd_peer_address_is_v6_ll(&base_sock->addr->addr)) {
		if (setsockopt(
			    fd, SOL_SOCKET, SO_BINDTODEVICE, base_sock->addr->bindtodev,
			    strlen(base_sock->addr->bindtodev))) {
			pr_debug_errno("setsockopt: unable to bind TCP hole punch socket to device");
			goto error;
		}
	}
#endif

#ifdef USE_PACKET_MARK
	if (conf.packet_mark) {
		if (setsockopt(fd, SOL_SOCKET, SO_MARK, &conf.packet_mark, sizeof(conf.packet_mark))) {
			pr_debug_errno("setsockopt: unable to set packet mark on TCP hole punch socket");
			goto error;
		}
	}
#endif

	fastd_peer_address_t local_addr = { .sa.sa_family = remote_addr->sa.sa_family };
	if (base_sock && base_sock->bound_addr && base_sock->bound_addr->sa.sa_family == remote_addr->sa.sa_family)
		local_addr = *base_sock->bound_addr;

	set_address_port(&local_addr, ntohs(fastd_peer_address_get_port(remote_addr)));

	if (bind(fd, &local_addr.sa, address_len(&local_addr))) {
		pr_debug2_errno("unable to bind TCP hole punch socket");
		goto error;
	}

#ifdef __ANDROID__
	if (!fastd_android_protect_socket(fd)) {
		pr_error("error protecting TCP hole punch socket");
		goto error;
	}
#endif

	int ret = connect(fd, &remote_addr->sa, address_len(remote_addr));
	if (ret < 0 && errno != EINPROGRESS && errno != EALREADY) {
		pr_debug_errno("TCP hole punch connect");
		goto error;
	}

	fastd_socket_t *sock = fastd_new0(fastd_socket_t);
	sock->fd = FASTD_POLL_FD(POLL_TYPE_SOCKET, fd);
	sock->type = SOCKET_TYPE_TCP_CONNECTION;
	sock->addr = base_sock ? base_sock->addr : NULL;
	sock->peer_addr = *remote_addr;
	sock->hole_punch_peer = peer;
	sock->hole_punch = true;
	sock->tcp_connecting = (ret < 0);
	sock->tcp_timeout = ctx.now + FASTD_HOLE_PUNCH_TIMEOUT;
	set_bound_address(sock);

	VECTOR_ADD(ctx.tcp_socks, sock);
	fastd_poll_fd_register(&sock->fd);
	fastd_poll_fd_set_write(&sock->fd, true);

	pr_debug("opening TCP hole punch connection to %P[%I]", peer, remote_addr);
	return sock;

error:
	if (close(fd))
		pr_error_errno("close");
	return NULL;
}


/**
   Creates a new socket bound to a specific address

   \return The new socket's file descriptor
*/
static int bind_socket(const fastd_bind_address_t *addr, bool reuseaddr_early, bool quiet) {
	int fd = -1;
	int af = AF_UNSPEC;

	if (addr->addr.sa.sa_family != AF_INET) {
		fd = socket(PF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
		if (fd >= 0) {
			af = AF_INET6;

			int val = (addr->addr.sa.sa_family == AF_INET6);
			if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val))) {
				pr_warn_errno("setsockopt");
				goto error;
			}
		}
	}
	if (fd < 0 && addr->addr.sa.sa_family != AF_INET6) {
		fd = socket(PF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
		if (fd < 0)
			exit_errno("unable to create socket");
		else
			af = AF_INET;
	}

	if (fd < 0)
		goto error;

#ifdef NO_HAVE_SOCK_NONBLOCK
	fastd_setnonblock(fd);
#endif

	const int one = 1;

#ifdef USE_PKTINFO
	if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one))) {
		pr_error_errno("setsockopt: unable to set IP_PKTINFO");
		goto error;
	}
#endif

#ifdef USE_FREEBIND
	if (setsockopt(fd, IPPROTO_IP, IP_FREEBIND, &one, sizeof(one)))
		pr_warn_errno("setsockopt: unable to set IP_FREEBIND");
#endif

	if (af == AF_INET6) {
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one))) {
			pr_error_errno("setsockopt: unable to set IPV6_RECVPKTINFO");
			goto error;
		}
	}

#ifdef USE_BINDTODEVICE
	if (addr->bindtodev && !fastd_peer_address_is_v6_ll(&addr->addr)) {
		if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, addr->bindtodev, strlen(addr->bindtodev))) {
			pr_warn_errno("setsockopt: unable to bind to device");
			goto error;
		}
	}
#endif

#ifdef USE_PMTU
	int pmtu = IP_PMTUDISC_DONT;
	if (setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu, sizeof(pmtu))) {
		pr_error_errno("setsockopt: unable to disable PMTU discovery");
		goto error;
	}
#endif

#ifdef USE_PACKET_MARK
	if (conf.packet_mark) {
		if (setsockopt(fd, SOL_SOCKET, SO_MARK, &conf.packet_mark, sizeof(conf.packet_mark))) {
			pr_error_errno("setsockopt: unable to set packet mark");
			goto error;
		}
	}
#endif

	fastd_peer_address_t bind_address = addr->addr;

	if (fastd_peer_address_is_v6_ll(&addr->addr) && addr->bindtodev) {
		char *end;
		bind_address.in6.sin6_scope_id = strtoul(addr->bindtodev, &end, 10);

		if (*end)
			bind_address.in6.sin6_scope_id = if_nametoindex(addr->bindtodev);

		if (!bind_address.in6.sin6_scope_id) {
			pr_warn_errno("if_nametoindex");
			goto error;
		}
	}

	if (bind_address.sa.sa_family == AF_UNSPEC) {
		memset(&bind_address, 0, sizeof(bind_address));
		bind_address.sa.sa_family = af;

		if (af == AF_INET6)
			bind_address.in6.sin6_port = addr->addr.in.sin_port;
		else
			bind_address.in.sin_port = addr->addr.in.sin_port;
	}

	if (reuseaddr_early) {
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one))) {
			pr_error_errno("setsockopt: unable to set SO_REUSEADDR");
			goto error;
		}

#ifdef SO_REUSEPORT
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)))
			pr_debug_errno("setsockopt: unable to set SO_REUSEPORT");
#endif
	}

	if (bind(fd, &bind_address.sa,
		 bind_address.sa.sa_family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in))) {
		if (quiet)
			pr_debug2_errno("bind");
		else
			pr_warn_errno("bind");
		goto error;
	}

	if (fastd_use_offload_l2tp() && !reuseaddr_early) {
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one))) {
			pr_error_errno("setsockopt: unable to set SO_REUSEADDR");
			goto error;
		}
	}

#ifdef __ANDROID__
	if (!fastd_android_protect_socket(fd)) {
		pr_error("error protecting socket");
		goto error;
	}
#endif

	return fd;

error:
	if (fd >= 0) {
		if (close(fd))
			pr_error_errno("close");
	}

	if (!quiet) {
		if (addr->bindtodev)
			pr_error(
				fastd_peer_address_is_v6_ll(&addr->addr) ? "unable to bind to %L"
									 : "unable to bind to %B on `%s'",
				&addr->addr, addr->bindtodev);
		else
			pr_error("unable to bind to %B", &addr->addr);
	}

	return -1;
}

/** Creates a TCP listener matching a bound UDP socket */
static fastd_socket_t *open_tcp_listener(fastd_socket_t *udp_sock) {
	const fastd_peer_address_t *addr = udp_sock->bound_addr;
	int fd = -1;

	switch (addr->sa.sa_family) {
	case AF_INET:
		fd = socket(PF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
		break;

	case AF_INET6:
		fd = socket(PF_INET6, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
		break;

	default:
		return NULL;
	}

	if (fd < 0) {
		pr_warn_errno("unable to create TCP listener socket");
		return NULL;
	}

#ifdef NO_HAVE_SOCK_NONBLOCK
	fastd_setnonblock(fd);
#endif

	const int one = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)))
		pr_warn_errno("setsockopt: unable to set SO_REUSEADDR");

#ifdef SO_REUSEPORT
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)))
		pr_warn_errno("setsockopt: unable to set SO_REUSEPORT");
#endif

	if (addr->sa.sa_family == AF_INET6) {
		int val = (udp_sock->addr && udp_sock->addr->addr.sa.sa_family == AF_INET6);
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val))) {
			pr_warn_errno("setsockopt: unable to set IPV6_V6ONLY");
			goto error;
		}
	}

	set_tcp_options(fd);

#ifdef USE_BINDTODEVICE
	if (udp_sock->addr && udp_sock->addr->bindtodev && !fastd_peer_address_is_v6_ll(&udp_sock->addr->addr)) {
		if (setsockopt(
			    fd, SOL_SOCKET, SO_BINDTODEVICE, udp_sock->addr->bindtodev,
			    strlen(udp_sock->addr->bindtodev))) {
			pr_warn_errno("setsockopt: unable to bind TCP listener to device");
			goto error;
		}
	}
#endif

#ifdef USE_FREEBIND
	if (setsockopt(fd, IPPROTO_IP, IP_FREEBIND, &one, sizeof(one)))
		pr_warn_errno("setsockopt: unable to set IP_FREEBIND");
#endif

#ifdef USE_PACKET_MARK
	if (conf.packet_mark) {
		if (setsockopt(fd, SOL_SOCKET, SO_MARK, &conf.packet_mark, sizeof(conf.packet_mark))) {
			pr_warn_errno("setsockopt: unable to set packet mark on TCP listener");
			goto error;
		}
	}
#endif

	if (bind(fd, &addr->sa, address_len(addr))) {
		pr_warn_errno("unable to bind TCP listener");
		goto error;
	}

	if (listen(fd, TCP_LISTEN_BACKLOG)) {
		pr_warn_errno("listen");
		goto error;
	}

#ifdef __ANDROID__
	if (!fastd_android_protect_socket(fd)) {
		pr_error("error protecting TCP listener socket");
		goto error;
	}
#endif

	fastd_socket_t *listener = fastd_new0(fastd_socket_t);
	listener->fd = FASTD_POLL_FD(POLL_TYPE_SOCKET, fd);
	listener->type = SOCKET_TYPE_TCP_LISTENER;
	listener->addr = udp_sock->addr;
	set_bound_address(listener);

	return listener;

error:
	if (close(fd))
		pr_error_errno("close");
	return NULL;
}

/** Gets the address a socket is bound to and sets it in the socket structure */
static void set_bound_address(fastd_socket_t *sock) {
	fastd_peer_address_t addr = {};
	socklen_t len = sizeof(addr);

	if (getsockname(sock->fd.fd, &addr.sa, &len) < 0)
		exit_errno("getsockname");

	sock->bound_addr = fastd_new(fastd_peer_address_t);
	*sock->bound_addr = addr;
}

/** Tries to initialize sockets for all configured bind addresses */
void fastd_socket_bind_all(void) {
	size_t i;

	for (i = 0; i < ctx.n_socks; i++) {
		fastd_socket_t *sock = &ctx.socks[i];

		if (!sock->addr)
			continue;

		sock->fd = FASTD_POLL_FD(POLL_TYPE_SOCKET, bind_socket(sock->addr, false, false));
		if (sock->fd.fd < 0)
			exit(1); /* message has already been printed */

		set_bound_address(sock);

		fastd_peer_address_t bound_addr = *sock->bound_addr;
		if (!sock->addr->addr.sa.sa_family)
			bound_addr.sa.sa_family = AF_UNSPEC;

		if (sock->addr->bindtodev && !fastd_peer_address_is_v6_ll(&bound_addr))
			pr_info("bound to %B on `%s'", &bound_addr, sock->addr->bindtodev);
		else
			pr_info("bound to %B", &bound_addr);

		fastd_poll_fd_register(&sock->fd);
	}

	fastd_socket_update_tcp_listeners();
}

/** Opens or closes TCP listeners according to the active peer transport configuration */
void fastd_socket_update_tcp_listeners(void) {
	bool required = tcp_listeners_required();

	size_t i;
	for (i = 0; i < ctx.n_socks; i++) {
		fastd_socket_t *sock = &ctx.socks[i];

		if (!sock->addr || sock->fd.fd < 0)
			continue;

		if (required) {
			if (sock->tcp_listener)
				continue;

			sock->tcp_listener = open_tcp_listener(sock);
			if (sock->tcp_listener) {
				fastd_poll_fd_register(&sock->tcp_listener->fd);
				pr_info("listening for TCP connections on %B", sock->tcp_listener->bound_addr);
			}
		} else if (sock->tcp_listener) {
			fastd_socket_close(sock->tcp_listener);
			free(sock->tcp_listener);
			sock->tcp_listener = NULL;
		}
	}
}

/** Opens a new socket for a given peer */
static fastd_socket_t *open_dynamic_socket(const fastd_bind_address_t *addr, bool reuseaddr_early, bool quiet) {
	int fd = bind_socket(addr, reuseaddr_early, quiet);
	if (fd < 0)
		return NULL;

	fastd_socket_t *sock = fastd_new0(fastd_socket_t);
	sock->fd = FASTD_POLL_FD(POLL_TYPE_SOCKET, fd);
	sock->type = SOCKET_TYPE_UDP;
	set_bound_address(sock);

	return sock;
}

/** Opens a single socket bound to a random port for the given address family */
fastd_socket_t *fastd_socket_open(fastd_peer_t *peer, int af) {
	const fastd_bind_address_t any_address = { .addr.sa.sa_family = af };

	const fastd_bind_address_t *bind_address;

	if (af == AF_INET && conf.bind_addr_default_v4) {
		bind_address = conf.bind_addr_default_v4;
	} else if (af == AF_INET6 && conf.bind_addr_default_v6) {
		bind_address = conf.bind_addr_default_v6;
	} else if (!conf.bind_addr_default_v4 && !conf.bind_addr_default_v6) {
		bind_address = &any_address;
	} else {
		pr_debug(
			"not opening an %s socket for peer %P (no bind address with matching address family)",
			(af == AF_INET6) ? "IPv6" : "IPv4", peer);
		return NULL;
	}

	fastd_socket_t *sock = open_dynamic_socket(bind_address, false, false);
	if (!sock)
		return NULL;

	sock->peer = peer;

	fastd_poll_fd_register(&sock->fd);
	return sock;
}

/** Opens a TCP connection socket for a peer */
fastd_socket_t *
fastd_socket_open_tcp(fastd_peer_t *peer, const fastd_socket_t *base_sock, const fastd_peer_address_t *remote_addr) {
	if (remote_addr->sa.sa_family != AF_INET && remote_addr->sa.sa_family != AF_INET6)
		return NULL;

	int fd = socket(
		remote_addr->sa.sa_family == AF_INET6 ? PF_INET6 : PF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
	if (fd < 0) {
		pr_warn_errno("unable to create TCP connection socket");
		return NULL;
	}

#ifdef NO_HAVE_SOCK_NONBLOCK
	fastd_setnonblock(fd);
#endif

	const int one = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)))
		pr_warn_errno("setsockopt: unable to set SO_REUSEADDR");

#ifdef SO_REUSEPORT
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)))
		pr_warn_errno("setsockopt: unable to set SO_REUSEPORT");
#endif

	set_tcp_options(fd);

#ifdef USE_PACKET_MARK
	if (conf.packet_mark) {
		if (setsockopt(fd, SOL_SOCKET, SO_MARK, &conf.packet_mark, sizeof(conf.packet_mark))) {
			pr_warn_errno("setsockopt: unable to set packet mark on TCP connection");
			goto error;
		}
	}
#endif

	if (base_sock && base_sock->bound_addr && base_sock->bound_addr->sa.sa_family == remote_addr->sa.sa_family) {
		fastd_peer_address_t local_addr = *base_sock->bound_addr;

		if (bind(fd, &local_addr.sa, address_len(&local_addr))) {
			pr_warn_errno("unable to bind TCP connection socket");
			goto error;
		}
	}

#ifdef __ANDROID__
	if (!fastd_android_protect_socket(fd)) {
		pr_error("error protecting TCP connection socket");
		goto error;
	}
#endif

	int ret = connect(fd, &remote_addr->sa, address_len(remote_addr));
	if (ret < 0 && errno != EINPROGRESS) {
		pr_debug_errno("connect");
		goto error;
	}

	fastd_socket_t *sock = fastd_new0(fastd_socket_t);
	sock->fd = FASTD_POLL_FD(POLL_TYPE_SOCKET, fd);
	sock->type = SOCKET_TYPE_TCP_CONNECTION;
	sock->peer = peer;
	sock->peer_addr = *remote_addr;
	sock->tcp_connecting = (ret < 0);
	sock->tcp_timeout = ctx.now + MIN_HANDSHAKE_INTERVAL;
	set_bound_address(sock);

	VECTOR_ADD(ctx.tcp_socks, sock);
	fastd_poll_fd_register(&sock->fd);
	fastd_poll_fd_set_write(&sock->fd, sock->tcp_connecting);

	pr_debug("opening TCP connection to %P[%I]", peer, remote_addr);
	return sock;

error:
	if (close(fd))
		pr_error_errno("close");
	return NULL;
}

/** Opens a socket for L2TP offloading */
fastd_socket_t *fastd_socket_open_offload(fastd_socket_t *sock, const fastd_peer_address_t *local_addr) {
	if (!sock->bound_addr)
		exit_bug("attempted to clone unbound socket");

	fastd_bind_address_t bind_address = {
		.addr = *local_addr,
		.bindtodev = sock->addr ? sock->addr->bindtodev : NULL,
	};

	fastd_socket_t *offload_sock = open_dynamic_socket(&bind_address, true, false);
	if (!offload_sock)
		return NULL;

	offload_sock->parent = sock;

	fastd_poll_fd_register(&offload_sock->fd);

	return offload_sock;
}

/** Closes a socket */
void fastd_socket_close(fastd_socket_t *sock) {
	if (sock->type == SOCKET_TYPE_UDP && sock->hole_punch)
		udp_punch_unlink(sock);

	if (sock->tcp_listener) {
		fastd_socket_close(sock->tcp_listener);
		free(sock->tcp_listener);
		sock->tcp_listener = NULL;
	}

	if (sock->type == SOCKET_TYPE_TCP_CONNECTION) {
		sock->tcp_closed = true;
		tcp_connection_unlink(sock);

		if (sock->peer && sock->peer->sock == sock)
			sock->peer->sock = NULL;
		sock->peer = NULL;

		free(sock->tcp_packet);
		sock->tcp_packet = NULL;
		tcp_free_output(sock);
	}

	if (sock->peer) {
		if (sock->peer->sock == sock)
			sock->peer->sock = NULL;

		if (sock->peer->backup_sock == sock)
			sock->peer->backup_sock = NULL;

		sock->peer = NULL;
	}

	if (sock->punch_listener_mapping_registered)
		fastd_port_mapping_release_socket(sock);

	if (sock->fd.fd >= 0) {
		if (!fastd_poll_fd_close(&sock->fd))
			pr_error_errno("closing socket: close");

		sock->fd.fd = -1;
	}

	if (sock->bound_addr) {
		free(sock->bound_addr);
		sock->bound_addr = NULL;
	}
}

/** Handles an error that occured on a socket */
void fastd_socket_error(const fastd_socket_t *sock) {
	/* This function is only called for sockets that have been registered
	 * for polling. This implies that bound_addr is set. */
	pr_debug2("error on socket bound to %B", sock->bound_addr);

	int error;
	socklen_t errlen = sizeof(error);
	getsockopt(sock->fd.fd, SOL_SOCKET, SO_ERROR, &error, &errlen);
}

/** Returns true if a socket can still be used for I/O */
bool fastd_socket_is_open(const fastd_socket_t *sock) {
	return sock && sock->fd.fd >= 0 && sock->bound_addr;
}

/** Returns true if the socket is a TCP connection */
bool fastd_socket_is_tcp(const fastd_socket_t *sock) {
	return sock && sock->type == SOCKET_TYPE_TCP_CONNECTION;
}

/** Returns true if the socket was established through hole punching */
bool fastd_socket_is_hole_punch(const fastd_socket_t *sock) {
	return sock && sock->hole_punch;
}

/** Updates write readiness polling for a TCP connection */
static void tcp_update_write(fastd_socket_t *sock) {
	if (sock->fd.fd >= 0)
		fastd_poll_fd_set_write(&sock->fd, sock->tcp_connecting || sock->tcp_output_head);
}

/** Checks if a non-blocking TCP connect has completed */
static bool tcp_check_connect(fastd_socket_t *sock) {
	if (!sock->tcp_connecting)
		return true;

	int error = 0;
	socklen_t len = sizeof(error);
	if (getsockopt(sock->fd.fd, SOL_SOCKET, SO_ERROR, &error, &len)) {
		pr_warn_errno("getsockopt");
		close_tcp_connection(sock, true);
		return false;
	}

	if (error) {
		errno = error;
		pr_debug_errno("TCP connect");
		close_tcp_connection(sock, true);
		return false;
	}

	sock->tcp_connecting = false;
	sock->tcp_timeout = FASTD_TIMEOUT_INV;
	pr_debug("TCP connection to %I established", &sock->peer_addr);
	return true;
}

/** Flushes queued TCP output frames */
static void tcp_flush(fastd_socket_t *sock) {
	if (!tcp_check_connect(sock))
		return;

	while (sock->tcp_output_head) {
		fastd_tcp_frame_t *frame = sock->tcp_output_head;

		ssize_t ret =
			send(sock->fd.fd, frame->data + frame->written, frame->len - frame->written, MSG_NOSIGNAL);
		if (ret < 0) {
			switch (errno) {
			case EAGAIN:
#if EAGAIN != EWOULDBLOCK
			case EWOULDBLOCK:
#endif
				tcp_update_write(sock);
				return;

			default:
				pr_debug_errno("TCP send");
				close_tcp_connection(sock, true);
				return;
			}
		}

		if (ret == 0) {
			close_tcp_connection(sock, true);
			return;
		}

		frame->written += ret;
		sock->tcp_output_len -= ret;

		if (frame->written < frame->len)
			continue;

		fastd_stats_add(frame->peer, STAT_TX, frame->stat_size);

		sock->tcp_output_head = frame->next;
		if (!sock->tcp_output_head)
			sock->tcp_output_tail = NULL;
		free(frame);
	}

	tcp_update_write(sock);
}

/** Queues a packet for transmission on a TCP connection */
static bool tcp_queue(fastd_socket_t *sock, fastd_peer_t *peer, const fastd_buffer_t *buffer, size_t stat_size) {
	if (buffer->len > UINT32_MAX) {
		pr_warn("packet for %P is too large for TCP framing", peer);
		fastd_stats_add(peer, STAT_TX_ERROR, stat_size);
		return true;
	}

	size_t frame_len = TCP_FRAME_HEADER + buffer->len;
	if (sock->tcp_output_len + frame_len > TCP_MAX_OUTPUT_QUEUE) {
		pr_debug("dropping packet for %P because TCP output queue is full", peer);
		fastd_stats_add(peer, STAT_TX_DROPPED, stat_size);
		return true;
	}

	fastd_tcp_frame_t *frame = fastd_alloc(sizeof(*frame) + frame_len);
	*frame = (fastd_tcp_frame_t){
		.len = frame_len,
		.stat_size = stat_size,
		.peer = peer,
	};

	uint32_t len = htonl(buffer->len);
	memcpy(frame->data, &len, TCP_FRAME_HEADER);
	memcpy(frame->data + TCP_FRAME_HEADER, buffer->data, buffer->len);

	if (sock->tcp_output_tail)
		sock->tcp_output_tail->next = frame;
	else
		sock->tcp_output_head = frame;
	sock->tcp_output_tail = frame;
	sock->tcp_output_len += frame_len;

	tcp_flush(sock);
	return true;
}

/** Queues an initial handshake on deterministic TCP hole punching candidates */
static void
tcp_hole_punch_queue(fastd_peer_t *peer, const fastd_peer_address_t *remote_addr, const fastd_buffer_t *buffer) {
	if (!peer || !fastd_peer_hole_punch_allows(peer, TRANSPORT_TCP))
		return;

	if (!fastd_peer_transport_allows(fastd_peer_get_transport(peer), TRANSPORT_TCP))
		return;

	if (fastd_peer_is_punch_control_candidate(peer, remote_addr, NULL, NULL) &&
	    !fastd_peer_is_punch_control_candidate_transport(peer, remote_addr, TRANSPORT_TCP, NULL, NULL))
		return;

	if (fastd_peer_is_established(peer)) {
		if (fastd_peer_has_verified_backup_path(peer))
			return;
		if (fastd_peer_address_equal(&peer->address, remote_addr))
			return;
	}

	if (remote_addr->sa.sa_family != AF_INET)
		return;

	uint16_t ports[FASTD_HOLE_PUNCH_NUM_PORTS * FASTD_HOLE_PUNCH_BUCKETS];
	size_t n_ports = fastd_hole_punch_generate_ports(ports, array_size(ports), time(NULL));

	size_t i;
	for (i = 0; i < n_ports; i++) {
		fastd_peer_address_t punch_addr = *remote_addr;
		set_address_port(&punch_addr, ports[i]);

		fastd_socket_t *sock = find_tcp_hole_punch_socket(peer, &punch_addr);
		if (!sock)
			sock = open_tcp_hole_punch_socket(peer, &punch_addr);

		if (sock)
			tcp_queue(sock, peer, buffer, 0);
	}
}

/** Returns an existing UDP punch socket for a peer and remote candidate */
static fastd_socket_t *find_udp_hole_punch_socket(fastd_peer_t *peer, const fastd_peer_address_t *remote_addr) {
	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.udp_punch_socks); i++) {
		fastd_socket_t *sock = VECTOR_INDEX(ctx.udp_punch_socks, i);

		if (sock->hole_punch_peer == peer && fastd_peer_address_equal(&sock->peer_addr, remote_addr))
			return sock;
	}

	return NULL;
}

/** Returns an existing UDP punch socket for a peer and remote candidate */
fastd_socket_t *fastd_udp_punch_find_socket(fastd_peer_t *peer, const fastd_peer_address_t *remote_addr) {
	return find_udp_hole_punch_socket(peer, remote_addr);
}

/** Counts existing UDP punch sockets for a peer and remote candidate */
static size_t count_udp_hole_punch_sockets(fastd_peer_t *peer, const fastd_peer_address_t *remote_addr) {
	size_t count = 0;
	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.udp_punch_socks); i++) {
		fastd_socket_t *sock = VECTOR_INDEX(ctx.udp_punch_socks, i);

		if (sock->hole_punch_peer == peer && fastd_peer_address_equal(&sock->peer_addr, remote_addr))
			count++;
	}

	return count;
}

/** Sends a UDP punch handshake from one socket */
static bool udp_punch_send_from_socket(
	fastd_socket_t *sock, const fastd_peer_address_t *remote_addr, const fastd_buffer_t *buffer) {
	fastd_punch_probe_send(sock, remote_addr);

	ssize_t ret = sendto(sock->fd.fd, buffer->data, buffer->len, 0, &remote_addr->sa, address_len(remote_addr));
	if (ret < 0) {
		pr_debug2_errno("UDP punch sendto");
		return false;
	}

	if (sock->hole_punch)
		sock->hole_punch_timeout = ctx.now + FASTD_HOLE_PUNCH_TIMEOUT;

	ctx.punch_udp_exact_tx++;
	return true;
}

/** Opens a UDP socket for active UDP hole punching with a selected local source port */
static fastd_socket_t *
open_udp_hole_punch_socket_local(fastd_peer_t *peer, const fastd_peer_address_t *remote_addr, uint16_t local_port) {
	unsigned limit = conf.punch_max_sockets ? conf.punch_max_sockets : 1;
	if (udp_punch_active_socket_count() >= limit) {
		pr_debug("not opening UDP punch socket for %P because the punch socket limit has been reached", peer);
		return NULL;
	}

	const fastd_socket_t *base_sock = get_default_socket(remote_addr->sa.sa_family);

	fastd_peer_address_t local_addr = { .sa.sa_family = remote_addr->sa.sa_family };
	if (base_sock && base_sock->bound_addr && base_sock->bound_addr->sa.sa_family == remote_addr->sa.sa_family)
		local_addr = *base_sock->bound_addr;

	set_address_port(&local_addr, local_port);

	fastd_bind_address_t bind_address = {
		.addr = local_addr,
		.bindtodev = base_sock && base_sock->addr ? base_sock->addr->bindtodev : NULL,
	};

	fastd_socket_t *sock = open_dynamic_socket(&bind_address, true, true);
	if (!sock)
		return NULL;

	sock->hole_punch_peer = peer;
	sock->hole_punch = true;
	sock->peer_addr = *remote_addr;
	sock->hole_punch_timeout = ctx.now + FASTD_HOLE_PUNCH_TIMEOUT;
	fastd_punch_probe_init_socket(sock);

	VECTOR_ADD(ctx.udp_punch_socks, sock);
	fastd_poll_fd_register(&sock->fd);

	pr_debug("opening UDP punch socket to %P[%I]", peer, remote_addr);
	return sock;
}

/** Opens a UDP socket using the deterministic target port as local source port */
static fastd_socket_t *open_udp_hole_punch_socket(fastd_peer_t *peer, const fastd_peer_address_t *remote_addr) {
	return open_udp_hole_punch_socket_local(peer, remote_addr, ntohs(fastd_peer_address_get_port(remote_addr)));
}

/** Returns the configured dynamic bind address for a public punch listener family */
static const fastd_bind_address_t *
udp_punch_public_listener_bind_address(sa_family_t family, fastd_bind_address_t *fallback) {
	*fallback = (fastd_bind_address_t){ .addr.sa.sa_family = family };

	if (family == AF_INET && conf.bind_addr_default_v4)
		return conf.bind_addr_default_v4;
	if (family == AF_INET6 && conf.bind_addr_default_v6)
		return conf.bind_addr_default_v6;
	if (!conf.bind_addr_default_v4 && !conf.bind_addr_default_v6)
		return fallback;

	return NULL;
}

/** Finds a reusable public punch listener for one address family */
static fastd_socket_t *find_udp_punch_public_listener(sa_family_t family, bool require_port_mapping) {
	fastd_socket_t *best = NULL;
	size_t i;

	for (i = 0; i < VECTOR_LEN(ctx.udp_punch_socks); i++) {
		fastd_socket_t *sock = VECTOR_INDEX(ctx.udp_punch_socks, i);
		refresh_udp_punch_public_listener_mapping(sock);
		if (!udp_punch_public_listener_available(sock) ||
		    sock->punch_listener_public_addr.sa.sa_family != family)
			continue;
		if (require_port_mapping && !sock->punch_listener_port_mapped)
			continue;

		if (!best || sock->punch_listener_selected > best->punch_listener_selected)
			best = sock;
	}

	return best;
}

/** Computes reusable public listener availability for one address family */
static void udp_punch_public_listener_stats(
	sa_family_t family, size_t *listener_count, bool *has_reusable_listener, bool *has_port_mapping_listener) {
	*listener_count = udp_punch_public_listener_count();
	*has_reusable_listener = find_udp_punch_public_listener(family, false) != NULL;
	*has_port_mapping_listener = find_udp_punch_public_listener(family, true) != NULL;
}

/** Opens and STUN-probes one reusable public punch listener */
static fastd_socket_t *open_udp_punch_public_listener(sa_family_t family) {
	if (udp_punch_public_listener_count() >= DEFAULT_PUNCH_PUBLIC_LISTENERS) {
		pr_debug("not opening public UDP punch listener because the listener limit has been reached");
		return NULL;
	}

	fastd_bind_address_t fallback;
	const fastd_bind_address_t *bind_address = udp_punch_public_listener_bind_address(family, &fallback);
	if (!bind_address) {
		pr_debug("not opening public UDP punch listener for unsupported address family");
		return NULL;
	}

	fastd_socket_t *sock = open_dynamic_socket(bind_address, false, true);
	if (!sock)
		return NULL;

	sock->hole_punch = true;
	sock->punch_public_listener = true;
	sock->punch_listener_id = next_udp_punch_public_listener_id();
	sock->hole_punch_timeout = ctx.now + PEER_STALE_TIME;
	sock->punch_listener_selected = ctx.now;
	fastd_punch_probe_init_socket(sock);

	fastd_peer_address_t public_addr = {};
	if (family == AF_INET && fastd_port_mapping_register_socket(sock) &&
	    fastd_port_mapping_get_external_address(sock, &public_addr)) {
		sock->punch_listener_port_mapped = true;
	} else if (!fastd_nat_probe_socket_public_address(sock->fd.fd, family, &public_addr)) {
		fastd_socket_close(sock);
		free(sock);
		return NULL;
	}

	sock->punch_listener_public_addr = public_addr;

	VECTOR_ADD(ctx.udp_punch_socks, sock);
	fastd_poll_fd_register(&sock->fd);

	pr_debug("opening public UDP punch listener on %B with mapped endpoint %I", sock->bound_addr, &public_addr);
	return sock;
}

/** Selects a reusable public UDP punch listener and returns its public endpoint */
bool fastd_udp_punch_select_listener(
	sa_family_t family, bool force_new, bool prefer_port_mapping, fastd_peer_address_t *public_addr,
	bool *port_mapped, uint32_t *listener_id) {
	if (!public_addr || (family != AF_INET && family != AF_INET6))
		return false;

	size_t listener_count = 0;
	bool has_reusable_listener = false, has_port_mapping_listener = false;
	udp_punch_public_listener_stats(
		family, &listener_count, &has_reusable_listener, &has_port_mapping_listener);

	bool should_create = udp_punch_should_create_public_listener(
		listener_count, has_reusable_listener, has_port_mapping_listener, force_new, prefer_port_mapping);
	fastd_socket_t *created = should_create ? open_udp_punch_public_listener(family) : NULL;

	fastd_socket_t *sock = NULL;
	if (prefer_port_mapping)
		sock = find_udp_punch_public_listener(family, true);
	if (!sock && created && udp_punch_public_listener_available(created) &&
	    created->punch_listener_public_addr.sa.sa_family == family)
		sock = created;
	if (!sock)
		sock = find_udp_punch_public_listener(family, false);
	if (!sock)
		return false;

	sock->hole_punch_timeout = ctx.now + PEER_STALE_TIME;
	sock->punch_listener_selected = ctx.now;
	*public_addr = sock->punch_listener_public_addr;
	if (port_mapped)
		*port_mapped = sock->punch_listener_port_mapped;
	if (listener_id)
		*listener_id = sock->punch_listener_id;

	return true;
}

/** Sends one handshake from an ephemeral UDP punch socket to the exact remote endpoint */
static bool
udp_punch_send_exact(fastd_peer_t *peer, const fastd_peer_address_t *remote_addr, const fastd_buffer_t *buffer) {
	fastd_socket_t *sock = find_udp_hole_punch_socket(peer, remote_addr);
	if (!sock)
		sock = open_udp_hole_punch_socket_local(peer, remote_addr, 0);

	if (!sock)
		return false;

	return udp_punch_send_from_socket(sock, remote_addr, buffer);
}

/** Sends handshakes from an ephemeral UDP punch socket array to one endpoint */
static bool udp_punch_send_socket_array(
	fastd_peer_t *peer, const fastd_peer_address_t *remote_addr, const fastd_buffer_t *buffer,
	unsigned socket_count) {
	if (socket_count <= 1)
		return udp_punch_send_exact(peer, remote_addr, buffer);

	bool sent = false;

	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.udp_punch_socks); i++) {
		fastd_socket_t *sock = VECTOR_INDEX(ctx.udp_punch_socks, i);
		if (sock->hole_punch_peer == peer && fastd_peer_address_equal(&sock->peer_addr, remote_addr))
			sent |= udp_punch_send_from_socket(sock, remote_addr, buffer);
	}

	size_t existing = count_udp_hole_punch_sockets(peer, remote_addr);
	while (existing < socket_count) {
		fastd_socket_t *sock = open_udp_hole_punch_socket_local(peer, remote_addr, 0);
		if (!sock)
			break;

		existing++;
		sent |= udp_punch_send_from_socket(sock, remote_addr, buffer);
	}

	return sent;
}

/** Returns true if exact UDP punch sockets support an address family */
static bool udp_punch_exact_family_supported(sa_family_t family) {
	return family == AF_INET || family == AF_INET6;
}

/** Returns true if deterministic UDP punch port buckets support an address family */
static bool udp_punch_deterministic_family_supported(sa_family_t family) {
	return family == AF_INET || family == AF_INET6;
}

/** Sends an initial handshake on deterministic UDP hole punching candidates */
bool fastd_udp_punch_send(
	fastd_peer_t *peer, UNUSED const fastd_socket_t *base_sock, const fastd_peer_address_t *remote_addr,
	const fastd_buffer_t *buffer) {
	if (!peer || !fastd_peer_hole_punch_allows(peer, TRANSPORT_UDP))
		return false;

	if (!fastd_peer_transport_allows(fastd_peer_get_transport(peer), TRANSPORT_UDP))
		return false;

	if (!udp_punch_exact_family_supported(remote_addr->sa.sa_family))
		return false;

	bool exact_udp_punch = false;
	unsigned udp_punch_sockets = 0;
	if (fastd_peer_is_current_punch_control_candidate_transport(
		    peer, remote_addr, TRANSPORT_UDP, &exact_udp_punch, &udp_punch_sockets))
		return exact_udp_punch ? udp_punch_send_socket_array(peer, remote_addr, buffer, udp_punch_sockets)
				       : false;

	if (fastd_peer_is_established(peer))
		return false;

	if (!udp_punch_deterministic_family_supported(remote_addr->sa.sa_family))
		return false;

	uint16_t ports[FASTD_HOLE_PUNCH_NUM_PORTS * FASTD_HOLE_PUNCH_BUCKETS];
	size_t n_ports = fastd_hole_punch_generate_ports(ports, array_size(ports), time(NULL));
	bool sent = false;

	size_t i;
	for (i = 0; i < n_ports; i++) {
		fastd_peer_address_t punch_addr = *remote_addr;
		set_address_port(&punch_addr, ports[i]);

		fastd_socket_t *sock = find_udp_hole_punch_socket(peer, &punch_addr);
		if (!sock)
			sock = open_udp_hole_punch_socket(peer, &punch_addr);

		if (!sock)
			continue;

		ssize_t ret =
			sendto(sock->fd.fd, buffer->data, buffer->len, 0, &punch_addr.sa, address_len(&punch_addr));
		if (ret < 0)
			pr_debug2_errno("UDP punch sendto");
		else
			sent = true;
	}

	return sent;
}

#ifdef WITH_TESTS

/** Test wrapper for exact UDP punch family policy */
bool fastd_socket_test_udp_punch_exact_family_supported(sa_family_t family) {
	return udp_punch_exact_family_supported(family);
}

/** Test wrapper for deterministic UDP punch family policy */
bool fastd_socket_test_udp_punch_deterministic_family_supported(sa_family_t family) {
	return udp_punch_deterministic_family_supported(family);
}

/** Test wrapper for public UDP punch listener availability */
bool fastd_socket_test_udp_punch_public_listener_available(const fastd_socket_t *sock) {
	return udp_punch_public_listener_available(sock);
}

/** Test wrapper for public UDP punch listener count */
size_t fastd_socket_test_udp_punch_public_listener_count(void) {
	return udp_punch_public_listener_count();
}

/** Test wrapper for active per-peer UDP punch socket count */
size_t fastd_socket_test_udp_punch_active_socket_count(void) {
	return udp_punch_active_socket_count();
}

/** Test wrapper for public listener creation policy */
bool fastd_socket_test_udp_punch_should_create_public_listener(
	size_t current_listener_count, bool has_reusable_listener, bool has_port_mapping_listener, bool force_new,
	bool prefer_port_mapping) {
	return udp_punch_should_create_public_listener(
		current_listener_count, has_reusable_listener, has_port_mapping_listener, force_new, prefer_port_mapping);
}

/** Test wrapper for public listener selection policy */
uint32_t fastd_socket_test_udp_punch_select_public_listener_id(sa_family_t family, bool prefer_port_mapping) {
	fastd_socket_t *sock = NULL;
	if (prefer_port_mapping)
		sock = find_udp_punch_public_listener(family, true);
	if (!sock)
		sock = find_udp_punch_public_listener(family, false);

	return sock ? sock->punch_listener_id : 0;
}

#endif

/** Sends a packet over TCP if the peer is configured for TCP transport */
bool fastd_tcp_send(
	fastd_peer_t *peer, fastd_socket_t *sock, UNUSED const fastd_peer_address_t *local_addr,
	const fastd_peer_address_t *remote_addr, const fastd_buffer_t *buffer, size_t stat_size) {
	if (!stat_size && peer && fastd_peer_is_punch_control_candidate(peer, remote_addr, NULL, NULL) &&
	    !fastd_peer_is_punch_control_candidate_transport(peer, remote_addr, TRANSPORT_TCP, NULL, NULL))
		return false;

	if (sock && sock->type == SOCKET_TYPE_TCP_CONNECTION) {
		if (fastd_peer_address_equal(&sock->peer_addr, remote_addr) &&
		    (!sock->peer || !peer || sock->peer == peer)) {
			if (!stat_size && sock->peer == peer)
				tcp_hole_punch_queue(peer, remote_addr, buffer);

			return tcp_queue(sock, peer, buffer, stat_size);
		}

		fastd_stats_add(peer, STAT_TX_ERROR, stat_size);
		return true;
	}

	if (!peer)
		return false;

	fastd_peer_transport_t transport = fastd_peer_get_transport(peer);
	bool auto_probe_handshake =
		!stat_size && transport == TRANSPORT_AUTO && (!sock || sock->type != SOCKET_TYPE_TCP_CONNECTION);

	switch (transport) {
	case TRANSPORT_TCP:
		break;

	case TRANSPORT_AUTO:
		if (!peer->transport_probe)
			peer->transport_probe = TRANSPORT_TCP;
		if (peer->transport_probe != TRANSPORT_TCP)
			return false;
		break;

	default:
		return false;
	}

	if (remote_addr->sa.sa_family != AF_INET && remote_addr->sa.sa_family != AF_INET6) {
		fastd_stats_add(peer, STAT_TX_ERROR, stat_size);
		return true;
	}

	fastd_socket_t *tcp_sock = NULL;

	if (peer->sock && peer->sock->type == SOCKET_TYPE_TCP_CONNECTION &&
	    fastd_peer_address_equal(&peer->sock->peer_addr, remote_addr))
		tcp_sock = peer->sock;

	if (!tcp_sock) {
		fastd_peer_reset_socket(peer);

		if (peer->sock && peer->sock->type == SOCKET_TYPE_TCP_CONNECTION &&
		    fastd_peer_address_equal(&peer->sock->peer_addr, remote_addr))
			tcp_sock = peer->sock;
	}

	if (!tcp_sock) {
		if (!auto_probe_handshake)
			fastd_stats_add(peer, STAT_TX_ERROR, stat_size);
		return !auto_probe_handshake;
	}

	if (!stat_size)
		tcp_hole_punch_queue(peer, remote_addr, buffer);

	bool queued = tcp_queue(tcp_sock, peer, buffer, stat_size);
	return auto_probe_handshake ? false : queued;
}

/** Accepts all pending TCP connections from a listener */
static void tcp_accept(fastd_socket_t *listener) {
	while (true) {
		fastd_peer_address_t peer_addr = {};
		socklen_t peer_addr_len = sizeof(peer_addr);
		int fd = accept(listener->fd.fd, &peer_addr.sa, &peer_addr_len);
		if (fd < 0) {
			switch (errno) {
			case EAGAIN:
#if EAGAIN != EWOULDBLOCK
			case EWOULDBLOCK:
#endif
				return;

			default:
				pr_warn_errno("accept");
				return;
			}
		}

		if (VECTOR_LEN(ctx.tcp_socks) >= TCP_MAX_CONNECTIONS) {
			pr_debug("rejecting TCP connection because the connection limit has been reached");
			close(fd);
			continue;
		}

		fastd_setnonblock(fd);
		set_tcp_options(fd);

#ifdef __ANDROID__
		if (!fastd_android_protect_socket(fd)) {
			pr_error("error protecting accepted TCP socket");
			close(fd);
			continue;
		}
#endif

		fastd_socket_t *sock = fastd_new0(fastd_socket_t);
		sock->fd = FASTD_POLL_FD(POLL_TYPE_SOCKET, fd);
		sock->type = SOCKET_TYPE_TCP_CONNECTION;
		sock->addr = listener->addr;
		sock->peer_addr = peer_addr;
		fastd_peer_address_simplify(&sock->peer_addr);
		sock->tcp_timeout = ctx.now + MIN_HANDSHAKE_INTERVAL;
		set_bound_address(sock);
		fastd_peer_address_simplify(sock->bound_addr);

		VECTOR_ADD(ctx.tcp_socks, sock);
		fastd_poll_fd_register(&sock->fd);

		pr_debug("accepted TCP connection from %I", &sock->peer_addr);
	}
}

/** Closes a TCP connection after a protocol error */
static void tcp_protocol_error(fastd_socket_t *sock, const char *message) {
	pr_debug("closing TCP connection from %I: %s", &sock->peer_addr, message);
	close_tcp_connection(sock, true);
}

/** Handles a fully received TCP frame */
static void tcp_handle_frame(fastd_socket_t *sock) {
	fastd_buffer_t *buffer = fastd_buffer_alloc(sock->tcp_packet_len, conf.decrypt_headroom);
	memcpy(buffer->data, sock->tcp_packet, sock->tcp_packet_len);

	free(sock->tcp_packet);
	sock->tcp_packet = NULL;
	sock->tcp_packet_len = 0;
	sock->tcp_packet_pos = 0;
	sock->tcp_header_len = 0;
	sock->tcp_timeout = sock->peer ? FASTD_TIMEOUT_INV : ctx.now + MIN_HANDSHAKE_INTERVAL;

	fastd_receive_packet(sock, sock->bound_addr, &sock->peer_addr, buffer);
}

/** Reads all pending TCP frames from a connection */
static void tcp_read(fastd_socket_t *sock) {
	while (!sock->tcp_closed) {
		if (sock->tcp_header_len < TCP_FRAME_HEADER) {
			ssize_t ret =
				recv(sock->fd.fd, sock->tcp_header + sock->tcp_header_len,
				     TCP_FRAME_HEADER - sock->tcp_header_len, 0);
			if (ret < 0) {
				switch (errno) {
				case EAGAIN:
#if EAGAIN != EWOULDBLOCK
				case EWOULDBLOCK:
#endif
					return;

				default:
					pr_debug_errno("TCP recv");
					close_tcp_connection(sock, true);
					return;
				}
			}

			if (ret == 0) {
				close_tcp_connection(sock, true);
				return;
			}

			sock->tcp_header_len += ret;
			if (sock->tcp_header_len < TCP_FRAME_HEADER)
				continue;

			uint32_t len;
			memcpy(&len, sock->tcp_header, TCP_FRAME_HEADER);
			sock->tcp_packet_len = ntohl(len);

			if (!sock->tcp_packet_len || sock->tcp_packet_len > ctx.max_buffer ||
			    conf.decrypt_headroom > ctx.max_buffer - sock->tcp_packet_len) {
				tcp_protocol_error(sock, "invalid frame length");
				return;
			}

			sock->tcp_packet = fastd_alloc(sock->tcp_packet_len);
		}

		ssize_t ret =
			recv(sock->fd.fd, sock->tcp_packet + sock->tcp_packet_pos,
			     sock->tcp_packet_len - sock->tcp_packet_pos, 0);
		if (ret < 0) {
			switch (errno) {
			case EAGAIN:
#if EAGAIN != EWOULDBLOCK
			case EWOULDBLOCK:
#endif
				return;

			default:
				pr_debug_errno("TCP recv");
				close_tcp_connection(sock, true);
				return;
			}
		}

		if (ret == 0) {
			close_tcp_connection(sock, true);
			return;
		}

		sock->tcp_packet_pos += ret;
		if (sock->tcp_packet_pos == sock->tcp_packet_len)
			tcp_handle_frame(sock);
	}
}

/** Handles events on a socket */
void fastd_socket_handle(fastd_socket_t *sock, bool input, bool output, bool error) {
	if (!fastd_socket_is_open(sock))
		return;

	switch (sock->type) {
	case SOCKET_TYPE_UDP:
		if (error)
			fastd_socket_error(sock);

		if (input)
			fastd_receive(sock);
		break;

	case SOCKET_TYPE_TCP_LISTENER:
		if (error)
			fastd_socket_error(sock);

		if (input)
			tcp_accept(sock);
		break;

	case SOCKET_TYPE_TCP_CONNECTION: {
		sock->tcp_handling = true;

		if (error) {
			close_tcp_connection(sock, true);
		} else {
			if (output)
				tcp_flush(sock);

			if (!sock->tcp_closed && input)
				tcp_read(sock);
		}

		bool closed = sock->tcp_closed;
		sock->tcp_handling = false;

		if (closed)
			free(sock);
		break;
	}
	}
}

/** Performs TCP connection maintenance */
void fastd_tcp_maintenance(void) {
	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.tcp_socks);) {
		fastd_socket_t *sock = VECTOR_INDEX(ctx.tcp_socks, i);

		if (sock->tcp_timeout != FASTD_TIMEOUT_INV && fastd_timed_out(sock->tcp_timeout)) {
			pr_debug("TCP connection with %I timed out", &sock->peer_addr);
			close_tcp_connection(sock, sock->peer != NULL);
			continue;
		}

		i++;
	}
}

/** Performs UDP hole punching socket maintenance */
void fastd_udp_punch_maintenance(void) {
	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.udp_punch_socks);) {
		fastd_socket_t *sock = VECTOR_INDEX(ctx.udp_punch_socks, i);

		if (sock->hole_punch_timeout != FASTD_TIMEOUT_INV && fastd_timed_out(sock->hole_punch_timeout)) {
			if (sock->punch_public_listener)
				pr_debug(
					"public UDP punch listener with mapped endpoint %I timed out",
					&sock->punch_listener_public_addr);
			else
				pr_debug("UDP hole punching socket with %I timed out", &sock->peer_addr);
			close_udp_punch_socket(sock);
			continue;
		}

		i++;
	}
}

/** Closes all UDP hole punching sockets */
void fastd_udp_punch_cleanup(void) {
	while (VECTOR_LEN(ctx.udp_punch_socks))
		close_udp_punch_socket(VECTOR_INDEX(ctx.udp_punch_socks, VECTOR_LEN(ctx.udp_punch_socks) - 1));

	VECTOR_FREE(ctx.udp_punch_socks);
}

/** Closes all TCP connections */
void fastd_tcp_cleanup(void) {
	while (VECTOR_LEN(ctx.tcp_socks))
		close_tcp_connection(VECTOR_INDEX(ctx.tcp_socks, VECTOR_LEN(ctx.tcp_socks) - 1), false);

	VECTOR_FREE(ctx.tcp_socks);
}
