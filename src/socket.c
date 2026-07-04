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
#include "peer.h"
#include "peer_group.h"
#include "polling.h"
#include "tcp_punch.h"

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

	free(sock);
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

		if (reset_peer && established)
			fastd_peer_reset(peer);
		else if (reset_peer)
			fastd_peer_transport_failed(peer, TRANSPORT_TCP);
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

/** Closes all unclaimed TCP punch sockets for a peer */
void fastd_tcp_punch_close_peer(fastd_peer_t *peer) {
	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.tcp_socks);) {
		fastd_socket_t *sock = VECTOR_INDEX(ctx.tcp_socks, i);

		if (sock->tcp_punch_peer != peer) {
			i++;
			continue;
		}

		close_tcp_connection(sock, false);
	}
}

/** Returns an existing TCP punch socket for a peer and remote candidate */
static fastd_socket_t *find_tcp_punch_socket(fastd_peer_t *peer, const fastd_peer_address_t *remote_addr) {
	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.tcp_socks); i++) {
		fastd_socket_t *sock = VECTOR_INDEX(ctx.tcp_socks, i);

		if (sock->tcp_punch_peer == peer && fastd_peer_address_equal(&sock->peer_addr, remote_addr))
			return sock;
	}

	return NULL;
}

/** Opens a TCP socket for active TCP hole punching */
static fastd_socket_t *open_tcp_punch_socket(fastd_peer_t *peer, const fastd_peer_address_t *remote_addr) {
	if (VECTOR_LEN(ctx.tcp_socks) >= TCP_MAX_CONNECTIONS) {
		pr_debug("not opening TCP punch connection for %P because the connection limit has been reached", peer);
		return NULL;
	}

	const fastd_socket_t *base_sock = get_default_socket(remote_addr->sa.sa_family);

	int fd = socket(
		remote_addr->sa.sa_family == AF_INET6 ? PF_INET6 : PF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
	if (fd < 0) {
		pr_debug_errno("unable to create TCP punch socket");
		return NULL;
	}

#ifdef NO_HAVE_SOCK_NONBLOCK
	fastd_setnonblock(fd);
#endif

	const int one = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)))
		pr_debug_errno("setsockopt: unable to set SO_REUSEADDR on TCP punch socket");

#ifdef SO_REUSEPORT
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)))
		pr_debug_errno("setsockopt: unable to set SO_REUSEPORT on TCP punch socket");
#endif

	set_tcp_options(fd);

#ifdef USE_BINDTODEVICE
	if (base_sock && base_sock->addr && base_sock->addr->bindtodev
	    && !fastd_peer_address_is_v6_ll(&base_sock->addr->addr)) {
		if (setsockopt(
			    fd, SOL_SOCKET, SO_BINDTODEVICE, base_sock->addr->bindtodev,
			    strlen(base_sock->addr->bindtodev))) {
			pr_debug_errno("setsockopt: unable to bind TCP punch socket to device");
			goto error;
		}
	}
#endif

#ifdef USE_PACKET_MARK
	if (conf.packet_mark) {
		if (setsockopt(fd, SOL_SOCKET, SO_MARK, &conf.packet_mark, sizeof(conf.packet_mark))) {
			pr_debug_errno("setsockopt: unable to set packet mark on TCP punch socket");
			goto error;
		}
	}
#endif

	fastd_peer_address_t local_addr = { .sa.sa_family = remote_addr->sa.sa_family };
	if (base_sock && base_sock->bound_addr && base_sock->bound_addr->sa.sa_family == remote_addr->sa.sa_family)
		local_addr = *base_sock->bound_addr;

	set_address_port(&local_addr, ntohs(fastd_peer_address_get_port(remote_addr)));

	if (bind(fd, &local_addr.sa, address_len(&local_addr))) {
		pr_debug2_errno("unable to bind TCP punch socket");
		goto error;
	}

#ifdef __ANDROID__
	if (!fastd_android_protect_socket(fd)) {
		pr_error("error protecting TCP punch socket");
		goto error;
	}
#endif

	int ret = connect(fd, &remote_addr->sa, address_len(remote_addr));
	if (ret < 0 && errno != EINPROGRESS && errno != EALREADY) {
		pr_debug_errno("TCP punch connect");
		goto error;
	}

	fastd_socket_t *sock = fastd_new0(fastd_socket_t);
	sock->fd = FASTD_POLL_FD(POLL_TYPE_SOCKET, fd);
	sock->type = SOCKET_TYPE_TCP_CONNECTION;
	sock->addr = base_sock ? base_sock->addr : NULL;
	sock->peer_addr = *remote_addr;
	sock->tcp_punch_peer = peer;
	sock->tcp_punch = true;
	sock->tcp_connecting = (ret < 0);
	sock->tcp_timeout = ctx.now + FASTD_TCP_PUNCH_TIMEOUT;
	set_bound_address(sock);

	VECTOR_ADD(ctx.tcp_socks, sock);
	fastd_poll_fd_register(&sock->fd);
	fastd_poll_fd_set_write(&sock->fd, true);

	pr_debug("opening TCP punch connection to %P[%I]", peer, remote_addr);
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
static int bind_socket(const fastd_bind_address_t *addr, bool reuseaddr_early) {
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

	if (fastd_use_offload_l2tp() && reuseaddr_early) {
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one))) {
			pr_error_errno("setsockopt: unable to set SO_REUSEADDR");
			goto error;
		}
	}

	if (bind(fd, &bind_address.sa,
		 bind_address.sa.sa_family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in))) {
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

	if (addr->bindtodev)
		pr_error(
			fastd_peer_address_is_v6_ll(&addr->addr) ? "unable to bind to %L"
								 : "unable to bind to %B on `%s'",
			&addr->addr, addr->bindtodev);
	else
		pr_error("unable to bind to %B", &addr->addr);

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

		sock->fd = FASTD_POLL_FD(POLL_TYPE_SOCKET, bind_socket(sock->addr, false));
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
static fastd_socket_t *open_dynamic_socket(const fastd_bind_address_t *addr, bool reuseaddr_early) {
	int fd = bind_socket(addr, reuseaddr_early);
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

	fastd_socket_t *sock = open_dynamic_socket(bind_address, false);
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

	fastd_socket_t *offload_sock = open_dynamic_socket(&bind_address, true);
	if (!offload_sock)
		return NULL;

	offload_sock->parent = sock;

	fastd_poll_fd_register(&offload_sock->fd);

	return offload_sock;
}

/** Closes a socket */
void fastd_socket_close(fastd_socket_t *sock) {
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

/** Returns true if the socket is a TCP connection */
bool fastd_socket_is_tcp(const fastd_socket_t *sock) {
	return sock && sock->type == SOCKET_TYPE_TCP_CONNECTION;
}

/** Returns true if the socket is a TCP connection established through TCP hole punching */
bool fastd_socket_is_tcp_punch(const fastd_socket_t *sock) {
	return fastd_socket_is_tcp(sock) && sock->tcp_punch;
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

/** Queues an initial handshake on deterministic TCP punch candidates */
static void tcp_punch_queue(fastd_peer_t *peer, const fastd_peer_address_t *remote_addr, const fastd_buffer_t *buffer) {
	if (!peer || fastd_peer_is_established(peer) || !fastd_peer_get_tcp_punch(peer))
		return;

	if (!fastd_peer_transport_allows(fastd_peer_get_transport(peer), TRANSPORT_TCP))
		return;

	if (remote_addr->sa.sa_family != AF_INET)
		return;

	uint16_t ports[FASTD_TCP_PUNCH_NUM_PORTS * FASTD_TCP_PUNCH_BUCKETS];
	size_t n_ports = fastd_tcp_punch_generate_ports(ports, array_size(ports), time(NULL));

	size_t i;
	for (i = 0; i < n_ports; i++) {
		fastd_peer_address_t punch_addr = *remote_addr;
		set_address_port(&punch_addr, ports[i]);

		fastd_socket_t *sock = find_tcp_punch_socket(peer, &punch_addr);
		if (!sock)
			sock = open_tcp_punch_socket(peer, &punch_addr);

		if (sock)
			tcp_queue(sock, peer, buffer, 0);
	}
}

/** Sends a packet over TCP if the peer is configured for TCP transport */
bool fastd_tcp_send(
	fastd_peer_t *peer, fastd_socket_t *sock, UNUSED const fastd_peer_address_t *local_addr,
	const fastd_peer_address_t *remote_addr, const fastd_buffer_t *buffer, size_t stat_size) {
	if (sock && sock->type == SOCKET_TYPE_TCP_CONNECTION) {
		if (fastd_peer_address_equal(&sock->peer_addr, remote_addr) && (!sock->peer || !peer || sock->peer == peer)) {
			if (!stat_size && sock->peer == peer)
				tcp_punch_queue(peer, remote_addr, buffer);

			return tcp_queue(sock, peer, buffer, stat_size);
		}

		fastd_stats_add(peer, STAT_TX_ERROR, stat_size);
		return true;
	}

	if (!peer)
		return false;

	fastd_peer_transport_t transport = fastd_peer_get_transport(peer);
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
		fastd_stats_add(peer, STAT_TX_ERROR, stat_size);
		return true;
	}

	if (!stat_size)
		tcp_punch_queue(peer, remote_addr, buffer);

	return tcp_queue(tcp_sock, peer, buffer, stat_size);
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

/** Closes all TCP connections */
void fastd_tcp_cleanup(void) {
	while (VECTOR_LEN(ctx.tcp_socks))
		close_tcp_connection(VECTOR_INDEX(ctx.tcp_socks, VECTOR_LEN(ctx.tcp_socks) - 1), false);

	VECTOR_FREE(ctx.tcp_socks);
}
