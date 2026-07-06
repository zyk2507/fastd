// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Implementations of functions for peer management
*/

#include "peer.h"
#include "discovery.h"
#include "handshake.h"
#include "hole_punch.h"
#include "offload/offload.h"
#include "peer_group.h"
#include "peer_hashtable.h"
#include "polling.h"
#include "turn.h"

#include <arpa/inet.h>
#include <sys/wait.h>

#define FASTD_DIRECT_MAC_LIMIT 256
#define FASTD_DIRECT_CANDIDATE_LIMIT 256
#define FASTD_DIRECT_CANDIDATE_ATTEMPT_INTERVAL 5000
#define FASTD_DIRECT_CANDIDATE_PRIORITY_REALM 80
#define FASTD_DIRECT_CANDIDATE_PRIORITY_DISCOVERY 100
#define FASTD_PUNCH_SUPPRESSION_LIMIT 32
#define FASTD_PUNCH_SUPPRESSION_TIME 60000


static bool direct_candidate_valid(const fastd_peer_direct_candidate_t *candidate);
static bool send_handshake_address(fastd_peer_t *peer, const fastd_peer_address_t *addr);

/** Adds address and port of an fastd_peer_address_t to \e env */
static void fastd_peer_set_shell_env_addr(
	fastd_shell_env_t *env, const fastd_peer_address_t *addr, const char *address_var, const char *port_var) {
	/* both INET6_ADDRSTRLEN and IFNAMSIZ already include space for the zero termination, so there is no need to add
	 * space for the '%' here. */
	char buf[INET6_ADDRSTRLEN + IFNAMSIZ];

	switch (addr ? addr->sa.sa_family : AF_UNSPEC) {
	case AF_INET:
		inet_ntop(AF_INET, &addr->in.sin_addr, buf, sizeof(buf));
		fastd_shell_env_set(env, address_var, buf);

		snprintf(buf, sizeof(buf), "%u", ntohs(addr->in.sin_port));
		fastd_shell_env_set(env, port_var, buf);

		return;

	case AF_INET6:
		inet_ntop(AF_INET6, &addr->in6.sin6_addr, buf, sizeof(buf));

		if (IN6_IS_ADDR_LINKLOCAL(&addr->in6.sin6_addr)) {
			if (if_indextoname(addr->in6.sin6_scope_id, buf + strlen(buf) + 1))
				buf[strlen(buf)] = '%';
		}

		fastd_shell_env_set(env, address_var, buf);

		snprintf(buf, sizeof(buf), "%u", ntohs(addr->in6.sin6_port));
		fastd_shell_env_set(env, port_var, buf);

		return;
	}

	fastd_shell_env_set(env, address_var, NULL);
	fastd_shell_env_set(env, port_var, NULL);
}


/** Adds peer-specific fields to \e env */
void fastd_peer_set_shell_env(
	fastd_shell_env_t *env, const fastd_peer_t *peer, const fastd_peer_address_t *local_addr,
	const fastd_peer_address_t *peer_addr) {

	fastd_shell_env_set(env, "PEER_NAME", peer ? peer->name : NULL);

	const char *ifname = NULL;
	uint16_t mtu = 0;
	if (peer) {
		if (peer->offload) {
			peer->offload->get_iface(peer->offload_state, &ifname, &mtu);
		} else if (peer->iface) {
			ifname = peer->iface->name;
			mtu = peer->iface->mtu;
		}
	}
	fastd_shell_env_set_iface(env, ifname, mtu);

	fastd_peer_set_shell_env_addr(env, local_addr, "LOCAL_ADDRESS", "LOCAL_PORT");
	fastd_peer_set_shell_env_addr(env, peer_addr, "PEER_ADDRESS", "PEER_PORT");

	conf.protocol->set_shell_env(env, peer);
}

/** Executes a shell command, providing peer-specific enviroment fields */
void fastd_peer_exec_shell_command(
	const fastd_shell_command_t *command, const fastd_peer_t *peer, const fastd_peer_address_t *local_addr,
	const fastd_peer_address_t *peer_addr, bool sync) {
	fastd_shell_env_t *env = fastd_shell_env_alloc();
	fastd_peer_set_shell_env(env, peer, local_addr, peer_addr);

	if (sync)
		fastd_shell_command_exec_sync(command, env, NULL);
	else
		fastd_shell_command_exec(command, env);

	fastd_shell_env_free(env);
}

/** Calls the on-up command */
static inline void on_up(const fastd_peer_t *peer, bool sync) {
	const fastd_shell_command_t *on_up = fastd_peer_group_lookup_peer_shell_command(peer, on_up);
	fastd_peer_exec_shell_command(on_up, peer, NULL, NULL, sync);
}

/** Calls the on-down command */
static inline void on_down(const fastd_peer_t *peer, bool sync) {
	const fastd_shell_command_t *on_down = fastd_peer_group_lookup_peer_shell_command(peer, on_down);
	fastd_peer_exec_shell_command(on_down, peer, NULL, NULL, sync);
}

/** Executes the on-establish command for a peer */
static inline void on_establish(const fastd_peer_t *peer) {
	const fastd_shell_command_t *on_establish = fastd_peer_group_lookup_peer_shell_command(peer, on_establish);
	fastd_peer_exec_shell_command(on_establish, peer, &peer->local_address, &peer->address, false);
}

/** Executes the on-disestablish command for a peer */
static inline void on_disestablish(const fastd_peer_t *peer) {
	const fastd_shell_command_t *on_disestablish =
		fastd_peer_group_lookup_peer_shell_command(peer, on_disestablish);
	fastd_peer_exec_shell_command(on_disestablish, peer, &peer->local_address, &peer->address, false);
}

/** Compares two peers by their peer ID */
static int peer_id_cmp(fastd_peer_t *const *a, fastd_peer_t *const *b) {
	if ((*a)->id == (*b)->id)
		return 0;
	else if ((*a)->id < (*b)->id)
		return -1;
	else
		return 1;
}

/** Finds the entry for a peer with a specified ID in the array \e ctx.peers */
static fastd_peer_t **peer_p_find_by_id(uint64_t id) {
	fastd_peer_t key = { .id = id };
	fastd_peer_t *const keyp = &key;

	return VECTOR_BSEARCH(&keyp, ctx.peers, peer_id_cmp);
}

/** Finds the index of a peer with a specified ID in the array \e ctx.peers */
static size_t peer_index_find_by_id(uint64_t id) {
	fastd_peer_t **ret = peer_p_find_by_id(id);

	if (!ret)
		exit_bug("peer_index_find_by_id: not found");

	return ret - VECTOR_DATA(ctx.peers);
}

/** Finds the index of a peer in the array \e ctx.peers */
static inline size_t peer_index(fastd_peer_t *peer) {
	return peer_index_find_by_id(peer->id);
}

/** Finds a peer with a specified ID */
fastd_peer_t *fastd_peer_find_by_id(uint64_t id) {
	fastd_peer_t **ret = peer_p_find_by_id(id);

	if (ret)
		return *ret;
	else
		return NULL;
}

/** Closes and frees a peer's dynamic socket */
static inline void free_socket(fastd_peer_t *peer) {
	fastd_hole_punch_close_peer(peer);

	if (!peer->sock)
		return;

	if (fastd_peer_is_socket_dynamic(peer)) {
		if (peer->sock->peer != peer)
			exit_bug("dynamic peer socket mismatch");

		fastd_socket_t *sock = peer->sock;
		fastd_socket_close(sock);
		fastd_socket_free_dynamic(sock);
	}

	peer->sock = NULL;
}

/** Checks if a socket reference points to a dynamically allocated socket */
static inline bool socket_ref_dynamic(const fastd_socket_t *sock) {
	return sock && (!sock->addr || sock->type == SOCKET_TYPE_TCP_CONNECTION);
}

/** Checks whether a peer should send periodic NAT traversal keepalives */
bool fastd_peer_nat_traversal_keepalive_enabled(const fastd_peer_t *peer) {
	if (!conf.punch_keepalive)
		return false;

	if (conf.punch_control_relay)
		return true;

	if (peer && peer->realm && conf.realm.server)
		return true;

	if (fastd_peer_get_hole_punch(peer) != HOLE_PUNCH_OFF)
		return true;

	if (fastd_peer_get_turn_relay(peer) || fastd_peer_get_turn_servers(peer))
		return true;

	if (fastd_peer_get_port_mapping_mode(peer) != PORT_MAPPING_OFF)
		return true;

	if (peer && (peer->direct_established || peer->backup_direct_established ||
		     fastd_peer_has_direct_candidate(peer) || fastd_peer_has_backup_path(peer)))
		return true;

	return false;
}

/** Resets the active path keepalive timeout */
void fastd_peer_clear_keepalive(fastd_peer_t *peer) {
	unsigned interval =
		fastd_peer_nat_traversal_keepalive_enabled(peer) ? conf.punch_keepalive_interval : KEEPALIVE_TIMEOUT;
	peer->keepalive_timeout = ctx.now + interval;
}

/** Closes and frees the backup path socket if it is dynamic */
static void free_backup_socket(fastd_peer_t *peer) {
	fastd_socket_t *sock = peer->backup_sock;
	if (!sock)
		return;

	peer->backup_sock = NULL;

	if (!socket_ref_dynamic(sock) || sock == peer->sock)
		return;

	if (sock->peer == peer)
		sock->peer = NULL;

	fastd_socket_close(sock);
	fastd_socket_free_dynamic(sock);
}

/** Checks if a peer group has any contraints which might cause connection attempts to be rejected */
static inline bool has_group_config_constraints(const fastd_peer_group_t *group) {
	for (; group; group = group->parent) {
		if (group->max_connections >= 0)
			return true;
	}

	return false;
}

/**
   Resets a peer's socket

   If the peer's old socket is dynamic, it is closed. Then either a new dynamic socket is opened
   or a default socket is used.
*/
void fastd_peer_reset_socket(fastd_peer_t *peer) {
	if (peer->address.sa.sa_family == AF_UNSPEC) {
		free_socket(peer);
		return;
	}

	if (!fastd_peer_is_socket_dynamic(peer))
		return;

	pr_debug("resetting socket for peer %P", peer);

	free_socket(peer);

	fastd_peer_transport_t transport = fastd_peer_get_transport(peer);
	if (transport == TRANSPORT_AUTO) {
		if (!peer->transport_probe)
			peer->transport_probe = TRANSPORT_TCP;

		transport = peer->transport_probe;
	}

	if (transport == TRANSPORT_TCP) {
		const fastd_socket_t *base_sock = NULL;

		switch (peer->address.sa.sa_family) {
		case AF_INET:
			base_sock = ctx.sock_default_v4;
			break;

		case AF_INET6:
			base_sock = ctx.sock_default_v6;
			break;
		}

		peer->sock = fastd_socket_open_tcp(peer, base_sock, &peer->address);
		if (peer->sock)
			return;

		fastd_peer_transport_failed(peer, TRANSPORT_TCP);
		if (fastd_peer_get_transport(peer) != TRANSPORT_AUTO)
			return;
	}

	switch (peer->address.sa.sa_family) {
	case AF_INET:
		if (ctx.sock_default_v4)
			peer->sock = ctx.sock_default_v4;
		else
			peer->sock = fastd_socket_open(peer, AF_INET);
		break;

	case AF_INET6:
		if (ctx.sock_default_v6)
			peer->sock = ctx.sock_default_v6;
		else
			peer->sock = fastd_socket_open(peer, AF_INET6);
	}
}

/** Schedules the peer maintenance task (or removes the scheduled task if there's nothing to do) */
static void schedule_peer_task(fastd_peer_t *peer) {
	bool has_backup_path = fastd_peer_has_backup_path(peer);
	fastd_timeout_t active_path_timeout = has_backup_path ? peer->active_path_timeout : FASTD_TIMEOUT_INV;
	fastd_timeout_t backup_reset_timeout = has_backup_path ? peer->backup_reset_timeout : FASTD_TIMEOUT_INV;
	fastd_timeout_t backup_keepalive_timeout = has_backup_path ? peer->backup_keepalive_timeout : FASTD_TIMEOUT_INV;

	fastd_timeout_t timeout = fastd_timeout_min(
		peer->reset_timeout,
		fastd_timeout_min(
			peer->keepalive_timeout,
			fastd_timeout_min(
				peer->next_handshake,
				fastd_timeout_min(
					active_path_timeout,
					fastd_timeout_min(backup_reset_timeout, backup_keepalive_timeout)))));

	if (timeout == FASTD_TIMEOUT_INV) {
		pr_debug2("Removing scheduled task for %P", peer);
		fastd_task_unschedule(&peer->task);
	} else if (fastd_task_timeout(&peer->task) > timeout) {
		pr_debug2("Replacing scheduled task for %P", peer);
		fastd_task_unschedule(&peer->task);
		fastd_task_schedule(&peer->task, TASK_TYPE_PEER, timeout);
	} else {
		pr_debug2("Keeping scheduled task for %P", peer);
	}
}

/** Sets the timeout for the next handshake without actually rescheduling */
static void set_next_handshake(fastd_peer_t *peer, int delay) {
	peer->next_handshake = ctx.now + delay;
}

/** Sets the timeout for the next handshake to the default delay and jitter without actually rescheduling */
static void set_next_handshake_default(fastd_peer_t *peer) {
	set_next_handshake(peer, fastd_peer_handshake_default_rand());
}

/**
   Schedules a handshake after the given delay

   @param peer	the peer
   @param delay	the delay in milliseconds
*/
void fastd_peer_schedule_handshake(fastd_peer_t *peer, int delay) {
	set_next_handshake(peer, delay);
	schedule_peer_task(peer);
}

/** Handles a failed transport probe */
void fastd_peer_transport_failed(fastd_peer_t *peer, fastd_peer_transport_t transport) {
	if (!peer || fastd_peer_get_transport(peer) != TRANSPORT_AUTO || fastd_peer_is_established(peer))
		return;

	if (transport != TRANSPORT_TCP || peer->transport_probe != TRANSPORT_TCP)
		return;

	peer->transport_probe = TRANSPORT_UDP;
	peer->last_handshake_timeout = ctx.now;
	peer->last_handshake_address.sa.sa_family = AF_UNSPEC;
	fastd_peer_schedule_handshake(peer, 0);
}

/** Checks if the peer group \e group1 lies in \e group2 */
static inline bool is_group_in(const fastd_peer_group_t *group1, const fastd_peer_group_t *group2) {
	while (group1) {
		if (group1 == group2)
			return true;

		group1 = group1->parent;
	}

	return false;
}

/** Checks if a peer lies in a peer group */
static bool is_peer_in_group(const fastd_peer_t *peer, const fastd_peer_group_t *group) {
	return is_group_in(peer->group, group);
}

/**
   Resets a peer (internal function)

   Disestablished the current connection with the peer (if any) and drops any scheduled handshake.

   After a call to reset_peer a peer must be deleted by delete_peer or re-initialized by setup_peer.
*/
static void reset_peer(fastd_peer_t *peer) {
	if (fastd_peer_is_established(peer)) {
		on_disestablish(peer);
		pr_info("connection with %P disestablished.", peer);
	}

	free_socket(peer);
	fastd_turn_reset_peer(peer);

	conf.protocol->reset_peer_state(peer);
	fastd_peer_clear_backup_path(peer);
	peer->active_path_timeout = FASTD_TIMEOUT_INV;
	peer->payload_candidate_timeout = FASTD_TIMEOUT_INV;
	peer->payload_candidate_address.sa.sa_family = AF_UNSPEC;

	size_t i, deleted = 0;
	for (i = 0; i < VECTOR_LEN(ctx.eth_addrs); i++) {
		if (VECTOR_INDEX(ctx.eth_addrs, i).peer == peer) {
			deleted++;
		} else if (deleted) {
			VECTOR_INDEX(ctx.eth_addrs, i - deleted) = VECTOR_INDEX(ctx.eth_addrs, i);
		}
	}

	VECTOR_RESIZE(ctx.eth_addrs, VECTOR_LEN(ctx.eth_addrs) - deleted);

	fastd_task_unschedule(&peer->task);

	fastd_peer_hashtable_remove(peer);

	memset(&peer->stats, 0, sizeof(peer->stats));

	peer->address.sa.sa_family = AF_UNSPEC;
	peer->local_address.sa.sa_family = AF_UNSPEC;
	peer->direct_established = false;
	peer->transport_probe = TRANSPORT_UNSET;
	peer->turn_fallback_timeout = FASTD_TIMEOUT_INV;
	peer->state = STATE_INACTIVE;

	if (peer->offload) {
		on_down(peer, false);
		peer->offload->free_session(peer->offload_state);
		peer->offload = NULL;
	}

	if (!conf.iface_persist || peer->config_state == CONFIG_DISABLED || fastd_peer_is_dynamic(peer)) {
		if (peer->iface && peer->iface->peer) {
			on_down(peer, false);
			fastd_iface_close(peer->iface);
		}

		peer->iface = NULL;
	}
}

/**
   Starts the first handshake with a newly setup peer

   If a peer group has a peer limit the handshakes will be delayed between 0 and 3 seconds
   make the choice of peers random (it will be biased by the latency, which might or might not be
   what a user wants)
*/
static void init_handshake(fastd_peer_t *peer) {
	unsigned delay = 0;
	if (has_group_config_constraints(peer->group))
		delay = fastd_rand(0, 3000);

	peer->state = STATE_HANDSHAKE;

	fastd_peer_schedule_handshake(peer, delay);
}

/** Handles an asynchronous DNS resolve response */
void fastd_peer_handle_resolve(
	fastd_peer_t *peer, fastd_remote_t *remote, size_t n_addresses, const fastd_peer_address_t *addresses) {
	free(remote->addresses);
	remote->addresses = fastd_new_array(n_addresses, fastd_peer_address_t);
	memcpy(remote->addresses, addresses, n_addresses * sizeof(fastd_peer_address_t));

	remote->n_addresses = n_addresses;
	remote->current_address = 0;

	if (peer->state == STATE_RESOLVING)
		init_handshake(peer);
}

/** Initializes a peer */
static void setup_peer(fastd_peer_t *peer) {
	if (VECTOR_LEN(peer->remotes) == 0) {
		peer->next_remote = -1;
	} else {
		size_t i;
		for (i = 0; i < VECTOR_LEN(peer->remotes); i++) {
			fastd_remote_t *remote = &VECTOR_INDEX(peer->remotes, i);

			remote->last_resolve_timeout = ctx.now;

			if (!remote->hostname) {
				remote->n_addresses = 1;
				remote->addresses = &remote->address;
			}
		}

		peer->next_remote = 0;
	}

	peer->last_handshake_timeout = ctx.now;
	peer->last_handshake_address.sa.sa_family = AF_UNSPEC;

	peer->last_handshake_response_timeout = ctx.now;
	peer->last_handshake_response_address.sa.sa_family = AF_UNSPEC;

	peer->establish_handshake_timeout = ctx.now;
	peer->turn_fallback_timeout = FASTD_TIMEOUT_INV;
	peer->direct_established = false;
	peer->punch_timeout = FASTD_TIMEOUT_INV;
	peer->next_punch_announce = ctx.now;
	peer->next_punch_relay = ctx.now;
	peer->punch_success_counted = false;

#ifdef WITH_DYNAMIC_PEERS
	peer->verify_timeout = ctx.now;
	peer->verify_valid_timeout = ctx.now;
#endif

	peer->next_handshake = FASTD_TIMEOUT_INV;
	peer->reset_timeout = FASTD_TIMEOUT_INV;
	peer->keepalive_timeout = FASTD_TIMEOUT_INV;
	peer->active_path_timeout = FASTD_TIMEOUT_INV;
	peer->backup_reset_timeout = FASTD_TIMEOUT_INV;
	peer->backup_keepalive_timeout = FASTD_TIMEOUT_INV;
	peer->payload_candidate_timeout = FASTD_TIMEOUT_INV;

	if (fastd_peer_is_dynamic(peer))
		peer->reset_timeout = ctx.now;

	if (!fastd_peer_is_enabled(peer))
		/* Keep the peer in STATE_INACTIVE */
		return;

	if (ctx.iface) {
		peer->iface = ctx.iface;
	} else if (conf.iface_persist && !peer->iface && !fastd_peer_is_dynamic(peer)) {
		peer->iface = fastd_iface_open(peer);
		if (peer->iface)
			on_up(peer, true);
		else if (!peer->config_source_dir)
			/* Fail for statically configured peers;
			   an error message has already been printed by fastd_iface_open() */
			exit(1);
	}

	fastd_remote_t *next_remote = fastd_peer_get_next_remote(peer);
	if (next_remote) {
		next_remote->current_address = 0;

		if (next_remote->hostname) {
			peer->state = STATE_RESOLVING;
			fastd_resolve_peer(peer, next_remote);
			set_next_handshake_default(peer);
		} else {
			init_handshake(peer);
		}
	} else {
		peer->state = STATE_PASSIVE;
	}

	schedule_peer_task(peer);
}

/**
   Frees a peer

   If the peer has already been added to the peer list,
   use fastd_peer_delete() instead.
*/
void fastd_peer_free(fastd_peer_t *peer) {
	free(peer->key);

	size_t i;
	for (i = 0; i < VECTOR_LEN(peer->remotes); i++) {
		fastd_remote_t *remote = &VECTOR_INDEX(peer->remotes, i);

		if (remote->hostname) {
			free(remote->addresses);
			free(remote->hostname);
		}
	}

	VECTOR_FREE(peer->remotes);
	VECTOR_FREE(peer->direct_candidates);
	VECTOR_FREE(peer->punch_suppressions);
	VECTOR_FREE(peer->direct_macs);
	fastd_turn_server_free(peer->turn_servers);

	free(peer->realm);
	free(peer->ifname);
	free(peer->name);
	free(peer);
}

/** Deletes a peer */
static void delete_peer(fastd_peer_t *peer) {
	if (fastd_peer_is_dynamic(peer) || peer->config_source_dir)
		pr_verbose("deleting peer %P", peer);

	fastd_discovery_peer_deleted(peer);

	size_t i = peer_index(peer);
	VECTOR_DELETE(ctx.peers, i);

	conf.protocol->free_peer_state(peer);

	if (peer->iface && peer->iface->peer) {
		on_down(peer, true);
		fastd_iface_close(peer->iface);
	}

	fastd_peer_free(peer);
}


/** Checks if two fastd_peer_address_t are equal */
bool fastd_peer_address_equal(const fastd_peer_address_t *addr1, const fastd_peer_address_t *addr2) {
	if (addr1->sa.sa_family != addr2->sa.sa_family)
		return false;

	switch (addr1->sa.sa_family) {
	case AF_UNSPEC:
		break;

	case AF_INET:
		if (addr1->in.sin_addr.s_addr != addr2->in.sin_addr.s_addr)
			return false;
		if (addr1->in.sin_port != addr2->in.sin_port)
			return false;
		break;

	case AF_INET6:
		if (!IN6_ARE_ADDR_EQUAL(&addr1->in6.sin6_addr, &addr2->in6.sin6_addr))
			return false;
		if (addr1->in6.sin6_port != addr2->in6.sin6_port)
			return false;
		if (IN6_IS_ADDR_LINKLOCAL(&addr1->in6.sin6_addr)) {
			if (addr1->in6.sin6_scope_id != addr2->in6.sin6_scope_id)
				return false;
		}
	}

	return true;
}

/** Checks if two addresses have the same address family and IP address, ignoring the port */
static bool fastd_peer_address_ip_equal(const fastd_peer_address_t *addr1, const fastd_peer_address_t *addr2) {
	if (addr1->sa.sa_family != addr2->sa.sa_family)
		return false;

	switch (addr1->sa.sa_family) {
	case AF_INET:
		return addr1->in.sin_addr.s_addr == addr2->in.sin_addr.s_addr;

	case AF_INET6:
		if (!IN6_ARE_ADDR_EQUAL(&addr1->in6.sin6_addr, &addr2->in6.sin6_addr))
			return false;

		return !IN6_IS_ADDR_LINKLOCAL(&addr1->in6.sin6_addr) ||
		       addr1->in6.sin6_scope_id == addr2->in6.sin6_scope_id;

	default:
		return false;
	}
}

/** If \e addr is a v4-mapped IPv6 address, it is converted to an IPv4 address */
void fastd_peer_address_simplify(fastd_peer_address_t *addr) {
	if (addr->sa.sa_family == AF_INET6 && IN6_IS_ADDR_V4MAPPED(&addr->in6.sin6_addr)) {
		struct sockaddr_in6 mapped = addr->in6;

		memset(addr, 0, sizeof(fastd_peer_address_t));
		addr->in.sin_family = AF_INET;
		addr->in.sin_port = mapped.sin6_port;
		memcpy(&addr->in.sin_addr.s_addr, &mapped.sin6_addr.s6_addr[12], 4);
	}
}

/** If \e addr is an IPv4 address, it is converted to a v4-mapped IPv6 address */
void fastd_peer_address_widen(fastd_peer_address_t *addr) {
	if (addr->sa.sa_family == AF_INET) {
		struct sockaddr_in addr4 = addr->in;

		memset(addr, 0, sizeof(fastd_peer_address_t));
		addr->in6.sin6_family = AF_INET6;
		addr->in6.sin6_port = addr4.sin_port;
		addr->in6.sin6_addr.s6_addr[10] = 0xff;
		addr->in6.sin6_addr.s6_addr[11] = 0xff;
		memcpy(&addr->in6.sin6_addr.s6_addr[12], &addr4.sin_addr.s_addr, 4);
	}
}


/** Resets a peer's address to the unspecified address */
static inline void reset_peer_address(fastd_peer_t *peer) {
	if (fastd_peer_is_established(peer)) {
		fastd_peer_reset(peer);
	} else {
		fastd_peer_hashtable_remove(peer);
		peer->address.sa.sa_family = AF_UNSPEC;
	}
}

/** Checks if an address is statically configured for a peer */
bool fastd_peer_owns_address(const fastd_peer_t *peer, const fastd_peer_address_t *addr) {
	if (fastd_peer_is_floating(peer))
		return false;

	size_t i;
	for (i = 0; i < VECTOR_LEN(peer->remotes); i++) {
		fastd_remote_t *remote = &VECTOR_INDEX(peer->remotes, i);

		if (remote->hostname)
			continue;

		if (fastd_peer_address_equal(&remote->address, addr))
			return true;
	}

	return false;
}

/** Checks if an address matches any of the configured or resolved remotes of a peer */
bool fastd_peer_matches_address(const fastd_peer_t *peer, const fastd_peer_address_t *addr) {
	if (fastd_peer_is_floating(peer))
		return true;

	if (fastd_peer_has_direct_candidate(peer)) {
		fastd_peer_transport_t transport = fastd_peer_get_transport(peer);
		bool can_hole_punch = (fastd_peer_hole_punch_allows(peer, TRANSPORT_UDP) &&
				       fastd_peer_transport_allows(transport, TRANSPORT_UDP)) ||
				      (fastd_peer_hole_punch_allows(peer, TRANSPORT_TCP) &&
				       fastd_peer_transport_allows(transport, TRANSPORT_TCP));

		size_t i;
		for (i = 0; i < VECTOR_LEN(peer->direct_candidates); i++) {
			const fastd_peer_direct_candidate_t *candidate = &VECTOR_INDEX(peer->direct_candidates, i);
			if (!direct_candidate_valid(candidate))
				continue;

			if (fastd_peer_address_equal(&candidate->remote, addr))
				return true;

			if (addr->sa.sa_family == AF_INET && can_hole_punch &&
			    fastd_hole_punch_port_valid(ntohs(fastd_peer_address_get_port(addr)), time(NULL)) &&
			    fastd_peer_address_ip_equal(&candidate->remote, addr))
				return true;
		}
	}

	size_t i, j;
	for (i = 0; i < VECTOR_LEN(peer->remotes); i++) {
		fastd_remote_t *remote = &VECTOR_INDEX(peer->remotes, i);

		for (j = 0; j < remote->n_addresses; j++) {
			if (fastd_peer_address_equal(&remote->addresses[j], addr))
				return true;
		}
	}

	fastd_peer_transport_t transport = fastd_peer_get_transport(peer);
	bool can_hole_punch = (fastd_peer_hole_punch_allows(peer, TRANSPORT_UDP) &&
			       fastd_peer_transport_allows(transport, TRANSPORT_UDP)) ||
			      (fastd_peer_hole_punch_allows(peer, TRANSPORT_TCP) &&
			       fastd_peer_transport_allows(transport, TRANSPORT_TCP));

	if (addr->sa.sa_family == AF_INET && can_hole_punch &&
	    fastd_hole_punch_port_valid(ntohs(fastd_peer_address_get_port(addr)), time(NULL))) {
		for (i = 0; i < VECTOR_LEN(peer->remotes); i++) {
			fastd_remote_t *remote = &VECTOR_INDEX(peer->remotes, i);

			for (j = 0; j < remote->n_addresses; j++) {
				if (fastd_peer_address_ip_equal(&remote->addresses[j], addr))
					return true;
			}
		}
	}

	return false;
}

/** Adds one relay-discovered MAC address to a direct peer */
static void add_direct_mac(fastd_peer_t *peer, fastd_eth_addr_t mac) {
	if (!fastd_eth_addr_is_unicast(mac))
		return;

	size_t i;
	for (i = 0; i < VECTOR_LEN(peer->direct_macs); i++) {
		if (!memcmp(&VECTOR_INDEX(peer->direct_macs, i), &mac, sizeof(mac)))
			return;
	}

	if (VECTOR_LEN(peer->direct_macs) >= FASTD_DIRECT_MAC_LIMIT)
		return;

	VECTOR_ADD(peer->direct_macs, mac);
}

/** Checks whether a direct candidate is still usable */
static bool direct_candidate_valid(const fastd_peer_direct_candidate_t *candidate) {
	return candidate->remote.sa.sa_family != AF_UNSPEC && !fastd_timed_out(candidate->timeout);
}

/** Checks whether a punch-control candidate has exhausted its configured attempts */
static bool direct_candidate_attempts_exhausted(const fastd_peer_direct_candidate_t *candidate) {
	return candidate->source == DIRECT_CANDIDATE_PUNCH_CONTROL && conf.punch_max_attempts &&
	       candidate->attempts >= conf.punch_max_attempts;
}

/** Checks whether a punch suppression entry is still active */
static bool punch_suppression_valid(const fastd_peer_punch_suppression_t *suppression) {
	return suppression->remote.sa.sa_family != AF_UNSPEC && !fastd_timed_out(suppression->timeout);
}

/** Checks whether two direct candidates describe the same endpoint path */
static bool direct_candidate_equal(
	const fastd_peer_direct_candidate_t *candidate, fastd_peer_t *relay, const fastd_peer_address_t *remote_addr) {
	return candidate->relay == relay && fastd_peer_address_equal(&candidate->remote, remote_addr);
}

/** Clears the cached selected direct candidate */
static void clear_direct_candidate_cache(fastd_peer_t *peer) {
	peer->direct_relay = NULL;
	memset(&peer->direct_remote, 0, sizeof(peer->direct_remote));
	peer->direct_remote_timeout = FASTD_TIMEOUT_INV;
	peer->direct_remote_source = DIRECT_CANDIDATE_REALM;
	peer->direct_remote_exact_udp = false;
	peer->direct_remote_udp_punch_sockets = 0;
}

/** Removes expired punch suppression entries */
static void compact_punch_suppressions(fastd_peer_t *peer) {
	size_t i;
	for (i = 0; i < VECTOR_LEN(peer->punch_suppressions);) {
		if (punch_suppression_valid(&VECTOR_INDEX(peer->punch_suppressions, i))) {
			i++;
			continue;
		}

		VECTOR_DELETE(peer->punch_suppressions, i);
	}
}

/** Suppresses one failed punch endpoint for a short cooldown period */
static void suppress_punch_candidate(fastd_peer_t *peer, const fastd_peer_address_t *remote_addr) {
	compact_punch_suppressions(peer);

	size_t i;
	for (i = 0; i < VECTOR_LEN(peer->punch_suppressions); i++) {
		fastd_peer_punch_suppression_t *entry = &VECTOR_INDEX(peer->punch_suppressions, i);
		if (fastd_peer_address_equal(&entry->remote, remote_addr)) {
			entry->timeout = ctx.now + FASTD_PUNCH_SUPPRESSION_TIME;
			return;
		}
	}

	if (VECTOR_LEN(peer->punch_suppressions) >= FASTD_PUNCH_SUPPRESSION_LIMIT) {
		size_t victim = 0;
		for (i = 1; i < VECTOR_LEN(peer->punch_suppressions); i++) {
			if (VECTOR_INDEX(peer->punch_suppressions, i).timeout <
			    VECTOR_INDEX(peer->punch_suppressions, victim).timeout)
				victim = i;
		}

		VECTOR_DELETE(peer->punch_suppressions, victim);
	}

	VECTOR_ADD(
		peer->punch_suppressions, ((fastd_peer_punch_suppression_t){
						  .remote = *remote_addr,
						  .timeout = ctx.now + FASTD_PUNCH_SUPPRESSION_TIME,
					  }));
}

#ifdef WITH_TESTS

/** Test wrapper for punch endpoint suppression */
void fastd_peer_test_suppress_punch_candidate(fastd_peer_t *peer, const fastd_peer_address_t *remote_addr) {
	suppress_punch_candidate(peer, remote_addr);
}

#endif

/** Updates the cached selected direct candidate */
static void set_direct_candidate_cache(fastd_peer_t *peer, const fastd_peer_direct_candidate_t *candidate) {
	peer->direct_relay = candidate->relay;
	peer->direct_remote = candidate->remote;
	peer->direct_remote_timeout = candidate->timeout;
	peer->direct_remote_source = candidate->source;
	peer->direct_remote_exact_udp = candidate->exact_udp_punch;
	peer->direct_remote_udp_punch_sockets = candidate->udp_punch_sockets;
}

/** Records a successful direct punch-control path once per peer session */
static void count_direct_success(fastd_peer_t *peer, fastd_peer_direct_candidate_source_t source) {
	if (source != DIRECT_CANDIDATE_PUNCH_CONTROL || peer->punch_success_counted)
		return;

	ctx.punch_direct_success++;
	peer->punch_success_counted = true;
	VECTOR_RESIZE(peer->punch_suppressions, 0);

	size_t i;
	for (i = 0; i < VECTOR_LEN(peer->direct_candidates); i++) {
		fastd_peer_direct_candidate_t *candidate = &VECTOR_INDEX(peer->direct_candidates, i);
		if (candidate->source == DIRECT_CANDIDATE_PUNCH_CONTROL)
			candidate->attempts = 0;
	}
}

/** Finds the source of a direct endpoint candidate matching an address exactly */
bool fastd_peer_get_direct_candidate_source(
	const fastd_peer_t *peer, const fastd_peer_address_t *remote_addr,
	fastd_peer_direct_candidate_source_t *source) {
	bool found = false;
	uint8_t priority = 0;

	size_t i;
	for (i = 0; i < VECTOR_LEN(peer->direct_candidates); i++) {
		const fastd_peer_direct_candidate_t *candidate = &VECTOR_INDEX(peer->direct_candidates, i);
		if (!direct_candidate_valid(candidate))
			continue;

		if (!fastd_peer_address_equal(&candidate->remote, remote_addr))
			continue;

		if (!found || candidate->priority > priority) {
			found = true;
			priority = candidate->priority;
			if (source)
				*source = candidate->source;
		}
	}

	return found;
}

/** Finds the selection quality of a direct endpoint candidate */
static bool direct_candidate_quality(
	const fastd_peer_t *peer, const fastd_peer_address_t *remote_addr, uint8_t *priority, uint8_t *order) {
	bool found = false;
	uint8_t best_priority = 0;
	uint8_t best_order = UINT8_MAX;

	size_t i;
	for (i = 0; i < VECTOR_LEN(peer->direct_candidates); i++) {
		const fastd_peer_direct_candidate_t *candidate = &VECTOR_INDEX(peer->direct_candidates, i);
		if (!direct_candidate_valid(candidate) || !fastd_peer_address_equal(&candidate->remote, remote_addr))
			continue;

		if (!found || candidate->priority > best_priority ||
		    (candidate->priority == best_priority && candidate->order < best_order)) {
			found = true;
			best_priority = candidate->priority;
			best_order = candidate->order;
		}
	}

	if (priority)
		*priority = best_priority;
	if (order)
		*order = best_order;
	return found;
}

/** Returns true if a new candidate should replace the current backup candidate */
static bool direct_candidate_preferred(
	const fastd_peer_t *peer, const fastd_peer_address_t *new_addr, const fastd_peer_address_t *old_addr) {
	uint8_t new_priority, old_priority, new_order, old_order;
	if (!direct_candidate_quality(peer, new_addr, &new_priority, &new_order))
		return false;
	if (!direct_candidate_quality(peer, old_addr, &old_priority, &old_order))
		return true;

	return new_priority > old_priority || (new_priority == old_priority && new_order < old_order);
}

/** Returns true if one direct candidate has a higher selection quality than another address */
bool fastd_peer_direct_candidate_preferred(
	const fastd_peer_t *peer, const fastd_peer_address_t *new_addr, const fastd_peer_address_t *old_addr) {
	return direct_candidate_preferred(peer, new_addr, old_addr);
}

/** Marks an established peer as direct when its address matches a direct candidate */
static void mark_direct_established(
	fastd_peer_t *peer, const fastd_peer_address_t *remote_addr, fastd_peer_direct_candidate_source_t source) {
	if (!fastd_peer_is_established(peer) || remote_addr->sa.sa_family == AF_UNSPEC)
		return;

	if (!fastd_peer_address_equal(remote_addr, &peer->address) &&
	    !fastd_peer_address_ip_equal(remote_addr, &peer->address))
		return;

	peer->direct_established = true;
	count_direct_success(peer, source);
}

/** Removes expired direct endpoint candidates */
static void compact_direct_candidates(fastd_peer_t *peer) {
	bool cache_valid = false;

	size_t i;
	for (i = 0; i < VECTOR_LEN(peer->direct_candidates);) {
		fastd_peer_direct_candidate_t *candidate = &VECTOR_INDEX(peer->direct_candidates, i);
		if (!direct_candidate_valid(candidate)) {
			if (!fastd_peer_is_established(peer) && candidate->source == DIRECT_CANDIDATE_PUNCH_CONTROL &&
			    candidate->attempts) {
				ctx.punch_direct_failures++;
				suppress_punch_candidate(peer, &candidate->remote);
			}
			VECTOR_DELETE(peer->direct_candidates, i);
			continue;
		}

		if (candidate->relay == peer->direct_relay &&
		    fastd_peer_address_equal(&candidate->remote, &peer->direct_remote))
			cache_valid = true;

		i++;
	}

	if (!cache_valid)
		clear_direct_candidate_cache(peer);
}

/** Checks if a candidate already describes an established path */
static bool direct_candidate_established(const fastd_peer_t *peer, const fastd_peer_direct_candidate_t *candidate) {
	if (fastd_peer_is_established(peer) && fastd_peer_address_equal(&candidate->remote, &peer->address))
		return true;

	return fastd_peer_has_backup_path(peer) && fastd_peer_address_equal(&candidate->remote, &peer->backup_address);
}

/** Selects the best direct candidate without updating attempt counters */
static fastd_peer_direct_candidate_t *
best_direct_candidate(fastd_peer_t *peer, bool require_ready, bool skip_established) {
	fastd_peer_direct_candidate_t *best = NULL;

	size_t i;
	for (i = 0; i < VECTOR_LEN(peer->direct_candidates); i++) {
		fastd_peer_direct_candidate_t *candidate = &VECTOR_INDEX(peer->direct_candidates, i);
		if (!direct_candidate_valid(candidate))
			continue;

		if (direct_candidate_attempts_exhausted(candidate))
			continue;

		if (skip_established && direct_candidate_established(peer, candidate))
			continue;

		if (require_ready && candidate->attempts &&
		    !fastd_timed_out(candidate->last_attempt + FASTD_DIRECT_CANDIDATE_ATTEMPT_INTERVAL))
			continue;

		if (!best || candidate->priority > best->priority ||
		    (candidate->priority == best->priority && candidate->order < best->order) ||
		    (candidate->priority == best->priority && candidate->order == best->order &&
		     candidate->last_attempt < best->last_attempt))
			best = candidate;
	}

	return best;
}

/** Selects one direct candidate for the next handshake attempt */
static bool select_direct_candidate(fastd_peer_t *peer, bool skip_established) {
	compact_direct_candidates(peer);

	fastd_peer_direct_candidate_t *candidate = best_direct_candidate(peer, true, skip_established);
	if (!candidate)
		return false;

	candidate->attempts++;
	candidate->last_attempt = ctx.now;
	set_direct_candidate_cache(peer, candidate);
	return true;
}

/** Sends limited keepalive handshakes to inactive direct candidates */
static void send_direct_candidate_keepalives(fastd_peer_t *peer) {
	if (!fastd_peer_nat_traversal_keepalive_enabled(peer) || !conf.punch_max_backups)
		return;

	if (fastd_peer_has_verified_backup_path(peer))
		return;

	if (select_direct_candidate(peer, true))
		send_handshake_address(peer, &peer->direct_remote);
}

/** Checks if a relay-discovered direct endpoint is currently usable */
bool fastd_peer_has_direct_candidate(const fastd_peer_t *peer) {
	return fastd_peer_direct_candidate_count(peer) > 0;
}

/** Counts currently usable direct endpoint candidates */
size_t fastd_peer_direct_candidate_count(const fastd_peer_t *peer) {
	size_t count = 0;
	size_t i;
	for (i = 0; i < VECTOR_LEN(peer->direct_candidates); i++) {
		if (direct_candidate_valid(&VECTOR_INDEX(peer->direct_candidates, i)))
			count++;
	}

	return count;
}

/** Counts currently usable direct endpoint candidates from a given source */
size_t
fastd_peer_direct_candidate_count_by_source(const fastd_peer_t *peer, fastd_peer_direct_candidate_source_t source) {
	size_t count = 0;
	size_t i;
	for (i = 0; i < VECTOR_LEN(peer->direct_candidates); i++) {
		const fastd_peer_direct_candidate_t *candidate = &VECTOR_INDEX(peer->direct_candidates, i);
		if (candidate->source == source && direct_candidate_valid(candidate))
			count++;
	}

	return count;
}

/** Checks if an address is the currently selected punch-control direct candidate */
bool fastd_peer_is_current_punch_control_candidate(
	const fastd_peer_t *peer, const fastd_peer_address_t *addr, bool *exact_udp_punch,
	unsigned *udp_punch_sockets) {
	if (peer->direct_remote_source != DIRECT_CANDIDATE_PUNCH_CONTROL ||
	    peer->direct_remote.sa.sa_family == AF_UNSPEC || fastd_timed_out(peer->direct_remote_timeout) ||
	    !fastd_peer_address_equal(&peer->direct_remote, addr))
		return false;

	if (exact_udp_punch)
		*exact_udp_punch = peer->direct_remote_exact_udp;
	if (udp_punch_sockets)
		*udp_punch_sockets = peer->direct_remote_udp_punch_sockets;

	return true;
}

/** Checks if an address is the currently selected exact-UDP punch-control direct candidate */
bool fastd_peer_is_current_punch_candidate(const fastd_peer_t *peer, const fastd_peer_address_t *addr) {
	bool exact_udp_punch = false;
	return fastd_peer_is_current_punch_control_candidate(peer, addr, &exact_udp_punch, NULL) && exact_udp_punch;
}

/** Checks if an address is any punch-control direct candidate */
bool fastd_peer_is_punch_control_candidate(
	const fastd_peer_t *peer, const fastd_peer_address_t *addr, bool *exact_udp_punch, unsigned *udp_punch_sockets) {
	bool found = false;
	uint8_t priority = 0;
	uint8_t order = UINT8_MAX;
	bool best_exact_udp_punch = false;
	unsigned best_udp_punch_sockets = 0;

	if (!peer || !addr)
		goto end;

	size_t i;
	for (i = 0; i < VECTOR_LEN(peer->direct_candidates); i++) {
		const fastd_peer_direct_candidate_t *candidate = &VECTOR_INDEX(peer->direct_candidates, i);
		if (candidate->source != DIRECT_CANDIDATE_PUNCH_CONTROL || !direct_candidate_valid(candidate) ||
		    !fastd_peer_address_equal(&candidate->remote, addr))
			continue;

		if (!found || candidate->priority > priority || (candidate->priority == priority && candidate->order < order)) {
			found = true;
			priority = candidate->priority;
			order = candidate->order;
			best_exact_udp_punch = candidate->exact_udp_punch;
			best_udp_punch_sockets = candidate->udp_punch_sockets;
		}
	}

end:
	if (exact_udp_punch)
		*exact_udp_punch = best_exact_udp_punch;
	if (udp_punch_sockets)
		*udp_punch_sockets = best_udp_punch_sockets;

	return found;
}

/** Checks if an address is any exact-UDP punch-control direct candidate */
bool fastd_peer_is_punch_candidate(const fastd_peer_t *peer, const fastd_peer_address_t *addr) {
	bool exact_udp_punch = false;
	return fastd_peer_is_punch_control_candidate(peer, addr, &exact_udp_punch, NULL) && exact_udp_punch;
}

/** Checks if a punch-control candidate endpoint is temporarily suppressed */
bool fastd_peer_punch_candidate_suppressed(const fastd_peer_t *peer, const fastd_peer_address_t *addr) {
	size_t i;
	for (i = 0; i < VECTOR_LEN(peer->punch_suppressions); i++) {
		const fastd_peer_punch_suppression_t *entry = &VECTOR_INDEX(peer->punch_suppressions, i);
		if (punch_suppression_valid(entry) && fastd_peer_address_equal(&entry->remote, addr))
			return true;
	}

	return false;
}

/** Counts active punch endpoint suppressions */
size_t fastd_peer_punch_suppression_count(const fastd_peer_t *peer) {
	size_t count = 0;
	size_t i;
	for (i = 0; i < VECTOR_LEN(peer->punch_suppressions); i++) {
		if (punch_suppression_valid(&VECTOR_INDEX(peer->punch_suppressions, i)))
			count++;
	}

	return count;
}

/** Adds or refreshes a direct endpoint candidate for a peer */
void fastd_peer_add_direct_candidate_source(
	fastd_peer_t *peer, fastd_peer_t *relay, const fastd_peer_address_t *remote_addr, const fastd_eth_addr_t *macs,
	size_t n_macs, fastd_peer_direct_candidate_source_t source, uint8_t priority) {
	if (relay && source == DIRECT_CANDIDATE_DISCOVERY && !conf.peer_discovery)
		return;

	if ((relay && peer == relay) || !fastd_peer_is_enabled(peer))
		return;

	if (remote_addr->sa.sa_family != AF_INET && remote_addr->sa.sa_family != AF_INET6)
		return;

	compact_direct_candidates(peer);

	fastd_peer_direct_candidate_t *candidate = NULL;
	size_t i;
	for (i = 0; i < VECTOR_LEN(peer->direct_candidates); i++) {
		fastd_peer_direct_candidate_t *entry = &VECTOR_INDEX(peer->direct_candidates, i);
		if (direct_candidate_equal(entry, relay, remote_addr)) {
			candidate = entry;
			break;
		}
	}

	if (!candidate) {
		if (VECTOR_LEN(peer->direct_candidates) >= FASTD_DIRECT_CANDIDATE_LIMIT) {
			size_t victim = 0;
			for (i = 1; i < VECTOR_LEN(peer->direct_candidates); i++) {
				fastd_peer_direct_candidate_t *entry = &VECTOR_INDEX(peer->direct_candidates, i);
				fastd_peer_direct_candidate_t *old = &VECTOR_INDEX(peer->direct_candidates, victim);
				if (entry->priority < old->priority ||
				    (entry->priority == old->priority && entry->order > old->order) ||
				    (entry->priority == old->priority && entry->order == old->order &&
				     entry->timeout < old->timeout))
					victim = i;
			}

			fastd_peer_direct_candidate_t *old = &VECTOR_INDEX(peer->direct_candidates, victim);
			if (old->priority > priority)
				return;

			VECTOR_DELETE(peer->direct_candidates, victim);
		}

		VECTOR_ADD(
			peer->direct_candidates, ((fastd_peer_direct_candidate_t){
							 .remote = *remote_addr,
							 .relay = relay,
							 .last_attempt = 0,
							 .order = UINT8_MAX,
							 .source = source,
						 }));
		candidate = &VECTOR_INDEX(peer->direct_candidates, VECTOR_LEN(peer->direct_candidates) - 1);
	}

	candidate->timeout = ctx.now + PEER_STALE_TIME;
	if (priority >= candidate->priority) {
		candidate->priority = priority;
		candidate->source = source;
	}
	if (source != DIRECT_CANDIDATE_PUNCH_CONTROL)
		candidate->exact_udp_punch = false;
	if (source != DIRECT_CANDIDATE_PUNCH_CONTROL)
		candidate->udp_punch_sockets = 0;

	for (i = 0; i < n_macs; i++)
		add_direct_mac(peer, macs[i]);

	if (source != DIRECT_CANDIDATE_PUNCH_CONTROL) {
		fastd_peer_direct_candidate_t *best = best_direct_candidate(peer, false, false);
		if (best)
			set_direct_candidate_cache(peer, best);
	}

	if (fastd_peer_is_established(peer)) {
		mark_direct_established(peer, &candidate->remote, candidate->source);

		for (i = 0; i < VECTOR_LEN(peer->direct_macs); i++)
			fastd_peer_eth_addr_add(peer, VECTOR_INDEX(peer->direct_macs, i));

		if (source != DIRECT_CANDIDATE_PUNCH_CONTROL && !direct_candidate_established(peer, candidate))
			fastd_peer_schedule_handshake(peer, 0);

		return;
	}

	fastd_peer_seen(peer);
	fastd_peer_schedule_handshake(peer, 0);
}

/** Adds or refreshes a relay/realm-discovered direct endpoint for a peer */
void fastd_peer_add_direct_candidate(
	fastd_peer_t *peer, fastd_peer_t *relay, const fastd_peer_address_t *remote_addr, const fastd_eth_addr_t *macs,
	size_t n_macs) {
	fastd_peer_add_direct_candidate_source(
		peer, relay, remote_addr, macs, n_macs, relay ? DIRECT_CANDIDATE_DISCOVERY : DIRECT_CANDIDATE_REALM,
		relay ? FASTD_DIRECT_CANDIDATE_PRIORITY_DISCOVERY : FASTD_DIRECT_CANDIDATE_PRIORITY_REALM);
}

/** Adds or refreshes a punch-control direct endpoint for a peer */
bool fastd_peer_add_punch_control_candidate(
	fastd_peer_t *peer, const fastd_peer_address_t *remote_addr, uint8_t priority, bool exact_udp_punch,
	unsigned udp_punch_sockets, uint8_t order) {
	if (!fastd_peer_is_established(peer) && fastd_peer_punch_candidate_suppressed(peer, remote_addr)) {
		ctx.punch_direct_suppressed++;
		pr_debug("suppressing punch-control candidate for %P[%I] after recent failures", peer, remote_addr);
		return false;
	}

	fastd_peer_add_direct_candidate_source(
		peer, NULL, remote_addr, NULL, 0, DIRECT_CANDIDATE_PUNCH_CONTROL, priority);

	size_t i;
	for (i = 0; i < VECTOR_LEN(peer->direct_candidates); i++) {
		fastd_peer_direct_candidate_t *candidate = &VECTOR_INDEX(peer->direct_candidates, i);
		if (candidate->source == DIRECT_CANDIDATE_PUNCH_CONTROL &&
		    direct_candidate_equal(candidate, NULL, remote_addr)) {
			candidate->exact_udp_punch = exact_udp_punch;
			candidate->udp_punch_sockets = udp_punch_sockets;
			if (order < candidate->order)
				candidate->order = order;

			fastd_peer_direct_candidate_t *best = best_direct_candidate(peer, false, false);
			if (best)
				set_direct_candidate_cache(peer, best);

			if (fastd_peer_is_established(peer) && best == candidate &&
			    !fastd_peer_has_verified_backup_path(peer) &&
			    !direct_candidate_established(peer, candidate))
				fastd_peer_schedule_handshake(peer, 0);

			return true;
		}
	}

	return false;
}

/** Returns true if a peer has an established backup path */
bool fastd_peer_has_backup_path(const fastd_peer_t *peer) {
	return peer->backup_address.sa.sa_family != AF_UNSPEC && !fastd_timed_out(peer->backup_reset_timeout) &&
	       fastd_socket_is_open(peer->backup_sock);
}

/** Returns true if a peer has an established and verified backup path */
bool fastd_peer_has_verified_backup_path(const fastd_peer_t *peer) {
	return fastd_peer_has_backup_path(peer) && peer->backup_path_verified;
}

/** Marks that a valid packet was received on the backup path */
void fastd_peer_backup_seen(fastd_peer_t *peer) {
	peer->backup_reset_timeout = ctx.now + PEER_STALE_TIME;
	peer->backup_path_verified = true;
}

/** Resets the backup path keepalive timeout */
void fastd_peer_clear_backup_keepalive(fastd_peer_t *peer) {
	unsigned interval =
		fastd_peer_nat_traversal_keepalive_enabled(peer) ? conf.punch_keepalive_interval : KEEPALIVE_TIMEOUT;
	peer->backup_keepalive_timeout = ctx.now + interval;
}

/** Clears the generic backup path metadata and socket reference */
void fastd_peer_clear_backup_path(fastd_peer_t *peer) {
	free_backup_socket(peer);

	memset(&peer->backup_local_address, 0, sizeof(peer->backup_local_address));
	memset(&peer->backup_address, 0, sizeof(peer->backup_address));
	peer->backup_reset_timeout = FASTD_TIMEOUT_INV;
	peer->backup_keepalive_timeout = FASTD_TIMEOUT_INV;
	peer->backup_direct_established = false;
	peer->backup_direct_source = DIRECT_CANDIDATE_REALM;
	peer->backup_path_verified = false;
}

/** Checks whether one packet belongs to the peer's backup path */
bool fastd_peer_is_backup_path(
	const fastd_peer_t *peer, const fastd_socket_t *sock, const fastd_peer_address_t *local_addr,
	const fastd_peer_address_t *remote_addr) {
	if (!fastd_peer_has_backup_path(peer))
		return false;

	if (!fastd_peer_address_equal(&peer->backup_address, remote_addr))
		return false;

	if (peer->backup_direct_established && !fastd_socket_is_tcp(peer->backup_sock) && !fastd_socket_is_tcp(sock))
		return true;

	if (local_addr && peer->backup_local_address.sa.sa_family &&
	    !fastd_peer_address_equal(&peer->backup_local_address, local_addr))
		return false;

	return !peer->backup_sock || sock == peer->backup_sock;
}

/** Finds a peer by matching a packet against established backup paths */
fastd_peer_t *fastd_peer_find_backup_path(
	const fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr) {
	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
		fastd_peer_t *peer = VECTOR_INDEX(ctx.peers, i);
		if (fastd_peer_is_backup_path(peer, sock, local_addr, remote_addr))
			return peer;
	}

	return NULL;
}

/** Finds an established peer with a direct candidate matching an address */
fastd_peer_t *fastd_peer_find_direct_candidate(const fastd_peer_address_t *remote_addr) {
	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
		fastd_peer_t *peer = VECTOR_INDEX(ctx.peers, i);
		if (fastd_peer_is_established(peer) && fastd_peer_get_direct_candidate_source(peer, remote_addr, NULL))
			return peer;
	}

	return NULL;
}

/** Claims a socket/address tuple as a peer's backup path */
bool fastd_peer_claim_backup_path(
	fastd_peer_t *peer, fastd_socket_t *sock, const fastd_peer_address_t *local_addr,
	const fastd_peer_address_t *remote_addr) {
	if (!fastd_peer_is_established(peer) || remote_addr->sa.sa_family == AF_UNSPEC)
		return false;

	if (sock && !fastd_socket_is_open(sock))
		return false;

	if (fastd_peer_address_equal(&peer->address, remote_addr))
		return false;

	bool payload_candidate = fastd_peer_is_payload_candidate(peer, remote_addr);
	if (fastd_peer_has_backup_path(peer) && !fastd_peer_address_equal(&peer->backup_address, remote_addr) &&
	    !payload_candidate)
		return false;

	bool has_actual_transport = sock != NULL;
	fastd_peer_transport_t actual_transport = fastd_socket_is_tcp(sock) ? TRANSPORT_TCP : TRANSPORT_UDP;
	if (has_actual_transport && !fastd_peer_transport_allows(fastd_peer_get_transport(peer), actual_transport))
		return false;

	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
		fastd_peer_t *other = VECTOR_INDEX(ctx.peers, i);

		if (other == peer || !fastd_peer_is_enabled(other))
			continue;

		if (fastd_peer_owns_address(other, remote_addr))
			return false;

		if (fastd_peer_address_equal(&other->address, remote_addr))
			return false;

		if (fastd_peer_has_backup_path(other) && fastd_peer_address_equal(&other->backup_address, remote_addr))
			return false;
	}

	fastd_peer_clear_backup_path(peer);

	peer->backup_address = *remote_addr;
	if (local_addr)
		peer->backup_local_address = *local_addr;
	else if (sock && sock->bound_addr)
		peer->backup_local_address = *sock->bound_addr;
	else
		peer->backup_local_address.sa.sa_family = AF_UNSPEC;

	peer->backup_sock = sock;
	if (sock && (sock->hole_punch || sock->type == SOCKET_TYPE_TCP_CONNECTION)) {
		fastd_hole_punch_claim_socket(sock);
		sock->peer = peer;
	}

	fastd_peer_direct_candidate_source_t source;
	if (fastd_peer_get_direct_candidate_source(peer, remote_addr, &source)) {
		peer->backup_direct_established = true;
		peer->backup_direct_source = source;
		count_direct_success(peer, source);
	}

	peer->backup_path_verified = false;
	if (fastd_peer_nat_traversal_keepalive_enabled(peer)) {
		unsigned verify_timeout = 2 * conf.punch_keepalive_interval;
		if (verify_timeout < 5000)
			verify_timeout = 5000;
		peer->backup_reset_timeout = ctx.now + verify_timeout;
	} else {
		peer->backup_reset_timeout = ctx.now + PEER_STALE_TIME;
	}
	fastd_peer_clear_backup_keepalive(peer);
	schedule_peer_task(peer);

	return true;
}

/** Promotes the generic backup path endpoint to active */
bool fastd_peer_promote_backup_path(fastd_peer_t *peer) {
	if (!fastd_peer_has_backup_path(peer) || peer->offload)
		return false;

	fastd_socket_t *old_sock = peer->sock;
	fastd_peer_address_t old_local_address = peer->local_address;
	fastd_peer_address_t old_address = peer->address;
	fastd_timeout_t old_reset_timeout = peer->reset_timeout;
	fastd_timeout_t old_keepalive_timeout = peer->keepalive_timeout;
	bool old_direct_established = peer->direct_established;
	fastd_peer_direct_candidate_source_t old_direct_source = peer->direct_remote_source;
	bool old_backup_verified = peer->backup_path_verified;
	bool old_active_verified =
		peer->active_path_timeout != FASTD_TIMEOUT_INV && !fastd_timed_out(peer->active_path_timeout);

	fastd_peer_hashtable_remove(peer);

	peer->sock = peer->backup_sock;
	peer->local_address = peer->backup_local_address;
	peer->address = peer->backup_address;
	peer->reset_timeout = peer->backup_reset_timeout;
	peer->keepalive_timeout = peer->backup_keepalive_timeout;
	peer->active_path_timeout = old_backup_verified ? ctx.now + (fastd_peer_nat_traversal_keepalive_enabled(peer)
									     ? conf.punch_keepalive_interval
									     : KEEPALIVE_TIMEOUT)
							: FASTD_TIMEOUT_INV;
	peer->direct_established = peer->backup_direct_established;
	peer->direct_remote_source = peer->backup_direct_source;

	peer->backup_sock = old_sock;
	peer->backup_local_address = old_local_address;
	peer->backup_address = old_address;
	peer->backup_reset_timeout = old_reset_timeout;
	peer->backup_keepalive_timeout = old_keepalive_timeout;
	peer->backup_direct_established = old_direct_established;
	peer->backup_direct_source = old_direct_source;
	peer->backup_path_verified = old_active_verified;
	peer->payload_candidate_timeout = FASTD_TIMEOUT_INV;

	if (peer->sock && socket_ref_dynamic(peer->sock))
		peer->sock->peer = peer;

	if (peer->backup_sock && socket_ref_dynamic(peer->backup_sock))
		peer->backup_sock->peer = peer;

	fastd_peer_hashtable_insert(peer);
	fastd_receive_unknown_purge(peer->address);
	schedule_peer_task(peer);

	pr_info("promoted backup path for %P from %I to %I", peer, &old_address, &peer->address);
	return true;
}

/** Sends an initial handshake over the established backup path */
bool fastd_peer_send_backup_handshake(fastd_peer_t *peer) {
	if (!fastd_peer_has_backup_path(peer) || !peer->backup_sock)
		return false;

	if (!fastd_timed_out(peer->last_handshake_timeout) &&
	    fastd_peer_address_equal(&peer->backup_address, &peer->last_handshake_address)) {
		pr_debug("not sending a backup handshake to %P as we sent one a short time ago", peer);
		return false;
	}

	peer->last_handshake_timeout = ctx.now + MIN_HANDSHAKE_INTERVAL;
	peer->last_handshake_address = peer->backup_address;
	conf.protocol->handshake_init(
		peer->backup_sock, &peer->backup_local_address, &peer->backup_address, peer, FLAG_INITIAL);

	return true;
}

/** Records an inactive direct path that has carried payload data */
void fastd_peer_note_payload_candidate(fastd_peer_t *peer, const fastd_peer_address_t *remote_addr) {
	peer->payload_candidate_address = *remote_addr;
	peer->payload_candidate_timeout = ctx.now + MIN_HANDSHAKE_INTERVAL;
}

/** Checks if an address matches the current payload-proven candidate */
bool fastd_peer_is_payload_candidate(const fastd_peer_t *peer, const fastd_peer_address_t *remote_addr) {
	return peer->payload_candidate_address.sa.sa_family != AF_UNSPEC &&
	       !fastd_timed_out(peer->payload_candidate_timeout) &&
	       fastd_peer_address_equal(&peer->payload_candidate_address, remote_addr);
}

/**
   Tries to claim an address for a peer

   Each remote address (+ port) can by used by only one peer at a time.

   If it is tried to claim an address that is currently used by another peer, the claim will fail unless
   \e force is set. The claim will fail even with \e force set if the other peer has statically configured the address
   in question.
 */
bool fastd_peer_claim_address(
	fastd_peer_t *new_peer, fastd_socket_t *sock, const fastd_peer_address_t *local_addr,
	const fastd_peer_address_t *remote_addr, bool force) {
	bool address_changed = !fastd_peer_address_equal(&new_peer->address, remote_addr);
	bool has_actual_transport = sock != NULL;
	fastd_peer_transport_t actual_transport = fastd_socket_is_tcp(sock) ? TRANSPORT_TCP : TRANSPORT_UDP;

	if (sock && !fastd_socket_is_open(sock)) {
		reset_peer_address(new_peer);
		return false;
	}

	if (has_actual_transport &&
	    !fastd_peer_transport_allows(fastd_peer_get_transport(new_peer), actual_transport)) {
		reset_peer_address(new_peer);
		return false;
	}

	if (remote_addr->sa.sa_family == AF_UNSPEC) {
		if (fastd_peer_is_established(new_peer))
			fastd_peer_reset(new_peer);
	} else {
		size_t i;
		for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
			fastd_peer_t *peer = VECTOR_INDEX(ctx.peers, i);

			if (peer == new_peer)
				continue;

			if (!fastd_peer_is_enabled(peer))
				continue;

			if (fastd_peer_owns_address(peer, remote_addr)) {
				reset_peer_address(new_peer);
				return false;
			}

			if (fastd_peer_address_equal(&peer->address, remote_addr)) {
				if (!force && fastd_peer_is_established(peer)) {
					reset_peer_address(new_peer);
					return false;
				}

				reset_peer_address(peer);
				break;
			}
		}
	}

	fastd_peer_hashtable_remove(new_peer);
	new_peer->address = *remote_addr;
	fastd_peer_hashtable_insert(new_peer);

	if (address_changed && fastd_peer_get_transport(new_peer) == TRANSPORT_AUTO)
		new_peer->transport_probe = TRANSPORT_UNSET;

	if (has_actual_transport && fastd_peer_get_transport(new_peer) == TRANSPORT_AUTO)
		new_peer->transport_probe = actual_transport;

	if (sock && sock->hole_punch && sock != new_peer->sock) {
		fastd_hole_punch_claim_socket(sock);
		free_socket(new_peer);
		new_peer->sock = sock;
		sock->peer = new_peer;
	} else if (sock && sock->type == SOCKET_TYPE_TCP_CONNECTION && sock != new_peer->sock) {
		fastd_hole_punch_claim_socket(sock);
		free_socket(new_peer);
		new_peer->sock = sock;
		sock->peer = new_peer;
	} else if (sock && sock->addr && sock != new_peer->sock) {
		free_socket(new_peer);
		new_peer->sock = sock;
	}

	if (local_addr)
		new_peer->local_address = *local_addr;

	return true;
}

/** Resets and re-initializes a peer */
void fastd_peer_reset(fastd_peer_t *peer) {
	if (peer->state != STATE_INACTIVE) {
		pr_debug("resetting peer %P", peer);
		reset_peer(peer);
	}

	setup_peer(peer);
}

/** Deletes a peer */
void fastd_peer_delete(fastd_peer_t *peer) {
	reset_peer(peer);
	delete_peer(peer);
}

/** Counts how many peers in the given peer group have established a connection */
static inline size_t count_established_group_peers(const fastd_peer_group_t *group) {
	size_t i, ret = 0;
	for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
		fastd_peer_t *peer = VECTOR_INDEX(ctx.peers, i);

		if (fastd_peer_is_established(peer) && is_peer_in_group(peer, group))
			ret++;
	}

	return ret;
}

/** Checks if a peer may currently establish a connection */
bool fastd_peer_may_connect(fastd_peer_t *peer) {
	if (fastd_peer_is_established(peer))
		return true;

	const fastd_peer_group_t *group;

	for (group = peer->group; group; group = group->parent) {
		if (group->max_connections < 0)
			continue;

		if (count_established_group_peers(group) >= (size_t)group->max_connections)
			return false;
	}

	return true;
}

/** Checks if two peer configurations are equivalent (exept for the name) */
static inline bool peer_configs_equal(const fastd_peer_t *peer1, const fastd_peer_t *peer2) {
	if (peer1->group != peer2->group)
		return false;

	if (peer1->floating != peer2->floating)
		return false;

	if (!strequal(peer1->realm, peer2->realm))
		return false;

	if (VECTOR_LEN(peer1->remotes) != VECTOR_LEN(peer2->remotes))
		return false;

	if (!strequal(peer1->ifname, peer2->ifname))
		return false;

	if (peer1->port_mapping != peer2->port_mapping)
		return false;

	if (peer1->transport != peer2->transport)
		return false;

	if (peer1->hole_punch != peer2->hole_punch)
		return false;

	if (peer1->punch_symmetric.set != peer2->punch_symmetric.set ||
	    peer1->punch_symmetric.state != peer2->punch_symmetric.state)
		return false;

	if (peer1->turn_relay.set != peer2->turn_relay.set || peer1->turn_relay.state != peer2->turn_relay.state)
		return false;

	if (!fastd_turn_server_list_equal(peer1->turn_servers, peer2->turn_servers))
		return false;

	size_t i;
	for (i = 0; i < VECTOR_LEN(peer1->remotes); i++) {
		const fastd_remote_t *remote1 = &VECTOR_INDEX(peer1->remotes, i),
				     *remote2 = &VECTOR_INDEX(peer2->remotes, i);

		if (!fastd_peer_address_equal(&remote1->address, &remote2->address))
			return false;

		if (!strequal(remote1->hostname, remote2->hostname))
			return false;
	}

	return true;
}

/** Adds a new peer */
bool fastd_peer_add(fastd_peer_t *peer) {
	if (!peer->key) {
		pr_warn("no valid key configured for peer %P", peer);
		goto error;
	}

	fastd_peer_t *other = conf.protocol->find_peer(peer->key);
	if (other) {
		if (peer->config_state != CONFIG_NEW)
			exit_bug("tried to replace with active peer");

		switch (other->config_state) {
		case CONFIG_NEW:
		case CONFIG_DISABLED:
			pr_warn("duplicate key used by peers %P and %P, disabling both", peer, other);
			other->config_state = CONFIG_DISABLED;
			goto error;

		case CONFIG_STATIC:
			if (!strequal(other->name, peer->name))
				pr_verbose("peer %P has been renamed to %P", other, peer);

			if (peer_configs_equal(other, peer)) {
				free(other->name);
				other->name = peer->name;
				peer->name = NULL;

				fastd_peer_free(peer);

				pr_verbose("peer %P is unchanged", other);
				other->config_state = CONFIG_NEW;

				return true;
			} else {
				pr_verbose("peer %P has changed", peer);
			}

			fastd_peer_delete(other);
			break;

#ifdef WITH_DYNAMIC_PEERS
		case CONFIG_DYNAMIC:
			pr_verbose("dynamic peer %P is now configured as %P", other, peer);
			fastd_peer_delete(other);
#endif
		}
	}

	peer->id = ctx.next_peer_id++;

	VECTOR_ADD(ctx.peers, peer);

	conf.protocol->init_peer_state(peer);

	if (fastd_peer_is_dynamic(peer) || peer->config_source_dir)
		pr_verbose("adding peer %P", peer);

	return true;

error:
	fastd_peer_free(peer);
	return false;
}

/** Prints a debug message when no handshake could be sent because the current remote didn't resolve successfully */
static inline void no_valid_address_debug(const fastd_peer_t *peer) {
	pr_debug("not sending a handshake to %P (no valid address resolved)", peer);
}

/** Returns the default UDP socket matching a remote address family */
static fastd_socket_t *default_udp_socket_for_address(const fastd_peer_address_t *addr) {
	switch (addr->sa.sa_family) {
	case AF_INET:
		return ctx.sock_default_v4;

	case AF_INET6:
		return ctx.sock_default_v6;

	default:
		return NULL;
	}
}

/** Sends a new handshake to a specific peer address */
static bool send_handshake_address(fastd_peer_t *peer, const fastd_peer_address_t *addr) {
	fastd_socket_t *sock = peer->sock;
	fastd_peer_address_t local_address = peer->local_address;
	const fastd_peer_address_t *handshake_addr = addr;

	if (!fastd_peer_is_established(peer)) {
		fastd_peer_claim_address(peer, NULL, NULL, addr, false);
		fastd_peer_reset_socket(peer);

		sock = peer->sock;
		local_address = peer->local_address;
		handshake_addr = &peer->address;
	} else if (!fastd_peer_address_equal(addr, &peer->address) && (!sock || fastd_socket_is_tcp(sock))) {
		if (fastd_peer_transport_allows(fastd_peer_get_transport(peer), TRANSPORT_UDP)) {
			switch (addr->sa.sa_family) {
			case AF_INET:
				sock = ctx.sock_default_v4;
				break;

			case AF_INET6:
				sock = ctx.sock_default_v6;
				break;
			}
		}

		if (sock && sock->bound_addr)
			local_address = *sock->bound_addr;
	}

	if (!sock)
		return false;

	if (handshake_addr->sa.sa_family == AF_UNSPEC) {
		no_valid_address_debug(peer);
		return false;
	}

	bool current_exact_udp_punch = fastd_peer_is_current_punch_candidate(peer, handshake_addr);
	if (current_exact_udp_punch) {
		fastd_socket_t *udp_sock = default_udp_socket_for_address(handshake_addr);
		if (udp_sock && udp_sock->bound_addr) {
			sock = udp_sock;
			local_address = *udp_sock->bound_addr;
		}
	}

	if (!fastd_timed_out(peer->last_handshake_timeout) &&
	    fastd_peer_address_equal(handshake_addr, &peer->last_handshake_address)) {
		pr_debug("not sending a handshake to %P as we sent one a short time ago", peer);
		return false;
	}

	peer->last_handshake_timeout = ctx.now + MIN_HANDSHAKE_INTERVAL;
	peer->last_handshake_address = *handshake_addr;
	conf.protocol->handshake_init(sock, &local_address, handshake_addr, peer, FLAG_INITIAL);

	if (!current_exact_udp_punch && fastd_peer_get_transport(peer) == TRANSPORT_AUTO &&
	    fastd_peer_hole_punch_allows(peer, TRANSPORT_UDP) && fastd_socket_is_tcp(sock)) {
		fastd_socket_t *udp_sock = default_udp_socket_for_address(handshake_addr);
		if (udp_sock && udp_sock->bound_addr) {
			fastd_peer_transport_t old_probe = peer->transport_probe;
			fastd_peer_address_t udp_local_address = *udp_sock->bound_addr;

			peer->transport_probe = TRANSPORT_UDP;
			conf.protocol->handshake_init(udp_sock, &udp_local_address, handshake_addr, peer, FLAG_INITIAL);
			peer->transport_probe = old_probe;
		}
	}

	return true;
}

/** Sends an immediate direct punch handshake to a candidate endpoint */
bool fastd_peer_send_direct_handshake(fastd_peer_t *peer, const fastd_peer_address_t *addr) {
	if (!peer || !fastd_peer_is_enabled(peer))
		return false;

	if (!fastd_peer_may_connect(peer))
		return false;

	bool was_established = fastd_peer_is_established(peer);
	bool sent = send_handshake_address(peer, addr);
	if (sent && !was_established)
		peer->state = STATE_HANDSHAKE;

	return sent;
}

/** Sends a new handshake to the current address of the given remote of a peer */
static void send_handshake(fastd_peer_t *peer, fastd_remote_t *next_remote) {
	if (!fastd_peer_is_established(peer)) {
		if (!next_remote->n_addresses) {
			no_valid_address_debug(peer);
			return;
		}

		send_handshake_address(peer, &next_remote->addresses[next_remote->current_address]);
	} else {
		send_handshake_address(peer, &peer->address);
	}
}

/** Marks a peer as established */
bool fastd_peer_set_established(fastd_peer_t *peer, const fastd_offload_t *offload) {
	if (peer->offload) {
		bool need_reset;

		if (peer->offload == offload)
			need_reset = !peer->offload->update_session(peer, peer->offload_state);
		else
			need_reset = true;

		if (need_reset) {
			on_down(peer, false);
			peer->offload->free_session(peer->offload_state);
			peer->offload = NULL;
		}
	}

	if (offload && !peer->offload) {
		if (peer->iface && peer->iface->peer) {
			on_down(peer, false);
			fastd_iface_close(peer->iface);
		}
		peer->iface = NULL;

		peer->offload_state = offload->init_session(peer);
		if (!peer->offload_state)
			return false;

		peer->offload = offload;
		on_up(peer, false);
	}

	if (!peer->iface && !peer->offload) {
		peer->iface = fastd_iface_open(peer);
		if (!peer->iface)
			return false;

		on_up(peer, false);
	}

	if (fastd_peer_is_established(peer))
		return true;

	peer->state = STATE_ESTABLISHED;
	peer->established = ctx.now;

	mark_direct_established(peer, &peer->direct_remote, peer->direct_remote_source);

	fastd_peer_seen(peer);
	fastd_peer_clear_keepalive(peer);
	fastd_receive_unknown_purge(peer->address);

	schedule_peer_task(peer);

	on_establish(peer);
	fastd_discovery_peer_established(peer);
	pr_info("connection with %P established.", peer);

	return true;
}

/** Compares two MAC addresses */
static inline int eth_addr_cmp(const fastd_eth_addr_t *addr1, const fastd_eth_addr_t *addr2) {
	return memcmp(addr1->data, addr2->data, sizeof(fastd_eth_addr_t));
}

/** Compares two fastd_peer_eth_addr_t entries by their MAC addresses */
static int peer_eth_addr_cmp(const fastd_peer_eth_addr_t *addr1, const fastd_peer_eth_addr_t *addr2) {
	return eth_addr_cmp(&addr1->addr, &addr2->addr);
}

/** Adds a MAC address to the sorted list of addresses associated with a peer (or updates the timeout of an existing
 * entry) */
void fastd_peer_eth_addr_add(fastd_peer_t *peer, fastd_eth_addr_t addr) {
	size_t min = 0, max = VECTOR_LEN(ctx.eth_addrs);

	if (peer && !fastd_peer_is_established(peer))
		exit_bug("tried to learn ethernet address on non-established peer");

	while (max > min) {
		size_t cur = min + (max - min) / 2;
		int cmp = eth_addr_cmp(&addr, &VECTOR_INDEX(ctx.eth_addrs, cur).addr);

		if (cmp == 0) {
			fastd_peer_t *old_peer = VECTOR_INDEX(ctx.eth_addrs, cur).peer;
			if (old_peer && old_peer->direct_relay == peer && fastd_peer_is_established(old_peer)) {
				VECTOR_INDEX(ctx.eth_addrs, cur).timeout = ctx.now + ETH_ADDR_STALE_TIME;
				return;
			}

			VECTOR_INDEX(ctx.eth_addrs, cur).peer = peer;
			VECTOR_INDEX(ctx.eth_addrs, cur).timeout = ctx.now + ETH_ADDR_STALE_TIME;
			return; /* We're done here. */
		} else if (cmp < 0) {
			max = cur;
		} else {
			min = cur + 1;
		}
	}

	VECTOR_INSERT(ctx.eth_addrs, ((fastd_peer_eth_addr_t){ addr, peer, ctx.now + ETH_ADDR_STALE_TIME }), min);

	if (peer)
		pr_debug("learned new MAC address %E on peer %P", &addr, peer);
	else
		pr_debug("learned new local MAC address %E", &addr);
}

/** Finds the peer that is associated with a given MAC address */
bool fastd_peer_find_by_eth_addr(const fastd_eth_addr_t addr, fastd_peer_t **peer) {
	const fastd_peer_eth_addr_t key = { .addr = addr };
	fastd_peer_eth_addr_t *peer_eth_addr = VECTOR_BSEARCH(&key, ctx.eth_addrs, peer_eth_addr_cmp);

	if (!peer_eth_addr)
		return false;

	*peer = peer_eth_addr->peer;
	return true;
}

/** Sends a handshake to one peer, if a scheduled handshake is due */
static void handle_task_handshake(fastd_peer_t *peer) {
	set_next_handshake_default(peer);

	if (!fastd_peer_may_connect(peer)) {
		if (peer->next_remote != -1) {
			pr_debug("temporarily disabling handshakes with %P", peer);
			peer->next_remote = -1;
		}

		return;
	}

	fastd_remote_t *next_remote = fastd_peer_get_next_remote(peer);

	if (fastd_peer_is_established(peer) && !fastd_peer_has_verified_backup_path(peer) &&
	    select_direct_candidate(peer, true)) {
		send_handshake_address(peer, &peer->direct_remote);
	}

	if (!fastd_peer_is_established(peer) && select_direct_candidate(peer, false)) {
		send_handshake_address(peer, &peer->direct_remote);
		peer->state = STATE_HANDSHAKE;

		if (!next_remote)
			return;
	}

	if (next_remote || fastd_peer_is_established(peer)) {
		send_handshake(peer, next_remote);

		if (fastd_peer_is_established(peer))
			return;

		peer->state = STATE_HANDSHAKE;

		if (++next_remote->current_address < next_remote->n_addresses)
			return;

		peer->next_remote++;
	}

	if (!VECTOR_LEN(peer->remotes))
		return;

	if (peer->next_remote < 0 || (size_t)peer->next_remote >= VECTOR_LEN(peer->remotes))
		peer->next_remote = 0;

	next_remote = fastd_peer_get_next_remote(peer);
	next_remote->current_address = 0;

	if (next_remote->hostname)
		fastd_resolve_peer(peer, next_remote);
}

/**
   Performs maintenance tasks for a peer

   \li If no data was received from the peer for some time, it is reset.
   \li If no data was sent to the peer for some time, a keepalive is sent.
 */
void fastd_peer_handle_task(fastd_task_t *task) {
	fastd_peer_t *peer = container_of(task, fastd_peer_t, task);

	if (!fastd_peer_is_established(peer) && fastd_peer_has_backup_path(peer) &&
	    conf.protocol->promote_backup_path(peer))
		return;

	/* check for peer timeout */
	if (fastd_timed_out(peer->reset_timeout)) {
		if (fastd_peer_has_backup_path(peer) && conf.protocol->promote_backup_path(peer))
			return;

		if (fastd_peer_is_dynamic(peer))
			fastd_peer_delete(peer);
		else
			fastd_peer_reset(peer);

		return;
	}

	/* check for backup path timeout or closed backing socket */
	if (peer->backup_address.sa.sa_family != AF_UNSPEC && !fastd_peer_has_backup_path(peer))
		conf.protocol->drop_backup_path(peer);

	if (fastd_peer_is_established(peer) && peer->active_path_timeout != FASTD_TIMEOUT_INV &&
	    fastd_timed_out(peer->active_path_timeout) && fastd_peer_has_backup_path(peer) &&
	    conf.protocol->promote_backup_path(peer))
		return;
	else if (
		fastd_peer_is_established(peer) && peer->active_path_timeout != FASTD_TIMEOUT_INV &&
		fastd_timed_out(peer->active_path_timeout))
		peer->active_path_timeout = FASTD_TIMEOUT_INV;

	/* check for keepalive timeout */
	if (fastd_timed_out(peer->keepalive_timeout)) {
		pr_debug2("sending keepalive to %P", peer);
		conf.protocol->send(peer, fastd_buffer_alloc(0, conf.encrypt_headroom));
		send_direct_candidate_keepalives(peer);
		fastd_peer_clear_keepalive(peer);
	}

	if (fastd_timed_out(peer->backup_keepalive_timeout) && fastd_peer_has_backup_path(peer))
		conf.protocol->send_backup_keepalive(peer);

	if (fastd_timed_out(peer->next_handshake))
		handle_task_handshake(peer);

	schedule_peer_task(peer);
}

/** Removes all time-outed MAC addresses from \e ctx.eth_addrs */
void fastd_peer_eth_addr_cleanup(void) {
	size_t i, deleted = 0;

	for (i = 0; i < VECTOR_LEN(ctx.eth_addrs); i++) {
		if (fastd_timed_out(VECTOR_INDEX(ctx.eth_addrs, i).timeout)) {
			deleted++;
			pr_debug(
				"MAC address %E not seen for more than %u seconds, removing",
				&VECTOR_INDEX(ctx.eth_addrs, i).addr, ETH_ADDR_STALE_TIME / 1000);
		} else if (deleted) {
			VECTOR_INDEX(ctx.eth_addrs, i - deleted) = VECTOR_INDEX(ctx.eth_addrs, i);
		}
	}

	VECTOR_RESIZE(ctx.eth_addrs, VECTOR_LEN(ctx.eth_addrs) - deleted);
}

/** Resets all peers */
void fastd_peer_reset_all(void) {
	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.peers);) {
		fastd_peer_t *peer = VECTOR_INDEX(ctx.peers, i);

		if (fastd_peer_is_dynamic(peer)) {
			fastd_peer_delete(peer);
		} else {
			fastd_peer_reset(peer);
			i++;
		}
	}
}
