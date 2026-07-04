// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   TURN relay support
*/


#include "turn.h"
#include "hole_punch.h"
#include "peer.h"

#ifdef WITH_TURN
#include <nice/agent.h>
#endif


/** Adds a TURN server to a list */
void fastd_turn_server_add(
	fastd_turn_server_t **servers, const char *host, uint16_t port, const char *username, const char *password) {
	fastd_turn_server_t *server = fastd_new(fastd_turn_server_t);
	*server = (fastd_turn_server_t){
		.next = *servers,
		.host = fastd_strdup(host),
		.port = port,
		.username = fastd_strdup(username),
		.password = fastd_strdup(password),
	};

	*servers = server;
}

/** Copies a TURN server list */
fastd_turn_server_t *fastd_turn_server_copy(const fastd_turn_server_t *servers) {
	fastd_turn_server_t *ret = NULL;
	fastd_turn_server_t **tail = &ret;

	while (servers) {
		*tail = fastd_new(fastd_turn_server_t);
		**tail = (fastd_turn_server_t){
			.host = fastd_strdup(servers->host),
			.port = servers->port,
			.username = fastd_strdup(servers->username),
			.password = fastd_strdup(servers->password),
		};

		tail = &(*tail)->next;
		servers = servers->next;
	}

	return ret;
}

/** Returns true if two TURN server lists are equal */
bool fastd_turn_server_list_equal(const fastd_turn_server_t *a, const fastd_turn_server_t *b) {
	while (a && b) {
		if (a->port != b->port)
			return false;

		if (!strequal(a->host, b->host))
			return false;

		if (!strequal(a->username, b->username))
			return false;

		if (!strequal(a->password, b->password))
			return false;

		a = a->next;
		b = b->next;
	}

	return !a && !b;
}

/** Frees a TURN server list */
void fastd_turn_server_free(fastd_turn_server_t *servers) {
	while (servers) {
		fastd_turn_server_t *next = servers->next;

		free(servers->host);
		free(servers->username);
		free(servers->password);
		free(servers);

		servers = next;
	}
}

#ifdef WITH_TURN

#define FASTD_TURN_COMPONENT NICE_COMPONENT_TYPE_RTP
#define FASTD_TURN_INTERVAL 100

/** TURN relay state for a single peer */
struct fastd_turn_peer {
	NiceAgent *agent;          /**< The libnice agent */
	GMainContext *context;     /**< The GLib main context used by the agent */
	guint stream_id;           /**< The libnice stream ID */
	fastd_socket_t *sock;      /**< The fastd socket this relay represents */
	fastd_peer_address_t local_addr;  /**< The local address for fastd receive handling */
	fastd_peer_address_t remote_addr; /**< The selected non-ICE remote candidate */
	fastd_turn_server_t *servers;     /**< TURN servers used by this relay */
	bool selected;             /**< true if a relay candidate pair has been selected */
	bool warned_not_ready;     /**< suppresses repeated not-ready warnings */
};


/** Returns true if there are active TURN relay sessions */
static bool turn_active(void) {
	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
		if (VECTOR_INDEX(ctx.peers, i)->turn_peer)
			return true;
	}

	return false;
}

/** Schedules the TURN maintenance task if needed */
static void schedule_turn_task(void) {
	if (!fastd_task_scheduled(&ctx.turn_task))
		fastd_task_schedule(&ctx.turn_task, TASK_TYPE_TURN, ctx.now + FASTD_TURN_INTERVAL);
}

/** Runs one non-blocking GLib main context iteration for a peer relay */
static bool turn_context_iteration(fastd_peer_t *peer) {
	fastd_turn_peer_t *turn_peer = peer->turn_peer;
	GMainContext *context = g_main_context_ref(turn_peer->context);

	bool ret = g_main_context_iteration(context, false);
	g_main_context_unref(context);

	return ret && peer->turn_peer == turn_peer;
}

/** Converts a fastd peer address to a NiceAddress */
static bool nice_address_from_peer(NiceAddress *out, const fastd_peer_address_t *addr) {
	nice_address_init(out);

	switch (addr->sa.sa_family) {
	case AF_INET:
		nice_address_set_from_sockaddr(out, &addr->sa);
		return true;

	case AF_INET6:
		nice_address_set_from_sockaddr(out, &addr->sa);
		return true;

	default:
		return false;
	}
}

/** Creates a libnice remote candidate for a non-ICE fastd peer address */
static NiceCandidate *create_remote_candidate(fastd_turn_peer_t *turn_peer, const fastd_peer_address_t *remote_addr) {
	NiceCandidate *candidate = nice_candidate_new(NICE_CANDIDATE_TYPE_HOST);
	candidate->transport = NICE_CANDIDATE_TRANSPORT_UDP;
	candidate->stream_id = turn_peer->stream_id;
	candidate->component_id = FASTD_TURN_COMPONENT;
	candidate->priority = 1;
	snprintf(candidate->foundation, sizeof(candidate->foundation), "fastd");

	if (!nice_address_from_peer(&candidate->addr, remote_addr)) {
		nice_candidate_free(candidate);
		return NULL;
	}

	candidate->base_addr = candidate->addr;
	return candidate;
}

/** Selects the peer's normal remote address as a non-ICE remote candidate */
static bool select_remote_candidate(fastd_peer_t *peer, fastd_turn_peer_t *turn_peer) {
	NiceCandidate *candidate = create_remote_candidate(turn_peer, &turn_peer->remote_addr);
	if (!candidate) {
		pr_warn("can't create TURN remote candidate for %P[%I]", peer, &turn_peer->remote_addr);
		return false;
	}

	bool ok = nice_agent_set_selected_remote_candidate(
		turn_peer->agent, turn_peer->stream_id, FASTD_TURN_COMPONENT, candidate);
	nice_candidate_free(candidate);

	if (!ok) {
		pr_warn("can't select TURN remote candidate for %P[%I]", peer, &turn_peer->remote_addr);
		return false;
	}

	turn_peer->selected = true;
	turn_peer->warned_not_ready = false;
	pr_verbose("TURN relay for %P[%I] is ready", peer, &turn_peer->remote_addr);
	return true;
}

/** Handles local candidate gathering completion */
static void handle_candidate_gathering_done(
	UNUSED NiceAgent *agent, guint stream_id, gpointer user_data) {
	fastd_peer_t *peer = user_data;
	fastd_turn_peer_t *turn_peer = peer->turn_peer;

	if (!turn_peer || stream_id != turn_peer->stream_id)
		return;

	if (!turn_peer->selected)
		select_remote_candidate(peer, turn_peer);
}

/** Logs libnice component state changes */
static void handle_component_state_changed(
	UNUSED NiceAgent *agent, guint stream_id, guint component_id, guint state, gpointer user_data) {
	fastd_peer_t *peer = user_data;
	fastd_turn_peer_t *turn_peer = peer->turn_peer;

	if (!turn_peer || stream_id != turn_peer->stream_id || component_id != FASTD_TURN_COMPONENT)
		return;

	pr_debug("TURN relay state for %P[%I] changed to %s", peer, &turn_peer->remote_addr,
		 nice_component_state_to_string(state));
}

/** Handles a packet received through TURN */
static void handle_turn_recv(
	UNUSED NiceAgent *agent, UNUSED guint stream_id, UNUSED guint component_id, guint len, gchar *buf,
	gpointer user_data) {
	fastd_peer_t *peer = user_data;
	fastd_turn_peer_t *turn_peer = peer->turn_peer;

	if (!turn_peer)
		return;

	fastd_buffer_t *buffer = fastd_buffer_alloc(len, conf.decrypt_headroom);
	memcpy(buffer->data, buf, len);

	fastd_receive_packet(turn_peer->sock, &turn_peer->local_addr, &turn_peer->remote_addr, buffer);
}

/** Frees the relay state of a peer */
static void free_turn_peer(fastd_peer_t *peer) {
	fastd_turn_peer_t *turn_peer = peer->turn_peer;
	if (!turn_peer)
		return;

	if (turn_peer->agent) {
		g_signal_handlers_disconnect_by_data(turn_peer->agent, peer);
		if (turn_peer->stream_id)
			nice_agent_attach_recv(
				turn_peer->agent, turn_peer->stream_id, FASTD_TURN_COMPONENT, turn_peer->context, NULL,
				NULL);
		nice_agent_close_async(turn_peer->agent, NULL, NULL);
		g_object_unref(turn_peer->agent);
	}

	if (turn_peer->context)
		g_main_context_unref(turn_peer->context);

	fastd_turn_server_free(turn_peer->servers);
	free(turn_peer);
	peer->turn_peer = NULL;
}

/** Returns true if the existing relay state can be reused */
static bool turn_peer_matches(
	const fastd_peer_t *peer, const fastd_socket_t *sock, const fastd_peer_address_t *local_addr,
	const fastd_peer_address_t *remote_addr) {
	const fastd_turn_peer_t *turn_peer = peer->turn_peer;
	if (!turn_peer)
		return false;

	if (turn_peer->sock != sock)
		return false;

	if (!fastd_peer_address_equal(&turn_peer->local_addr, local_addr))
		return false;

	if (!fastd_peer_address_equal(&turn_peer->remote_addr, remote_addr))
		return false;

	if (!fastd_turn_server_list_equal(turn_peer->servers, fastd_peer_get_turn_servers(peer)))
		return false;

	return true;
}

/** Creates and starts a TURN relay state for a peer */
static bool create_turn_peer(
	fastd_peer_t *peer, const fastd_socket_t *sock, const fastd_peer_address_t *local_addr,
	const fastd_peer_address_t *remote_addr) {
	const fastd_turn_server_t *servers = fastd_peer_get_turn_servers(peer);
	if (!servers) {
		pr_warn("TURN relay enabled for %P, but no TURN servers are configured", peer);
		return false;
	}

	if (remote_addr->sa.sa_family != AF_INET && remote_addr->sa.sa_family != AF_INET6) {
		pr_warn("TURN relay enabled for %P, but remote address is not usable", peer);
		return false;
	}

	fastd_turn_peer_t *turn_peer = fastd_new0(fastd_turn_peer_t);
	turn_peer->context = g_main_context_new();
	turn_peer->agent = nice_agent_new(turn_peer->context, NICE_COMPATIBILITY_RFC5245);
	turn_peer->sock = (fastd_socket_t *)sock;
	turn_peer->local_addr = *local_addr;
	turn_peer->remote_addr = *remote_addr;
	turn_peer->servers = fastd_turn_server_copy(servers);

	if (!turn_peer->agent) {
		pr_warn("can't create TURN relay agent for %P", peer);
		goto error;
	}

	g_object_set(turn_peer->agent, "force-relay", TRUE, NULL);

	turn_peer->stream_id = nice_agent_add_stream(turn_peer->agent, 1);
	if (!turn_peer->stream_id) {
		pr_warn("can't create TURN relay stream for %P", peer);
		goto error;
	}

	const fastd_turn_server_t *server;
	for (server = servers; server; server = server->next) {
		if (!nice_agent_set_relay_info(
			    turn_peer->agent, turn_peer->stream_id, FASTD_TURN_COMPONENT, server->host, server->port,
			    server->username, server->password, NICE_RELAY_TYPE_TURN_UDP)) {
			pr_warn("invalid TURN server `%s' for %P", server->host, peer);
			goto error;
		}
	}

	g_signal_connect(
		G_OBJECT(turn_peer->agent), "candidate-gathering-done", G_CALLBACK(handle_candidate_gathering_done),
		peer);
	g_signal_connect(
		G_OBJECT(turn_peer->agent), "component-state-changed", G_CALLBACK(handle_component_state_changed),
		peer);

	if (!nice_agent_attach_recv(
		    turn_peer->agent, turn_peer->stream_id, FASTD_TURN_COMPONENT, turn_peer->context,
		    handle_turn_recv, peer)) {
		pr_warn("can't attach TURN relay receive handler for %P", peer);
		goto error;
	}

	if (!nice_agent_gather_candidates(turn_peer->agent, turn_peer->stream_id)) {
		pr_warn("can't gather TURN relay candidates for %P", peer);
		goto error;
	}

	peer->turn_peer = turn_peer;
	pr_verbose("starting TURN relay for %P[%I]", peer, remote_addr);
	return true;

error:
	peer->turn_peer = turn_peer;
	free_turn_peer(peer);
	return false;
}

/** Ensures that the peer has a relay state matching the packet being sent */
static bool ensure_turn_peer(
	fastd_peer_t *peer, const fastd_socket_t *sock, const fastd_peer_address_t *local_addr,
	const fastd_peer_address_t *remote_addr) {
	if (turn_peer_matches(peer, sock, local_addr, remote_addr))
		return true;

	free_turn_peer(peer);
	return create_turn_peer(peer, sock, local_addr, remote_addr);
}

/** Returns true if TURN should be used for this send attempt */
static bool should_use_turn(fastd_peer_t *peer) {
	if (!peer || !fastd_peer_get_turn_relay(peer))
		return false;

	if (fastd_peer_get_hole_punch(peer) != HOLE_PUNCH_AUTO || fastd_peer_is_established(peer))
		return true;

	if (peer->turn_fallback_timeout == FASTD_TIMEOUT_INV)
		peer->turn_fallback_timeout = ctx.now + FASTD_HOLE_PUNCH_TIMEOUT;

	return fastd_timed_out(peer->turn_fallback_timeout);
}

bool fastd_turn_check(void) {
#ifdef WITH_DYNAMIC_PEERS
	const fastd_peer_group_t *dynamic_group = conf.on_verify_group ?: conf.peer_group;
	if (fastd_allow_verify() && fastd_peer_group_get_turn_relay(dynamic_group) &&
	    !fastd_peer_group_get_turn_servers(dynamic_group)) {
		pr_error("TURN relay is enabled for dynamic peers, but no TURN servers are configured");
		return false;
	}
#endif

	size_t i;

	for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
		fastd_peer_t *peer = VECTOR_INDEX(ctx.peers, i);

		if (!fastd_peer_get_turn_relay(peer))
			continue;

		if (!fastd_peer_get_turn_servers(peer)) {
			pr_error("TURN relay is enabled for %P, but no TURN servers are configured", peer);
			return false;
		}
	}

	return true;
}

void fastd_turn_handle_task(void) {
	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
		fastd_peer_t *peer = VECTOR_INDEX(ctx.peers, i);

		if (!peer->turn_peer)
			continue;

		while (turn_context_iteration(peer)) {
		}
	}

	if (turn_active())
		fastd_task_schedule(&ctx.turn_task, TASK_TYPE_TURN, ctx.now + FASTD_TURN_INTERVAL);
}

bool fastd_turn_send(
	fastd_peer_t *peer, const fastd_socket_t *sock, const fastd_peer_address_t *local_addr,
	const fastd_peer_address_t *remote_addr, const fastd_buffer_t *buffer, size_t stat_size) {
	if (!should_use_turn(peer))
		return false;

	schedule_turn_task();

	const fastd_peer_address_t *effective_local_addr = local_addr ?: sock->bound_addr;
	if (!effective_local_addr) {
		fastd_stats_add(peer, STAT_TX_ERROR, stat_size);
		return true;
	}

	if (!ensure_turn_peer(peer, sock, effective_local_addr, remote_addr)) {
		fastd_stats_add(peer, STAT_TX_ERROR, stat_size);
		return true;
	}

	while (turn_context_iteration(peer)) {
	}

	if (!peer->turn_peer) {
		fastd_stats_add(peer, STAT_TX_DROPPED, stat_size);
		return true;
	}

	if (!peer->turn_peer->selected) {
		if (!peer->turn_peer->warned_not_ready) {
			pr_debug("TURN relay for %P[%I] is not ready yet", peer, remote_addr);
			peer->turn_peer->warned_not_ready = true;
		}

		fastd_stats_add(peer, STAT_TX_DROPPED, stat_size);
		return true;
	}

	gint ret = nice_agent_send(
		peer->turn_peer->agent, peer->turn_peer->stream_id, FASTD_TURN_COMPONENT, buffer->len, buffer->data);
	if (ret < 0 || (size_t)ret != buffer->len) {
		pr_warn("sending packet through TURN relay for %P[%I] failed", peer, remote_addr);
		fastd_stats_add(peer, STAT_TX_ERROR, stat_size);
		return true;
	}

	fastd_stats_add(peer, STAT_TX, stat_size);
	return true;
}

void fastd_turn_reset_peer(fastd_peer_t *peer) {
	free_turn_peer(peer);
}

void fastd_turn_cleanup(void) {
	fastd_task_unschedule(&ctx.turn_task);

	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.peers); i++)
		free_turn_peer(VECTOR_INDEX(ctx.peers, i));
}

#else

bool fastd_turn_check(void) {
	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
		fastd_peer_t *peer = VECTOR_INDEX(ctx.peers, i);

		if (fastd_peer_get_turn_relay(peer)) {
			pr_error("TURN relay is not supported by this build of fastd");
			return false;
		}
	}

	return true;
}

void fastd_turn_handle_task(void) {}

bool fastd_turn_send(
	UNUSED fastd_peer_t *peer, UNUSED const fastd_socket_t *sock, UNUSED const fastd_peer_address_t *local_addr,
	UNUSED const fastd_peer_address_t *remote_addr, UNUSED const fastd_buffer_t *buffer, UNUSED size_t stat_size) {
	return false;
}

void fastd_turn_reset_peer(UNUSED fastd_peer_t *peer) {}

void fastd_turn_cleanup(void) {}

#endif
