// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Authenticated punch control RPC
*/

#include "punch_rpc.h"
#include "method.h"
#include "peer.h"


#define FASTD_PUNCH_VERSION 1
#define FASTD_PUNCH_NAT_INFO 1
#define FASTD_PUNCH_SEND_CONE 2

#define FASTD_PUNCH_ANNOUNCE_INTERVAL 15000
#define FASTD_PUNCH_RELAY_INTERVAL 10000
#define FASTD_PUNCH_CANDIDATE_PRIORITY 120
#define FASTD_PUNCH_EASY_SYM_MAX_STEP 8

static const uint8_t fastd_punch_magic[4] = { 'f', 'p', 'c', 'h' };

#define FASTD_PUNCH_AF_INET 4
#define FASTD_PUNCH_AF_INET6 6


/** Punch control message header */
typedef struct __attribute__((packed)) fastd_punch_header {
	uint8_t magic[4]; /**< Packet discriminator */
	uint8_t version;  /**< Punch control protocol version */
	uint8_t type;     /**< FASTD_PUNCH_* message type */
	uint16_t length;  /**< Total message length, network byte order */
} fastd_punch_header_t;

/** Endpoint payload used by NAT_INFO and SEND_CONE */
typedef struct __attribute__((packed)) fastd_punch_endpoint {
	uint8_t key_len;        /**< Length of the following protocol key */
	uint8_t nat_type;       /**< fastd_nat_type_t value */
	uint8_t address_family; /**< FASTD_PUNCH_AF_* */
	uint8_t reserved;       /**< Reserved for future use */
	uint16_t port;          /**< Endpoint UDP port, network byte order */
	uint16_t min_port;      /**< Lowest observed public UDP port, network byte order */
	uint16_t max_port;      /**< Highest observed public UDP port, network byte order */
	int16_t port_delta;     /**< Easy-symmetric public port delta, network byte order */
	uint16_t reserved2;     /**< Reserved for future use */
	uint8_t address[16];    /**< IPv4 address in the first 4 bytes, or an IPv6 address */
} fastd_punch_endpoint_t;


/** Returns true if punch control messages can be sent with the current protocol */
static bool punch_control_supported(void) {
	return conf.protocol->send_control && conf.protocol->key_length && conf.protocol->get_own_key &&
	       conf.protocol->get_peer_key && conf.protocol->find_peer_by_key_data && conf.protocol->get_current_method;
}

/** Returns true if the currently negotiated method can carry control packets to a peer */
static bool peer_control_supported(const fastd_peer_t *peer) {
	const fastd_method_info_t *method = conf.protocol->get_current_method(peer);
	return method && (method->provider->flags & METHOD_SUPPORTS_CONTROL);
}

/** Encodes an endpoint into a punch control payload */
static bool encode_address(fastd_punch_endpoint_t *endpoint, const fastd_peer_address_t *addr) {
	memset(endpoint->address, 0, sizeof(endpoint->address));
	endpoint->port = fastd_peer_address_get_port(addr);

	switch (addr->sa.sa_family) {
	case AF_INET:
		endpoint->address_family = FASTD_PUNCH_AF_INET;
		memcpy(endpoint->address, &addr->in.sin_addr, sizeof(addr->in.sin_addr));
		return true;

	case AF_INET6:
		endpoint->address_family = FASTD_PUNCH_AF_INET6;
		memcpy(endpoint->address, &addr->in6.sin6_addr, sizeof(addr->in6.sin6_addr));
		return true;

	default:
		return false;
	}
}

/** Decodes an endpoint from a punch control payload */
static bool decode_address(fastd_peer_address_t *addr, const fastd_punch_endpoint_t *endpoint) {
	memset(addr, 0, sizeof(*addr));

	switch (endpoint->address_family) {
	case FASTD_PUNCH_AF_INET:
		addr->in.sin_family = AF_INET;
		addr->in.sin_port = endpoint->port;
		memcpy(&addr->in.sin_addr, endpoint->address, sizeof(addr->in.sin_addr));
		return true;

	case FASTD_PUNCH_AF_INET6:
		addr->in6.sin6_family = AF_INET6;
		addr->in6.sin6_port = endpoint->port;
		memcpy(&addr->in6.sin6_addr, endpoint->address, sizeof(addr->in6.sin6_addr));
		return true;

	default:
		return false;
	}
}

/** Parses and validates the common endpoint punch control message format */
static bool
parse_endpoint_message(const fastd_buffer_t *buffer, uint8_t *type, const fastd_punch_endpoint_t **payload) {
	if (buffer->len < sizeof(fastd_punch_header_t))
		return false;

	const fastd_punch_header_t *header = buffer->data;
	if (memcmp(header->magic, fastd_punch_magic, sizeof(header->magic)))
		return false;

	if (header->version != FASTD_PUNCH_VERSION)
		return false;

	size_t len = be16toh(header->length);
	if (len != buffer->len || len < sizeof(*header) + sizeof(fastd_punch_endpoint_t))
		return false;

	const fastd_punch_endpoint_t *parsed_payload = (const fastd_punch_endpoint_t *)(header + 1);
	size_t key_len = parsed_payload->key_len;
	if (len != sizeof(*header) + sizeof(*parsed_payload) + key_len)
		return false;

	*type = header->type;
	*payload = parsed_payload;
	return true;
}

/** Returns true if a raw protocol key is this fastd instance's own key */
static bool key_is_self(const void *key, size_t key_len) {
	return conf.protocol->get_own_key && key_len == conf.protocol->key_length() &&
	       !memcmp(conf.protocol->get_own_key(), key, key_len);
}

/** Finds a configured peer by raw protocol key */
static fastd_peer_t *find_peer_by_key(const void *key, size_t key_len) {
	if (!conf.protocol->find_peer_by_key_data)
		return NULL;

	fastd_peer_t *peer = conf.protocol->find_peer_by_key_data(key, key_len);
	if (!peer || !fastd_peer_is_enabled(peer))
		return NULL;

	return peer;
}

/** Returns the best endpoint currently known for a peer from the relay's point of view */
static bool get_peer_endpoint(const fastd_peer_t *peer, fastd_peer_address_t *endpoint, fastd_nat_type_t *type) {
	bool have_nat_info = peer->punch_endpoint.sa.sa_family != AF_UNSPEC && !fastd_timed_out(peer->punch_timeout);

	if (fastd_peer_is_established(peer) &&
	    (peer->address.sa.sa_family == AF_INET || peer->address.sa.sa_family == AF_INET6)) {
		*endpoint = peer->address;
		*type = have_nat_info ? peer->punch_nat_type : FASTD_NAT_UNKNOWN;
		return true;
	}

	if (peer->punch_endpoint.sa.sa_family != AF_UNSPEC && !fastd_timed_out(peer->punch_timeout)) {
		*endpoint = peer->punch_endpoint;
		*type = peer->punch_nat_type;
		return true;
	}

	return false;
}

/** Sends one endpoint punch control message */
static bool send_endpoint_message(
	fastd_peer_t *dest, uint8_t type, const void *subject_key, size_t key_len, const fastd_peer_address_t *endpoint,
	fastd_nat_type_t nat_type, uint16_t min_port, uint16_t max_port, int port_delta) {
	if (!punch_control_supported() || !fastd_peer_is_established(dest))
		return false;
	if (!peer_control_supported(dest))
		return false;

	if (key_len > UINT8_MAX)
		return false;

	size_t len = sizeof(fastd_punch_header_t) + sizeof(fastd_punch_endpoint_t) + key_len;
	if (len > UINT16_MAX)
		return false;

	fastd_buffer_t *buffer = fastd_buffer_alloc(len, conf.encrypt_headroom);

	fastd_punch_header_t *header = buffer->data;
	memcpy(header->magic, fastd_punch_magic, sizeof(header->magic));
	header->version = FASTD_PUNCH_VERSION;
	header->type = type;
	header->length = htobe16(len);

	fastd_punch_endpoint_t *payload = (fastd_punch_endpoint_t *)(header + 1);
	*payload = (fastd_punch_endpoint_t){
		.key_len = key_len,
		.nat_type = nat_type,
		.min_port = htobe16(min_port),
		.max_port = htobe16(max_port),
		.port_delta = htobe16((uint16_t)port_delta),
	};

	if (!encode_address(payload, endpoint)) {
		fastd_buffer_free(buffer);
		return false;
	}

	memcpy(payload + 1, subject_key, key_len);

	conf.protocol->send_control(dest, buffer);
	ctx.punch_control_tx++;
	return true;
}

/** Sends this instance's current NAT metadata to one established peer */
static void send_local_nat_info(fastd_peer_t *dest) {
	if (!fastd_timed_out(dest->next_punch_announce))
		return;

	dest->next_punch_announce = ctx.now + FASTD_PUNCH_ANNOUNCE_INTERVAL;

	fastd_nat_status_t status;
	if (!fastd_nat_get_status(&status) || !status.available)
		return;

	send_endpoint_message(
		dest, FASTD_PUNCH_NAT_INFO, conf.protocol->get_own_key(), conf.protocol->key_length(),
		&status.reflexive, status.type, status.min_port, status.max_port, status.port_delta);
}

/** Sets an endpoint port from host byte order */
static void set_endpoint_port(fastd_peer_address_t *endpoint, uint16_t port) {
	switch (endpoint->sa.sa_family) {
	case AF_INET:
		endpoint->in.sin_port = htons(port);
		return;

	case AF_INET6:
		endpoint->in6.sin6_port = htons(port);
		return;
	}
}

/** Returns an absolute bounded easy-symmetric port step */
static int easy_symmetric_step(int port_delta) {
	if (port_delta < 0)
		port_delta = -port_delta;

	if (port_delta < 1)
		return 1;
	if (port_delta > FASTD_PUNCH_EASY_SYM_MAX_STEP)
		return FASTD_PUNCH_EASY_SYM_MAX_STEP;

	return port_delta;
}

/** Returns true for local NAT types that benefit from opening a UDP punch socket array */
static bool nat_type_uses_local_socket_array(fastd_nat_type_t nat_type, bool hard_symmetric) {
	switch (nat_type) {
	case FASTD_NAT_SYMMETRIC_EASY_INC:
	case FASTD_NAT_SYMMETRIC_EASY_DEC:
		return true;

	case FASTD_NAT_SYMMETRIC:
		return hard_symmetric;

	default:
		return false;
	}
}

/** Returns the number of UDP sockets to use for one punch command with known NAT metadata */
static unsigned punch_udp_socket_count_for_nat(
	fastd_peer_t *peer, fastd_nat_type_t remote_nat_type, bool local_available, fastd_nat_type_t local_nat_type) {
	if (!fastd_peer_get_punch_symmetric(peer))
		return 0;

	if (remote_nat_type == FASTD_NAT_SYMMETRIC)
		return fastd_peer_get_punch_hard_symmetric(peer) ? 1 : 0;

	if (remote_nat_type == FASTD_NAT_SYMMETRIC_EASY_INC || remote_nat_type == FASTD_NAT_SYMMETRIC_EASY_DEC)
		return 1;

	if (!local_available)
		return 0;

	if (!nat_type_uses_local_socket_array(local_nat_type, fastd_peer_get_punch_hard_symmetric(peer)))
		return 0;

	return conf.punch_max_sockets ? conf.punch_max_sockets : 1;
}

/** Returns the number of short-lived UDP sockets to use for one punch command */
static unsigned punch_udp_socket_count(fastd_peer_t *peer, fastd_nat_type_t remote_nat_type) {
	fastd_nat_status_t status;
	if (!fastd_nat_get_status(&status) || !status.available)
		return punch_udp_socket_count_for_nat(peer, remote_nat_type, false, FASTD_NAT_UNKNOWN);

	return punch_udp_socket_count_for_nat(peer, remote_nat_type, true, status.type);
}

/** Adds one endpoint candidate to a bounded output array */
static size_t
add_endpoint_candidate(fastd_peer_address_t *out, size_t out_len, size_t count, const fastd_peer_address_t *endpoint) {
	if (count >= out_len)
		return count;

	out[count++] = *endpoint;
	return count;
}

/** Builds concrete endpoint candidates for a remote peer's NAT metadata */
static size_t build_endpoint_candidates(
	fastd_peer_address_t *out, size_t out_len, const fastd_peer_address_t *endpoint, fastd_nat_type_t nat_type,
	int port_delta, unsigned max_sockets, bool symmetric, bool hard_symmetric) {
	if (!out_len)
		return 0;

	if (!symmetric || endpoint->sa.sa_family != AF_INET)
		return add_endpoint_candidate(out, out_len, 0, endpoint);

	unsigned count = max_sockets ? max_sockets : 1;
	if (count > out_len)
		count = out_len;

	int base_port = ntohs(fastd_peer_address_get_port(endpoint));
	size_t n_candidates = 0;

	if (nat_type == FASTD_NAT_SYMMETRIC && hard_symmetric) {
		int start = base_port - (int)(count / 2);

		unsigned i;
		for (i = 0; i < count; i++) {
			int port = start + (int)i;
			if (port <= 0 || port > 65535)
				continue;

			fastd_peer_address_t predicted = *endpoint;
			set_endpoint_port(&predicted, port);
			n_candidates = add_endpoint_candidate(out, out_len, n_candidates, &predicted);
		}

		return n_candidates;
	}

	if (nat_type != FASTD_NAT_SYMMETRIC_EASY_INC && nat_type != FASTD_NAT_SYMMETRIC_EASY_DEC)
		return add_endpoint_candidate(out, out_len, 0, endpoint);

	int direction = nat_type == FASTD_NAT_SYMMETRIC_EASY_INC ? 1 : -1;
	int step = easy_symmetric_step(port_delta);

	unsigned i;
	for (i = 0; i < count; i++) {
		int port = base_port + direction * step * (int)i;
		if (port <= 0 || port > 65535)
			continue;

		fastd_peer_address_t predicted = *endpoint;
		set_endpoint_port(&predicted, port);
		n_candidates = add_endpoint_candidate(out, out_len, n_candidates, &predicted);
	}

	return n_candidates;
}

#ifdef WITH_TESTS

/** Test wrapper for punch endpoint prediction */
size_t fastd_punch_test_build_endpoint_candidates(
	fastd_peer_address_t *out, size_t out_len, const fastd_peer_address_t *endpoint, fastd_nat_type_t nat_type,
	int port_delta, unsigned max_sockets, bool symmetric, bool hard_symmetric) {
	return build_endpoint_candidates(
		out, out_len, endpoint, nat_type, port_delta, max_sockets, symmetric, hard_symmetric);
}

/** Test wrapper for punch control message parsing */
bool fastd_punch_test_parse_endpoint_message(const uint8_t *data, size_t len, uint8_t *type, size_t *key_len) {
	fastd_buffer_t buffer = {
		.data = (void *)data,
		.len = len,
	};
	const fastd_punch_endpoint_t *payload = NULL;
	uint8_t parsed_type = 0;

	if (!parse_endpoint_message(&buffer, &parsed_type, &payload))
		return false;

	if (type)
		*type = parsed_type;
	if (key_len)
		*key_len = payload->key_len;

	return true;
}

/** Test wrapper for punch UDP socket count policy */
unsigned fastd_punch_test_udp_socket_count(fastd_peer_t *peer, fastd_nat_type_t remote_nat_type) {
	return punch_udp_socket_count(peer, remote_nat_type);
}

/** Test wrapper for punch UDP socket count policy with explicit local NAT type */
unsigned fastd_punch_test_udp_socket_count_for_nat(
	fastd_peer_t *peer, fastd_nat_type_t remote_nat_type, bool local_available, fastd_nat_type_t local_nat_type) {
	return punch_udp_socket_count_for_nat(peer, remote_nat_type, local_available, local_nat_type);
}

#endif

/** Sends one concrete endpoint candidate as a cone punching command */
static bool relay_one_endpoint_to_peer(
	fastd_peer_t *dest, fastd_peer_t *subject, const fastd_peer_address_t *endpoint, fastd_nat_type_t nat_type) {
	return send_endpoint_message(
		dest, FASTD_PUNCH_SEND_CONE, conf.protocol->get_peer_key(subject), conf.protocol->key_length(),
		endpoint, nat_type, subject->punch_min_port, subject->punch_max_port, subject->punch_port_delta);
}

/** Sends one peer endpoint, or bounded easy-symmetric predictions, to another peer */
static size_t relay_endpoint_to_peer(fastd_peer_t *dest, fastd_peer_t *subject, size_t limit) {
	if (!fastd_peer_is_established(dest) || !fastd_peer_is_established(subject))
		return 0;
	if (!limit)
		return 0;

	fastd_peer_address_t endpoint;
	fastd_nat_type_t nat_type;
	if (!get_peer_endpoint(subject, &endpoint, &nat_type))
		return 0;

	unsigned count = conf.punch_max_sockets;
	if (!count)
		count = 1;
	if (count > limit)
		count = limit;

	fastd_peer_address_t *candidates = fastd_new_array(count, fastd_peer_address_t);
	size_t n_candidates = build_endpoint_candidates(
		candidates, count, &endpoint, nat_type, subject->punch_port_delta, conf.punch_max_sockets,
		fastd_peer_get_punch_symmetric(subject), fastd_peer_get_punch_hard_symmetric(subject));

	size_t sent = 0;
	size_t i;
	for (i = 0; i < n_candidates; i++) {
		if (relay_one_endpoint_to_peer(dest, subject, &candidates[i], nat_type))
			sent++;
	}

	free(candidates);

	return sent;
}

/** Relays endpoint control messages between established peers without forwarding data packets */
static void relay_peer_endpoints(void) {
	if (!conf.punch_control_relay || !punch_control_supported())
		return;

	size_t sent = 0;
	size_t i, j;
	for (i = 0; i < VECTOR_LEN(ctx.peers) && sent < conf.punch_max_packets; i++) {
		fastd_peer_t *subject = VECTOR_INDEX(ctx.peers, i);
		if (!fastd_peer_is_established(subject) || !fastd_timed_out(subject->next_punch_relay))
			continue;

		for (j = 0; j < VECTOR_LEN(ctx.peers) && sent < conf.punch_max_packets; j++) {
			fastd_peer_t *dest = VECTOR_INDEX(ctx.peers, j);
			if (dest == subject)
				continue;

			sent += relay_endpoint_to_peer(dest, subject, conf.punch_max_packets - sent);
		}

		subject->next_punch_relay = ctx.now + FASTD_PUNCH_RELAY_INTERVAL;
	}
}

/** Stores NAT metadata announced by a peer */
static void handle_nat_info(fastd_peer_t *sender, const fastd_punch_endpoint_t *payload) {
	size_t key_len = conf.protocol->key_length();
	if (payload->key_len != key_len)
		return;

	const uint8_t *key = (const uint8_t *)(payload + 1);
	fastd_peer_t *subject = find_peer_by_key(key, key_len);
	if (!subject || subject != sender)
		return;

	fastd_peer_address_t endpoint;
	if (!decode_address(&endpoint, payload))
		return;

	subject->punch_endpoint = endpoint;
	subject->punch_nat_type = payload->nat_type;
	subject->punch_min_port = be16toh(payload->min_port);
	subject->punch_max_port = be16toh(payload->max_port);
	subject->punch_port_delta = (int16_t)be16toh(payload->port_delta);
	subject->punch_timeout = ctx.now + PEER_STALE_TIME;

	pr_debug(
		"received punch NAT info from %P: %s %I", subject, fastd_nat_type_name(subject->punch_nat_type),
		&endpoint);
}

/** Handles a cone punching command */
static void handle_send_cone(fastd_peer_t *sender, const fastd_punch_endpoint_t *payload) {
	size_t key_len = conf.protocol->key_length();
	if (payload->key_len != key_len)
		return;

	const uint8_t *key = (const uint8_t *)(payload + 1);
	if (key_is_self(key, key_len))
		return;

	fastd_peer_t *peer = find_peer_by_key(key, key_len);
	if (!peer)
		return;

	fastd_peer_address_t endpoint;
	if (!decode_address(&endpoint, payload))
		return;

	unsigned udp_punch_sockets = punch_udp_socket_count(peer, payload->nat_type);
	bool exact_udp_punch = udp_punch_sockets > 0;
	fastd_peer_add_punch_control_candidate(
		peer, &endpoint, FASTD_PUNCH_CANDIDATE_PRIORITY, exact_udp_punch, udp_punch_sockets);
	if (fastd_peer_send_direct_handshake(peer, &endpoint))
		ctx.punch_direct_handshakes++;

	pr_debug("received punch cone command from %P for %P[%I]", sender, peer, &endpoint);
}

/** Handles an authenticated punch control packet. Returns true if the packet was consumed. */
bool fastd_punch_handle_control(fastd_peer_t *peer, fastd_buffer_t *buffer) {
	if (buffer->len < sizeof(fastd_punch_header_t) ||
	    memcmp(buffer->data, fastd_punch_magic, sizeof(fastd_punch_magic)))
		return false;

	if (!punch_control_supported())
		goto end_free;

	uint8_t type = 0;
	const fastd_punch_endpoint_t *payload = NULL;
	if (!parse_endpoint_message(buffer, &type, &payload))
		goto end_free;

	ctx.punch_control_rx++;

	switch (type) {
	case FASTD_PUNCH_NAT_INFO:
		handle_nat_info(peer, payload);
		break;

	case FASTD_PUNCH_SEND_CONE:
		handle_send_cone(peer, payload);
		break;

	default:
		break;
	}

end_free:
	fastd_buffer_free(buffer);
	return true;
}

/** Periodic punch control maintenance */
void fastd_punch_maintenance(void) {
	if (!punch_control_supported())
		return;

	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
		fastd_peer_t *peer = VECTOR_INDEX(ctx.peers, i);
		if (fastd_peer_is_established(peer))
			send_local_nat_info(peer);
	}

	relay_peer_endpoints();
}
