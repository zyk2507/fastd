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
#include "hole_punch.h"
#include "method.h"
#include "peer.h"


#define FASTD_PUNCH_VERSION 1
#define FASTD_PUNCH_NAT_INFO 1
#define FASTD_PUNCH_SEND_CONE 2
#define FASTD_PUNCH_RESULT 3
#define FASTD_PUNCH_SEND_EASY_SYM 4
#define FASTD_PUNCH_SEND_HARD_SYM 5
#define FASTD_PUNCH_BOTH_EASY_SYM 6
#define FASTD_PUNCH_TCP_NAT_INFO 7
#define FASTD_PUNCH_SEND_TCP 8
#define FASTD_PUNCH_RESULT_EXT 9
#define FASTD_PUNCH_RESULT_LISTENER 10
#define FASTD_PUNCH_SELECT_LISTENER 11
#define FASTD_PUNCH_LISTENER_INFO 12
#define FASTD_PUNCH_NAT_INFO_EXTRA 13
#define FASTD_PUNCH_TCP_NAT_INFO_EXTRA 14

#define FASTD_PUNCH_CANDIDATE_PRIORITY 120
#define FASTD_PUNCH_EASY_SYM_MAX_STEP 8
#define FASTD_PUNCH_BOTH_EASY_SYM_OFFSET 20
#define FASTD_PUNCH_HARD_SYM_PORT_SPACE 65535U
#define FASTD_PUNCH_NAT_INFO_GRACE 2000
#define FASTD_PUNCH_PAIR_DEMAND_TIME 30000
#define FASTD_PUNCH_RESULT_DEDUP_TIME 2000

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

/** Endpoint payload used by NAT_INFO and endpoint punch commands */
typedef struct __attribute__((packed)) fastd_punch_endpoint {
	uint8_t key_len;        /**< Length of the following protocol key */
	uint8_t nat_type;       /**< fastd_nat_type_t value */
	uint8_t address_family; /**< FASTD_PUNCH_AF_* */
	uint8_t reserved;       /**< Type-specific extra value; used as result code for FASTD_PUNCH_RESULT* */
	uint16_t port;          /**< Endpoint port, network byte order */
	uint16_t min_port;      /**< Lowest observed public port, network byte order */
	uint16_t max_port;      /**< Highest observed public port, network byte order */
	int16_t port_delta;     /**< Easy-symmetric public port delta, network byte order */
	uint16_t packet_count;  /**< Requested punch packet/socket count, network byte order */
	uint8_t address[16];    /**< IPv4 address in the first 4 bytes, or an IPv6 address */
} fastd_punch_endpoint_t;

/** Extended result metadata appended by FASTD_PUNCH_RESULT_EXT before the subject key */
typedef struct __attribute__((packed)) fastd_punch_result_ext {
	uint8_t command_type;          /**< Original FASTD_PUNCH_SEND_* command type */
	uint8_t reserved;              /**< Reserved for future flags */
	uint16_t udp_punch_sockets;    /**< Receiver-side UDP punch socket count, network byte order */
	uint32_t hard_sym_port_index;  /**< Receiver hard-symmetric scan index, network byte order */
	uint32_t hard_sym_next_index;  /**< Receiver hard-symmetric next scan index, network byte order */
	uint32_t hard_sym_round;       /**< Receiver hard-symmetric scan round, network byte order */
	uint32_t wait_window_ms;       /**< Expected short-term punch wait window, network byte order */
} fastd_punch_result_ext_t;

/** Compact address payload used inside punch result listener metadata */
typedef struct __attribute__((packed)) fastd_punch_address {
	uint8_t address_family; /**< FASTD_PUNCH_AF_* */
	uint8_t flags;          /**< FASTD_PUNCH_ADDRESS_* flags */
	uint16_t port;          /**< Endpoint port, network byte order */
	uint8_t address[16];    /**< IPv4 address in the first 4 bytes, or an IPv6 address */
} fastd_punch_address_t;

/** Extended result metadata with the target's base mapped listener endpoint */
typedef struct __attribute__((packed)) fastd_punch_result_listener {
	fastd_punch_result_ext_t result;         /**< Common extended result metadata */
	uint32_t listener_id;                    /**< Runtime public listener ID, network byte order */
	fastd_punch_address_t base_mapped_addr; /**< Target's selected base mapped listener endpoint */
} fastd_punch_result_listener_t;

/** Listener metadata appended by FASTD_PUNCH_LISTENER_INFO before the sender key */
typedef struct __attribute__((packed)) fastd_punch_listener_info {
	uint32_t listener_id; /**< Runtime public listener ID, network byte order */
} fastd_punch_listener_info_t;

/** Optional listener metadata appended by endpoint punch commands before the subject key */
typedef struct __attribute__((packed)) fastd_punch_command_listener {
	uint32_t listener_id; /**< Runtime public listener ID for the command endpoint, network byte order */
} fastd_punch_command_listener_t;

enum {
	FASTD_PUNCH_ADDRESS_AVAILABLE = 1u << 0,
	FASTD_PUNCH_ADDRESS_PORT_MAPPED = 1u << 1,
};

enum {
	FASTD_PUNCH_SELECT_FORCE_NEW = 1u << 0,
	FASTD_PUNCH_SELECT_PREFER_PORT_MAPPING = 1u << 1,
	FASTD_PUNCH_LISTENER_PORT_MAPPED = 1u << 0,
};

/** Result codes carried by FASTD_PUNCH_RESULT */
typedef enum fastd_punch_result {
	FASTD_PUNCH_RESULT_ACCEPTED = 1,   /**< Candidate was accepted but no immediate handshake was sent */
	FASTD_PUNCH_RESULT_HANDSHAKE = 2,  /**< Candidate was accepted and an immediate handshake was sent */
	FASTD_PUNCH_RESULT_SUPPRESSED = 3, /**< Candidate was suppressed by local cooldown policy */
	FASTD_PUNCH_RESULT_NO_PEER = 4,    /**< Subject key is not configured locally */
	FASTD_PUNCH_RESULT_BUSY = 5,       /**< Receiver already has a verified path for this peer */
} fastd_punch_result_t;


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

/** Encodes a compact address into a nested punch control payload */
static bool encode_compact_address(fastd_punch_address_t *payload, const fastd_peer_address_t *addr) {
	memset(payload, 0, sizeof(*payload));
	payload->port = fastd_peer_address_get_port(addr);

	switch (addr->sa.sa_family) {
	case AF_INET:
		payload->address_family = FASTD_PUNCH_AF_INET;
		memcpy(payload->address, &addr->in.sin_addr, sizeof(addr->in.sin_addr));
		return true;

	case AF_INET6:
		payload->address_family = FASTD_PUNCH_AF_INET6;
		memcpy(payload->address, &addr->in6.sin6_addr, sizeof(addr->in6.sin6_addr));
		return true;

	default:
		return false;
	}
}

/** Decodes a compact address from a nested punch control payload */
static bool decode_compact_address(fastd_peer_address_t *addr, const fastd_punch_address_t *payload) {
	memset(addr, 0, sizeof(*addr));

	if (!(payload->flags & FASTD_PUNCH_ADDRESS_AVAILABLE))
		return false;

	switch (payload->address_family) {
	case FASTD_PUNCH_AF_INET:
		addr->in.sin_family = AF_INET;
		addr->in.sin_port = payload->port;
		memcpy(&addr->in.sin_addr, payload->address, sizeof(addr->in.sin_addr));
		return true;

	case FASTD_PUNCH_AF_INET6:
		addr->in6.sin6_family = AF_INET6;
		addr->in6.sin6_port = payload->port;
		memcpy(&addr->in6.sin6_addr, payload->address, sizeof(addr->in6.sin6_addr));
		return true;

	default:
		return false;
	}
}

/** Returns the extra payload length used by a punch control message type */
static size_t endpoint_message_static_extra_len(uint8_t type) {
	switch (type) {
	case FASTD_PUNCH_RESULT_EXT:
		return sizeof(fastd_punch_result_ext_t);

	case FASTD_PUNCH_RESULT_LISTENER:
		return sizeof(fastd_punch_result_listener_t);

	case FASTD_PUNCH_LISTENER_INFO:
		return sizeof(fastd_punch_listener_info_t);

	default:
		return 0;
	}
}

/** Returns true for endpoint punch commands that may carry optional listener metadata */
static bool endpoint_message_accepts_command_listener(uint8_t type) {
	switch (type) {
	case FASTD_PUNCH_SEND_CONE:
	case FASTD_PUNCH_SEND_EASY_SYM:
	case FASTD_PUNCH_SEND_HARD_SYM:
	case FASTD_PUNCH_BOTH_EASY_SYM:
		return true;

	default:
		return false;
	}
}

/** Returns the validated extra payload length for an endpoint punch control message */
static size_t endpoint_message_extra_len(uint8_t type, const fastd_punch_endpoint_t *payload) {
	size_t static_len = endpoint_message_static_extra_len(type);
	if (static_len)
		return static_len;
	if (!endpoint_message_accepts_command_listener(type))
		return 0;

	const fastd_punch_header_t *header = (const fastd_punch_header_t *)payload - 1;
	size_t len = be16toh(header->length);
	size_t base_len = sizeof(*header) + sizeof(*payload) + payload->key_len;

	return len == base_len + sizeof(fastd_punch_command_listener_t) ?
		       sizeof(fastd_punch_command_listener_t) :
		       0;
}

/** Returns the key pointer for an already validated endpoint punch control message */
static const uint8_t *endpoint_message_key(uint8_t type, const fastd_punch_endpoint_t *payload) {
	return (const uint8_t *)(payload + 1) + endpoint_message_extra_len(type, payload);
}

/** Returns the extended result payload for an already validated result-ext message */
static const fastd_punch_result_ext_t *endpoint_message_result_ext(uint8_t type, const fastd_punch_endpoint_t *payload) {
	if (type != FASTD_PUNCH_RESULT_EXT && type != FASTD_PUNCH_RESULT_LISTENER)
		return NULL;

	return (const fastd_punch_result_ext_t *)(payload + 1);
}

/** Returns the listener result payload for an already validated listener-result message */
static const fastd_punch_result_listener_t *
endpoint_message_result_listener(uint8_t type, const fastd_punch_endpoint_t *payload) {
	if (type != FASTD_PUNCH_RESULT_LISTENER)
		return NULL;

	return (const fastd_punch_result_listener_t *)(payload + 1);
}

/** Returns the listener-info payload for an already validated listener-info message */
static const fastd_punch_listener_info_t *
endpoint_message_listener_info(uint8_t type, const fastd_punch_endpoint_t *payload) {
	if (type != FASTD_PUNCH_LISTENER_INFO)
		return NULL;

	return (const fastd_punch_listener_info_t *)(payload + 1);
}

/** Returns optional command listener metadata for an already validated endpoint command message */
static const fastd_punch_command_listener_t *
endpoint_message_command_listener(uint8_t type, const fastd_punch_endpoint_t *payload) {
	if (!endpoint_message_accepts_command_listener(type))
		return NULL;
	if (endpoint_message_extra_len(type, payload) != sizeof(fastd_punch_command_listener_t))
		return NULL;

	return (const fastd_punch_command_listener_t *)(payload + 1);
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
	size_t base_len = sizeof(*header) + sizeof(*parsed_payload) + key_len;
	size_t static_extra_len = endpoint_message_static_extra_len(header->type);
	if (static_extra_len) {
		if (len != base_len + static_extra_len)
			return false;
	} else if (endpoint_message_accepts_command_listener(header->type)) {
		if (len != base_len && len != base_len + sizeof(fastd_punch_command_listener_t))
			return false;
	} else if (len != base_len) {
		return false;
	}

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

/** Adds one endpoint to a bounded list if it has not already been added */
static size_t add_unique_endpoint(
	fastd_peer_address_t *endpoints, size_t n_endpoints, size_t max_endpoints,
	const fastd_peer_address_t *endpoint) {
	if (endpoint->sa.sa_family != AF_INET && endpoint->sa.sa_family != AF_INET6)
		return n_endpoints;

	size_t i;
	for (i = 0; i < n_endpoints; i++) {
		if (fastd_peer_address_equal(&endpoints[i], endpoint))
			return n_endpoints;
	}

	if (n_endpoints >= max_endpoints)
		return n_endpoints;

	endpoints[n_endpoints++] = *endpoint;
	return n_endpoints;
}

/** Writes endpoint-local scan state back to the peer metadata by endpoint address */
static void sync_peer_punch_endpoint_scan_state(
	fastd_peer_t *peer, const fastd_peer_punch_endpoint_t *endpoints, size_t n_endpoints) {
	size_t i, j;

	for (i = 0; i < peer->n_punch_endpoints; i++) {
		for (j = 0; j < n_endpoints; j++) {
			if (!fastd_peer_address_equal(&peer->punch_endpoints[i].address, &endpoints[j].address))
				continue;

			peer->punch_endpoints[i].hard_sym_port_index = endpoints[j].hard_sym_port_index;
			peer->punch_endpoints[i].hard_sym_round = endpoints[j].hard_sym_round;
			break;
		}
	}

	for (j = 0; j < n_endpoints; j++) {
		if (!fastd_peer_address_equal(&peer->punch_endpoint, &endpoints[j].address))
			continue;

		peer->punch_hard_sym_port_index = endpoints[j].hard_sym_port_index;
		peer->punch_hard_sym_round = endpoints[j].hard_sym_round;
		return;
	}

	if (n_endpoints) {
		peer->punch_hard_sym_port_index = endpoints[0].hard_sym_port_index;
		peer->punch_hard_sym_round = endpoints[0].hard_sym_round;
	}
}

/** Initializes one punch endpoint metadata entry */
static fastd_peer_punch_endpoint_t make_punch_endpoint(
	const fastd_peer_address_t *endpoint, fastd_nat_type_t nat_type, uint16_t min_port, uint16_t max_port,
	int port_delta) {
	return (fastd_peer_punch_endpoint_t){
		.address = *endpoint,
		.nat_type = nat_type,
		.min_port = min_port,
		.max_port = max_port,
		.port_delta = port_delta,
	};
}

/** Adds or updates one punch endpoint metadata entry, preserving scan state when metadata is unchanged */
static size_t add_or_update_punch_endpoint(
	fastd_peer_punch_endpoint_t *endpoints, size_t n_endpoints, size_t max_endpoints,
	const fastd_peer_address_t *endpoint, fastd_nat_type_t nat_type, uint16_t min_port, uint16_t max_port,
	int port_delta) {
	if (endpoint->sa.sa_family != AF_INET && endpoint->sa.sa_family != AF_INET6)
		return n_endpoints;

	size_t i;
	for (i = 0; i < n_endpoints; i++) {
		fastd_peer_punch_endpoint_t *entry = &endpoints[i];
		if (!fastd_peer_address_equal(&entry->address, endpoint))
			continue;

		bool changed = entry->nat_type != nat_type || entry->min_port != min_port ||
			       entry->max_port != max_port || entry->port_delta != port_delta;

		entry->nat_type = nat_type;
		entry->min_port = min_port;
		entry->max_port = max_port;
		entry->port_delta = port_delta;
		if (changed) {
			entry->hard_sym_port_index = 0;
			entry->hard_sym_round = 0;
		}

		return n_endpoints;
	}

	if (n_endpoints >= max_endpoints)
		return n_endpoints;

	endpoints[n_endpoints++] = make_punch_endpoint(endpoint, nat_type, min_port, max_port, port_delta);
	return n_endpoints;
}

/** Adds one punch endpoint metadata entry to a bounded list if it has not already been added */
static size_t add_unique_punch_endpoint(
	fastd_peer_punch_endpoint_t *endpoints, size_t n_endpoints, size_t max_endpoints,
	const fastd_peer_punch_endpoint_t *endpoint) {
	if (endpoint->address.sa.sa_family != AF_INET && endpoint->address.sa.sa_family != AF_INET6)
		return n_endpoints;

	size_t i;
	for (i = 0; i < n_endpoints; i++) {
		if (fastd_peer_address_equal(&endpoints[i].address, &endpoint->address))
			return n_endpoints;
	}

	if (n_endpoints >= max_endpoints)
		return n_endpoints;

	endpoints[n_endpoints++] = *endpoint;
	return n_endpoints;
}

/** Returns all currently known punchable UDP endpoints for a peer from the relay's point of view */
static size_t get_peer_endpoints(
	const fastd_peer_t *peer, fastd_peer_punch_endpoint_t *endpoints, size_t max_endpoints) {
	bool have_nat_info = peer->punch_endpoint.sa.sa_family != AF_UNSPEC && !fastd_timed_out(peer->punch_timeout);
	size_t n_endpoints = 0;

	if (fastd_peer_is_established(peer) &&
	    (peer->address.sa.sa_family == AF_INET || peer->address.sa.sa_family == AF_INET6)) {
		fastd_peer_punch_endpoint_t endpoint = make_punch_endpoint(
			&peer->address, have_nat_info ? peer->punch_nat_type : FASTD_NAT_UNKNOWN,
			peer->punch_min_port, peer->punch_max_port, peer->punch_port_delta);
		n_endpoints = add_unique_punch_endpoint(endpoints, n_endpoints, max_endpoints, &endpoint);
	}

	if (have_nat_info) {
		size_t i;
		if (peer->n_punch_endpoints) {
			for (i = 0; i < peer->n_punch_endpoints; i++)
				n_endpoints = add_unique_punch_endpoint(
					endpoints, n_endpoints, max_endpoints, &peer->punch_endpoints[i]);
		} else {
			fastd_peer_punch_endpoint_t endpoint = make_punch_endpoint(
				&peer->punch_endpoint, peer->punch_nat_type, peer->punch_min_port,
				peer->punch_max_port, peer->punch_port_delta);
			n_endpoints = add_unique_punch_endpoint(endpoints, n_endpoints, max_endpoints, &endpoint);
		}
	}

	return n_endpoints;
}

/** Returns true if a NAT type has a predictable symmetric port direction */
static bool nat_type_is_easy_symmetric(fastd_nat_type_t nat_type) {
	return nat_type == FASTD_NAT_SYMMETRIC_EASY_INC || nat_type == FASTD_NAT_SYMMETRIC_EASY_DEC;
}

/** Returns true if a NAT type uses endpoint-dependent mappings */
static bool nat_type_is_endpoint_dependent(fastd_nat_type_t nat_type) {
	return nat_type == FASTD_NAT_SYMMETRIC || nat_type_is_easy_symmetric(nat_type);
}

/** Returns true if punching this NAT type needs the receiver's NAT metadata as well */
static bool nat_type_needs_dest_nat_info(fastd_nat_type_t nat_type) {
	return nat_type_is_endpoint_dependent(nat_type);
}

/** Returns true if a peer has fresh punch NAT metadata */
static bool peer_has_fresh_punch_nat_info(const fastd_peer_t *peer) {
	return peer->punch_endpoint.sa.sa_family != AF_UNSPEC && !fastd_timed_out(peer->punch_timeout);
}

/** Returns true if a peer has fresh TCP punch NAT metadata */
static bool peer_has_fresh_tcp_punch_nat_info(const fastd_peer_t *peer) {
	return peer->tcp_punch_endpoint.sa.sa_family != AF_UNSPEC && !fastd_timed_out(peer->tcp_punch_timeout);
}

/** Returns true if a peer has fresh UDP or TCP punch metadata */
static bool peer_has_fresh_punch_task_metadata(const fastd_peer_t *peer) {
	return peer_has_fresh_punch_nat_info(peer) || peer_has_fresh_tcp_punch_nat_info(peer);
}

/** Returns true if relay-generated punch commands may be sent for a peer now */
static bool peer_punch_relay_due(const fastd_peer_t *peer) {
	return fastd_peer_is_established(peer) && fastd_timed_out(peer->next_punch_relay);
}

/** Tracks the earliest future retry point observed during one task-manager collection run */
static void task_manager_note_next_retry(fastd_timeout_t timeout) {
	if (timeout == FASTD_TIMEOUT_INV || fastd_timed_out(timeout))
		return;

	if (ctx.punch_task_manager_next_retry == FASTD_TIMEOUT_INV || timeout < ctx.punch_task_manager_next_retry)
		ctx.punch_task_manager_next_retry = timeout;
}

/** Returns the earlier future retry timeout, ignoring invalid or expired timeouts */
static fastd_timeout_t task_manager_earlier_next_retry(fastd_timeout_t a, fastd_timeout_t b) {
	if (a == FASTD_TIMEOUT_INV || fastd_timed_out(a))
		return b == FASTD_TIMEOUT_INV || fastd_timed_out(b) ? FASTD_TIMEOUT_INV : b;
	if (b == FASTD_TIMEOUT_INV || fastd_timed_out(b))
		return a;

	return a < b ? a : b;
}

/** Returns the next monotonic peer-pair task ID */
static uint64_t next_punch_pair_task_id(void) {
	ctx.next_punch_pair_task_id++;
	if (!ctx.next_punch_pair_task_id)
		ctx.next_punch_pair_task_id++;

	return ctx.next_punch_pair_task_id;
}

/** Stores the stable peer ID order used by peer-pair task history */
static void ordered_punch_pair_ids(const fastd_peer_t *a, const fastd_peer_t *b, uint64_t *peer_a_id, uint64_t *peer_b_id) {
	uint64_t a_id = a ? a->id : 0;
	uint64_t b_id = b ? b->id : 0;

	if (a_id <= b_id) {
		*peer_a_id = a_id;
		*peer_b_id = b_id;
	}
	else {
		*peer_a_id = b_id;
		*peer_b_id = a_id;
	}
}

/** Clamps a task-manager count to a status snapshot field */
static uint16_t pair_task_count16(size_t count) {
	return count > UINT16_MAX ? UINT16_MAX : count;
}

/** Records one bounded peer-pair task-manager lifecycle snapshot */
static void task_manager_record_pair_task_ids(
	uint64_t peer_a_id, uint64_t peer_b_id, uint64_t subject_id, uint64_t destination_id,
	fastd_punch_pair_task_stage_t stage, size_t candidates_sent, size_t backoff_skipped,
	fastd_timeout_t next_retry, bool budget_exhausted) {
	size_t pos = ctx.punch_pair_task_pos % FASTD_PUNCH_PAIR_TASK_HISTORY;
	ctx.punch_pair_tasks[pos] = (fastd_punch_pair_task_t){
		.id = next_punch_pair_task_id(),
		.updated = ctx.now,
		.next_retry = next_retry,
		.peer_a_id = peer_a_id,
		.peer_b_id = peer_b_id,
		.subject_id = subject_id,
		.destination_id = destination_id,
		.stage = stage,
		.candidates_sent = pair_task_count16(candidates_sent),
		.backoff_skipped = pair_task_count16(backoff_skipped),
		.budget_exhausted = budget_exhausted,
	};

	ctx.punch_pair_task_pos = (pos + 1) % FASTD_PUNCH_PAIR_TASK_HISTORY;
	if (ctx.punch_pair_task_count < FASTD_PUNCH_PAIR_TASK_HISTORY)
		ctx.punch_pair_task_count++;
}

/** Records one bounded peer-pair task-manager lifecycle snapshot */
static void task_manager_record_pair_task(
	const fastd_peer_t *a, const fastd_peer_t *b, const fastd_peer_t *subject, const fastd_peer_t *destination,
	fastd_punch_pair_task_stage_t stage, size_t candidates_sent, size_t backoff_skipped,
	fastd_timeout_t next_retry, bool budget_exhausted) {
	uint64_t peer_a_id, peer_b_id;
	ordered_punch_pair_ids(a, b, &peer_a_id, &peer_b_id);
	task_manager_record_pair_task_ids(
		peer_a_id, peer_b_id, subject ? subject->id : 0, destination ? destination->id : 0, stage,
		candidates_sent, backoff_skipped, next_retry, budget_exhausted);
}

/** Records the lifecycle outcome after attempting to launch one collected peer-pair task */
static void task_manager_record_launch_result(
	size_t before_pair, size_t sent, size_t backoff_skipped, fastd_timeout_t backoff_next_retry) {
	if (sent > before_pair) {
		ctx.punch_task_manager_launched++;
		return;
	}

	if (backoff_skipped) {
		ctx.punch_task_manager_blacklisted++;
		task_manager_note_next_retry(backoff_next_retry);
		return;
	}

	ctx.punch_task_manager_suppressed++;
}

/** Records a remote punch-result outcome in the task-manager lifecycle counters */
static void task_manager_record_remote_result(fastd_punch_result_t result) {
	switch (result) {
	case FASTD_PUNCH_RESULT_ACCEPTED:
		ctx.punch_task_manager_outcome_accepted++;
		return;

	case FASTD_PUNCH_RESULT_HANDSHAKE:
		ctx.punch_task_manager_outcome_handshake++;
		return;

	case FASTD_PUNCH_RESULT_SUPPRESSED:
		ctx.punch_task_manager_outcome_suppressed++;
		return;

	case FASTD_PUNCH_RESULT_NO_PEER:
		ctx.punch_task_manager_outcome_no_peer++;
		return;

	case FASTD_PUNCH_RESULT_BUSY:
		ctx.punch_task_manager_outcome_busy++;
		return;

	default:
		return;
	}
}

/** Returns true if a timeout is active and still in the future */
static bool task_timeout_active(fastd_timeout_t timeout) {
	return timeout != FASTD_TIMEOUT_INV && !fastd_timed_out(timeout);
}

static bool punch_result_causes_relay_backoff(fastd_punch_result_t result);

/** Returns true if a peer-pair runtime entry still carries useful scheduling state */
static bool pair_runtime_active(const fastd_punch_pair_runtime_t *runtime) {
	return task_timeout_active(runtime->in_flight_until) || task_timeout_active(runtime->backoff_until) ||
	       task_timeout_active(runtime->recent_demand_until);
}

/** Finds the runtime state index for a peer pair */
static bool find_pair_runtime_index(uint64_t peer_a_id, uint64_t peer_b_id, size_t *index) {
	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.punch_pair_states); i++) {
		const fastd_punch_pair_runtime_t *runtime = &VECTOR_INDEX(ctx.punch_pair_states, i);
		if (runtime->peer_a_id == peer_a_id && runtime->peer_b_id == peer_b_id) {
			if (index)
				*index = i;
			return true;
		}
	}

	return false;
}

/** Finds the runtime state for a peer pair */
static fastd_punch_pair_runtime_t *find_pair_runtime(const fastd_peer_t *a, const fastd_peer_t *b) {
	uint64_t peer_a_id, peer_b_id;
	ordered_punch_pair_ids(a, b, &peer_a_id, &peer_b_id);

	size_t index;
	return find_pair_runtime_index(peer_a_id, peer_b_id, &index) ? &VECTOR_INDEX(ctx.punch_pair_states, index) :
								       NULL;
}

/** Removes stale pair runtime entries and reports expired in-flight tasks */
static void task_manager_compact_pair_states(void) {
	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.punch_pair_states);) {
		fastd_punch_pair_runtime_t *runtime = &VECTOR_INDEX(ctx.punch_pair_states, i);
		bool aborted = runtime->in_flight_until != FASTD_TIMEOUT_INV && fastd_timed_out(runtime->in_flight_until);

		if (aborted) {
			runtime->in_flight_until = FASTD_TIMEOUT_INV;
			runtime->abort_count++;
			runtime->updated = ctx.now;
			ctx.punch_task_manager_aborted++;
			task_manager_record_pair_task_ids(
				runtime->peer_a_id, runtime->peer_b_id, 0, 0, PUNCH_PAIR_TASK_STAGE_ABORTED, 0, 0,
				runtime->backoff_until, false);
		}

		if (pair_runtime_active(runtime)) {
			i++;
			continue;
		}

		VECTOR_DELETE(ctx.punch_pair_states, i);
	}
}

/** Returns an existing runtime entry or creates a bounded new one */
static fastd_punch_pair_runtime_t *get_pair_runtime(const fastd_peer_t *a, const fastd_peer_t *b) {
	uint64_t peer_a_id, peer_b_id;
	ordered_punch_pair_ids(a, b, &peer_a_id, &peer_b_id);

	size_t index;
	if (find_pair_runtime_index(peer_a_id, peer_b_id, &index))
		return &VECTOR_INDEX(ctx.punch_pair_states, index);

	task_manager_compact_pair_states();
	if (find_pair_runtime_index(peer_a_id, peer_b_id, &index))
		return &VECTOR_INDEX(ctx.punch_pair_states, index);

	if (VECTOR_LEN(ctx.punch_pair_states) >= FASTD_PUNCH_PAIR_STATE_LIMIT) {
		size_t victim = 0;
		size_t i;
		for (i = 1; i < VECTOR_LEN(ctx.punch_pair_states); i++) {
			if (VECTOR_INDEX(ctx.punch_pair_states, i).updated <
			    VECTOR_INDEX(ctx.punch_pair_states, victim).updated)
				victim = i;
		}
		VECTOR_DELETE(ctx.punch_pair_states, victim);
	}

	VECTOR_ADD(
		ctx.punch_pair_states, ((fastd_punch_pair_runtime_t){
					       .peer_a_id = peer_a_id,
					       .peer_b_id = peer_b_id,
					       .updated = ctx.now,
					       .in_flight_until = FASTD_TIMEOUT_INV,
					       .backoff_until = FASTD_TIMEOUT_INV,
					       .recent_demand_until = FASTD_TIMEOUT_INV,
				       }));
	return &VECTOR_INDEX(ctx.punch_pair_states, VECTOR_LEN(ctx.punch_pair_states) - 1);
}

/** Records forwarded data demand between two peers for punch scheduling and diagnostics */
void fastd_punch_note_peer_pair_demand(const fastd_peer_t *a, const fastd_peer_t *b) {
	if (!a || !b || a == b)
		return;

	fastd_punch_pair_runtime_t *runtime = get_pair_runtime(a, b);
	runtime->recent_demand_until = ctx.now + FASTD_PUNCH_PAIR_DEMAND_TIME;
	runtime->demand_seq++;
	if (!runtime->demand_seq) {
		runtime->demand_seq++;
		runtime->served_demand_seq = 0;
	}
	runtime->updated = ctx.now;

	fastd_timeout_t maintenance_timeout = fastd_task_timeout(&ctx.next_maintenance);
	if (conf.punch_control_relay && punch_control_supported() &&
	    (maintenance_timeout == FASTD_TIMEOUT_INV || maintenance_timeout > ctx.now)) {
		if (fastd_task_scheduled(&ctx.next_maintenance))
			fastd_task_unschedule(&ctx.next_maintenance);
		fastd_task_schedule(&ctx.next_maintenance, TASK_TYPE_MAINTENANCE, ctx.now);
	}
}

/** Marks a pair-level punch task as launched */
static void pair_runtime_mark_launched(const fastd_peer_t *a, const fastd_peer_t *b) {
	fastd_punch_pair_runtime_t *runtime = get_pair_runtime(a, b);
	runtime->in_flight_until = ctx.now + FASTD_HOLE_PUNCH_TIMEOUT;
	runtime->served_demand_seq = runtime->demand_seq;
	runtime->updated = ctx.now;
	if (runtime->launch_count < UINT16_MAX)
		runtime->launch_count++;
}

/** Marks a pair-level remote result and adjusts retry state */
static void pair_runtime_mark_result(
	fastd_peer_t *sender, fastd_peer_t *subject, fastd_punch_result_t result, fastd_timeout_t backoff_timeout) {
	if (!sender || !subject)
		return;

	fastd_punch_pair_runtime_t *runtime = get_pair_runtime(sender, subject);
	runtime->in_flight_until = FASTD_TIMEOUT_INV;
	runtime->updated = ctx.now;
	if (runtime->result_count < UINT16_MAX)
		runtime->result_count++;

	if (punch_result_causes_relay_backoff(result)) {
		if (runtime->busy_count < UINT16_MAX)
			runtime->busy_count++;
		runtime->backoff_until = backoff_timeout != FASTD_TIMEOUT_INV ? backoff_timeout :
								     ctx.now + FASTD_PUNCH_SUPPRESSION_TIME;
	}
	else {
		runtime->backoff_until = FASTD_TIMEOUT_INV;
	}
}

/** Releases punch-control task-manager runtime state */
void fastd_punch_cleanup(void) {
	VECTOR_FREE(ctx.punch_pair_states);
	ctx.punch_pair_states = (__typeof__(ctx.punch_pair_states)){};
	memset(ctx.punch_result_seen, 0, sizeof(ctx.punch_result_seen));
	ctx.punch_result_seen_pos = 0;
}

typedef struct fastd_punch_pair_state {
	bool established;
	bool has_metadata_a;
	bool has_metadata_b;
	bool due_a;
	bool due_b;
	bool collected;
	bool waiting;
	bool in_flight;
	bool backoff;
	bool recent_demand;
	bool pending_demand;
	bool missing_metadata;
	fastd_timeout_t next_retry;
} fastd_punch_pair_state_t;

static bool request_peer_punch_metadata(fastd_peer_t *peer);

/** Requests missing pair metadata after recent traffic demand exposed a useful direct path opportunity */
static size_t request_missing_pair_metadata(
	fastd_peer_t *a, fastd_peer_t *b, const fastd_punch_pair_state_t *state, size_t limit,
	fastd_timeout_t *next_retry) {
	if (!limit || !state->recent_demand)
		return 0;

	size_t sent = 0;

	if (!state->has_metadata_a && sent < limit && request_peer_punch_metadata(a)) {
		sent++;
		*next_retry = task_manager_earlier_next_retry(*next_retry, a->next_punch_metadata_request);
	}
	if (!state->has_metadata_b && sent < limit && request_peer_punch_metadata(b)) {
		sent++;
		*next_retry = task_manager_earlier_next_retry(*next_retry, b->next_punch_metadata_request);
	}

	if (!sent) {
		if (!state->has_metadata_a)
			*next_retry = task_manager_earlier_next_retry(*next_retry, a->next_punch_metadata_request);
		if (!state->has_metadata_b)
			*next_retry = task_manager_earlier_next_retry(*next_retry, b->next_punch_metadata_request);
	}

	return sent;
}

/** Evaluates whether an established peer pair should produce punch-control tasks in this maintenance tick */
static fastd_punch_pair_state_t punch_pair_state(const fastd_peer_t *a, const fastd_peer_t *b) {
	fastd_punch_pair_state_t state = {};

	state.established = fastd_peer_is_established(a) && fastd_peer_is_established(b);
	if (!state.established)
		return state;

	const fastd_punch_pair_runtime_t *runtime = find_pair_runtime(a, b);
	if (runtime) {
		state.in_flight = task_timeout_active(runtime->in_flight_until);
		state.backoff = task_timeout_active(runtime->backoff_until);
		state.recent_demand = task_timeout_active(runtime->recent_demand_until);
		state.pending_demand = state.recent_demand && runtime->demand_seq != runtime->served_demand_seq;
	}

	state.has_metadata_a = peer_has_fresh_punch_task_metadata(a);
	state.has_metadata_b = peer_has_fresh_punch_task_metadata(b);
	state.due_a = peer_punch_relay_due(a);
	state.due_b = peer_punch_relay_due(b);

	if (state.in_flight) {
		state.waiting = true;
		state.next_retry = runtime->in_flight_until;
		return state;
	}

	if (state.backoff)
		state.next_retry = runtime->backoff_until;

	if (state.backoff)
		return state;

	if (!state.has_metadata_a && !state.has_metadata_b) {
		state.missing_metadata = true;
		return state;
	}

	state.collected = state.pending_demand ||
			  (state.has_metadata_a && state.due_a) || (state.has_metadata_b && state.due_b);
	state.waiting = !state.collected;
	if (state.waiting) {
		state.next_retry = FASTD_TIMEOUT_INV;
		if (state.has_metadata_a && !state.due_a)
			state.next_retry = task_manager_earlier_next_retry(state.next_retry, a->next_punch_relay);
		if (state.has_metadata_b && !state.due_b)
			state.next_retry = task_manager_earlier_next_retry(state.next_retry, b->next_punch_relay);
	}
	return state;
}

/** Returns true while a newly established symmetric-punch peer may still publish NAT metadata */
static bool peer_waiting_for_punch_nat_info(const fastd_peer_t *peer) {
	if (!fastd_peer_get_punch_symmetric(peer) || peer_has_fresh_punch_nat_info(peer))
		return false;

	return peer->established && ctx.now < peer->established + FASTD_PUNCH_NAT_INFO_GRACE;
}

/** Returns true for endpoint punch command message types */
static bool punch_type_is_endpoint_command(uint8_t type) {
	switch (type) {
	case FASTD_PUNCH_SEND_CONE:
	case FASTD_PUNCH_SEND_EASY_SYM:
	case FASTD_PUNCH_SEND_HARD_SYM:
	case FASTD_PUNCH_BOTH_EASY_SYM:
	case FASTD_PUNCH_SEND_TCP:
		return true;

	default:
		return false;
	}
}

/** Returns a human-readable endpoint punch command name */
static const char *punch_command_type_name(uint8_t type) {
	switch (type) {
	case FASTD_PUNCH_SEND_CONE:
		return "cone";

	case FASTD_PUNCH_SEND_EASY_SYM:
		return "easy-symmetric";

	case FASTD_PUNCH_SEND_HARD_SYM:
		return "hard-symmetric";

	case FASTD_PUNCH_BOTH_EASY_SYM:
		return "both-easy-symmetric";

	case FASTD_PUNCH_SEND_TCP:
		return "tcp";

	default:
		return "unknown";
	}
}

/** Converts a wire command type to peer task status */
static fastd_peer_punch_task_command_t punch_task_command_from_type(uint8_t type) {
	switch (type) {
	case FASTD_PUNCH_SEND_CONE:
		return PEER_PUNCH_TASK_COMMAND_CONE;

	case FASTD_PUNCH_SEND_EASY_SYM:
		return PEER_PUNCH_TASK_COMMAND_EASY_SYM;

	case FASTD_PUNCH_SEND_HARD_SYM:
		return PEER_PUNCH_TASK_COMMAND_HARD_SYM;

	case FASTD_PUNCH_BOTH_EASY_SYM:
		return PEER_PUNCH_TASK_COMMAND_BOTH_EASY_SYM;

	case FASTD_PUNCH_SEND_TCP:
		return PEER_PUNCH_TASK_COMMAND_TCP;

	default:
		return PEER_PUNCH_TASK_COMMAND_NONE;
	}
}

/** Converts a wire result code to peer task status */
static fastd_peer_punch_task_result_t punch_task_result_from_wire(fastd_punch_result_t result) {
	switch (result) {
	case FASTD_PUNCH_RESULT_ACCEPTED:
		return PEER_PUNCH_TASK_RESULT_ACCEPTED;

	case FASTD_PUNCH_RESULT_HANDSHAKE:
		return PEER_PUNCH_TASK_RESULT_HANDSHAKE;

	case FASTD_PUNCH_RESULT_SUPPRESSED:
		return PEER_PUNCH_TASK_RESULT_SUPPRESSED;

	case FASTD_PUNCH_RESULT_NO_PEER:
		return PEER_PUNCH_TASK_RESULT_NO_PEER;

	case FASTD_PUNCH_RESULT_BUSY:
		return PEER_PUNCH_TASK_RESULT_BUSY;

	default:
		return PEER_PUNCH_TASK_RESULT_NONE;
	}
}

/** Returns the expected short-term wait window for one endpoint punch command */
static uint32_t punch_command_wait_window_ms(uint8_t type) {
	switch (type) {
	case FASTD_PUNCH_SEND_CONE:
	case FASTD_PUNCH_SEND_EASY_SYM:
	case FASTD_PUNCH_SEND_HARD_SYM:
	case FASTD_PUNCH_BOTH_EASY_SYM:
	case FASTD_PUNCH_SEND_TCP:
		return FASTD_HOLE_PUNCH_TIMEOUT;

	default:
		return 0;
	}
}

/** Returns the expected short-term wait window for one recorded punch task */
static uint32_t punch_task_wait_window_ms(fastd_peer_punch_task_command_t command) {
	switch (command) {
	case PEER_PUNCH_TASK_COMMAND_CONE:
	case PEER_PUNCH_TASK_COMMAND_EASY_SYM:
	case PEER_PUNCH_TASK_COMMAND_HARD_SYM:
	case PEER_PUNCH_TASK_COMMAND_BOTH_EASY_SYM:
	case PEER_PUNCH_TASK_COMMAND_TCP:
		return FASTD_HOLE_PUNCH_TIMEOUT;

	default:
		return 0;
	}
}

/** Returns the cause represented by one local punch task snapshot */
static fastd_peer_punch_task_cause_t punch_task_cause(
	fastd_peer_punch_task_role_t role, fastd_peer_punch_task_command_t command,
	fastd_peer_punch_task_result_t result) {
	switch (result) {
	case PEER_PUNCH_TASK_RESULT_NO_PEER:
		return PEER_PUNCH_TASK_CAUSE_MISSING_PEER;

	case PEER_PUNCH_TASK_RESULT_BUSY:
		return PEER_PUNCH_TASK_CAUSE_VERIFIED_BACKUP;

	case PEER_PUNCH_TASK_RESULT_SUPPRESSED:
		return PEER_PUNCH_TASK_CAUSE_LOCAL_POLICY;

	case PEER_PUNCH_TASK_RESULT_HANDSHAKE:
		return PEER_PUNCH_TASK_CAUSE_HANDSHAKE_SENT;

	case PEER_PUNCH_TASK_RESULT_ACCEPTED:
		return PEER_PUNCH_TASK_CAUSE_CANDIDATE_ADDED;

	default:
		break;
	}

	switch (role) {
	case PEER_PUNCH_TASK_ROLE_RELAY_SUBJECT:
	case PEER_PUNCH_TASK_ROLE_RELAY_DEST:
		return command == PEER_PUNCH_TASK_COMMAND_TCP ? PEER_PUNCH_TASK_CAUSE_RELAY_TCP :
								PEER_PUNCH_TASK_CAUSE_RELAY_UDP;

	case PEER_PUNCH_TASK_ROLE_COMMAND_TARGET:
		return PEER_PUNCH_TASK_CAUSE_REMOTE_COMMAND;

	case PEER_PUNCH_TASK_ROLE_RESULT_SENDER:
	case PEER_PUNCH_TASK_ROLE_RESULT_SUBJECT:
		return PEER_PUNCH_TASK_CAUSE_REMOTE_RESULT;

	default:
		return PEER_PUNCH_TASK_CAUSE_NONE;
	}
}

/** Returns the earliest expected retry or outcome timeout for one local punch task snapshot */
static fastd_timeout_t punch_task_next_retry_timeout(
	fastd_peer_punch_task_role_t role, fastd_peer_punch_task_command_t command,
	fastd_peer_punch_task_result_t result) {
	switch (result) {
	case PEER_PUNCH_TASK_RESULT_SUPPRESSED:
	case PEER_PUNCH_TASK_RESULT_NO_PEER:
	case PEER_PUNCH_TASK_RESULT_BUSY:
		return ctx.now + FASTD_PUNCH_SUPPRESSION_TIME;

	case PEER_PUNCH_TASK_RESULT_ACCEPTED:
	case PEER_PUNCH_TASK_RESULT_HANDSHAKE: {
		uint32_t wait_window_ms = punch_task_wait_window_ms(command);
		return wait_window_ms ? ctx.now + wait_window_ms : FASTD_TIMEOUT_INV;
	}

	default:
		break;
	}

	switch (role) {
	case PEER_PUNCH_TASK_ROLE_RELAY_SUBJECT:
	case PEER_PUNCH_TASK_ROLE_RELAY_DEST:
		return ctx.now + conf.punch_relay_interval;

	default:
		return FASTD_TIMEOUT_INV;
	}
}

/** Returns the next non-zero local punch task ID */
static uint64_t next_punch_task_id(void) {
	ctx.next_punch_task_id++;
	if (!ctx.next_punch_task_id)
		ctx.next_punch_task_id++;

	return ctx.next_punch_task_id;
}

/** Clamps a size_t counter to a 16-bit status field */
static uint16_t punch_task_count16(size_t count) {
	return count > UINT16_MAX ? UINT16_MAX : (uint16_t)count;
}

/** Records a peer's latest local view of a punch-control task with optional base mapped endpoint metadata */
static void record_punch_task_base(
	fastd_peer_t *peer, fastd_peer_punch_task_role_t role, fastd_peer_punch_task_command_t command,
	fastd_peer_punch_task_result_t result, const fastd_peer_address_t *endpoint, uint16_t packet_count,
	size_t candidate_count, size_t candidates_sent, uint8_t order, unsigned udp_punch_sockets,
	uint32_t hard_sym_port_index, uint32_t hard_sym_next_port_index, uint32_t hard_sym_round,
	const fastd_peer_address_t *base_mapped_endpoint, uint32_t base_mapped_listener_id,
	bool base_mapped_port_mapped) {
	if (!peer)
		return;

	peer->last_punch_task = (fastd_peer_punch_task_t){
		.id = next_punch_task_id(),
		.updated = ctx.now,
		.next_retry = punch_task_next_retry_timeout(role, command, result),
		.role = role,
		.cause = punch_task_cause(role, command, result),
		.command = command,
		.result = result,
		.packet_count = packet_count,
		.candidate_count = punch_task_count16(candidate_count),
		.candidates_sent = punch_task_count16(candidates_sent),
		.order = order,
			.udp_punch_sockets = udp_punch_sockets,
			.hard_sym_port_index = hard_sym_port_index,
			.hard_sym_next_port_index = hard_sym_next_port_index,
			.hard_sym_round = hard_sym_round,
			.wait_window_ms = punch_task_wait_window_ms(command),
		};

	if (endpoint)
		peer->last_punch_task.endpoint = *endpoint;
	if (base_mapped_endpoint) {
		peer->last_punch_task.base_mapped_endpoint = *base_mapped_endpoint;
		peer->last_punch_task.base_mapped_listener_id = base_mapped_listener_id;
		peer->last_punch_task.base_mapped_available = true;
		peer->last_punch_task.base_mapped_port_mapped = base_mapped_port_mapped;
	}
}

/** Records a peer's latest local view of a punch-control task */
static void record_punch_task(
	fastd_peer_t *peer, fastd_peer_punch_task_role_t role, fastd_peer_punch_task_command_t command,
	fastd_peer_punch_task_result_t result, const fastd_peer_address_t *endpoint, uint16_t packet_count,
	size_t candidate_count, size_t candidates_sent, uint8_t order, unsigned udp_punch_sockets,
	uint32_t hard_sym_port_index, uint32_t hard_sym_next_port_index, uint32_t hard_sym_round) {
	record_punch_task_base(
		peer, role, command, result, endpoint, packet_count, candidate_count, candidates_sent, order,
		udp_punch_sockets, hard_sym_port_index, hard_sym_next_port_index, hard_sym_round, NULL, 0, false);
}

/** Returns true if a punch result should temporarily stop relaying that endpoint to the sender */
static bool punch_result_causes_relay_backoff(fastd_punch_result_t result) {
	switch (result) {
	case FASTD_PUNCH_RESULT_SUPPRESSED:
	case FASTD_PUNCH_RESULT_NO_PEER:
	case FASTD_PUNCH_RESULT_BUSY:
		return true;

	default:
		return false;
	}
}

/** Returns the peer-pair lifecycle stage represented by a remote punch result */
static fastd_punch_pair_task_stage_t punch_pair_task_stage_from_result(fastd_punch_result_t result) {
	switch (result) {
	case FASTD_PUNCH_RESULT_ACCEPTED:
		return PUNCH_PAIR_TASK_STAGE_RESULT_ACCEPTED;

	case FASTD_PUNCH_RESULT_HANDSHAKE:
		return PUNCH_PAIR_TASK_STAGE_RESULT_HANDSHAKE;

	case FASTD_PUNCH_RESULT_SUPPRESSED:
		return PUNCH_PAIR_TASK_STAGE_RESULT_SUPPRESSED;

	case FASTD_PUNCH_RESULT_NO_PEER:
		return PUNCH_PAIR_TASK_STAGE_RESULT_NO_PEER;

	case FASTD_PUNCH_RESULT_BUSY:
		return PUNCH_PAIR_TASK_STAGE_RESULT_BUSY;

	default:
		return PUNCH_PAIR_TASK_STAGE_NONE;
	}
}

/** Hashes a punch result subject key for duplicate suppression */
static uint64_t punch_result_subject_key_hash(const void *key, size_t key_len) {
	const uint8_t *bytes = key;
	uint64_t hash = 1469598103934665603ULL;

	size_t i;
	for (i = 0; i < key_len; i++) {
		hash ^= bytes[i];
		hash *= 1099511628211ULL;
	}

	return hash ? hash : 1;
}

/** Records peer-pair lifecycle state returned by a remote punch command target */
static void task_manager_record_pair_result(
	fastd_peer_t *sender, fastd_peer_t *subject, fastd_punch_result_t result,
	const fastd_peer_address_t *endpoint) {
	fastd_punch_pair_task_stage_t stage = punch_pair_task_stage_from_result(result);
	if (!sender || !subject || stage == PUNCH_PAIR_TASK_STAGE_NONE)
		return;

	fastd_timeout_t next_retry = FASTD_TIMEOUT_INV;
	size_t backoff_recorded = 0;
	if (endpoint && punch_result_causes_relay_backoff(result)) {
		next_retry = fastd_peer_punch_relay_backoff_timeout(sender, endpoint);
		if (next_retry != FASTD_TIMEOUT_INV)
			backoff_recorded = 1;
	}
	pair_runtime_mark_result(sender, subject, result, next_retry);

	task_manager_record_pair_task(
		sender, subject, subject, sender, stage, 0, backoff_recorded, next_retry, false);
}

/** Returns true if this punch result has already been handled through a redundant result packet */
static bool punch_result_duplicate(
	fastd_peer_t *sender, fastd_peer_t *subject, const fastd_peer_address_t *endpoint, fastd_punch_result_t result,
	uint8_t command_type, uint16_t packet_count, uint64_t subject_key_hash) {
	uint64_t sender_id = sender ? sender->id : 0;
	uint64_t subject_id = subject ? subject->id : 0;

	size_t i;
	for (i = 0; i < array_size(ctx.punch_result_seen); i++) {
		fastd_punch_result_seen_t *seen = &ctx.punch_result_seen[i];
		if (!seen->used)
			continue;
		if (fastd_timed_out(seen->updated + FASTD_PUNCH_RESULT_DEDUP_TIME)) {
			seen->used = false;
			continue;
		}
		bool command_matches = !seen->command_type || !command_type || seen->command_type == command_type;
		if (seen->sender_id == sender_id && seen->subject_id == subject_id &&
		    seen->subject_key_hash == subject_key_hash &&
		    seen->result == (uint8_t)result && seen->packet_count == packet_count && command_matches &&
		    fastd_peer_address_equal(&seen->endpoint, endpoint)) {
			ctx.punch_result_duplicates++;
			return true;
		}
	}

	size_t pos = ctx.punch_result_seen_pos % array_size(ctx.punch_result_seen);
	ctx.punch_result_seen[pos] = (fastd_punch_result_seen_t){
		.updated = ctx.now,
		.sender_id = sender_id,
		.subject_id = subject_id,
		.subject_key_hash = subject_key_hash,
		.endpoint = *endpoint,
		.packet_count = packet_count,
		.result = (uint8_t)result,
		.command_type = command_type,
		.used = true,
	};
	ctx.punch_result_seen_pos = (pos + 1) % array_size(ctx.punch_result_seen);
	return false;
}

/** Returns true for TCP NAT types where a mapped-address exchange is expected to be useful */
static bool tcp_nat_type_punchable(fastd_nat_type_t nat_type) {
	switch (nat_type) {
	case FASTD_NAT_OPEN_INTERNET:
	case FASTD_NAT_NO_PAT:
	case FASTD_NAT_FULL_CONE:
	case FASTD_NAT_RESTRICTED:
	case FASTD_NAT_PORT_RESTRICTED:
		return true;

	default:
		return false;
	}
}

/** Returns true when punch-control should ask NAT detection for fresher metadata */
static bool punch_nat_status_needs_refresh(const fastd_nat_status_t *status) {
	if (!status->enabled)
		return false;

	if (!status->available)
		return true;

	if (!status->last_update || status->last_update > ctx.now)
		return false;

	unsigned interval = conf.punch_announce_interval ? conf.punch_announce_interval : DEFAULT_PUNCH_ANNOUNCE_INTERVAL;
	return ctx.now - status->last_update >= interval;
}

/** Returns a default UDP socket for an address family */
static const fastd_socket_t *default_udp_socket_for_family(sa_family_t family) {
	switch (family) {
	case AF_INET:
		return ctx.sock_default_v4;

	case AF_INET6:
		return ctx.sock_default_v6;

	default:
		return NULL;
	}
}

/** Returns true if a mapped endpoint is usable as stable full-cone punch metadata */
static bool mapped_endpoint_to_nat_info(
	const fastd_peer_address_t *mapped, fastd_peer_address_t *endpoint, fastd_nat_type_t *nat_type,
	uint16_t *min_port, uint16_t *max_port, int *port_delta) {
	if (mapped->sa.sa_family != AF_INET && mapped->sa.sa_family != AF_INET6)
		return false;

	uint16_t port = ntohs(fastd_peer_address_get_port(mapped));
	if (!port)
		return false;

	*endpoint = *mapped;
	*nat_type = FASTD_NAT_FULL_CONE;
	*min_port = port;
	*max_port = port;
	*port_delta = 0;
	return true;
}

/** Returns true if a socket has an external UDP port mapping */
static bool mapped_endpoint_for_socket(
	const fastd_socket_t *sock, fastd_peer_address_t *endpoint, fastd_nat_type_t *nat_type, uint16_t *min_port,
	uint16_t *max_port, int *port_delta) {
	if (!sock)
		return false;

	fastd_peer_address_t mapped;
	if (!fastd_port_mapping_get_external_address(sock, &mapped))
		return false;

	return mapped_endpoint_to_nat_info(&mapped, endpoint, nat_type, min_port, max_port, port_delta);
}

/** Selects the preferred local UDP endpoint for punch-control NAT_INFO */
static bool get_local_udp_nat_info_endpoint(
	fastd_peer_t *dest, const fastd_nat_status_t *status, fastd_peer_address_t *endpoint,
	fastd_nat_type_t *nat_type, uint16_t *min_port, uint16_t *max_port, int *port_delta, bool *port_mapped,
	uint32_t *listener_id, sa_family_t preferred_family, bool force_new_listener, bool prefer_port_mapping) {
	if (listener_id)
		*listener_id = 0;

	if (dest && dest->sock && !fastd_socket_is_tcp(dest->sock) &&
	    mapped_endpoint_for_socket(dest->sock, endpoint, nat_type, min_port, max_port, port_delta)) {
		if (port_mapped)
			*port_mapped = true;
		return true;
	}

	sa_family_t family = AF_UNSPEC;
	if (preferred_family == AF_INET || preferred_family == AF_INET6)
		family = preferred_family;
	else if (status->available)
		family = status->reflexive.sa.sa_family;
	else if (dest && (dest->address.sa.sa_family == AF_INET || dest->address.sa.sa_family == AF_INET6))
		family = dest->address.sa.sa_family;

	if (mapped_endpoint_for_socket(
		    default_udp_socket_for_family(family), endpoint, nat_type, min_port, max_port, port_delta)) {
		if (port_mapped)
			*port_mapped = true;
		return true;
	}

	if (mapped_endpoint_for_socket(ctx.sock_default_v4, endpoint, nat_type, min_port, max_port, port_delta)) {
		if (port_mapped)
			*port_mapped = true;
		return true;
	}

	if (mapped_endpoint_for_socket(ctx.sock_default_v6, endpoint, nat_type, min_port, max_port, port_delta)) {
		if (port_mapped)
			*port_mapped = true;
		return true;
	}

	size_t i;
	for (i = 0; i < ctx.n_socks; i++) {
		if (mapped_endpoint_for_socket(&ctx.socks[i], endpoint, nat_type, min_port, max_port, port_delta)) {
			if (port_mapped)
				*port_mapped = true;
			return true;
		}
	}

	bool listener_port_mapped = false;
	uint32_t selected_listener_id = 0;
	if (family != AF_UNSPEC &&
	    fastd_udp_punch_select_listener(
		    family, force_new_listener, prefer_port_mapping, endpoint, &listener_port_mapped,
		    &selected_listener_id)) {
		uint16_t port = ntohs(fastd_peer_address_get_port(endpoint));
		if (listener_id)
			*listener_id = selected_listener_id;

		if (listener_port_mapped) {
			*nat_type = FASTD_NAT_FULL_CONE;
			*min_port = port;
			*max_port = port;
			*port_delta = 0;
			if (port_mapped)
				*port_mapped = true;
			return true;
		}

		if (status->available && status->reflexive.sa.sa_family == endpoint->sa.sa_family) {
			*nat_type = status->type;
			*min_port = status->min_port;
			*max_port = status->max_port;
			*port_delta = status->port_delta;
		} else {
			*nat_type = FASTD_NAT_UNKNOWN;
			*min_port = port;
			*max_port = port;
			*port_delta = 0;
		}

		if (!*min_port || port < *min_port)
			*min_port = port;
		if (port > *max_port)
			*max_port = port;
		if (port_mapped)
			*port_mapped = false;
		return true;
	}

	if (!status->available)
		return false;

	*endpoint = status->reflexive;
	*nat_type = status->type;
	*min_port = status->min_port;
	*max_port = status->max_port;
	*port_delta = status->port_delta;
	if (port_mapped)
		*port_mapped = false;
	return true;
}

/** Selects the most specific endpoint punch command type for a relayed endpoint */
static uint8_t
punch_endpoint_command_type(const fastd_peer_t *dest, const fastd_peer_t *subject, fastd_nat_type_t subject_nat_type) {
	if (!fastd_peer_get_punch_symmetric(subject))
		return FASTD_PUNCH_SEND_CONE;

	if (nat_type_is_easy_symmetric(subject_nat_type)) {
		if (fastd_peer_get_punch_symmetric(dest) && peer_has_fresh_punch_nat_info(dest) &&
		    nat_type_is_easy_symmetric(dest->punch_nat_type))
			return FASTD_PUNCH_BOTH_EASY_SYM;

		return FASTD_PUNCH_SEND_EASY_SYM;
	}

	if (subject_nat_type == FASTD_NAT_SYMMETRIC)
		return FASTD_PUNCH_SEND_HARD_SYM;

	return FASTD_PUNCH_SEND_CONE;
}

/** Sends one endpoint punch control message, optionally with type-specific extra payload before the key */
static bool send_endpoint_message_extra(
	fastd_peer_t *dest, uint8_t type, const void *subject_key, size_t key_len, const fastd_peer_address_t *endpoint,
	fastd_nat_type_t nat_type, uint16_t min_port, uint16_t max_port, int port_delta, uint8_t extra,
	uint16_t packet_count, const void *extra_payload, size_t extra_payload_len) {
	if (!punch_control_supported() || !fastd_peer_is_established(dest))
		return false;
	if (!peer_control_supported(dest))
		return false;

	if (key_len > UINT8_MAX)
		return false;

	size_t len = sizeof(fastd_punch_header_t) + sizeof(fastd_punch_endpoint_t) + extra_payload_len + key_len;
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
		.reserved = extra,
		.packet_count = htobe16(packet_count),
	};

	if (!encode_address(payload, endpoint)) {
		fastd_buffer_free(buffer);
		return false;
	}

	uint8_t *cursor = (uint8_t *)(payload + 1);
	if (extra_payload_len) {
		memcpy(cursor, extra_payload, extra_payload_len);
		cursor += extra_payload_len;
	}

	memcpy(cursor, subject_key, key_len);

	conf.protocol->send_control(dest, buffer);
	ctx.punch_control_tx++;
	return true;
}

/** Sends one endpoint punch control message */
static bool send_endpoint_message(
	fastd_peer_t *dest, uint8_t type, const void *subject_key, size_t key_len, const fastd_peer_address_t *endpoint,
	fastd_nat_type_t nat_type, uint16_t min_port, uint16_t max_port, int port_delta, uint8_t extra,
	uint16_t packet_count) {
	return send_endpoint_message_extra(
		dest, type, subject_key, key_len, endpoint, nat_type, min_port, max_port, port_delta, extra,
			packet_count, NULL, 0);
}

/** Sends additional NAT_INFO endpoints without duplicating the primary endpoint */
static void send_nat_info_extra_endpoints(
	fastd_peer_t *dest, uint8_t type, const fastd_peer_address_t *primary,
	const fastd_peer_address_t *endpoints, size_t n_endpoints, fastd_nat_type_t nat_type, uint16_t min_port,
	uint16_t max_port, int port_delta) {
	size_t i;
	for (i = 0; i < n_endpoints; i++) {
		const fastd_peer_address_t *endpoint = &endpoints[i];
		if (fastd_peer_address_equal(endpoint, primary))
			continue;

		send_endpoint_message(
			dest, type, conf.protocol->get_own_key(), conf.protocol->key_length(), endpoint, nat_type,
			min_port, max_port, port_delta, 0, 0);
	}
}

/** Requests an EasyTier-style public punch listener selection from a peer */
static bool send_select_listener_request(
	fastd_peer_t *dest, const fastd_peer_address_t *request_endpoint, bool force_new, bool prefer_port_mapping) {
	uint8_t flags = 0;
	if (force_new)
		flags |= FASTD_PUNCH_SELECT_FORCE_NEW;
	if (prefer_port_mapping)
		flags |= FASTD_PUNCH_SELECT_PREFER_PORT_MAPPING;

	return send_endpoint_message(
		dest, FASTD_PUNCH_SELECT_LISTENER, conf.protocol->get_own_key(), conf.protocol->key_length(),
		request_endpoint, FASTD_NAT_UNKNOWN, 0, 0, 0, flags, 0);
}

/** Returns the request endpoint to use when asking a peer for fresh listener metadata */
static bool peer_metadata_request_endpoint(const fastd_peer_t *peer, fastd_peer_address_t *endpoint) {
	if (!fastd_peer_is_established(peer))
		return false;
	if (peer->address.sa.sa_family != AF_INET && peer->address.sa.sa_family != AF_INET6)
		return false;
	if (!fastd_peer_address_get_port(&peer->address))
		return false;

	*endpoint = peer->address;
	return true;
}

/** Requests fresh punch metadata from one established peer, rate-limited per peer */
static bool request_peer_punch_metadata(fastd_peer_t *peer) {
	if (!fastd_peer_get_nat_traversal(peer) || !fastd_timed_out(peer->next_punch_metadata_request))
		return false;
	if (!fastd_peer_hole_punch_allows(peer, TRANSPORT_UDP) ||
	    !fastd_peer_transport_allows(fastd_peer_get_transport(peer), TRANSPORT_UDP))
		return false;

	fastd_peer_address_t endpoint;
	if (!peer_metadata_request_endpoint(peer, &endpoint))
		return false;

	fastd_timeout_t next_request = ctx.now + conf.punch_announce_interval;
	if (!send_select_listener_request(peer, &endpoint, true, true))
		return false;

	peer->next_punch_metadata_request = next_request;
	return true;
}

/** Sends the selected local public punch listener endpoint to a peer */
static bool send_listener_info(
	fastd_peer_t *dest, const fastd_peer_address_t *endpoint, fastd_nat_type_t nat_type, uint16_t min_port,
	uint16_t max_port, int port_delta, bool port_mapped, uint32_t listener_id) {
	fastd_punch_listener_info_t info = {
		.listener_id = htobe32(listener_id),
	};
	uint8_t flags = port_mapped ? FASTD_PUNCH_LISTENER_PORT_MAPPED : 0;

	return send_endpoint_message_extra(
		dest, FASTD_PUNCH_LISTENER_INFO, conf.protocol->get_own_key(), conf.protocol->key_length(), endpoint,
		nat_type, min_port, max_port, port_delta, flags, 0, &info, sizeof(info));
}

/** Sends this instance's current NAT metadata to one established peer */
static void send_local_nat_info(fastd_peer_t *dest) {
	if (!fastd_timed_out(dest->next_punch_announce))
		return;

	dest->next_punch_announce = ctx.now + conf.punch_announce_interval;

	fastd_nat_status_t status = {};
	bool have_nat_status = fastd_nat_get_status(&status);

	if (have_nat_status && punch_nat_status_needs_refresh(&status))
		fastd_nat_request_refresh();

	fastd_peer_address_t udp_endpoint;
	fastd_nat_type_t udp_nat_type;
	uint16_t udp_min_port, udp_max_port;
	int udp_port_delta;
	if (get_local_udp_nat_info_endpoint(
		    dest, &status, &udp_endpoint, &udp_nat_type, &udp_min_port, &udp_max_port, &udp_port_delta, NULL,
		    NULL, AF_UNSPEC, false, true)) {
			send_endpoint_message(
				dest, FASTD_PUNCH_NAT_INFO, conf.protocol->get_own_key(), conf.protocol->key_length(),
				&udp_endpoint, udp_nat_type, udp_min_port, udp_max_port, udp_port_delta, 0, 0);
			if (status.available && status.n_reflexive_addrs)
				send_nat_info_extra_endpoints(
					dest, FASTD_PUNCH_NAT_INFO_EXTRA, &udp_endpoint, status.reflexive_addrs,
					status.n_reflexive_addrs, status.type, status.min_port, status.max_port,
					status.port_delta);
			if (fastd_peer_hole_punch_allows(dest, TRANSPORT_UDP) &&
			    fastd_peer_transport_allows(fastd_peer_get_transport(dest), TRANSPORT_UDP))
				send_select_listener_request(dest, &udp_endpoint, false, true);
		}

		if (status.tcp_available && tcp_nat_type_punchable(status.tcp_type)) {
			send_endpoint_message(
				dest, FASTD_PUNCH_TCP_NAT_INFO, conf.protocol->get_own_key(), conf.protocol->key_length(),
				&status.tcp_reflexive, status.tcp_type, status.tcp_min_port, status.tcp_max_port, 0, 0, 0);
			if (status.n_tcp_reflexive_addrs)
				send_nat_info_extra_endpoints(
					dest, FASTD_PUNCH_TCP_NAT_INFO_EXTRA, &status.tcp_reflexive,
					status.tcp_reflexive_addrs, status.n_tcp_reflexive_addrs, status.tcp_type,
					status.tcp_min_port, status.tcp_max_port, 0);
		}
	}

/** Selects this instance's current base mapped UDP listener endpoint for a punch result */
static bool get_local_base_mapped_endpoint(
	fastd_peer_t *dest, fastd_peer_address_t *endpoint, bool *port_mapped, uint32_t *listener_id) {
	fastd_nat_status_t status;
	if (!fastd_nat_get_status(&status))
		return false;

	fastd_nat_type_t nat_type;
	uint16_t min_port, max_port;
	int port_delta;
	return get_local_udp_nat_info_endpoint(
		dest, &status, endpoint, &nat_type, &min_port, &max_port, &port_delta, port_mapped, listener_id,
		AF_UNSPEC, false, true);
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

/** Mixes endpoint attributes into a stable 32-bit hard-symmetric scan seed */
static uint32_t hard_symmetric_mix32(uint32_t value) {
	value ^= value >> 16;
	value *= 0x7feb352dU;
	value ^= value >> 15;
	value *= 0x846ca68bU;
	value ^= value >> 16;
	return value;
}

/** Returns a stable seed for a hard-symmetric endpoint */
static uint32_t hard_symmetric_seed(const fastd_peer_address_t *endpoint) {
	uint32_t seed = 0x811c9dc5U;

	switch (endpoint->sa.sa_family) {
	case AF_INET:
		seed ^= ntohl(endpoint->in.sin_addr.s_addr);
		seed = hard_symmetric_mix32(seed);
		break;

	case AF_INET6: {
		size_t i;
		for (i = 0; i < sizeof(endpoint->in6.sin6_addr.s6_addr); i++) {
			seed ^= endpoint->in6.sin6_addr.s6_addr[i];
			seed = hard_symmetric_mix32(seed);
		}
		break;
	}

	default:
		break;
	}

	seed ^= (uint32_t)ntohs(fastd_peer_address_get_port(endpoint)) << 16;
	return hard_symmetric_mix32(seed) % FASTD_PUNCH_HARD_SYM_PORT_SPACE;
}

/** Returns a full-cycle stride for the 1..65535 UDP port permutation */
static uint32_t hard_symmetric_stride(const fastd_peer_address_t *endpoint) {
	uint32_t stride = hard_symmetric_mix32(hard_symmetric_seed(endpoint) ^ 0x9e3779b9U);
	stride = (stride % (FASTD_PUNCH_HARD_SYM_PORT_SPACE - 1)) + 1;

	while (!(stride % 3) || !(stride % 5) || !(stride % 17) || !(stride % 257)) {
		stride++;
		if (stride >= FASTD_PUNCH_HARD_SYM_PORT_SPACE)
			stride = 1;
	}

	return stride;
}

/** Returns one port from a stable full-port-space hard-symmetric permutation */
static uint16_t hard_symmetric_port(const fastd_peer_address_t *endpoint, uint32_t index) {
	uint64_t value = hard_symmetric_seed(endpoint);
	value += (uint64_t)(index % FASTD_PUNCH_HARD_SYM_PORT_SPACE) * hard_symmetric_stride(endpoint);
	return (uint16_t)((value % FASTD_PUNCH_HARD_SYM_PORT_SPACE) + 1);
}

/** Advances a hard-symmetric scan index and counts full-space wraparounds */
static uint32_t hard_symmetric_advance_index(uint32_t index, uint32_t *round) {
	index++;
	if (index >= FASTD_PUNCH_HARD_SYM_PORT_SPACE) {
		index = 0;
		if (round)
			(*round)++;
	}

	return index;
}

/** Returns true for local NAT types that benefit from opening a UDP punch socket array */
static bool nat_type_uses_local_socket_array(fastd_nat_type_t nat_type) {
	switch (nat_type) {
	case FASTD_NAT_SYMMETRIC_EASY_INC:
	case FASTD_NAT_SYMMETRIC_EASY_DEC:
	case FASTD_NAT_SYMMETRIC:
		return true;

	default:
		return false;
	}
}

/** Returns the configured punch socket limit with the parser's lower bound enforced defensively */
static unsigned configured_punch_socket_limit(void) {
	return conf.punch_max_sockets ? conf.punch_max_sockets : 1;
}

/** Returns the local UDP socket count for the detected local NAT behavior */
static unsigned local_socket_count_for_nat(fastd_nat_type_t nat_type) {
	unsigned count = configured_punch_socket_limit();

	if (nat_type_is_easy_symmetric(nat_type) && count > DEFAULT_PUNCH_EASY_SYM_SOCKETS)
		return DEFAULT_PUNCH_EASY_SYM_SOCKETS;

	return count;
}

/** Returns the number of UDP sockets to use for one punch command with known NAT metadata */
static unsigned punch_udp_socket_count_for_nat(
	fastd_peer_t *peer, fastd_nat_type_t remote_nat_type, bool local_available, fastd_nat_type_t local_nat_type) {
	if (!fastd_peer_get_punch_symmetric(peer))
		return 0;

	if (remote_nat_type == FASTD_NAT_SYMMETRIC || remote_nat_type == FASTD_NAT_SYMMETRIC_EASY_INC ||
	    remote_nat_type == FASTD_NAT_SYMMETRIC_EASY_DEC)
		return 1;

	if (!local_available)
		return 0;

	if (!nat_type_uses_local_socket_array(local_nat_type))
		return 0;

	return local_socket_count_for_nat(local_nat_type);
}

/** Returns the UDP socket count for a specific punch command */
static unsigned punch_udp_socket_count_for_command(
	fastd_peer_t *peer, uint8_t command_type, fastd_nat_type_t remote_nat_type, bool local_available,
	fastd_nat_type_t local_nat_type) {
	if (command_type == FASTD_PUNCH_SEND_TCP)
		return 0;

	if (command_type == FASTD_PUNCH_BOTH_EASY_SYM) {
		if (!fastd_peer_get_punch_symmetric(peer))
			return 0;

		return 1;
	}

	return punch_udp_socket_count_for_nat(peer, remote_nat_type, local_available, local_nat_type);
}

/** Returns the number of short-lived UDP sockets to use for one punch command */
static unsigned punch_udp_socket_count(fastd_peer_t *peer, uint8_t command_type, fastd_nat_type_t remote_nat_type) {
	fastd_nat_status_t status;
	if (!fastd_nat_get_status(&status) || !status.available) {
		fastd_nat_request_refresh();
		return punch_udp_socket_count_for_command(
			peer, command_type, remote_nat_type, false, FASTD_NAT_UNKNOWN);
	}

	if (punch_nat_status_needs_refresh(&status))
		fastd_nat_request_refresh();

	return punch_udp_socket_count_for_command(peer, command_type, remote_nat_type, true, status.type);
}

/** Returns the UDP punch packet/socket count a relay should request from a destination peer */
static unsigned relay_udp_packet_count(fastd_peer_t *dest, uint8_t command_type, fastd_nat_type_t remote_nat_type) {
	bool have_dest_nat = peer_has_fresh_punch_nat_info(dest);
	fastd_nat_type_t dest_nat_type = have_dest_nat ? dest->punch_nat_type : FASTD_NAT_UNKNOWN;

	return punch_udp_socket_count_for_command(dest, command_type, remote_nat_type, have_dest_nat, dest_nat_type);
}

/** Converts an unsigned punch packet count to the bounded wire field */
static uint16_t punch_packet_count_wire(unsigned count) {
	return count > UINT16_MAX ? UINT16_MAX : (uint16_t)count;
}

/** Returns the number of endpoint command candidates a relay may emit for one command */
static unsigned punch_relay_candidate_count(uint8_t command_type, size_t limit) {
	if (!limit)
		return 0;

	unsigned count;
	switch (command_type) {
	case FASTD_PUNCH_SEND_HARD_SYM:
		count = conf.punch_max_packets ? conf.punch_max_packets : DEFAULT_PUNCH_HARD_SYM_PACKETS;
		break;

	case FASTD_PUNCH_SEND_EASY_SYM:
	case FASTD_PUNCH_BOTH_EASY_SYM:
		count = configured_punch_socket_limit();
		if (count > DEFAULT_PUNCH_EASY_SYM_SOCKETS)
			count = DEFAULT_PUNCH_EASY_SYM_SOCKETS;
		break;

	default:
		count = 1;
		break;
	}

	return count > limit ? (unsigned)limit : count;
}

/** Applies an explicit relay-requested packet/socket count to a local UDP punch policy result */
static unsigned punch_udp_socket_count_apply_request(unsigned local_count, uint16_t requested_count) {
	if (!requested_count || requested_count >= local_count)
		return local_count;

	return requested_count;
}

/** Applies an explicit relay-requested packet/socket count to the local UDP punch policy */
static unsigned punch_udp_socket_count_for_request(
	fastd_peer_t *peer, uint8_t command_type, fastd_nat_type_t remote_nat_type, uint16_t requested_count) {
	return punch_udp_socket_count_apply_request(
		punch_udp_socket_count(peer, command_type, remote_nat_type), requested_count);
}

/** Adds one endpoint candidate to a bounded output array */
static size_t
add_endpoint_candidate(fastd_peer_address_t *out, size_t out_len, size_t count, const fastd_peer_address_t *endpoint) {
	if (count >= out_len)
		return count;

	out[count++] = *endpoint;
	return count;
}

/** Checks whether a candidate port has already been selected in this batch */
static bool port_already_selected(const fastd_peer_address_t *out, size_t count, uint16_t port) {
	size_t i;
	for (i = 0; i < count; i++) {
		if (ntohs(fastd_peer_address_get_port(&out[i])) == port)
			return true;
	}

	return false;
}

/** Builds hard-symmetric candidates using a full-port-space permutation instead of a local contiguous scan */
static size_t build_hard_symmetric_candidates(
	fastd_peer_address_t *out, size_t out_len, const fastd_peer_address_t *endpoint, unsigned count,
	uint16_t min_port, uint16_t max_port, uint32_t hard_sym_index, uint32_t *next_hard_sym_index,
	uint32_t *hard_sym_round) {
	size_t n_candidates = 0;
	uint16_t base_port = ntohs(fastd_peer_address_get_port(endpoint));

	if (base_port)
		n_candidates = add_endpoint_candidate(out, out_len, n_candidates, endpoint);

	if (min_port && max_port && min_port <= max_port) {
		uint32_t range = (uint32_t)max_port - min_port + 1;
		uint32_t offset;
		for (offset = 0; n_candidates < count && offset < range; offset++) {
			uint16_t port = (uint16_t)(min_port + offset);
			if (port == base_port || port_already_selected(out, n_candidates, port))
				continue;

			fastd_peer_address_t predicted = *endpoint;
			set_endpoint_port(&predicted, port);
			n_candidates = add_endpoint_candidate(out, out_len, n_candidates, &predicted);
		}
	}

	uint32_t index = hard_sym_index % FASTD_PUNCH_HARD_SYM_PORT_SPACE;
	uint32_t round = hard_sym_round ? *hard_sym_round : 0;
	unsigned consumed = 0;

	while (n_candidates < count && consumed < FASTD_PUNCH_HARD_SYM_PORT_SPACE) {
		uint16_t port = hard_symmetric_port(endpoint, index);
		index = hard_symmetric_advance_index(index, &round);
		consumed++;

		if (port == base_port || port_already_selected(out, n_candidates, port))
			continue;

		fastd_peer_address_t predicted = *endpoint;
		set_endpoint_port(&predicted, port);
		n_candidates = add_endpoint_candidate(out, out_len, n_candidates, &predicted);
	}

	if (next_hard_sym_index)
		*next_hard_sym_index = index;
	if (hard_sym_round)
		*hard_sym_round = round;

	return n_candidates;
}

/** Builds concrete endpoint candidates for a remote peer's NAT metadata */
static size_t build_endpoint_candidates(
	fastd_peer_address_t *out, size_t out_len, const fastd_peer_address_t *endpoint, fastd_nat_type_t nat_type,
	uint16_t min_port, uint16_t max_port, int port_delta, unsigned max_sockets, bool symmetric,
	bool paired_easy_symmetric, uint32_t hard_sym_index, uint32_t *next_hard_sym_index, uint32_t *hard_sym_round) {
	if (!out_len)
		return 0;

	if (!symmetric || (endpoint->sa.sa_family != AF_INET && endpoint->sa.sa_family != AF_INET6))
		return add_endpoint_candidate(out, out_len, 0, endpoint);

	unsigned count = max_sockets ? max_sockets : 1;
	if (count > out_len)
		count = out_len;

	int base_port = ntohs(fastd_peer_address_get_port(endpoint));
	size_t n_candidates = 0;

	if (nat_type == FASTD_NAT_SYMMETRIC) {
		return build_hard_symmetric_candidates(
			out, out_len, endpoint, count, min_port, max_port, hard_sym_index, next_hard_sym_index,
			hard_sym_round);
	}

	if (nat_type != FASTD_NAT_SYMMETRIC_EASY_INC && nat_type != FASTD_NAT_SYMMETRIC_EASY_DEC)
		return add_endpoint_candidate(out, out_len, 0, endpoint);

	int step = easy_symmetric_step(port_delta);
	int direction = nat_type == FASTD_NAT_SYMMETRIC_EASY_INC ? 1 : -1;

	unsigned i;
	for (i = 0; i < count; i++) {
		int port;

		if (paired_easy_symmetric) {
			int delta = 0;
			if (i) {
				int radius = ((int)i + 1) / 2;
				delta = (i & 1) ? -radius : radius;
			}

			port = base_port + direction * FASTD_PUNCH_BOTH_EASY_SYM_OFFSET + delta * step;
		} else {
			port = base_port + direction * step * (int)i;
		}

		if (port <= 0 || port > 65535)
			continue;

		fastd_peer_address_t predicted = *endpoint;
		set_endpoint_port(&predicted, port);
		n_candidates = add_endpoint_candidate(out, out_len, n_candidates, &predicted);
	}

	return n_candidates;
}

/** Builds endpoint candidates for multiple public endpoints within one bounded packet budget */
static size_t build_punch_endpoint_candidates(
	fastd_peer_address_t *out, size_t out_len, fastd_peer_punch_endpoint_t *endpoints, size_t n_endpoints,
	unsigned max_sockets, bool symmetric, bool paired_easy_symmetric) {
	if (!out_len || !n_endpoints)
		return 0;

	unsigned total_budget = max_sockets ? max_sockets : 1;
	if (total_budget > out_len)
		total_budget = out_len;
	if (total_budget < n_endpoints)
		total_budget = (unsigned)n_endpoints > out_len ? (unsigned)out_len : (unsigned)n_endpoints;

	size_t n_candidates = 0;

	size_t i;
	for (i = 0; i < n_endpoints && n_candidates < total_budget && n_candidates < out_len; i++) {
		fastd_peer_punch_endpoint_t *endpoint = &endpoints[i];
		size_t endpoints_left = n_endpoints - i;
		unsigned budget_left = total_budget - (unsigned)n_candidates;
		unsigned endpoint_budget = (budget_left + (unsigned)endpoints_left - 1) / (unsigned)endpoints_left;
		size_t out_left = out_len - n_candidates;
		if (endpoint_budget > out_left)
				endpoint_budget = (unsigned)out_left;

		size_t added = build_endpoint_candidates(
			out + n_candidates, out_left, &endpoint->address, endpoint->nat_type, endpoint->min_port,
			endpoint->max_port, endpoint->port_delta, endpoint_budget, symmetric, paired_easy_symmetric,
			endpoint->hard_sym_port_index, &endpoint->hard_sym_port_index, &endpoint->hard_sym_round);
		n_candidates += added;
	}

	return n_candidates;
}

static void refresh_observed_peer_punch_metadata(fastd_peer_t *peer);
static void relay_peer_endpoints(void);

#ifdef WITH_TESTS

/** Test wrapper for punch endpoint prediction */
size_t fastd_punch_test_build_endpoint_candidates(
	fastd_peer_address_t *out, size_t out_len, const fastd_peer_address_t *endpoint, fastd_nat_type_t nat_type,
	int port_delta, unsigned max_sockets, bool symmetric) {
	return build_endpoint_candidates(
		out, out_len, endpoint, nat_type, 0, 0, port_delta, max_sockets, symmetric, false, 0, NULL, NULL);
}

/** Test wrapper for paired easy-symmetric endpoint prediction */
size_t fastd_punch_test_build_paired_endpoint_candidates(
	fastd_peer_address_t *out, size_t out_len, const fastd_peer_address_t *endpoint, fastd_nat_type_t nat_type,
	int port_delta, unsigned max_sockets, bool symmetric) {
	return build_endpoint_candidates(
		out, out_len, endpoint, nat_type, 0, 0, port_delta, max_sockets, symmetric, true, 0, NULL, NULL);
}

/** Test wrapper for hard-symmetric full-port-space endpoint prediction */
size_t fastd_punch_test_build_hard_symmetric_endpoint_candidates(
	fastd_peer_address_t *out, size_t out_len, const fastd_peer_address_t *endpoint, unsigned max_sockets,
	uint32_t hard_sym_index, uint32_t *next_hard_sym_index, uint32_t *hard_sym_round) {
	return build_endpoint_candidates(
		out, out_len, endpoint, FASTD_NAT_SYMMETRIC, 0, 0, 0, max_sockets, true, false, hard_sym_index,
		next_hard_sym_index, hard_sym_round);
}

/** Test wrapper for hard-symmetric endpoint prediction with an observed public port range */
size_t fastd_punch_test_build_hard_symmetric_range_endpoint_candidates(
	fastd_peer_address_t *out, size_t out_len, const fastd_peer_address_t *endpoint, uint16_t min_port,
	uint16_t max_port, unsigned max_sockets, uint32_t hard_sym_index, uint32_t *next_hard_sym_index,
	uint32_t *hard_sym_round) {
	return build_endpoint_candidates(
		out, out_len, endpoint, FASTD_NAT_SYMMETRIC, min_port, max_port, 0, max_sockets, true, false,
		hard_sym_index, next_hard_sym_index, hard_sym_round);
}

/** Test wrapper for multi-public-endpoint punch candidate prediction */
size_t fastd_punch_test_build_multi_endpoint_candidates(
	fastd_peer_address_t *out, size_t out_len, const fastd_peer_address_t *endpoints, size_t n_endpoints,
	fastd_nat_type_t nat_type, int port_delta, unsigned max_sockets, bool symmetric) {
	fastd_peer_punch_endpoint_t metadata[FASTD_NAT_MAX_PUBLIC_ENDPOINTS] = {};
	size_t n_metadata = 0;

	size_t i;
	for (i = 0; i < n_endpoints && n_metadata < array_size(metadata); i++)
		n_metadata = add_or_update_punch_endpoint(
			metadata, n_metadata, array_size(metadata), &endpoints[i], nat_type, 0, 0, port_delta);

	return build_punch_endpoint_candidates(out, out_len, metadata, n_metadata, max_sockets, symmetric, false);
}

/** Test wrapper for per-endpoint punch candidate prediction */
size_t fastd_punch_test_build_punch_endpoint_candidates(
	fastd_peer_address_t *out, size_t out_len, fastd_peer_punch_endpoint_t *endpoints, size_t n_endpoints,
	unsigned max_sockets, bool symmetric, bool paired_easy_symmetric) {
	return build_punch_endpoint_candidates(
		out, out_len, endpoints, n_endpoints, max_sockets, symmetric, paired_easy_symmetric);
}

/** Test wrapper for punch control message parsing */
bool fastd_punch_test_parse_endpoint_message(
	const uint8_t *data, size_t len, uint8_t *type, size_t *key_len, uint16_t *packet_count) {
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
	if (packet_count)
		*packet_count = be16toh(payload->packet_count);

	return true;
}

/** Test wrapper for extended punch result message parsing */
bool fastd_punch_test_parse_result_ext_message(
	const uint8_t *data, size_t len, uint8_t *type, size_t *key_len, uint16_t *packet_count,
	uint8_t *command_type, uint16_t *udp_punch_sockets, uint32_t *hard_sym_port_index,
	uint32_t *hard_sym_next_port_index, uint32_t *hard_sym_round, uint32_t *wait_window_ms) {
	fastd_buffer_t buffer = {
		.data = (void *)data,
		.len = len,
	};
	const fastd_punch_endpoint_t *payload = NULL;
	uint8_t parsed_type = 0;

	if (!parse_endpoint_message(&buffer, &parsed_type, &payload))
		return false;

	const fastd_punch_result_ext_t *ext = endpoint_message_result_ext(parsed_type, payload);
	if (!ext)
		return false;

	if (type)
		*type = parsed_type;
	if (key_len)
		*key_len = payload->key_len;
	if (packet_count)
		*packet_count = be16toh(payload->packet_count);
	if (command_type)
		*command_type = ext->command_type;
	if (udp_punch_sockets)
		*udp_punch_sockets = be16toh(ext->udp_punch_sockets);
	if (hard_sym_port_index)
		*hard_sym_port_index = be32toh(ext->hard_sym_port_index);
	if (hard_sym_next_port_index)
		*hard_sym_next_port_index = be32toh(ext->hard_sym_next_index);
	if (hard_sym_round)
		*hard_sym_round = be32toh(ext->hard_sym_round);
	if (wait_window_ms)
		*wait_window_ms = be32toh(ext->wait_window_ms);

	return true;
}

/** Test wrapper for punch result listener message parsing */
bool fastd_punch_test_parse_result_listener_message(
	const uint8_t *data, size_t len, uint8_t *type, size_t *key_len, uint16_t *packet_count,
	uint8_t *command_type, uint16_t *udp_punch_sockets, uint32_t *hard_sym_port_index,
	uint32_t *hard_sym_next_port_index, uint32_t *hard_sym_round, fastd_peer_address_t *base_mapped_endpoint,
	uint32_t *wait_window_ms, uint32_t *base_mapped_listener_id, bool *base_mapped_port_mapped) {
	fastd_buffer_t buffer = {
		.data = (void *)data,
		.len = len,
	};
	const fastd_punch_endpoint_t *payload = NULL;
	uint8_t parsed_type = 0;

	if (!parse_endpoint_message(&buffer, &parsed_type, &payload))
		return false;

	const fastd_punch_result_ext_t *ext = endpoint_message_result_ext(parsed_type, payload);
	const fastd_punch_result_listener_t *listener = endpoint_message_result_listener(parsed_type, payload);
	if (!ext || !listener)
		return false;

	if (type)
		*type = parsed_type;
	if (key_len)
		*key_len = payload->key_len;
	if (packet_count)
		*packet_count = be16toh(payload->packet_count);
	if (command_type)
		*command_type = ext->command_type;
	if (udp_punch_sockets)
		*udp_punch_sockets = be16toh(ext->udp_punch_sockets);
	if (hard_sym_port_index)
		*hard_sym_port_index = be32toh(ext->hard_sym_port_index);
	if (hard_sym_next_port_index)
		*hard_sym_next_port_index = be32toh(ext->hard_sym_next_index);
	if (hard_sym_round)
		*hard_sym_round = be32toh(ext->hard_sym_round);
	if (wait_window_ms)
		*wait_window_ms = be32toh(ext->wait_window_ms);
	if (base_mapped_listener_id)
		*base_mapped_listener_id = be32toh(listener->listener_id);
	if (base_mapped_endpoint && !decode_compact_address(base_mapped_endpoint, &listener->base_mapped_addr))
		return false;
	if (base_mapped_port_mapped)
		*base_mapped_port_mapped =
			(listener->base_mapped_addr.flags & FASTD_PUNCH_ADDRESS_PORT_MAPPED) != 0;

	return true;
}

/** Test wrapper for listener-info message parsing */
bool fastd_punch_test_parse_listener_info_message(
	const uint8_t *data, size_t len, uint8_t *type, size_t *key_len, uint32_t *listener_id) {
	fastd_buffer_t buffer = {
		.data = (void *)data,
		.len = len,
	};
	const fastd_punch_endpoint_t *payload = NULL;
	uint8_t parsed_type = 0;

	if (!parse_endpoint_message(&buffer, &parsed_type, &payload))
		return false;

	const fastd_punch_listener_info_t *info = endpoint_message_listener_info(parsed_type, payload);
	if (!info)
		return false;

	if (type)
		*type = parsed_type;
	if (key_len)
		*key_len = payload->key_len;
	if (listener_id)
		*listener_id = be32toh(info->listener_id);

	return true;
}

/** Test wrapper for endpoint command listener metadata parsing */
bool fastd_punch_test_parse_command_listener_message(
	const uint8_t *data, size_t len, uint8_t *type, size_t *key_len, uint16_t *packet_count,
	uint32_t *listener_id) {
	fastd_buffer_t buffer = {
		.data = (void *)data,
		.len = len,
	};
	const fastd_punch_endpoint_t *payload = NULL;
	uint8_t parsed_type = 0;

	if (!parse_endpoint_message(&buffer, &parsed_type, &payload))
		return false;

	const fastd_punch_command_listener_t *listener = endpoint_message_command_listener(parsed_type, payload);
	if (!listener)
		return false;

	if (type)
		*type = parsed_type;
	if (key_len)
		*key_len = payload->key_len;
	if (packet_count)
		*packet_count = be16toh(payload->packet_count);
	if (listener_id)
		*listener_id = be32toh(listener->listener_id);

	return true;
}

/** Test wrapper for port-mapped NAT_INFO promotion */
bool fastd_punch_test_mapped_endpoint_to_nat_info(
	const fastd_peer_address_t *mapped, fastd_peer_address_t *endpoint, fastd_nat_type_t *nat_type,
	uint16_t *min_port, uint16_t *max_port, int *port_delta) {
	return mapped_endpoint_to_nat_info(mapped, endpoint, nat_type, min_port, max_port, port_delta);
}

/** Test wrapper for punch result relay backoff policy */
bool fastd_punch_test_result_causes_relay_backoff(uint8_t result) {
	return punch_result_causes_relay_backoff((fastd_punch_result_t)result);
}

/** Test wrapper for punch UDP socket count policy */
unsigned fastd_punch_test_udp_socket_count(fastd_peer_t *peer, fastd_nat_type_t remote_nat_type) {
	return punch_udp_socket_count(peer, FASTD_PUNCH_SEND_CONE, remote_nat_type);
}

/** Test wrapper for punch UDP socket count policy with explicit local NAT type */
unsigned fastd_punch_test_udp_socket_count_for_nat(
	fastd_peer_t *peer, fastd_nat_type_t remote_nat_type, bool local_available, fastd_nat_type_t local_nat_type) {
	return punch_udp_socket_count_for_nat(peer, remote_nat_type, local_available, local_nat_type);
}

/** Test wrapper for command-specific punch UDP socket count policy */
unsigned fastd_punch_test_udp_socket_count_for_command(
	fastd_peer_t *peer, uint8_t command_type, fastd_nat_type_t remote_nat_type, bool local_available,
	fastd_nat_type_t local_nat_type) {
	return punch_udp_socket_count_for_command(peer, command_type, remote_nat_type, local_available, local_nat_type);
}

/** Test wrapper for relay-requested UDP socket count policy */
unsigned fastd_punch_test_udp_socket_count_for_request(
	fastd_peer_t *peer, uint8_t command_type, fastd_nat_type_t remote_nat_type, uint16_t requested_count) {
	return punch_udp_socket_count_for_request(peer, command_type, remote_nat_type, requested_count);
}

/** Test wrapper for relay-requested UDP socket count policy with explicit local NAT type */
unsigned fastd_punch_test_udp_socket_count_for_request_nat(
	fastd_peer_t *peer, uint8_t command_type, fastd_nat_type_t remote_nat_type, uint16_t requested_count,
	bool local_available, fastd_nat_type_t local_nat_type) {
	return punch_udp_socket_count_apply_request(
		punch_udp_socket_count_for_command(peer, command_type, remote_nat_type, local_available, local_nat_type),
		requested_count);
}

/** Test wrapper for relay endpoint command candidate count policy */
unsigned fastd_punch_test_relay_candidate_count(uint8_t command_type, size_t limit) {
	return punch_relay_candidate_count(command_type, limit);
}

/** Test wrapper for punch command type classification */
uint8_t
fastd_punch_test_endpoint_command_type(fastd_peer_t *dest, fastd_peer_t *subject, fastd_nat_type_t subject_nat_type) {
	return punch_endpoint_command_type(dest, subject, subject_nat_type);
}

/** Test wrapper for endpoint punch command type detection */
bool fastd_punch_test_is_endpoint_command_type(uint8_t type) {
	return punch_type_is_endpoint_command(type);
}

/** Test wrapper for punch-control NAT refresh policy */
bool fastd_punch_test_nat_status_needs_refresh(const fastd_nat_status_t *status) {
	return punch_nat_status_needs_refresh(status);
}

/** Test wrapper for punch task-manager pair collection state */
fastd_punch_test_pair_state_t fastd_punch_test_pair_state(const fastd_peer_t *a, const fastd_peer_t *b) {
	fastd_punch_pair_state_t state = punch_pair_state(a, b);

	return (fastd_punch_test_pair_state_t){
		.established = state.established,
		.has_metadata_a = state.has_metadata_a,
		.has_metadata_b = state.has_metadata_b,
		.due_a = state.due_a,
		.due_b = state.due_b,
		.collected = state.collected,
		.waiting = state.waiting,
		.in_flight = state.in_flight,
		.backoff = state.backoff,
		.recent_demand = state.recent_demand,
		.pending_demand = state.pending_demand,
		.missing_metadata = state.missing_metadata,
		.next_retry = state.next_retry,
	};
}

/** Test wrapper for marking a pair-level punch task as in-flight */
void fastd_punch_test_pair_runtime_mark_launched(const fastd_peer_t *a, const fastd_peer_t *b) {
	pair_runtime_mark_launched(a, b);
}

/** Test wrapper for compacting pair-level runtime state */
void fastd_punch_test_task_manager_compact_pair_states(void) {
	task_manager_compact_pair_states();
}

/** Test wrapper for task-manager launch lifecycle accounting */
void fastd_punch_test_task_manager_record_launch_result(
	size_t before_pair, size_t sent, size_t backoff_skipped, fastd_timeout_t backoff_next_retry) {
	task_manager_record_launch_result(before_pair, sent, backoff_skipped, backoff_next_retry);
}

/** Test wrapper for one relay task-manager run */
void fastd_punch_test_relay_peer_endpoints(void) {
	relay_peer_endpoints();
}

/** Test wrapper for remote punch-result lifecycle accounting */
void fastd_punch_test_task_manager_record_remote_result(uint8_t result) {
	task_manager_record_remote_result((fastd_punch_result_t)result);
}

/** Test wrapper for task-manager peer-pair lifecycle history */
void fastd_punch_test_task_manager_record_pair_task(
	const fastd_peer_t *a, const fastd_peer_t *b, const fastd_peer_t *subject, const fastd_peer_t *destination,
	fastd_punch_pair_task_stage_t stage, size_t candidates_sent, size_t backoff_skipped,
	fastd_timeout_t next_retry, bool budget_exhausted) {
	task_manager_record_pair_task(
		a, b, subject, destination, stage, candidates_sent, backoff_skipped, next_retry, budget_exhausted);
}

/** Test wrapper for remote result peer-pair lifecycle history */
void fastd_punch_test_task_manager_record_pair_result(
	fastd_peer_t *sender, fastd_peer_t *subject, uint8_t result, const fastd_peer_address_t *endpoint) {
	task_manager_record_pair_result(sender, subject, (fastd_punch_result_t)result, endpoint);
}

/** Test wrapper for authoritative punch result handling with duplicate suppression */
bool fastd_punch_test_handle_remote_result(
	fastd_peer_t *sender, fastd_peer_t *subject, uint8_t result, uint8_t command_type,
	const fastd_peer_address_t *endpoint) {
	uint64_t subject_key_hash = subject ? subject->id : 0;
	if (punch_result_duplicate(
		    sender, subject, endpoint, (fastd_punch_result_t)result, command_type, 0, subject_key_hash))
		return false;

	ctx.punch_result_rx++;
	if (sender && punch_result_causes_relay_backoff((fastd_punch_result_t)result))
		fastd_peer_add_punch_relay_backoff(sender, endpoint);
	task_manager_record_pair_result(sender, subject, (fastd_punch_result_t)result, endpoint);
	task_manager_record_remote_result((fastd_punch_result_t)result);
	return true;
}

/** Test wrapper for observed UDP control-path metadata fallback */
void fastd_punch_test_refresh_observed_peer_punch_metadata(fastd_peer_t *peer) {
	refresh_observed_peer_punch_metadata(peer);
}

#endif

/** Sends one concrete endpoint candidate as a punching command */
static bool relay_one_endpoint_to_peer(
	fastd_peer_t *dest, fastd_peer_t *subject, const fastd_peer_address_t *endpoint, fastd_nat_type_t nat_type,
	uint16_t min_port, uint16_t max_port, int port_delta, uint8_t command_type, uint8_t order,
	uint16_t packet_count) {
	if (subject->punch_listener_id && dest->punch_listener_id &&
	    endpoint_message_accepts_command_listener(command_type)) {
		fastd_punch_command_listener_t listener = {
			.listener_id = htobe32(subject->punch_listener_id),
		};

		return send_endpoint_message_extra(
			dest, command_type, conf.protocol->get_peer_key(subject), conf.protocol->key_length(), endpoint,
			nat_type, min_port, max_port, port_delta, order, packet_count, &listener, sizeof(listener));
	}

	return send_endpoint_message(
		dest, command_type, conf.protocol->get_peer_key(subject), conf.protocol->key_length(), endpoint, nat_type,
		min_port, max_port, port_delta, order, packet_count);
}

/** Sends a punch command result back to the peer that requested it */
static void send_punch_result(
	fastd_peer_t *dest, const void *subject_key, size_t key_len, const fastd_peer_address_t *endpoint,
	fastd_punch_result_t result, uint8_t command_type, uint16_t packet_count, unsigned udp_punch_sockets,
	uint32_t hard_sym_port_index, uint32_t hard_sym_next_port_index, uint32_t hard_sym_round,
	const fastd_peer_address_t *base_mapped_endpoint, uint32_t base_mapped_listener_id,
	bool base_mapped_port_mapped) {
	bool sent_legacy = send_endpoint_message(
		dest, FASTD_PUNCH_RESULT, subject_key, key_len, endpoint, FASTD_NAT_UNKNOWN, 0, 0, 0,
		(uint8_t)result, packet_count);

	fastd_punch_result_ext_t ext = {
		.command_type = command_type,
		.udp_punch_sockets = htobe16(punch_packet_count_wire(udp_punch_sockets)),
		.hard_sym_port_index = htobe32(hard_sym_port_index),
		.hard_sym_next_index = htobe32(hard_sym_next_port_index),
		.hard_sym_round = htobe32(hard_sym_round),
		.wait_window_ms = htobe32(punch_command_wait_window_ms(command_type)),
	};
	bool sent_listener = false;
	if (base_mapped_endpoint) {
		fastd_punch_result_listener_t listener = {
			.result = ext,
			.listener_id = htobe32(base_mapped_listener_id),
		};

		if (encode_compact_address(&listener.base_mapped_addr, base_mapped_endpoint)) {
			listener.base_mapped_addr.flags = FASTD_PUNCH_ADDRESS_AVAILABLE;
			if (base_mapped_port_mapped)
				listener.base_mapped_addr.flags |= FASTD_PUNCH_ADDRESS_PORT_MAPPED;

			sent_listener = send_endpoint_message_extra(
				dest, FASTD_PUNCH_RESULT_LISTENER, subject_key, key_len, endpoint, FASTD_NAT_UNKNOWN,
				0, 0, 0, (uint8_t)result, packet_count, &listener, sizeof(listener));
		}
	}

	bool sent_ext = false;
	if (!base_mapped_endpoint || !sent_listener) {
		sent_ext = send_endpoint_message_extra(
			dest, FASTD_PUNCH_RESULT_EXT, subject_key, key_len, endpoint, FASTD_NAT_UNKNOWN, 0, 0, 0,
			(uint8_t)result, packet_count, &ext, sizeof(ext));
	}

	if (sent_legacy || sent_ext || sent_listener)
		ctx.punch_result_tx++;
}

/** Sends one peer endpoint, or bounded easy-symmetric predictions, to another peer */
static size_t relay_endpoint_to_peer(
	fastd_peer_t *dest, fastd_peer_t *subject, size_t limit, size_t *backoff_skipped,
	fastd_timeout_t *backoff_next_retry) {
	if (!fastd_peer_is_established(dest) || !fastd_peer_is_established(subject))
		return 0;
	if (!limit)
		return 0;

	fastd_peer_punch_endpoint_t endpoints[FASTD_NAT_MAX_PUBLIC_ENDPOINTS + 1] = {};
	size_t n_endpoints = get_peer_endpoints(subject, endpoints, array_size(endpoints));
	if (!n_endpoints)
		return 0;

	size_t sent = 0;
	size_t generated = 0;
	fastd_peer_punch_task_command_t last_task_command = PEER_PUNCH_TASK_COMMAND_NONE;
	uint16_t last_packet_count = 0;
	uint32_t last_hard_sym_index = 0;
	uint32_t last_hard_sym_next_index = 0;
	uint32_t last_hard_sym_round = 0;
	fastd_peer_address_t last_endpoint = {};

	size_t i;
	for (i = 0; i < n_endpoints && generated < limit; i++) {
		fastd_peer_punch_endpoint_t *endpoint = &endpoints[i];
		fastd_nat_type_t nat_type = endpoint->nat_type;

		if (nat_type == FASTD_NAT_UNKNOWN && peer_waiting_for_punch_nat_info(subject))
			continue;

		if (fastd_peer_get_punch_symmetric(subject) && nat_type_needs_dest_nat_info(nat_type) &&
		    !peer_has_fresh_punch_nat_info(dest))
			continue;

		uint8_t command_type = punch_endpoint_command_type(dest, subject, nat_type);
		unsigned command_limit = punch_relay_candidate_count(command_type, limit - generated);
		if (!command_limit)
			continue;

		size_t endpoints_left = n_endpoints - i;
		unsigned budget_left = (unsigned)(limit - generated);
		unsigned endpoint_budget = (budget_left + (unsigned)endpoints_left - 1) / (unsigned)endpoints_left;
		if (endpoint_budget > command_limit)
			endpoint_budget = command_limit;
		if (!endpoint_budget)
			continue;

		bool paired_easy_symmetric = command_type == FASTD_PUNCH_BOTH_EASY_SYM;
		uint32_t hard_sym_index = endpoint->hard_sym_port_index;

		fastd_peer_address_t *candidates = fastd_new_array(endpoint_budget, fastd_peer_address_t);
		size_t n_candidates = build_endpoint_candidates(
			candidates, endpoint_budget, &endpoint->address, nat_type, endpoint->min_port, endpoint->max_port,
			endpoint->port_delta, endpoint_budget, fastd_peer_get_punch_symmetric(subject),
			paired_easy_symmetric, hard_sym_index, &endpoint->hard_sym_port_index, &endpoint->hard_sym_round);

		size_t endpoint_sent = 0;
		size_t j;
		for (j = 0; j < n_candidates; j++) {
			fastd_timeout_t backoff_timeout = fastd_peer_punch_relay_backoff_timeout(dest, &candidates[j]);
			if (backoff_timeout != FASTD_TIMEOUT_INV) {
				if (backoff_skipped)
					(*backoff_skipped)++;
				if (backoff_next_retry &&
				    (*backoff_next_retry == FASTD_TIMEOUT_INV || backoff_timeout < *backoff_next_retry))
					*backoff_next_retry = backoff_timeout;
				continue;
			}

			uint8_t order = generated + j > UINT8_MAX ? UINT8_MAX : (uint8_t)(generated + j);
			uint16_t packet_count = punch_packet_count_wire(relay_udp_packet_count(dest, command_type, nat_type));
			if (relay_one_endpoint_to_peer(
				    dest, subject, &candidates[j], nat_type, endpoint->min_port, endpoint->max_port,
				    endpoint->port_delta, command_type, order, packet_count)) {
				endpoint_sent++;
				last_packet_count = packet_count;
			}
		}

		free(candidates);
		generated += n_candidates;
		sent += endpoint_sent;

		if (endpoint_sent) {
			last_task_command = punch_task_command_from_type(command_type);
			last_hard_sym_index = hard_sym_index;
			last_hard_sym_next_index = endpoint->hard_sym_port_index;
			last_hard_sym_round = endpoint->hard_sym_round;
			last_endpoint = endpoint->address;
		}
	}

	sync_peer_punch_endpoint_scan_state(subject, endpoints, n_endpoints);

	if (sent && last_task_command != PEER_PUNCH_TASK_COMMAND_NONE) {
		record_punch_task(
			subject, PEER_PUNCH_TASK_ROLE_RELAY_SUBJECT, last_task_command, PEER_PUNCH_TASK_RESULT_NONE,
			&last_endpoint, last_packet_count, generated, sent, 0, 0, last_hard_sym_index,
			last_hard_sym_next_index, last_hard_sym_round);
		record_punch_task(
			dest, PEER_PUNCH_TASK_ROLE_RELAY_DEST, last_task_command, PEER_PUNCH_TASK_RESULT_NONE,
			&last_endpoint, last_packet_count, generated, sent, 0, last_packet_count, last_hard_sym_index,
			last_hard_sym_next_index, last_hard_sym_round);
	}

	return sent;
}

/** Sends one peer TCP mapped endpoint to another peer for simultaneous TCP connect */
static size_t relay_tcp_endpoint_to_peer(
	fastd_peer_t *dest, fastd_peer_t *subject, size_t limit, size_t *backoff_skipped,
	fastd_timeout_t *backoff_next_retry) {
	if (!limit)
		return 0;
	if (!fastd_peer_is_established(dest) || !fastd_peer_is_established(subject))
		return 0;

	if (!fastd_peer_hole_punch_allows(dest, TRANSPORT_TCP) ||
	    !fastd_peer_transport_allows(fastd_peer_get_transport(dest), TRANSPORT_TCP))
		return 0;
	if (!fastd_peer_hole_punch_allows(subject, TRANSPORT_TCP) ||
	    !fastd_peer_transport_allows(fastd_peer_get_transport(subject), TRANSPORT_TCP))
		return 0;

	if (!peer_has_fresh_tcp_punch_nat_info(dest) || !peer_has_fresh_tcp_punch_nat_info(subject))
		return 0;

	if (!tcp_nat_type_punchable(dest->tcp_punch_nat_type) || !tcp_nat_type_punchable(subject->tcp_punch_nat_type))
		return 0;

	fastd_peer_address_t endpoints[FASTD_NAT_MAX_PUBLIC_ENDPOINTS];
	size_t n_endpoints = 0;
	size_t i;

	for (i = 0; i < subject->n_tcp_punch_endpoints; i++) {
		n_endpoints = add_unique_endpoint(
			endpoints, n_endpoints, array_size(endpoints), &subject->tcp_punch_endpoints[i]);
	}
	n_endpoints =
		add_unique_endpoint(endpoints, n_endpoints, array_size(endpoints), &subject->tcp_punch_endpoint);

	size_t sent = 0;
	fastd_peer_address_t last_endpoint = {};
	for (i = 0; i < n_endpoints && sent < limit; i++) {
		fastd_timeout_t backoff_timeout = fastd_peer_punch_relay_backoff_timeout(dest, &endpoints[i]);
		if (backoff_timeout != FASTD_TIMEOUT_INV) {
			if (backoff_skipped)
				(*backoff_skipped)++;
			if (backoff_next_retry &&
			    (*backoff_next_retry == FASTD_TIMEOUT_INV || backoff_timeout < *backoff_next_retry))
				*backoff_next_retry = backoff_timeout;
			continue;
		}

		if (!send_endpoint_message(
			    dest, FASTD_PUNCH_SEND_TCP, conf.protocol->get_peer_key(subject),
			    conf.protocol->key_length(), &endpoints[i], subject->tcp_punch_nat_type,
			    subject->tcp_punch_min_port, subject->tcp_punch_max_port, 0, 0, 0))
			continue;

		last_endpoint = endpoints[i];
		sent++;
	}

	if (sent) {
		record_punch_task(
			subject, PEER_PUNCH_TASK_ROLE_RELAY_SUBJECT, PEER_PUNCH_TASK_COMMAND_TCP,
			PEER_PUNCH_TASK_RESULT_NONE, &last_endpoint, 0, n_endpoints, sent, 0, 0, 0, 0, 0);
		record_punch_task(
			dest, PEER_PUNCH_TASK_ROLE_RELAY_DEST, PEER_PUNCH_TASK_COMMAND_TCP,
			PEER_PUNCH_TASK_RESULT_NONE, &last_endpoint, 0, n_endpoints, sent, 0, 0, 0, 0, 0);
	}

	return sent;
}

/** Stores punch NAT metadata and resets hard-symmetric scan state when the public mapping changes */
static void update_punch_metadata(
	fastd_peer_t *peer, const fastd_peer_address_t *endpoint, fastd_nat_type_t nat_type, uint16_t min_port,
	uint16_t max_port, int port_delta, uint32_t listener_id, bool listener_id_available) {
	bool changed = !fastd_peer_address_equal(&peer->punch_endpoint, endpoint) || peer->punch_nat_type != nat_type ||
		       peer->punch_min_port != min_port || peer->punch_max_port != max_port ||
		       peer->punch_port_delta != port_delta;

	peer->punch_endpoint = *endpoint;
	peer->punch_nat_type = nat_type;
	peer->punch_min_port = min_port;
	peer->punch_max_port = max_port;
	peer->punch_port_delta = port_delta;
	peer->punch_timeout = ctx.now + PEER_STALE_TIME;
	peer->n_punch_endpoints = 0;
	peer->n_punch_endpoints = add_or_update_punch_endpoint(
		peer->punch_endpoints, peer->n_punch_endpoints, array_size(peer->punch_endpoints), endpoint, nat_type,
		min_port, max_port, port_delta);
	if (listener_id_available)
		peer->punch_listener_id = listener_id;
	else if (changed)
		peer->punch_listener_id = 0;

	if (changed) {
		peer->punch_hard_sym_port_index = 0;
		peer->punch_hard_sym_round = 0;
	}
}

/** Refreshes peer punch metadata from the authenticated UDP control path when no explicit NAT_INFO is available */
static void refresh_observed_peer_punch_metadata(fastd_peer_t *peer) {
	if (!fastd_peer_is_established(peer) || !fastd_peer_get_nat_traversal(peer))
		return;
	if (!peer->sock || fastd_socket_is_tcp(peer->sock))
		return;
	if (peer->address.sa.sa_family != AF_INET && peer->address.sa.sa_family != AF_INET6)
		return;

	if (peer_has_fresh_punch_nat_info(peer) &&
	    (peer->punch_nat_type != FASTD_NAT_UNKNOWN ||
	     fastd_peer_address_equal(&peer->punch_endpoint, &peer->address)))
		return;

	uint16_t port = ntohs(fastd_peer_address_get_port(&peer->address));
	if (!port)
		return;

	update_punch_metadata(peer, &peer->address, FASTD_NAT_UNKNOWN, port, port, 0, 0, false);
}

/** Adds a secondary UDP NAT metadata endpoint without replacing the primary endpoint */
static void add_punch_metadata_endpoint(
	fastd_peer_t *peer, const fastd_peer_address_t *endpoint, fastd_nat_type_t nat_type, uint16_t min_port,
	uint16_t max_port, int port_delta) {
	if (!peer_has_fresh_punch_nat_info(peer)) {
		update_punch_metadata(peer, endpoint, nat_type, min_port, max_port, port_delta, 0, false);
		return;
	}

	peer->punch_timeout = ctx.now + PEER_STALE_TIME;
	if (min_port && (!peer->punch_min_port || min_port < peer->punch_min_port))
		peer->punch_min_port = min_port;
	if (max_port > peer->punch_max_port)
		peer->punch_max_port = max_port;
	if (port_delta)
		peer->punch_port_delta = port_delta;

	peer->n_punch_endpoints = add_or_update_punch_endpoint(
		peer->punch_endpoints, peer->n_punch_endpoints, array_size(peer->punch_endpoints), endpoint,
		nat_type != FASTD_NAT_UNKNOWN ? nat_type : peer->punch_nat_type, min_port, max_port, port_delta);
}

/** Stores TCP NAT metadata announced by a peer */
static void update_tcp_punch_metadata(
	fastd_peer_t *peer, const fastd_peer_address_t *endpoint, fastd_nat_type_t nat_type, uint16_t min_port,
	uint16_t max_port) {
	peer->tcp_punch_endpoint = *endpoint;
	peer->n_tcp_punch_endpoints = 0;
	peer->n_tcp_punch_endpoints = add_unique_endpoint(
		peer->tcp_punch_endpoints, peer->n_tcp_punch_endpoints, array_size(peer->tcp_punch_endpoints), endpoint);
	peer->tcp_punch_nat_type = nat_type;
	peer->tcp_punch_min_port = min_port;
	peer->tcp_punch_max_port = max_port;
	peer->tcp_punch_timeout = ctx.now + PEER_STALE_TIME;
}

/** Adds a secondary TCP NAT metadata endpoint without replacing the primary endpoint */
static void add_tcp_punch_metadata_endpoint(
	fastd_peer_t *peer, const fastd_peer_address_t *endpoint, fastd_nat_type_t nat_type, uint16_t min_port,
	uint16_t max_port) {
	if (!peer_has_fresh_tcp_punch_nat_info(peer)) {
		update_tcp_punch_metadata(peer, endpoint, nat_type, min_port, max_port);
		return;
	}

	peer->tcp_punch_timeout = ctx.now + PEER_STALE_TIME;
	if (nat_type != FASTD_NAT_UNKNOWN)
		peer->tcp_punch_nat_type = nat_type;
	if (min_port && (!peer->tcp_punch_min_port || min_port < peer->tcp_punch_min_port))
		peer->tcp_punch_min_port = min_port;
	if (max_port > peer->tcp_punch_max_port)
		peer->tcp_punch_max_port = max_port;

	peer->n_tcp_punch_endpoints = add_unique_endpoint(
		peer->tcp_punch_endpoints, peer->n_tcp_punch_endpoints, array_size(peer->tcp_punch_endpoints),
		endpoint);
}

/** Relays endpoint control messages between established peers without forwarding data packets */
static void relay_peer_endpoints(void) {
	if (!conf.punch_control_relay || !punch_control_supported())
		return;

	ctx.punch_task_manager_runs++;
	ctx.punch_task_manager_pairs = 0;
	ctx.punch_task_manager_collected = 0;
	ctx.punch_task_manager_launched = 0;
	ctx.punch_task_manager_waiting = 0;
	ctx.punch_task_manager_in_flight = 0;
	ctx.punch_task_manager_missing_metadata = 0;
	ctx.punch_task_manager_metadata_requests = 0;
	ctx.punch_task_manager_blacklisted = 0;
	ctx.punch_task_manager_suppressed = 0;
	ctx.punch_task_manager_aborted = 0;
	ctx.punch_task_manager_recent_demand = 0;
	ctx.punch_task_manager_budget_exhausted = 0;
	ctx.punch_task_manager_next_retry = FASTD_TIMEOUT_INV;
	task_manager_compact_pair_states();

	size_t sent = 0;
	size_t i, j;
	for (i = 0; i < VECTOR_LEN(ctx.peers) && sent < conf.punch_max_packets; i++) {
		fastd_peer_t *a = VECTOR_INDEX(ctx.peers, i);
		refresh_observed_peer_punch_metadata(a);

		for (j = i + 1; j < VECTOR_LEN(ctx.peers) && sent < conf.punch_max_packets; j++) {
			fastd_peer_t *b = VECTOR_INDEX(ctx.peers, j);
			refresh_observed_peer_punch_metadata(b);
			fastd_punch_pair_state_t state = punch_pair_state(a, b);
			if (!state.established)
				continue;

			ctx.punch_task_manager_pairs++;
			if (state.recent_demand)
				ctx.punch_task_manager_recent_demand++;

			if (state.missing_metadata) {
				ctx.punch_task_manager_missing_metadata++;
				fastd_timeout_t next_retry = FASTD_TIMEOUT_INV;
				size_t metadata_requests = request_missing_pair_metadata(
					a, b, &state, conf.punch_max_packets - sent, &next_retry);
				sent += metadata_requests;
				ctx.punch_task_manager_metadata_requests += metadata_requests;
				task_manager_note_next_retry(next_retry);
				task_manager_record_pair_task(
					a, b, NULL, NULL,
					metadata_requests ? PUNCH_PAIR_TASK_STAGE_METADATA_REQUESTED :
							    PUNCH_PAIR_TASK_STAGE_MISSING_METADATA,
					metadata_requests, 0, next_retry,
					sent >= conf.punch_max_packets && conf.punch_max_packets);
				continue;
			}
			if (state.in_flight) {
				ctx.punch_task_manager_in_flight++;
				task_manager_note_next_retry(state.next_retry);
				task_manager_record_pair_task(
					a, b, NULL, NULL, PUNCH_PAIR_TASK_STAGE_IN_FLIGHT, 0, 0, state.next_retry,
					false);
				continue;
			}
			if (state.backoff) {
				ctx.punch_task_manager_blacklisted++;
				task_manager_note_next_retry(state.next_retry);
				task_manager_record_pair_task(
					a, b, NULL, NULL, PUNCH_PAIR_TASK_STAGE_BLACKLISTED, 0, 0,
					state.next_retry, false);
				continue;
			}
			if (state.waiting) {
				ctx.punch_task_manager_waiting++;
				task_manager_note_next_retry(state.next_retry);
				task_manager_record_pair_task(
					a, b, NULL, NULL, PUNCH_PAIR_TASK_STAGE_WAITING, 0, 0, state.next_retry, false);
				continue;
			}

			ctx.punch_task_manager_collected++;
			task_manager_record_pair_task(
				a, b, NULL, NULL, PUNCH_PAIR_TASK_STAGE_COLLECTED, 0, 0, FASTD_TIMEOUT_INV, false);

			size_t before_pair = sent;
			size_t backoff_skipped = 0;
			fastd_timeout_t backoff_next_retry = FASTD_TIMEOUT_INV;
			if (state.has_metadata_a && (state.due_a || state.pending_demand)) {
				size_t before_direction = sent;
				size_t before_direction_backoff = backoff_skipped;
				sent += relay_endpoint_to_peer(
					b, a, conf.punch_max_packets - sent, &backoff_skipped, &backoff_next_retry);
				if (sent < conf.punch_max_packets)
					sent += relay_tcp_endpoint_to_peer(
						b, a, conf.punch_max_packets - sent, &backoff_skipped,
						&backoff_next_retry);

				if (sent > before_direction) {
					task_manager_record_pair_task(
						a, b, a, b, PUNCH_PAIR_TASK_STAGE_LAUNCHED, sent - before_direction,
						backoff_skipped - before_direction_backoff, FASTD_TIMEOUT_INV,
						sent >= conf.punch_max_packets && conf.punch_max_packets);
					pair_runtime_mark_launched(a, b);
				}
				a->next_punch_relay = ctx.now + conf.punch_relay_interval;
				task_manager_note_next_retry(a->next_punch_relay);
			}
			if (sent < conf.punch_max_packets && state.has_metadata_b && (state.due_b || state.pending_demand)) {
				size_t before_direction = sent;
				size_t before_direction_backoff = backoff_skipped;
				sent += relay_endpoint_to_peer(
					a, b, conf.punch_max_packets - sent, &backoff_skipped, &backoff_next_retry);
				if (sent < conf.punch_max_packets)
					sent += relay_tcp_endpoint_to_peer(
						a, b, conf.punch_max_packets - sent, &backoff_skipped,
						&backoff_next_retry);

				if (sent > before_direction) {
					task_manager_record_pair_task(
						a, b, b, a, PUNCH_PAIR_TASK_STAGE_LAUNCHED, sent - before_direction,
						backoff_skipped - before_direction_backoff, FASTD_TIMEOUT_INV,
						sent >= conf.punch_max_packets && conf.punch_max_packets);
					pair_runtime_mark_launched(a, b);
				}
				b->next_punch_relay = ctx.now + conf.punch_relay_interval;
				task_manager_note_next_retry(b->next_punch_relay);
			}

			if (sent == before_pair) {
				task_manager_record_pair_task(
					a, b, NULL, NULL,
					backoff_skipped ? PUNCH_PAIR_TASK_STAGE_BLACKLISTED : PUNCH_PAIR_TASK_STAGE_SUPPRESSED,
					0, backoff_skipped, backoff_next_retry, false);
			}
			task_manager_record_launch_result(before_pair, sent, backoff_skipped, backoff_next_retry);
		}
	}

	ctx.punch_task_manager_budget_exhausted = sent >= conf.punch_max_packets && conf.punch_max_packets ? 1 : 0;
}

/** Stores NAT metadata announced by a peer */
static void handle_nat_info(fastd_peer_t *sender, const fastd_punch_endpoint_t *payload, bool additional) {
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

	if (additional)
		add_punch_metadata_endpoint(
			subject, &endpoint, payload->nat_type, be16toh(payload->min_port), be16toh(payload->max_port),
			(int16_t)be16toh(payload->port_delta));
	else
		update_punch_metadata(
			subject, &endpoint, payload->nat_type, be16toh(payload->min_port), be16toh(payload->max_port),
			(int16_t)be16toh(payload->port_delta), 0, false);

	pr_debug(
		"received punch NAT info from %P: %s %I", subject, fastd_nat_type_name(subject->punch_nat_type),
		&endpoint);
}

/** Stores TCP NAT metadata announced by a peer */
static void handle_tcp_nat_info(fastd_peer_t *sender, const fastd_punch_endpoint_t *payload, bool additional) {
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

	fastd_nat_type_t nat_type = payload->nat_type;
	if (!tcp_nat_type_punchable(nat_type))
		return;

	if (additional)
		add_tcp_punch_metadata_endpoint(
			subject, &endpoint, nat_type, be16toh(payload->min_port), be16toh(payload->max_port));
	else
		update_tcp_punch_metadata(
			subject, &endpoint, nat_type, be16toh(payload->min_port), be16toh(payload->max_port));

	pr_debug(
		"received TCP punch NAT info from %P: %s %I", subject, fastd_nat_type_name(subject->tcp_punch_nat_type),
		&endpoint);
}

/** Handles a remote request to select a reusable local public UDP punch listener */
static void handle_select_listener_request(fastd_peer_t *sender, const fastd_punch_endpoint_t *payload) {
	size_t key_len = conf.protocol->key_length();
	if (payload->key_len != key_len)
		return;

	const uint8_t *key = (const uint8_t *)(payload + 1);
	fastd_peer_t *subject = find_peer_by_key(key, key_len);
	if (!subject || subject != sender)
		return;

	fastd_peer_address_t requested_endpoint;
	if (!decode_address(&requested_endpoint, payload))
		return;

	sa_family_t family = requested_endpoint.sa.sa_family;
	if (family != AF_INET && family != AF_INET6)
		return;

	fastd_nat_status_t status;
	if (!fastd_nat_get_status(&status)) {
		fastd_nat_request_refresh();
		return;
	}

	bool force_new = (payload->reserved & FASTD_PUNCH_SELECT_FORCE_NEW) != 0;
	bool prefer_port_mapping = (payload->reserved & FASTD_PUNCH_SELECT_PREFER_PORT_MAPPING) != 0;
	fastd_peer_address_t listener_endpoint;
	fastd_nat_type_t nat_type;
	uint16_t min_port, max_port;
	int port_delta;
	bool port_mapped = false;
	uint32_t listener_id = 0;

	if (!get_local_udp_nat_info_endpoint(
		    sender, &status, &listener_endpoint, &nat_type, &min_port, &max_port, &port_delta, &port_mapped,
		    &listener_id, family, force_new, prefer_port_mapping))
		return;

	send_listener_info(
		sender, &listener_endpoint, nat_type, min_port, max_port, port_delta, port_mapped, listener_id);
	pr_debug("selected punch listener for %P: %I", sender, &listener_endpoint);
}

/** Stores listener metadata selected by a peer for this instance */
static void handle_listener_info(fastd_peer_t *sender, const fastd_punch_endpoint_t *payload, uint8_t type) {
	size_t key_len = conf.protocol->key_length();
	if (payload->key_len != key_len)
		return;

	const fastd_punch_listener_info_t *info = endpoint_message_listener_info(type, payload);
	if (!info)
		return;

	const uint8_t *key = endpoint_message_key(type, payload);
	fastd_peer_t *subject = find_peer_by_key(key, key_len);
	if (!subject || subject != sender)
		return;

	fastd_peer_address_t endpoint;
	if (!decode_address(&endpoint, payload))
		return;

	uint32_t listener_id = be32toh(info->listener_id);
	bool port_mapped = (payload->reserved & FASTD_PUNCH_LISTENER_PORT_MAPPED) != 0;
	fastd_nat_type_t nat_type = port_mapped ? FASTD_NAT_FULL_CONE : payload->nat_type;

	update_punch_metadata(
		sender, &endpoint, nat_type, be16toh(payload->min_port), be16toh(payload->max_port),
		(int16_t)be16toh(payload->port_delta), listener_id, true);
	pr_debug("received punch listener info from %P: listener %u %I", sender, (unsigned)listener_id, &endpoint);
}

/** Handles an endpoint punching command */
static void handle_send_endpoint_command(fastd_peer_t *sender, const fastd_punch_endpoint_t *payload, uint8_t type) {
	size_t key_len = conf.protocol->key_length();
	if (payload->key_len != key_len)
		return;

	const uint8_t *key = endpoint_message_key(type, payload);
	if (key_is_self(key, key_len))
		return;

	fastd_peer_address_t endpoint;
	if (!decode_address(&endpoint, payload))
		return;

	uint16_t requested_count = be16toh(payload->packet_count);
	fastd_peer_punch_task_command_t task_command = punch_task_command_from_type(type);
	const fastd_punch_command_listener_t *command_listener = endpoint_message_command_listener(type, payload);
	uint32_t endpoint_listener_id = command_listener ? be32toh(command_listener->listener_id) : 0;

	fastd_peer_t *peer = find_peer_by_key(key, key_len);
	if (!peer) {
		record_punch_task(
			sender, PEER_PUNCH_TASK_ROLE_RESULT_SENDER, task_command, PEER_PUNCH_TASK_RESULT_NO_PEER,
			&endpoint, requested_count, 1, 0, payload->reserved, 0, 0, 0, 0);
		send_punch_result(
			sender, key, key_len, &endpoint, FASTD_PUNCH_RESULT_NO_PEER, type, requested_count, 0, 0, 0, 0,
			NULL, 0, false);
		return;
	}

	bool endpoint_dependent_nat = nat_type_is_endpoint_dependent(payload->nat_type);
	if (fastd_peer_active_path_proven(peer) &&
	    ((endpoint_dependent_nat && fastd_peer_has_backup_path(peer)) ||
	     (fastd_peer_has_verified_backup_path(peer) && peer->backup_payload_proven))) {
		record_punch_task(
			peer, PEER_PUNCH_TASK_ROLE_COMMAND_TARGET, task_command, PEER_PUNCH_TASK_RESULT_BUSY, &endpoint,
			requested_count, 1, 0, payload->reserved, 0, peer->punch_hard_sym_port_index,
			peer->punch_hard_sym_port_index, peer->punch_hard_sym_round);
		send_punch_result(
			sender, key, key_len, &endpoint, FASTD_PUNCH_RESULT_BUSY, type, requested_count, 0,
			peer->punch_hard_sym_port_index, peer->punch_hard_sym_port_index, peer->punch_hard_sym_round, NULL,
			0, false);
		return;
	}

	update_punch_metadata(
		peer, &endpoint, payload->nat_type, be16toh(payload->min_port), be16toh(payload->max_port),
		(int16_t)be16toh(payload->port_delta), endpoint_listener_id, command_listener != NULL);

	fastd_peer_address_t base_mapped_endpoint = {};
	bool base_mapped_port_mapped = false;
	uint32_t base_mapped_listener_id = 0;
	bool have_base_mapped =
		get_local_base_mapped_endpoint(sender, &base_mapped_endpoint, &base_mapped_port_mapped, &base_mapped_listener_id);
	const fastd_peer_address_t *base_mapped = have_base_mapped ? &base_mapped_endpoint : NULL;

	unsigned udp_punch_sockets = punch_udp_socket_count_for_request(peer, type, payload->nat_type, requested_count);
	bool exact_udp_punch = udp_punch_sockets > 0;
	bool accepted = fastd_peer_add_punch_control_candidate(
		peer, &endpoint, FASTD_PUNCH_CANDIDATE_PRIORITY, exact_udp_punch, udp_punch_sockets, payload->reserved);

	if (!accepted) {
		record_punch_task_base(
			peer, PEER_PUNCH_TASK_ROLE_COMMAND_TARGET, task_command, PEER_PUNCH_TASK_RESULT_SUPPRESSED,
			&endpoint, requested_count, 1, 0, payload->reserved, udp_punch_sockets,
			peer->punch_hard_sym_port_index, peer->punch_hard_sym_port_index, peer->punch_hard_sym_round,
			base_mapped, base_mapped_listener_id, base_mapped_port_mapped);
		send_punch_result(
			sender, key, key_len, &endpoint, FASTD_PUNCH_RESULT_SUPPRESSED, type, requested_count,
			udp_punch_sockets, peer->punch_hard_sym_port_index, peer->punch_hard_sym_port_index,
			peer->punch_hard_sym_round, base_mapped, base_mapped_listener_id, base_mapped_port_mapped);
		return;
	}

	if (fastd_peer_is_current_punch_control_candidate_transport(peer, &endpoint, TRANSPORT_UDP, NULL, NULL) &&
	    fastd_peer_send_direct_handshake_transport(peer, &endpoint, TRANSPORT_UDP)) {
		ctx.punch_direct_handshakes++;
		record_punch_task_base(
			peer, PEER_PUNCH_TASK_ROLE_COMMAND_TARGET, task_command, PEER_PUNCH_TASK_RESULT_HANDSHAKE,
			&endpoint, requested_count, 1, 1, payload->reserved, udp_punch_sockets,
			peer->punch_hard_sym_port_index, peer->punch_hard_sym_port_index, peer->punch_hard_sym_round,
			base_mapped, base_mapped_listener_id, base_mapped_port_mapped);
		send_punch_result(
			sender, key, key_len, &endpoint, FASTD_PUNCH_RESULT_HANDSHAKE, type, requested_count,
			udp_punch_sockets, peer->punch_hard_sym_port_index, peer->punch_hard_sym_port_index,
			peer->punch_hard_sym_round, base_mapped, base_mapped_listener_id, base_mapped_port_mapped);
	} else {
		record_punch_task_base(
			peer, PEER_PUNCH_TASK_ROLE_COMMAND_TARGET, task_command, PEER_PUNCH_TASK_RESULT_ACCEPTED,
			&endpoint, requested_count, 1, 1, payload->reserved, udp_punch_sockets,
			peer->punch_hard_sym_port_index, peer->punch_hard_sym_port_index, peer->punch_hard_sym_round,
			base_mapped, base_mapped_listener_id, base_mapped_port_mapped);
		send_punch_result(
			sender, key, key_len, &endpoint, FASTD_PUNCH_RESULT_ACCEPTED, type, requested_count,
			udp_punch_sockets, peer->punch_hard_sym_port_index, peer->punch_hard_sym_port_index,
			peer->punch_hard_sym_round, base_mapped, base_mapped_listener_id, base_mapped_port_mapped);
	}

	pr_debug(
		"received punch %s command from %P for %P[%I]", punch_command_type_name(type), sender, peer, &endpoint);
}

/** Handles a TCP mapped-address exchange command */
static void handle_send_tcp_endpoint_command(fastd_peer_t *sender, const fastd_punch_endpoint_t *payload) {
	size_t key_len = conf.protocol->key_length();
	if (payload->key_len != key_len)
		return;

	const uint8_t *key = (const uint8_t *)(payload + 1);
	if (key_is_self(key, key_len))
		return;

	fastd_peer_address_t endpoint;
	if (!decode_address(&endpoint, payload))
		return;

	fastd_peer_t *peer = find_peer_by_key(key, key_len);
	if (!peer) {
		record_punch_task(
			sender, PEER_PUNCH_TASK_ROLE_RESULT_SENDER, PEER_PUNCH_TASK_COMMAND_TCP,
			PEER_PUNCH_TASK_RESULT_NO_PEER, &endpoint, 0, 1, 0, 0, 0, 0, 0, 0);
		send_punch_result(
			sender, key, key_len, &endpoint, FASTD_PUNCH_RESULT_NO_PEER, FASTD_PUNCH_SEND_TCP, 0, 0, 0, 0,
			0, NULL, 0, false);
		return;
	}

	if (fastd_peer_has_verified_backup_path(peer) && fastd_peer_active_path_proven(peer) &&
	    peer->backup_payload_proven) {
		record_punch_task(
			peer, PEER_PUNCH_TASK_ROLE_COMMAND_TARGET, PEER_PUNCH_TASK_COMMAND_TCP, PEER_PUNCH_TASK_RESULT_BUSY,
			&endpoint, 0, 1, 0, 0, 0, 0, 0, 0);
		send_punch_result(
			sender, key, key_len, &endpoint, FASTD_PUNCH_RESULT_BUSY, FASTD_PUNCH_SEND_TCP, 0, 0, 0, 0, 0,
			NULL, 0, false);
		return;
	}

	fastd_nat_type_t nat_type = payload->nat_type;
	if (peer_has_fresh_tcp_punch_nat_info(peer))
		add_tcp_punch_metadata_endpoint(
			peer, &endpoint, nat_type, be16toh(payload->min_port), be16toh(payload->max_port));
	else
		update_tcp_punch_metadata(
			peer, &endpoint, nat_type, be16toh(payload->min_port), be16toh(payload->max_port));

	if (!tcp_nat_type_punchable(nat_type) || !fastd_peer_hole_punch_allows(peer, TRANSPORT_TCP) ||
	    !fastd_peer_transport_allows(fastd_peer_get_transport(peer), TRANSPORT_TCP)) {
		record_punch_task(
			peer, PEER_PUNCH_TASK_ROLE_COMMAND_TARGET, PEER_PUNCH_TASK_COMMAND_TCP,
			PEER_PUNCH_TASK_RESULT_SUPPRESSED, &endpoint, 0, 1, 0, payload->reserved, 0, 0, 0, 0);
		send_punch_result(
			sender, key, key_len, &endpoint, FASTD_PUNCH_RESULT_SUPPRESSED, FASTD_PUNCH_SEND_TCP, 0, 0, 0,
			0, 0, NULL, 0, false);
		return;
	}

	bool accepted = fastd_peer_add_punch_control_candidate_transport(
		peer, &endpoint, FASTD_PUNCH_CANDIDATE_PRIORITY, false, 0, payload->reserved,
		DIRECT_CANDIDATE_TRANSPORT_TCP);

	if (!accepted) {
		record_punch_task(
			peer, PEER_PUNCH_TASK_ROLE_COMMAND_TARGET, PEER_PUNCH_TASK_COMMAND_TCP,
			PEER_PUNCH_TASK_RESULT_SUPPRESSED, &endpoint, 0, 1, 0, payload->reserved, 0, 0, 0, 0);
		send_punch_result(
			sender, key, key_len, &endpoint, FASTD_PUNCH_RESULT_SUPPRESSED, FASTD_PUNCH_SEND_TCP, 0, 0, 0,
			0, 0, NULL, 0, false);
		return;
	}

	if (fastd_peer_is_current_punch_control_candidate_transport(peer, &endpoint, TRANSPORT_TCP, NULL, NULL) &&
	    fastd_peer_send_direct_handshake_transport(peer, &endpoint, TRANSPORT_TCP)) {
		ctx.punch_direct_handshakes++;
		record_punch_task(
			peer, PEER_PUNCH_TASK_ROLE_COMMAND_TARGET, PEER_PUNCH_TASK_COMMAND_TCP,
			PEER_PUNCH_TASK_RESULT_HANDSHAKE, &endpoint, 0, 1, 1, payload->reserved, 0, 0, 0, 0);
		send_punch_result(
			sender, key, key_len, &endpoint, FASTD_PUNCH_RESULT_HANDSHAKE, FASTD_PUNCH_SEND_TCP, 0, 0, 0,
			0, 0, NULL, 0, false);
	} else {
		record_punch_task(
			peer, PEER_PUNCH_TASK_ROLE_COMMAND_TARGET, PEER_PUNCH_TASK_COMMAND_TCP,
			PEER_PUNCH_TASK_RESULT_ACCEPTED, &endpoint, 0, 1, 1, payload->reserved, 0, 0, 0, 0);
		send_punch_result(
			sender, key, key_len, &endpoint, FASTD_PUNCH_RESULT_ACCEPTED, FASTD_PUNCH_SEND_TCP, 0, 0, 0,
			0, 0, NULL, 0, false);
	}

	pr_debug("received punch tcp command from %P for %P[%I]", sender, peer, &endpoint);
}

/** Handles a punch command result from another peer */
static void handle_result(fastd_peer_t *sender, const fastd_punch_endpoint_t *payload, uint8_t type) {
	size_t key_len = conf.protocol->key_length();
	if (payload->key_len != key_len)
		return;

	const uint8_t *key = endpoint_message_key(type, payload);
	fastd_peer_t *subject = find_peer_by_key(key, key_len);
	uint64_t subject_key_hash = punch_result_subject_key_hash(key, key_len);

	fastd_peer_address_t endpoint;
	if (!decode_address(&endpoint, payload))
		return;

	fastd_punch_result_t result = (fastd_punch_result_t)payload->reserved;
	fastd_peer_punch_task_result_t task_result = punch_task_result_from_wire(result);
	uint16_t packet_count = be16toh(payload->packet_count);
	uint16_t udp_punch_sockets = 0;
	fastd_peer_punch_task_command_t task_command = PEER_PUNCH_TASK_COMMAND_NONE;
	uint32_t hard_sym_index = sender ? sender->punch_hard_sym_port_index : 0;
	uint32_t hard_sym_next_index = hard_sym_index;
	uint32_t hard_sym_round = sender ? sender->punch_hard_sym_round : 0;
	uint32_t wait_window_ms = 0;
	fastd_peer_address_t base_mapped_endpoint = {};
	bool have_base_mapped = false;
	bool base_mapped_port_mapped = false;
	uint32_t base_mapped_listener_id = 0;

	const fastd_punch_result_ext_t *ext = endpoint_message_result_ext(type, payload);
	if (ext) {
		task_command = punch_task_command_from_type(ext->command_type);
		udp_punch_sockets = be16toh(ext->udp_punch_sockets);
		hard_sym_index = be32toh(ext->hard_sym_port_index);
		hard_sym_next_index = be32toh(ext->hard_sym_next_index);
		hard_sym_round = be32toh(ext->hard_sym_round);
		wait_window_ms = be32toh(ext->wait_window_ms);
	}

	const fastd_punch_result_listener_t *listener = endpoint_message_result_listener(type, payload);
	if (listener) {
		base_mapped_listener_id = be32toh(listener->listener_id);
		have_base_mapped = decode_compact_address(&base_mapped_endpoint, &listener->base_mapped_addr);
		base_mapped_port_mapped =
			(listener->base_mapped_addr.flags & FASTD_PUNCH_ADDRESS_PORT_MAPPED) != 0;
	}

	bool duplicate = punch_result_duplicate(
		sender, subject, &endpoint, result, ext ? ext->command_type : 0, packet_count, subject_key_hash);
	if (duplicate && !ext)
		return;

	const fastd_peer_address_t *base_mapped = have_base_mapped ? &base_mapped_endpoint : NULL;
	record_punch_task_base(
		sender, PEER_PUNCH_TASK_ROLE_RESULT_SENDER, task_command, task_result, &endpoint, packet_count, 1, 0,
		0, udp_punch_sockets, hard_sym_index, hard_sym_next_index, hard_sym_round, base_mapped,
		base_mapped_listener_id, base_mapped_port_mapped);
	if (sender && wait_window_ms)
		sender->last_punch_task.wait_window_ms = wait_window_ms;
	if (subject) {
		record_punch_task_base(
			subject, PEER_PUNCH_TASK_ROLE_RESULT_SUBJECT, task_command, task_result, &endpoint,
			packet_count, 1, 0, 0, udp_punch_sockets, hard_sym_index, hard_sym_next_index, hard_sym_round,
			base_mapped, base_mapped_listener_id, base_mapped_port_mapped);
		if (wait_window_ms)
			subject->last_punch_task.wait_window_ms = wait_window_ms;
	}

	if (sender && have_base_mapped) {
		uint16_t port = ntohs(fastd_peer_address_get_port(&base_mapped_endpoint));
		fastd_nat_type_t nat_type = base_mapped_port_mapped ? FASTD_NAT_FULL_CONE : sender->punch_nat_type;
		uint16_t min_port = sender->punch_min_port;
		uint16_t max_port = sender->punch_max_port;
		int port_delta = sender->punch_port_delta;

		if (sender->punch_endpoint.sa.sa_family == AF_UNSPEC || fastd_timed_out(sender->punch_timeout)) {
			nat_type = base_mapped_port_mapped ? FASTD_NAT_FULL_CONE : FASTD_NAT_UNKNOWN;
			min_port = port;
			max_port = port;
			port_delta = 0;
		}

		if (!min_port || port < min_port)
			min_port = port;
		if (port > max_port)
			max_port = port;

		update_punch_metadata(
			sender, &base_mapped_endpoint, nat_type, min_port, max_port, port_delta,
			base_mapped_listener_id, true);
	}

	if (duplicate)
		return;

	ctx.punch_result_rx++;
	if (sender && punch_result_causes_relay_backoff(result))
		fastd_peer_add_punch_relay_backoff(sender, &endpoint);
	task_manager_record_pair_result(sender, subject, result, &endpoint);

	switch (result) {
	case FASTD_PUNCH_RESULT_ACCEPTED:
		ctx.punch_result_accepted++;
		task_manager_record_remote_result(result);
		if (subject)
			pr_debug("received punch accepted result from %P for %P[%I]", sender, subject, &endpoint);
		else
			pr_debug(
				"received punch accepted result from %P for unknown key endpoint %I", sender,
				&endpoint);
		break;

	case FASTD_PUNCH_RESULT_HANDSHAKE:
		ctx.punch_result_handshake++;
		task_manager_record_remote_result(result);
		if (subject)
			pr_debug("received punch handshake result from %P for %P[%I]", sender, subject, &endpoint);
		else
			pr_debug(
				"received punch handshake result from %P for unknown key endpoint %I", sender,
				&endpoint);
		break;

	case FASTD_PUNCH_RESULT_SUPPRESSED:
		ctx.punch_result_suppressed++;
		task_manager_record_remote_result(result);
		if (subject)
			pr_debug("received punch suppressed result from %P for %P[%I]", sender, subject, &endpoint);
		else
			pr_debug(
				"received punch suppressed result from %P for unknown key endpoint %I", sender,
				&endpoint);
		break;

	case FASTD_PUNCH_RESULT_NO_PEER:
		ctx.punch_result_no_peer++;
		task_manager_record_remote_result(result);
		pr_debug(
			"received punch no-peer result from %P for key length %zu endpoint %I", sender, key_len,
			&endpoint);
		break;

	case FASTD_PUNCH_RESULT_BUSY:
		ctx.punch_result_busy++;
		task_manager_record_remote_result(result);
		if (subject)
			pr_debug("received punch busy result from %P for %P[%I]", sender, subject, &endpoint);
		else
			pr_debug("received punch busy result from %P for unknown key endpoint %I", sender, &endpoint);
		break;

	default:
		break;
	}
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
		handle_nat_info(peer, payload, false);
		break;

	case FASTD_PUNCH_NAT_INFO_EXTRA:
		handle_nat_info(peer, payload, true);
		break;

	case FASTD_PUNCH_TCP_NAT_INFO:
		handle_tcp_nat_info(peer, payload, false);
		break;

	case FASTD_PUNCH_TCP_NAT_INFO_EXTRA:
		handle_tcp_nat_info(peer, payload, true);
		break;

	case FASTD_PUNCH_SELECT_LISTENER:
		handle_select_listener_request(peer, payload);
		break;

	case FASTD_PUNCH_LISTENER_INFO:
		handle_listener_info(peer, payload, type);
		break;

	case FASTD_PUNCH_SEND_CONE:
	case FASTD_PUNCH_SEND_EASY_SYM:
	case FASTD_PUNCH_SEND_HARD_SYM:
	case FASTD_PUNCH_BOTH_EASY_SYM:
		if (punch_type_is_endpoint_command(type))
			handle_send_endpoint_command(peer, payload, type);
		break;

	case FASTD_PUNCH_SEND_TCP:
		handle_send_tcp_endpoint_command(peer, payload);
		break;

	case FASTD_PUNCH_RESULT:
	case FASTD_PUNCH_RESULT_EXT:
	case FASTD_PUNCH_RESULT_LISTENER:
		handle_result(peer, payload, type);
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
