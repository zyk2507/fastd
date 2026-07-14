// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Relay-assisted peer endpoint discovery
*/

#include "discovery.h"
#include "peer.h"


#define FASTD_DISCOVERY_VERSION 1
#define FASTD_DISCOVERY_VERSION_SCOPED 2
#define FASTD_DISCOVERY_ENDPOINT 1
#define FASTD_DISCOVERY_MAX_MACS 16
#define FASTD_DISCOVERY_ANNOUNCE_INTERVAL 5000

#define FASTD_DISCOVERY_AF_INET 4
#define FASTD_DISCOVERY_AF_INET6 6


/** Endpoint announcement sent over an authenticated control packet */
typedef struct __attribute__((packed)) fastd_discovery_endpoint {
	uint8_t version;        /**< Discovery protocol version */
	uint8_t type;           /**< Discovery message type */
	uint8_t key_len;        /**< Length of the following peer public key */
	uint8_t mac_count;      /**< Number of following Ethernet addresses */
	uint8_t address_family; /**< FASTD_DISCOVERY_AF_* */
	uint8_t reserved;       /**< Reserved for future use */
	uint16_t port;          /**< Peer endpoint port, in network byte order */
	uint8_t address[16];    /**< IPv4 address in the first 4 bytes, or an IPv6 address */
} fastd_discovery_endpoint_t;


/** Returns true if an endpoint announcement must carry an IPv6 scope ID */
static bool address_needs_scope_id(const fastd_peer_address_t *addr) {
	return addr->sa.sa_family == AF_INET6 && addr->in6.sin6_scope_id;
}

/** Returns the wire header length for an endpoint announcement */
static size_t endpoint_header_len(const fastd_discovery_endpoint_t *header) {
	switch (header->version) {
	case FASTD_DISCOVERY_VERSION:
		return sizeof(fastd_discovery_endpoint_t);

	case FASTD_DISCOVERY_VERSION_SCOPED:
		return sizeof(fastd_discovery_endpoint_t) + sizeof(uint32_t);

	default:
		return 0;
	}
}

/** Writes the optional IPv6 scope ID extension */
static bool encode_scope_id(uint8_t *wire, size_t len, const fastd_peer_address_t *addr) {
	if (!address_needs_scope_id(addr))
		return false;

	if (len < sizeof(fastd_discovery_endpoint_t) + sizeof(uint32_t))
		return false;

	uint32_t scope_id = htonl(addr->in6.sin6_scope_id);
	memcpy(wire + sizeof(fastd_discovery_endpoint_t), &scope_id, sizeof(scope_id));
	return true;
}

/** Reads the optional IPv6 scope ID extension */
static void decode_scope_id(fastd_peer_address_t *addr, const uint8_t *wire, size_t len) {
	if (addr->sa.sa_family != AF_INET6 || len < sizeof(fastd_discovery_endpoint_t) + sizeof(uint32_t))
		return;

	uint32_t scope_id;
	memcpy(&scope_id, wire + sizeof(fastd_discovery_endpoint_t), sizeof(scope_id));
	addr->in6.sin6_scope_id = ntohl(scope_id);
}

/** Returns true if two Ethernet addresses are equal */
static bool eth_addr_equal(fastd_eth_addr_t a, fastd_eth_addr_t b) {
	return !memcmp(&a, &b, sizeof(a));
}

/** Adds an Ethernet address to a fixed-size list, avoiding duplicates */
static void add_mac(fastd_eth_addr_t *macs, size_t *n_macs, fastd_eth_addr_t mac) {
	if (!fastd_eth_addr_is_unicast(mac))
		return;

	size_t i;
	for (i = 0; i < *n_macs; i++) {
		if (eth_addr_equal(macs[i], mac))
			return;
	}

	if (*n_macs < FASTD_DISCOVERY_MAX_MACS)
		macs[(*n_macs)++] = mac;
}

/** Collects MAC addresses currently known to belong to a peer */
static size_t collect_macs(fastd_peer_t *peer, fastd_eth_addr_t source_mac, fastd_eth_addr_t *macs) {
	size_t n_macs = 0;
	add_mac(macs, &n_macs, source_mac);

	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.eth_addrs); i++) {
		const fastd_peer_eth_addr_t *entry = &VECTOR_INDEX(ctx.eth_addrs, i);

		if (entry->peer != peer)
			continue;

		if (fastd_timed_out(entry->timeout))
			continue;

		add_mac(macs, &n_macs, entry->addr);
	}

	return n_macs;
}

/** Writes a peer address into an endpoint announcement header */
static bool encode_address(fastd_discovery_endpoint_t *header, const fastd_peer_address_t *addr) {
	memset(header->address, 0, sizeof(header->address));
	header->port = fastd_peer_address_get_port(addr);

	switch (addr->sa.sa_family) {
	case AF_INET:
		header->address_family = FASTD_DISCOVERY_AF_INET;
		memcpy(header->address, &addr->in.sin_addr, sizeof(addr->in.sin_addr));
		return true;

	case AF_INET6:
		header->address_family = FASTD_DISCOVERY_AF_INET6;
		memcpy(header->address, &addr->in6.sin6_addr, sizeof(addr->in6.sin6_addr));
		return true;

	default:
		return false;
	}
}

/** Reads a peer address from an endpoint announcement header */
static bool decode_address(fastd_peer_address_t *addr, const fastd_discovery_endpoint_t *header) {
	memset(addr, 0, sizeof(*addr));

	switch (header->address_family) {
	case FASTD_DISCOVERY_AF_INET:
		addr->in.sin_family = AF_INET;
		addr->in.sin_port = header->port;
		memcpy(&addr->in.sin_addr, header->address, sizeof(addr->in.sin_addr));
		return true;

	case FASTD_DISCOVERY_AF_INET6:
		addr->in6.sin6_family = AF_INET6;
		addr->in6.sin6_port = header->port;
		memcpy(&addr->in6.sin6_addr, header->address, sizeof(addr->in6.sin6_addr));
		return true;

	default:
		return false;
	}
}

/** Sends one endpoint announcement to a relay client */
static void
send_endpoint_announce(fastd_peer_t *dest, fastd_peer_t *subject, const fastd_eth_addr_t *macs, size_t n_macs) {
	if (!conf.protocol->send_control || !conf.protocol->key_length || !conf.protocol->get_peer_key)
		return;

	size_t key_len = conf.protocol->key_length();
	if (key_len > UINT8_MAX)
		return;

	bool scoped = address_needs_scope_id(&subject->address);
	size_t header_len = sizeof(fastd_discovery_endpoint_t) + (scoped ? sizeof(uint32_t) : 0);
	size_t len = header_len + key_len + n_macs * sizeof(fastd_eth_addr_t);
	fastd_buffer_t *buffer = fastd_buffer_alloc(len, conf.encrypt_headroom);

	fastd_discovery_endpoint_t *header = buffer->data;
	*header = (fastd_discovery_endpoint_t){
		.version = scoped ? FASTD_DISCOVERY_VERSION_SCOPED : FASTD_DISCOVERY_VERSION,
		.type = FASTD_DISCOVERY_ENDPOINT,
		.key_len = key_len,
		.mac_count = n_macs,
	};

	if (!encode_address(header, &subject->address)) {
		fastd_buffer_free(buffer);
		return;
	}

	if (scoped && !encode_scope_id(buffer->data, len, &subject->address)) {
		fastd_buffer_free(buffer);
		return;
	}

	uint8_t *p = (uint8_t *)buffer->data + header_len;
	memcpy(p, conf.protocol->get_peer_key(subject), key_len);
	p += key_len;

	memcpy(p, macs, n_macs * sizeof(fastd_eth_addr_t));

	conf.protocol->send_control(dest, buffer);
}

/** Relay hook: announces a source peer endpoint to other peers */
void fastd_discovery_maybe_announce(fastd_peer_t *source, fastd_eth_addr_t source_mac) {
	if (!conf.peer_discovery || !conf.forward || conf.mode != MODE_TAP)
		return;

	if (fastd_peer_is_remote_passive(source) || !fastd_peer_is_established(source) ||
	    source->address.sa.sa_family == AF_UNSPEC)
		return;

	if (!fastd_timed_out(source->next_discovery_announce))
		return;

	fastd_eth_addr_t macs[FASTD_DISCOVERY_MAX_MACS];
	size_t n_macs = collect_macs(source, source_mac, macs);

	source->next_discovery_announce = ctx.now + FASTD_DISCOVERY_ANNOUNCE_INTERVAL;

	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
		fastd_peer_t *dest = VECTOR_INDEX(ctx.peers, i);

		if (dest == source || fastd_peer_is_remote_passive(dest) || !fastd_peer_is_established(dest))
			continue;

		send_endpoint_announce(dest, source, macs, n_macs);
	}
}

/** Returns true if a raw key belongs to this fastd instance or to the relay that sent the announcement */
static bool key_is_self_or_relay(fastd_peer_t *relay, const void *key, size_t key_len) {
	if (conf.protocol->get_own_key && !memcmp(conf.protocol->get_own_key(), key, key_len))
		return true;

	if (conf.protocol->get_peer_key && !memcmp(conf.protocol->get_peer_key(relay), key, key_len))
		return true;

	return false;
}

/** Handles a relay endpoint announcement received from an established peer */
void fastd_discovery_handle_control(fastd_peer_t *relay, fastd_buffer_t *buffer) {
	if (!conf.peer_discovery || fastd_peer_is_remote_passive(relay))
		goto end_free;

	if (buffer->len < sizeof(fastd_discovery_endpoint_t))
		goto end_free;

	const fastd_discovery_endpoint_t *header = buffer->data;
	if (header->type != FASTD_DISCOVERY_ENDPOINT)
		goto end_free;

	size_t header_len = endpoint_header_len(header);
	if (!header_len || buffer->len < header_len)
		goto end_free;

	if (!conf.protocol->key_length || !conf.protocol->find_peer_by_key_data)
		goto end_free;

	size_t key_len = conf.protocol->key_length();
	if (header->key_len != key_len)
		goto end_free;

	size_t expected = header_len + key_len + header->mac_count * sizeof(fastd_eth_addr_t);
	if (buffer->len != expected)
		goto end_free;

	const uint8_t *key = (const uint8_t *)buffer->data + header_len;
	if (key_is_self_or_relay(relay, key, key_len))
		goto end_free;

	fastd_peer_address_t remote_addr;
	if (!decode_address(&remote_addr, header))
		goto end_free;
	if (header->version == FASTD_DISCOVERY_VERSION_SCOPED)
		decode_scope_id(&remote_addr, buffer->data, header_len);

	fastd_peer_t *peer = conf.protocol->find_peer_by_key_data(key, key_len);
#ifdef WITH_DYNAMIC_PEERS
	if (!peer && conf.protocol->add_dynamic_peer_by_key_data)
		peer = conf.protocol->add_dynamic_peer_by_key_data(key, key_len);
#endif

	if (!peer || !fastd_peer_is_enabled(peer))
		goto end_free;

	const fastd_eth_addr_t *macs = (const fastd_eth_addr_t *)(key + key_len);
	fastd_peer_add_direct_candidate(peer, relay, &remote_addr, macs, header->mac_count);

end_free:
	fastd_buffer_free(buffer);
}

#ifdef WITH_TESTS

/** Test wrapper for endpoint discovery address encoding */
size_t fastd_discovery_test_encode_endpoint(void *out, size_t out_len, const fastd_peer_address_t *addr) {
	fastd_discovery_endpoint_t *header = out;
	bool scoped = address_needs_scope_id(addr);
	size_t len = sizeof(fastd_discovery_endpoint_t) + (scoped ? sizeof(uint32_t) : 0);

	if (out_len < len)
		return 0;

	memset(out, 0, len);
	*header = (fastd_discovery_endpoint_t){
		.version = scoped ? FASTD_DISCOVERY_VERSION_SCOPED : FASTD_DISCOVERY_VERSION,
		.type = FASTD_DISCOVERY_ENDPOINT,
	};

	if (!encode_address(header, addr))
		return 0;

	if (scoped && !encode_scope_id(out, len, addr))
		return 0;

	return len;
}

/** Test wrapper for endpoint discovery address decoding */
bool fastd_discovery_test_decode_endpoint(fastd_peer_address_t *addr, const void *data, size_t len) {
	if (len < sizeof(fastd_discovery_endpoint_t))
		return false;

	const fastd_discovery_endpoint_t *header = data;
	size_t header_len = endpoint_header_len(header);
	if (!header_len || len < header_len)
		return false;

	if (!decode_address(addr, header))
		return false;
	if (header->version == FASTD_DISCOVERY_VERSION_SCOPED)
		decode_scope_id(addr, data, header_len);

	return true;
}

#endif

/** Applies known direct MAC mappings after a direct peer session has been established */
void fastd_discovery_peer_established(fastd_peer_t *peer) {
	if (!conf.peer_discovery || !peer->direct_relay)
		return;

	size_t i;
	for (i = 0; i < VECTOR_LEN(peer->direct_macs); i++)
		fastd_peer_eth_addr_add(peer, VECTOR_INDEX(peer->direct_macs, i));
}

/** Clears relay pointers that would otherwise dangle after a peer is deleted */
void fastd_discovery_peer_deleted(fastd_peer_t *peer) {
	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
		fastd_peer_t *other = VECTOR_INDEX(ctx.peers, i);

		if (other->direct_relay == peer)
			other->direct_relay = NULL;

		for (size_t j = 0; j < VECTOR_LEN(other->direct_candidates);) {
			if (VECTOR_INDEX(other->direct_candidates, j).relay == peer)
				VECTOR_DELETE(other->direct_candidates, j);
			else
				j++;
		}
	}
}
