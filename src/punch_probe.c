// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Dedicated UDP punch probe packets
*/

#include "fastd.h"
#include "handshake.h"
#include "peer.h"
#include "peer_hashtable.h"


#define FASTD_PUNCH_PROBE_VERSION 1
#define FASTD_PUNCH_PROBE_REQUEST 1
#define FASTD_PUNCH_PROBE_RESPONSE 2

static const uint8_t fastd_punch_probe_magic[4] = { 'f', 'p', 'u', 'p' };


/** Dedicated UDP punch probe header */
typedef struct __attribute__((packed)) fastd_punch_probe_header {
	uint8_t magic[4];     /**< Packet discriminator */
	uint8_t version;      /**< Probe protocol version */
	uint8_t type;         /**< FASTD_PUNCH_PROBE_* type */
	uint16_t length;      /**< Total message length, network byte order */
	uint32_t transaction; /**< Per-socket punch transaction ID, network byte order */
	uint8_t key_len;      /**< Length of the sender key following this header */
	uint8_t reserved[3];  /**< Reserved for alignment and future extensions */
} fastd_punch_probe_header_t;


/** Returns the sockaddr length for a peer address */
static socklen_t address_len(const fastd_peer_address_t *addr) {
	switch (addr->sa.sa_family) {
	case AF_INET:
		return sizeof(struct sockaddr_in);

	case AF_INET6:
		return sizeof(struct sockaddr_in6);

	default:
		return 0;
	}
}

/** Returns true when a socket can carry UDP probe packets */
static bool probe_socket_usable(const fastd_socket_t *sock, const fastd_peer_address_t *remote_addr) {
	return sock && sock->type == SOCKET_TYPE_UDP && sock->fd.fd >= 0 &&
	       (remote_addr->sa.sa_family == AF_INET || remote_addr->sa.sa_family == AF_INET6);
}

/** Parses a UDP punch probe packet */
static bool parse_probe(
	const uint8_t *data, size_t len, uint8_t *type, uint32_t *transaction, const uint8_t **key, size_t *key_len) {
	if (len < sizeof(fastd_punch_probe_header_t))
		return false;

	const fastd_punch_probe_header_t *header = (const fastd_punch_probe_header_t *)data;
	if (memcmp(header->magic, fastd_punch_probe_magic, sizeof(header->magic)))
		return false;

	size_t packet_len = be16toh(header->length);
	if (header->version != FASTD_PUNCH_PROBE_VERSION || packet_len != len)
		return false;

	if (header->type != FASTD_PUNCH_PROBE_REQUEST && header->type != FASTD_PUNCH_PROBE_RESPONSE)
		return false;

	size_t parsed_key_len = header->key_len;
	if (packet_len != sizeof(*header) + parsed_key_len)
		return false;

	if (type)
		*type = header->type;
	if (transaction)
		*transaction = be32toh(header->transaction);
	if (key)
		*key = data + sizeof(*header);
	if (key_len)
		*key_len = parsed_key_len;

	return true;
}

/** Finds the peer identified by a probe sender key */
static fastd_peer_t *find_probe_peer(const uint8_t *key, size_t key_len) {
	if (!conf.protocol->key_length || !conf.protocol->get_own_key || !conf.protocol->find_peer_by_key_data)
		return NULL;

	size_t local_key_len = conf.protocol->key_length();
	if (key_len != local_key_len)
		return NULL;

	if (!memcmp(conf.protocol->get_own_key(), key, key_len))
		return NULL;

	fastd_peer_t *peer = conf.protocol->find_peer_by_key_data(key, key_len);
	if (!peer || !fastd_peer_is_enabled(peer))
		return NULL;

	return peer;
}

/** Returns true if two addresses have the same address family and IP address */
static bool address_ip_equal(const fastd_peer_address_t *addr1, const fastd_peer_address_t *addr2) {
	if (addr1->sa.sa_family != addr2->sa.sa_family)
		return false;

	switch (addr1->sa.sa_family) {
	case AF_INET:
		return addr1->in.sin_addr.s_addr == addr2->in.sin_addr.s_addr;

	case AF_INET6:
		return !memcmp(&addr1->in6.sin6_addr, &addr2->in6.sin6_addr, sizeof(addr1->in6.sin6_addr));

	default:
		return false;
	}
}

/** Returns true if a NAT type can produce multiple public ports for one peer IP during punching */
static bool endpoint_dependent_nat(fastd_nat_type_t nat_type) {
	return nat_type == FASTD_NAT_SYMMETRIC || nat_type == FASTD_NAT_SYMMETRIC_EASY_INC ||
	       nat_type == FASTD_NAT_SYMMETRIC_EASY_DEC;
}

/** Returns true if a probe source matches a punch-control candidate by IP for endpoint-dependent NATs */
static bool probe_source_matches_candidate_ip(const fastd_peer_t *peer, const fastd_peer_address_t *remote_addr) {
	if (!endpoint_dependent_nat(peer->punch_nat_type) || fastd_timed_out(peer->punch_timeout))
		return false;

	size_t i;
	for (i = 0; i < VECTOR_LEN(peer->direct_candidates); i++) {
		const fastd_peer_direct_candidate_t *candidate = &VECTOR_INDEX(peer->direct_candidates, i);
		if (candidate->source != DIRECT_CANDIDATE_PUNCH_CONTROL || candidate->remote.sa.sa_family == AF_UNSPEC ||
		    fastd_timed_out(candidate->timeout))
			continue;

		if (candidate->transports && !(candidate->transports & DIRECT_CANDIDATE_TRANSPORT_UDP))
			continue;

		if (address_ip_equal(&candidate->remote, remote_addr))
			return true;
	}

	return false;
}

/** Returns true if a probe source is tied to the peer through an existing path or direct candidate */
static bool probe_source_allowed(
	const fastd_peer_t *peer, const fastd_socket_t *sock, const fastd_peer_address_t *local_addr,
	const fastd_peer_address_t *remote_addr) {
	if (sock->peer)
		return sock->peer == peer && (fastd_peer_address_equal(&peer->address, remote_addr) ||
					      fastd_peer_is_backup_path(peer, sock, local_addr, remote_addr) ||
					      fastd_peer_get_direct_candidate_source_transport(
						      peer, remote_addr, TRANSPORT_UDP, NULL));

	if (sock->hole_punch_peer)
		return sock->hole_punch_peer == peer &&
		       (fastd_peer_address_equal(&sock->peer_addr, remote_addr) ||
			fastd_peer_get_direct_candidate_source_transport(peer, remote_addr, TRANSPORT_UDP, NULL));

	if (fastd_peer_hashtable_lookup(remote_addr) == peer)
		return true;

	if (fastd_peer_find_backup_path(sock, local_addr, remote_addr) == peer)
		return true;

	if (fastd_peer_get_direct_candidate_source_transport(peer, remote_addr, TRANSPORT_UDP, NULL))
		return true;

	if (probe_source_matches_candidate_ip(peer, remote_addr))
		return true;

	return !fastd_peer_is_floating(peer) && fastd_peer_matches_address(peer, remote_addr);
}

/** Builds and sends one probe packet */
static bool
send_probe_packet(fastd_socket_t *sock, const fastd_peer_address_t *remote_addr, uint8_t type, uint32_t transaction) {
	if (!probe_socket_usable(sock, remote_addr) || !conf.protocol->key_length || !conf.protocol->get_own_key)
		return false;

	size_t key_len = conf.protocol->key_length();
	if (key_len > UINT8_MAX)
		return false;

	uint8_t buf[sizeof(fastd_punch_probe_header_t) + UINT8_MAX];
	size_t len = sizeof(fastd_punch_probe_header_t) + key_len;

	fastd_punch_probe_header_t *header = (fastd_punch_probe_header_t *)buf;
	memcpy(header->magic, fastd_punch_probe_magic, sizeof(header->magic));
	header->version = FASTD_PUNCH_PROBE_VERSION;
	header->type = type;
	header->length = htobe16(len);
	header->transaction = htobe32(transaction);
	header->key_len = key_len;
	memset(header->reserved, 0, sizeof(header->reserved));
	memcpy(header + 1, conf.protocol->get_own_key(), key_len);

	ssize_t ret = sendto(sock->fd.fd, buf, len, 0, &remote_addr->sa, address_len(remote_addr));
	if (ret < 0) {
		pr_debug2_errno("UDP punch probe sendto");
		return false;
	}

	if (type == FASTD_PUNCH_PROBE_RESPONSE)
		ctx.punch_probe_response_tx++;
	else
		ctx.punch_probe_tx++;

	return true;
}

/** Sends a rate-limited handshake after a probe proves that packets traverse the path */
static bool send_probe_handshake(
	fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr,
	fastd_peer_t *peer) {
	if (!fastd_peer_transport_allows(fastd_peer_get_transport(peer), TRANSPORT_UDP))
		return false;

	if (!fastd_peer_may_connect(peer))
		return false;

	if (!fastd_timed_out(peer->last_handshake_timeout) &&
	    fastd_peer_address_equal(remote_addr, &peer->last_handshake_address))
		return false;

	peer->last_handshake_timeout = ctx.now + MIN_HANDSHAKE_INTERVAL;
	peer->last_handshake_address = *remote_addr;
	conf.protocol->handshake_init(sock, local_addr, remote_addr, peer, FLAG_INITIAL);

	if (!fastd_peer_is_established(peer))
		peer->state = STATE_HANDSHAKE;

	ctx.punch_probe_handshakes++;
	return true;
}

/** Initializes a UDP punch socket's transaction ID */
void fastd_punch_probe_init_socket(fastd_socket_t *sock) {
	if (!sock || sock->type != SOCKET_TYPE_UDP)
		return;

	do {
		fastd_random_bytes(&sock->punch_transaction_id, sizeof(sock->punch_transaction_id), false);
	} while (!sock->punch_transaction_id);
}

/** Sends one UDP punch probe request */
bool fastd_punch_probe_send(fastd_socket_t *sock, const fastd_peer_address_t *remote_addr) {
	if (!probe_socket_usable(sock, remote_addr))
		return false;

	if (!sock->punch_transaction_id)
		fastd_punch_probe_init_socket(sock);

	return send_probe_packet(sock, remote_addr, FASTD_PUNCH_PROBE_REQUEST, sock->punch_transaction_id);
}

/** Handles a UDP punch probe packet. Returns true if the buffer was consumed. */
bool fastd_punch_probe_handle(
	fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr,
	const uint8_t *data, size_t len) {
	uint8_t type;
	uint32_t transaction;
	const uint8_t *key;
	size_t key_len;

	if (!parse_probe(data, len, &type, &transaction, &key, &key_len)) {
		if (len >= sizeof(fastd_punch_probe_magic) &&
		    !memcmp(data, fastd_punch_probe_magic, sizeof(fastd_punch_probe_magic))) {
			pr_debug("ignoring malformed UDP punch probe from %I", remote_addr);
			return true;
		}

		return false;
	}

	ctx.punch_probe_rx++;

	fastd_peer_t *peer = find_probe_peer(key, key_len);
	if (!peer || !probe_source_allowed(peer, sock, local_addr, remote_addr)) {
		pr_debug("ignoring UDP punch probe from %I without a matching peer path", remote_addr);
		return true;
	}

	if (type == FASTD_PUNCH_PROBE_RESPONSE) {
		if (!sock->hole_punch || !sock->punch_transaction_id || sock->punch_transaction_id != transaction) {
			pr_debug("ignoring unmatched UDP punch probe response from %P[%I]", peer, remote_addr);
			return true;
		}

		ctx.punch_probe_matched++;
		fastd_peer_note_probe_candidate(peer, remote_addr);
		send_probe_handshake(sock, local_addr, remote_addr, peer);
		return true;
	}

	if (send_probe_packet(sock, remote_addr, FASTD_PUNCH_PROBE_RESPONSE, transaction) &&
	    endpoint_dependent_nat(peer->punch_nat_type)) {
		fastd_peer_note_probe_candidate(peer, remote_addr);
		send_probe_handshake(sock, local_addr, remote_addr, peer);
	}

	return true;
}

#ifdef WITH_TESTS

/** Test wrapper for UDP punch probe parsing */
bool fastd_punch_probe_test_parse(
	const uint8_t *data, size_t len, uint8_t *type, uint32_t *transaction, size_t *key_len) {
	const uint8_t *key;
	return parse_probe(data, len, type, transaction, &key, key_len);
}

/** Test wrapper for UDP punch probe packet construction */
size_t fastd_punch_probe_test_build(uint8_t *out, size_t out_len, uint8_t type, uint32_t transaction, size_t key_len) {
	if (key_len > UINT8_MAX)
		return 0;

	size_t len = sizeof(fastd_punch_probe_header_t) + key_len;
	if (out_len < len)
		return 0;

	fastd_punch_probe_header_t *header = (fastd_punch_probe_header_t *)out;
	memcpy(header->magic, fastd_punch_probe_magic, sizeof(header->magic));
	header->version = FASTD_PUNCH_PROBE_VERSION;
	header->type = type;
	header->length = htobe16(len);
	header->transaction = htobe32(transaction);
	header->key_len = key_len;
	memset(header->reserved, 0, sizeof(header->reserved));
	memset(header + 1, 0xa5, key_len);

	return len;
}

#endif
