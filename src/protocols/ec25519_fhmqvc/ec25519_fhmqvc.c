// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   ec25519-fhmqvc protocol: basic functions
*/


#include "ec25519_fhmqvc.h"
#include "../../compression.h"
#include "../../crypto.h"
#include "../../discovery.h"


#define FASTD_ACTIVE_PATH_INITIAL_GRACE 2000


/** Converts a private or public key from a hexadecimal string representation to a uint8 array */
static inline bool read_key(uint8_t key[32], const char *hexkey) {
	if ((strlen(hexkey) != 64) || (strspn(hexkey, "0123456789abcdefABCDEF") != 64))
		return false;

	size_t i;
	for (i = 0; i < 32; i++)
		sscanf(&hexkey[2 * i], "%02hhx", &key[i]);

	return true;
}

/** Checks if a session with a peer needs refreshing */
static inline void check_session_refresh(fastd_peer_t *peer, protocol_session_t *session, bool backup_path) {
	if (!session->refreshing && session->method->provider->session_want_refresh(session->method_state)) {
		pr_verbose("refreshing %s session with %P", backup_path ? "backup" : "active", peer);
		session->handshakes_cleaned = true;
		session->refreshing = true;

		if (backup_path)
			fastd_peer_send_backup_handshake(peer);
		else
			fastd_peer_schedule_handshake(peer, 0);
	}
}

/** Initializes the protocol-specific configuration */
static fastd_protocol_config_t *protocol_init(void) {
	fastd_protocol_config_t *protocol_config = fastd_new(fastd_protocol_config_t);

	if (!conf.secret)
		exit_error("no secret key configured");

	if (!read_key(protocol_config->key.secret.p, conf.secret))
		exit_error("invalid secret key");

	ecc_25519_work_t work;
	ecc_25519_scalarmult_base(&work, &protocol_config->key.secret);
	ecc_25519_store_packed_legacy(&protocol_config->key.public.int256, &work);

	if (!divide_key(&protocol_config->key.secret))
		exit_error("invalid secret key");

	return protocol_config;
}

/** Parses a peer's key */
static fastd_protocol_key_t *protocol_read_key(const char *key) {
	fastd_protocol_key_t *ret = fastd_new(fastd_protocol_key_t);

	if (read_key(ret->key.u8, key)) {
		if (ecc_25519_load_packed_legacy(&ret->unpacked, &ret->key.int256)) {
			if (!ecc_25519_is_identity(&ret->unpacked))
				return ret;
		}
	}

	free(ret);
	return NULL;
}


/** Checks if a peer is configured using our own key */
static bool protocol_check_peer(const fastd_peer_t *peer) {
	if (memcmp(conf.protocol_config->key.public.u8, peer->key->key.u8, PUBLICKEYBYTES) == 0) {
		pr_verbose("found own key as %P, ignoring peer", peer);
		return false;
	}

	return true;
}

/** Resets a session, freeing method-specific state */
static void reset_protocol_session(protocol_session_t *session) {
	if (session->method)
		session->method->provider->session_free(session->method_state);
	secure_memzero(session, sizeof(*session));
}

/** Checks if a session with a peer is valid and resets the corresponding path if not */
static inline bool check_session(fastd_peer_t *peer, bool backup_path) {
	protocol_session_t *session =
		backup_path ? &peer->protocol_state->backup_session : &peer->protocol_state->session;

	if (is_session_valid(session))
		return true;

	if (backup_path) {
		pr_verbose("backup session with %P timed out", peer);
		fastd_protocol_ec25519_fhmqvc_drop_backup_path(peer);
	} else {
		pr_verbose("active session with %P timed out", peer);
		fastd_peer_reset(peer);
	}

	return false;
}

/** Determines if the old or the new session should be used for sending a packet */
static inline bool use_old_session(const fastd_protocol_peer_state_t *state) {
	if (!state->session.method->provider->session_is_initiator(state->session.method_state))
		return false;

	if (!is_session_valid(&state->old_session))
		return false;

	return true;
}

/** Sends a packet using a path-specific session */
static void session_send_path_flags(
	fastd_peer_t *peer, fastd_socket_t *sock, const fastd_peer_address_t *local_addr,
	const fastd_peer_address_t *remote_addr, fastd_buffer_t *buffer, protocol_session_t *session, uint8_t flags,
	size_t stat_size, bool backup_path) {
	if (!sock) {
		fastd_buffer_free(buffer);
		return;
	}

	if (flags && !(session->method->provider->flags & METHOD_SUPPORTS_CONTROL)) {
		fastd_buffer_free(buffer);
		return;
	}

	bool keepalive = !flags && !buffer->len;

	if (!flags && buffer->len && session->compression != COMPRESSION_NONE)
		buffer = fastd_compress_payload(buffer);

	fastd_buffer_zero_pad(buffer);

	fastd_buffer_t *send_buffer = session->method->provider->encrypt(session->method_state, buffer, flags);
	if (!send_buffer) {
		fastd_buffer_free(buffer);
		pr_error("failed to encrypt packet for %P", peer);
		return;
	}

	fastd_send(sock, local_addr, remote_addr, peer, send_buffer, stat_size);
	fastd_buffer_free(send_buffer);

	if (!keepalive && (fastd_peer_nat_traversal_keepalive_enabled(peer) ||
			   (session->method->provider->flags & METHOD_FORCE_KEEPALIVE)))
		return;

	if (backup_path)
		fastd_peer_clear_backup_keepalive(peer);
	else
		fastd_peer_clear_keepalive(peer);
}

/** Sends an empty payload packet (i.e. keepalive) to a backup path using a specified session */
static void send_backup_empty(fastd_peer_t *peer, protocol_session_t *session) {
	session_send_path_flags(
		peer, peer->backup_sock, &peer->backup_local_address, &peer->backup_address,
		fastd_buffer_alloc(0, alignto(session->method->provider->encrypt_headroom, 8)), session, 0, 0, true);
}

/** Sends bounded backup probes to inactive direct candidates */
static void send_backup_candidate_probes(fastd_peer_t *peer, protocol_session_t *session) {
	if (fastd_peer_has_verified_backup_path(peer) || !conf.punch_max_backups)
		return;

	fastd_socket_t *sock = peer->backup_sock ? peer->backup_sock : peer->sock;
	if (!sock)
		return;

	size_t sent = 0;
	size_t i;
	for (i = 0; i < VECTOR_LEN(peer->direct_candidates) && sent < conf.punch_max_backups; i++) {
		const fastd_peer_direct_candidate_t *candidate = &VECTOR_INDEX(peer->direct_candidates, i);

		if (candidate->remote.sa.sa_family == AF_UNSPEC || fastd_timed_out(candidate->timeout))
			continue;
		if (fastd_peer_address_equal(&candidate->remote, &peer->address) ||
		    fastd_peer_address_equal(&candidate->remote, &peer->backup_address))
			continue;

		session_send_path_flags(
			peer, sock, &peer->backup_local_address, &candidate->remote,
			fastd_buffer_alloc(0, alignto(session->method->provider->encrypt_headroom, 8)), session, 0, 0,
			true);
		sent++;
	}
}

/** Tries to decrypt a packet with the sessions of one transport path */
static bool decrypt_path_session(
	fastd_peer_t *peer, bool backup_path, fastd_buffer_t *buffer, fastd_buffer_t **recv_buffer,
	protocol_session_t **recv_session, bool *recv_current_session, bool *reordered, uint8_t *flags) {
	protocol_session_t *old_session =
		backup_path ? &peer->protocol_state->backup_old_session : &peer->protocol_state->old_session;
	protocol_session_t *session =
		backup_path ? &peer->protocol_state->backup_session : &peer->protocol_state->session;

	if (!is_session_valid(session))
		return false;

	*recv_buffer = NULL;
	*recv_session = NULL;
	*recv_current_session = false;
	*reordered = false;
	*flags = 0;

	if (is_session_valid(old_session)) {
		*recv_buffer =
			old_session->method->provider->decrypt(old_session->method_state, buffer, reordered, flags);
		if (*recv_buffer) {
			*recv_session = old_session;
			return true;
		}
	}

	*recv_buffer = session->method->provider->decrypt(session->method_state, buffer, reordered, flags);
	if (!*recv_buffer)
		return false;

	*recv_session = session;
	*recv_current_session = true;

	if (old_session->method) {
		pr_debug("invalidating old %s session with %P", backup_path ? "backup" : "active", peer);
		reset_protocol_session(old_session);
	}

	if (!session->handshakes_cleaned) {
		pr_debug("cleaning left %s handshakes with %P", backup_path ? "backup" : "active", peer);
		if (!backup_path)
			fastd_peer_unschedule_handshake(peer);
		session->handshakes_cleaned = true;

		if (session->method->provider->session_is_initiator(session->method_state)) {
			if (backup_path)
				send_backup_empty(peer, session);
			else
				fastd_protocol_ec25519_fhmqvc_send_empty(peer, session);
		}
	}

	check_session_refresh(peer, session, backup_path);
	return true;
}

/** Drops an established backup path */
void fastd_protocol_ec25519_fhmqvc_drop_backup_path(fastd_peer_t *peer) {
	if (peer->protocol_state) {
		reset_protocol_session(&peer->protocol_state->backup_old_session);
		reset_protocol_session(&peer->protocol_state->backup_session);
	}

	fastd_peer_clear_backup_path(peer);
}

/** Checks whether the active path is still within its verified health window */
static bool active_path_verified(const fastd_peer_t *peer) {
	return peer->active_path_timeout != FASTD_TIMEOUT_INV && !fastd_timed_out(peer->active_path_timeout);
}

/** Checks whether a newly established active path is still within its initial verification grace */
static bool active_path_initial_grace(const fastd_peer_t *peer) {
	return peer->active_path_timeout == FASTD_TIMEOUT_INV && peer->established &&
	       ctx.now < peer->established + FASTD_ACTIVE_PATH_INITIAL_GRACE;
}

/** Promotes an established backup path to the active path */
bool fastd_protocol_ec25519_fhmqvc_promote_backup_path(fastd_peer_t *peer) {
	if (!peer->protocol_state || !fastd_peer_has_backup_path(peer) || peer->offload ||
	    !is_session_valid(&peer->protocol_state->backup_session))
		return false;

	bool old_active_verified = active_path_verified(peer);
	bool backup_verified = fastd_peer_has_verified_backup_path(peer);
	bool backup_payload_candidate = fastd_peer_is_payload_candidate(peer, &peer->backup_address);
	if (fastd_peer_is_established(peer) && !backup_verified && (old_active_verified || !backup_payload_candidate))
		return false;

	bool was_established = fastd_peer_is_established(peer);
	protocol_session_t old_active_old_session = peer->protocol_state->old_session;
	protocol_session_t old_active_session = peer->protocol_state->session;
	protocol_session_t old_backup_old_session = peer->protocol_state->backup_old_session;
	protocol_session_t old_backup_session = peer->protocol_state->backup_session;

	if (!fastd_peer_promote_backup_path(peer))
		return false;

	peer->protocol_state->old_session = old_backup_old_session;
	peer->protocol_state->session = old_backup_session;
	peer->protocol_state->backup_old_session = old_active_old_session;
	peer->protocol_state->backup_session = old_active_session;

	reset_protocol_session(&peer->protocol_state->old_session);

	if (!old_active_verified) {
		reset_protocol_session(&peer->protocol_state->backup_old_session);
		reset_protocol_session(&peer->protocol_state->backup_session);
		fastd_peer_clear_backup_path(peer);
	}

	if (!was_established && !fastd_peer_set_established(peer, NULL)) {
		fastd_peer_reset(peer);
		return false;
	}

	if (was_established && is_session_valid(&peer->protocol_state->session))
		fastd_protocol_ec25519_fhmqvc_send_empty(peer, &peer->protocol_state->session);

	return true;
}

/** Sends a keepalive on an established backup path */
void fastd_protocol_ec25519_fhmqvc_send_backup_keepalive(fastd_peer_t *peer) {
	if (!peer->protocol_state || !fastd_peer_has_backup_path(peer) ||
	    !is_session_valid(&peer->protocol_state->backup_session)) {
		fastd_protocol_ec25519_fhmqvc_drop_backup_path(peer);
		return;
	}

	pr_debug2("sending backup keepalive to %P", peer);
	send_backup_empty(peer, &peer->protocol_state->backup_session);
	send_backup_candidate_probes(peer, &peer->protocol_state->backup_session);
}

/** Handles a payload packet received from a peer */
static void protocol_handle_recv(
	fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr,
	fastd_peer_t *peer, fastd_buffer_t *buffer) {
	if (!peer->protocol_state)
		goto fail;

	bool backup_path = fastd_peer_is_backup_path(peer, sock, local_addr, remote_addr);
	bool direct_candidate = fastd_peer_get_direct_candidate_source(peer, remote_addr, NULL);
	bool refresh_active_path = !backup_path;
	fastd_buffer_t *recv_buffer = NULL;
	protocol_session_t *recv_session = NULL;
	bool recv_current_session = false;
	bool reordered = false;
	uint8_t flags = 0;

	fastd_buffer_zero_pad(buffer);

	if (!decrypt_path_session(
		    peer, backup_path, buffer, &recv_buffer, &recv_session, &recv_current_session, &reordered,
		    &flags)) {
		if (direct_candidate && decrypt_path_session(
						peer, !backup_path, buffer, &recv_buffer, &recv_session,
						&recv_current_session, &reordered, &flags)) {
			backup_path = !backup_path;
			pr_debug2(
				"payload data from %P[%I] decrypted with alternate %s session", peer, remote_addr,
				backup_path ? "backup" : "active");
		} else {
			if (!check_session(peer, backup_path))
				goto fail;

			pr_debug2("verification failed for packet received from %P", peer);
			goto fail;
		}
	}

	if (!backup_path && (!fastd_peer_address_equal(&peer->local_address, local_addr) || peer->sock != sock) &&
	    fastd_peer_address_equal(&peer->address, remote_addr)) {
		if (!fastd_peer_claim_address(peer, sock, local_addr, remote_addr, true)) {
			fastd_buffer_free(recv_buffer);
			return;
		}
	}

	if (flags & ~FASTD_METHOD_FLAG_CONTROL) {
		pr_debug("ignoring packet with unknown method flags from %P", peer);
		fastd_buffer_free(recv_buffer);
		return;
	}

	if (backup_path && direct_candidate && recv_current_session &&
	    !fastd_peer_is_backup_path(peer, sock, local_addr, remote_addr)) {
		fastd_peer_note_payload_candidate(peer, remote_addr);
		pr_debug("payload data from %P[%I] decrypted on an alternate backup session", peer, remote_addr);

		bool active_path_unverified =
			!active_path_initial_grace(peer) &&
			(peer->active_path_timeout == FASTD_TIMEOUT_INV || fastd_timed_out(peer->active_path_timeout));
		bool active_path_failed = !fastd_peer_is_established(peer) || fastd_timed_out(peer->reset_timeout);

		if (!fastd_peer_claim_backup_path(peer, sock, local_addr, remote_addr)) {
			fastd_buffer_free(recv_buffer);
			return;
		}

		fastd_peer_backup_seen(peer);

		if ((active_path_unverified || active_path_failed) &&
		    fastd_protocol_ec25519_fhmqvc_promote_backup_path(peer)) {
			backup_path = false;
			recv_session = &peer->protocol_state->session;
		}
	}

	if (!backup_path && !fastd_peer_address_equal(&peer->address, remote_addr) && direct_candidate) {
		fastd_peer_note_payload_candidate(peer, remote_addr);
		pr_debug("payload data from %P[%I] decrypted on an inactive direct path", peer, remote_addr);

		bool active_path_unhealthy =
			(!active_path_initial_grace(peer) && peer->active_path_timeout == FASTD_TIMEOUT_INV) ||
			fastd_timed_out(peer->active_path_timeout) || !fastd_peer_is_established(peer) ||
			fastd_timed_out(peer->reset_timeout);

		if (active_path_unhealthy && !fastd_peer_has_verified_backup_path(peer)) {
			pr_debug("switching active path for %P to inactive direct path %I", peer, remote_addr);
			if (!fastd_peer_claim_address(peer, sock, local_addr, remote_addr, true)) {
				fastd_buffer_free(recv_buffer);
				return;
			}
		} else if (fastd_peer_has_verified_backup_path(peer)) {
			refresh_active_path = false;
		}
	}

	if (backup_path) {
		fastd_peer_backup_seen(peer);
	} else {
		fastd_peer_seen(peer);
		if (refresh_active_path)
			peer->active_path_timeout = ctx.now + (fastd_peer_nat_traversal_keepalive_enabled(peer)
								       ? conf.punch_keepalive_interval
								       : KEEPALIVE_TIMEOUT);
	}

	fastd_compression_algorithm_t compression = recv_session->compression;
	bool backup_payload = backup_path && recv_buffer->len && !(flags & FASTD_METHOD_FLAG_CONTROL) &&
			      fastd_peer_has_verified_backup_path(peer);
	bool active_path_unverified =
		peer->active_path_timeout == FASTD_TIMEOUT_INV && !active_path_initial_grace(peer);
	bool active_path_stale = !active_path_unverified && fastd_timed_out(peer->active_path_timeout);
	bool backup_should_promote =
		backup_path && (backup_payload || !fastd_peer_is_established(peer) ||
				fastd_timed_out(peer->reset_timeout) || active_path_unverified || active_path_stale);

	if (backup_should_promote) {
		if (!fastd_protocol_ec25519_fhmqvc_promote_backup_path(peer)) {
			fastd_buffer_free(recv_buffer);
			return;
		}

		backup_path = false;
	}

	if (flags & FASTD_METHOD_FLAG_CONTROL) {
		if (fastd_punch_handle_control(peer, recv_buffer))
			return;

		fastd_discovery_handle_control(peer, recv_buffer);
		return;
	}

	if (recv_buffer->len && compression != COMPRESSION_NONE) {
		recv_buffer = fastd_decompress_payload(recv_buffer, fastd_max_payload(fastd_peer_get_mtu(peer)));
		if (!recv_buffer)
			return;
	}

	if (recv_buffer->len)
		fastd_handle_receive(peer, recv_buffer, reordered);
	else
		fastd_buffer_free(recv_buffer);

	return;

fail:
	fastd_buffer_free(buffer);
}

/** Encrypts and sends a packet to a peer using a specified session */
static void session_send_flags(
	fastd_peer_t *peer, fastd_buffer_t *buffer, protocol_session_t *session, uint8_t flags, size_t stat_size) {
	session_send_path_flags(
		peer, peer->sock, &peer->local_address, &peer->address, buffer, session, flags, stat_size, false);
}

/** Encrypts and sends a packet to a peer using a specified session */
static void session_send(fastd_peer_t *peer, fastd_buffer_t *buffer, protocol_session_t *session) {
	session_send_flags(peer, buffer, session, 0, buffer->len);
}

/** Encrypts and sends a packet to a peer */
static void protocol_send(fastd_peer_t *peer, fastd_buffer_t *buffer) {
	if (!peer->protocol_state || !fastd_peer_is_established(peer) || !check_session(peer, false)) {
		fastd_buffer_free(buffer);
		return;
	}

	check_session_refresh(peer, &peer->protocol_state->session, false);

	if (use_old_session(peer->protocol_state)) {
		pr_debug2("sending packet for old session to %P", peer);
		session_send(peer, buffer, &peer->protocol_state->old_session);
	} else {
		session_send(peer, buffer, &peer->protocol_state->session);
	}
}

/** Sends an authenticated internal control packet to a peer */
static void protocol_send_control(fastd_peer_t *peer, fastd_buffer_t *buffer) {
	if (!peer->protocol_state || !fastd_peer_is_established(peer) || !check_session(peer, false)) {
		fastd_buffer_free(buffer);
		return;
	}

	session_send_flags(peer, buffer, &peer->protocol_state->session, FASTD_METHOD_FLAG_CONTROL, 0);
}

/** Sends an empty payload packet (i.e. keepalive) to a peer using a specified session */
void fastd_protocol_ec25519_fhmqvc_send_empty(fastd_peer_t *peer, protocol_session_t *session) {
	session_send(peer, fastd_buffer_alloc(0, alignto(session->method->provider->encrypt_headroom, 8)), session);
}

/** Returns the raw ec25519-fhmqvc public key length */
static size_t protocol_key_length(void) {
	return PUBLICKEYBYTES;
}

/** Returns our raw ec25519-fhmqvc public key */
static const void *protocol_get_own_key(void) {
	return conf.protocol_config->key.public.u8;
}

/** Returns a peer's raw ec25519-fhmqvc public key */
static const void *protocol_get_peer_key(const fastd_peer_t *peer) {
	return peer->key->key.u8;
}

/** Finds a peer by a raw ec25519-fhmqvc public key */
static fastd_peer_t *protocol_find_peer_by_key_data(const void *key, size_t len) {
	if (len != PUBLICKEYBYTES)
		return NULL;

	fastd_protocol_key_t peer_key;
	memcpy(peer_key.key.u8, key, PUBLICKEYBYTES);
	return fastd_protocol_ec25519_fhmqvc_find_peer(&peer_key);
}

#ifdef WITH_DYNAMIC_PEERS
/** Adds a dynamic peer for a raw ec25519-fhmqvc public key */
static fastd_peer_t *protocol_add_dynamic_peer_by_key_data(const void *key, size_t len) {
	if (len != PUBLICKEYBYTES)
		return NULL;

	fastd_protocol_key_t peer_key;
	memcpy(peer_key.key.u8, key, PUBLICKEYBYTES);

	if (!ecc_25519_load_packed_legacy(&peer_key.unpacked, &peer_key.key.int256) ||
	    ecc_25519_is_identity(&peer_key.unpacked))
		return NULL;

	fastd_peer_t *peer = fastd_new0(fastd_peer_t);
	peer->group = conf.peer_group;
	peer->config_state = CONFIG_DYNAMIC;
	peer->floating = true;

	peer->key = fastd_new(fastd_protocol_key_t);
	*peer->key = peer_key;

	if (!fastd_peer_add(peer))
		return NULL;

	fastd_peer_reset(peer);
	return peer;
}
#endif

/** get_current_method implementation for ec25519-fhmqvc */
const fastd_method_info_t *protocol_get_current_method(const fastd_peer_t *peer) {
	if (!peer->protocol_state || !fastd_peer_is_established(peer))
		return NULL;

	if (use_old_session(peer->protocol_state))
		return peer->protocol_state->old_session.method;
	else
		return peer->protocol_state->session.method;
}


/** The \em ec25519-fhmqvc protocol definition */
const fastd_protocol_t fastd_protocol_ec25519_fhmqvc = {
	.name = "ec25519-fhmqvc",

	.init = protocol_init,

	.handshake_init = fastd_protocol_ec25519_fhmqvc_handshake_init,
	.handshake_handle = fastd_protocol_ec25519_fhmqvc_handshake_handle,
#ifdef WITH_DYNAMIC_PEERS
	.handle_verify_return = fastd_protocol_ec25519_fhmqvc_handle_verify_return,
#endif

	.handle_recv = protocol_handle_recv,
	.send = protocol_send,
	.send_control = protocol_send_control,
	.promote_backup_path = fastd_protocol_ec25519_fhmqvc_promote_backup_path,
	.drop_backup_path = fastd_protocol_ec25519_fhmqvc_drop_backup_path,
	.send_backup_keepalive = fastd_protocol_ec25519_fhmqvc_send_backup_keepalive,

	.init_peer_state = fastd_protocol_ec25519_fhmqvc_init_peer_state,
	.reset_peer_state = fastd_protocol_ec25519_fhmqvc_reset_peer_state,
	.free_peer_state = fastd_protocol_ec25519_fhmqvc_free_peer_state,

	.read_key = protocol_read_key,
	.check_peer = protocol_check_peer,
	.find_peer = fastd_protocol_ec25519_fhmqvc_find_peer,
	.key_length = protocol_key_length,
	.get_own_key = protocol_get_own_key,
	.get_peer_key = protocol_get_peer_key,
	.find_peer_by_key_data = protocol_find_peer_by_key_data,
#ifdef WITH_DYNAMIC_PEERS
	.add_dynamic_peer_by_key_data = protocol_add_dynamic_peer_by_key_data,
#endif

	.get_current_method = protocol_get_current_method,

	.generate_key = fastd_protocol_ec25519_fhmqvc_generate_key,
	.show_key = fastd_protocol_ec25519_fhmqvc_show_key,

	.set_shell_env = fastd_protocol_ec25519_fhmqvc_set_shell_env,
	.describe_peer = fastd_protocol_ec25519_fhmqvc_describe_peer,
};
