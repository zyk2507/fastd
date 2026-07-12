// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Authenticated punch control RPC
*/

#pragma once

#include "fastd.h"
#include "peer.h"


#ifdef WITH_TESTS

typedef struct fastd_punch_test_pair_state {
	bool established;
	bool has_metadata_a;
	bool has_metadata_b;
	bool due_a;
	bool due_b;
	bool collected;
	bool waiting;
	bool demand_waiting;
	bool settled;
	bool in_flight;
	bool backoff;
	bool recent_demand;
	bool pending_demand;
	bool missing_metadata;
	bool unpunchable_metadata;
	fastd_timeout_t next_retry;
} fastd_punch_test_pair_state_t;

size_t fastd_punch_test_build_endpoint_candidates(
	fastd_peer_address_t *out, size_t out_len, const fastd_peer_address_t *endpoint, fastd_nat_type_t nat_type,
	int port_delta, unsigned max_sockets, bool symmetric);
size_t fastd_punch_test_build_paired_endpoint_candidates(
	fastd_peer_address_t *out, size_t out_len, const fastd_peer_address_t *endpoint, fastd_nat_type_t nat_type,
	int port_delta, unsigned max_sockets, bool symmetric);
size_t fastd_punch_test_build_hard_symmetric_endpoint_candidates(
	fastd_peer_address_t *out, size_t out_len, const fastd_peer_address_t *endpoint, unsigned max_sockets,
	uint32_t hard_sym_index, uint32_t *next_hard_sym_index, uint32_t *hard_sym_round);
size_t fastd_punch_test_build_hard_symmetric_range_endpoint_candidates(
	fastd_peer_address_t *out, size_t out_len, const fastd_peer_address_t *endpoint, uint16_t min_port,
	uint16_t max_port, unsigned max_sockets, uint32_t hard_sym_index, uint32_t *next_hard_sym_index,
	uint32_t *hard_sym_round);
size_t fastd_punch_test_build_multi_endpoint_candidates(
	fastd_peer_address_t *out, size_t out_len, const fastd_peer_address_t *endpoints, size_t n_endpoints,
	fastd_nat_type_t nat_type, int port_delta, unsigned max_sockets, bool symmetric);
size_t fastd_punch_test_build_punch_endpoint_candidates(
	fastd_peer_address_t *out, size_t out_len, fastd_peer_punch_endpoint_t *endpoints, size_t n_endpoints,
	unsigned max_sockets, bool symmetric, bool paired_easy_symmetric);

bool fastd_punch_test_parse_endpoint_message(
	const uint8_t *data, size_t len, uint8_t *type, size_t *key_len, uint16_t *packet_count);
bool fastd_punch_test_parse_endpoint_address(
	const uint8_t *data, size_t len, uint8_t *version, fastd_peer_address_t *endpoint);
bool fastd_punch_test_parse_result_ext_message(
	const uint8_t *data, size_t len, uint8_t *type, size_t *key_len, uint16_t *packet_count,
	uint8_t *command_type, uint16_t *udp_punch_sockets, uint32_t *hard_sym_port_index,
	uint32_t *hard_sym_next_port_index, uint32_t *hard_sym_round, uint32_t *wait_window_ms);
bool fastd_punch_test_parse_result_listener_message(
	const uint8_t *data, size_t len, uint8_t *type, size_t *key_len, uint16_t *packet_count,
	uint8_t *command_type, uint16_t *udp_punch_sockets, uint32_t *hard_sym_port_index,
	uint32_t *hard_sym_next_port_index, uint32_t *hard_sym_round, fastd_peer_address_t *base_mapped_endpoint,
	uint32_t *wait_window_ms, uint32_t *base_mapped_listener_id, bool *base_mapped_port_mapped);
bool fastd_punch_test_parse_listener_info_message(
	const uint8_t *data, size_t len, uint8_t *type, size_t *key_len, uint32_t *listener_id);
bool fastd_punch_test_parse_command_listener_message(
	const uint8_t *data, size_t len, uint8_t *type, size_t *key_len, uint16_t *packet_count,
	uint32_t *listener_id);
bool fastd_punch_test_mapped_endpoint_to_nat_info(
	const fastd_peer_address_t *mapped, fastd_peer_address_t *endpoint, fastd_nat_type_t *nat_type,
	uint16_t *min_port, uint16_t *max_port, int *port_delta);
bool fastd_punch_test_result_causes_relay_backoff(uint8_t result);

unsigned fastd_punch_test_udp_socket_count(fastd_peer_t *peer, fastd_nat_type_t remote_nat_type);
unsigned fastd_punch_test_udp_socket_count_for_nat(
	fastd_peer_t *peer, fastd_nat_type_t remote_nat_type, bool local_available, fastd_nat_type_t local_nat_type);
unsigned fastd_punch_test_udp_socket_count_for_command(
	fastd_peer_t *peer, uint8_t command_type, fastd_nat_type_t remote_nat_type, bool local_available,
	fastd_nat_type_t local_nat_type);
unsigned fastd_punch_test_udp_socket_count_for_request(
	fastd_peer_t *peer, uint8_t command_type, fastd_nat_type_t remote_nat_type, uint16_t requested_count);
unsigned fastd_punch_test_udp_socket_count_for_request_nat(
	fastd_peer_t *peer, uint8_t command_type, fastd_nat_type_t remote_nat_type, uint16_t requested_count,
	bool local_available, fastd_nat_type_t local_nat_type);
unsigned fastd_punch_test_relay_candidate_count(uint8_t command_type, size_t limit);
uint8_t
fastd_punch_test_endpoint_command_type(fastd_peer_t *dest, fastd_peer_t *subject, fastd_nat_type_t subject_nat_type);
bool fastd_punch_test_is_endpoint_command_type(uint8_t type);
bool fastd_punch_test_nat_status_needs_refresh(const fastd_nat_status_t *status);
bool fastd_punch_test_tcp_metadata_update_should_wake(
	const fastd_peer_t *peer, bool was_fresh, fastd_nat_type_t old_nat_type, fastd_nat_type_t new_nat_type);
fastd_punch_test_pair_state_t fastd_punch_test_pair_state(const fastd_peer_t *a, const fastd_peer_t *b);
void fastd_punch_test_pair_runtime_mark_launched(const fastd_peer_t *a, const fastd_peer_t *b);
void fastd_punch_test_relay_peer_endpoints(void);
void fastd_punch_test_task_manager_compact_pair_states(void);
void fastd_punch_test_task_manager_record_launch_result(
	size_t before_pair, size_t sent, size_t backoff_skipped, fastd_timeout_t backoff_next_retry);
void fastd_punch_test_task_manager_record_remote_result(uint8_t result);
void fastd_punch_test_task_manager_record_pair_task(
	const fastd_peer_t *a, const fastd_peer_t *b, const fastd_peer_t *subject, const fastd_peer_t *destination,
	fastd_punch_pair_task_stage_t stage, size_t candidates_sent, size_t backoff_skipped,
	fastd_timeout_t next_retry, bool budget_exhausted);
void fastd_punch_test_task_manager_record_pair_result(
	fastd_peer_t *sender, fastd_peer_t *subject, uint8_t result, const fastd_peer_address_t *endpoint);
bool fastd_punch_test_handle_remote_result(
	fastd_peer_t *sender, fastd_peer_t *subject, uint8_t result, uint8_t command_type,
	const fastd_peer_address_t *endpoint);
void fastd_punch_test_refresh_observed_peer_punch_metadata(fastd_peer_t *peer);

#endif
