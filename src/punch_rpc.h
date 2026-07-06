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


#ifdef WITH_TESTS

size_t fastd_punch_test_build_endpoint_candidates(
	fastd_peer_address_t *out, size_t out_len, const fastd_peer_address_t *endpoint, fastd_nat_type_t nat_type,
	int port_delta, unsigned max_sockets, bool symmetric);
size_t fastd_punch_test_build_paired_endpoint_candidates(
	fastd_peer_address_t *out, size_t out_len, const fastd_peer_address_t *endpoint, fastd_nat_type_t nat_type,
	int port_delta, unsigned max_sockets, bool symmetric);

bool fastd_punch_test_parse_endpoint_message(const uint8_t *data, size_t len, uint8_t *type, size_t *key_len);

unsigned fastd_punch_test_udp_socket_count(fastd_peer_t *peer, fastd_nat_type_t remote_nat_type);
unsigned fastd_punch_test_udp_socket_count_for_nat(
	fastd_peer_t *peer, fastd_nat_type_t remote_nat_type, bool local_available, fastd_nat_type_t local_nat_type);
uint8_t
fastd_punch_test_endpoint_command_type(fastd_peer_t *dest, fastd_peer_t *subject, fastd_nat_type_t subject_nat_type);
bool fastd_punch_test_is_endpoint_command_type(uint8_t type);

#endif
