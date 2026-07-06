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
	int port_delta, unsigned max_sockets, bool symmetric, bool hard_symmetric);

bool fastd_punch_test_parse_endpoint_message(const uint8_t *data, size_t len, uint8_t *type, size_t *key_len);

#endif
