// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Relay-assisted peer endpoint discovery
*/

#pragma once

#include "fastd.h"


void fastd_discovery_handle_control(fastd_peer_t *relay, fastd_buffer_t *buffer);
void fastd_discovery_maybe_announce(fastd_peer_t *source, fastd_eth_addr_t source_mac);
void fastd_discovery_peer_established(fastd_peer_t *peer);
void fastd_discovery_peer_deleted(fastd_peer_t *peer);

#ifdef WITH_TESTS
size_t fastd_discovery_test_encode_endpoint(void *out, size_t out_len, const fastd_peer_address_t *addr);
bool fastd_discovery_test_decode_endpoint(fastd_peer_address_t *addr, const void *data, size_t len);
#endif
