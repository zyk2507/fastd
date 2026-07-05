// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   External rendezvous support for peer hole punching
*/

#pragma once

#include "fastd.h"


void fastd_realm_add_candidate(
	const char *source_id, const char *source_key, const fastd_peer_address_t *addresses, size_t n_addresses);
bool fastd_realm_handle_stun_response(const fastd_peer_address_t *remote_addr, const void *data, size_t len);
