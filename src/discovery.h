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
