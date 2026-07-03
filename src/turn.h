// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   TURN relay helpers
*/


#pragma once

#include "fastd.h"


/** A configured TURN server */
struct fastd_turn_server {
	fastd_turn_server_t *next; /**< The next TURN server */

	char *host;     /**< The TURN server address */
	uint16_t port;  /**< The TURN server port */
	char *username; /**< The TURN username */
	char *password; /**< The TURN password */
};


void fastd_turn_server_add(
	fastd_turn_server_t **servers, const char *host, uint16_t port, const char *username, const char *password);
fastd_turn_server_t *fastd_turn_server_copy(const fastd_turn_server_t *servers);
bool fastd_turn_server_list_equal(const fastd_turn_server_t *a, const fastd_turn_server_t *b);
void fastd_turn_server_free(fastd_turn_server_t *servers);

bool fastd_turn_check(void);
void fastd_turn_handle_task(void);
bool fastd_turn_send(
	fastd_peer_t *peer, const fastd_socket_t *sock, const fastd_peer_address_t *local_addr,
	const fastd_peer_address_t *remote_addr, const fastd_buffer_t *buffer, size_t stat_size);
void fastd_turn_reset_peer(fastd_peer_t *peer);
void fastd_turn_cleanup(void);
