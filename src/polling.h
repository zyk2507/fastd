// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Portable polling API
*/


#pragma once


#include "types.h"


/** A file descriptor to poll on */
struct fastd_poll_fd {
	fastd_poll_type_t type; /**< What the file descriptor is used for */
	int fd;                 /**< The file descriptor itself */
	bool write;             /**< Whether write readiness should be polled */
};


/** Initializes the poll interface */
void fastd_poll_init(void);
/** Frees the poll interface */
void fastd_poll_free(void);

/** Returns a fastd_poll_fd_t structure */
#define FASTD_POLL_FD(poll_type, poll_fd) ((fastd_poll_fd_t){ .type = (poll_type), .fd = (poll_fd) })

/** Registers a new file descriptor to poll on */
void fastd_poll_fd_register(fastd_poll_fd_t *fd);
/** Enables or disables write readiness polling for a file descriptor */
void fastd_poll_fd_set_write(fastd_poll_fd_t *fd, bool write);
/** Unregisters and closes a file descriptor */
bool fastd_poll_fd_close(fastd_poll_fd_t *fd);

/** Waits for the next input event */
void fastd_poll_handle(void);
