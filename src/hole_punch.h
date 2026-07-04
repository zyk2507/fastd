// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Deterministic hole punching helpers
*/

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>


#define FASTD_HOLE_PUNCH_WINDOW 42
#define FASTD_HOLE_PUNCH_MAX_CLOCK_ERROR 20
#define FASTD_HOLE_PUNCH_NUM_PORTS 16
#define FASTD_HOLE_PUNCH_BUCKETS 3
#define FASTD_HOLE_PUNCH_BASE_PORT 30000
#define FASTD_HOLE_PUNCH_PORT_RANGE 20000
#define FASTD_HOLE_PUNCH_TIMEOUT 5000


/** Returns the time bucket shared by peers with reasonably synchronized clocks */
static inline int64_t fastd_hole_punch_bucket(time_t now) {
	return ((int64_t)now - FASTD_HOLE_PUNCH_MAX_CLOCK_ERROR) / FASTD_HOLE_PUNCH_WINDOW;
}

/** Mixes a bucket into a deterministic pseudo-random boundary */
static inline uint32_t fastd_hole_punch_boundary(int64_t bucket) {
	return (uint64_t)bucket * UINT32_C(2654435761) % UINT32_C(0xffffffff);
}

/** Returns the next deterministic pseudo-random value */
static inline uint32_t fastd_hole_punch_next(uint32_t *state) {
	*state = *state * UINT32_C(1664525) + UINT32_C(1013904223);
	return *state;
}

/** Returns true if a candidate port has already been generated */
static inline bool fastd_hole_punch_contains_port(const uint16_t *ports, size_t n_ports, uint16_t port) {
	size_t i;
	for (i = 0; i < n_ports; i++) {
		if (ports[i] == port)
			return true;
	}

	return false;
}

/** Generates deterministic punch ports for the current and adjacent buckets */
static inline size_t fastd_hole_punch_generate_ports(uint16_t *ports, size_t max_ports, time_t now) {
	size_t n_ports = 0;
	int64_t bucket = fastd_hole_punch_bucket(now) - 1;
	unsigned b;

	for (b = 0; b < FASTD_HOLE_PUNCH_BUCKETS && n_ports < max_ports; b++, bucket++) {
		uint32_t state = fastd_hole_punch_boundary(bucket) ^ UINT32_C(0x9e3779b9);
		size_t bucket_ports = 0;
		unsigned tries = 0;

		while (bucket_ports < FASTD_HOLE_PUNCH_NUM_PORTS && n_ports < max_ports && tries < 128) {
			uint16_t port = FASTD_HOLE_PUNCH_BASE_PORT
					+ fastd_hole_punch_next(&state) % FASTD_HOLE_PUNCH_PORT_RANGE;
			tries++;

			if (fastd_hole_punch_contains_port(ports, n_ports, port))
				continue;

			ports[n_ports++] = port;
			bucket_ports++;
		}
	}

	return n_ports;
}

/** Checks whether a port belongs to the deterministic punch set around the current time bucket */
static inline bool fastd_hole_punch_port_valid(uint16_t port, time_t now) {
	uint16_t ports[FASTD_HOLE_PUNCH_NUM_PORTS * FASTD_HOLE_PUNCH_BUCKETS];
	size_t n_ports = fastd_hole_punch_generate_ports(ports, sizeof(ports) / sizeof(ports[0]), now);

	return fastd_hole_punch_contains_port(ports, n_ports, port);
}
