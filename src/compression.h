// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Payload compression support
*/


#pragma once

#include "fastd.h"


/** Maximum per-packet overhead added by the compression framing */
#define FASTD_COMPRESSION_MAX_OVERHEAD 1


void fastd_config_compression_none(void);
void fastd_config_compression_zstd(int level);

bool fastd_compression_check(void);

const char *fastd_compression_get_name(fastd_compression_algorithm_t algorithm);
fastd_compression_algorithm_t fastd_compression_get_by_name(const char *name, size_t len);

fastd_buffer_t *fastd_compress_payload(fastd_buffer_t *buffer);
fastd_buffer_t *fastd_decompress_payload(fastd_buffer_t *buffer, size_t max_payload);
