// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Payload compression support
*/


#include "compression.h"


#ifdef WITH_ZSTD
#include <zstd.h>
#endif


/** Marker for an uncompressed payload in a compressed session */
#define FASTD_COMPRESSION_PACKET_PLAIN 0
/** Marker for a zstd-compressed payload in a compressed session */
#define FASTD_COMPRESSION_PACKET_ZSTD 1


/** Configures payload compression as disabled */
void fastd_config_compression_none(void) {
	conf.compression.algorithm = COMPRESSION_NONE;
}

/** Configures zstd payload compression */
void fastd_config_compression_zstd(int level) {
	conf.compression.algorithm = COMPRESSION_ZSTD;
	conf.compression.level = level;
}

/** Checks if the configured compression mode is supported */
bool fastd_compression_check(void) {
	switch (conf.compression.algorithm) {
	case COMPRESSION_NONE:
		return true;

	case COMPRESSION_ZSTD:
#ifdef WITH_ZSTD
		return true;
#else
		pr_error("config error: zstd compression is not supported by this build of fastd");
		return false;
#endif

	default:
		exit_bug("invalid compression algorithm");
	}
}

/** Returns the wire name of a compression algorithm */
const char *fastd_compression_get_name(fastd_compression_algorithm_t algorithm) {
	switch (algorithm) {
	case COMPRESSION_NONE:
		return "none";

	case COMPRESSION_ZSTD:
		return "zstd";

	default:
		exit_bug("invalid compression algorithm");
	}
}

/** Returns the compression algorithm named by a handshake record */
fastd_compression_algorithm_t fastd_compression_get_by_name(const char *name, size_t len) {
	if (len == 4 && !memcmp(name, "zstd", 4))
		return COMPRESSION_ZSTD;

	if (len == 4 && !memcmp(name, "none", 4))
		return COMPRESSION_NONE;

	return COMPRESSION_NONE;
}

#ifdef WITH_ZSTD

/** Adds an uncompressed payload marker to a buffer */
static fastd_buffer_t *mark_plain(fastd_buffer_t *buffer) {
	fastd_buffer_t *out = fastd_buffer_alloc(buffer->len + 1, conf.encrypt_headroom);

	((uint8_t *)out->data)[0] = FASTD_COMPRESSION_PACKET_PLAIN;
	memcpy(out->data + 1, buffer->data, buffer->len);

	fastd_buffer_free(buffer);

	return out;
}

/** Compresses payload data with zstd */
fastd_buffer_t *fastd_compress_payload(fastd_buffer_t *buffer) {
	if (!buffer->len)
		return buffer;

	size_t bound = ZSTD_compressBound(buffer->len);
	uint8_t *compressed = fastd_alloc(bound);

	size_t len = ZSTD_compress(compressed, bound, buffer->data, buffer->len, conf.compression.level);

	if (ZSTD_isError(len) || len + 1 >= buffer->len + 1) {
		free(compressed);
		return mark_plain(buffer);
	}

	fastd_buffer_t *out = fastd_buffer_alloc(len + 1, conf.encrypt_headroom);
	((uint8_t *)out->data)[0] = FASTD_COMPRESSION_PACKET_ZSTD;
	memcpy(out->data + 1, compressed, len);
	out->len = len + 1;

	free(compressed);
	fastd_buffer_free(buffer);

	return out;
}

/** Decompresses payload data with zstd */
fastd_buffer_t *fastd_decompress_payload(fastd_buffer_t *buffer, size_t max_payload) {
	if (!buffer->len) {
		pr_debug("received compressed session packet without compression marker");
		goto fail;
	}

	uint8_t packet_type;
	fastd_buffer_pull_to(buffer, &packet_type, 1);

	if (packet_type == FASTD_COMPRESSION_PACKET_PLAIN)
		return buffer;

	if (packet_type != FASTD_COMPRESSION_PACKET_ZSTD) {
		pr_debug("received compressed session packet with unknown compression marker");
		goto fail;
	}

	unsigned long long decompressed_len = ZSTD_getFrameContentSize(buffer->data, buffer->len);
	if (decompressed_len == ZSTD_CONTENTSIZE_ERROR || decompressed_len == ZSTD_CONTENTSIZE_UNKNOWN ||
	    decompressed_len > max_payload) {
		pr_debug("received invalid zstd-compressed payload");
		goto fail;
	}

	fastd_buffer_t *out = fastd_buffer_alloc(decompressed_len, conf.encrypt_headroom);
	size_t len = ZSTD_decompress(out->data, decompressed_len, buffer->data, buffer->len);

	if (ZSTD_isError(len) || len != decompressed_len) {
		pr_debug("failed to decompress zstd-compressed payload");
		fastd_buffer_free(out);
		goto fail;
	}

	fastd_buffer_free(buffer);
	return out;

fail:
	fastd_buffer_free(buffer);
	return NULL;
}

#else

/** Compression stub for builds without zstd */
fastd_buffer_t *fastd_compress_payload(fastd_buffer_t *buffer) {
	return buffer;
}

/** Decompression stub for builds without zstd */
fastd_buffer_t *fastd_decompress_payload(fastd_buffer_t *buffer, UNUSED size_t max_payload) {
	fastd_buffer_free(buffer);
	return NULL;
}

#endif
