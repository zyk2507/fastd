// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

#include "nat_detect.h"
#include "method.h"
#include "peer.h"
#include "peer_hashtable.h"
#include "hole_punch.h"
#include "punch_rpc.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/socket.h>

#include <cmocka.h>

#ifdef WITH_STATUS_SOCKET
#include <json-c/json.h>
#endif


#define FASTD_PUNCH_TEST_HARD_SYM_PORT_SPACE 65535U
#define FASTD_PUNCH_TEST_HARD_SYM_LAST_INDEX (FASTD_PUNCH_TEST_HARD_SYM_PORT_SPACE - 1)

typedef struct __attribute__((packed)) test_punch_header {
	uint8_t magic[4];
	uint8_t version;
	uint8_t type;
	uint16_t length;
} test_punch_header_t;

typedef struct __attribute__((packed)) test_punch_endpoint {
	uint8_t key_len;
	uint8_t nat_type;
	uint8_t address_family;
	uint8_t reserved;
	uint16_t port;
	uint16_t min_port;
	uint16_t max_port;
	int16_t port_delta;
	uint16_t packet_count;
	uint8_t address[16];
} test_punch_endpoint_t;

typedef struct __attribute__((packed)) test_punch_result_ext {
	uint8_t command_type;
	uint8_t reserved;
	uint16_t udp_punch_sockets;
	uint32_t hard_sym_port_index;
	uint32_t hard_sym_next_index;
	uint32_t hard_sym_round;
	uint32_t wait_window_ms;
} test_punch_result_ext_t;

typedef struct __attribute__((packed)) test_punch_address {
	uint8_t address_family;
	uint8_t flags;
	uint16_t port;
	uint8_t address[16];
} test_punch_address_t;

typedef struct __attribute__((packed)) test_punch_result_listener {
	test_punch_result_ext_t result;
	uint32_t listener_id;
	test_punch_address_t base_mapped_addr;
} test_punch_result_listener_t;

typedef struct __attribute__((packed)) test_punch_listener_info {
	uint32_t listener_id;
} test_punch_listener_info_t;

typedef struct __attribute__((packed)) test_punch_command_listener {
	uint32_t listener_id;
} test_punch_command_listener_t;

typedef struct __attribute__((packed)) test_punch_message {
	test_punch_header_t header;
	test_punch_endpoint_t endpoint;
	uint8_t key[4];
} test_punch_message_t;

typedef struct __attribute__((packed)) test_punch_result_ext_message {
	test_punch_header_t header;
	test_punch_endpoint_t endpoint;
	test_punch_result_ext_t ext;
	uint8_t key[4];
} test_punch_result_ext_message_t;

typedef struct __attribute__((packed)) test_punch_result_listener_message {
	test_punch_header_t header;
	test_punch_endpoint_t endpoint;
	test_punch_result_listener_t listener;
	uint8_t key[4];
} test_punch_result_listener_message_t;

typedef struct __attribute__((packed)) test_punch_listener_info_message {
	test_punch_header_t header;
	test_punch_endpoint_t endpoint;
	test_punch_listener_info_t listener;
	uint8_t key[4];
} test_punch_listener_info_message_t;

typedef struct __attribute__((packed)) test_punch_command_listener_message {
	test_punch_header_t header;
	test_punch_endpoint_t endpoint;
	test_punch_command_listener_t listener;
	uint8_t key[4];
} test_punch_command_listener_message_t;

enum {
	TEST_PUNCH_NAT_INFO = 1,
	TEST_PUNCH_PROBE_REQUEST = 1,
	TEST_PUNCH_PROBE_RESPONSE = 2,
	TEST_PUNCH_SEND_CONE = 2,
	TEST_PUNCH_RESULT = 3,
	TEST_PUNCH_SEND_EASY_SYM = 4,
	TEST_PUNCH_SEND_HARD_SYM = 5,
	TEST_PUNCH_BOTH_EASY_SYM = 6,
	TEST_PUNCH_TCP_NAT_INFO = 7,
	TEST_PUNCH_SEND_TCP = 8,
	TEST_PUNCH_RESULT_EXT = 9,
	TEST_PUNCH_RESULT_LISTENER = 10,
	TEST_PUNCH_SELECT_LISTENER = 11,
	TEST_PUNCH_LISTENER_INFO = 12,
	TEST_PUNCH_NAT_INFO_EXTRA = 13,
	TEST_PUNCH_TCP_NAT_INFO_EXTRA = 14,
};

enum {
	TEST_PUNCH_NAT_INFO_RELAYED = 1u << 0,
	TEST_PUNCH_ADDRESS_AVAILABLE = 1u << 0,
	TEST_PUNCH_ADDRESS_PORT_MAPPED = 1u << 1,
};

enum {
	TEST_PUNCH_RESULT_ACCEPTED = 1,
	TEST_PUNCH_RESULT_HANDSHAKE = 2,
	TEST_PUNCH_RESULT_SUPPRESSED = 3,
	TEST_PUNCH_RESULT_NO_PEER = 4,
	TEST_PUNCH_RESULT_BUSY = 5,
};

#define TEST_CONTROL_HISTORY 32

static fastd_peer_t *test_send_peer;
static size_t test_send_count;
static size_t test_handshake_count;
static fastd_peer_t *test_handshake_peer;
static fastd_peer_transport_t test_handshake_transport;
static fastd_peer_address_t test_handshake_remote;
static fastd_peer_t *test_control_send_peer;
static size_t test_control_send_count;
static uint8_t test_control_last_type;
static fastd_peer_t *test_control_send_peers[TEST_CONTROL_HISTORY];
static uint8_t test_control_send_types[TEST_CONTROL_HISTORY];
static uint16_t test_control_send_ports[TEST_CONTROL_HISTORY];
static fastd_peer_t *test_lookup_peer;
static const uint8_t test_key_self[32] = { 9 };
static const uint8_t test_key_a[32] = { 1 };
static const uint8_t test_key_b[32] = { 2 };
static const fastd_method_info_t test_control_method = {
	.provider = &(const fastd_method_provider_t){
		.flags = METHOD_SUPPORTS_CONTROL,
	},
};

static void test_reset_control_sends(void) {
	test_control_send_peer = NULL;
	test_control_send_count = 0;
	test_control_last_type = 0;
	memset(test_control_send_peers, 0, sizeof(test_control_send_peers));
	memset(test_control_send_types, 0, sizeof(test_control_send_types));
	memset(test_control_send_ports, 0, sizeof(test_control_send_ports));
}

static void test_protocol_send(fastd_peer_t *peer, fastd_buffer_t *buffer) {
	test_send_peer = peer;
	test_send_count++;
	fastd_buffer_free(buffer);
}

static void test_protocol_handshake_init(
	fastd_socket_t *sock, const fastd_peer_address_t *local_addr UNUSED,
	const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, unsigned flags UNUSED) {
	test_handshake_count++;
	test_handshake_peer = peer;
	test_handshake_transport = fastd_socket_is_tcp(sock) ? TRANSPORT_TCP : TRANSPORT_UDP;
	test_handshake_remote = *remote_addr;
}

static void test_protocol_send_control(fastd_peer_t *peer, fastd_buffer_t *buffer) {
	test_control_send_peer = peer;
	test_control_send_count++;
	test_control_last_type = 0;
	size_t pos = test_control_send_count <= TEST_CONTROL_HISTORY ? test_control_send_count - 1 : TEST_CONTROL_HISTORY;
	if (buffer->len >= sizeof(test_punch_header_t)) {
		const test_punch_header_t *header = buffer->data;
		if (!memcmp(header->magic, "fpch", 4)) {
			test_control_last_type = header->type;
			if (pos < TEST_CONTROL_HISTORY) {
				test_control_send_peers[pos] = peer;
				test_control_send_types[pos] = header->type;
				if (buffer->len >= sizeof(test_punch_header_t) + sizeof(test_punch_endpoint_t)) {
					const test_punch_endpoint_t *endpoint = (const test_punch_endpoint_t *)(header + 1);
					test_control_send_ports[pos] = be16toh(endpoint->port);
				}
			}
		}
	}
	fastd_buffer_free(buffer);
}

static size_t test_protocol_key_length(void) {
	return sizeof(test_key_self);
}

static const void *test_protocol_get_own_key(void) {
	return test_key_self;
}

static const void *test_protocol_get_peer_key(const fastd_peer_t *peer) {
	if (peer && peer->id == 20)
		return test_key_b;
	if (peer && peer->id == 30)
		return test_key_a;
	return test_key_self;
}

static fastd_peer_t *test_protocol_find_peer_by_key_data(const void *key, size_t len) {
	if (test_lookup_peer && len == test_protocol_key_length() &&
	    !memcmp(key, test_protocol_get_peer_key(test_lookup_peer), len))
		return test_lookup_peer;

	return NULL;
}

static const fastd_method_info_t *test_protocol_get_current_method(const fastd_peer_t *peer UNUSED) {
	return &test_control_method;
}

static const fastd_protocol_t test_protocol = {
	.name = "test",
	.handshake_init = test_protocol_handshake_init,
	.send = test_protocol_send,
	.send_control = test_protocol_send_control,
	.key_length = test_protocol_key_length,
	.get_own_key = test_protocol_get_own_key,
	.get_peer_key = test_protocol_get_peer_key,
	.find_peer_by_key_data = test_protocol_find_peer_by_key_data,
	.get_current_method = test_protocol_get_current_method,
};

static fastd_peer_address_t addr4(uint32_t ip, uint16_t port) {
	fastd_peer_address_t ret = {};

	ret.in.sin_family = AF_INET;
	ret.in.sin_addr.s_addr = htonl(ip);
	ret.in.sin_port = htons(port);

	return ret;
}

static fastd_peer_address_t addr6(uint16_t suffix, uint16_t port) {
	static const uint8_t prefix[14] = {
		0x20, 0x01, 0x0d, 0xb8,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0,
	};
	fastd_peer_address_t ret = {};

	ret.in6.sin6_family = AF_INET6;
	ret.in6.sin6_port = htons(port);
	memcpy(ret.in6.sin6_addr.s6_addr, prefix, sizeof(prefix));
	ret.in6.sin6_addr.s6_addr[14] = suffix >> 8;
	ret.in6.sin6_addr.s6_addr[15] = suffix & 0xff;

	return ret;
}

static uint16_t port4(const fastd_peer_address_t *addr) {
	return ntohs(addr->in.sin_port);
}

static uint16_t port6(const fastd_peer_address_t *addr) {
	return ntohs(addr->in6.sin6_port);
}

static void assert_port4(const fastd_peer_address_t *addr, uint16_t port) {
	assert_int_equal(addr->sa.sa_family, AF_INET);
	assert_int_equal(port4(addr), port);
}

static void assert_port6(const fastd_peer_address_t *addr, uint16_t port) {
	assert_int_equal(addr->sa.sa_family, AF_INET6);
	assert_int_equal(port6(addr), port);
}

	#ifdef WITH_STATUS_SOCKET

static struct json_object *json_get_required(struct json_object *object, const char *key) {
	struct json_object *ret = NULL;
	assert_true(json_object_object_get_ex(object, key, &ret));
	return ret;
}

static struct json_object *json_get_object_required(struct json_object *object, const char *key) {
	struct json_object *ret = json_get_required(object, key);
	assert_int_equal(json_object_get_type(ret), json_type_object);
	return ret;
}

static struct json_object *json_get_array_required(struct json_object *object, const char *key) {
	struct json_object *ret = json_get_required(object, key);
	assert_int_equal(json_object_get_type(ret), json_type_array);
	return ret;
}

static bool json_get_bool_required(struct json_object *object, const char *key) {
	struct json_object *ret = json_get_required(object, key);
	assert_int_equal(json_object_get_type(ret), json_type_boolean);
	return json_object_get_boolean(ret);
}

static int64_t json_get_int_required(struct json_object *object, const char *key) {
	struct json_object *ret = json_get_required(object, key);
	assert_true(json_object_get_type(ret) == json_type_int);
	return json_object_get_int64(ret);
}

static const char *json_get_string_required(struct json_object *object, const char *key) {
	struct json_object *ret = json_get_required(object, key);
	assert_int_equal(json_object_get_type(ret), json_type_string);
	return json_object_get_string(ret);
}

#endif

static test_punch_message_t make_punch_message(void) {
	test_punch_message_t msg = {};

	memcpy(msg.header.magic, "fpch", 4);
	msg.header.version = 1;
	msg.header.type = TEST_PUNCH_SEND_CONE;
	msg.header.length = htobe16(sizeof(msg));
	msg.endpoint.key_len = sizeof(msg.key);
	msg.endpoint.address_family = 4;
	msg.endpoint.port = htons(41000);
	msg.endpoint.address[0] = 203;
	msg.endpoint.address[1] = 0;
	msg.endpoint.address[2] = 113;
	msg.endpoint.address[3] = 5;
	memcpy(msg.key, "\x01\x02\x03\x04", sizeof(msg.key));

	return msg;
}

static fastd_buffer_t *make_punch_control_buffer(
	uint8_t type, const fastd_peer_address_t *endpoint, fastd_nat_type_t nat_type, const uint8_t *key,
	size_t key_len) {
	size_t len = sizeof(test_punch_header_t) + sizeof(test_punch_endpoint_t) + key_len;
	fastd_buffer_t *buffer = fastd_buffer_alloc(len, 0);

	test_punch_header_t *header = buffer->data;
	memset(header, 0, len);
	memcpy(header->magic, "fpch", 4);
	header->version = 1;
	header->type = type;
	header->length = htobe16(len);

	test_punch_endpoint_t *payload = (test_punch_endpoint_t *)(header + 1);
	payload->key_len = key_len;
	payload->nat_type = nat_type;
	payload->address_family = endpoint->sa.sa_family == AF_INET6 ? 6 : 4;
	if (endpoint->sa.sa_family == AF_INET6) {
		payload->port = endpoint->in6.sin6_port;
		memcpy(payload->address, &endpoint->in6.sin6_addr, sizeof(endpoint->in6.sin6_addr));
		payload->min_port = endpoint->in6.sin6_port;
		payload->max_port = endpoint->in6.sin6_port;
	} else {
		payload->port = endpoint->in.sin_port;
		memcpy(payload->address, &endpoint->in.sin_addr, sizeof(endpoint->in.sin_addr));
		payload->min_port = endpoint->in.sin_port;
		payload->max_port = endpoint->in.sin_port;
	}

	memcpy(payload + 1, key, key_len);
	return buffer;
}

static fastd_buffer_t *make_punch_control_buffer_extra(
	uint8_t type, const fastd_peer_address_t *endpoint, fastd_nat_type_t nat_type, const uint8_t *key,
	size_t key_len, uint8_t extra) {
	fastd_buffer_t *buffer = make_punch_control_buffer(type, endpoint, nat_type, key, key_len);
	test_punch_endpoint_t *payload = (test_punch_endpoint_t *)((test_punch_header_t *)buffer->data + 1);
	payload->reserved = extra;
	return buffer;
}

static test_punch_result_ext_message_t make_punch_result_ext_message(void) {
	test_punch_message_t base = make_punch_message();
	test_punch_result_ext_message_t msg = {};

	msg.header = base.header;
	msg.header.type = TEST_PUNCH_RESULT_EXT;
	msg.header.length = htobe16(sizeof(msg));
	msg.endpoint = base.endpoint;
	memcpy(msg.key, base.key, sizeof(msg.key));

	return msg;
}

static test_punch_result_listener_message_t make_punch_result_listener_message(void) {
	test_punch_message_t base = make_punch_message();
	test_punch_result_listener_message_t msg = {};

	msg.header = base.header;
	msg.header.type = TEST_PUNCH_RESULT_LISTENER;
	msg.header.length = htobe16(sizeof(msg));
	msg.endpoint = base.endpoint;
	memcpy(msg.key, base.key, sizeof(msg.key));

	return msg;
}

static test_punch_listener_info_message_t make_punch_listener_info_message(void) {
	test_punch_message_t base = make_punch_message();
	test_punch_listener_info_message_t msg = {};

	msg.header = base.header;
	msg.header.type = TEST_PUNCH_LISTENER_INFO;
	msg.header.length = htobe16(sizeof(msg));
	msg.endpoint = base.endpoint;
	memcpy(msg.key, base.key, sizeof(msg.key));

	return msg;
}

static test_punch_command_listener_message_t make_punch_command_listener_message(void) {
	test_punch_message_t base = make_punch_message();
	test_punch_command_listener_message_t msg = {};

	msg.header = base.header;
	msg.header.type = TEST_PUNCH_SEND_CONE;
	msg.header.length = htobe16(sizeof(msg));
	msg.endpoint = base.endpoint;
	memcpy(msg.key, base.key, sizeof(msg.key));

	return msg;
}

#ifdef WITH_NAT_DETECT

static void test_nat_classifies_open_internet(void **state UNUSED) {
	const fastd_peer_address_t base[] = {
		addr4(0x0a000002, 51234),
		addr4(0x0a000002, 51234),
	};
	const fastd_peer_address_t local = addr4(0x0a000002, 51234);

	assert_int_equal(
		fastd_nat_test_classify(
			base, array_size(base), base, array_size(base), &local, true, true, false, NULL),
		FASTD_NAT_OPEN_INTERNET);
}

static void test_nat_classifies_symmetric_udp_firewall(void **state UNUSED) {
	const fastd_peer_address_t base[] = {
		addr4(0x0a000002, 51234),
		addr4(0x0a000002, 51234),
	};
	const fastd_peer_address_t local = addr4(0x0a000002, 51234);

	assert_int_equal(
		fastd_nat_test_classify(
			base, array_size(base), base, array_size(base), &local, true, false, false, NULL),
		FASTD_NAT_SYM_UDP_FIREWALL);
}

static void test_nat_classifies_full_cone(void **state UNUSED) {
	const fastd_peer_address_t base[] = {
		addr4(0xcb007105, 41000),
		addr4(0xcb007105, 41000),
	};
	const fastd_peer_address_t local = addr4(0x0a000002, 51234);
	int delta = 99;

	assert_int_equal(
		fastd_nat_test_classify(
			base, array_size(base), base, array_size(base), &local, true, true, false, &delta),
		FASTD_NAT_FULL_CONE);
	assert_int_equal(delta, 99);
}

static void test_nat_classifies_restricted(void **state UNUSED) {
	const fastd_peer_address_t base[] = {
		addr4(0xcb007105, 41000),
		addr4(0xcb007105, 41000),
	};
	const fastd_peer_address_t local = addr4(0x0a000002, 51234);

	assert_int_equal(
		fastd_nat_test_classify(
			base, array_size(base), base, array_size(base), &local, true, false, true, NULL),
		FASTD_NAT_RESTRICTED);
}

static void test_nat_classifies_port_restricted(void **state UNUSED) {
	const fastd_peer_address_t base[] = {
		addr4(0xcb007105, 41000),
		addr4(0xcb007105, 41000),
	};
	const fastd_peer_address_t local = addr4(0x0a000002, 51234);

	assert_int_equal(
		fastd_nat_test_classify(
			base, array_size(base), base, array_size(base), &local, true, false, false, NULL),
		FASTD_NAT_PORT_RESTRICTED);
}

static void test_nat_classifies_no_pat(void **state UNUSED) {
	const fastd_peer_address_t base[] = {
		addr4(0xcb007105, 51234),
		addr4(0xcb007105, 51234),
	};
	const fastd_peer_address_t local = addr4(0x0a000002, 51234);

	assert_int_equal(
		fastd_nat_test_classify(
			base, array_size(base), base, array_size(base), &local, true, false, false, NULL),
		FASTD_NAT_NO_PAT);
}

static void test_nat_classifies_easy_symmetric_inc(void **state UNUSED) {
	const fastd_peer_address_t base[] = {
		addr4(0xcb007105, 41000),
		addr4(0xcb007105, 41004),
	};
	const fastd_peer_address_t all[] = {
		addr4(0xcb007105, 41000),
		addr4(0xcb007105, 41004),
		addr4(0xcb007105, 41008),
		addr4(0xcb007105, 41012),
	};
	const fastd_peer_address_t local = addr4(0x0a000002, 51234);
	int delta = 0;

	assert_int_equal(
		fastd_nat_test_classify(
			base, array_size(base), all, array_size(all), &local, true, false, false, &delta),
		FASTD_NAT_SYMMETRIC_EASY_INC);
	assert_int_equal(delta, 4);
}

static void test_nat_classifies_hard_symmetric(void **state UNUSED) {
	const fastd_peer_address_t base[] = {
		addr4(0xcb007105, 41000),
		addr4(0xcb007105, 41150),
	};
	const fastd_peer_address_t all[] = {
		addr4(0xcb007105, 41000),
		addr4(0xcb007105, 41150),
		addr4(0xcb007105, 41080),
		addr4(0xcb007105, 41320),
	};
	const fastd_peer_address_t local = addr4(0x0a000002, 51234);

	assert_int_equal(
		fastd_nat_test_classify(base, array_size(base), all, array_size(all), &local, true, false, false, NULL),
		FASTD_NAT_SYMMETRIC);
}

static void test_nat_detects_easy_symmetric_dec_delta(void **state UNUSED) {
	const fastd_peer_address_t samples[] = {
		addr4(0xcb007105, 41012),
		addr4(0xcb007105, 41009),
		addr4(0xcb007105, 41006),
		addr4(0xcb007105, 41003),
	};

	assert_int_equal(fastd_nat_test_detect_port_delta(samples, array_size(samples)), -3);
}

static void test_nat_rejects_unstable_delta(void **state UNUSED) {
	const fastd_peer_address_t samples[] = {
		addr4(0xcb007105, 41000),
		addr4(0xcb007105, 41004),
		addr4(0xcb007105, 41001),
		addr4(0xcb007105, 41007),
	};

	assert_int_equal(fastd_nat_test_detect_port_delta(samples, array_size(samples)), 0);
}

static void test_nat_collects_unique_public_endpoints_by_ip(void **state UNUSED) {
	const fastd_peer_address_t samples[] = {
		addr4(0xcb007105, 41000),
		addr4(0xcb007105, 41004),
		addr4(0xc6336408, 42000),
	};
	fastd_peer_address_t endpoints[FASTD_NAT_MAX_PUBLIC_ENDPOINTS] = {};

	size_t n = fastd_nat_test_collect_public_endpoints(endpoints, samples, array_size(samples));

	assert_int_equal(n, 2);
	assert_int_equal(endpoints[0].in.sin_addr.s_addr, htonl(0xcb007105));
	assert_port4(&endpoints[0], 41000);
	assert_int_equal(endpoints[1].in.sin_addr.s_addr, htonl(0xc6336408));
	assert_port4(&endpoints[1], 42000);
}

static void test_tcp_nat_classifies_open_internet(void **state UNUSED) {
	const fastd_peer_address_t source = addr4(0xcb007105, 51234);
	const fastd_peer_address_t samples[] = {
		addr4(0xcb007105, 51234),
	};

	assert_int_equal(fastd_nat_test_classify_tcp(samples, array_size(samples), &source), FASTD_NAT_OPEN_INTERNET);
}

static void test_tcp_nat_classifies_unknown_with_one_translated_sample(void **state UNUSED) {
	const fastd_peer_address_t source = addr4(0x0a000002, 51234);
	const fastd_peer_address_t samples[] = {
		addr4(0xcb007105, 41000),
	};

	assert_int_equal(fastd_nat_test_classify_tcp(samples, array_size(samples), &source), FASTD_NAT_UNKNOWN);
}

static void test_tcp_nat_classifies_no_pat(void **state UNUSED) {
	const fastd_peer_address_t source = addr4(0x0a000002, 51234);
	const fastd_peer_address_t samples[] = {
		addr4(0xcb007105, 51234),
		addr4(0xcb007105, 51234),
		addr4(0xcb007105, 51234),
	};

	assert_int_equal(fastd_nat_test_classify_tcp(samples, array_size(samples), &source), FASTD_NAT_NO_PAT);
}

static void test_tcp_nat_classifies_full_cone(void **state UNUSED) {
	const fastd_peer_address_t source = addr4(0x0a000002, 51234);
	const fastd_peer_address_t samples[] = {
		addr4(0xcb007105, 41000),
		addr4(0xcb007105, 41000),
	};

	assert_int_equal(fastd_nat_test_classify_tcp(samples, array_size(samples), &source), FASTD_NAT_FULL_CONE);
}

static void test_tcp_nat_classifies_symmetric(void **state UNUSED) {
	const fastd_peer_address_t source = addr4(0x0a000002, 51234);
	const fastd_peer_address_t samples[] = {
		addr4(0xcb007105, 41000),
		addr4(0xcb007105, 41001),
	};

	assert_int_equal(fastd_nat_test_classify_tcp(samples, array_size(samples), &source), FASTD_NAT_SYMMETRIC);
}

#endif

static void test_punch_uses_exact_endpoint_when_symmetric_disabled(void **state UNUSED) {
	const fastd_peer_address_t endpoint = addr4(0xcb007105, 41000);
	fastd_peer_address_t out[4];

	size_t n = fastd_punch_test_build_endpoint_candidates(
		out, array_size(out), &endpoint, FASTD_NAT_SYMMETRIC_EASY_INC, 4, 4, false);

	assert_int_equal(n, 1);
	assert_port4(&out[0], 41000);
}

static void test_punch_predicts_easy_symmetric_inc(void **state UNUSED) {
	const fastd_peer_address_t endpoint = addr4(0xcb007105, 41000);
	fastd_peer_address_t out[4];

	size_t n = fastd_punch_test_build_endpoint_candidates(
		out, array_size(out), &endpoint, FASTD_NAT_SYMMETRIC_EASY_INC, 4, 4, true);

	assert_int_equal(n, 4);
	assert_port4(&out[0], 41000);
	assert_port4(&out[1], 41004);
	assert_port4(&out[2], 41008);
	assert_port4(&out[3], 41012);
}

static void test_punch_predicts_easy_symmetric_dec(void **state UNUSED) {
	const fastd_peer_address_t endpoint = addr4(0xcb007105, 41000);
	fastd_peer_address_t out[4];

	size_t n = fastd_punch_test_build_endpoint_candidates(
		out, array_size(out), &endpoint, FASTD_NAT_SYMMETRIC_EASY_DEC, -3, 4, true);

	assert_int_equal(n, 4);
	assert_port4(&out[0], 41000);
	assert_port4(&out[1], 40997);
	assert_port4(&out[2], 40994);
	assert_port4(&out[3], 40991);
}

static void test_punch_predicts_ipv6_easy_symmetric_inc(void **state UNUSED) {
	const fastd_peer_address_t endpoint = addr6(1, 41000);
	fastd_peer_address_t out[4];

	size_t n = fastd_punch_test_build_endpoint_candidates(
		out, array_size(out), &endpoint, FASTD_NAT_SYMMETRIC_EASY_INC, 4, 4, true);

	assert_int_equal(n, 4);
	assert_memory_equal(&out[0].in6.sin6_addr, &endpoint.in6.sin6_addr, sizeof(endpoint.in6.sin6_addr));
	assert_port6(&out[0], 41000);
	assert_port6(&out[1], 41004);
	assert_port6(&out[2], 41008);
	assert_port6(&out[3], 41012);
}

static void test_punch_pairs_easy_symmetric_dec_from_easytier_offset(void **state UNUSED) {
	const fastd_peer_address_t endpoint = addr4(0xcb007105, 42163);
	fastd_peer_address_t out[4];

	size_t n = fastd_punch_test_build_paired_endpoint_candidates(
		out, array_size(out), &endpoint, FASTD_NAT_SYMMETRIC_EASY_DEC, -1, 4, true);

	assert_int_equal(n, 4);
	assert_port4(&out[0], 42143);
	assert_port4(&out[1], 42142);
	assert_port4(&out[2], 42144);
	assert_port4(&out[3], 42141);
}

static void test_punch_pairs_easy_symmetric_inc_from_easytier_offset(void **state UNUSED) {
	const fastd_peer_address_t endpoint = addr4(0xcb007105, 41100);
	fastd_peer_address_t out[4];

	size_t n = fastd_punch_test_build_paired_endpoint_candidates(
		out, array_size(out), &endpoint, FASTD_NAT_SYMMETRIC_EASY_INC, 1, 4, true);

	assert_int_equal(n, 4);
	assert_port4(&out[0], 41120);
	assert_port4(&out[1], 41119);
	assert_port4(&out[2], 41121);
	assert_port4(&out[3], 41118);
}

static void test_punch_clamps_easy_symmetric_step(void **state UNUSED) {
	const fastd_peer_address_t endpoint = addr4(0xcb007105, 41000);
	fastd_peer_address_t out[3];

	size_t n = fastd_punch_test_build_endpoint_candidates(
		out, array_size(out), &endpoint, FASTD_NAT_SYMMETRIC_EASY_INC, 100, 3, true);

	assert_int_equal(n, 3);
	assert_port4(&out[0], 41000);
	assert_port4(&out[1], 41008);
	assert_port4(&out[2], 41016);
}

static void test_punch_builds_multi_endpoint_candidates_with_budget(void **state UNUSED) {
	const fastd_peer_address_t endpoints[] = {
		addr4(0xcb007105, 41000),
		addr4(0xc6336408, 42000),
	};
	fastd_peer_address_t out[4];

	size_t n = fastd_punch_test_build_multi_endpoint_candidates(
		out, array_size(out), endpoints, array_size(endpoints), FASTD_NAT_SYMMETRIC_EASY_INC, 4, 4, true);

	assert_int_equal(n, 4);
	assert_int_equal(out[0].in.sin_addr.s_addr, htonl(0xcb007105));
	assert_port4(&out[0], 41000);
	assert_int_equal(out[1].in.sin_addr.s_addr, htonl(0xcb007105));
	assert_port4(&out[1], 41004);
	assert_int_equal(out[2].in.sin_addr.s_addr, htonl(0xc6336408));
	assert_port4(&out[2], 42000);
	assert_int_equal(out[3].in.sin_addr.s_addr, htonl(0xc6336408));
	assert_port4(&out[3], 42004);

	n = fastd_punch_test_build_multi_endpoint_candidates(
		out, array_size(out), endpoints, array_size(endpoints), FASTD_NAT_FULL_CONE, 0, 1, false);

	assert_int_equal(n, 2);
	assert_int_equal(out[0].in.sin_addr.s_addr, htonl(0xcb007105));
	assert_port4(&out[0], 41000);
	assert_int_equal(out[1].in.sin_addr.s_addr, htonl(0xc6336408));
	assert_port4(&out[1], 42000);
}

static void test_punch_builds_per_endpoint_metadata_candidates(void **state UNUSED) {
	fastd_peer_punch_endpoint_t endpoints[] = {
		{
			.address = addr4(0xcb007105, 41000),
			.nat_type = FASTD_NAT_SYMMETRIC_EASY_INC,
			.port_delta = 4,
		},
		{
			.address = addr4(0xc6336408, 42000),
			.nat_type = FASTD_NAT_SYMMETRIC_EASY_DEC,
			.port_delta = -3,
		},
	};
	fastd_peer_address_t out[4];

	size_t n = fastd_punch_test_build_punch_endpoint_candidates(
		out, array_size(out), endpoints, array_size(endpoints), 4, true, false);

	assert_int_equal(n, 4);
	assert_int_equal(out[0].in.sin_addr.s_addr, htonl(0xcb007105));
	assert_port4(&out[0], 41000);
	assert_port4(&out[1], 41004);
	assert_int_equal(out[2].in.sin_addr.s_addr, htonl(0xc6336408));
	assert_port4(&out[2], 42000);
	assert_port4(&out[3], 41997);
}

static void test_punch_advances_hard_symmetric_scan_per_endpoint(void **state UNUSED) {
	fastd_peer_punch_endpoint_t endpoints[] = {
		{
			.address = addr4(0xcb007105, 41000),
			.nat_type = FASTD_NAT_SYMMETRIC,
		},
		{
			.address = addr4(0xc6336408, 42000),
			.nat_type = FASTD_NAT_SYMMETRIC,
			.hard_sym_port_index = 10,
			.hard_sym_round = 2,
		},
	};
	fastd_peer_address_t out[4];

	size_t n = fastd_punch_test_build_punch_endpoint_candidates(
		out, array_size(out), endpoints, array_size(endpoints), 4, true, false);

	assert_int_equal(n, 4);
	assert_port4(&out[0], 41000);
	assert_port4(&out[2], 42000);
	assert_int_equal(endpoints[0].hard_sym_port_index, 1);
	assert_int_equal(endpoints[0].hard_sym_round, 0);
	assert_int_equal(endpoints[1].hard_sym_port_index, 11);
	assert_int_equal(endpoints[1].hard_sym_round, 2);
}

static void test_punch_scans_hard_symmetric_when_symmetric_enabled(void **state UNUSED) {
	const fastd_peer_address_t endpoint = addr4(0xcb007105, 41000);
	fastd_peer_address_t out[5];

	size_t n = fastd_punch_test_build_endpoint_candidates(
		out, array_size(out), &endpoint, FASTD_NAT_SYMMETRIC, 0, 5, true);

	assert_int_equal(n, 5);
	assert_port4(&out[0], 41000);

	bool saw_full_space_probe = false;
	size_t i, j;
	for (i = 0; i < n; i++) {
		uint16_t port = port4(&out[i]);
		if (port < 40998 || port > 41002)
			saw_full_space_probe = true;
		for (j = i + 1; j < n; j++)
			assert_int_not_equal(port, port4(&out[j]));
	}
	assert_true(saw_full_space_probe);
}

static void test_punch_scans_ipv6_hard_symmetric_when_symmetric_enabled(void **state UNUSED) {
	const fastd_peer_address_t endpoint = addr6(1, 41000);
	fastd_peer_address_t out[5];
	uint32_t next_index = 0;
	uint32_t round = 0;

	size_t n = fastd_punch_test_build_hard_symmetric_endpoint_candidates(
		out, array_size(out), &endpoint, array_size(out), 0, &next_index, &round);

	assert_int_equal(n, 5);
	assert_port6(&out[0], 41000);
	assert_true(next_index > 0);
	assert_int_equal(round, 0);

	bool saw_full_space_probe = false;
	size_t i, j;
	for (i = 0; i < n; i++) {
		uint16_t port = port6(&out[i]);
		if (port < 40998 || port > 41002)
			saw_full_space_probe = true;
		for (j = i + 1; j < n; j++)
			assert_int_not_equal(port, port6(&out[j]));
	}
	assert_true(saw_full_space_probe);
}

static void test_punch_ipv6_hard_symmetric_seed_uses_address(void **state UNUSED) {
	const fastd_peer_address_t endpoint_a = addr6(1, 41000);
	const fastd_peer_address_t endpoint_b = addr6(2, 41000);
	fastd_peer_address_t out_a[4], out_b[4];
	uint32_t next_a = 0, next_b = 0;
	uint32_t round_a = 0, round_b = 0;

	size_t n_a = fastd_punch_test_build_hard_symmetric_endpoint_candidates(
		out_a, array_size(out_a), &endpoint_a, array_size(out_a), 0, &next_a, &round_a);
	size_t n_b = fastd_punch_test_build_hard_symmetric_endpoint_candidates(
		out_b, array_size(out_b), &endpoint_b, array_size(out_b), 0, &next_b, &round_b);

	assert_int_equal(n_a, 4);
	assert_int_equal(n_b, 4);

	bool differs = false;
	size_t i;
	for (i = 1; i < n_a; i++) {
		if (port6(&out_a[i]) != port6(&out_b[i]))
			differs = true;
	}
	assert_true(differs);
}

static void test_punch_prefers_hard_symmetric_observed_port_range(void **state UNUSED) {
	const fastd_peer_address_t endpoint = addr4(0xcb007105, 41000);
	fastd_peer_address_t out[5];
	uint32_t next_index = 0;
	uint32_t round = 0;

	size_t n = fastd_punch_test_build_hard_symmetric_range_endpoint_candidates(
		out, array_size(out), &endpoint, 40998, 41002, array_size(out), 0, &next_index, &round);

	assert_int_equal(n, 5);
	assert_port4(&out[0], 41000);
	assert_port4(&out[1], 40998);
	assert_port4(&out[2], 40999);
	assert_port4(&out[3], 41001);
	assert_port4(&out[4], 41002);
	assert_int_equal(next_index, 0);
	assert_int_equal(round, 0);
}

static void test_punch_advances_hard_symmetric_scan_index(void **state UNUSED) {
	const fastd_peer_address_t endpoint = addr4(0xcb007105, 41000);
	fastd_peer_address_t first[5], second[5];
	uint32_t next_index = 0;
	uint32_t round = 0;

	size_t n_first = fastd_punch_test_build_hard_symmetric_endpoint_candidates(
		first, array_size(first), &endpoint, array_size(first), 0, &next_index, &round);
	assert_int_equal(n_first, 5);
	assert_true(next_index > 0);
	assert_int_equal(round, 0);

	uint32_t second_next_index = next_index;
	size_t n_second = fastd_punch_test_build_hard_symmetric_endpoint_candidates(
		second, array_size(second), &endpoint, array_size(second), next_index, &second_next_index, &round);
	assert_int_equal(n_second, 5);
	assert_true(second_next_index > next_index);

	size_t i, j;
	for (i = 1; i < n_first; i++) {
		for (j = 1; j < n_second; j++)
			assert_int_not_equal(port4(&first[i]), port4(&second[j]));
	}
}

static void test_punch_counts_hard_symmetric_scan_rounds(void **state UNUSED) {
	const fastd_peer_address_t endpoint = addr4(0xcb007105, 41000);
	fastd_peer_address_t out[4];
	uint32_t next_index = FASTD_PUNCH_TEST_HARD_SYM_LAST_INDEX;
	uint32_t round = 7;

	size_t n = fastd_punch_test_build_hard_symmetric_endpoint_candidates(
		out, array_size(out), &endpoint, array_size(out), next_index, &next_index, &round);

	assert_int_equal(n, 4);
	assert_true(next_index < FASTD_PUNCH_TEST_HARD_SYM_PORT_SPACE);
	assert_true(round > 7);
}

static void test_punch_keeps_hard_symmetric_exact_when_symmetric_disabled(void **state UNUSED) {
	const fastd_peer_address_t endpoint = addr4(0xcb007105, 41000);
	fastd_peer_address_t out[5];

	size_t n = fastd_punch_test_build_endpoint_candidates(
		out, array_size(out), &endpoint, FASTD_NAT_SYMMETRIC, 0, 5, false);

	assert_int_equal(n, 1);
	assert_port4(&out[0], 41000);
}

static void test_punch_skips_out_of_range_predicted_ports(void **state UNUSED) {
	const fastd_peer_address_t endpoint = addr4(0xcb007105, 65534);
	fastd_peer_address_t out[4];

	size_t n = fastd_punch_test_build_endpoint_candidates(
		out, array_size(out), &endpoint, FASTD_NAT_SYMMETRIC_EASY_INC, 4, 4, true);

	assert_int_equal(n, 1);
	assert_port4(&out[0], 65534);
}

static void test_punch_respects_output_limit(void **state UNUSED) {
	const fastd_peer_address_t endpoint = addr4(0xcb007105, 41000);
	fastd_peer_address_t out[2];

	size_t n = fastd_punch_test_build_endpoint_candidates(
		out, array_size(out), &endpoint, FASTD_NAT_SYMMETRIC_EASY_INC, 1, 5, true);

	assert_int_equal(n, 2);
	assert_port4(&out[0], 41000);
	assert_port4(&out[1], 41001);
}

static void test_punch_parses_valid_message(void **state UNUSED) {
	test_punch_message_t msg = make_punch_message();
	uint8_t type = 0;
	size_t key_len = 0;

	assert_true(
		fastd_punch_test_parse_endpoint_message((const uint8_t *)&msg, sizeof(msg), &type, &key_len, NULL));
	assert_int_equal(type, TEST_PUNCH_SEND_CONE);
	assert_int_equal(key_len, 4);
}

static void test_punch_parses_packet_count(void **state UNUSED) {
	test_punch_message_t msg = make_punch_message();
	msg.endpoint.packet_count = htobe16(17);

	uint8_t type = 0;
	size_t key_len = 0;
	uint16_t packet_count = 0;

	assert_true(fastd_punch_test_parse_endpoint_message(
		(const uint8_t *)&msg, sizeof(msg), &type, &key_len, &packet_count));
	assert_int_equal(type, TEST_PUNCH_SEND_CONE);
	assert_int_equal(key_len, 4);
	assert_int_equal(packet_count, 17);
}

static void test_punch_parses_result_message(void **state UNUSED) {
	test_punch_message_t msg = make_punch_message();
	msg.header.type = TEST_PUNCH_RESULT;
	msg.endpoint.reserved = 3;

	uint8_t type = 0;
	size_t key_len = 0;

	assert_true(
		fastd_punch_test_parse_endpoint_message((const uint8_t *)&msg, sizeof(msg), &type, &key_len, NULL));
	assert_int_equal(type, TEST_PUNCH_RESULT);
	assert_int_equal(key_len, 4);
}

static void test_punch_parses_result_ext_message(void **state UNUSED) {
	test_punch_result_ext_message_t msg = make_punch_result_ext_message();
	msg.endpoint.reserved = TEST_PUNCH_RESULT_HANDSHAKE;
	msg.endpoint.packet_count = htobe16(800);
	msg.ext.command_type = TEST_PUNCH_SEND_HARD_SYM;
	msg.ext.udp_punch_sockets = htobe16(84);
	msg.ext.hard_sym_port_index = htobe32(12345);
	msg.ext.hard_sym_next_index = htobe32(13145);
	msg.ext.hard_sym_round = htobe32(7);
	msg.ext.wait_window_ms = htobe32(5000);

	uint8_t type = 0;
	size_t key_len = 0;
	uint16_t packet_count = 0;
	uint8_t command_type = 0;
	uint16_t udp_punch_sockets = 0;
	uint32_t hard_sym_port_index = 0;
	uint32_t hard_sym_next_index = 0;
	uint32_t hard_sym_round = 0;
	uint32_t wait_window_ms = 0;

	assert_true(fastd_punch_test_parse_result_ext_message(
		(const uint8_t *)&msg, sizeof(msg), &type, &key_len, &packet_count, &command_type,
		&udp_punch_sockets, &hard_sym_port_index, &hard_sym_next_index, &hard_sym_round, &wait_window_ms));
	assert_int_equal(type, TEST_PUNCH_RESULT_EXT);
	assert_int_equal(key_len, 4);
	assert_int_equal(packet_count, 800);
	assert_int_equal(command_type, TEST_PUNCH_SEND_HARD_SYM);
	assert_int_equal(udp_punch_sockets, 84);
	assert_int_equal(hard_sym_port_index, 12345);
	assert_int_equal(hard_sym_next_index, 13145);
	assert_int_equal(hard_sym_round, 7);
	assert_int_equal(wait_window_ms, 5000);
}

static void test_punch_parses_result_listener_message(void **state UNUSED) {
	test_punch_result_listener_message_t msg = make_punch_result_listener_message();
	msg.endpoint.reserved = TEST_PUNCH_RESULT_HANDSHAKE;
	msg.endpoint.packet_count = htobe16(800);
	msg.listener.result.command_type = TEST_PUNCH_BOTH_EASY_SYM;
	msg.listener.result.udp_punch_sockets = htobe16(25);
	msg.listener.result.hard_sym_port_index = htobe32(12345);
	msg.listener.result.hard_sym_next_index = htobe32(13145);
	msg.listener.result.hard_sym_round = htobe32(7);
	msg.listener.result.wait_window_ms = htobe32(5000);
	msg.listener.listener_id = htobe32(77);
	msg.listener.base_mapped_addr.address_family = 4;
	msg.listener.base_mapped_addr.flags = TEST_PUNCH_ADDRESS_AVAILABLE | TEST_PUNCH_ADDRESS_PORT_MAPPED;
	msg.listener.base_mapped_addr.port = htons(43000);
	uint32_t ip = htonl(0xcb007106);
	memcpy(msg.listener.base_mapped_addr.address, &ip, sizeof(ip));

	uint8_t type = 0;
	size_t key_len = 0;
	uint16_t packet_count = 0;
	uint8_t command_type = 0;
	uint16_t udp_punch_sockets = 0;
	uint32_t hard_sym_port_index = 0;
	uint32_t hard_sym_next_index = 0;
	uint32_t hard_sym_round = 0;
	uint32_t wait_window_ms = 0;
	uint32_t base_mapped_listener_id = 0;
	fastd_peer_address_t base_mapped_endpoint = {};
	bool base_mapped_port_mapped = false;

	assert_true(fastd_punch_test_parse_result_listener_message(
		(const uint8_t *)&msg, sizeof(msg), &type, &key_len, &packet_count, &command_type,
		&udp_punch_sockets, &hard_sym_port_index, &hard_sym_next_index, &hard_sym_round,
		&base_mapped_endpoint, &wait_window_ms, &base_mapped_listener_id, &base_mapped_port_mapped));
	assert_int_equal(type, TEST_PUNCH_RESULT_LISTENER);
	assert_int_equal(key_len, 4);
	assert_int_equal(packet_count, 800);
	assert_int_equal(command_type, TEST_PUNCH_BOTH_EASY_SYM);
	assert_int_equal(udp_punch_sockets, 25);
	assert_int_equal(hard_sym_port_index, 12345);
	assert_int_equal(hard_sym_next_index, 13145);
	assert_int_equal(hard_sym_round, 7);
	assert_int_equal(wait_window_ms, 5000);
	assert_int_equal(base_mapped_listener_id, 77);
	assert_int_equal(base_mapped_endpoint.sa.sa_family, AF_INET);
	assert_int_equal(port4(&base_mapped_endpoint), 43000);
	assert_int_equal(base_mapped_endpoint.in.sin_addr.s_addr, htonl(0xcb007106));
	assert_true(base_mapped_port_mapped);
}

static void test_punch_parses_listener_info_message(void **state UNUSED) {
	test_punch_listener_info_message_t msg = make_punch_listener_info_message();
	msg.listener.listener_id = htobe32(1234);

	uint8_t type = 0;
	size_t key_len = 0;
	uint32_t listener_id = 0;

	assert_true(fastd_punch_test_parse_listener_info_message(
		(const uint8_t *)&msg, sizeof(msg), &type, &key_len, &listener_id));
	assert_int_equal(type, TEST_PUNCH_LISTENER_INFO);
	assert_int_equal(key_len, 4);
	assert_int_equal(listener_id, 1234);
}

static void test_punch_parses_command_listener_message(void **state UNUSED) {
	test_punch_command_listener_message_t msg = make_punch_command_listener_message();
	msg.endpoint.packet_count = htobe16(25);
	msg.listener.listener_id = htobe32(4321);

	uint8_t type = 0;
	size_t key_len = 0;
	uint16_t packet_count = 0;
	uint32_t listener_id = 0;

	assert_true(fastd_punch_test_parse_command_listener_message(
		(const uint8_t *)&msg, sizeof(msg), &type, &key_len, &packet_count, &listener_id));
	assert_int_equal(type, TEST_PUNCH_SEND_CONE);
	assert_int_equal(key_len, 4);
	assert_int_equal(packet_count, 25);
	assert_int_equal(listener_id, 4321);
}

static void test_punch_parses_all_endpoint_command_messages(void **state UNUSED) {
	static const uint8_t command_types[] = {
		TEST_PUNCH_SEND_CONE,
		TEST_PUNCH_SEND_EASY_SYM,
		TEST_PUNCH_SEND_HARD_SYM,
		TEST_PUNCH_BOTH_EASY_SYM,
		TEST_PUNCH_SEND_TCP,
	};

	size_t i;
	for (i = 0; i < array_size(command_types); i++) {
		test_punch_message_t msg = make_punch_message();
		msg.header.type = command_types[i];

		uint8_t type = 0;
		size_t key_len = 0;

		assert_true(
			fastd_punch_test_parse_endpoint_message(
				(const uint8_t *)&msg, sizeof(msg), &type, &key_len, NULL));
		assert_true(fastd_punch_test_is_endpoint_command_type(type));
		assert_int_equal(type, command_types[i]);
		assert_int_equal(key_len, 4);
	}
}

static void test_punch_parses_tcp_nat_info_message(void **state UNUSED) {
	test_punch_message_t msg = make_punch_message();
	msg.header.type = TEST_PUNCH_TCP_NAT_INFO;
	msg.endpoint.nat_type = FASTD_NAT_FULL_CONE;

	uint8_t type = 0;
	size_t key_len = 0;

	assert_true(
		fastd_punch_test_parse_endpoint_message((const uint8_t *)&msg, sizeof(msg), &type, &key_len, NULL));
	assert_int_equal(type, TEST_PUNCH_TCP_NAT_INFO);
	assert_int_equal(key_len, 4);
	assert_false(fastd_punch_test_is_endpoint_command_type(type));
}

static void test_punch_parses_extra_nat_info_messages(void **state UNUSED) {
	static const uint8_t info_types[] = {
		TEST_PUNCH_NAT_INFO_EXTRA,
		TEST_PUNCH_TCP_NAT_INFO_EXTRA,
	};

	size_t i;
	for (i = 0; i < array_size(info_types); i++) {
		test_punch_message_t msg = make_punch_message();
		msg.header.type = info_types[i];
		msg.endpoint.nat_type = FASTD_NAT_FULL_CONE;

		uint8_t type = 0;
		size_t key_len = 0;

		assert_true(
			fastd_punch_test_parse_endpoint_message(
				(const uint8_t *)&msg, sizeof(msg), &type, &key_len, NULL));
		assert_int_equal(type, info_types[i]);
		assert_int_equal(key_len, 4);
		assert_false(fastd_punch_test_is_endpoint_command_type(type));
	}
}

static void test_punch_promotes_port_mapping_nat_info(void **state UNUSED) {
	const fastd_peer_address_t mapped = addr4(0xcb007105, 47000);
	fastd_peer_address_t endpoint = {};
	fastd_nat_type_t nat_type = FASTD_NAT_UNKNOWN;
	uint16_t min_port = 0, max_port = 0;
	int port_delta = 99;

	assert_true(fastd_punch_test_mapped_endpoint_to_nat_info(
		&mapped, &endpoint, &nat_type, &min_port, &max_port, &port_delta));
	assert_true(fastd_peer_address_equal(&endpoint, &mapped));
	assert_int_equal(nat_type, FASTD_NAT_FULL_CONE);
	assert_int_equal(min_port, 47000);
	assert_int_equal(max_port, 47000);
	assert_int_equal(port_delta, 0);
}

static void test_punch_rejects_zero_port_mapping_nat_info(void **state UNUSED) {
	const fastd_peer_address_t mapped = addr4(0xcb007105, 0);
	fastd_peer_address_t endpoint = {};
	fastd_nat_type_t nat_type = FASTD_NAT_FULL_CONE;
	uint16_t min_port = 1, max_port = 1;
	int port_delta = 0;

	assert_false(fastd_punch_test_mapped_endpoint_to_nat_info(
		&mapped, &endpoint, &nat_type, &min_port, &max_port, &port_delta));
}

static void test_punch_rejects_bad_magic(void **state UNUSED) {
	test_punch_message_t msg = make_punch_message();
	msg.header.magic[0] = 'x';

	assert_false(fastd_punch_test_parse_endpoint_message((const uint8_t *)&msg, sizeof(msg), NULL, NULL, NULL));
}

static void test_punch_rejects_bad_version(void **state UNUSED) {
	test_punch_message_t msg = make_punch_message();
	msg.header.version = 2;

	assert_false(fastd_punch_test_parse_endpoint_message((const uint8_t *)&msg, sizeof(msg), NULL, NULL, NULL));
}

static void test_punch_rejects_bad_length(void **state UNUSED) {
	test_punch_message_t msg = make_punch_message();
	msg.header.length = htobe16(sizeof(msg) - 1);

	assert_false(fastd_punch_test_parse_endpoint_message((const uint8_t *)&msg, sizeof(msg), NULL, NULL, NULL));
}

static void test_punch_rejects_bad_key_length(void **state UNUSED) {
	test_punch_message_t msg = make_punch_message();
	msg.endpoint.key_len = sizeof(msg.key) - 1;

	assert_false(fastd_punch_test_parse_endpoint_message((const uint8_t *)&msg, sizeof(msg), NULL, NULL, NULL));
}

static void test_punch_suppresses_failed_endpoint_temporarily(void **state UNUSED) {
	fastd_peer_t peer = {};
	const fastd_peer_address_t endpoint = addr4(0xcb007105, 41000);

	ctx.now = 1000;
	fastd_peer_test_suppress_punch_candidate(&peer, &endpoint);

	assert_true(fastd_peer_punch_candidate_suppressed(&peer, &endpoint));
	assert_int_equal(fastd_peer_punch_suppression_count(&peer), 1);

	ctx.now += 30000;
	assert_true(fastd_peer_punch_candidate_suppressed(&peer, &endpoint));

	ctx.now += 31000;
	assert_false(fastd_peer_punch_candidate_suppressed(&peer, &endpoint));
	assert_int_equal(fastd_peer_punch_suppression_count(&peer), 0);

	VECTOR_FREE(peer.punch_suppressions);
}

static void test_punch_suppression_is_bounded(void **state UNUSED) {
	fastd_peer_t peer = {};
	size_t i;

	ctx.now = 1000;
	for (i = 0; i < 40; i++) {
		fastd_peer_address_t endpoint = addr4(0xcb007105, 41000 + i);
		fastd_peer_test_suppress_punch_candidate(&peer, &endpoint);
		ctx.now++;
	}

	assert_int_equal(fastd_peer_punch_suppression_count(&peer), 32);

	const fastd_peer_address_t evicted = addr4(0xcb007105, 41000);
	const fastd_peer_address_t retained = addr4(0xcb007105, 41039);
	assert_false(fastd_peer_punch_candidate_suppressed(&peer, &evicted));
	assert_true(fastd_peer_punch_candidate_suppressed(&peer, &retained));

	VECTOR_FREE(peer.punch_suppressions);
}

static void test_punch_result_backoff_policy(void **state UNUSED) {
	assert_false(fastd_punch_test_result_causes_relay_backoff(TEST_PUNCH_RESULT_ACCEPTED));
	assert_false(fastd_punch_test_result_causes_relay_backoff(TEST_PUNCH_RESULT_HANDSHAKE));
	assert_true(fastd_punch_test_result_causes_relay_backoff(TEST_PUNCH_RESULT_SUPPRESSED));
	assert_true(fastd_punch_test_result_causes_relay_backoff(TEST_PUNCH_RESULT_NO_PEER));
	assert_true(fastd_punch_test_result_causes_relay_backoff(TEST_PUNCH_RESULT_BUSY));
}

static void test_punch_relay_backoff_expires(void **state UNUSED) {
	fastd_peer_t peer = {};
	const fastd_peer_address_t endpoint = addr4(0xcb007105, 41000);

	ctx.now = 1000;
	fastd_peer_add_punch_relay_backoff(&peer, &endpoint);

	assert_true(fastd_peer_punch_relay_backoff_active(&peer, &endpoint));
	assert_int_equal(fastd_peer_punch_relay_backoff_timeout(&peer, &endpoint), ctx.now + FASTD_PUNCH_SUPPRESSION_TIME);
	assert_int_equal(fastd_peer_punch_relay_backoff_count(&peer), 1);

	ctx.now += 30000;
	assert_true(fastd_peer_punch_relay_backoff_active(&peer, &endpoint));
	assert_int_equal(fastd_peer_punch_relay_backoff_timeout(&peer, &endpoint), 61000);

	ctx.now += 31000;
	assert_false(fastd_peer_punch_relay_backoff_active(&peer, &endpoint));
	assert_int_equal(fastd_peer_punch_relay_backoff_timeout(&peer, &endpoint), FASTD_TIMEOUT_INV);
	assert_int_equal(fastd_peer_punch_relay_backoff_count(&peer), 0);

	VECTOR_FREE(peer.punch_relay_backoffs);
}

static void test_punch_relay_backoff_is_bounded(void **state UNUSED) {
	fastd_peer_t peer = {};
	size_t i;

	ctx.now = 1000;
	for (i = 0; i < 40; i++) {
		fastd_peer_address_t endpoint = addr4(0xcb007105, 42000 + i);
		fastd_peer_add_punch_relay_backoff(&peer, &endpoint);
		ctx.now++;
	}

	assert_int_equal(fastd_peer_punch_relay_backoff_count(&peer), 32);

	const fastd_peer_address_t evicted = addr4(0xcb007105, 42000);
	const fastd_peer_address_t retained = addr4(0xcb007105, 42039);
	assert_false(fastd_peer_punch_relay_backoff_active(&peer, &evicted));
	assert_true(fastd_peer_punch_relay_backoff_active(&peer, &retained));

	VECTOR_FREE(peer.punch_relay_backoffs);
}

static void test_peer_punch_symmetric_inherits_and_overrides(void **state UNUSED) {
	fastd_peer_t peer = {};

	conf.punch_symmetric = true;
	assert_true(fastd_peer_get_punch_symmetric(&peer));

	peer.punch_symmetric = FASTD_TRISTATE_FALSE;
	assert_false(fastd_peer_get_punch_symmetric(&peer));

	conf.punch_symmetric = false;
	peer.punch_symmetric = FASTD_TRISTATE_UNDEF;
	assert_false(fastd_peer_get_punch_symmetric(&peer));

	peer.punch_symmetric = FASTD_TRISTATE_TRUE;
	assert_true(fastd_peer_get_punch_symmetric(&peer));
}

static void test_nat_traversal_inherits_and_overrides(void **state UNUSED) {
	fastd_peer_group_t group = {
		.nat_traversal = FASTD_TRISTATE_TRUE,
		.turn_relay = FASTD_TRISTATE_UNDEF,
		.turn_servers = (fastd_turn_server_t *)0x1,
	};
	fastd_peer_t peer = { .group = &group };

	assert_true(fastd_peer_get_nat_traversal(&peer));
	assert_true(fastd_peer_get_turn_relay(&peer));

	peer.nat_traversal = FASTD_TRISTATE_FALSE;
	assert_false(fastd_peer_get_nat_traversal(&peer));
	assert_false(fastd_peer_get_turn_relay(&peer));

	peer.nat_traversal = FASTD_TRISTATE_TRUE;
	peer.turn_relay = FASTD_TRISTATE_FALSE;
	assert_true(fastd_peer_get_nat_traversal(&peer));
	assert_false(fastd_peer_get_turn_relay(&peer));
}

static void test_tcp_direct_loss_preserves_nat_session_and_schedules_reconnect(void **state UNUSED) {
	fastd_pqueue_t *old_task_queue = ctx.task_queue;
	int64_t old_now = ctx.now;
	bool old_keepalive = conf.punch_keepalive;
	__typeof__(conf.punch_keepalive_interval) old_keepalive_interval = conf.punch_keepalive_interval;

	ctx.task_queue = NULL;
	ctx.now = 424000;
	conf.punch_keepalive = true;
	conf.punch_keepalive_interval = 25000;

	fastd_peer_t peer = {
		.id = 77,
		.name = "tcp-peer",
		.state = STATE_ESTABLISHED,
		.transport = TRANSPORT_TCP,
		.nat_traversal = FASTD_TRISTATE_TRUE,
		.hole_punch = HOLE_PUNCH_TCP,
		.direct_established = true,
		.address = addr4(0xcb007105, 45100),
		.active_path_timeout = ctx.now + 10000,
		.active_path_proven_timeout = ctx.now + 11000,
		.active_path_payload_seen = ctx.now + 12000,
		.active_path_payload_sent = true,
		.last_handshake_timeout = ctx.now - 1000,
		.last_handshake_address = addr4(0xcb007105, 45100),
		.last_handshake_transport = TRANSPORT_TCP,
		.reset_timeout = FASTD_TIMEOUT_INV,
		.keepalive_timeout = ctx.now + 30000,
		.next_handshake = FASTD_TIMEOUT_INV,
		.backup_reset_timeout = FASTD_TIMEOUT_INV,
		.backup_keepalive_timeout = FASTD_TIMEOUT_INV,
	};

	assert_true(fastd_peer_handle_tcp_connection_lost(&peer));
	assert_true(fastd_peer_is_established(&peer));
	assert_true(peer.direct_established);
	assert_int_equal(peer.active_path_timeout, ctx.now);
	assert_int_equal(peer.active_path_proven_timeout, FASTD_TIMEOUT_INV);
	assert_int_equal(peer.active_path_payload_seen, FASTD_TIMEOUT_INV);
	assert_false(peer.active_path_payload_sent);
	assert_int_equal(peer.last_handshake_timeout, ctx.now);
	assert_int_equal(peer.last_handshake_address.sa.sa_family, AF_UNSPEC);
	assert_int_equal(peer.last_handshake_transport, TRANSPORT_UNSET);
	assert_int_equal(peer.next_handshake, ctx.now + 100);
	assert_int_equal(peer.keepalive_timeout, ctx.now + conf.punch_keepalive_interval);
	assert_int_equal(fastd_task_timeout(&peer.task), peer.next_handshake);

	fastd_peer_t ordinary_peer = peer;
	ordinary_peer.task = (fastd_task_t){};
	ordinary_peer.direct_established = false;
	ordinary_peer.active_path_timeout = ctx.now + 3000;
	assert_false(fastd_peer_handle_tcp_connection_lost(&ordinary_peer));
	assert_int_equal(ordinary_peer.active_path_timeout, ctx.now + 3000);

	if (fastd_task_scheduled(&peer.task))
		fastd_task_unschedule(&peer.task);

	assert_null(ctx.task_queue);
	ctx.task_queue = old_task_queue;
	ctx.now = old_now;
	conf.punch_keepalive = old_keepalive;
	conf.punch_keepalive_interval = old_keepalive_interval;
}

static bool test_simultaneous_yield(uint8_t own_key_byte, uint8_t peer_key_byte, fastd_nat_type_t peer_nat_type) {
	uint8_t own_key[32] = {};
	uint8_t peer_key[32] = {};

	own_key[31] = own_key_byte;
	peer_key[31] = peer_key_byte;
	return fastd_protocol_ec25519_fhmqvc_test_accept_simultaneous_responder(
		own_key, peer_key, peer_nat_type, ctx.now + 10000);
}

static void test_ec25519_simultaneous_responder_yield_is_deterministic(void **state UNUSED) {
	int64_t old_now = ctx.now;
	ctx.now = 1000;

	assert_true(test_simultaneous_yield(2, 1, FASTD_NAT_SYMMETRIC_EASY_INC));
	assert_false(test_simultaneous_yield(1, 2, FASTD_NAT_SYMMETRIC_EASY_INC));
	assert_int_equal(
		test_simultaneous_yield(2, 1, FASTD_NAT_SYMMETRIC_EASY_INC) +
			test_simultaneous_yield(1, 2, FASTD_NAT_SYMMETRIC_EASY_INC),
		1);

	assert_true(test_simultaneous_yield(2, 1, FASTD_NAT_SYMMETRIC_EASY_DEC));
	assert_false(test_simultaneous_yield(1, 2, FASTD_NAT_SYMMETRIC_EASY_DEC));
	assert_int_equal(
		test_simultaneous_yield(2, 1, FASTD_NAT_SYMMETRIC_EASY_DEC) +
			test_simultaneous_yield(1, 2, FASTD_NAT_SYMMETRIC_EASY_DEC),
		1);

	ctx.now = old_now;
}

static void test_punch_data_relay_effective_setting(void **state UNUSED) {
	fastd_tristate_t old_data_relay = conf.punch_data_relay;
	bool old_control_relay = conf.punch_control_relay;
	fastd_peer_group_t *old_peer_group = conf.peer_group;
	fastd_peer_group_t root_group = {
		.nat_traversal = FASTD_TRISTATE_FALSE,
	};
	conf.peer_group = &root_group;

	conf.punch_data_relay = FASTD_TRISTATE_UNDEF;
	conf.punch_control_relay = false;
	assert_false(fastd_peer_get_punch_data_relay());

	conf.punch_control_relay = true;
	assert_true(fastd_peer_get_punch_data_relay());

	conf.punch_data_relay = FASTD_TRISTATE_FALSE;
	assert_false(fastd_peer_get_punch_data_relay());

	conf.punch_data_relay = FASTD_TRISTATE_TRUE;
	conf.punch_control_relay = false;
	assert_true(fastd_peer_get_punch_data_relay());

	conf.punch_data_relay = FASTD_TRISTATE_UNDEF;
	root_group.nat_traversal = FASTD_TRISTATE_TRUE;
	assert_true(fastd_peer_get_punch_data_relay());

	conf.punch_data_relay = old_data_relay;
	conf.punch_control_relay = old_control_relay;
	conf.peer_group = old_peer_group;
}

static fastd_buffer_t *test_eth_frame(fastd_eth_addr_t dest, fastd_eth_addr_t source) {
	fastd_buffer_t *buffer = fastd_buffer_alloc(sizeof(fastd_eth_header_t), conf.encrypt_headroom);
	fastd_eth_header_t header = {
		.dest = dest,
		.source = source,
	};
	memcpy(buffer->data, &header, sizeof(header));
	return buffer;
}

static void test_punch_data_relay_only_for_learned_nat_unicast(void **state UNUSED) {
	__typeof__(ctx.eth_addrs) old_eth_addrs = ctx.eth_addrs;
	__typeof__(ctx.punch_pair_states) old_pair_states = ctx.punch_pair_states;
	const fastd_protocol_t *old_protocol = conf.protocol;
	fastd_tristate_t old_data_relay = conf.punch_data_relay;
	fastd_mode_t old_mode = conf.mode;
	size_t old_encrypt_headroom = conf.encrypt_headroom;
	size_t old_max_buffer = ctx.max_buffer;
	fastd_timeout_t old_now = ctx.now;

	ctx.eth_addrs = (__typeof__(ctx.eth_addrs)){};
	ctx.punch_pair_states = (__typeof__(ctx.punch_pair_states)){};
	conf.protocol = &test_protocol;
	conf.punch_data_relay = FASTD_TRISTATE_TRUE;
	conf.mode = MODE_MULTITAP;
	conf.encrypt_headroom = 0;
	ctx.max_buffer = 2048;
	ctx.now = 1000;
	fastd_init_buffers();

	fastd_peer_group_t group = {
		.nat_traversal = FASTD_TRISTATE_TRUE,
	};
	fastd_peer_t source = {
		.id = 10,
		.name = "source",
		.group = &group,
		.state = STATE_ESTABLISHED,
	};
	fastd_peer_t dest = {
		.id = 20,
		.name = "dest",
		.group = &group,
		.state = STATE_ESTABLISHED,
	};

	fastd_eth_addr_t source_mac = { .data = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 } };
	fastd_eth_addr_t dest_mac = { .data = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 } };
	fastd_eth_addr_t multicast_mac = { .data = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x03 } };

	fastd_peer_eth_addr_add(&dest, dest_mac);
	test_send_peer = NULL;
	test_send_count = 0;
	assert_true(fastd_send_data_relay(test_eth_frame(dest_mac, source_mac), &source));
	assert_ptr_equal(test_send_peer, &dest);
	assert_int_equal(test_send_count, 1);
	assert_int_equal(VECTOR_LEN(ctx.punch_pair_states), 1);

	fastd_buffer_t *blocked = test_eth_frame(multicast_mac, source_mac);
	assert_false(fastd_send_data_relay(blocked, &source));
	fastd_buffer_free(blocked);
	assert_int_equal(test_send_count, 1);

	dest.nat_traversal = FASTD_TRISTATE_FALSE;
	blocked = test_eth_frame(dest_mac, source_mac);
	assert_false(fastd_send_data_relay(blocked, &source));
	fastd_buffer_free(blocked);
	assert_int_equal(test_send_count, 1);

	fastd_cleanup_buffers();
	VECTOR_FREE(ctx.eth_addrs);
	VECTOR_FREE(ctx.punch_pair_states);
	ctx.eth_addrs = old_eth_addrs;
	ctx.punch_pair_states = old_pair_states;
	conf.protocol = old_protocol;
	conf.punch_data_relay = old_data_relay;
	conf.mode = old_mode;
	conf.encrypt_headroom = old_encrypt_headroom;
	ctx.max_buffer = old_max_buffer;
	ctx.now = old_now;
}

static void test_punch_udp_command_suppressed_for_tcp_only_peer(void **state UNUSED) {
	const fastd_protocol_t *old_protocol = conf.protocol;
	fastd_peer_t *old_lookup_peer = test_lookup_peer;
	size_t old_handshake_count = test_handshake_count;
	size_t old_encrypt_headroom = conf.encrypt_headroom;
	size_t old_max_buffer = ctx.max_buffer;

	fastd_peer_t sender = {
		.id = 10,
		.name = "sender",
		.state = STATE_ESTABLISHED,
	};
	fastd_peer_t peer = {
		.id = 20,
		.name = "peer",
		.transport = TRANSPORT_TCP,
		.hole_punch = HOLE_PUNCH_TCP,
		.nat_traversal = FASTD_TRISTATE_TRUE,
	};
	fastd_peer_address_t endpoint = addr4(0xcb007105, 41000);

	conf.protocol = &test_protocol;
	conf.encrypt_headroom = 0;
	ctx.max_buffer = 2048;
	fastd_init_buffers();
	test_lookup_peer = &peer;
	test_handshake_count = 0;
	test_reset_control_sends();

	assert_true(fastd_punch_handle_control(
		&sender,
		make_punch_control_buffer(
			TEST_PUNCH_SEND_CONE, &endpoint, FASTD_NAT_FULL_CONE, test_key_b, sizeof(test_key_b))));

	assert_int_equal(VECTOR_LEN(peer.direct_candidates), 0);
	assert_int_equal(test_handshake_count, 0);
	assert_ptr_equal(test_control_send_peer, &sender);
	assert_int_equal(test_control_send_count, 2);
	assert_int_equal(test_control_send_types[0], TEST_PUNCH_RESULT);
	assert_int_equal(test_control_send_types[1], TEST_PUNCH_RESULT_EXT);

	fastd_cleanup_buffers();
	conf.protocol = old_protocol;
	test_lookup_peer = old_lookup_peer;
	test_handshake_count = old_handshake_count;
	conf.encrypt_headroom = old_encrypt_headroom;
	ctx.max_buffer = old_max_buffer;
}

static void test_punch_nat_refresh_policy(void **state UNUSED) {
	ctx.now = 10000;
	conf.punch_announce_interval = 15000;

	fastd_nat_status_t status = {
		.enabled = true,
		.available = false,
		.last_update = 0,
	};

	assert_true(fastd_punch_test_nat_status_needs_refresh(&status));

	status.available = true;
	status.last_update = ctx.now - 14999;
	assert_false(fastd_punch_test_nat_status_needs_refresh(&status));

	status.last_update = ctx.now - 15000;
	assert_true(fastd_punch_test_nat_status_needs_refresh(&status));

	status.last_update = ctx.now + 1;
	assert_false(fastd_punch_test_nat_status_needs_refresh(&status));

	status.enabled = false;
	status.available = false;
	assert_false(fastd_punch_test_nat_status_needs_refresh(&status));
}

static void test_punch_observed_udp_metadata_fills_without_stun(void **state UNUSED) {
	fastd_timeout_t old_now = ctx.now;
	ctx.now = 1000;

	fastd_socket_t udp_sock = {
		.type = SOCKET_TYPE_UDP,
	};
	fastd_peer_t peer = {
		.state = STATE_ESTABLISHED,
		.nat_traversal = FASTD_TRISTATE_TRUE,
		.hole_punch = HOLE_PUNCH_AUTO,
		.sock = &udp_sock,
		.address = addr4(0xcb007105, 41000),
	};

	fastd_punch_test_refresh_observed_peer_punch_metadata(&peer);
	assert_true(fastd_peer_address_equal(&peer.punch_endpoint, &peer.address));
	assert_int_equal(peer.punch_nat_type, FASTD_NAT_UNKNOWN);
	assert_int_equal(peer.punch_min_port, 41000);
	assert_int_equal(peer.punch_max_port, 41000);
	assert_int_equal(peer.punch_timeout, ctx.now + PEER_STALE_TIME);
	assert_int_equal(peer.n_punch_endpoints, 1);

	peer.punch_nat_type = FASTD_NAT_FULL_CONE;
	peer.punch_endpoint = addr4(0xcb007105, 41001);
	peer.punch_timeout = ctx.now + 10000;
	peer.address = addr4(0xcb007105, 41002);
	fastd_punch_test_refresh_observed_peer_punch_metadata(&peer);
	assert_int_equal(port4(&peer.punch_endpoint), 41001);
	assert_int_equal(peer.punch_nat_type, FASTD_NAT_FULL_CONE);

	peer.punch_nat_type = FASTD_NAT_UNKNOWN;
	peer.punch_endpoint = addr4(0xcb007105, 41003);
	peer.punch_timeout = ctx.now + 10000;
	peer.address = addr4(0xcb007105, 41004);
	fastd_punch_test_refresh_observed_peer_punch_metadata(&peer);
	assert_true(fastd_peer_address_equal(&peer.punch_endpoint, &peer.address));
	assert_int_equal(peer.punch_min_port, 41004);
	assert_int_equal(peer.punch_max_port, 41004);

	ctx.now = old_now;
}

static void test_punch_task_pair_state_requires_established_metadata_and_due(void **state UNUSED) {
	fastd_peer_t a = {
		.state = STATE_ESTABLISHED,
		.punch_endpoint = addr4(0xcb007105, 41000),
		.punch_timeout = 2000,
		.next_punch_relay = 500,
	};
	fastd_peer_t b = {
		.state = STATE_ESTABLISHED,
		.next_punch_relay = 500,
	};

	ctx.now = 1000;

	fastd_punch_test_pair_state_t pair_state = fastd_punch_test_pair_state(&a, &b);
	assert_true(pair_state.established);
	assert_true(pair_state.has_metadata_a);
	assert_false(pair_state.has_metadata_b);
	assert_true(pair_state.due_a);
	assert_true(pair_state.due_b);
	assert_true(pair_state.collected);
	assert_false(pair_state.waiting);
	assert_false(pair_state.in_flight);
	assert_false(pair_state.backoff);
	assert_false(pair_state.missing_metadata);

	a.next_punch_relay = ctx.now + 1000;
	pair_state = fastd_punch_test_pair_state(&a, &b);
	assert_true(pair_state.waiting);
	assert_false(pair_state.collected);
	assert_int_equal(pair_state.next_retry, ctx.now + 1000);

	a.punch_endpoint = (fastd_peer_address_t){};
	pair_state = fastd_punch_test_pair_state(&a, &b);
	assert_true(pair_state.missing_metadata);
	assert_false(pair_state.collected);
	assert_false(pair_state.waiting);

	b.tcp_punch_endpoint = addr4(0xcb007106, 51000);
	b.tcp_punch_timeout = ctx.now + 5000;
	pair_state = fastd_punch_test_pair_state(&a, &b);
	assert_true(pair_state.has_metadata_b);
	assert_true(pair_state.collected);
	assert_false(pair_state.missing_metadata);

	b.state = STATE_INACTIVE;
	pair_state = fastd_punch_test_pair_state(&a, &b);
	assert_false(pair_state.established);
	assert_false(pair_state.collected);
}

static void test_punch_task_manager_launch_lifecycle_accounting(void **state UNUSED) {
	uint64_t old_launched = ctx.punch_task_manager_launched;
	uint64_t old_blacklisted = ctx.punch_task_manager_blacklisted;
	uint64_t old_suppressed = ctx.punch_task_manager_suppressed;
	fastd_timeout_t old_next_retry = ctx.punch_task_manager_next_retry;

	ctx.now = 1000;
	ctx.punch_task_manager_launched = 0;
	ctx.punch_task_manager_blacklisted = 0;
	ctx.punch_task_manager_suppressed = 0;
	ctx.punch_task_manager_next_retry = FASTD_TIMEOUT_INV;

	fastd_punch_test_task_manager_record_launch_result(0, 2, 0, FASTD_TIMEOUT_INV);
	assert_int_equal(ctx.punch_task_manager_launched, 1);
	assert_int_equal(ctx.punch_task_manager_blacklisted, 0);
	assert_int_equal(ctx.punch_task_manager_suppressed, 0);
	assert_int_equal(ctx.punch_task_manager_next_retry, FASTD_TIMEOUT_INV);

	fastd_punch_test_task_manager_record_launch_result(2, 2, 4, ctx.now + 8000);
	assert_int_equal(ctx.punch_task_manager_launched, 1);
	assert_int_equal(ctx.punch_task_manager_blacklisted, 1);
	assert_int_equal(ctx.punch_task_manager_suppressed, 0);
	assert_int_equal(ctx.punch_task_manager_next_retry, ctx.now + 8000);

	fastd_punch_test_task_manager_record_launch_result(2, 2, 1, ctx.now + 7000);
	assert_int_equal(ctx.punch_task_manager_blacklisted, 2);
	assert_int_equal(ctx.punch_task_manager_next_retry, ctx.now + 7000);

	fastd_punch_test_task_manager_record_launch_result(2, 2, 0, FASTD_TIMEOUT_INV);
	assert_int_equal(ctx.punch_task_manager_suppressed, 1);

	fastd_punch_test_task_manager_record_launch_result(2, 2, 1, ctx.now - 1);
	assert_int_equal(ctx.punch_task_manager_blacklisted, 3);
	assert_int_equal(ctx.punch_task_manager_next_retry, ctx.now + 7000);

	ctx.punch_task_manager_launched = old_launched;
	ctx.punch_task_manager_blacklisted = old_blacklisted;
	ctx.punch_task_manager_suppressed = old_suppressed;
	ctx.punch_task_manager_next_retry = old_next_retry;
}

static void test_punch_pair_runtime_tracks_inflight_backoff_and_demand(void **state UNUSED) {
	__typeof__(ctx.punch_pair_states) old_pair_states = ctx.punch_pair_states;
	fastd_task_t old_next_maintenance = ctx.next_maintenance;
	fastd_pqueue_t *old_task_queue = ctx.task_queue;
	const fastd_protocol_t *old_protocol = conf.protocol;
	bool old_control_relay = conf.punch_control_relay;
	fastd_punch_pair_task_t old_pair_tasks[FASTD_PUNCH_PAIR_TASK_HISTORY];
	memcpy(old_pair_tasks, ctx.punch_pair_tasks, sizeof(old_pair_tasks));
	uint64_t old_next_pair_task_id = ctx.next_punch_pair_task_id;
	size_t old_pair_task_pos = ctx.punch_pair_task_pos;
	size_t old_pair_task_count = ctx.punch_pair_task_count;
	uint64_t old_aborted = ctx.punch_task_manager_aborted;
	int64_t old_now = ctx.now;

	ctx.punch_pair_states = (__typeof__(ctx.punch_pair_states)){};
	ctx.next_maintenance = (fastd_task_t){};
	ctx.task_queue = NULL;
	memset(ctx.punch_pair_tasks, 0, sizeof(ctx.punch_pair_tasks));
	ctx.next_punch_pair_task_id = 0;
	ctx.punch_pair_task_pos = 0;
	ctx.punch_pair_task_count = 0;
	ctx.punch_task_manager_aborted = 0;
	ctx.now = 1000;
	conf.protocol = &test_protocol;
	conf.punch_control_relay = true;

	fastd_peer_t a = {
		.id = 30,
		.state = STATE_ESTABLISHED,
		.punch_endpoint = addr4(0xcb007105, 41000),
		.punch_timeout = ctx.now + 10000,
		.next_punch_relay = ctx.now + 10000,
	};
	fastd_peer_t b = {
		.id = 20,
		.state = STATE_ESTABLISHED,
		.punch_endpoint = addr4(0xcb007106, 42000),
		.punch_timeout = ctx.now + 10000,
		.next_punch_relay = ctx.now + 10000,
	};

	fastd_punch_test_pair_state_t pair_state = fastd_punch_test_pair_state(&a, &b);
	assert_false(pair_state.collected);
	assert_true(pair_state.waiting);
	assert_false(pair_state.in_flight);
	assert_false(pair_state.backoff);
	assert_false(pair_state.recent_demand);
	assert_int_equal(pair_state.next_retry, ctx.now + 10000);

	fastd_punch_note_peer_pair_demand(&a, &b);
	pair_state = fastd_punch_test_pair_state(&a, &b);
	assert_true(pair_state.collected);
	assert_true(pair_state.recent_demand);
	assert_true(pair_state.pending_demand);
	assert_int_equal(VECTOR_LEN(ctx.punch_pair_states), 1);
	assert_int_equal(VECTOR_INDEX(ctx.punch_pair_states, 0).peer_a_id, 20);
	assert_int_equal(VECTOR_INDEX(ctx.punch_pair_states, 0).peer_b_id, 30);
	assert_int_equal(VECTOR_INDEX(ctx.punch_pair_states, 0).demand_seq, 1);
	assert_int_equal(VECTOR_INDEX(ctx.punch_pair_states, 0).served_demand_seq, 0);
	assert_int_equal(fastd_task_timeout(&ctx.next_maintenance), ctx.now);
	assert_ptr_equal(ctx.task_queue, &ctx.next_maintenance.entry);

	fastd_punch_test_pair_runtime_mark_launched(&a, &b);
	pair_state = fastd_punch_test_pair_state(&a, &b);
	assert_true(pair_state.waiting);
	assert_true(pair_state.in_flight);
	assert_false(pair_state.collected);
	assert_false(pair_state.pending_demand);
	assert_int_equal(pair_state.next_retry, ctx.now + 5000);
	assert_int_equal(VECTOR_INDEX(ctx.punch_pair_states, 0).served_demand_seq, 1);

	fastd_peer_address_t endpoint = addr4(0xcb007105, 41001);
	fastd_punch_test_task_manager_record_pair_result(&a, &b, TEST_PUNCH_RESULT_ACCEPTED, &endpoint);
	pair_state = fastd_punch_test_pair_state(&a, &b);
	assert_true(pair_state.recent_demand);
	assert_false(pair_state.pending_demand);
	assert_false(pair_state.collected);
	assert_true(pair_state.waiting);
	assert_true(pair_state.in_flight);
	assert_int_equal(pair_state.next_retry, ctx.now + FASTD_HOLE_PUNCH_TIMEOUT);

	fastd_punch_note_peer_pair_demand(&a, &b);
	pair_state = fastd_punch_test_pair_state(&a, &b);
	assert_true(pair_state.recent_demand);
	assert_true(pair_state.pending_demand);
	assert_false(pair_state.collected);
	assert_true(pair_state.in_flight);
	assert_int_equal(pair_state.next_retry, ctx.now + FASTD_HOLE_PUNCH_TIMEOUT);
	assert_int_equal(VECTOR_INDEX(ctx.punch_pair_states, 0).demand_seq, 2);
	assert_int_equal(VECTOR_INDEX(ctx.punch_pair_states, 0).served_demand_seq, 1);

	fastd_peer_add_punch_relay_backoff(&a, &endpoint);
	fastd_punch_test_task_manager_record_pair_result(&a, &b, TEST_PUNCH_RESULT_BUSY, &endpoint);
	pair_state = fastd_punch_test_pair_state(&a, &b);
	assert_false(pair_state.collected);
	assert_false(pair_state.waiting);
	assert_true(pair_state.backoff);
	assert_false(pair_state.in_flight);
	assert_int_equal(pair_state.next_retry, ctx.now + FASTD_PUNCH_SUPPRESSION_TIME);
	assert_int_equal(VECTOR_INDEX(ctx.punch_pair_states, 0).result_count, 2);
	assert_int_equal(VECTOR_INDEX(ctx.punch_pair_states, 0).busy_count, 1);

	ctx.now += FASTD_PUNCH_SUPPRESSION_TIME + 1;
	a.next_punch_relay = ctx.now;
	b.next_punch_relay = ctx.now;
	a.punch_timeout = ctx.now + 10000;
	b.punch_timeout = ctx.now + 10000;
	pair_state = fastd_punch_test_pair_state(&a, &b);
	assert_true(pair_state.collected);
	assert_false(pair_state.backoff);

	fastd_punch_test_pair_runtime_mark_launched(&a, &b);
	ctx.now += 5001;
	fastd_punch_test_task_manager_compact_pair_states();
	assert_int_equal(ctx.punch_task_manager_aborted, 1);
	assert_int_equal(ctx.punch_pair_task_count, 3);
	size_t latest_pos =
		(ctx.punch_pair_task_pos + FASTD_PUNCH_PAIR_TASK_HISTORY - 1) % FASTD_PUNCH_PAIR_TASK_HISTORY;
	assert_int_equal(ctx.punch_pair_tasks[latest_pos].stage, PUNCH_PAIR_TASK_STAGE_ABORTED);
	assert_int_equal(ctx.punch_pair_tasks[latest_pos].peer_a_id, 20);
	assert_int_equal(ctx.punch_pair_tasks[latest_pos].peer_b_id, 30);
	assert_int_equal(ctx.punch_pair_tasks[latest_pos].next_retry, ctx.now + FASTD_PUNCH_SUPPRESSION_TIME);
	pair_state = fastd_punch_test_pair_state(&a, &b);
	assert_true(pair_state.backoff);
	assert_false(pair_state.in_flight);
	assert_int_equal(pair_state.next_retry, ctx.now + FASTD_PUNCH_SUPPRESSION_TIME);

	fastd_task_unschedule(&ctx.next_maintenance);
	fastd_task_schedule(&ctx.next_maintenance, TASK_TYPE_MAINTENANCE, ctx.now - 1);
	fastd_punch_note_peer_pair_demand(&a, &b);
	assert_int_equal(fastd_task_timeout(&ctx.next_maintenance), ctx.now - 1);

	fastd_task_unschedule(&ctx.next_maintenance);
	conf.punch_control_relay = false;
	fastd_punch_note_peer_pair_demand(&a, &b);
	assert_int_equal(fastd_task_timeout(&ctx.next_maintenance), FASTD_TIMEOUT_INV);
	assert_null(ctx.task_queue);

	VECTOR_FREE(a.punch_relay_backoffs);
	fastd_task_unschedule(&ctx.next_maintenance);
	VECTOR_FREE(ctx.punch_pair_states);
	ctx.punch_pair_states = old_pair_states;
	ctx.next_maintenance = old_next_maintenance;
	ctx.task_queue = old_task_queue;
	conf.protocol = old_protocol;
	conf.punch_control_relay = old_control_relay;
	memcpy(ctx.punch_pair_tasks, old_pair_tasks, sizeof(ctx.punch_pair_tasks));
	ctx.next_punch_pair_task_id = old_next_pair_task_id;
	ctx.punch_pair_task_pos = old_pair_task_pos;
	ctx.punch_pair_task_count = old_pair_task_count;
	ctx.punch_task_manager_aborted = old_aborted;
	ctx.now = old_now;
}

static void test_punch_task_manager_requests_missing_metadata_on_demand(void **state UNUSED) {
	__typeof__(ctx.peers) old_peers = ctx.peers;
	__typeof__(ctx.punch_pair_states) old_pair_states = ctx.punch_pair_states;
	const fastd_protocol_t *old_protocol = conf.protocol;
	fastd_peer_group_t *old_peer_group = conf.peer_group;
	bool old_control_relay = conf.punch_control_relay;
	unsigned old_announce_interval = conf.punch_announce_interval;
	unsigned old_max_packets = conf.punch_max_packets;
	uint64_t old_runs = ctx.punch_task_manager_runs;
	uint64_t old_pairs = ctx.punch_task_manager_pairs;
	uint64_t old_missing_metadata = ctx.punch_task_manager_missing_metadata;
	uint64_t old_metadata_requests = ctx.punch_task_manager_metadata_requests;
	uint64_t old_metadata_relays = ctx.punch_task_manager_metadata_relays;
	uint64_t old_recent_demand = ctx.punch_task_manager_recent_demand;
	uint64_t old_budget_exhausted = ctx.punch_task_manager_budget_exhausted;
	fastd_timeout_t old_next_retry = ctx.punch_task_manager_next_retry;
	fastd_punch_pair_task_t old_pair_tasks[FASTD_PUNCH_PAIR_TASK_HISTORY];
	memcpy(old_pair_tasks, ctx.punch_pair_tasks, sizeof(old_pair_tasks));
	uint64_t old_next_pair_task_id = ctx.next_punch_pair_task_id;
	size_t old_pair_task_pos = ctx.punch_pair_task_pos;
	size_t old_pair_task_count = ctx.punch_pair_task_count;
	size_t old_encrypt_headroom = conf.encrypt_headroom;
	size_t old_max_buffer = ctx.max_buffer;
	int64_t old_now = ctx.now;

	ctx.peers = (__typeof__(ctx.peers)){};
	ctx.punch_pair_states = (__typeof__(ctx.punch_pair_states)){};
	memset(ctx.punch_pair_tasks, 0, sizeof(ctx.punch_pair_tasks));
	ctx.next_punch_pair_task_id = 0;
	ctx.punch_pair_task_pos = 0;
	ctx.punch_pair_task_count = 0;
	ctx.now = 1000;
	conf.protocol = &test_protocol;
	conf.punch_control_relay = true;
	conf.punch_announce_interval = 15000;
	conf.punch_max_packets = 2;
	conf.encrypt_headroom = 0;
	ctx.max_buffer = 2048;
	test_control_send_peer = NULL;
	test_control_send_count = 0;
	test_control_last_type = 0;
	fastd_init_buffers();

	fastd_peer_group_t group = {
		.transport = TRANSPORT_AUTO,
		.hole_punch = HOLE_PUNCH_AUTO,
		.nat_traversal = FASTD_TRISTATE_TRUE,
	};
	conf.peer_group = &group;

	fastd_peer_t a = {
		.id = 30,
		.group = &group,
		.name = "peer-a",
		.state = STATE_ESTABLISHED,
		.address = addr4(0xcb007105, 41000),
		.next_punch_metadata_request = ctx.now,
	};
	fastd_peer_t b = {
		.id = 20,
		.group = &group,
		.name = "peer-b",
		.state = STATE_ESTABLISHED,
		.address = addr4(0xcb007106, 42000),
		.next_punch_metadata_request = ctx.now,
	};
	VECTOR_ADD(ctx.peers, &a);
	VECTOR_ADD(ctx.peers, &b);

	fastd_punch_note_peer_pair_demand(&a, &b);
	fastd_punch_test_relay_peer_endpoints();
	assert_int_equal(ctx.punch_task_manager_pairs, 1);
	assert_int_equal(ctx.punch_task_manager_missing_metadata, 1);
	assert_int_equal(ctx.punch_task_manager_recent_demand, 1);
	assert_int_equal(ctx.punch_task_manager_metadata_requests, 2);
	assert_int_equal(test_control_send_count, 2);
	assert_int_equal(test_control_last_type, TEST_PUNCH_SELECT_LISTENER);
	assert_ptr_equal(test_control_send_peer, &b);
	assert_int_equal(a.next_punch_metadata_request, ctx.now + conf.punch_announce_interval);
	assert_int_equal(b.next_punch_metadata_request, ctx.now + conf.punch_announce_interval);
	assert_int_equal(ctx.punch_task_manager_next_retry, ctx.now + conf.punch_announce_interval);
	assert_int_equal(ctx.punch_task_manager_budget_exhausted, 1);
	assert_int_equal(ctx.punch_pair_task_count, 1);
	size_t latest_pos =
		(ctx.punch_pair_task_pos + FASTD_PUNCH_PAIR_TASK_HISTORY - 1) % FASTD_PUNCH_PAIR_TASK_HISTORY;
	assert_int_equal(ctx.punch_pair_tasks[latest_pos].stage, PUNCH_PAIR_TASK_STAGE_METADATA_REQUESTED);
	assert_int_equal(ctx.punch_pair_tasks[latest_pos].candidates_sent, 2);
	assert_true(ctx.punch_pair_tasks[latest_pos].budget_exhausted);

	test_control_send_count = 0;
	fastd_punch_test_relay_peer_endpoints();
	assert_int_equal(ctx.punch_task_manager_pairs, 1);
	assert_int_equal(ctx.punch_task_manager_missing_metadata, 1);
	assert_int_equal(ctx.punch_task_manager_metadata_requests, 0);
	assert_int_equal(test_control_send_count, 0);
	assert_int_equal(ctx.punch_task_manager_next_retry, ctx.now + conf.punch_announce_interval);
	latest_pos = (ctx.punch_pair_task_pos + FASTD_PUNCH_PAIR_TASK_HISTORY - 1) % FASTD_PUNCH_PAIR_TASK_HISTORY;
	assert_int_equal(ctx.punch_pair_tasks[latest_pos].stage, PUNCH_PAIR_TASK_STAGE_MISSING_METADATA);

	a.next_punch_metadata_request = ctx.now;
	b.next_punch_metadata_request = ctx.now;
	test_control_send_count = 0;
	conf.punch_control_relay = false;
	fastd_punch_test_relay_peer_endpoints();
	assert_int_equal(test_control_send_count, 0);

	VECTOR_FREE(ctx.peers);
	VECTOR_FREE(ctx.punch_pair_states);
	ctx.peers = old_peers;
	ctx.punch_pair_states = old_pair_states;
	conf.protocol = old_protocol;
	conf.peer_group = old_peer_group;
	conf.punch_control_relay = old_control_relay;
	conf.punch_announce_interval = old_announce_interval;
	conf.punch_max_packets = old_max_packets;
	conf.encrypt_headroom = old_encrypt_headroom;
	ctx.max_buffer = old_max_buffer;
	ctx.punch_task_manager_runs = old_runs;
	ctx.punch_task_manager_pairs = old_pairs;
	ctx.punch_task_manager_missing_metadata = old_missing_metadata;
	ctx.punch_task_manager_metadata_requests = old_metadata_requests;
	ctx.punch_task_manager_metadata_relays = old_metadata_relays;
	ctx.punch_task_manager_recent_demand = old_recent_demand;
	ctx.punch_task_manager_budget_exhausted = old_budget_exhausted;
	ctx.punch_task_manager_next_retry = old_next_retry;
	memcpy(ctx.punch_pair_tasks, old_pair_tasks, sizeof(ctx.punch_pair_tasks));
	ctx.next_punch_pair_task_id = old_next_pair_task_id;
	ctx.punch_pair_task_pos = old_pair_task_pos;
	ctx.punch_pair_task_count = old_pair_task_count;
	ctx.now = old_now;
	test_control_send_peer = NULL;
	test_control_send_count = 0;
	test_control_last_type = 0;
	fastd_cleanup_buffers();
}

static void test_punch_task_manager_requests_partial_symmetric_metadata(void **state UNUSED) {
	__typeof__(ctx.peers) old_peers = ctx.peers;
	__typeof__(ctx.punch_pair_states) old_pair_states = ctx.punch_pair_states;
	const fastd_protocol_t *old_protocol = conf.protocol;
	fastd_peer_group_t *old_peer_group = conf.peer_group;
	bool old_control_relay = conf.punch_control_relay;
	bool old_punch_symmetric = conf.punch_symmetric;
	unsigned old_announce_interval = conf.punch_announce_interval;
	unsigned old_max_packets = conf.punch_max_packets;
	size_t old_encrypt_headroom = conf.encrypt_headroom;
	size_t old_max_buffer = ctx.max_buffer;
	uint64_t old_runs = ctx.punch_task_manager_runs;
	uint64_t old_pairs = ctx.punch_task_manager_pairs;
	uint64_t old_collected = ctx.punch_task_manager_collected;
	uint64_t old_launched = ctx.punch_task_manager_launched;
	uint64_t old_waiting = ctx.punch_task_manager_waiting;
	uint64_t old_in_flight = ctx.punch_task_manager_in_flight;
	uint64_t old_missing_metadata = ctx.punch_task_manager_missing_metadata;
	uint64_t old_metadata_requests = ctx.punch_task_manager_metadata_requests;
	uint64_t old_metadata_relays = ctx.punch_task_manager_metadata_relays;
	uint64_t old_blacklisted = ctx.punch_task_manager_blacklisted;
	uint64_t old_suppressed = ctx.punch_task_manager_suppressed;
	uint64_t old_aborted = ctx.punch_task_manager_aborted;
	uint64_t old_recent_demand = ctx.punch_task_manager_recent_demand;
	uint64_t old_budget_exhausted = ctx.punch_task_manager_budget_exhausted;
	fastd_timeout_t old_next_retry = ctx.punch_task_manager_next_retry;
	fastd_punch_pair_task_t old_pair_tasks[FASTD_PUNCH_PAIR_TASK_HISTORY];
	memcpy(old_pair_tasks, ctx.punch_pair_tasks, sizeof(old_pair_tasks));
	uint64_t old_next_pair_task_id = ctx.next_punch_pair_task_id;
	size_t old_pair_task_pos = ctx.punch_pair_task_pos;
	size_t old_pair_task_count = ctx.punch_pair_task_count;
	int64_t old_now = ctx.now;

	ctx.peers = (__typeof__(ctx.peers)){};
	ctx.punch_pair_states = (__typeof__(ctx.punch_pair_states)){};
	memset(ctx.punch_pair_tasks, 0, sizeof(ctx.punch_pair_tasks));
	ctx.next_punch_pair_task_id = 0;
	ctx.punch_pair_task_pos = 0;
	ctx.punch_pair_task_count = 0;
	ctx.now = 1000;
	conf.protocol = &test_protocol;
	conf.punch_control_relay = true;
	conf.punch_symmetric = true;
	conf.punch_announce_interval = 15000;
	conf.punch_max_packets = 4;
	conf.encrypt_headroom = 0;
	ctx.max_buffer = 2048;
	test_reset_control_sends();
	fastd_init_buffers();

	fastd_peer_group_t group = {
		.transport = TRANSPORT_AUTO,
		.hole_punch = HOLE_PUNCH_AUTO,
		.nat_traversal = FASTD_TRISTATE_TRUE,
	};
	conf.peer_group = &group;

	fastd_peer_t a = {
		.id = 30,
		.group = &group,
		.name = "peer-a",
		.state = STATE_ESTABLISHED,
		.address = addr4(0xcb007105, 41000),
		.punch_endpoint = addr4(0xc6336407, 51000),
		.punch_nat_type = FASTD_NAT_SYMMETRIC_EASY_INC,
		.punch_min_port = 51000,
		.punch_max_port = 51000,
		.punch_port_delta = 1,
		.punch_timeout = ctx.now + 10000,
		.next_punch_relay = ctx.now,
	};
	fastd_peer_t b = {
		.id = 20,
		.group = &group,
		.name = "peer-b",
		.state = STATE_ESTABLISHED,
		.address = addr4(0xcb007106, 42000),
		.next_punch_metadata_request = ctx.now,
		.next_punch_relay = ctx.now,
	};
	VECTOR_ADD(ctx.peers, &a);
	VECTOR_ADD(ctx.peers, &b);

	fastd_punch_test_pair_state_t pair_state = fastd_punch_test_pair_state(&a, &b);
	assert_true(pair_state.established);
	assert_true(pair_state.has_metadata_a);
	assert_false(pair_state.has_metadata_b);
	assert_true(pair_state.missing_metadata);
	assert_true(pair_state.collected);

	fastd_punch_test_relay_peer_endpoints();
	assert_int_equal(ctx.punch_task_manager_missing_metadata, 1);
	assert_int_equal(ctx.punch_task_manager_metadata_requests, 1);
	assert_int_equal(ctx.punch_task_manager_metadata_relays, 1);
	assert_int_equal(test_control_send_count, 2);
	assert_ptr_equal(test_control_send_peers[0], &b);
	assert_ptr_equal(test_control_send_peers[1], &b);
	assert_int_equal(test_control_send_types[0], TEST_PUNCH_SELECT_LISTENER);
	assert_int_equal(test_control_send_types[1], TEST_PUNCH_NAT_INFO);
	assert_int_equal(test_control_send_ports[0], 42000);
	assert_int_equal(test_control_send_ports[1], 51000);
	assert_int_equal(b.next_punch_metadata_request, ctx.now + conf.punch_announce_interval);
	assert_int_equal(ctx.punch_task_manager_budget_exhausted, 0);
	assert_int_equal(ctx.punch_pair_task_count, 1);
	size_t latest_pos =
		(ctx.punch_pair_task_pos + FASTD_PUNCH_PAIR_TASK_HISTORY - 1) % FASTD_PUNCH_PAIR_TASK_HISTORY;
	assert_int_equal(ctx.punch_pair_tasks[latest_pos].stage, PUNCH_PAIR_TASK_STAGE_METADATA_REQUESTED);
	assert_int_equal(ctx.punch_pair_tasks[latest_pos].candidates_sent, 2);

	VECTOR_FREE(ctx.peers);
	VECTOR_FREE(ctx.punch_pair_states);
	ctx.peers = old_peers;
	ctx.punch_pair_states = old_pair_states;
	conf.protocol = old_protocol;
	conf.peer_group = old_peer_group;
	conf.punch_control_relay = old_control_relay;
	conf.punch_symmetric = old_punch_symmetric;
	conf.punch_announce_interval = old_announce_interval;
	conf.punch_max_packets = old_max_packets;
	conf.encrypt_headroom = old_encrypt_headroom;
	ctx.max_buffer = old_max_buffer;
	ctx.punch_task_manager_runs = old_runs;
	ctx.punch_task_manager_pairs = old_pairs;
	ctx.punch_task_manager_collected = old_collected;
	ctx.punch_task_manager_launched = old_launched;
	ctx.punch_task_manager_waiting = old_waiting;
	ctx.punch_task_manager_in_flight = old_in_flight;
	ctx.punch_task_manager_missing_metadata = old_missing_metadata;
	ctx.punch_task_manager_metadata_requests = old_metadata_requests;
	ctx.punch_task_manager_metadata_relays = old_metadata_relays;
	ctx.punch_task_manager_blacklisted = old_blacklisted;
	ctx.punch_task_manager_suppressed = old_suppressed;
	ctx.punch_task_manager_aborted = old_aborted;
	ctx.punch_task_manager_recent_demand = old_recent_demand;
	ctx.punch_task_manager_budget_exhausted = old_budget_exhausted;
	ctx.punch_task_manager_next_retry = old_next_retry;
	memcpy(ctx.punch_pair_tasks, old_pair_tasks, sizeof(old_pair_tasks));
	ctx.next_punch_pair_task_id = old_next_pair_task_id;
	ctx.punch_pair_task_pos = old_pair_task_pos;
	ctx.punch_pair_task_count = old_pair_task_count;
	ctx.now = old_now;
	test_reset_control_sends();
	fastd_cleanup_buffers();
}

static void test_punch_task_manager_prewarms_relayed_nat_metadata(void **state UNUSED) {
	__typeof__(ctx.peers) old_peers = ctx.peers;
	__typeof__(ctx.punch_pair_states) old_pair_states = ctx.punch_pair_states;
	const fastd_protocol_t *old_protocol = conf.protocol;
	fastd_peer_group_t *old_peer_group = conf.peer_group;
	bool old_control_relay = conf.punch_control_relay;
	unsigned old_relay_interval = conf.punch_relay_interval;
	unsigned old_max_packets = conf.punch_max_packets;
	size_t old_encrypt_headroom = conf.encrypt_headroom;
	size_t old_max_buffer = ctx.max_buffer;
	uint64_t old_runs = ctx.punch_task_manager_runs;
	uint64_t old_pairs = ctx.punch_task_manager_pairs;
	uint64_t old_collected = ctx.punch_task_manager_collected;
	uint64_t old_launched = ctx.punch_task_manager_launched;
	uint64_t old_metadata_relays = ctx.punch_task_manager_metadata_relays;
	uint64_t old_budget_exhausted = ctx.punch_task_manager_budget_exhausted;
	fastd_timeout_t old_next_retry = ctx.punch_task_manager_next_retry;
	fastd_punch_pair_task_t old_pair_tasks[FASTD_PUNCH_PAIR_TASK_HISTORY];
	memcpy(old_pair_tasks, ctx.punch_pair_tasks, sizeof(old_pair_tasks));
	uint64_t old_next_pair_task_id = ctx.next_punch_pair_task_id;
	size_t old_pair_task_pos = ctx.punch_pair_task_pos;
	size_t old_pair_task_count = ctx.punch_pair_task_count;
	int64_t old_now = ctx.now;

	ctx.peers = (__typeof__(ctx.peers)){};
	ctx.punch_pair_states = (__typeof__(ctx.punch_pair_states)){};
	memset(ctx.punch_pair_tasks, 0, sizeof(ctx.punch_pair_tasks));
	ctx.next_punch_pair_task_id = 0;
	ctx.punch_pair_task_pos = 0;
	ctx.punch_pair_task_count = 0;
	ctx.now = 1000;
	conf.protocol = &test_protocol;
	conf.punch_control_relay = true;
	conf.punch_relay_interval = 7000;
	conf.punch_max_packets = 8;
	conf.encrypt_headroom = 0;
	ctx.max_buffer = 2048;
	test_reset_control_sends();
	fastd_init_buffers();

	fastd_peer_group_t group = {
		.transport = TRANSPORT_AUTO,
		.hole_punch = HOLE_PUNCH_AUTO,
		.nat_traversal = FASTD_TRISTATE_TRUE,
	};
	conf.peer_group = &group;

	fastd_peer_t a = {
		.id = 30,
		.group = &group,
		.name = "peer-a",
		.state = STATE_ESTABLISHED,
		.address = addr4(0xcb007105, 41000),
		.punch_endpoint = addr4(0xc6336407, 51000),
		.punch_nat_type = FASTD_NAT_FULL_CONE,
		.punch_min_port = 51000,
		.punch_max_port = 51000,
		.punch_timeout = ctx.now + 10000,
		.tcp_punch_endpoint = addr4(0xc6336407, 53000),
		.n_tcp_punch_endpoints = 1,
		.tcp_punch_nat_type = FASTD_NAT_FULL_CONE,
		.tcp_punch_min_port = 53000,
		.tcp_punch_max_port = 53000,
		.tcp_punch_timeout = ctx.now + 10000,
		.next_punch_relay = ctx.now,
	};
	a.tcp_punch_endpoints[0] = a.tcp_punch_endpoint;
	fastd_peer_t b = {
		.id = 20,
		.group = &group,
		.name = "peer-b",
		.state = STATE_ESTABLISHED,
		.address = addr4(0xcb007106, 42000),
		.punch_endpoint = addr4(0xc6336408, 52000),
		.punch_nat_type = FASTD_NAT_FULL_CONE,
		.punch_min_port = 52000,
		.punch_max_port = 52000,
		.punch_timeout = ctx.now + 10000,
		.tcp_punch_endpoint = addr4(0xc6336408, 54000),
		.n_tcp_punch_endpoints = 1,
		.tcp_punch_nat_type = FASTD_NAT_FULL_CONE,
		.tcp_punch_min_port = 54000,
		.tcp_punch_max_port = 54000,
		.tcp_punch_timeout = ctx.now + 10000,
		.next_punch_relay = ctx.now,
	};
	b.tcp_punch_endpoints[0] = b.tcp_punch_endpoint;

	VECTOR_ADD(ctx.peers, &a);
	VECTOR_ADD(ctx.peers, &b);

	fastd_punch_test_relay_peer_endpoints();
	assert_int_equal(ctx.punch_task_manager_pairs, 1);
	assert_int_equal(ctx.punch_task_manager_collected, 1);
	assert_int_equal(ctx.punch_task_manager_launched, 1);
	assert_int_equal(ctx.punch_task_manager_metadata_relays, 2);
	assert_int_equal(ctx.punch_task_manager_budget_exhausted, 1);
	assert_int_equal(test_control_send_count, 8);
	assert_ptr_equal(test_control_send_peers[0], &b);
	assert_ptr_equal(test_control_send_peers[1], &b);
	assert_ptr_equal(test_control_send_peers[2], &b);
	assert_ptr_equal(test_control_send_peers[3], &a);
	assert_ptr_equal(test_control_send_peers[4], &a);
	assert_ptr_equal(test_control_send_peers[5], &a);
	assert_ptr_equal(test_control_send_peers[6], &b);
	assert_ptr_equal(test_control_send_peers[7], &b);
	assert_int_equal(test_control_send_types[0], TEST_PUNCH_SEND_CONE);
	assert_int_equal(test_control_send_types[1], TEST_PUNCH_SEND_CONE);
	assert_int_equal(test_control_send_types[2], TEST_PUNCH_SEND_TCP);
	assert_int_equal(test_control_send_types[3], TEST_PUNCH_SEND_CONE);
	assert_int_equal(test_control_send_types[4], TEST_PUNCH_SEND_CONE);
	assert_int_equal(test_control_send_types[5], TEST_PUNCH_SEND_TCP);
	assert_int_equal(test_control_send_types[6], TEST_PUNCH_NAT_INFO);
	assert_int_equal(test_control_send_types[7], TEST_PUNCH_TCP_NAT_INFO);
	assert_int_equal(test_control_send_ports[0], 41000);
	assert_int_equal(test_control_send_ports[1], 51000);
	assert_int_equal(test_control_send_ports[2], 53000);
	assert_int_equal(test_control_send_ports[3], 42000);
	assert_int_equal(test_control_send_ports[4], 52000);
	assert_int_equal(test_control_send_ports[5], 54000);
	assert_int_equal(test_control_send_ports[6], 51000);
	assert_int_equal(test_control_send_ports[7], 53000);

	VECTOR_FREE(ctx.peers);
	VECTOR_FREE(ctx.punch_pair_states);
	ctx.peers = old_peers;
	ctx.punch_pair_states = old_pair_states;
	conf.protocol = old_protocol;
	conf.peer_group = old_peer_group;
	conf.punch_control_relay = old_control_relay;
	conf.punch_relay_interval = old_relay_interval;
	conf.punch_max_packets = old_max_packets;
	conf.encrypt_headroom = old_encrypt_headroom;
	ctx.max_buffer = old_max_buffer;
	ctx.punch_task_manager_runs = old_runs;
	ctx.punch_task_manager_pairs = old_pairs;
	ctx.punch_task_manager_collected = old_collected;
	ctx.punch_task_manager_launched = old_launched;
	ctx.punch_task_manager_metadata_relays = old_metadata_relays;
	ctx.punch_task_manager_budget_exhausted = old_budget_exhausted;
	ctx.punch_task_manager_next_retry = old_next_retry;
	memcpy(ctx.punch_pair_tasks, old_pair_tasks, sizeof(old_pair_tasks));
	ctx.next_punch_pair_task_id = old_next_pair_task_id;
	ctx.punch_pair_task_pos = old_pair_task_pos;
	ctx.punch_pair_task_count = old_pair_task_count;
	ctx.now = old_now;
	test_reset_control_sends();
	fastd_cleanup_buffers();
}

static void test_punch_task_manager_skips_endpoint_dependent_post_command_prewarm(void **state UNUSED) {
	__typeof__(ctx.peers) old_peers = ctx.peers;
	__typeof__(ctx.punch_pair_states) old_pair_states = ctx.punch_pair_states;
	const fastd_protocol_t *old_protocol = conf.protocol;
	fastd_peer_group_t *old_peer_group = conf.peer_group;
	bool old_control_relay = conf.punch_control_relay;
	bool old_punch_symmetric = conf.punch_symmetric;
	unsigned old_relay_interval = conf.punch_relay_interval;
	unsigned old_max_packets = conf.punch_max_packets;
	size_t old_encrypt_headroom = conf.encrypt_headroom;
	size_t old_max_buffer = ctx.max_buffer;
	uint64_t old_runs = ctx.punch_task_manager_runs;
	uint64_t old_pairs = ctx.punch_task_manager_pairs;
	uint64_t old_collected = ctx.punch_task_manager_collected;
	uint64_t old_launched = ctx.punch_task_manager_launched;
	uint64_t old_metadata_relays = ctx.punch_task_manager_metadata_relays;
	uint64_t old_budget_exhausted = ctx.punch_task_manager_budget_exhausted;
	fastd_timeout_t old_next_retry = ctx.punch_task_manager_next_retry;
	fastd_punch_pair_task_t old_pair_tasks[FASTD_PUNCH_PAIR_TASK_HISTORY];
	memcpy(old_pair_tasks, ctx.punch_pair_tasks, sizeof(old_pair_tasks));
	uint64_t old_next_pair_task_id = ctx.next_punch_pair_task_id;
	size_t old_pair_task_pos = ctx.punch_pair_task_pos;
	size_t old_pair_task_count = ctx.punch_pair_task_count;
	int64_t old_now = ctx.now;

	ctx.peers = (__typeof__(ctx.peers)){};
	ctx.punch_pair_states = (__typeof__(ctx.punch_pair_states)){};
	memset(ctx.punch_pair_tasks, 0, sizeof(ctx.punch_pair_tasks));
	ctx.next_punch_pair_task_id = 0;
	ctx.punch_pair_task_pos = 0;
	ctx.punch_pair_task_count = 0;
	ctx.now = 1000;
	conf.protocol = &test_protocol;
	conf.punch_control_relay = true;
	conf.punch_symmetric = true;
	conf.punch_relay_interval = 7000;
	conf.punch_max_packets = 32;
	conf.encrypt_headroom = 0;
	ctx.max_buffer = 2048;
	test_reset_control_sends();
	fastd_init_buffers();

	fastd_peer_group_t group = {
		.transport = TRANSPORT_AUTO,
		.hole_punch = HOLE_PUNCH_AUTO,
		.nat_traversal = FASTD_TRISTATE_TRUE,
	};
	conf.peer_group = &group;

	fastd_peer_t a = {
		.id = 30,
		.group = &group,
		.name = "peer-a",
		.state = STATE_ESTABLISHED,
		.address = addr4(0xcb007105, 41000),
		.punch_endpoint = addr4(0xc6336407, 51000),
		.punch_nat_type = FASTD_NAT_SYMMETRIC_EASY_INC,
		.punch_min_port = 51000,
		.punch_max_port = 51000,
		.punch_port_delta = 1,
		.punch_timeout = ctx.now + 10000,
		.next_punch_relay = ctx.now,
	};
	fastd_peer_t b = {
		.id = 20,
		.group = &group,
		.name = "peer-b",
		.state = STATE_ESTABLISHED,
		.address = addr4(0xcb007106, 42000),
		.punch_endpoint = addr4(0xc6336408, 52000),
		.punch_nat_type = FASTD_NAT_FULL_CONE,
		.punch_min_port = 52000,
		.punch_max_port = 52000,
		.punch_timeout = ctx.now + 10000,
		.next_punch_relay = ctx.now,
	};

	VECTOR_ADD(ctx.peers, &a);
	VECTOR_ADD(ctx.peers, &b);

	fastd_punch_test_relay_peer_endpoints();
	assert_int_equal(ctx.punch_task_manager_pairs, 1);
	assert_int_equal(ctx.punch_task_manager_collected, 1);
	assert_int_equal(ctx.punch_task_manager_launched, 1);
	assert_int_equal(ctx.punch_task_manager_metadata_relays, 1);
	assert_int_equal(ctx.punch_task_manager_budget_exhausted, 0);
	assert_true(test_control_send_count < conf.punch_max_packets);

	bool saw_stable_nat_info = false;
	bool saw_endpoint_dependent_nat_info = false;
	size_t i;
	for (i = 0; i < test_control_send_count && i < TEST_CONTROL_HISTORY; i++) {
		if (test_control_send_types[i] != TEST_PUNCH_NAT_INFO)
			continue;

		if (test_control_send_ports[i] == 52000)
			saw_stable_nat_info = true;
		if (test_control_send_ports[i] == 51000)
			saw_endpoint_dependent_nat_info = true;
	}
	assert_true(saw_stable_nat_info);
	assert_false(saw_endpoint_dependent_nat_info);

	VECTOR_FREE(ctx.peers);
	VECTOR_FREE(ctx.punch_pair_states);
	ctx.peers = old_peers;
	ctx.punch_pair_states = old_pair_states;
	conf.protocol = old_protocol;
	conf.peer_group = old_peer_group;
	conf.punch_control_relay = old_control_relay;
	conf.punch_symmetric = old_punch_symmetric;
	conf.punch_relay_interval = old_relay_interval;
	conf.punch_max_packets = old_max_packets;
	conf.encrypt_headroom = old_encrypt_headroom;
	ctx.max_buffer = old_max_buffer;
	ctx.punch_task_manager_runs = old_runs;
	ctx.punch_task_manager_pairs = old_pairs;
	ctx.punch_task_manager_collected = old_collected;
	ctx.punch_task_manager_launched = old_launched;
	ctx.punch_task_manager_metadata_relays = old_metadata_relays;
	ctx.punch_task_manager_budget_exhausted = old_budget_exhausted;
	ctx.punch_task_manager_next_retry = old_next_retry;
	memcpy(ctx.punch_pair_tasks, old_pair_tasks, sizeof(old_pair_tasks));
	ctx.next_punch_pair_task_id = old_next_pair_task_id;
	ctx.punch_pair_task_pos = old_pair_task_pos;
	ctx.punch_pair_task_count = old_pair_task_count;
	ctx.now = old_now;
	test_reset_control_sends();
	fastd_cleanup_buffers();
}

static void test_punch_task_manager_relays_multiple_tcp_endpoints_with_budget(void **state UNUSED) {
	__typeof__(ctx.peers) old_peers = ctx.peers;
	__typeof__(ctx.punch_pair_states) old_pair_states = ctx.punch_pair_states;
	const fastd_protocol_t *old_protocol = conf.protocol;
	fastd_peer_group_t *old_peer_group = conf.peer_group;
	bool old_control_relay = conf.punch_control_relay;
	unsigned old_relay_interval = conf.punch_relay_interval;
	unsigned old_max_packets = conf.punch_max_packets;
	size_t old_encrypt_headroom = conf.encrypt_headroom;
	size_t old_max_buffer = ctx.max_buffer;
	uint64_t old_tx = ctx.punch_control_tx;
	uint64_t old_budget_exhausted = ctx.punch_task_manager_budget_exhausted;
	fastd_timeout_t old_next_retry = ctx.punch_task_manager_next_retry;
	fastd_punch_pair_task_t old_pair_tasks[FASTD_PUNCH_PAIR_TASK_HISTORY];
	memcpy(old_pair_tasks, ctx.punch_pair_tasks, sizeof(old_pair_tasks));
	uint64_t old_next_pair_task_id = ctx.next_punch_pair_task_id;
	size_t old_pair_task_pos = ctx.punch_pair_task_pos;
	size_t old_pair_task_count = ctx.punch_pair_task_count;
	int64_t old_now = ctx.now;

	ctx.peers = (__typeof__(ctx.peers)){};
	ctx.punch_pair_states = (__typeof__(ctx.punch_pair_states)){};
	memset(ctx.punch_pair_tasks, 0, sizeof(ctx.punch_pair_tasks));
	ctx.next_punch_pair_task_id = 0;
	ctx.punch_pair_task_pos = 0;
	ctx.punch_pair_task_count = 0;
	ctx.now = 1000;
	conf.protocol = &test_protocol;
	conf.punch_control_relay = true;
	conf.punch_relay_interval = 7000;
	conf.punch_max_packets = 3;
	conf.encrypt_headroom = 0;
	ctx.max_buffer = 2048;
	test_reset_control_sends();
	fastd_init_buffers();

	fastd_peer_group_t group = {
		.transport = TRANSPORT_AUTO,
		.hole_punch = HOLE_PUNCH_AUTO,
		.nat_traversal = FASTD_TRISTATE_TRUE,
	};
	conf.peer_group = &group;

	fastd_peer_t a = {
		.id = 30,
		.group = &group,
		.name = "peer-a",
		.state = STATE_ESTABLISHED,
		.address = addr4(0xcb007105, 41000),
		.tcp_punch_endpoint = addr4(0xc6336407, 51000),
		.n_tcp_punch_endpoints = 4,
		.tcp_punch_nat_type = FASTD_NAT_FULL_CONE,
		.tcp_punch_min_port = 51000,
		.tcp_punch_max_port = 51003,
		.tcp_punch_timeout = ctx.now + 10000,
		.next_punch_relay = ctx.now,
	};
	a.tcp_punch_endpoints[0] = a.tcp_punch_endpoint;
	a.tcp_punch_endpoints[1] = addr4(0xc6336407, 51001);
	a.tcp_punch_endpoints[2] = addr4(0xc6336407, 51002);
	a.tcp_punch_endpoints[3] = addr4(0xc6336407, 51003);

	fastd_peer_t b = {
		.id = 20,
		.group = &group,
		.name = "peer-b",
		.state = STATE_ESTABLISHED,
		.address = addr4(0xcb007106, 42000),
		.tcp_punch_endpoint = addr4(0xc6336408, 52000),
		.n_tcp_punch_endpoints = 1,
		.tcp_punch_nat_type = FASTD_NAT_FULL_CONE,
		.tcp_punch_min_port = 52000,
		.tcp_punch_max_port = 52000,
		.tcp_punch_timeout = ctx.now + 10000,
		.next_punch_relay = ctx.now,
	};
	b.tcp_punch_endpoints[0] = b.tcp_punch_endpoint;

	VECTOR_ADD(ctx.peers, &a);
	VECTOR_ADD(ctx.peers, &b);

	fastd_punch_test_relay_peer_endpoints();
	assert_int_equal(test_control_send_count, 3);
	assert_ptr_equal(test_control_send_peers[0], &b);
	assert_ptr_equal(test_control_send_peers[1], &b);
	assert_ptr_equal(test_control_send_peers[2], &b);
	assert_int_equal(test_control_send_types[0], TEST_PUNCH_SEND_CONE);
	assert_int_equal(test_control_send_types[1], TEST_PUNCH_SEND_TCP);
	assert_int_equal(test_control_send_types[2], TEST_PUNCH_SEND_TCP);
	assert_int_equal(test_control_send_ports[0], 41000);
	assert_int_equal(test_control_send_ports[1], 51000);
	assert_int_equal(test_control_send_ports[2], 51001);
	assert_int_equal(ctx.punch_task_manager_budget_exhausted, 1);
	assert_int_equal(ctx.punch_pair_task_count, 2);
	size_t latest_pos =
		(ctx.punch_pair_task_pos + FASTD_PUNCH_PAIR_TASK_HISTORY - 1) % FASTD_PUNCH_PAIR_TASK_HISTORY;
	assert_int_equal(ctx.punch_pair_tasks[latest_pos].stage, PUNCH_PAIR_TASK_STAGE_LAUNCHED);
	assert_int_equal(ctx.punch_pair_tasks[latest_pos].subject_id, a.id);
	assert_int_equal(ctx.punch_pair_tasks[latest_pos].destination_id, b.id);
	assert_int_equal(ctx.punch_pair_tasks[latest_pos].candidates_sent, 3);
	assert_true(ctx.punch_pair_tasks[latest_pos].budget_exhausted);
	assert_int_equal(a.last_punch_task.command, PEER_PUNCH_TASK_COMMAND_TCP);
	assert_int_equal(a.last_punch_task.candidate_count, 4);
	assert_int_equal(a.last_punch_task.candidates_sent, 2);
	assert_int_equal(port4(&a.last_punch_task.endpoint), 51001);
	assert_int_equal(b.last_punch_task.command, PEER_PUNCH_TASK_COMMAND_TCP);
	assert_int_equal(b.last_punch_task.candidate_count, 4);
	assert_int_equal(b.last_punch_task.candidates_sent, 2);
	assert_int_equal(port4(&b.last_punch_task.endpoint), 51001);

	VECTOR_FREE(ctx.peers);
	VECTOR_FREE(ctx.punch_pair_states);
	ctx.peers = old_peers;
	ctx.punch_pair_states = old_pair_states;
	conf.protocol = old_protocol;
	conf.peer_group = old_peer_group;
	conf.punch_control_relay = old_control_relay;
	conf.punch_relay_interval = old_relay_interval;
	conf.punch_max_packets = old_max_packets;
	conf.encrypt_headroom = old_encrypt_headroom;
	ctx.max_buffer = old_max_buffer;
	ctx.punch_control_tx = old_tx;
	ctx.punch_task_manager_budget_exhausted = old_budget_exhausted;
	ctx.punch_task_manager_next_retry = old_next_retry;
	memcpy(ctx.punch_pair_tasks, old_pair_tasks, sizeof(ctx.punch_pair_tasks));
	ctx.next_punch_pair_task_id = old_next_pair_task_id;
	ctx.punch_pair_task_pos = old_pair_task_pos;
	ctx.punch_pair_task_count = old_pair_task_count;
	ctx.now = old_now;
	test_reset_control_sends();
	fastd_cleanup_buffers();
}

static void test_punch_task_manager_tcp_only_skips_udp_commands(void **state UNUSED) {
	__typeof__(ctx.peers) old_peers = ctx.peers;
	__typeof__(ctx.punch_pair_states) old_pair_states = ctx.punch_pair_states;
	const fastd_protocol_t *old_protocol = conf.protocol;
	fastd_peer_group_t *old_peer_group = conf.peer_group;
	bool old_control_relay = conf.punch_control_relay;
	unsigned old_relay_interval = conf.punch_relay_interval;
	unsigned old_max_packets = conf.punch_max_packets;
	size_t old_encrypt_headroom = conf.encrypt_headroom;
	size_t old_max_buffer = ctx.max_buffer;
	int64_t old_now = ctx.now;

	ctx.peers = (__typeof__(ctx.peers)){};
	ctx.punch_pair_states = (__typeof__(ctx.punch_pair_states)){};
	ctx.now = 1000;
	conf.protocol = &test_protocol;
	conf.punch_control_relay = true;
	conf.punch_relay_interval = 7000;
	conf.punch_max_packets = 8;
	conf.encrypt_headroom = 0;
	ctx.max_buffer = 2048;
	test_reset_control_sends();
	fastd_init_buffers();

	fastd_peer_group_t group = {
		.transport = TRANSPORT_TCP,
		.hole_punch = HOLE_PUNCH_TCP,
		.nat_traversal = FASTD_TRISTATE_TRUE,
	};
	conf.peer_group = &group;

	fastd_peer_t a = {
		.id = 30,
		.group = &group,
		.name = "peer-a",
		.state = STATE_ESTABLISHED,
		.address = addr4(0xcb007105, 41000),
		.punch_endpoint = addr4(0xc6336407, 51010),
		.punch_nat_type = FASTD_NAT_FULL_CONE,
		.punch_min_port = 51010,
		.punch_max_port = 51010,
		.punch_timeout = ctx.now + 10000,
		.tcp_punch_endpoint = addr4(0xc6336407, 51000),
		.n_tcp_punch_endpoints = 1,
		.tcp_punch_nat_type = FASTD_NAT_FULL_CONE,
		.tcp_punch_min_port = 51000,
		.tcp_punch_max_port = 51000,
		.tcp_punch_timeout = ctx.now + 10000,
		.next_punch_relay = ctx.now,
	};
	a.punch_endpoints[0] = (fastd_peer_punch_endpoint_t){
		.address = a.punch_endpoint,
		.nat_type = a.punch_nat_type,
		.min_port = a.punch_min_port,
		.max_port = a.punch_max_port,
	};
	a.n_punch_endpoints = 1;
	a.tcp_punch_endpoints[0] = a.tcp_punch_endpoint;

	fastd_peer_t b = {
		.id = 20,
		.group = &group,
		.name = "peer-b",
		.state = STATE_ESTABLISHED,
		.address = addr4(0xcb007106, 42000),
		.punch_endpoint = addr4(0xc6336408, 52010),
		.punch_nat_type = FASTD_NAT_FULL_CONE,
		.punch_min_port = 52010,
		.punch_max_port = 52010,
		.punch_timeout = ctx.now + 10000,
		.tcp_punch_endpoint = addr4(0xc6336408, 52000),
		.n_tcp_punch_endpoints = 1,
		.tcp_punch_nat_type = FASTD_NAT_FULL_CONE,
		.tcp_punch_min_port = 52000,
		.tcp_punch_max_port = 52000,
		.tcp_punch_timeout = ctx.now + 10000,
		.next_punch_relay = ctx.now,
	};
	b.punch_endpoints[0] = (fastd_peer_punch_endpoint_t){
		.address = b.punch_endpoint,
		.nat_type = b.punch_nat_type,
		.min_port = b.punch_min_port,
		.max_port = b.punch_max_port,
	};
	b.n_punch_endpoints = 1;
	b.tcp_punch_endpoints[0] = b.tcp_punch_endpoint;

	VECTOR_ADD(ctx.peers, &a);
	VECTOR_ADD(ctx.peers, &b);

	fastd_punch_test_relay_peer_endpoints();
	size_t tcp_commands = 0;
	size_t udp_commands = 0;
	bool saw_a_tcp_endpoint = false;
	bool saw_b_tcp_endpoint = false;
	size_t i;
	for (i = 0; i < test_control_send_count && i < TEST_CONTROL_HISTORY; i++) {
		switch (test_control_send_types[i]) {
		case TEST_PUNCH_SEND_TCP:
			tcp_commands++;
			if (test_control_send_ports[i] == 51000)
				saw_a_tcp_endpoint = true;
			if (test_control_send_ports[i] == 52000)
				saw_b_tcp_endpoint = true;
			break;

		case TEST_PUNCH_SEND_CONE:
		case TEST_PUNCH_SEND_EASY_SYM:
		case TEST_PUNCH_SEND_HARD_SYM:
		case TEST_PUNCH_BOTH_EASY_SYM:
			udp_commands++;
			break;
		}
	}
	assert_int_equal(tcp_commands, 2);
	assert_int_equal(udp_commands, 0);
	assert_true(saw_a_tcp_endpoint);
	assert_true(saw_b_tcp_endpoint);
	assert_int_equal(ctx.punch_task_manager_budget_exhausted, 0);

	VECTOR_FREE(ctx.peers);
	VECTOR_FREE(ctx.punch_pair_states);
	ctx.peers = old_peers;
	ctx.punch_pair_states = old_pair_states;
	conf.protocol = old_protocol;
	conf.peer_group = old_peer_group;
	conf.punch_control_relay = old_control_relay;
	conf.punch_relay_interval = old_relay_interval;
	conf.punch_max_packets = old_max_packets;
	conf.encrypt_headroom = old_encrypt_headroom;
	ctx.max_buffer = old_max_buffer;
	ctx.now = old_now;
	test_reset_control_sends();
	fastd_cleanup_buffers();
}

static void test_punch_send_tcp_preserves_multiple_received_endpoints(void **state UNUSED) {
	const fastd_protocol_t *old_protocol = conf.protocol;
	fastd_peer_group_t *old_peer_group = conf.peer_group;
	size_t old_encrypt_headroom = conf.encrypt_headroom;
	size_t old_max_buffer = ctx.max_buffer;
	__typeof__(ctx.tcp_socks) old_tcp_socks = ctx.tcp_socks;
	int old_epoll_fd = ctx.epoll_fd;
	uint64_t old_rx = ctx.punch_control_rx;
	uint64_t old_tx = ctx.punch_result_tx;
	int64_t old_now = ctx.now;
	fastd_peer_t *old_lookup_peer = test_lookup_peer;

	ctx.now = 1000;
	ctx.tcp_socks = (__typeof__(ctx.tcp_socks)){};
	conf.protocol = &test_protocol;
	conf.encrypt_headroom = 0;
	ctx.max_buffer = 2048;
	test_reset_control_sends();
	fastd_init_buffers();
	fastd_poll_init();

	fastd_peer_group_t group = {
		.transport = TRANSPORT_AUTO,
		.hole_punch = HOLE_PUNCH_AUTO,
		.nat_traversal = FASTD_TRISTATE_TRUE,
	};
	conf.peer_group = &group;

	fastd_peer_t sender = {
		.id = 30,
		.group = &group,
		.config_state = CONFIG_STATIC,
		.name = "relay",
		.state = STATE_ESTABLISHED,
	};
	fastd_peer_t peer = {
		.id = 20,
		.group = &group,
		.config_state = CONFIG_STATIC,
		.name = "peer-b",
		.state = STATE_ESTABLISHED,
	};
	test_lookup_peer = &peer;
	test_handshake_count = 0;
	test_handshake_peer = NULL;
	test_handshake_transport = TRANSPORT_UNSET;
	test_handshake_remote = (fastd_peer_address_t){};

	fastd_peer_address_t endpoint0 = addr4(0xc6336408, 52000);
	fastd_peer_address_t endpoint1 = addr4(0xc6336408, 52001);
	assert_true(fastd_punch_handle_control(
		&sender,
		make_punch_control_buffer(
			TEST_PUNCH_SEND_TCP, &endpoint0, FASTD_NAT_FULL_CONE, test_key_b, sizeof(test_key_b))));
	assert_true(fastd_punch_handle_control(
		&sender,
		make_punch_control_buffer(
			TEST_PUNCH_SEND_TCP, &endpoint1, FASTD_NAT_FULL_CONE, test_key_b, sizeof(test_key_b))));

	assert_int_equal(peer.n_tcp_punch_endpoints, 2);
	assert_int_equal(port4(&peer.tcp_punch_endpoint), 52000);
	assert_int_equal(port4(&peer.tcp_punch_endpoints[0]), 52000);
	assert_int_equal(port4(&peer.tcp_punch_endpoints[1]), 52001);
	assert_int_equal(peer.tcp_punch_min_port, 52000);
	assert_int_equal(peer.tcp_punch_max_port, 52001);
	assert_true(fastd_peer_is_punch_control_candidate_transport(&peer, &endpoint0, TRANSPORT_TCP, NULL, NULL));
	assert_true(fastd_peer_is_punch_control_candidate_transport(&peer, &endpoint1, TRANSPORT_TCP, NULL, NULL));
	assert_int_equal(fastd_peer_direct_candidate_count_by_source(&peer, DIRECT_CANDIDATE_PUNCH_CONTROL), 2);
	assert_int_equal(test_handshake_count, 1);
	assert_ptr_equal(test_handshake_peer, &peer);
	assert_int_equal(test_handshake_transport, TRANSPORT_TCP);
	assert_true(fastd_peer_address_equal(&test_handshake_remote, &endpoint0));
	assert_int_equal(test_control_send_count, 4);
	assert_int_equal(test_control_send_types[0], TEST_PUNCH_RESULT);
	assert_int_equal(test_control_send_types[1], TEST_PUNCH_RESULT_EXT);
	assert_int_equal(test_control_send_types[2], TEST_PUNCH_RESULT);
	assert_int_equal(test_control_send_types[3], TEST_PUNCH_RESULT_EXT);

	fastd_tcp_cleanup();
	fastd_poll_free();
	VECTOR_FREE(peer.direct_candidates);
	VECTOR_FREE(peer.punch_suppressions);
	fastd_task_unschedule(&peer.task);
	test_lookup_peer = old_lookup_peer;
	ctx.tcp_socks = old_tcp_socks;
	ctx.epoll_fd = old_epoll_fd;
	conf.protocol = old_protocol;
	conf.peer_group = old_peer_group;
	conf.encrypt_headroom = old_encrypt_headroom;
	ctx.max_buffer = old_max_buffer;
	ctx.punch_control_rx = old_rx;
	ctx.punch_result_tx = old_tx;
	ctx.now = old_now;
	test_reset_control_sends();
	test_handshake_count = 0;
	test_handshake_peer = NULL;
	test_handshake_transport = TRANSPORT_UNSET;
	test_handshake_remote = (fastd_peer_address_t){};
	fastd_cleanup_buffers();
}

static void test_tcp_direct_handshake_reuses_unestablished_candidate_socket(void **state UNUSED) {
	const fastd_protocol_t *old_protocol = conf.protocol;
	fastd_peer_group_t *old_peer_group = conf.peer_group;
	int old_epoll_fd = ctx.epoll_fd;
	uint32_t old_peer_addr_ht_seed = ctx.peer_addr_ht_seed;
	size_t old_peer_addr_ht_size = ctx.peer_addr_ht_size;
	size_t old_peer_addr_ht_used = ctx.peer_addr_ht_used;
	__typeof__(ctx.peer_addr_ht) old_peer_addr_ht = ctx.peer_addr_ht;
	__typeof__(ctx.tcp_socks) old_tcp_socks = ctx.tcp_socks;
	__typeof__(ctx.deferred_socks) old_deferred_socks = ctx.deferred_socks;
	int64_t old_now = ctx.now;

	ctx.now = 1000;
	ctx.peer_addr_ht_seed = 0;
	ctx.peer_addr_ht_size = 0;
	ctx.peer_addr_ht_used = 0;
	ctx.peer_addr_ht = NULL;
	ctx.tcp_socks = (__typeof__(ctx.tcp_socks)){};
	ctx.deferred_socks = (__typeof__(ctx.deferred_socks)){};
	conf.protocol = &test_protocol;
	test_handshake_count = 0;
	test_handshake_peer = NULL;
	test_handshake_transport = TRANSPORT_UNSET;
	test_handshake_remote = (fastd_peer_address_t){};
	fastd_poll_init();
	ctx.peer_addr_ht_seed = 0x12345678;
	ctx.peer_addr_ht_size = 8;
	ctx.peer_addr_ht = fastd_new0_array(ctx.peer_addr_ht_size, __typeof__(*ctx.peer_addr_ht));

	fastd_peer_group_t group = {
		.transport = TRANSPORT_TCP,
		.hole_punch = HOLE_PUNCH_TCP,
		.nat_traversal = FASTD_TRISTATE_TRUE,
		.max_connections = -1,
	};
	conf.peer_group = &group;

	fastd_peer_address_t endpoint = addr4(0xc6336408, 52000);
	fastd_peer_t peer = {
		.id = 20,
		.group = &group,
		.config_state = CONFIG_STATIC,
		.name = "peer-b",
		.state = STATE_INACTIVE,
		.transport = TRANSPORT_TCP,
		.hole_punch = HOLE_PUNCH_TCP,
		.nat_traversal = FASTD_TRISTATE_TRUE,
	};

	int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
	assert_true(fd >= 0);

	fastd_socket_t *tcp_sock = fastd_new0(fastd_socket_t);
	tcp_sock->fd = FASTD_POLL_FD(POLL_TYPE_SOCKET, fd);
	tcp_sock->type = SOCKET_TYPE_TCP_CONNECTION;
	tcp_sock->peer = &peer;
	tcp_sock->peer_addr = endpoint;
	tcp_sock->bound_addr = fastd_new(fastd_peer_address_t);
	*tcp_sock->bound_addr = addr4(0x0a000001, 10001);
	peer.sock = tcp_sock;
	peer.local_address = *tcp_sock->bound_addr;
	VECTOR_ADD(ctx.tcp_socks, tcp_sock);
	fastd_poll_fd_register(&tcp_sock->fd);

	assert_true(fastd_peer_add_punch_control_candidate_transport(
		&peer, &endpoint, 120, false, 0, 0, DIRECT_CANDIDATE_TRANSPORT_TCP));
	assert_true(fastd_peer_send_direct_handshake_transport(&peer, &endpoint, TRANSPORT_TCP));

	assert_ptr_equal(peer.sock, tcp_sock);
	assert_ptr_equal(tcp_sock->peer, &peer);
	assert_int_equal(test_handshake_count, 1);
	assert_ptr_equal(test_handshake_peer, &peer);
	assert_int_equal(test_handshake_transport, TRANSPORT_TCP);
	assert_true(fastd_peer_address_equal(&test_handshake_remote, &endpoint));

	fastd_socket_close(tcp_sock);
	fastd_socket_free_dynamic(tcp_sock);
	fastd_socket_free_deferred();
	fastd_peer_hashtable_remove(&peer);
	peer.address = (fastd_peer_address_t){};
	fastd_peer_hashtable_free();
	fastd_poll_free();
	VECTOR_FREE(ctx.tcp_socks);
	VECTOR_FREE(ctx.deferred_socks);
	VECTOR_FREE(peer.direct_candidates);
	VECTOR_FREE(peer.punch_suppressions);
	fastd_task_unschedule(&peer.task);
	conf.protocol = old_protocol;
	conf.peer_group = old_peer_group;
	ctx.epoll_fd = old_epoll_fd;
	ctx.peer_addr_ht_seed = old_peer_addr_ht_seed;
	ctx.peer_addr_ht_size = old_peer_addr_ht_size;
	ctx.peer_addr_ht_used = old_peer_addr_ht_used;
	ctx.peer_addr_ht = old_peer_addr_ht;
	ctx.tcp_socks = old_tcp_socks;
	ctx.deferred_socks = old_deferred_socks;
	ctx.now = old_now;
	test_handshake_count = 0;
	test_handshake_peer = NULL;
	test_handshake_transport = TRANSPORT_UNSET;
	test_handshake_remote = (fastd_peer_address_t){};
}

static void test_punch_accepts_relayed_nat_metadata(void **state UNUSED) {
	const fastd_protocol_t *old_protocol = conf.protocol;
	fastd_peer_group_t *old_peer_group = conf.peer_group;
	fastd_peer_t *old_lookup_peer = test_lookup_peer;
	size_t old_encrypt_headroom = conf.encrypt_headroom;
	size_t old_max_buffer = ctx.max_buffer;
	uint64_t old_rx = ctx.punch_control_rx;
	int64_t old_now = ctx.now;

	ctx.now = 1000;
	conf.protocol = &test_protocol;
	conf.encrypt_headroom = 0;
	ctx.max_buffer = 2048;
	fastd_init_buffers();

	fastd_peer_group_t group = {
		.transport = TRANSPORT_AUTO,
		.hole_punch = HOLE_PUNCH_AUTO,
		.nat_traversal = FASTD_TRISTATE_TRUE,
	};
	conf.peer_group = &group;

	fastd_peer_t relay = {
		.id = 30,
		.group = &group,
		.config_state = CONFIG_STATIC,
		.name = "relay",
		.state = STATE_ESTABLISHED,
	};
	fastd_peer_t subject = {
		.id = 20,
		.group = &group,
		.config_state = CONFIG_STATIC,
		.name = "peer-b",
		.state = STATE_INACTIVE,
	};
	test_lookup_peer = &subject;

	fastd_peer_address_t udp_endpoint = addr4(0xc6336408, 52000);
	assert_true(fastd_punch_handle_control(
		&relay,
		make_punch_control_buffer(
			TEST_PUNCH_NAT_INFO, &udp_endpoint, FASTD_NAT_SYMMETRIC_EASY_INC, test_key_b,
			sizeof(test_key_b))));
	assert_int_equal(subject.punch_endpoint.sa.sa_family, AF_UNSPEC);
	assert_int_equal(subject.n_punch_endpoints, 0);

	assert_true(fastd_punch_handle_control(
		&relay,
		make_punch_control_buffer_extra(
			TEST_PUNCH_NAT_INFO, &udp_endpoint, FASTD_NAT_SYMMETRIC_EASY_INC, test_key_b,
			sizeof(test_key_b), TEST_PUNCH_NAT_INFO_RELAYED)));
	assert_int_equal(subject.punch_nat_type, FASTD_NAT_SYMMETRIC_EASY_INC);
	assert_int_equal(port4(&subject.punch_endpoint), 52000);
	assert_int_equal(subject.punch_min_port, 52000);
	assert_int_equal(subject.punch_max_port, 52000);
	assert_int_equal(subject.n_punch_endpoints, 1);

	fastd_peer_address_t tcp_endpoint = addr4(0xc6336408, 53000);
	assert_true(fastd_punch_handle_control(
		&relay,
		make_punch_control_buffer_extra(
			TEST_PUNCH_TCP_NAT_INFO, &tcp_endpoint, FASTD_NAT_FULL_CONE, test_key_b,
			sizeof(test_key_b), TEST_PUNCH_NAT_INFO_RELAYED)));
	assert_int_equal(subject.tcp_punch_nat_type, FASTD_NAT_FULL_CONE);
	assert_int_equal(port4(&subject.tcp_punch_endpoint), 53000);
	assert_int_equal(subject.tcp_punch_min_port, 53000);
	assert_int_equal(subject.tcp_punch_max_port, 53000);
	assert_int_equal(subject.n_tcp_punch_endpoints, 1);

	test_lookup_peer = old_lookup_peer;
	conf.protocol = old_protocol;
	conf.peer_group = old_peer_group;
	conf.encrypt_headroom = old_encrypt_headroom;
	ctx.max_buffer = old_max_buffer;
	ctx.punch_control_rx = old_rx;
	ctx.now = old_now;
	fastd_cleanup_buffers();
}

static void test_punch_metadata_updates_wake_task_manager(void **state UNUSED) {
	const fastd_protocol_t *old_protocol = conf.protocol;
	fastd_peer_group_t *old_peer_group = conf.peer_group;
	fastd_peer_t *old_lookup_peer = test_lookup_peer;
	bool old_control_relay = conf.punch_control_relay;
	fastd_task_t old_next_maintenance = ctx.next_maintenance;
	fastd_pqueue_t *old_task_queue = ctx.task_queue;
	__typeof__(ctx.punch_pair_states) old_pair_states = ctx.punch_pair_states;
	size_t old_encrypt_headroom = conf.encrypt_headroom;
	size_t old_max_buffer = ctx.max_buffer;
	uint64_t old_rx = ctx.punch_control_rx;
	int64_t old_now = ctx.now;

	ctx.next_maintenance = (fastd_task_t){};
	ctx.task_queue = NULL;
	ctx.punch_pair_states = (__typeof__(ctx.punch_pair_states)){};
	ctx.now = 1000;
	conf.protocol = &test_protocol;
	conf.punch_control_relay = true;
	conf.encrypt_headroom = 0;
	ctx.max_buffer = 2048;
	fastd_init_buffers();

	fastd_peer_group_t group = {
		.transport = TRANSPORT_AUTO,
		.hole_punch = HOLE_PUNCH_AUTO,
		.nat_traversal = FASTD_TRISTATE_TRUE,
	};
	conf.peer_group = &group;

	fastd_peer_t peer = {
		.id = 20,
		.group = &group,
		.config_state = CONFIG_STATIC,
		.name = "peer-b",
		.state = STATE_ESTABLISHED,
	};
	test_lookup_peer = &peer;

	fastd_peer_t other = {
		.id = 30,
		.group = &group,
		.config_state = CONFIG_STATIC,
		.name = "peer-c",
		.state = STATE_ESTABLISHED,
	};

	fastd_punch_note_peer_pair_demand(&peer, &other);
	fastd_punch_test_pair_runtime_mark_launched(&peer, &other);
	VECTOR_INDEX(ctx.punch_pair_states, 0).backoff_until = ctx.now + FASTD_PUNCH_SUPPRESSION_TIME;
	fastd_punch_test_pair_state_t pair_state = fastd_punch_test_pair_state(&peer, &other);
	assert_true(pair_state.in_flight);
	assert_true(pair_state.backoff);
	assert_false(pair_state.pending_demand);

	fastd_peer_address_t udp_endpoint = addr4(0xc6336408, 52000);
	fastd_task_unschedule(&ctx.next_maintenance);
	fastd_task_schedule(&ctx.next_maintenance, TASK_TYPE_MAINTENANCE, ctx.now + 10000);
	assert_true(fastd_punch_handle_control(
		&peer,
		make_punch_control_buffer(
			TEST_PUNCH_NAT_INFO, &udp_endpoint, FASTD_NAT_FULL_CONE, test_key_b, sizeof(test_key_b))));
	assert_int_equal(fastd_task_timeout(&ctx.next_maintenance), ctx.now);
	pair_state = fastd_punch_test_pair_state(&peer, &other);
	assert_false(pair_state.in_flight);
	assert_false(pair_state.backoff);
	assert_true(pair_state.pending_demand);

	fastd_task_unschedule(&ctx.next_maintenance);
	fastd_task_schedule(&ctx.next_maintenance, TASK_TYPE_MAINTENANCE, ctx.now + 10000);
	assert_true(fastd_punch_handle_control(
		&peer,
		make_punch_control_buffer(
			TEST_PUNCH_NAT_INFO, &udp_endpoint, FASTD_NAT_FULL_CONE, test_key_b, sizeof(test_key_b))));
	assert_int_equal(fastd_task_timeout(&ctx.next_maintenance), ctx.now + 10000);

	peer.punch_endpoint = addr4(0xc6336408, 52010);
	peer.punch_nat_type = FASTD_NAT_SYMMETRIC_EASY_INC;
	peer.punch_min_port = 52010;
	peer.punch_max_port = 52010;
	peer.punch_port_delta = 1;
	peer.punch_timeout = ctx.now + 10000;
	peer.n_punch_endpoints = 1;
	peer.punch_endpoints[0] = (fastd_peer_punch_endpoint_t){
		.address = peer.punch_endpoint,
		.nat_type = FASTD_NAT_SYMMETRIC_EASY_INC,
		.min_port = 52010,
		.max_port = 52010,
		.port_delta = 1,
	};
	fastd_task_unschedule(&ctx.next_maintenance);
	fastd_task_schedule(&ctx.next_maintenance, TASK_TYPE_MAINTENANCE, ctx.now + 10000);
	fastd_peer_address_t udp_endpoint_changed = addr4(0xc6336408, 52011);
	fastd_buffer_t *easy_buf = make_punch_control_buffer(
		TEST_PUNCH_NAT_INFO, &udp_endpoint_changed, FASTD_NAT_SYMMETRIC_EASY_INC, test_key_b,
		sizeof(test_key_b));
	test_punch_endpoint_t *easy_payload = (test_punch_endpoint_t *)((test_punch_header_t *)easy_buf->data + 1);
	easy_payload->port_delta = htobe16(1);
	assert_true(fastd_punch_handle_control(&peer, easy_buf));
	assert_int_equal(fastd_task_timeout(&ctx.next_maintenance), ctx.now + 10000);

	fastd_task_unschedule(&ctx.next_maintenance);
	fastd_peer_address_t tcp_endpoint = addr4(0xc6336408, 53000);
	fastd_task_schedule(&ctx.next_maintenance, TASK_TYPE_MAINTENANCE, ctx.now + 10000);
	assert_true(fastd_punch_handle_control(
		&peer,
		make_punch_control_buffer(
			TEST_PUNCH_TCP_NAT_INFO, &tcp_endpoint, FASTD_NAT_FULL_CONE, test_key_b,
			sizeof(test_key_b))));
	assert_int_equal(fastd_task_timeout(&ctx.next_maintenance), ctx.now);

	fastd_task_unschedule(&ctx.next_maintenance);
	VECTOR_FREE(ctx.punch_pair_states);
	test_lookup_peer = old_lookup_peer;
	ctx.next_maintenance = old_next_maintenance;
	ctx.task_queue = old_task_queue;
	ctx.punch_pair_states = old_pair_states;
	conf.protocol = old_protocol;
	conf.peer_group = old_peer_group;
	conf.punch_control_relay = old_control_relay;
	conf.encrypt_headroom = old_encrypt_headroom;
	ctx.max_buffer = old_max_buffer;
	ctx.punch_control_rx = old_rx;
	ctx.now = old_now;
	fastd_cleanup_buffers();
}

static void test_punch_task_manager_outcome_accounting(void **state UNUSED) {
	uint64_t old_direct_success = ctx.punch_direct_success;
	uint64_t old_direct_failures = ctx.punch_direct_failures;
	uint64_t old_outcome_success = ctx.punch_task_manager_outcome_success;
	uint64_t old_outcome_failed = ctx.punch_task_manager_outcome_failed;
	uint64_t old_outcome_accepted = ctx.punch_task_manager_outcome_accepted;
	uint64_t old_outcome_handshake = ctx.punch_task_manager_outcome_handshake;
	uint64_t old_outcome_suppressed = ctx.punch_task_manager_outcome_suppressed;
	uint64_t old_outcome_no_peer = ctx.punch_task_manager_outcome_no_peer;
	uint64_t old_outcome_busy = ctx.punch_task_manager_outcome_busy;

	ctx.now = 1000;
	ctx.punch_direct_success = 0;
	ctx.punch_direct_failures = 0;
	ctx.punch_task_manager_outcome_success = 0;
	ctx.punch_task_manager_outcome_failed = 0;
	ctx.punch_task_manager_outcome_accepted = 0;
	ctx.punch_task_manager_outcome_handshake = 0;
	ctx.punch_task_manager_outcome_suppressed = 0;
	ctx.punch_task_manager_outcome_no_peer = 0;
	ctx.punch_task_manager_outcome_busy = 0;

	fastd_peer_t success_peer = {};
	fastd_peer_test_count_direct_success(&success_peer, DIRECT_CANDIDATE_REALM);
	assert_int_equal(ctx.punch_direct_success, 0);
	assert_int_equal(ctx.punch_task_manager_outcome_success, 0);
	fastd_peer_test_count_direct_success(&success_peer, DIRECT_CANDIDATE_PUNCH_CONTROL);
	fastd_peer_test_count_direct_success(&success_peer, DIRECT_CANDIDATE_PUNCH_CONTROL);
	assert_int_equal(ctx.punch_direct_success, 1);
	assert_int_equal(ctx.punch_task_manager_outcome_success, 1);

	fastd_peer_t failure_peer = {};
	const fastd_peer_address_t expired = addr4(0xcb007105, 41000);
	VECTOR_ADD(
		failure_peer.direct_candidates, ((fastd_peer_direct_candidate_t){
							.remote = expired,
							.timeout = ctx.now - 1,
							.attempts = 1,
							.source = DIRECT_CANDIDATE_PUNCH_CONTROL,
							.transports = DIRECT_CANDIDATE_TRANSPORT_UDP,
						}));
	fastd_peer_test_compact_direct_candidates(&failure_peer);
	assert_int_equal(ctx.punch_direct_failures, 1);
	assert_int_equal(ctx.punch_task_manager_outcome_failed, 1);
	assert_true(fastd_peer_punch_candidate_suppressed(&failure_peer, &expired));

	fastd_punch_test_task_manager_record_remote_result(TEST_PUNCH_RESULT_ACCEPTED);
	fastd_punch_test_task_manager_record_remote_result(TEST_PUNCH_RESULT_HANDSHAKE);
	fastd_punch_test_task_manager_record_remote_result(TEST_PUNCH_RESULT_SUPPRESSED);
	fastd_punch_test_task_manager_record_remote_result(TEST_PUNCH_RESULT_NO_PEER);
	fastd_punch_test_task_manager_record_remote_result(TEST_PUNCH_RESULT_BUSY);
	fastd_punch_test_task_manager_record_remote_result(0xff);
	assert_int_equal(ctx.punch_task_manager_outcome_accepted, 1);
	assert_int_equal(ctx.punch_task_manager_outcome_handshake, 1);
	assert_int_equal(ctx.punch_task_manager_outcome_suppressed, 1);
	assert_int_equal(ctx.punch_task_manager_outcome_no_peer, 1);
	assert_int_equal(ctx.punch_task_manager_outcome_busy, 1);

	VECTOR_FREE(success_peer.direct_candidates);
	VECTOR_FREE(success_peer.punch_suppressions);
	VECTOR_FREE(failure_peer.direct_candidates);
	VECTOR_FREE(failure_peer.punch_suppressions);
	ctx.punch_direct_success = old_direct_success;
	ctx.punch_direct_failures = old_direct_failures;
	ctx.punch_task_manager_outcome_success = old_outcome_success;
	ctx.punch_task_manager_outcome_failed = old_outcome_failed;
	ctx.punch_task_manager_outcome_accepted = old_outcome_accepted;
	ctx.punch_task_manager_outcome_handshake = old_outcome_handshake;
	ctx.punch_task_manager_outcome_suppressed = old_outcome_suppressed;
	ctx.punch_task_manager_outcome_no_peer = old_outcome_no_peer;
	ctx.punch_task_manager_outcome_busy = old_outcome_busy;
}

static void test_punch_pair_task_history_is_bounded_and_ordered(void **state UNUSED) {
	fastd_punch_pair_task_t old_pair_tasks[FASTD_PUNCH_PAIR_TASK_HISTORY];
	memcpy(old_pair_tasks, ctx.punch_pair_tasks, sizeof(old_pair_tasks));
	uint64_t old_next_pair_task_id = ctx.next_punch_pair_task_id;
	size_t old_pair_task_pos = ctx.punch_pair_task_pos;
	size_t old_pair_task_count = ctx.punch_pair_task_count;
	int64_t old_now = ctx.now;

	memset(ctx.punch_pair_tasks, 0, sizeof(ctx.punch_pair_tasks));
	ctx.next_punch_pair_task_id = 0;
	ctx.punch_pair_task_pos = 0;
	ctx.punch_pair_task_count = 0;

	fastd_peer_t high = { .id = 20 };
	fastd_peer_t low = { .id = 10 };
	fastd_peer_t destination = { .id = 30 };

	size_t i;
	for (i = 0; i < FASTD_PUNCH_PAIR_TASK_HISTORY + 3; i++) {
		ctx.now = 1000 + (int64_t)i;
		fastd_punch_test_task_manager_record_pair_task(
			&high, &low, &high, &destination, PUNCH_PAIR_TASK_STAGE_LAUNCHED, i, i + 1,
			FASTD_TIMEOUT_INV, false);
	}

	assert_int_equal(ctx.punch_pair_task_count, FASTD_PUNCH_PAIR_TASK_HISTORY);
	assert_int_equal(ctx.punch_pair_task_pos, 3);
	assert_int_equal(ctx.next_punch_pair_task_id, FASTD_PUNCH_PAIR_TASK_HISTORY + 3);

	size_t latest_pos =
		(ctx.punch_pair_task_pos + FASTD_PUNCH_PAIR_TASK_HISTORY - 1) % FASTD_PUNCH_PAIR_TASK_HISTORY;
	fastd_punch_pair_task_t *latest = &ctx.punch_pair_tasks[latest_pos];
	assert_int_equal(latest->id, FASTD_PUNCH_PAIR_TASK_HISTORY + 3);
	assert_int_equal(latest->peer_a_id, 10);
	assert_int_equal(latest->peer_b_id, 20);
	assert_int_equal(latest->subject_id, 20);
	assert_int_equal(latest->destination_id, 30);
	assert_int_equal(latest->stage, PUNCH_PAIR_TASK_STAGE_LAUNCHED);
	assert_int_equal(latest->candidates_sent, FASTD_PUNCH_PAIR_TASK_HISTORY + 2);
	assert_int_equal(latest->backoff_skipped, FASTD_PUNCH_PAIR_TASK_HISTORY + 3);

	ctx.now = 2000;
	fastd_punch_test_task_manager_record_pair_task(
		&low, &high, NULL, NULL, PUNCH_PAIR_TASK_STAGE_WAITING, 0, 0, ctx.now + 500, true);
	latest_pos = (ctx.punch_pair_task_pos + FASTD_PUNCH_PAIR_TASK_HISTORY - 1) % FASTD_PUNCH_PAIR_TASK_HISTORY;
	latest = &ctx.punch_pair_tasks[latest_pos];
	assert_int_equal(ctx.punch_pair_task_count, FASTD_PUNCH_PAIR_TASK_HISTORY);
	assert_int_equal(latest->id, FASTD_PUNCH_PAIR_TASK_HISTORY + 4);
	assert_int_equal(latest->stage, PUNCH_PAIR_TASK_STAGE_WAITING);
	assert_int_equal(latest->next_retry, 2500);
	assert_true(latest->budget_exhausted);

	memcpy(ctx.punch_pair_tasks, old_pair_tasks, sizeof(old_pair_tasks));
	ctx.next_punch_pair_task_id = old_next_pair_task_id;
	ctx.punch_pair_task_pos = old_pair_task_pos;
	ctx.punch_pair_task_count = old_pair_task_count;
	ctx.now = old_now;
}

static void test_punch_pair_task_history_records_remote_results(void **state UNUSED) {
	fastd_punch_pair_task_t old_pair_tasks[FASTD_PUNCH_PAIR_TASK_HISTORY];
	memcpy(old_pair_tasks, ctx.punch_pair_tasks, sizeof(old_pair_tasks));
	uint64_t old_next_pair_task_id = ctx.next_punch_pair_task_id;
	size_t old_pair_task_pos = ctx.punch_pair_task_pos;
	size_t old_pair_task_count = ctx.punch_pair_task_count;
	int64_t old_now = ctx.now;

	memset(ctx.punch_pair_tasks, 0, sizeof(ctx.punch_pair_tasks));
	ctx.next_punch_pair_task_id = 0;
	ctx.punch_pair_task_pos = 0;
	ctx.punch_pair_task_count = 0;
	ctx.now = 1000;

	fastd_peer_t sender = {
		.id = 40,
		.state = STATE_ESTABLISHED,
	};
	fastd_peer_t subject = {
		.id = 30,
		.state = STATE_ESTABLISHED,
	};
	fastd_peer_address_t endpoint = addr4(0xcb007105, 41000);

	fastd_punch_test_task_manager_record_pair_result(
		&sender, &subject, TEST_PUNCH_RESULT_ACCEPTED, &endpoint);

	size_t latest_pos =
		(ctx.punch_pair_task_pos + FASTD_PUNCH_PAIR_TASK_HISTORY - 1) % FASTD_PUNCH_PAIR_TASK_HISTORY;
	fastd_punch_pair_task_t *latest = &ctx.punch_pair_tasks[latest_pos];
	assert_int_equal(ctx.punch_pair_task_count, 1);
	assert_int_equal(latest->stage, PUNCH_PAIR_TASK_STAGE_RESULT_ACCEPTED);
	assert_int_equal(latest->peer_a_id, 30);
	assert_int_equal(latest->peer_b_id, 40);
	assert_int_equal(latest->subject_id, 30);
	assert_int_equal(latest->destination_id, 40);
	assert_int_equal(latest->backoff_skipped, 0);
	assert_int_equal(latest->next_retry, ctx.now + FASTD_HOLE_PUNCH_TIMEOUT);

	fastd_peer_add_punch_relay_backoff(&sender, &endpoint);
	fastd_punch_test_task_manager_record_pair_result(
		&sender, &subject, TEST_PUNCH_RESULT_BUSY, &endpoint);

	latest_pos = (ctx.punch_pair_task_pos + FASTD_PUNCH_PAIR_TASK_HISTORY - 1) % FASTD_PUNCH_PAIR_TASK_HISTORY;
	latest = &ctx.punch_pair_tasks[latest_pos];
	assert_int_equal(ctx.punch_pair_task_count, 2);
	assert_int_equal(latest->stage, PUNCH_PAIR_TASK_STAGE_RESULT_BUSY);
	assert_int_equal(latest->backoff_skipped, 1);
	assert_int_equal(latest->next_retry, ctx.now + FASTD_PUNCH_SUPPRESSION_TIME);

	VECTOR_FREE(sender.punch_relay_backoffs);
	memcpy(ctx.punch_pair_tasks, old_pair_tasks, sizeof(old_pair_tasks));
	ctx.next_punch_pair_task_id = old_next_pair_task_id;
	ctx.punch_pair_task_pos = old_pair_task_pos;
	ctx.punch_pair_task_count = old_pair_task_count;
	ctx.now = old_now;
}

static void test_punch_remote_result_ext_drives_state_and_legacy_is_deduped(void **state UNUSED) {
	__typeof__(ctx.punch_pair_states) old_pair_states = ctx.punch_pair_states;
	fastd_punch_pair_task_t old_pair_tasks[FASTD_PUNCH_PAIR_TASK_HISTORY];
	memcpy(old_pair_tasks, ctx.punch_pair_tasks, sizeof(old_pair_tasks));
	fastd_punch_result_seen_t old_seen[FASTD_PUNCH_RESULT_DEDUP_HISTORY];
	memcpy(old_seen, ctx.punch_result_seen, sizeof(old_seen));
	uint64_t old_next_pair_task_id = ctx.next_punch_pair_task_id;
	size_t old_pair_task_pos = ctx.punch_pair_task_pos;
	size_t old_pair_task_count = ctx.punch_pair_task_count;
	size_t old_seen_pos = ctx.punch_result_seen_pos;
	uint64_t old_result_rx = ctx.punch_result_rx;
	uint64_t old_result_duplicates = ctx.punch_result_duplicates;
	uint64_t old_result_handshake = ctx.punch_task_manager_outcome_handshake;
	int64_t old_now = ctx.now;

	ctx.punch_pair_states = (__typeof__(ctx.punch_pair_states)){};
	memset(ctx.punch_pair_tasks, 0, sizeof(ctx.punch_pair_tasks));
	memset(ctx.punch_result_seen, 0, sizeof(ctx.punch_result_seen));
	ctx.next_punch_pair_task_id = 0;
	ctx.punch_pair_task_pos = 0;
	ctx.punch_pair_task_count = 0;
	ctx.punch_result_seen_pos = 0;
	ctx.punch_result_rx = 0;
	ctx.punch_result_duplicates = 0;
	ctx.punch_task_manager_outcome_handshake = 0;
	ctx.now = 1000;

	fastd_peer_t sender = {
		.id = 40,
		.state = STATE_ESTABLISHED,
	};
	fastd_peer_t subject = {
		.id = 30,
		.state = STATE_ESTABLISHED,
	};
	fastd_peer_address_t endpoint = addr4(0xcb007105, 41000);

	fastd_punch_test_pair_runtime_mark_launched(&sender, &subject);
	assert_int_equal(VECTOR_LEN(ctx.punch_pair_states), 1);
	assert_true(fastd_punch_test_pair_state(&sender, &subject).in_flight);

	assert_true(fastd_punch_test_handle_remote_result(
		&sender, &subject, TEST_PUNCH_RESULT_HANDSHAKE, TEST_PUNCH_SEND_HARD_SYM, &endpoint));
	assert_int_equal(ctx.punch_result_rx, 1);
	assert_int_equal(ctx.punch_task_manager_outcome_handshake, 1);
	assert_true(fastd_punch_test_pair_state(&sender, &subject).in_flight);
	assert_int_equal(VECTOR_INDEX(ctx.punch_pair_states, 0).result_count, 1);
	assert_int_equal(ctx.punch_pair_task_count, 1);

	assert_false(fastd_punch_test_handle_remote_result(
		&sender, &subject, TEST_PUNCH_RESULT_HANDSHAKE, 0, &endpoint));
	assert_int_equal(ctx.punch_result_rx, 1);
	assert_int_equal(ctx.punch_result_duplicates, 1);
	assert_int_equal(ctx.punch_task_manager_outcome_handshake, 1);
	assert_int_equal(VECTOR_INDEX(ctx.punch_pair_states, 0).result_count, 1);
	assert_int_equal(ctx.punch_pair_task_count, 1);

	ctx.now += 2001;
	assert_true(fastd_punch_test_handle_remote_result(
		&sender, &subject, TEST_PUNCH_RESULT_HANDSHAKE, 0, &endpoint));
	assert_int_equal(ctx.punch_result_rx, 2);
	assert_int_equal(ctx.punch_result_duplicates, 1);
	assert_int_equal(ctx.punch_task_manager_outcome_handshake, 2);
	assert_int_equal(VECTOR_INDEX(ctx.punch_pair_states, 0).result_count, 2);
	assert_int_equal(ctx.punch_pair_task_count, 2);

	VECTOR_FREE(ctx.punch_pair_states);
	ctx.punch_pair_states = old_pair_states;
	memcpy(ctx.punch_pair_tasks, old_pair_tasks, sizeof(ctx.punch_pair_tasks));
	memcpy(ctx.punch_result_seen, old_seen, sizeof(ctx.punch_result_seen));
	ctx.next_punch_pair_task_id = old_next_pair_task_id;
	ctx.punch_pair_task_pos = old_pair_task_pos;
	ctx.punch_pair_task_count = old_pair_task_count;
	ctx.punch_result_seen_pos = old_seen_pos;
	ctx.punch_result_rx = old_result_rx;
	ctx.punch_result_duplicates = old_result_duplicates;
	ctx.punch_task_manager_outcome_handshake = old_result_handshake;
	ctx.now = old_now;
}

#ifdef WITH_STATUS_SOCKET

static void test_status_hole_punch_exposes_peer_nat_metadata(void **state UNUSED) {
	fastd_peer_t peer = {
		.hole_punch = HOLE_PUNCH_AUTO,
		.nat_traversal = FASTD_TRISTATE_TRUE,
		.punch_nat_type = FASTD_NAT_SYMMETRIC_EASY_INC,
		.punch_min_port = 40990,
		.punch_max_port = 41010,
		.punch_port_delta = 4,
		.tcp_punch_nat_type = FASTD_NAT_FULL_CONE,
		.tcp_punch_min_port = 51000,
		.tcp_punch_max_port = 51000,
		.direct_remote_source = DIRECT_CANDIDATE_PUNCH_CONTROL,
		.direct_remote_transports = DIRECT_CANDIDATE_TRANSPORT_UDP | DIRECT_CANDIDATE_TRANSPORT_TCP,
		.direct_remote_exact_udp = true,
		.direct_remote_udp_punch_sockets = 3,
	};
	const fastd_peer_address_t relay_backoff = addr4(0xcb007105, 41002);
	const fastd_peer_address_t suppression_addr = addr4(0xcb007105, 41004);

	ctx.now = 1000;
	conf.punch_symmetric = true;
	peer.punch_endpoint = addr4(0xcb007105, 41000);
	peer.punch_endpoints[0] = (fastd_peer_punch_endpoint_t){
		.address = peer.punch_endpoint,
		.nat_type = FASTD_NAT_SYMMETRIC_EASY_INC,
		.min_port = 40990,
		.max_port = 41010,
		.port_delta = 4,
		.hard_sym_port_index = 100,
		.hard_sym_round = 2,
	};
	peer.punch_endpoints[1] = (fastd_peer_punch_endpoint_t){
		.address = addr4(0xc6336408, 42000),
		.nat_type = FASTD_NAT_FULL_CONE,
		.min_port = 42000,
		.max_port = 42000,
	};
	peer.n_punch_endpoints = 2;
	peer.punch_listener_id = 88;
	peer.punch_timeout = ctx.now + 5000;
	peer.tcp_punch_endpoint = addr4(0xcb007105, 51000);
	peer.tcp_punch_endpoints[0] = peer.tcp_punch_endpoint;
	peer.tcp_punch_endpoints[1] = addr4(0xc6336408, 52000);
	peer.n_tcp_punch_endpoints = 2;
	peer.tcp_punch_timeout = ctx.now + 7000;
	peer.direct_remote = addr4(0xcb007105, 41001);
	peer.direct_remote_timeout = ctx.now + 6000;
	peer.last_punch_task = (fastd_peer_punch_task_t){
		.id = 42,
		.updated = ctx.now - 125,
		.next_retry = ctx.now + 15000,
		.endpoint = addr4(0xcb007105, 41003),
		.role = PEER_PUNCH_TASK_ROLE_RELAY_DEST,
		.cause = PEER_PUNCH_TASK_CAUSE_HANDSHAKE_SENT,
		.command = PEER_PUNCH_TASK_COMMAND_HARD_SYM,
		.result = PEER_PUNCH_TASK_RESULT_HANDSHAKE,
		.packet_count = 84,
		.candidate_count = 25,
		.candidates_sent = 23,
		.order = 7,
		.udp_punch_sockets = 84,
		.hard_sym_port_index = 100,
		.hard_sym_next_port_index = 125,
		.hard_sym_round = 2,
		.wait_window_ms = 5000,
		.base_mapped_endpoint = addr4(0xcb007105, 43000),
		.base_mapped_listener_id = 77,
		.base_mapped_available = true,
		.base_mapped_port_mapped = true,
	};

	VECTOR_ADD(
		peer.direct_candidates, ((fastd_peer_direct_candidate_t){
						.remote = peer.direct_remote,
						.timeout = ctx.now + 6000,
						.priority = 120,
						.order = 0,
						.last_attempt = ctx.now - 250,
						.probe_timeout = ctx.now + 3000,
						.payload_probe_timeout = ctx.now + 3500,
						.transports = DIRECT_CANDIDATE_TRANSPORT_UDP |
							      DIRECT_CANDIDATE_TRANSPORT_TCP,
						.source = DIRECT_CANDIDATE_PUNCH_CONTROL,
						.exact_udp_punch = true,
						.udp_punch_sockets = 3,
					}));
	fastd_peer_suppress_punch_candidate(&peer, &suppression_addr);
	fastd_peer_add_punch_relay_backoff(&peer, &relay_backoff);

	struct json_object *hole_punch = fastd_status_test_dump_hole_punch(&peer);
	assert_non_null(hole_punch);
	assert_true(json_get_bool_required(hole_punch, "nat_traversal"));
	assert_true(json_get_bool_required(hole_punch, "enabled"));
	assert_true(json_get_bool_required(hole_punch, "symmetric"));
	assert_string_equal(json_get_string_required(hole_punch, "path_state"), "not-direct");
	assert_string_equal(json_get_string_required(hole_punch, "reason"), "relay-backoff-active");
	assert_int_equal(json_get_int_required(hole_punch, "direct_candidates"), 1);
	assert_int_equal(json_get_int_required(hole_punch, "punch_control_candidates"), 1);
	assert_int_equal(json_get_int_required(hole_punch, "relay_backoffs"), 1);

	struct json_object *udp = json_get_object_required(hole_punch, "udp_metadata");
	assert_true(json_get_bool_required(udp, "available"));
	assert_string_equal(json_get_string_required(udp, "type"), "symmetric-easy-inc");
	assert_non_null(strstr(json_get_string_required(udp, "endpoint"), "41000"));
	assert_int_equal(json_get_int_required(udp, "min_port"), 40990);
	assert_int_equal(json_get_int_required(udp, "max_port"), 41010);
	assert_int_equal(json_get_int_required(udp, "port_delta"), 4);
	assert_int_equal(json_get_int_required(udp, "listener_id"), 88);
	assert_int_equal(json_get_int_required(udp, "expires_in"), 5000);
	struct json_object *udp_endpoints = json_get_array_required(udp, "endpoints");
	assert_int_equal(json_object_array_length(udp_endpoints), 2);
	assert_non_null(strstr(json_object_get_string(json_object_array_get_idx(udp_endpoints, 0)), "41000"));
	assert_non_null(strstr(json_object_get_string(json_object_array_get_idx(udp_endpoints, 1)), "42000"));
	struct json_object *udp_endpoint_details = json_get_array_required(udp, "endpoint_details");
	assert_int_equal(json_object_array_length(udp_endpoint_details), 2);
	struct json_object *udp_detail0 = json_object_array_get_idx(udp_endpoint_details, 0);
	assert_int_equal(json_object_get_type(udp_detail0), json_type_object);
	assert_non_null(strstr(json_get_string_required(udp_detail0, "endpoint"), "41000"));
	assert_string_equal(json_get_string_required(udp_detail0, "type"), "symmetric-easy-inc");
	assert_int_equal(json_get_int_required(udp_detail0, "min_port"), 40990);
	assert_int_equal(json_get_int_required(udp_detail0, "max_port"), 41010);
	assert_int_equal(json_get_int_required(udp_detail0, "port_delta"), 4);
	assert_int_equal(json_get_int_required(udp_detail0, "hard_symmetric_port_index"), 100);
	assert_int_equal(json_get_int_required(udp_detail0, "hard_symmetric_round"), 2);
	struct json_object *udp_detail1 = json_object_array_get_idx(udp_endpoint_details, 1);
	assert_string_equal(json_get_string_required(udp_detail1, "type"), "full-cone");
	assert_int_equal(json_get_int_required(udp_detail1, "min_port"), 42000);
	assert_int_equal(json_get_int_required(udp_detail1, "max_port"), 42000);

	struct json_object *tcp = json_get_object_required(hole_punch, "tcp_metadata");
	assert_true(json_get_bool_required(tcp, "available"));
	assert_string_equal(json_get_string_required(tcp, "type"), "full-cone");
	assert_non_null(strstr(json_get_string_required(tcp, "endpoint"), "51000"));
	assert_int_equal(json_get_int_required(tcp, "min_port"), 51000);
	assert_int_equal(json_get_int_required(tcp, "max_port"), 51000);
	assert_int_equal(json_get_int_required(tcp, "expires_in"), 7000);
	struct json_object *tcp_endpoints = json_get_array_required(tcp, "endpoints");
	assert_int_equal(json_object_array_length(tcp_endpoints), 2);
	assert_non_null(strstr(json_object_get_string(json_object_array_get_idx(tcp_endpoints, 0)), "51000"));
	assert_non_null(strstr(json_object_get_string(json_object_array_get_idx(tcp_endpoints, 1)), "52000"));

	struct json_object *candidate = json_get_object_required(hole_punch, "current_direct_candidate");
	assert_true(json_get_bool_required(candidate, "available"));
	assert_string_equal(json_get_string_required(candidate, "source"), "punch-control");
	assert_true(json_get_bool_required(candidate, "udp"));
	assert_true(json_get_bool_required(candidate, "tcp"));
	assert_true(json_get_bool_required(candidate, "exact_udp"));
	assert_int_equal(json_get_int_required(candidate, "udp_punch_sockets"), 3);
	assert_int_equal(json_get_int_required(candidate, "expires_in"), 6000);

	struct json_object *candidates = json_get_array_required(hole_punch, "direct_candidate_list");
	assert_int_equal(json_object_array_length(candidates), 1);
	struct json_object *listed_candidate = json_object_array_get_idx(candidates, 0);
	assert_int_equal(json_object_get_type(listed_candidate), json_type_object);
	assert_non_null(strstr(json_get_string_required(listed_candidate, "endpoint"), "41001"));
	assert_string_equal(json_get_string_required(listed_candidate, "source"), "punch-control");
	assert_true(json_get_bool_required(listed_candidate, "udp"));
	assert_true(json_get_bool_required(listed_candidate, "tcp"));
	assert_true(json_get_bool_required(listed_candidate, "exact_udp"));
	assert_int_equal(json_get_int_required(listed_candidate, "udp_punch_sockets"), 3);
	assert_int_equal(json_get_int_required(listed_candidate, "priority"), 120);
	assert_int_equal(json_get_int_required(listed_candidate, "order"), 0);
	assert_int_equal(json_get_int_required(listed_candidate, "last_attempt_age"), 250);
	assert_int_equal(json_get_int_required(listed_candidate, "probe_expires_in"), 3000);
	assert_int_equal(json_get_int_required(listed_candidate, "payload_probe_expires_in"), 3500);

	struct json_object *suppressions = json_get_array_required(hole_punch, "punch_suppression_list");
	assert_int_equal(json_object_array_length(suppressions), 1);
	struct json_object *suppression = json_object_array_get_idx(suppressions, 0);
	assert_int_equal(json_object_get_type(suppression), json_type_object);
	assert_non_null(strstr(json_get_string_required(suppression, "endpoint"), "41004"));
	assert_int_equal(json_get_int_required(suppression, "expires_in"), 60000);

	struct json_object *relay_backoffs = json_get_array_required(hole_punch, "relay_backoff_list");
	assert_int_equal(json_object_array_length(relay_backoffs), 1);
	struct json_object *backoff = json_object_array_get_idx(relay_backoffs, 0);
	assert_int_equal(json_object_get_type(backoff), json_type_object);
	assert_non_null(strstr(json_get_string_required(backoff, "endpoint"), "41002"));
	assert_int_equal(json_get_int_required(backoff, "expires_in"), 60000);

	struct json_object *task = json_get_object_required(hole_punch, "last_punch_task");
	assert_true(json_get_bool_required(task, "available"));
	assert_int_equal(json_get_int_required(task, "id"), 42);
	assert_int_equal(json_get_int_required(task, "updated_age"), 125);
	assert_string_equal(json_get_string_required(task, "role"), "relay-destination");
	assert_string_equal(json_get_string_required(task, "cause"), "handshake-sent");
	assert_string_equal(json_get_string_required(task, "command"), "hard-symmetric");
	assert_string_equal(json_get_string_required(task, "result"), "handshake");
	assert_int_equal(json_get_int_required(task, "next_retry_ms"), 15000);
	assert_non_null(strstr(json_get_string_required(task, "endpoint"), "41003"));
	assert_non_null(strstr(json_get_string_required(task, "base_mapped_endpoint"), "43000"));
	assert_int_equal(json_get_int_required(task, "base_mapped_listener_id"), 77);
	assert_true(json_get_bool_required(task, "base_mapped_port_mapped"));
	assert_int_equal(json_get_int_required(task, "packet_count"), 84);
	assert_int_equal(json_get_int_required(task, "candidate_count"), 25);
	assert_int_equal(json_get_int_required(task, "candidates_sent"), 23);
	assert_int_equal(json_get_int_required(task, "order"), 7);
	assert_int_equal(json_get_int_required(task, "udp_punch_sockets"), 84);
	assert_int_equal(json_get_int_required(task, "hard_symmetric_port_index"), 100);
	assert_int_equal(json_get_int_required(task, "wait_window_ms"), 5000);
	assert_int_equal(json_get_int_required(task, "hard_symmetric_next_port_index"), 125);
	assert_int_equal(json_get_int_required(task, "hard_symmetric_round"), 2);

	json_object_put(hole_punch);

	fastd_peer_address_t active_local = addr4(0xcb007105, 35000);
	fastd_peer_address_t backup_local = addr4(0xcb007105, 35001);
	fastd_socket_t active_sock = {
		.fd.fd = 1,
		.type = SOCKET_TYPE_UDP,
		.bound_addr = &active_local,
		.hole_punch = true,
	};
	fastd_socket_t backup_sock = {
		.fd.fd = 2,
		.type = SOCKET_TYPE_UDP,
		.bound_addr = &backup_local,
		.hole_punch = true,
	};
	peer.state = STATE_ESTABLISHED;
	peer.sock = &active_sock;
	peer.local_address = active_local;
	peer.address = peer.direct_remote;
	peer.direct_established = true;
	peer.active_path_timeout = ctx.now + 8000;
	peer.active_path_proven_timeout = ctx.now + 9000;
	peer.backup_sock = &backup_sock;
	peer.backup_local_address = backup_local;
	peer.backup_address = addr4(0xcb007105, 41005);
	peer.backup_reset_timeout = ctx.now + 10000;
	peer.backup_keepalive_timeout = ctx.now + 11000;
	peer.backup_direct_established = true;
	peer.backup_path_verified = true;
	peer.backup_payload_proven = true;

	hole_punch = fastd_status_test_dump_hole_punch(&peer);
	assert_string_equal(json_get_string_required(hole_punch, "path_state"), "direct-with-payload-backup");
	assert_string_equal(json_get_string_required(hole_punch, "reason"), "active-and-backup-payload-ready");
	assert_true(json_get_bool_required(hole_punch, "established"));
	assert_true(json_get_bool_required(hole_punch, "verified"));
	assert_true(json_get_bool_required(hole_punch, "proven"));
	assert_true(json_get_bool_required(hole_punch, "backup_established"));
	assert_true(json_get_bool_required(hole_punch, "backup_verified"));
	assert_true(json_get_bool_required(hole_punch, "backup_payload_proven"));
	json_object_put(hole_punch);

	VECTOR_FREE(peer.direct_candidates);
	VECTOR_FREE(peer.punch_suppressions);
	VECTOR_FREE(peer.punch_relay_backoffs);
}

static void test_status_punch_exposes_udp_socket_pool(void **state UNUSED) {
	__typeof__(ctx.udp_punch_socks) old_udp_punch_socks = ctx.udp_punch_socks;
	__typeof__(ctx.peers) old_peers = ctx.peers;
	fastd_peer_group_t *old_peer_group = conf.peer_group;
	uint64_t old_task_manager_runs = ctx.punch_task_manager_runs;
	uint64_t old_task_manager_pairs = ctx.punch_task_manager_pairs;
	uint64_t old_task_manager_collected = ctx.punch_task_manager_collected;
	uint64_t old_task_manager_launched = ctx.punch_task_manager_launched;
	uint64_t old_task_manager_waiting = ctx.punch_task_manager_waiting;
	uint64_t old_task_manager_in_flight = ctx.punch_task_manager_in_flight;
	uint64_t old_task_manager_missing_metadata = ctx.punch_task_manager_missing_metadata;
	uint64_t old_task_manager_metadata_requests = ctx.punch_task_manager_metadata_requests;
	uint64_t old_task_manager_metadata_relays = ctx.punch_task_manager_metadata_relays;
	uint64_t old_task_manager_blacklisted = ctx.punch_task_manager_blacklisted;
	uint64_t old_task_manager_suppressed = ctx.punch_task_manager_suppressed;
	uint64_t old_task_manager_aborted = ctx.punch_task_manager_aborted;
	uint64_t old_task_manager_recent_demand = ctx.punch_task_manager_recent_demand;
	uint64_t old_task_manager_budget_exhausted = ctx.punch_task_manager_budget_exhausted;
	fastd_timeout_t old_task_manager_next_retry = ctx.punch_task_manager_next_retry;
	uint64_t old_task_manager_outcome_success = ctx.punch_task_manager_outcome_success;
	uint64_t old_task_manager_outcome_failed = ctx.punch_task_manager_outcome_failed;
	uint64_t old_task_manager_outcome_accepted = ctx.punch_task_manager_outcome_accepted;
	uint64_t old_task_manager_outcome_handshake = ctx.punch_task_manager_outcome_handshake;
	uint64_t old_task_manager_outcome_suppressed = ctx.punch_task_manager_outcome_suppressed;
	uint64_t old_task_manager_outcome_no_peer = ctx.punch_task_manager_outcome_no_peer;
	uint64_t old_task_manager_outcome_busy = ctx.punch_task_manager_outcome_busy;
	uint64_t old_result_duplicates = ctx.punch_result_duplicates;
	fastd_punch_pair_task_t old_pair_tasks[FASTD_PUNCH_PAIR_TASK_HISTORY];
	memcpy(old_pair_tasks, ctx.punch_pair_tasks, sizeof(old_pair_tasks));
	uint64_t old_next_pair_task_id = ctx.next_punch_pair_task_id;
	size_t old_pair_task_pos = ctx.punch_pair_task_pos;
	size_t old_pair_task_count = ctx.punch_pair_task_count;
	__typeof__(ctx.punch_pair_states) old_pair_states = ctx.punch_pair_states;
	ctx.udp_punch_socks = (__typeof__(ctx.udp_punch_socks)){};
	ctx.peers = (__typeof__(ctx.peers)){};
	ctx.punch_pair_states = (__typeof__(ctx.punch_pair_states)){};
	memset(ctx.punch_pair_tasks, 0, sizeof(ctx.punch_pair_tasks));
	ctx.next_punch_pair_task_id = 200;
	ctx.punch_pair_task_pos = 0;
	ctx.punch_pair_task_count = 0;

	fastd_peer_group_t group = {};
	fastd_peer_t peer = {
		.id = 77,
		.name = "peer-a",
	};
	fastd_peer_t task_peer = {
		.id = 78,
		.name = "peer-b",
	};
	fastd_peer_address_t local = addr4(0x0a000001, 35000);
	fastd_peer_address_t public_local = addr4(0x0a000001, 35001);
	fastd_socket_t active = {
		.type = SOCKET_TYPE_UDP,
		.bound_addr = &local,
		.hole_punch_peer = &peer,
		.hole_punch = true,
		.peer_addr = addr4(0xcb007105, 41000),
		.hole_punch_timeout = 5000,
		.punch_transaction_id = 0x12345678,
	};
	fastd_socket_t expired = {
		.type = SOCKET_TYPE_UDP,
		.hole_punch_peer = &peer,
		.hole_punch = true,
		.peer_addr = addr4(0xcb007105, 41001),
		.hole_punch_timeout = 999,
	};
	fastd_socket_t public_listener = {
		.type = SOCKET_TYPE_UDP,
		.bound_addr = &public_local,
		.hole_punch = true,
		.punch_public_listener = true,
			.punch_listener_id = 77,
			.punch_listener_mapping_registered = true,
			.hole_punch_timeout = 6000,
			.punch_transaction_id = 0x87654321,
		.punch_listener_selected = 750,
		.punch_listener_public_addr = addr4(0xcb007105, 42000),
	};

	ctx.now = 1000;
	conf.peer_group = &group;
	conf.punch_max_sockets = DEFAULT_PUNCH_HARD_SYM_SOCKETS;
	ctx.punch_task_manager_runs = 9;
	ctx.punch_task_manager_pairs = 4;
	ctx.punch_task_manager_collected = 3;
	ctx.punch_task_manager_launched = 2;
	ctx.punch_task_manager_waiting = 1;
	ctx.punch_task_manager_in_flight = 15;
	ctx.punch_task_manager_missing_metadata = 5;
	ctx.punch_task_manager_metadata_requests = 18;
	ctx.punch_task_manager_metadata_relays = 19;
	ctx.punch_task_manager_blacklisted = 6;
	ctx.punch_task_manager_suppressed = 7;
	ctx.punch_task_manager_aborted = 16;
	ctx.punch_task_manager_recent_demand = 17;
	ctx.punch_task_manager_budget_exhausted = 1;
	ctx.punch_task_manager_next_retry = ctx.now + 12345;
	ctx.punch_task_manager_outcome_success = 8;
	ctx.punch_task_manager_outcome_failed = 9;
	ctx.punch_task_manager_outcome_accepted = 10;
	ctx.punch_task_manager_outcome_handshake = 11;
	ctx.punch_task_manager_outcome_suppressed = 12;
	ctx.punch_task_manager_outcome_no_peer = 13;
	ctx.punch_task_manager_outcome_busy = 14;
	ctx.punch_result_duplicates = 15;
	peer.last_punch_task = (fastd_peer_punch_task_t){
		.id = 101,
		.updated = ctx.now - 20,
		.next_retry = ctx.now + 10000,
		.role = PEER_PUNCH_TASK_ROLE_RELAY_DEST,
		.cause = PEER_PUNCH_TASK_CAUSE_RELAY_UDP,
		.command = PEER_PUNCH_TASK_COMMAND_HARD_SYM,
		.result = PEER_PUNCH_TASK_RESULT_NONE,
	};
	task_peer.last_punch_task = (fastd_peer_punch_task_t){
		.id = 102,
		.updated = ctx.now - 10,
		.next_retry = ctx.now + FASTD_PUNCH_SUPPRESSION_TIME,
		.role = PEER_PUNCH_TASK_ROLE_COMMAND_TARGET,
		.cause = PEER_PUNCH_TASK_CAUSE_LOCAL_POLICY,
		.command = PEER_PUNCH_TASK_COMMAND_CONE,
		.result = PEER_PUNCH_TASK_RESULT_SUPPRESSED,
	};
	VECTOR_ADD(ctx.peers, &peer);
	VECTOR_ADD(ctx.peers, &task_peer);
	VECTOR_ADD(ctx.udp_punch_socks, &active);
	VECTOR_ADD(ctx.udp_punch_socks, &expired);
	VECTOR_ADD(ctx.udp_punch_socks, &public_listener);
	fastd_punch_test_task_manager_record_pair_task(
		&peer, &task_peer, &peer, &task_peer, PUNCH_PAIR_TASK_STAGE_LAUNCHED, 2, 1,
		FASTD_TIMEOUT_INV, false);
	fastd_punch_test_task_manager_record_pair_task(
		&task_peer, &peer, NULL, NULL, PUNCH_PAIR_TASK_STAGE_WAITING, 0, 0, ctx.now + 6000, true);
	fastd_peer_address_t result_endpoint = addr4(0xcb007105, 43000);
	fastd_peer_add_punch_relay_backoff(&task_peer, &result_endpoint);
	fastd_punch_test_task_manager_record_pair_result(
		&task_peer, &peer, TEST_PUNCH_RESULT_BUSY, &result_endpoint);
	assert_int_equal(VECTOR_LEN(ctx.punch_pair_states), 1);
	VECTOR_INDEX(ctx.punch_pair_states, 0) = (fastd_punch_pair_runtime_t){
		.peer_a_id = 77,
		.peer_b_id = 78,
		.updated = ctx.now - 250,
		.in_flight_until = ctx.now + 5000,
		.backoff_until = ctx.now + 6000,
		.recent_demand_until = ctx.now + 7000,
		.demand_seq = 3,
		.served_demand_seq = 2,
		.launch_count = 4,
		.abort_count = 1,
		.result_count = 2,
		.busy_count = 1,
	};

	struct json_object *punch = fastd_status_test_dump_punch();
	struct json_object *pool = json_get_object_required(punch, "udp_punch_socket_pool");
	assert_int_equal(json_get_int_required(pool, "limit"), DEFAULT_PUNCH_HARD_SYM_SOCKETS);
	assert_int_equal(json_get_int_required(pool, "public_listener_limit"), DEFAULT_PUNCH_PUBLIC_LISTENERS);
	assert_int_equal(json_get_int_required(pool, "active"), 1);
	assert_int_equal(json_get_int_required(pool, "public_listeners"), 1);
	assert_int_equal(json_get_int_required(pool, "allocated"), 3);

	struct json_object *summary = json_get_object_required(punch, "task_summary");
	assert_int_equal(json_get_int_required(summary, "latest_tasks"), 2);
	assert_int_equal(json_get_int_required(summary, "waiting_tasks"), 2);
	assert_int_equal(json_get_int_required(summary, "relay_tasks"), 1);
	assert_int_equal(json_get_int_required(summary, "remote_result_tasks"), 0);
	assert_int_equal(json_get_int_required(summary, "candidate_added"), 0);
	assert_int_equal(json_get_int_required(summary, "handshake_sent"), 0);
	assert_int_equal(json_get_int_required(summary, "local_policy"), 1);
	assert_int_equal(json_get_int_required(summary, "result_suppressed"), 1);
	assert_int_equal(json_get_int_required(summary, "next_retry_min_ms"), 10000);

	struct json_object *manager = json_get_object_required(punch, "task_manager");
	assert_int_equal(json_get_int_required(manager, "runs"), 9);
	assert_int_equal(json_get_int_required(manager, "pairs"), 4);
	assert_int_equal(json_get_int_required(manager, "collected"), 3);
	assert_int_equal(json_get_int_required(manager, "launched"), 2);
	assert_int_equal(json_get_int_required(manager, "waiting"), 1);
	assert_int_equal(json_get_int_required(manager, "in_flight"), 15);
	assert_int_equal(json_get_int_required(manager, "missing_metadata"), 5);
	assert_int_equal(json_get_int_required(manager, "metadata_requests"), 18);
	assert_int_equal(json_get_int_required(manager, "metadata_relays"), 19);
	assert_int_equal(json_get_int_required(manager, "blacklisted"), 6);
	assert_int_equal(json_get_int_required(manager, "suppressed"), 7);
	assert_int_equal(json_get_int_required(manager, "aborted"), 16);
	assert_int_equal(json_get_int_required(manager, "recent_demand"), 17);
	assert_int_equal(json_get_int_required(manager, "runtime_states"), 1);
	assert_int_equal(json_get_int_required(manager, "runtime_limit"), FASTD_PUNCH_PAIR_STATE_LIMIT);
	struct json_object *runtime_states = json_get_array_required(manager, "runtime_state_list");
	assert_int_equal(json_object_array_length(runtime_states), 1);
	struct json_object *runtime_state = json_object_array_get_idx(runtime_states, 0);
	assert_int_equal(json_object_get_type(runtime_state), json_type_object);
	assert_int_equal(json_get_int_required(runtime_state, "peer_a_id"), 77);
	assert_int_equal(json_get_int_required(runtime_state, "peer_b_id"), 78);
	assert_string_equal(json_get_string_required(runtime_state, "peer_a"), "peer-a");
	assert_string_equal(json_get_string_required(runtime_state, "peer_b"), "peer-b");
	assert_string_equal(json_get_string_required(runtime_state, "state"), "in-flight");
	assert_string_equal(json_get_string_required(runtime_state, "reason"), "waiting-for-result");
	assert_int_equal(json_get_int_required(runtime_state, "updated_age"), 250);
	assert_true(json_get_bool_required(runtime_state, "in_flight"));
	assert_true(json_get_bool_required(runtime_state, "backoff"));
	assert_true(json_get_bool_required(runtime_state, "recent_demand"));
	assert_true(json_get_bool_required(runtime_state, "pending_demand"));
	assert_int_equal(json_get_int_required(runtime_state, "in_flight_ms"), 5000);
	assert_int_equal(json_get_int_required(runtime_state, "backoff_ms"), 6000);
	assert_int_equal(json_get_int_required(runtime_state, "recent_demand_ms"), 7000);
	assert_int_equal(json_get_int_required(runtime_state, "demand_seq"), 3);
	assert_int_equal(json_get_int_required(runtime_state, "served_demand_seq"), 2);
	assert_int_equal(json_get_int_required(runtime_state, "launch_count"), 4);
	assert_int_equal(json_get_int_required(runtime_state, "abort_count"), 1);
	assert_int_equal(json_get_int_required(runtime_state, "result_count"), 2);
	assert_int_equal(json_get_int_required(runtime_state, "busy_count"), 1);
	assert_int_equal(json_get_int_required(manager, "budget_exhausted"), 1);
	assert_int_equal(json_get_int_required(manager, "next_retry_min_ms"), 12345);
	assert_int_equal(json_get_int_required(manager, "outcome_success"), 8);
	assert_int_equal(json_get_int_required(manager, "outcome_failed"), 9);
	assert_int_equal(json_get_int_required(manager, "outcome_accepted"), 10);
	assert_int_equal(json_get_int_required(manager, "outcome_handshake"), 11);
	assert_int_equal(json_get_int_required(manager, "outcome_suppressed"), 12);
	assert_int_equal(json_get_int_required(manager, "outcome_no_peer"), 13);
	assert_int_equal(json_get_int_required(manager, "outcome_busy"), 14);
	assert_int_equal(json_get_int_required(manager, "history_limit"), FASTD_PUNCH_PAIR_TASK_HISTORY);
	assert_int_equal(json_get_int_required(manager, "history_count"), 3);
	struct json_object *history = json_get_array_required(manager, "history");
	assert_int_equal(json_object_array_length(history), 3);
	struct json_object *latest_task = json_object_array_get_idx(history, 0);
	assert_string_equal(json_get_string_required(latest_task, "stage"), "result-busy");
	assert_int_equal(json_get_int_required(latest_task, "id"), 203);
	assert_int_equal(json_get_int_required(latest_task, "peer_a_id"), 77);
	assert_int_equal(json_get_int_required(latest_task, "peer_b_id"), 78);
	assert_string_equal(json_get_string_required(latest_task, "subject"), "peer-a");
	assert_string_equal(json_get_string_required(latest_task, "destination"), "peer-b");
	assert_int_equal(json_get_int_required(latest_task, "backoff_skipped"), 1);
	assert_int_equal(json_get_int_required(latest_task, "next_retry_ms"), FASTD_PUNCH_SUPPRESSION_TIME);
	assert_false(json_get_bool_required(latest_task, "budget_exhausted"));
	struct json_object *waiting_task = json_object_array_get_idx(history, 1);
	assert_string_equal(json_get_string_required(waiting_task, "stage"), "waiting");
	assert_int_equal(json_get_int_required(waiting_task, "id"), 202);
	assert_int_equal(json_get_int_required(waiting_task, "peer_a_id"), 77);
	assert_int_equal(json_get_int_required(waiting_task, "peer_b_id"), 78);
	assert_string_equal(json_get_string_required(waiting_task, "peer_a"), "peer-a");
	assert_string_equal(json_get_string_required(waiting_task, "peer_b"), "peer-b");
	assert_int_equal(json_get_int_required(waiting_task, "next_retry_ms"), 6000);
	assert_true(json_get_bool_required(waiting_task, "budget_exhausted"));
	struct json_object *older_task = json_object_array_get_idx(history, 2);
	assert_string_equal(json_get_string_required(older_task, "stage"), "launched");
	assert_int_equal(json_get_int_required(older_task, "id"), 201);
	assert_int_equal(json_get_int_required(older_task, "subject_id"), 77);
	assert_int_equal(json_get_int_required(older_task, "destination_id"), 78);
	assert_string_equal(json_get_string_required(older_task, "subject"), "peer-a");
	assert_string_equal(json_get_string_required(older_task, "destination"), "peer-b");
	assert_int_equal(json_get_int_required(older_task, "candidates_sent"), 2);
	assert_int_equal(json_get_int_required(older_task, "backoff_skipped"), 1);
	assert_false(json_get_bool_required(older_task, "budget_exhausted"));

	struct json_object *counters = json_get_object_required(punch, "counters");
	assert_int_equal(json_get_int_required(counters, "result_duplicates"), 15);

	struct json_object *sockets = json_get_array_required(pool, "sockets");
	assert_int_equal(json_object_array_length(sockets), 2);
	struct json_object *socket = json_object_array_get_idx(sockets, 0);
	assert_int_equal(json_object_get_type(socket), json_type_object);
	assert_string_equal(json_get_string_required(socket, "kind"), "peer-punch");
	assert_string_equal(json_get_string_required(socket, "peer"), "peer-a");
	assert_int_equal(json_get_int_required(socket, "peer_id"), 77);
	assert_non_null(strstr(json_get_string_required(socket, "remote"), "41000"));
	assert_non_null(strstr(json_get_string_required(socket, "local"), "35000"));
	assert_int_equal(json_get_int_required(socket, "expires_in"), 4000);
	assert_int_equal(json_get_int_required(socket, "transaction_id"), 0x12345678);

	struct json_object *listener = json_object_array_get_idx(sockets, 1);
	assert_int_equal(json_object_get_type(listener), json_type_object);
	assert_string_equal(json_get_string_required(listener, "kind"), "public-listener");
	assert_non_null(strstr(json_get_string_required(listener, "public_endpoint"), "42000"));
	assert_int_equal(json_get_int_required(listener, "listener_id"), 77);
	assert_non_null(strstr(json_get_string_required(listener, "local"), "35001"));
		assert_int_equal(json_get_int_required(listener, "expires_in"), 5000);
		assert_int_equal(json_get_int_required(listener, "selected_age"), 250);
		assert_true(json_get_bool_required(listener, "mapping_registered"));
		assert_false(json_get_bool_required(listener, "port_mapped"));
	assert_int_equal(json_get_int_required(listener, "transaction_id"), 0x87654321);

	json_object_put(punch);
	VECTOR_FREE(ctx.udp_punch_socks);
	VECTOR_FREE(ctx.peers);
	VECTOR_FREE(ctx.punch_pair_states);
	VECTOR_FREE(task_peer.punch_relay_backoffs);
	ctx.udp_punch_socks = old_udp_punch_socks;
	ctx.peers = old_peers;
	ctx.punch_pair_states = old_pair_states;
	conf.peer_group = old_peer_group;
	ctx.punch_task_manager_runs = old_task_manager_runs;
	ctx.punch_task_manager_pairs = old_task_manager_pairs;
	ctx.punch_task_manager_collected = old_task_manager_collected;
	ctx.punch_task_manager_launched = old_task_manager_launched;
	ctx.punch_task_manager_waiting = old_task_manager_waiting;
	ctx.punch_task_manager_in_flight = old_task_manager_in_flight;
	ctx.punch_task_manager_missing_metadata = old_task_manager_missing_metadata;
	ctx.punch_task_manager_metadata_requests = old_task_manager_metadata_requests;
	ctx.punch_task_manager_metadata_relays = old_task_manager_metadata_relays;
	ctx.punch_task_manager_blacklisted = old_task_manager_blacklisted;
	ctx.punch_task_manager_suppressed = old_task_manager_suppressed;
	ctx.punch_task_manager_aborted = old_task_manager_aborted;
	ctx.punch_task_manager_recent_demand = old_task_manager_recent_demand;
	ctx.punch_task_manager_budget_exhausted = old_task_manager_budget_exhausted;
	ctx.punch_task_manager_next_retry = old_task_manager_next_retry;
	ctx.punch_task_manager_outcome_success = old_task_manager_outcome_success;
	ctx.punch_task_manager_outcome_failed = old_task_manager_outcome_failed;
	ctx.punch_task_manager_outcome_accepted = old_task_manager_outcome_accepted;
	ctx.punch_task_manager_outcome_handshake = old_task_manager_outcome_handshake;
	ctx.punch_task_manager_outcome_suppressed = old_task_manager_outcome_suppressed;
	ctx.punch_task_manager_outcome_no_peer = old_task_manager_outcome_no_peer;
	ctx.punch_task_manager_outcome_busy = old_task_manager_outcome_busy;
	ctx.punch_result_duplicates = old_result_duplicates;
	memcpy(ctx.punch_pair_tasks, old_pair_tasks, sizeof(old_pair_tasks));
	ctx.next_punch_pair_task_id = old_next_pair_task_id;
	ctx.punch_pair_task_pos = old_pair_task_pos;
	ctx.punch_pair_task_count = old_pair_task_count;
}

#endif

static void test_punch_detects_noncurrent_exact_candidate(void **state UNUSED) {
	fastd_peer_t peer = {};
	const fastd_peer_address_t current = addr4(0xcb007105, 41000);
	const fastd_peer_address_t other = addr4(0xcb007105, 41001);
	bool exact_udp_punch = false;
	unsigned udp_punch_sockets = 0;

	ctx.now = 1000;
	VECTOR_ADD(
		peer.direct_candidates, ((fastd_peer_direct_candidate_t){
						.remote = current,
						.timeout = ctx.now + 10000,
						.priority = 120,
						.order = 0,
						.source = DIRECT_CANDIDATE_PUNCH_CONTROL,
						.exact_udp_punch = true,
						.udp_punch_sockets = 3,
					}));
	VECTOR_ADD(
		peer.direct_candidates, ((fastd_peer_direct_candidate_t){
						.remote = other,
						.timeout = ctx.now + 10000,
						.priority = 120,
						.order = 1,
						.source = DIRECT_CANDIDATE_PUNCH_CONTROL,
						.exact_udp_punch = true,
						.udp_punch_sockets = 5,
					}));

	peer.direct_remote = current;
	peer.direct_remote_timeout = ctx.now + 10000;
	peer.direct_remote_source = DIRECT_CANDIDATE_PUNCH_CONTROL;
	peer.direct_remote_exact_udp = true;
	peer.direct_remote_udp_punch_sockets = 3;

	assert_true(fastd_peer_is_current_punch_candidate(&peer, &current));
	assert_false(fastd_peer_is_current_punch_candidate(&peer, &other));

	assert_true(fastd_peer_is_punch_control_candidate(&peer, &other, &exact_udp_punch, &udp_punch_sockets));
	assert_true(exact_udp_punch);
	assert_int_equal(udp_punch_sockets, 5);
	assert_true(fastd_peer_is_punch_candidate(&peer, &other));

	VECTOR_FREE(peer.direct_candidates);
}

static void test_endpoint_dependent_candidate_matches_same_ip(void **state UNUSED) {
	fastd_peer_t peer = {};
	const fastd_peer_address_t candidate_addr = addr4(0xcb007105, 41000);
	const fastd_peer_address_t remapped_addr = addr4(0xcb007105, 52000);
	const fastd_peer_address_t other_addr = addr4(0xcb007106, 52000);
	fastd_peer_direct_candidate_source_t source = DIRECT_CANDIDATE_REALM;

	ctx.now = 1000;
	peer.punch_nat_type = FASTD_NAT_SYMMETRIC_EASY_INC;
	peer.punch_timeout = ctx.now + 10000;
	VECTOR_ADD(
		peer.direct_candidates, ((fastd_peer_direct_candidate_t){
						.remote = candidate_addr,
						.timeout = ctx.now + 10000,
						.priority = 120,
						.order = 0,
						.source = DIRECT_CANDIDATE_PUNCH_CONTROL,
					}));

	assert_false(fastd_peer_get_direct_candidate_source(&peer, &remapped_addr, NULL));
	assert_true(fastd_peer_get_endpoint_dependent_candidate_source(&peer, &remapped_addr, &source));
	assert_int_equal(source, DIRECT_CANDIDATE_PUNCH_CONTROL);
	assert_false(fastd_peer_get_endpoint_dependent_candidate_source(&peer, &other_addr, NULL));

	peer.punch_nat_type = FASTD_NAT_FULL_CONE;
	assert_false(fastd_peer_get_endpoint_dependent_candidate_source(&peer, &remapped_addr, NULL));

	peer.punch_nat_type = FASTD_NAT_SYMMETRIC;
	peer.punch_timeout = ctx.now - 1;
	assert_false(fastd_peer_get_endpoint_dependent_candidate_source(&peer, &remapped_addr, NULL));

	VECTOR_FREE(peer.direct_candidates);
}

static void test_direct_candidate_transport_scope(void **state UNUSED) {
	fastd_peer_t peer = {};
	const fastd_peer_address_t candidate_addr = addr4(0xcb007105, 41000);
	const fastd_peer_address_t remapped_addr = addr4(0xcb007105, 52000);
	fastd_peer_direct_candidate_source_t source = DIRECT_CANDIDATE_REALM;
	bool exact_udp_punch = true;
	unsigned udp_punch_sockets = 7;

	ctx.now = 1000;
	peer.punch_nat_type = FASTD_NAT_SYMMETRIC;
	peer.punch_timeout = ctx.now + 10000;
	VECTOR_ADD(
		peer.direct_candidates, ((fastd_peer_direct_candidate_t){
						.remote = candidate_addr,
						.timeout = ctx.now + 10000,
						.priority = 120,
						.order = 0,
						.transports = DIRECT_CANDIDATE_TRANSPORT_TCP,
						.source = DIRECT_CANDIDATE_PUNCH_CONTROL,
					}));

	peer.direct_remote = candidate_addr;
	peer.direct_remote_timeout = ctx.now + 10000;
	peer.direct_remote_source = DIRECT_CANDIDATE_PUNCH_CONTROL;
	peer.direct_remote_transports = DIRECT_CANDIDATE_TRANSPORT_TCP;

	assert_true(fastd_peer_get_direct_candidate_source(&peer, &candidate_addr, &source));
	assert_int_equal(source, DIRECT_CANDIDATE_PUNCH_CONTROL);
	assert_true(fastd_peer_get_direct_candidate_source_transport(&peer, &candidate_addr, TRANSPORT_TCP, NULL));
	assert_false(fastd_peer_get_direct_candidate_source_transport(&peer, &candidate_addr, TRANSPORT_UDP, NULL));

	assert_true(fastd_peer_get_endpoint_dependent_candidate_source_transport(
		&peer, &remapped_addr, TRANSPORT_TCP, NULL));
	assert_false(fastd_peer_get_endpoint_dependent_candidate_source_transport(
		&peer, &remapped_addr, TRANSPORT_UDP, NULL));

	assert_true(fastd_peer_is_current_punch_control_candidate_transport(
		&peer, &candidate_addr, TRANSPORT_TCP, &exact_udp_punch, &udp_punch_sockets));
	assert_false(exact_udp_punch);
	assert_int_equal(udp_punch_sockets, 0);
	assert_false(fastd_peer_is_current_punch_control_candidate_transport(
		&peer, &candidate_addr, TRANSPORT_UDP, NULL, NULL));
	assert_false(fastd_peer_is_punch_candidate(&peer, &candidate_addr));

	VECTOR_FREE(peer.direct_candidates);
}

static void test_udp_punch_family_policy_allows_ipv6_deterministic(void **state UNUSED) {
	assert_true(fastd_socket_test_udp_punch_exact_family_supported(AF_INET));
	assert_true(fastd_socket_test_udp_punch_exact_family_supported(AF_INET6));
	assert_false(fastd_socket_test_udp_punch_exact_family_supported(AF_UNSPEC));

	assert_true(fastd_socket_test_udp_punch_deterministic_family_supported(AF_INET));
	assert_true(fastd_socket_test_udp_punch_deterministic_family_supported(AF_INET6));
	assert_false(fastd_socket_test_udp_punch_deterministic_family_supported(AF_UNSPEC));
}

static void test_udp_punch_socket_counts_public_listeners_separately(void **state UNUSED) {
	__typeof__(ctx.udp_punch_socks) old_udp_punch_socks = ctx.udp_punch_socks;
	ctx.udp_punch_socks = (__typeof__(ctx.udp_punch_socks)){};

	fastd_socket_t active = {
		.type = SOCKET_TYPE_UDP,
		.hole_punch = true,
		.hole_punch_timeout = 5000,
	};
	fastd_socket_t public_listener = {
		.type = SOCKET_TYPE_UDP,
		.hole_punch = true,
		.punch_public_listener = true,
		.hole_punch_timeout = 5000,
		.punch_listener_public_addr = addr4(0xcb007105, 42000),
	};
	fastd_socket_t expired_public_listener = {
		.type = SOCKET_TYPE_UDP,
		.hole_punch = true,
		.punch_public_listener = true,
		.hole_punch_timeout = 999,
		.punch_listener_public_addr = addr4(0xcb007105, 42001),
	};

	ctx.now = 1000;
	VECTOR_ADD(ctx.udp_punch_socks, &active);
	VECTOR_ADD(ctx.udp_punch_socks, &public_listener);
	VECTOR_ADD(ctx.udp_punch_socks, &expired_public_listener);

	assert_true(fastd_socket_test_udp_punch_public_listener_available(&public_listener));
	assert_false(fastd_socket_test_udp_punch_public_listener_available(&expired_public_listener));
	assert_int_equal(fastd_socket_test_udp_punch_active_socket_count(), 1);
	assert_int_equal(fastd_socket_test_udp_punch_public_listener_count(), 1);

	VECTOR_FREE(ctx.udp_punch_socks);
	ctx.udp_punch_socks = old_udp_punch_socks;
}

static void test_udp_punch_public_listener_selection_policy(void **state UNUSED) {
	__typeof__(ctx.udp_punch_socks) old_udp_punch_socks = ctx.udp_punch_socks;
	ctx.udp_punch_socks = (__typeof__(ctx.udp_punch_socks)){};

	fastd_socket_t older = {
		.type = SOCKET_TYPE_UDP,
		.hole_punch = true,
		.punch_public_listener = true,
		.punch_listener_id = 1,
		.hole_punch_timeout = 5000,
		.punch_listener_selected = 100,
		.punch_listener_public_addr = addr4(0xcb007105, 42000),
	};
	fastd_socket_t mapped = {
		.type = SOCKET_TYPE_UDP,
		.hole_punch = true,
		.punch_public_listener = true,
		.punch_listener_port_mapped = true,
		.punch_listener_id = 2,
		.hole_punch_timeout = 5000,
		.punch_listener_selected = 200,
		.punch_listener_public_addr = addr4(0xcb007105, 42001),
	};
	fastd_socket_t newest = {
		.type = SOCKET_TYPE_UDP,
		.hole_punch = true,
		.punch_public_listener = true,
		.punch_listener_id = 3,
		.hole_punch_timeout = 5000,
		.punch_listener_selected = 300,
		.punch_listener_public_addr = addr4(0xcb007105, 42002),
	};

	ctx.now = 1000;
	VECTOR_ADD(ctx.udp_punch_socks, &older);
	VECTOR_ADD(ctx.udp_punch_socks, &mapped);
	VECTOR_ADD(ctx.udp_punch_socks, &newest);

	assert_true(fastd_socket_test_udp_punch_should_create_public_listener(0, false, false, false, false));
	assert_true(fastd_socket_test_udp_punch_should_create_public_listener(1, true, true, true, false));
	assert_false(fastd_socket_test_udp_punch_should_create_public_listener(
		DEFAULT_PUNCH_PUBLIC_LISTENERS, true, true, true, false));
	assert_true(fastd_socket_test_udp_punch_should_create_public_listener(1, true, false, false, true));
	assert_false(fastd_socket_test_udp_punch_should_create_public_listener(1, true, true, false, true));
	assert_int_equal(fastd_socket_test_udp_punch_select_public_listener_id(AF_INET, false), 3);
	assert_int_equal(fastd_socket_test_udp_punch_select_public_listener_id(AF_INET, true), 2);

	VECTOR_FREE(ctx.udp_punch_socks);
	ctx.udp_punch_socks = old_udp_punch_socks;
}

static void test_public_listener_port_mapping_lifecycle(void **state UNUSED) {
	fastd_port_mapping_t *old_port_mapping = ctx.port_mapping;
	ctx.port_mapping = NULL;

	fastd_peer_address_t bound = addr4(0x00000000, 40000);
	fastd_socket_t sock = {
		.type = SOCKET_TYPE_UDP,
		.hole_punch = true,
		.punch_public_listener = true,
		.bound_addr = &bound,
	};

	assert_false(fastd_port_mapping_register_socket(&sock));
	assert_false(sock.punch_listener_mapping_registered);

	fastd_port_mapping_test_begin(true, true);
	assert_true(fastd_port_mapping_register_socket(&sock));
	assert_true(sock.punch_listener_mapping_registered);

	bool use_natpmp = false, use_upnp = false;
	uint16_t natpmp_refs = 0, upnp_refs = 0;
	assert_true(
		fastd_port_mapping_test_get_entry(40000, &use_natpmp, &use_upnp, &natpmp_refs, &upnp_refs));
	assert_true(use_natpmp);
	assert_true(use_upnp);
	assert_int_equal(natpmp_refs, 1);
	assert_int_equal(upnp_refs, 1);
	assert_int_equal(fastd_port_mapping_test_entry_count(), 1);

	fastd_hole_punch_claim_socket(&sock);
	assert_false(sock.punch_public_listener);
	assert_true(sock.punch_listener_mapping_registered);

	fastd_port_mapping_release_socket(&sock);
	assert_false(sock.punch_listener_mapping_registered);
	assert_int_equal(fastd_port_mapping_test_entry_count(), 0);

	__typeof__(ctx.udp_punch_socks) old_udp_punch_socks = ctx.udp_punch_socks;
	ctx.udp_punch_socks = (__typeof__(ctx.udp_punch_socks)){};

	fastd_peer_address_t bound_cleanup = addr4(0x00000000, 40001);
	fastd_socket_t cleanup_sock = {
		.type = SOCKET_TYPE_UDP,
		.hole_punch = true,
		.punch_public_listener = true,
		.punch_listener_port_mapped = true,
		.bound_addr = &bound_cleanup,
	};

	assert_true(fastd_port_mapping_register_socket(&cleanup_sock));
	VECTOR_ADD(ctx.udp_punch_socks, &cleanup_sock);
	fastd_port_mapping_cleanup();
	assert_false(cleanup_sock.punch_listener_mapping_registered);
	assert_false(cleanup_sock.punch_listener_port_mapped);
	assert_null(ctx.port_mapping);

	VECTOR_FREE(ctx.udp_punch_socks);
	ctx.udp_punch_socks = old_udp_punch_socks;
	ctx.port_mapping = old_port_mapping;
}

static void test_punch_socket_count_policy(void **state UNUSED) {
	fastd_peer_t peer = {};

	conf.punch_symmetric = true;
	conf.punch_max_sockets = 25;

	assert_int_equal(
		fastd_punch_test_udp_socket_count_for_nat(
			&peer, FASTD_NAT_SYMMETRIC_EASY_INC, false, FASTD_NAT_UNKNOWN),
		1);
	assert_int_equal(
		fastd_punch_test_udp_socket_count_for_nat(&peer, FASTD_NAT_SYMMETRIC, false, FASTD_NAT_UNKNOWN), 1);

	assert_int_equal(
		fastd_punch_test_udp_socket_count_for_nat(
			&peer, FASTD_NAT_FULL_CONE, true, FASTD_NAT_SYMMETRIC_EASY_DEC),
		25);
	assert_int_equal(
		fastd_punch_test_udp_socket_count_for_nat(&peer, FASTD_NAT_FULL_CONE, true, FASTD_NAT_SYMMETRIC), 25);
	assert_int_equal(
		fastd_punch_test_udp_socket_count_for_command(
			&peer, TEST_PUNCH_BOTH_EASY_SYM, FASTD_NAT_SYMMETRIC_EASY_INC, false, FASTD_NAT_UNKNOWN),
		1);
	assert_int_equal(
		fastd_punch_test_udp_socket_count_for_command(
			&peer, TEST_PUNCH_SEND_TCP, FASTD_NAT_FULL_CONE, true, FASTD_NAT_SYMMETRIC),
		0);

	peer.punch_symmetric = FASTD_TRISTATE_FALSE;
	assert_int_equal(
		fastd_punch_test_udp_socket_count_for_nat(
			&peer, FASTD_NAT_SYMMETRIC_EASY_INC, true, FASTD_NAT_SYMMETRIC_EASY_INC),
		0);
	assert_int_equal(
		fastd_punch_test_udp_socket_count_for_command(
			&peer, TEST_PUNCH_BOTH_EASY_SYM, FASTD_NAT_SYMMETRIC_EASY_INC, true,
			FASTD_NAT_SYMMETRIC_EASY_INC),
		0);

	conf.punch_symmetric = false;
}

static void test_punch_hard_symmetric_uses_easytier_grade_defaults(void **state UNUSED) {
	fastd_peer_t peer = {};
	fastd_peer_address_t out[DEFAULT_PUNCH_HARD_SYM_PACKETS];
	const fastd_peer_address_t endpoint = addr4(0xcb007105, 41000);
	uint32_t next_index = 0;
	uint32_t round = 0;

	conf.punch_symmetric = true;
	conf.punch_max_sockets = DEFAULT_PUNCH_HARD_SYM_SOCKETS;
	conf.punch_max_packets = DEFAULT_PUNCH_HARD_SYM_PACKETS;

	assert_int_equal(
		fastd_punch_test_udp_socket_count_for_nat(
			&peer, FASTD_NAT_FULL_CONE, true, FASTD_NAT_SYMMETRIC),
		DEFAULT_PUNCH_HARD_SYM_SOCKETS);
	assert_int_equal(
		fastd_punch_test_udp_socket_count_for_nat(
			&peer, FASTD_NAT_FULL_CONE, true, FASTD_NAT_SYMMETRIC_EASY_INC),
		DEFAULT_PUNCH_EASY_SYM_SOCKETS);

	assert_int_equal(
		fastd_punch_test_relay_candidate_count(TEST_PUNCH_SEND_HARD_SYM, 1000),
		DEFAULT_PUNCH_HARD_SYM_PACKETS);
	assert_int_equal(fastd_punch_test_relay_candidate_count(TEST_PUNCH_SEND_HARD_SYM, 300), 300);
	assert_int_equal(
		fastd_punch_test_relay_candidate_count(TEST_PUNCH_SEND_EASY_SYM, 1000),
		DEFAULT_PUNCH_EASY_SYM_SOCKETS);
	assert_int_equal(fastd_punch_test_relay_candidate_count(TEST_PUNCH_SEND_CONE, 1000), 1);

	size_t n = fastd_punch_test_build_hard_symmetric_endpoint_candidates(
		out, array_size(out), &endpoint, DEFAULT_PUNCH_HARD_SYM_PACKETS, 0, &next_index, &round);
	assert_int_equal(n, DEFAULT_PUNCH_HARD_SYM_PACKETS);
	assert_int_equal(next_index, DEFAULT_PUNCH_HARD_SYM_PACKETS - 1);

	conf.punch_max_sockets = 12;
	conf.punch_max_packets = 120;
	assert_int_equal(
		fastd_punch_test_relay_candidate_count(TEST_PUNCH_SEND_EASY_SYM, 1000), 12);
	assert_int_equal(
		fastd_punch_test_relay_candidate_count(TEST_PUNCH_SEND_HARD_SYM, 1000), 120);

	conf.punch_symmetric = false;
}

static void test_punch_socket_count_honors_explicit_request(void **state UNUSED) {
	fastd_peer_t peer = {};

	conf.punch_symmetric = true;
	conf.punch_max_sockets = 25;

	assert_int_equal(
		fastd_punch_test_udp_socket_count_for_request_nat(
			&peer, TEST_PUNCH_SEND_CONE, FASTD_NAT_FULL_CONE, 0, true, FASTD_NAT_SYMMETRIC),
		25);

	assert_int_equal(
		fastd_punch_test_udp_socket_count_for_request_nat(
			&peer, TEST_PUNCH_SEND_CONE, FASTD_NAT_FULL_CONE, 8, true, FASTD_NAT_SYMMETRIC),
		8);

	assert_int_equal(
		fastd_punch_test_udp_socket_count_for_request_nat(
			&peer, TEST_PUNCH_SEND_CONE, FASTD_NAT_FULL_CONE, 80, true, FASTD_NAT_SYMMETRIC),
		25);

	peer.punch_symmetric = FASTD_TRISTATE_FALSE;
	assert_int_equal(
		fastd_punch_test_udp_socket_count_for_request_nat(
			&peer, TEST_PUNCH_SEND_CONE, FASTD_NAT_FULL_CONE, 8, true, FASTD_NAT_SYMMETRIC),
		0);

	peer.punch_symmetric = FASTD_TRISTATE_UNDEF;
	assert_int_equal(
		fastd_punch_test_udp_socket_count_for_request_nat(
			&peer, TEST_PUNCH_SEND_TCP, FASTD_NAT_FULL_CONE, 8, true, FASTD_NAT_SYMMETRIC),
		0);

	conf.punch_symmetric = false;
}

static void test_punch_selects_endpoint_command_types(void **state UNUSED) {
	fastd_peer_t dest = {};
	fastd_peer_t subject = {};

	ctx.now = 1000;
	conf.punch_symmetric = true;

	assert_int_equal(
		fastd_punch_test_endpoint_command_type(&dest, &subject, FASTD_NAT_FULL_CONE), TEST_PUNCH_SEND_CONE);
	assert_int_equal(
		fastd_punch_test_endpoint_command_type(&dest, &subject, FASTD_NAT_SYMMETRIC_EASY_INC),
		TEST_PUNCH_SEND_EASY_SYM);

	assert_int_equal(
		fastd_punch_test_endpoint_command_type(&dest, &subject, FASTD_NAT_SYMMETRIC), TEST_PUNCH_SEND_HARD_SYM);

	dest.punch_endpoint = addr4(0xcb007107, 43000);
	dest.punch_nat_type = FASTD_NAT_SYMMETRIC_EASY_DEC;
	dest.punch_timeout = ctx.now + 1000;
	assert_int_equal(
		fastd_punch_test_endpoint_command_type(&dest, &subject, FASTD_NAT_SYMMETRIC_EASY_INC),
		TEST_PUNCH_BOTH_EASY_SYM);

	subject.punch_symmetric = FASTD_TRISTATE_FALSE;
	assert_int_equal(
		fastd_punch_test_endpoint_command_type(&dest, &subject, FASTD_NAT_SYMMETRIC_EASY_INC),
		TEST_PUNCH_SEND_CONE);
	assert_int_equal(
		fastd_punch_test_endpoint_command_type(&dest, &subject, FASTD_NAT_SYMMETRIC), TEST_PUNCH_SEND_CONE);

	conf.punch_symmetric = false;
}

static void test_punch_probe_parses_valid_request(void **state UNUSED) {
	uint8_t buf[64];
	uint8_t type = 0;
	uint32_t transaction = 0;
	size_t key_len = 0;

	size_t len = fastd_punch_probe_test_build(buf, sizeof(buf), TEST_PUNCH_PROBE_REQUEST, 0x12345678, 32);

	assert_int_equal(len, 48);
	assert_true(fastd_punch_probe_test_parse(buf, len, &type, &transaction, &key_len));
	assert_int_equal(type, TEST_PUNCH_PROBE_REQUEST);
	assert_int_equal(transaction, 0x12345678);
	assert_int_equal(key_len, 32);
}

static void test_punch_probe_parses_valid_response(void **state UNUSED) {
	uint8_t buf[64];
	uint8_t type = 0;
	uint32_t transaction = 0;
	size_t key_len = 0;

	size_t len = fastd_punch_probe_test_build(buf, sizeof(buf), TEST_PUNCH_PROBE_RESPONSE, 0xaabbccdd, 4);

	assert_int_equal(len, 20);
	assert_true(fastd_punch_probe_test_parse(buf, len, &type, &transaction, &key_len));
	assert_int_equal(type, TEST_PUNCH_PROBE_RESPONSE);
	assert_int_equal(transaction, 0xaabbccdd);
	assert_int_equal(key_len, 4);
}

static void test_punch_probe_rejects_bad_magic(void **state UNUSED) {
	uint8_t buf[64];
	size_t len = fastd_punch_probe_test_build(buf, sizeof(buf), TEST_PUNCH_PROBE_REQUEST, 1, 4);

	buf[0] = 0;
	assert_false(fastd_punch_probe_test_parse(buf, len, NULL, NULL, NULL));
}

static void test_punch_probe_rejects_bad_version(void **state UNUSED) {
	uint8_t buf[64];
	size_t len = fastd_punch_probe_test_build(buf, sizeof(buf), TEST_PUNCH_PROBE_REQUEST, 1, 4);

	buf[4] = 2;
	assert_false(fastd_punch_probe_test_parse(buf, len, NULL, NULL, NULL));
}

static void test_punch_probe_rejects_bad_type(void **state UNUSED) {
	uint8_t buf[64];
	size_t len = fastd_punch_probe_test_build(buf, sizeof(buf), TEST_PUNCH_PROBE_REQUEST, 1, 4);

	buf[5] = 99;
	assert_false(fastd_punch_probe_test_parse(buf, len, NULL, NULL, NULL));
}

static void test_punch_probe_rejects_bad_length(void **state UNUSED) {
	uint8_t buf[64];
	size_t len = fastd_punch_probe_test_build(buf, sizeof(buf), TEST_PUNCH_PROBE_REQUEST, 1, 4);

	buf[6] = 0;
	buf[7] = 17;
	assert_false(fastd_punch_probe_test_parse(buf, len, NULL, NULL, NULL));
}

int main(void) {
#ifndef WITH_NAT_DETECT
	printf("1..0 # Skipped: NAT detection not included\n");
	return 0;
#else
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_nat_classifies_open_internet),
		cmocka_unit_test(test_nat_classifies_symmetric_udp_firewall),
		cmocka_unit_test(test_nat_classifies_full_cone),
		cmocka_unit_test(test_nat_classifies_restricted),
		cmocka_unit_test(test_nat_classifies_port_restricted),
		cmocka_unit_test(test_nat_classifies_no_pat),
		cmocka_unit_test(test_nat_classifies_easy_symmetric_inc),
		cmocka_unit_test(test_nat_classifies_hard_symmetric),
		cmocka_unit_test(test_nat_detects_easy_symmetric_dec_delta),
		cmocka_unit_test(test_nat_rejects_unstable_delta),
		cmocka_unit_test(test_nat_collects_unique_public_endpoints_by_ip),
		cmocka_unit_test(test_tcp_nat_classifies_open_internet),
		cmocka_unit_test(test_tcp_nat_classifies_unknown_with_one_translated_sample),
		cmocka_unit_test(test_tcp_nat_classifies_no_pat),
		cmocka_unit_test(test_tcp_nat_classifies_full_cone),
		cmocka_unit_test(test_tcp_nat_classifies_symmetric),
		cmocka_unit_test(test_punch_uses_exact_endpoint_when_symmetric_disabled),
			cmocka_unit_test(test_punch_predicts_easy_symmetric_inc),
			cmocka_unit_test(test_punch_predicts_easy_symmetric_dec),
			cmocka_unit_test(test_punch_predicts_ipv6_easy_symmetric_inc),
			cmocka_unit_test(test_punch_pairs_easy_symmetric_dec_from_easytier_offset),
			cmocka_unit_test(test_punch_pairs_easy_symmetric_inc_from_easytier_offset),
			cmocka_unit_test(test_punch_clamps_easy_symmetric_step),
		cmocka_unit_test(test_punch_builds_multi_endpoint_candidates_with_budget),
			cmocka_unit_test(test_punch_builds_per_endpoint_metadata_candidates),
			cmocka_unit_test(test_punch_advances_hard_symmetric_scan_per_endpoint),
			cmocka_unit_test(test_punch_scans_hard_symmetric_when_symmetric_enabled),
			cmocka_unit_test(test_punch_scans_ipv6_hard_symmetric_when_symmetric_enabled),
			cmocka_unit_test(test_punch_ipv6_hard_symmetric_seed_uses_address),
			cmocka_unit_test(test_punch_prefers_hard_symmetric_observed_port_range),
		cmocka_unit_test(test_punch_advances_hard_symmetric_scan_index),
		cmocka_unit_test(test_punch_counts_hard_symmetric_scan_rounds),
		cmocka_unit_test(test_punch_keeps_hard_symmetric_exact_when_symmetric_disabled),
		cmocka_unit_test(test_punch_skips_out_of_range_predicted_ports),
		cmocka_unit_test(test_punch_respects_output_limit),
		cmocka_unit_test(test_punch_parses_valid_message),
		cmocka_unit_test(test_punch_parses_packet_count),
		cmocka_unit_test(test_punch_parses_result_message),
		cmocka_unit_test(test_punch_parses_result_ext_message),
		cmocka_unit_test(test_punch_parses_result_listener_message),
		cmocka_unit_test(test_punch_parses_listener_info_message),
		cmocka_unit_test(test_punch_parses_command_listener_message),
		cmocka_unit_test(test_punch_parses_all_endpoint_command_messages),
		cmocka_unit_test(test_punch_parses_tcp_nat_info_message),
		cmocka_unit_test(test_punch_parses_extra_nat_info_messages),
		cmocka_unit_test(test_punch_promotes_port_mapping_nat_info),
		cmocka_unit_test(test_punch_rejects_zero_port_mapping_nat_info),
		cmocka_unit_test(test_punch_rejects_bad_magic),
		cmocka_unit_test(test_punch_rejects_bad_version),
		cmocka_unit_test(test_punch_rejects_bad_length),
		cmocka_unit_test(test_punch_rejects_bad_key_length),
		cmocka_unit_test(test_punch_suppresses_failed_endpoint_temporarily),
		cmocka_unit_test(test_punch_suppression_is_bounded),
		cmocka_unit_test(test_punch_result_backoff_policy),
		cmocka_unit_test(test_punch_relay_backoff_expires),
		cmocka_unit_test(test_punch_relay_backoff_is_bounded),
		cmocka_unit_test(test_peer_punch_symmetric_inherits_and_overrides),
		cmocka_unit_test(test_nat_traversal_inherits_and_overrides),
		cmocka_unit_test(test_tcp_direct_loss_preserves_nat_session_and_schedules_reconnect),
		cmocka_unit_test(test_ec25519_simultaneous_responder_yield_is_deterministic),
		cmocka_unit_test(test_punch_data_relay_effective_setting),
		cmocka_unit_test(test_punch_data_relay_only_for_learned_nat_unicast),
		cmocka_unit_test(test_punch_udp_command_suppressed_for_tcp_only_peer),
		cmocka_unit_test(test_punch_nat_refresh_policy),
		cmocka_unit_test(test_punch_observed_udp_metadata_fills_without_stun),
		cmocka_unit_test(test_punch_task_pair_state_requires_established_metadata_and_due),
		cmocka_unit_test(test_punch_task_manager_launch_lifecycle_accounting),
		cmocka_unit_test(test_punch_pair_runtime_tracks_inflight_backoff_and_demand),
		cmocka_unit_test(test_punch_task_manager_requests_missing_metadata_on_demand),
		cmocka_unit_test(test_punch_task_manager_requests_partial_symmetric_metadata),
		cmocka_unit_test(test_punch_task_manager_prewarms_relayed_nat_metadata),
		cmocka_unit_test(test_punch_task_manager_skips_endpoint_dependent_post_command_prewarm),
		cmocka_unit_test(test_punch_task_manager_relays_multiple_tcp_endpoints_with_budget),
		cmocka_unit_test(test_punch_task_manager_tcp_only_skips_udp_commands),
		cmocka_unit_test(test_punch_send_tcp_preserves_multiple_received_endpoints),
		cmocka_unit_test(test_tcp_direct_handshake_reuses_unestablished_candidate_socket),
		cmocka_unit_test(test_punch_accepts_relayed_nat_metadata),
		cmocka_unit_test(test_punch_metadata_updates_wake_task_manager),
		cmocka_unit_test(test_punch_task_manager_outcome_accounting),
		cmocka_unit_test(test_punch_pair_task_history_is_bounded_and_ordered),
		cmocka_unit_test(test_punch_pair_task_history_records_remote_results),
		cmocka_unit_test(test_punch_remote_result_ext_drives_state_and_legacy_is_deduped),
#ifdef WITH_STATUS_SOCKET
		cmocka_unit_test(test_status_hole_punch_exposes_peer_nat_metadata),
		cmocka_unit_test(test_status_punch_exposes_udp_socket_pool),
#endif
		cmocka_unit_test(test_punch_detects_noncurrent_exact_candidate),
		cmocka_unit_test(test_endpoint_dependent_candidate_matches_same_ip),
		cmocka_unit_test(test_direct_candidate_transport_scope),
		cmocka_unit_test(test_udp_punch_family_policy_allows_ipv6_deterministic),
		cmocka_unit_test(test_udp_punch_socket_counts_public_listeners_separately),
		cmocka_unit_test(test_udp_punch_public_listener_selection_policy),
		cmocka_unit_test(test_public_listener_port_mapping_lifecycle),
		cmocka_unit_test(test_punch_socket_count_policy),
		cmocka_unit_test(test_punch_hard_symmetric_uses_easytier_grade_defaults),
		cmocka_unit_test(test_punch_socket_count_honors_explicit_request),
		cmocka_unit_test(test_punch_selects_endpoint_command_types),
		cmocka_unit_test(test_punch_probe_parses_valid_request),
		cmocka_unit_test(test_punch_probe_parses_valid_response),
		cmocka_unit_test(test_punch_probe_rejects_bad_magic),
		cmocka_unit_test(test_punch_probe_rejects_bad_version),
		cmocka_unit_test(test_punch_probe_rejects_bad_type),
		cmocka_unit_test(test_punch_probe_rejects_bad_length),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
#endif
}
