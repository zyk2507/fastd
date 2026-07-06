// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

#include "nat_detect.h"
#include "peer.h"
#include "punch_rpc.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>

#include <cmocka.h>


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
	uint16_t reserved2;
	uint8_t address[16];
} test_punch_endpoint_t;

typedef struct __attribute__((packed)) test_punch_message {
	test_punch_header_t header;
	test_punch_endpoint_t endpoint;
	uint8_t key[4];
} test_punch_message_t;

enum {
	TEST_PUNCH_SEND_CONE = 2,
	TEST_PUNCH_RESULT = 3,
	TEST_PUNCH_SEND_EASY_SYM = 4,
	TEST_PUNCH_SEND_HARD_SYM = 5,
	TEST_PUNCH_BOTH_EASY_SYM = 6,
};

static fastd_peer_address_t addr4(uint32_t ip, uint16_t port) {
	fastd_peer_address_t ret = {};

	ret.in.sin_family = AF_INET;
	ret.in.sin_addr.s_addr = htonl(ip);
	ret.in.sin_port = htons(port);

	return ret;
}

static uint16_t port4(const fastd_peer_address_t *addr) {
	return ntohs(addr->in.sin_port);
}

static void assert_port4(const fastd_peer_address_t *addr, uint16_t port) {
	assert_int_equal(addr->sa.sa_family, AF_INET);
	assert_int_equal(port4(addr), port);
}

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
		fastd_nat_test_classify(
			base, array_size(base), all, array_size(all), &local, true, false, false, NULL),
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

static void test_punch_scans_hard_symmetric_when_symmetric_enabled(void **state UNUSED) {
	const fastd_peer_address_t endpoint = addr4(0xcb007105, 41000);
	fastd_peer_address_t out[5];

	size_t n = fastd_punch_test_build_endpoint_candidates(
		out, array_size(out), &endpoint, FASTD_NAT_SYMMETRIC, 0, 5, true);

	assert_int_equal(n, 5);
	assert_port4(&out[0], 40998);
	assert_port4(&out[1], 40999);
	assert_port4(&out[2], 41000);
	assert_port4(&out[3], 41001);
	assert_port4(&out[4], 41002);
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

	assert_true(fastd_punch_test_parse_endpoint_message((const uint8_t *)&msg, sizeof(msg), &type, &key_len));
	assert_int_equal(type, TEST_PUNCH_SEND_CONE);
	assert_int_equal(key_len, 4);
}

static void test_punch_parses_result_message(void **state UNUSED) {
	test_punch_message_t msg = make_punch_message();
	msg.header.type = TEST_PUNCH_RESULT;
	msg.endpoint.reserved = 3;

	uint8_t type = 0;
	size_t key_len = 0;

	assert_true(fastd_punch_test_parse_endpoint_message((const uint8_t *)&msg, sizeof(msg), &type, &key_len));
	assert_int_equal(type, TEST_PUNCH_RESULT);
	assert_int_equal(key_len, 4);
}

static void test_punch_parses_all_endpoint_command_messages(void **state UNUSED) {
	static const uint8_t command_types[] = {
		TEST_PUNCH_SEND_CONE,
		TEST_PUNCH_SEND_EASY_SYM,
		TEST_PUNCH_SEND_HARD_SYM,
		TEST_PUNCH_BOTH_EASY_SYM,
	};

	size_t i;
	for (i = 0; i < array_size(command_types); i++) {
		test_punch_message_t msg = make_punch_message();
		msg.header.type = command_types[i];

		uint8_t type = 0;
		size_t key_len = 0;

		assert_true(fastd_punch_test_parse_endpoint_message((const uint8_t *)&msg, sizeof(msg), &type, &key_len));
		assert_true(fastd_punch_test_is_endpoint_command_type(type));
		assert_int_equal(type, command_types[i]);
		assert_int_equal(key_len, 4);
	}
}

static void test_punch_rejects_bad_magic(void **state UNUSED) {
	test_punch_message_t msg = make_punch_message();
	msg.header.magic[0] = 'x';

	assert_false(fastd_punch_test_parse_endpoint_message((const uint8_t *)&msg, sizeof(msg), NULL, NULL));
}

static void test_punch_rejects_bad_version(void **state UNUSED) {
	test_punch_message_t msg = make_punch_message();
	msg.header.version = 2;

	assert_false(fastd_punch_test_parse_endpoint_message((const uint8_t *)&msg, sizeof(msg), NULL, NULL));
}

static void test_punch_rejects_bad_length(void **state UNUSED) {
	test_punch_message_t msg = make_punch_message();
	msg.header.length = htobe16(sizeof(msg) - 1);

	assert_false(fastd_punch_test_parse_endpoint_message((const uint8_t *)&msg, sizeof(msg), NULL, NULL));
}

static void test_punch_rejects_bad_key_length(void **state UNUSED) {
	test_punch_message_t msg = make_punch_message();
	msg.endpoint.key_len = sizeof(msg.key) - 1;

	assert_false(fastd_punch_test_parse_endpoint_message((const uint8_t *)&msg, sizeof(msg), NULL, NULL));
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

static void test_punch_socket_count_policy(void **state UNUSED) {
	fastd_peer_t peer = {};

	conf.punch_symmetric = true;
	conf.punch_max_sockets = 25;

	assert_int_equal(
		fastd_punch_test_udp_socket_count_for_nat(
			&peer, FASTD_NAT_SYMMETRIC_EASY_INC, false, FASTD_NAT_UNKNOWN),
		1);
	assert_int_equal(
		fastd_punch_test_udp_socket_count_for_nat(&peer, FASTD_NAT_SYMMETRIC, false, FASTD_NAT_UNKNOWN),
		1);

	assert_int_equal(
		fastd_punch_test_udp_socket_count_for_nat(
			&peer, FASTD_NAT_FULL_CONE, true, FASTD_NAT_SYMMETRIC_EASY_DEC),
		25);
	assert_int_equal(
		fastd_punch_test_udp_socket_count_for_nat(
			&peer, FASTD_NAT_FULL_CONE, true, FASTD_NAT_SYMMETRIC),
		25);

	peer.punch_symmetric = FASTD_TRISTATE_FALSE;
	assert_int_equal(
		fastd_punch_test_udp_socket_count_for_nat(
			&peer, FASTD_NAT_SYMMETRIC_EASY_INC, true, FASTD_NAT_SYMMETRIC_EASY_INC),
		0);

	conf.punch_symmetric = false;
}

static void test_punch_selects_endpoint_command_types(void **state UNUSED) {
	fastd_peer_t dest = {};
	fastd_peer_t subject = {};

	ctx.now = 1000;
	conf.punch_symmetric = true;

	assert_int_equal(
		fastd_punch_test_endpoint_command_type(&dest, &subject, FASTD_NAT_FULL_CONE),
		TEST_PUNCH_SEND_CONE);
	assert_int_equal(
		fastd_punch_test_endpoint_command_type(&dest, &subject, FASTD_NAT_SYMMETRIC_EASY_INC),
		TEST_PUNCH_SEND_EASY_SYM);

	assert_int_equal(
		fastd_punch_test_endpoint_command_type(&dest, &subject, FASTD_NAT_SYMMETRIC),
		TEST_PUNCH_SEND_HARD_SYM);

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
		fastd_punch_test_endpoint_command_type(&dest, &subject, FASTD_NAT_SYMMETRIC),
		TEST_PUNCH_SEND_CONE);

	conf.punch_symmetric = false;
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
		cmocka_unit_test(test_punch_uses_exact_endpoint_when_symmetric_disabled),
		cmocka_unit_test(test_punch_predicts_easy_symmetric_inc),
		cmocka_unit_test(test_punch_predicts_easy_symmetric_dec),
		cmocka_unit_test(test_punch_clamps_easy_symmetric_step),
		cmocka_unit_test(test_punch_scans_hard_symmetric_when_symmetric_enabled),
		cmocka_unit_test(test_punch_keeps_hard_symmetric_exact_when_symmetric_disabled),
		cmocka_unit_test(test_punch_skips_out_of_range_predicted_ports),
		cmocka_unit_test(test_punch_respects_output_limit),
		cmocka_unit_test(test_punch_parses_valid_message),
		cmocka_unit_test(test_punch_parses_result_message),
		cmocka_unit_test(test_punch_parses_all_endpoint_command_messages),
		cmocka_unit_test(test_punch_rejects_bad_magic),
		cmocka_unit_test(test_punch_rejects_bad_version),
		cmocka_unit_test(test_punch_rejects_bad_length),
		cmocka_unit_test(test_punch_rejects_bad_key_length),
		cmocka_unit_test(test_punch_suppresses_failed_endpoint_temporarily),
		cmocka_unit_test(test_punch_suppression_is_bounded),
		cmocka_unit_test(test_peer_punch_symmetric_inherits_and_overrides),
		cmocka_unit_test(test_punch_socket_count_policy),
		cmocka_unit_test(test_punch_selects_endpoint_command_types),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
#endif
}
