// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   NAT behavior detection through STUN
*/

#pragma once

#include "fastd.h"


#if defined(WITH_NAT_DETECT) && defined(WITH_TESTS)

fastd_nat_type_t fastd_nat_test_classify(
	const fastd_peer_address_t *base_samples, size_t n_base_samples, const fastd_peer_address_t *all_samples,
	size_t n_all_samples, const fastd_peer_address_t *local, bool have_local, bool change_ip_port, bool change_port,
	int *port_delta);

int fastd_nat_test_detect_port_delta(const fastd_peer_address_t *samples, size_t n_samples);

#endif
