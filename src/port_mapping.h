// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Automatic port mapping helpers
*/


#pragma once

#include "fastd.h"

#ifdef WITH_UPNP_IGD
struct fastd_async_upnp_igd_result;
void fastd_port_mapping_handle_upnp_igd_result(const struct fastd_async_upnp_igd_result *result);
#endif


/** The interval after which successful NAT-PMP mappings are renewed */
#define FASTD_NATPMP_LIFETIME 3600

/** The interval after which successful PCP mappings are renewed */
#define FASTD_PCP_LIFETIME 3600
