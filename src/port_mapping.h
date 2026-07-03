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


/** The interval after which successful NAT-PMP mappings are renewed */
#define FASTD_NATPMP_LIFETIME 3600
