#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
#
# TCP-focused NAT punching wrapper for test-nat-punch-netns.sh.

set -u

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
FASTD_NAT_PUNCH_TCP=1 exec bash "$SCRIPT_DIR/test-nat-punch-netns.sh" "$@"
