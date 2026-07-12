#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
#
# Failure convergence coverage for hard-symmetric UDP NAT punching.

set -u

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

export FASTD_NAT_PUNCH_HARD_FAIL=1
exec bash "$SCRIPT_DIR/test-nat-punch-netns.sh" "$@"
