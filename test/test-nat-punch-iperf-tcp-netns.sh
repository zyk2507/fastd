#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
#
# High-traffic iperf3 coverage for TCP NAT punching netns scenarios.

set -u

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

export FASTD_NAT_PUNCH_IPERF=1
export FASTD_NAT_PUNCH_TCP=1
exec bash "$SCRIPT_DIR/test-nat-punch-netns.sh" "$@"
