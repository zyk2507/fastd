#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
#
# Direct UDP punching coverage for address-restricted NAT peers.

set -u

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

export FASTD_NAT_PUNCH_RESTRICTED=1
exec bash "$SCRIPT_DIR/test-nat-punch-netns.sh" "$@"
