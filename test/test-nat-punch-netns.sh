#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
#
# Integration test for control-relay assisted UDP hole punching.

set -u

FASTD=${1:?fastd binary path required}

skip() {
	printf '1..0 # SKIP %s\n' "$1"
	exit 0
}

fail() {
	printf 'not ok %s - %s\n' "${CURRENT_TEST:-1}" "$1"
	if [[ -n "${WORK:-}" && -d "$WORK" ]]; then
		for name in a b c; do
			if [[ -f "$WORK/$name.ip" ]]; then
				printf '# --- %s ip ---\n' "$name"
				cat "$WORK/$name.ip" | sed 's/^/# /'
			fi
			if [[ -f "$WORK/$name.ping" ]]; then
				printf '# --- %s ping ---\n' "$name"
				cat "$WORK/$name.ping" | sed 's/^/# /'
			fi
			for file in "$WORK/$name".*.iperf; do
				[[ -e "$file" ]] || continue
				printf '# --- %s ---\n' "$(basename "$file")"
				tail -80 "$file" | sed 's/^/# /'
			done
			if [[ -f "$WORK/$name.json" ]]; then
				printf '# --- %s status ---\n' "$name"
				python3 -m json.tool "$WORK/$name.json" 2>/dev/null | tail -120 | sed 's/^/# /'
			fi
			if [[ -f "$WORK/$name.log" ]]; then
				printf '# --- %s log ---\n' "$name"
				tail -80 "$WORK/$name.log" | sed 's/^/# /'
			fi
		done
		if [[ -f "$WORK/hard-fail.reason" ]]; then
			printf '# --- hard-fail reason ---\n'
			cat "$WORK/hard-fail.reason" | sed 's/^/# /'
		fi
	fi
	exit 1
}

for cmd in ip nft ping python3 mktemp timeout; do
	command -v "$cmd" >/dev/null 2>&1 || skip "$cmd not available"
done

IPERF_MODE=${FASTD_NAT_PUNCH_IPERF:-0}
TCP_MODE=${FASTD_NAT_PUNCH_TCP:-0}
HARD_FAIL_MODE=${FASTD_NAT_PUNCH_HARD_FAIL:-0}
if [[ "$IPERF_MODE" == 1 ]]; then
	command -v iperf3 >/dev/null 2>&1 || skip 'iperf3 not available'
fi

[[ -c /dev/net/tun ]] || skip '/dev/net/tun not available'

PROBE_NS="fastd-probe-$$"
if ! ip netns add "$PROBE_NS" >/dev/null 2>&1; then
	skip 'network namespace creation is not permitted'
fi
ip netns del "$PROBE_NS" >/dev/null 2>&1 || true

WORK=$(mktemp -d)
PREFIX="f$$"
NS_A="${PREFIX}a"
NS_B="${PREFIX}b"
NS_C="${PREFIX}c"
NS_RA="${PREFIX}ra"
NS_RB="${PREFIX}rb"
BR="${PREFIX}br"
PIDS=()
STUN_PID=
IPERF_PID=

FAST_WAIT_ATTEMPTS=28
FAST_WAIT_SLEEP=0.2
SHORT_WAIT_ATTEMPTS=6
SHORT_WAIT_SLEEP=0.2
PING_WAIT_ATTEMPTS=35
PING_WAIT_SLEEP=0.1
PING_TIMEOUT=0.4
FAILOVER_WAIT_ATTEMPTS=18
FAILOVER_WAIT_SLEEP=0.2
HARD_FAIL_WAIT_ATTEMPTS=40
TEST_PUNCH_KEEPALIVE=2
IPERF_DURATION=${FASTD_IPERF_DURATION:-9}
IPERF_ACTIVE_CUT_DURATION=${FASTD_IPERF_ACTIVE_CUT_DURATION:-9}
IPERF_RECOVERY_DURATION=${FASTD_IPERF_RECOVERY_DURATION:-9}
IPERF_PARALLEL=${FASTD_IPERF_PARALLEL:-8}
IPERF_CONNECT_TIMEOUT=${FASTD_IPERF_CONNECT_TIMEOUT:-4000}
IPERF_CLIENT_GRACE=${FASTD_IPERF_CLIENT_GRACE:-8}
IPERF_SERVER_IDLE_TIMEOUT=${FASTD_IPERF_SERVER_IDLE_TIMEOUT:-30}
IPERF_MIN_BYTES_FLOOR=$((50 * 1000 * 1000))
IPERF_MIN_BYTES=${FASTD_IPERF_MIN_BYTES:-$IPERF_MIN_BYTES_FLOOR}
IPERF_CASE_GROUP=${FASTD_IPERF_CASE_GROUP:-basic}
FASTD_LOG_LEVEL=${FASTD_LOG_LEVEL:-verbose}

if ! [[ "$IPERF_MIN_BYTES" =~ ^[0-9]+$ ]]; then
	echo "invalid FASTD_IPERF_MIN_BYTES: $IPERF_MIN_BYTES" >&2
	exit 1
fi
if ((IPERF_MIN_BYTES < IPERF_MIN_BYTES_FLOOR)); then
	IPERF_MIN_BYTES=$IPERF_MIN_BYTES_FLOOR
fi

punch_test_limits() {
	local maintenance=${1:-2}

	cat <<EOF
punch keepalive interval $TEST_PUNCH_KEEPALIVE;
punch maintenance interval $maintenance;
punch announce interval 1;
punch relay interval 1;
punch max backups 25;
punch max attempts 4;
punch max sockets 25;
punch max packets 800;
EOF
}

stop_fastds() {
	for pid in "${PIDS[@]}"; do
		kill "$pid" >/dev/null 2>&1 || true
	done
	for pid in "${PIDS[@]}"; do
		wait "$pid" >/dev/null 2>&1 || true
	done
	PIDS=()
}

stop_stun() {
	if [[ -n "$STUN_PID" ]]; then
		kill "$STUN_PID" >/dev/null 2>&1 || true
		wait "$STUN_PID" >/dev/null 2>&1 || true
		STUN_PID=
	fi
}

stop_iperf() {
	if [[ -n "$IPERF_PID" ]]; then
		kill "$IPERF_PID" >/dev/null 2>&1 || true
		wait "$IPERF_PID" >/dev/null 2>&1 || true
		IPERF_PID=
	fi
}

cleanup() {
	stop_iperf
	stop_fastds
	stop_stun

	ip link del "$BR" >/dev/null 2>&1 || true
	for ns in "$NS_A" "$NS_B" "$NS_C" "$NS_RA" "$NS_RB"; do
		ip netns del "$ns" >/dev/null 2>&1 || true
	done

	rm -rf "$WORK"
}
trap cleanup EXIT

run() {
	"$@" || fail "command failed: $*"
}

ping_direct() {
	ip netns exec "$NS_A" ping -I fda-b -n -c 1 -W "$PING_TIMEOUT" 10.52.10.2 >> "$WORK/a.ping" 2>&1
}

ping_data_relay() {
	ip netns exec "$NS_A" ping -I fda-c -n -c 1 -W "$PING_TIMEOUT" 10.52.30.2 >> "$WORK/a.ping" 2>&1
}

seed_data_relay_mac() {
	ip netns exec "$NS_B" ping -I fdb-c -n -c 1 -W "$PING_TIMEOUT" 10.52.30.1 >> "$WORK/b.ping" 2>&1 || true
}

ping_public_nat() {
	ip netns exec "$NS_C" ping -I fdc-a -n -c 1 -W "$PING_TIMEOUT" 10.52.20.2 >> "$WORK/c.ping" 2>&1
}

start_iperf_server() {
	local server_ns=$1 bind_addr=$2 port=$3 log_file=$4

	: > "$log_file"
	ip netns exec "$server_ns" iperf3 -s -1 -B "$bind_addr" -p "$port" --idle-timeout "$IPERF_SERVER_IDLE_TIMEOUT" > "$log_file" 2>&1 &
	IPERF_PID=$!

	for _ in $(seq 1 40); do
		grep -q 'Server listening' "$log_file" && return 0

		if ! kill -0 "$IPERF_PID" >/dev/null 2>&1; then
			wait "$IPERF_PID" >/dev/null 2>&1 || true
			IPERF_PID=
			return 1
		fi

		sleep 0.05
	done

	return 0
}

run_iperf_stream() {
	local label=$1 client_name=$2 client_ns=$3 client_addr=$4 server_name=$5 server_ns=$6 server_addr=$7 port=$8
	local duration=${9:-$IPERF_DURATION}
	local client_log="$WORK/$client_name.$label.client.iperf"
	local server_log="$WORK/$server_name.$label.server.iperf"
	local check_log="$WORK/$client_name.$label.check.iperf"

	stop_iperf
	if ! start_iperf_server "$server_ns" "$server_addr" "$port" "$server_log"; then
		dump_statuses
		fail "iperf3 server failed before start: $label"
	fi

	local client_timeout=$((duration + IPERF_CLIENT_GRACE))
	if ! timeout --kill-after=2 "$client_timeout" ip netns exec "$client_ns" iperf3 \
		-c "$server_addr" -B "$client_addr" -p "$port" -t "$duration" -P "$IPERF_PARALLEL" \
		--bidir --json --connect-timeout "$IPERF_CONNECT_TIMEOUT" --get-server-output > "$client_log" 2>&1; then
		stop_iperf
		dump_statuses
		fail "iperf3 client failed: $label"
	fi

	if ! wait "$IPERF_PID"; then
		IPERF_PID=
		dump_statuses
		fail "iperf3 server failed: $label"
	fi
	IPERF_PID=

	if ! assert_iperf_transferred "$label" "$client_log" "$check_log"; then
		dump_statuses
		fail "iperf3 transferred too little data: $label"
	fi
	sed 's/^/# /' "$check_log"

	check_fastds_alive
	dump_statuses
}

assert_iperf_transferred() {
	local label=$1 log_file=$2 check_log=$3

	python3 - "$log_file" "$label" "$IPERF_MIN_BYTES" > "$check_log" <<'PY'
import json
import sys

log_file, label, min_bytes_text = sys.argv[1:4]
min_bytes = int(min_bytes_text)

try:
    data = json.load(open(log_file))
except Exception as exc:
    print(f"{label}: failed to parse iperf3 JSON: {exc}")
    sys.exit(1)

if data.get("error"):
    print(f"{label}: iperf3 JSON error: {data['error']}")
    sys.exit(1)

end = data.get("end") or {}
fields = {
    "client_tx": "sum_sent",
    "server_rx": "sum_received",
    "server_tx": "sum_sent_bidir_reverse",
    "client_rx": "sum_received_bidir_reverse",
}

values = {}
errors = []
for name, key in fields.items():
    value = (end.get(key) or {}).get("bytes")
    if not isinstance(value, (int, float)):
        errors.append(f"{name}:{key}=missing")
        continue
    values[name] = int(value)

server_rx = values.get("server_rx", 0)
client_rx = values.get("client_rx", 0)
total_rx = server_rx + client_rx

if server_rx <= 0:
    errors.append("server_rx:no-data")
if client_rx <= 0:
    errors.append("client_rx:no-data")
if total_rx < min_bytes:
    errors.append(f"total_rx:{total_rx}<min:{min_bytes}")

summary = " ".join(f"{name}={values.get(name, 'missing')}" for name in fields)
print(f"{label}: {summary} total_rx={total_rx} min_total={min_bytes}")

if errors:
    print(f"{label}: failed checks: {', '.join(errors)}")
    sys.exit(1)
PY
}

run_direct_iperf() {
	local label=$1 port=$2
	local duration=${3:-$IPERF_DURATION}

	run_iperf_stream "$label" a "$NS_A" 10.52.10.1 b "$NS_B" 10.52.10.2 "$port" "$duration"
}

run_public_nat_iperf() {
	local label=$1 port=$2
	local duration=${3:-$IPERF_DURATION}

	run_iperf_stream "$label" c "$NS_C" 10.52.20.1 a "$NS_A" 10.52.20.2 "$port" "$duration"
}

check_fastds_alive() {
	local pid
	for pid in "${PIDS[@]}"; do
		if ! kill -0 "$pid" >/dev/null 2>&1; then
			fail 'fastd process exited before punch completed'
		fi
	done
}

dump_statuses() {
	[[ -S "$WORK/a.status" ]] && "$FASTD" --status-socket "$WORK/a.status" --status --json > "$WORK/a.json" 2>/dev/null || true
	[[ -S "$WORK/b.status" ]] && "$FASTD" --status-socket "$WORK/b.status" --status --json > "$WORK/b.json" 2>/dev/null || true
	[[ -S "$WORK/c.status" ]] && "$FASTD" --status-socket "$WORK/c.status" --status --json > "$WORK/c.json" 2>/dev/null || true
}

direct_hole_punched() {
	python3 - "$WORK/a.json" "$WORK/b.json" <<'PY'
import json
import sys

try:
    a = json.load(open(sys.argv[1]))
    b = json.load(open(sys.argv[2]))
except Exception:
    sys.exit(1)

def find_peer(doc, name):
    for peer in doc.get("peers", {}).values():
        if peer.get("name") == name:
            return peer
    return {}

def direct_hole_punched(doc, name):
    peer = find_peer(doc, name)
    connection = peer.get("connection") or {}
    hole_punch = peer.get("hole_punch") or {}
    return (
        "established" in connection
        and hole_punch.get("established")
        and hole_punch.get("transport") == "udp"
    )

sys.exit(0 if direct_hole_punched(a, "b") and direct_hole_punched(b, "a") else 1)
PY
}

direct_tcp_hole_punched() {
	python3 - "$WORK/a.json" "$WORK/b.json" <<'PY'
import json
import sys

try:
    a = json.load(open(sys.argv[1]))
    b = json.load(open(sys.argv[2]))
except Exception:
    sys.exit(1)

def find_peer(doc, name):
    for peer in doc.get("peers", {}).values():
        if peer.get("name") == name:
            return peer
    return {}

def direct_tcp_hole_punched(doc, name):
    peer = find_peer(doc, name)
    connection = peer.get("connection") or {}
    hole_punch = peer.get("hole_punch") or {}
    return (
        "established" in connection
        and hole_punch.get("established")
        and hole_punch.get("transport") == "tcp"
    )

sys.exit(0 if direct_tcp_hole_punched(a, "b") and direct_tcp_hole_punched(b, "a") else 1)
PY
}

punch_data_relay_enabled() {
	python3 - "$WORK/c.json" <<'PY'
import json
import sys

try:
    c = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(1)

punch = c.get("punch") or {}
sys.exit(0 if punch.get("data_relay") is True else 1)
PY
}

direct_peer_connected() {
	python3 - "$WORK/a.json" "$WORK/b.json" <<'PY'
import json
import sys

try:
    a = json.load(open(sys.argv[1]))
    b = json.load(open(sys.argv[2]))
except Exception:
    sys.exit(1)

def find_peer(doc, name):
    for peer in doc.get("peers", {}).values():
        if peer.get("name") == name:
            return peer
    return {}

def direct_connection(doc, name, public_ip):
    peer = find_peer(doc, name)
    connection = peer.get("connection") or {}
    address = peer.get("address") or ""
    return "established" in connection and address.startswith(public_ip + ":")

sys.exit(0 if direct_connection(a, "b", "10.52.0.3") and direct_connection(b, "a", "10.52.0.2") else 1)
PY
}

direct_backups_ready() {
	python3 - "$WORK/a.json" "$WORK/b.json" <<'PY'
import json
import sys

try:
    a = json.load(open(sys.argv[1]))
    b = json.load(open(sys.argv[2]))
except Exception:
    sys.exit(1)

def find_peer(doc, name):
    for peer in doc.get("peers", {}).values():
        if peer.get("name") == name:
            return peer
    return {}

def backup_ready(doc, name):
    peer = find_peer(doc, name)
    connection = peer.get("connection") or {}
    hole_punch = peer.get("hole_punch") or {}
    return (
        "established" in connection
        and hole_punch.get("established")
        and hole_punch.get("backup_established")
        and hole_punch.get("backup_verified")
        and hole_punch.get("transport") == "udp"
        and hole_punch.get("backup_transport") == "udp"
        and hole_punch.get("remote_port") != hole_punch.get("backup_remote_port")
    )

sys.exit(0 if backup_ready(a, "b") and backup_ready(b, "a") else 1)
PY
}

direct_backups_payload_ready() {
	python3 - "$WORK/a.json" "$WORK/b.json" <<'PY'
import json
import sys

try:
    a = json.load(open(sys.argv[1]))
    b = json.load(open(sys.argv[2]))
except Exception:
    sys.exit(1)

def find_peer(doc, name):
    for peer in doc.get("peers", {}).values():
        if peer.get("name") == name:
            return peer
    return {}

def backup_payload_ready(doc, name):
    peer = find_peer(doc, name)
    hole_punch = peer.get("hole_punch") or {}
    return (
        hole_punch.get("established")
        and hole_punch.get("backup_established")
        and hole_punch.get("backup_verified")
        and hole_punch.get("backup_payload_proven")
        and hole_punch.get("transport") == "udp"
        and hole_punch.get("backup_transport") == "udp"
        and hole_punch.get("remote_port") != hole_punch.get("backup_remote_port")
    )

sys.exit(0 if backup_payload_ready(a, "b") and backup_payload_ready(b, "a") else 1)
PY
}

hole_punch_field() {
	local node=$1 peer=$2 field=$3

	python3 - "$WORK/$node.json" "$peer" "$field" <<'PY'
import json
import sys

doc = json.load(open(sys.argv[1]))
peer_name = sys.argv[2]
field = sys.argv[3]

for peer in doc.get("peers", {}).values():
    if peer.get("name") == peer_name:
        value = (peer.get("hole_punch") or {}).get(field)
        if value is None:
            sys.exit(1)
        print(value)
        sys.exit(0)

sys.exit(1)
PY
}

block_active_direct_path() {
	local a_remote=$1 b_remote=$2
	local a_local=${3:-} b_local=${4:-}
	local proto=${5:-udp}
	local action=drop

	if [[ "$proto" != udp && "$proto" != tcp ]]; then
		fail "unsupported direct path block protocol: $proto"
	fi
	if [[ "$proto" == tcp ]]; then
		action='reject with tcp reset'
	fi

	clear_blocked_direct_path

	run ip netns exec "$NS_RA" nft add table ip failover
	run ip netns exec "$NS_RA" nft 'add chain ip failover prerouting { type filter hook prerouting priority -200; policy accept; }'
	run ip netns exec "$NS_RA" nft add rule ip failover prerouting iifname pub ip saddr 10.52.0.3 ip daddr 10.52.0.2 "$proto" sport "$a_remote" "$proto" dport "$b_remote" $action
	run ip netns exec "$NS_RB" nft add table ip failover
	run ip netns exec "$NS_RB" nft 'add chain ip failover prerouting { type filter hook prerouting priority -200; policy accept; }'
	run ip netns exec "$NS_RB" nft add rule ip failover prerouting iifname pub ip saddr 10.52.0.2 ip daddr 10.52.0.3 "$proto" sport "$b_remote" "$proto" dport "$a_remote" $action

	if [[ -n "$a_local" && -n "$b_local" ]]; then
		run ip netns exec "$NS_RA" nft 'add chain ip failover forward { type filter hook forward priority 0; policy accept; }'
		run ip netns exec "$NS_RA" nft add rule ip failover forward iifname pub oifname priv ip saddr 10.52.0.3 ip daddr 10.52.1.2 "$proto" sport "$a_remote" "$proto" dport "$a_local" $action
		run ip netns exec "$NS_RB" nft 'add chain ip failover forward { type filter hook forward priority 0; policy accept; }'
		run ip netns exec "$NS_RB" nft add rule ip failover forward iifname pub oifname priv ip saddr 10.52.0.2 ip daddr 10.52.2.2 "$proto" sport "$b_remote" "$proto" dport "$b_local" $action
	fi
}

clear_blocked_direct_path() {
	ip netns exec "$NS_RA" nft delete table ip failover >/dev/null 2>&1 || true
	ip netns exec "$NS_RB" nft delete table ip failover >/dev/null 2>&1 || true
}

block_direct_udp_between_nat_peers() {
	run ip netns exec "$NS_RA" nft add table ip hardfail
	run ip netns exec "$NS_RA" nft 'add chain ip hardfail forward { type filter hook forward priority -150; policy accept; }'
	run ip netns exec "$NS_RA" nft add rule ip hardfail forward ip daddr 10.52.0.3 meta l4proto udp drop
	run ip netns exec "$NS_RA" nft add rule ip hardfail forward ip saddr 10.52.0.3 meta l4proto udp drop

	run ip netns exec "$NS_RB" nft add table ip hardfail
	run ip netns exec "$NS_RB" nft 'add chain ip hardfail forward { type filter hook forward priority -150; policy accept; }'
	run ip netns exec "$NS_RB" nft add rule ip hardfail forward ip daddr 10.52.0.2 meta l4proto udp drop
	run ip netns exec "$NS_RB" nft add rule ip hardfail forward ip saddr 10.52.0.2 meta l4proto udp drop
}

direct_active_ports_changed() {
	local a_local=$1 a_remote=$2 b_local=$3 b_remote=$4

	python3 - "$WORK/a.json" "$WORK/b.json" "$a_local" "$a_remote" "$b_local" "$b_remote" <<'PY'
import json
import sys

try:
    a = json.load(open(sys.argv[1]))
    b = json.load(open(sys.argv[2]))
    old_a_local = int(sys.argv[3])
    old_a_remote = int(sys.argv[4])
    old_b_local = int(sys.argv[5])
    old_b_remote = int(sys.argv[6])
except Exception:
    sys.exit(1)

def find_peer(doc, name):
    for peer in doc.get("peers", {}).values():
        if peer.get("name") == name:
            return peer
    return {}

def active_changed(doc, name, old_local_port, old_remote_port):
    peer = find_peer(doc, name)
    connection = peer.get("connection") or {}
    hole_punch = peer.get("hole_punch") or {}
    local_port = hole_punch.get("local_port")
    remote_port = hole_punch.get("remote_port")
    return (
        "established" in connection
        and hole_punch.get("established")
        and hole_punch.get("transport") == "udp"
        and isinstance(local_port, int)
        and isinstance(remote_port, int)
        and (local_port != old_local_port or remote_port != old_remote_port)
    )

sys.exit(0 if active_changed(a, "b", old_a_local, old_a_remote) and active_changed(b, "a", old_b_local, old_b_remote) else 1)
PY
}

punch_results_seen() {
	python3 - "$WORK/c.json" <<'PY'
import json
import sys

try:
    c = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(1)

counters = ((c.get("punch") or {}).get("counters") or {})
if counters.get("result_rx", 0) < 2:
    sys.exit(1)
if counters.get("result_handshake", 0) < 1 and counters.get("result_accepted", 0) < 1:
    sys.exit(1)

sys.exit(0)
PY
}

nat_types_seen() {
	python3 - "$WORK/a.json" "$WORK/b.json" <<'PY'
import json
import sys

try:
    a = json.load(open(sys.argv[1]))
    b = json.load(open(sys.argv[2]))
except Exception:
    sys.exit(1)

if (a.get("nat") or {}).get("type") != "symmetric-easy-inc":
    sys.exit(1)
if (b.get("nat") or {}).get("type") != "full-cone":
    sys.exit(1)

sys.exit(0)
PY
}

both_easy_nat_types_seen() {
	python3 - "$WORK/a.json" "$WORK/b.json" <<'PY'
import json
import sys

try:
    a = json.load(open(sys.argv[1]))
    b = json.load(open(sys.argv[2]))
except Exception:
    sys.exit(1)

if (a.get("nat") or {}).get("type") != "symmetric-easy-inc":
    sys.exit(1)
if (b.get("nat") or {}).get("type") != "symmetric-easy-dec":
    sys.exit(1)

sys.exit(0)
PY
}

hard_symmetric_nat_types_seen() {
	python3 - "$WORK/a.json" "$WORK/b.json" <<'PY'
import json
import sys

try:
    a = json.load(open(sys.argv[1]))
    b = json.load(open(sys.argv[2]))
except Exception:
    sys.exit(1)

if (a.get("nat") or {}).get("type") != "symmetric":
    sys.exit(1)
if (b.get("nat") or {}).get("type") != "symmetric":
    sys.exit(1)

sys.exit(0)
PY
}

hard_symmetric_failure_bounded() {
	python3 - "$WORK/a.json" "$WORK/b.json" "$WORK/c.json" "$WORK/hard-fail.reason" <<'PY'
import json
import sys

reason_path = sys.argv[4]

def reject(reason):
    with open(reason_path, "w") as f:
        f.write(reason + "\n")
    sys.exit(1)

try:
	a = json.load(open(sys.argv[1]))
	b = json.load(open(sys.argv[2]))
	c = json.load(open(sys.argv[3]))
except Exception:
	reject("status-json-unavailable")

def find_peer(doc, name):
    for peer in doc.get("peers", {}).values():
        if peer.get("name") == name:
            return peer
    return {}

def direct_established(doc, name):
    peer = find_peer(doc, name)
    connection = peer.get("connection") or {}
    hole_punch = peer.get("hole_punch") or {}
    return "established" in connection and bool(hole_punch.get("established"))

def pool_bounded(doc):
    punch = doc.get("punch") or {}
    pool = punch.get("udp_punch_socket_pool") or {}
    limit = pool.get("limit")
    public_limit = pool.get("public_listener_limit", 0)
    active = pool.get("active", 0)
    public = pool.get("public_listeners", 0)
    allocated = pool.get("allocated", 0)
    if not isinstance(limit, int) or limit <= 0:
        return False
    return active <= limit and public <= public_limit and allocated <= limit + public_limit

def peer_udp_symmetric(doc, name):
	peer = find_peer(doc, name)
	hole_punch = peer.get("hole_punch") or {}
	metadata = hole_punch.get("udp_metadata") or {}
	return (
		metadata.get("type") == "symmetric"
		and isinstance(hole_punch.get("hard_symmetric_port_index"), int)
		and isinstance(hole_punch.get("hard_symmetric_round"), int)
	)

def pair_runtime_converged(doc):
	punch = doc.get("punch") or {}
	manager = punch.get("task_manager") or {}
	for state in manager.get("runtime_state_list") or []:
		if {state.get("peer_a"), state.get("peer_b")} != {"a", "b"}:
			continue
		return (
			state.get("backoff") is True
			and state.get("in_flight") is False
			and state.get("abort_count", 0) >= 1
			and state.get("launch_count", 0) <= 2
			and state.get("result_count", 0) >= 2
		)
	return False

if direct_established(a, "b") or direct_established(b, "a"):
	reject("direct-established")

if not (pool_bounded(a) and pool_bounded(b) and pool_bounded(c)):
	reject("pool-unbounded")

if not (peer_udp_symmetric(c, "a") and peer_udp_symmetric(c, "b")):
	reject("relay-metadata-not-symmetric")

if not pair_runtime_converged(c):
	reject("pair-runtime-not-converged")

punch = c.get("punch") or {}
counters = punch.get("counters") or {}
manager = punch.get("task_manager") or {}

if counters.get("result_rx", 0) < 2:
	reject("result-rx-too-low")
if manager.get("runs", 0) < 1 or manager.get("pairs", 0) < 1 or manager.get("history_count", 0) < 1:
	reject("manager-not-active")
if manager.get("budget_exhausted", 0) != 0:
	reject("budget-exhausted")

sys.exit(0)
PY
}

tcp_nat_types_seen() {
	python3 - "$WORK/a.json" "$WORK/b.json" <<'PY'
import json
import sys

try:
    a = json.load(open(sys.argv[1]))
    b = json.load(open(sys.argv[2]))
except Exception:
    sys.exit(1)

for doc in (a, b):
    nat = doc.get("nat") or {}
    if nat.get("tcp_available") is not True:
        sys.exit(1)
    if nat.get("tcp_type") not in ("no-pat", "full-cone", "open-internet"):
        sys.exit(1)
    if not nat.get("tcp_public_address"):
        sys.exit(1)

sys.exit(0)
PY
}

make_public_link() {
	local ns=$1 ifname=$2 host=$3
	local peer="${host}p"

	run ip link add "$host" type veth peer name "$peer"
	run ip link set "$peer" netns "$ns"
	run ip -n "$ns" link set "$peer" name "$ifname"
	run ip link set "$host" master "$BR"
	run ip link set "$host" up
	run ip -n "$ns" link set "$ifname" up
}

make_private_link() {
	local ns1=$1 if1=$2 ns2=$3 if2=$4 idx=$5
	local h1="${PREFIX}x${idx}a" h2="${PREFIX}x${idx}b"

	run ip link add "$h1" type veth peer name "$h2"
	run ip link set "$h1" netns "$ns1"
	run ip link set "$h2" netns "$ns2"
	run ip -n "$ns1" link set "$h1" name "$if1"
	run ip -n "$ns2" link set "$h2" name "$if2"
	run ip -n "$ns1" link set "$if1" up
	run ip -n "$ns2" link set "$if2" up
}

make_key() {
	"$FASTD" --machine-readable --generate-key
}

show_pub() {
	local file=$1 secret=$2
	printf '%s\n' 'method "salsa2012+umac";' "secret \"$secret\";" > "$file"
	"$FASTD" --machine-readable --show-key --config "$file"
}

for ns in "$NS_A" "$NS_B" "$NS_C" "$NS_RA" "$NS_RB"; do
	run ip netns add "$ns"
	run ip -n "$ns" link set lo up
done

run ip link add "$BR" type bridge
run ip link set "$BR" up

make_public_link "$NS_C" pub "${PREFIX}hc"
make_public_link "$NS_RA" pub "${PREFIX}ha"
make_public_link "$NS_RB" pub "${PREFIX}hb"
make_private_link "$NS_A" eth0 "$NS_RA" priv 1
make_private_link "$NS_B" eth0 "$NS_RB" priv 2

run ip -n "$NS_C" addr add 10.52.0.1/24 dev pub
run ip -n "$NS_RA" addr add 10.52.0.2/24 dev pub
run ip -n "$NS_RB" addr add 10.52.0.3/24 dev pub
run ip -n "$NS_RA" addr add 10.52.1.1/24 dev priv
run ip -n "$NS_RB" addr add 10.52.2.1/24 dev priv
run ip -n "$NS_A" addr add 10.52.1.2/24 dev eth0
run ip -n "$NS_B" addr add 10.52.2.2/24 dev eth0
run ip -n "$NS_A" route add default via 10.52.1.1
run ip -n "$NS_B" route add default via 10.52.2.1

run ip netns exec "$NS_RA" sysctl -qw net.ipv4.ip_forward=1
run ip netns exec "$NS_RB" sysctl -qw net.ipv4.ip_forward=1

for ns in "$NS_RA" "$NS_RB"; do
	run ip netns exec "$ns" nft add table ip nat
	run ip netns exec "$ns" nft 'add chain ip nat prerouting { type nat hook prerouting priority dstnat; policy accept; }'
	run ip netns exec "$ns" nft 'add chain ip nat postrouting { type nat hook postrouting priority srcnat; policy accept; }'
done

run ip netns exec "$NS_RA" nft add rule ip nat prerouting iifname pub udp dport 10001 dnat to 10.52.1.2:10001
run ip netns exec "$NS_RB" nft add rule ip nat prerouting iifname pub udp dport 10001 dnat to 10.52.2.2:10001
run ip netns exec "$NS_RA" nft add rule ip nat prerouting iifname pub tcp dport 10001 dnat to 10.52.1.2:10001
run ip netns exec "$NS_RB" nft add rule ip nat prerouting iifname pub tcp dport 10001 dnat to 10.52.2.2:10001
run ip netns exec "$NS_RA" nft add rule ip nat postrouting ip saddr 10.52.1.0/24 oifname pub masquerade
run ip netns exec "$NS_RB" nft add rule ip nat postrouting ip saddr 10.52.2.0/24 oifname pub masquerade

SEC_A=$(make_key)
SEC_B=$(make_key)
SEC_C=$(make_key)
PUB_A=$(show_pub "$WORK/show-a.conf" "$SEC_A")
PUB_B=$(show_pub "$WORK/show-b.conf" "$SEC_B")
PUB_C=$(show_pub "$WORK/show-c.conf" "$SEC_C")

cat > "$WORK/a.conf" <<EOF
mode multitap;
interface "fda-%n";
persist interface no;
method "salsa2012+umac";
secret "$SEC_A";
bind 0.0.0.0:10001;
status socket "$WORK/a.status";
$(punch_test_limits 3)
peer "c" { key "$PUB_C"; remote 10.52.0.1 port 10000; transport udp; }
peer "b" { key "$PUB_B"; nat traversal yes; }
EOF

cat > "$WORK/b.conf" <<EOF
mode multitap;
interface "fdb-%n";
persist interface no;
method "salsa2012+umac";
secret "$SEC_B";
bind 0.0.0.0:10001;
status socket "$WORK/b.status";
$(punch_test_limits 3)
peer "c" { key "$PUB_C"; remote 10.52.0.1 port 10000; transport udp; }
peer "a" { key "$PUB_A"; nat traversal yes; }
EOF

write_c_conf() {
	local relay=$1

	cat > "$WORK/c.conf" <<EOF
mode multitap;
interface "fdc-%n";
persist interface no;
method "salsa2012+umac";
secret "$SEC_C";
bind 10.52.0.1:10000;
status socket "$WORK/c.status";
forward no;
peer discovery no;
nat traversal $relay;
$(punch_test_limits 3)
peer "a" { key "$PUB_A"; nat traversal yes; }
peer "b" { key "$PUB_B"; nat traversal yes; }
EOF
}

write_c_data_relay_only_conf() {
	cat > "$WORK/c.conf" <<EOF
mode multitap;
interface "fdc-%n";
persist interface no;
method "salsa2012+umac";
secret "$SEC_C";
bind 10.52.0.1:10000;
status socket "$WORK/c.status";
forward no;
peer discovery no;
nat traversal yes;
punch control relay no;
$(punch_test_limits 3)
peer "a" { key "$PUB_A"; nat traversal yes; }
peer "b" { key "$PUB_B"; nat traversal yes; }
EOF
}

write_symmetric_to_cone_confs() {
	cat > "$WORK/a.conf" <<EOF
mode multitap;
interface "fda-%n";
persist interface no;
method "salsa2012+umac";
secret "$SEC_A";
bind 0.0.0.0:11001;
status socket "$WORK/a.status";
stun server "10.52.0.1" port 3478;
stun server "10.52.0.1" port 3479;
$(punch_test_limits)
peer "c" { key "$PUB_C"; remote 10.52.0.1 port 11000; transport udp; }
peer "b" { key "$PUB_B"; nat traversal yes; }
EOF

	cat > "$WORK/b.conf" <<EOF
mode multitap;
interface "fdb-%n";
persist interface no;
method "salsa2012+umac";
secret "$SEC_B";
bind 0.0.0.0:11001;
status socket "$WORK/b.status";
stun server "10.52.0.1" port 3478;
stun server "10.52.0.1" port 3479;
$(punch_test_limits)
peer "c" { key "$PUB_C"; remote 10.52.0.1 port 11000; transport udp; }
peer "a" { key "$PUB_A"; nat traversal yes; }
EOF

	cat > "$WORK/c.conf" <<EOF
mode multitap;
interface "fdc-%n";
persist interface no;
method "salsa2012+umac";
secret "$SEC_C";
bind 10.52.0.1:11000;
status socket "$WORK/c.status";
forward no;
peer discovery no;
nat traversal yes;
$(punch_test_limits)
peer "a" { key "$PUB_A"; nat traversal yes; }
peer "b" { key "$PUB_B"; nat traversal yes; }
EOF
}

write_both_easy_symmetric_confs() {
	cat > "$WORK/a.conf" <<EOF
mode multitap;
interface "fda-%n";
persist interface no;
method "salsa2012+umac";
secret "$SEC_A";
bind 0.0.0.0:12001;
status socket "$WORK/a.status";
stun server "10.52.0.1" port 3478;
stun server "10.52.0.1" port 3479;
$(punch_test_limits)
peer "c" { key "$PUB_C"; remote 10.52.0.1 port 12000; transport udp; }
peer "b" { key "$PUB_B"; nat traversal yes; }
EOF

	cat > "$WORK/b.conf" <<EOF
mode multitap;
interface "fdb-%n";
persist interface no;
method "salsa2012+umac";
secret "$SEC_B";
bind 0.0.0.0:12001;
status socket "$WORK/b.status";
stun server "10.52.0.1" port 3478;
stun server "10.52.0.1" port 3479;
$(punch_test_limits)
peer "c" { key "$PUB_C"; remote 10.52.0.1 port 12000; transport udp; }
peer "a" { key "$PUB_A"; nat traversal yes; }
EOF

	cat > "$WORK/c.conf" <<EOF
mode multitap;
interface "fdc-%n";
persist interface no;
method "salsa2012+umac";
secret "$SEC_C";
bind 10.52.0.1:12000;
status socket "$WORK/c.status";
forward no;
peer discovery no;
nat traversal yes;
$(punch_test_limits)
peer "a" { key "$PUB_A"; nat traversal yes; }
peer "b" { key "$PUB_B"; nat traversal yes; }
EOF
}

write_hard_symmetric_confs() {
	cat > "$WORK/a.conf" <<EOF
mode multitap;
interface "fda-%n";
persist interface no;
method "salsa2012+umac";
secret "$SEC_A";
bind 0.0.0.0:13001;
status socket "$WORK/a.status";
stun server "10.52.0.1" port 3478;
stun server "10.52.0.1" port 3479;
$(punch_test_limits)
peer "c" { key "$PUB_C"; remote 10.52.0.1 port 13000; transport udp; }
peer "b" { key "$PUB_B"; nat traversal yes; }
EOF

	cat > "$WORK/b.conf" <<EOF
mode multitap;
interface "fdb-%n";
persist interface no;
method "salsa2012+umac";
secret "$SEC_B";
bind 0.0.0.0:13001;
status socket "$WORK/b.status";
stun server "10.52.0.1" port 3478;
stun server "10.52.0.1" port 3479;
$(punch_test_limits)
peer "c" { key "$PUB_C"; remote 10.52.0.1 port 13000; transport udp; }
peer "a" { key "$PUB_A"; nat traversal yes; }
EOF

	cat > "$WORK/c.conf" <<EOF
mode multitap;
interface "fdc-%n";
persist interface no;
method "salsa2012+umac";
secret "$SEC_C";
bind 10.52.0.1:13000;
status socket "$WORK/c.status";
forward no;
peer discovery no;
nat traversal yes;
$(punch_test_limits)
peer "a" { key "$PUB_A"; nat traversal yes; }
peer "b" { key "$PUB_B"; nat traversal yes; }
EOF
}

write_tcp_punch_confs() {
	cat > "$WORK/a.conf" <<EOF
mode multitap;
interface "fda-%n";
persist interface no;
method "salsa2012+umac";
secret "$SEC_A";
bind 0.0.0.0:10001;
status socket "$WORK/a.status";
stun server "10.52.0.1" port 3478;
stun server "10.52.0.1" port 3479;
$(punch_test_limits)
peer "c" { key "$PUB_C"; remote 10.52.0.1 port 10000; transport tcp; }
peer "b" { key "$PUB_B"; nat traversal yes; transport tcp; hole-punch tcp; }
EOF

	cat > "$WORK/b.conf" <<EOF
mode multitap;
interface "fdb-%n";
persist interface no;
method "salsa2012+umac";
secret "$SEC_B";
bind 0.0.0.0:10001;
status socket "$WORK/b.status";
stun server "10.52.0.1" port 3478;
stun server "10.52.0.1" port 3479;
$(punch_test_limits)
peer "c" { key "$PUB_C"; remote 10.52.0.1 port 10000; transport tcp; }
peer "a" { key "$PUB_A"; nat traversal yes; transport tcp; hole-punch tcp; }
EOF

	cat > "$WORK/c.conf" <<EOF
mode multitap;
interface "fdc-%n";
persist interface no;
method "salsa2012+umac";
secret "$SEC_C";
bind 10.52.0.1:10000;
status socket "$WORK/c.status";
forward no;
peer discovery no;
nat traversal yes;
$(punch_test_limits)
peer "a" { key "$PUB_A"; nat traversal yes; transport tcp; hole-punch tcp; }
peer "b" { key "$PUB_B"; nat traversal yes; transport tcp; hole-punch tcp; }
EOF
}

start_fake_stun() {
	local mode=${1:-symmetric_to_cone}

	rm -f "$WORK/stun.ready"
	: > "$WORK/stun.log"

	ip netns exec "$NS_C" python3 - "$WORK/stun.ready" "$mode" > "$WORK/stun.log" 2>&1 <<'PY' &
import select
import signal
import socket
import struct
import sys

COOKIE = 0x2112A442
SERVER_IP = "10.52.0.1"
READY = sys.argv[1]
MODE = sys.argv[2]
running = True
easy_counters = {}


def stop(signum, frame):
    global running
    running = False


def mapped_endpoint(source):
    ip, port = source

    if MODE == "tcp":
        return ip, port

    if MODE == "hard_both" and ip == "10.52.0.2":
        sequence = (43100, 43250, 43180, 43320, 43140, 43290)
        counter = easy_counters.get(ip, 0)
        easy_counters[ip] = counter + 1
        return ip, sequence[counter % len(sequence)]

    if MODE == "hard_both" and ip == "10.52.0.3":
        sequence = (44100, 44270, 44150, 44310, 44190, 44230)
        counter = easy_counters.get(ip, 0)
        easy_counters[ip] = counter + 1
        return ip, sequence[counter % len(sequence)]

    if ip == "10.52.0.2":
        counter = easy_counters.get(ip, 0)
        easy_counters[ip] = counter + 1
        return ip, 41100 + counter

    if MODE == "both_easy" and ip == "10.52.0.3":
        counter = easy_counters.get(ip, 0)
        easy_counters[ip] = counter + 1
        return ip, 42163 - counter

    if ip == "10.52.0.3":
        return ip, 11001

    return ip, port


def stun_response(data, source):
    if len(data) < 20:
        return None

    msg_type, msg_len, cookie = struct.unpack("!HHI", data[:8])
    if msg_type != 0x0001 or cookie != COOKIE or len(data) < 20 + msg_len:
        return None

    transaction = data[8:20]
    mapped_ip, mapped_port = mapped_endpoint(source)
    xport = mapped_port ^ (COOKIE >> 16)
    xaddr = struct.unpack("!I", socket.inet_aton(mapped_ip))[0] ^ COOKIE
    attr = struct.pack("!HHBBHI", 0x0020, 8, 0, 1, xport, xaddr)
    return struct.pack("!HHI12s", 0x0101, len(attr), COOKIE, transaction) + attr


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)

sockets = []
socket_roles = {}
tcp_buffers = {}


def add_socket(sock, role):
    sock.setblocking(False)
    sockets.append(sock)
    socket_roles[sock] = role


def close_socket(sock):
    if sock in sockets:
        sockets.remove(sock)
    socket_roles.pop(sock, None)
    tcp_buffers.pop(sock, None)
    sock.close()


for port in (3478, 3479):
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_sock.bind((SERVER_IP, port))
    add_socket(udp_sock, "udp")

    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_sock.bind((SERVER_IP, port))
    tcp_sock.listen(16)
    add_socket(tcp_sock, "tcp-listener")

open(READY, "w").close()

while running:
    readable, _, _ = select.select(sockets, [], [], 0.5)
    for sock in readable:
        role = socket_roles.get(sock)
        if role == "udp":
            data, source = sock.recvfrom(2048)
            response = stun_response(data, source)
            if response:
                sock.sendto(response, source)
        elif role == "tcp-listener":
            while True:
                try:
                    conn, source = sock.accept()
                except BlockingIOError:
                    break
                add_socket(conn, "tcp-client")
                tcp_buffers[conn] = [b"", source]
        elif role == "tcp-client":
            try:
                data = sock.recv(2048)
            except BlockingIOError:
                continue
            if not data:
                close_socket(sock)
                continue

            buf, source = tcp_buffers[sock]
            buf += data
            tcp_buffers[sock][0] = buf
            if len(buf) < 20:
                continue

            msg_len = struct.unpack("!H", buf[2:4])[0]
            total = 20 + msg_len
            if len(buf) < total:
                continue

            response = stun_response(buf[:total], source)
            if response:
                sock.sendall(response)
            close_socket(sock)

for sock in sockets:
    sock.close()
PY
	STUN_PID=$!

	for _ in $(seq 1 20); do
		[[ -f "$WORK/stun.ready" ]] && return 0
		if ! kill -0 "$STUN_PID" >/dev/null 2>&1; then
			fail 'fake STUN server exited before becoming ready'
		fi
		sleep 0.1
	done

	fail 'fake STUN server did not become ready'
}

start_fastds() {
	rm -f "$WORK/a.status" "$WORK/b.status" "$WORK/c.status" "$WORK/a.json" "$WORK/b.json" "$WORK/c.json" \
		"$WORK/a.ip" "$WORK/b.ip" "$WORK/c.ip"
	: > "$WORK/a.log"
	: > "$WORK/b.log"
	: > "$WORK/c.log"
	: > "$WORK/a.ping"
	: > "$WORK/b.ping"
	: > "$WORK/c.ping"

	ip netns exec "$NS_C" "$FASTD" --config "$WORK/c.conf" --log-level "$FASTD_LOG_LEVEL" > "$WORK/c.log" 2>&1 &
	PID_C=$!
	PIDS=("$PID_C")

	for _ in $(seq 1 "$SHORT_WAIT_ATTEMPTS"); do
		[[ -S "$WORK/c.status" ]] && break
		check_fastds_alive
		sleep "$SHORT_WAIT_SLEEP"
	done

	ip netns exec "$NS_A" "$FASTD" --config "$WORK/a.conf" --log-level "$FASTD_LOG_LEVEL" > "$WORK/a.log" 2>&1 &
	PIDS+=("$!")
	ip netns exec "$NS_B" "$FASTD" --config "$WORK/b.conf" --log-level "$FASTD_LOG_LEVEL" > "$WORK/b.log" 2>&1 &
	PIDS+=("$!")
}

wait_without_direct_path() {
	local saw_status=false

	for _ in $(seq 1 6); do
		sleep "$SHORT_WAIT_SLEEP"
		check_fastds_alive
		dump_statuses

		if [[ -f "$WORK/a.json" && -f "$WORK/b.json" ]]; then
			saw_status=true
			if direct_hole_punched; then
				fail 'direct A/B path established even though punch control relay is disabled'
			fi
		fi
	done

	[[ "$saw_status" == true ]] || fail 'status sockets did not become available'
}

wait_for_iface() {
	local ns=$1 iface=$2

	for _ in $(seq 1 "$FAST_WAIT_ATTEMPTS"); do
		if ip -n "$ns" link show dev "$iface" >/dev/null 2>&1; then
			return 0
		fi
		check_fastds_alive
		sleep "$FAST_WAIT_SLEEP"
	done

	fail "interface $iface did not become available"
}

iface_mac() {
	ip netns exec "$1" cat "/sys/class/net/$2/address"
}

setup_data_relay_interfaces() {
	wait_for_iface "$NS_A" fda-c
	wait_for_iface "$NS_B" fdb-c

	run ip -n "$NS_A" addr replace 10.52.30.1/30 dev fda-c
	run ip -n "$NS_B" addr replace 10.52.30.2/30 dev fdb-c
	run ip -n "$NS_A" link set fda-c up
	run ip -n "$NS_B" link set fdb-c up

	local mac_a mac_b
	mac_a=$(iface_mac "$NS_A" fda-c) || fail 'failed to read A relay MAC'
	mac_b=$(iface_mac "$NS_B" fdb-c) || fail 'failed to read B relay MAC'

	run ip -n "$NS_A" neigh replace 10.52.30.2 lladdr "$mac_b" nud permanent dev fda-c
	run ip -n "$NS_B" neigh replace 10.52.30.1 lladdr "$mac_a" nud permanent dev fdb-c

	ip -n "$NS_A" addr show dev fda-c > "$WORK/a.ip" 2>&1 || true
	ip -n "$NS_B" addr show dev fdb-c > "$WORK/b.ip" 2>&1 || true
}

wait_for_data_relay_without_direct() {
	local ok=false

	for _ in $(seq 1 "$PING_WAIT_ATTEMPTS"); do
		check_fastds_alive
		dump_statuses

		seed_data_relay_mac
		if [[ -f "$WORK/c.json" ]] && punch_data_relay_enabled && ping_data_relay; then
			ok=true
			break
		fi

		if [[ -f "$WORK/a.json" && -f "$WORK/b.json" ]] && direct_hole_punched; then
			fail 'direct A/B path established before data relay fallback was verified'
		fi

		sleep "$PING_WAIT_SLEEP"
	done

	[[ "$ok" == true ]] || fail 'A/B data relay fallback failed without punch control relay'
}

wait_for_direct_path() {
	for _ in $(seq 1 "$FAST_WAIT_ATTEMPTS"); do
		sleep "$FAST_WAIT_SLEEP"
		check_fastds_alive
		dump_statuses

		if [[ -f "$WORK/a.json" && -f "$WORK/b.json" && -f "$WORK/c.json" ]] &&
			direct_hole_punched && punch_results_seen; then
			return 0
		fi
	done

	return 1
}

wait_for_symmetric_to_cone_path() {
	for _ in $(seq 1 "$FAST_WAIT_ATTEMPTS"); do
		sleep "$FAST_WAIT_SLEEP"
		check_fastds_alive
		dump_statuses

		if [[ -f "$WORK/a.json" && -f "$WORK/b.json" && -f "$WORK/c.json" ]] &&
			nat_types_seen && direct_hole_punched && punch_results_seen; then
			return 0
		fi
	done

	return 1
}

wait_for_both_easy_symmetric_path() {
	for _ in $(seq 1 "$FAST_WAIT_ATTEMPTS"); do
		sleep "$FAST_WAIT_SLEEP"
		check_fastds_alive
		dump_statuses

		if [[ -f "$WORK/a.json" && -f "$WORK/b.json" && -f "$WORK/c.json" ]] &&
			both_easy_nat_types_seen && direct_hole_punched && direct_backups_ready && punch_results_seen; then
			return 0
		fi
	done

	return 1
}

wait_for_hard_symmetric_path() {
	for _ in $(seq 1 "$FAST_WAIT_ATTEMPTS"); do
		sleep "$FAST_WAIT_SLEEP"
		check_fastds_alive
		dump_statuses

		if [[ -f "$WORK/a.json" && -f "$WORK/b.json" && -f "$WORK/c.json" ]] &&
			hard_symmetric_nat_types_seen && direct_peer_connected && punch_results_seen; then
			return 0
		fi
	done

	return 1
}

remove_pid() {
	local remove=$1
	local kept=()
	local pid

	for pid in "${PIDS[@]}"; do
		[[ "$pid" == "$remove" ]] && continue
		kept+=("$pid")
	done

	PIDS=("${kept[@]}")
}

stop_public_relay_fastd() {
	kill "$PID_C" >/dev/null 2>&1 || true
	wait "$PID_C" >/dev/null 2>&1 || true
	remove_pid "$PID_C"
}

wait_for_direct_ping() {
	local label=$1
	local ok=false

	for _ in $(seq 1 "$PING_WAIT_ATTEMPTS"); do
		if ping_direct; then
			ok=true
			break
		fi
		sleep "$PING_WAIT_SLEEP"
	done

	[[ "$ok" == true ]] || fail "$label"
}

run_direct_iperf_after_active_cut() {
	local label=$1 port=$2
	local a_local a_remote b_local b_remote

	dump_statuses
	a_local=$(hole_punch_field a b local_port) || fail "missing A active punch local port before $label iperf3 cut"
	a_remote=$(hole_punch_field a b remote_port) || fail "missing A active punch remote port before $label iperf3 cut"
	b_local=$(hole_punch_field b a local_port) || fail "missing B active punch local port before $label iperf3 cut"
	b_remote=$(hole_punch_field b a remote_port) || fail "missing B active punch remote port before $label iperf3 cut"
	block_active_direct_path "$a_remote" "$b_remote" "$a_local" "$b_local"
	run_direct_iperf "$label" "$port" "$IPERF_ACTIVE_CUT_DURATION"

	if ! direct_active_ports_changed "$a_local" "$a_remote" "$b_local" "$b_remote"; then
		fail "$label did not recover onto a different direct path during iperf3"
	fi
}

run_direct_iperf_after_transient_cut() {
	local label=$1 port=$2
	local a_active b_active

	dump_statuses
	a_active=$(hole_punch_field a b remote_port) || fail "missing A active punch remote port before $label iperf3 cut"
	b_active=$(hole_punch_field b a remote_port) || fail "missing B active punch remote port before $label iperf3 cut"
	block_active_direct_path "$a_active" "$b_active"
	sleep "$SHORT_WAIT_SLEEP"
	clear_blocked_direct_path
	run_direct_iperf "$label" "$port" "$IPERF_RECOVERY_DURATION"
}

run_direct_iperf_during_transient_cut() {
	local label=$1 port=$2 proto=${3:-udp}
	local a_local a_remote b_local b_remote unblock_pid

	dump_statuses
	a_local=$(hole_punch_field a b local_port) || fail "missing A active punch local port before $label iperf3 cut"
	a_remote=$(hole_punch_field a b remote_port) || fail "missing A active punch remote port before $label iperf3 cut"
	b_local=$(hole_punch_field b a local_port) || fail "missing B active punch local port before $label iperf3 cut"
	b_remote=$(hole_punch_field b a remote_port) || fail "missing B active punch remote port before $label iperf3 cut"
	block_active_direct_path "$a_remote" "$b_remote" "$a_local" "$b_local" "$proto"
	(sleep "$SHORT_WAIT_SLEEP"; clear_blocked_direct_path) &
	unblock_pid=$!
	run_direct_iperf "$label" "$port" "$IPERF_RECOVERY_DURATION"
	wait "$unblock_pid" >/dev/null 2>&1 || true
}

cut_public_nat_link_once() {
	run ip -n "$NS_RA" link set pub down
	sleep "$SHORT_WAIT_SLEEP"
	run ip -n "$NS_RA" link set pub up
}

iperf_basic_group_enabled() {
	[[ "$IPERF_CASE_GROUP" == basic || "$IPERF_CASE_GROUP" == all ]]
}

iperf_symmetric_group_enabled() {
	[[ "$IPERF_CASE_GROUP" == symmetric || "$IPERF_CASE_GROUP" == all ]]
}

print_iperf_plan() {
	case "$IPERF_CASE_GROUP" in
	basic)
		printf '1..3\n'
		;;
	symmetric)
		printf '1..2\n'
		;;
	all)
		printf '1..5\n'
		;;
	*)
		printf '1..0 # SKIP unknown iperf case group: %s\n' "$IPERF_CASE_GROUP"
		exit 0
		;;
	esac
}

begin_iperf_case() {
	CURRENT_TEST=$((CURRENT_TEST + 1))
}

run_iperf_tests() {
	print_iperf_plan
	CURRENT_TEST=0

	if iperf_basic_group_enabled; then
		begin_iperf_case
		write_c_conf yes
		start_fastds

		if ! wait_for_direct_path; then
			fail 'direct UDP path was not established before public iperf3'
		fi

		run ip -n "$NS_C" addr add 10.52.20.1/30 dev fdc-a
		run ip -n "$NS_A" addr add 10.52.20.2/30 dev fda-c
		run ip -n "$NS_C" link set fdc-a up
		run ip -n "$NS_A" link set fda-c up
		ip -n "$NS_C" addr show dev fdc-a > "$WORK/c.ip" 2>&1 || true
		ip -n "$NS_A" addr show dev fda-c >> "$WORK/a.ip" 2>&1 || true
		cut_public_nat_link_once
		run_public_nat_iperf public-nat-after-cut 5201
		printf 'ok %s - public node carries bidirectional iperf3 traffic with a NAT peer after a link cut\n' "$CURRENT_TEST"

		begin_iperf_case
		run ip -n "$NS_A" addr add 10.52.10.1/30 dev fda-b
		run ip -n "$NS_B" addr add 10.52.10.2/30 dev fdb-a
		run ip -n "$NS_A" link set fda-b up
		run ip -n "$NS_B" link set fdb-a up
		ip -n "$NS_A" addr show dev fda-b > "$WORK/a.ip" 2>&1 || true
		ip -n "$NS_B" addr show dev fdb-a > "$WORK/b.ip" 2>&1 || true
		wait_for_direct_ping 'direct A/B data path failed before full-cone iperf3'
		stop_public_relay_fastd
		sleep "$SHORT_WAIT_SLEEP"
		run_direct_iperf_after_transient_cut full-cone-after-cut 5202
		printf 'ok %s - full-cone direct path recovers and carries bidirectional iperf3 traffic after active cut\n' "$CURRENT_TEST"

		begin_iperf_case
		stop_fastds
		start_fake_stun
		run ip netns exec "$NS_RA" nft insert rule ip nat postrouting ip saddr 10.52.1.2 ip daddr 10.52.0.1 udp dport 11000 snat to 10.52.0.2:41100
		run ip netns exec "$NS_RA" nft insert rule ip nat postrouting ip saddr 10.52.1.2 ip daddr 10.52.0.3 udp dport 11001 snat to 10.52.0.2:41100-41124
		run ip netns exec "$NS_RB" nft add rule ip nat prerouting iifname pub udp dport 11001 dnat to 10.52.2.2:11001
		write_symmetric_to_cone_confs
		start_fastds

		if ! wait_for_symmetric_to_cone_path; then
			fail 'symmetric-to-cone UDP path was not established before iperf3'
		fi

		run ip -n "$NS_A" addr add 10.52.10.1/30 dev fda-b
		run ip -n "$NS_B" addr add 10.52.10.2/30 dev fdb-a
		run ip -n "$NS_A" link set fda-b up
		run ip -n "$NS_B" link set fdb-a up
		ip -n "$NS_A" addr show dev fda-b > "$WORK/a.ip" 2>&1 || true
		ip -n "$NS_B" addr show dev fdb-a > "$WORK/b.ip" 2>&1 || true
		wait_for_direct_ping 'symmetric-to-cone direct data path failed before iperf3'
		run_direct_iperf_after_transient_cut symmetric-to-cone-after-cut 5203
		printf 'ok %s - easy-symmetric to full-cone path recovers and carries bidirectional iperf3 traffic after active cut\n' "$CURRENT_TEST"
	fi

	if iperf_symmetric_group_enabled; then
		begin_iperf_case
		stop_fastds
		stop_stun
		start_fake_stun both_easy
		run ip netns exec "$NS_RA" nft insert rule ip nat postrouting ip saddr 10.52.1.2 ip daddr 10.52.0.1 udp dport 12000 snat to 10.52.0.2:41100
		run ip netns exec "$NS_RA" nft insert rule ip nat postrouting ip saddr 10.52.1.2 ip daddr 10.52.0.3 udp dport 42139-42163 snat to 10.52.0.2:41100-41124
		run ip netns exec "$NS_RB" nft insert rule ip nat postrouting ip saddr 10.52.2.2 ip daddr 10.52.0.1 udp dport 12000 snat to 10.52.0.3:42163
		run ip netns exec "$NS_RB" nft insert rule ip nat postrouting ip saddr 10.52.2.2 ip daddr 10.52.0.2 udp dport 41100-41124 snat to 10.52.0.3:42139-42163
		run ip netns exec "$NS_RA" nft add rule ip nat prerouting iifname pub udp dport 41100-41124 dnat to 10.52.1.2:12001
		run ip netns exec "$NS_RB" nft add rule ip nat prerouting iifname pub udp dport 42139-42163 dnat to 10.52.2.2:12001
		write_both_easy_symmetric_confs
		start_fastds

		if ! wait_for_both_easy_symmetric_path; then
			fail 'easy-symmetric to easy-symmetric UDP path was not established before iperf3'
		fi

		run ip -n "$NS_A" addr add 10.52.10.1/30 dev fda-b
		run ip -n "$NS_B" addr add 10.52.10.2/30 dev fdb-a
		run ip -n "$NS_A" link set fda-b up
		run ip -n "$NS_B" link set fdb-a up
		ip -n "$NS_A" addr show dev fda-b > "$WORK/a.ip" 2>&1 || true
		ip -n "$NS_B" addr show dev fdb-a > "$WORK/b.ip" 2>&1 || true
		wait_for_direct_ping 'easy-symmetric direct data path failed before iperf3'
		run_direct_iperf_after_active_cut both-easy-after-cut 5204
		printf 'ok %s - easy-symmetric peers recover and carry bidirectional iperf3 traffic after active cut\n' "$CURRENT_TEST"

		begin_iperf_case
		stop_fastds
		stop_stun
		start_fake_stun hard_both
		run ip netns exec "$NS_RA" nft insert rule ip nat postrouting ip saddr 10.52.1.2 ip daddr 10.52.0.1 udp dport 13000 snat to 10.52.0.2:43100
		run ip netns exec "$NS_RA" nft insert rule ip nat postrouting ip saddr 10.52.1.2 ip daddr 10.52.0.3 udp dport 44088-44112 snat to 10.52.0.2:43088-43112
		run ip netns exec "$NS_RB" nft insert rule ip nat postrouting ip saddr 10.52.2.2 ip daddr 10.52.0.1 udp dport 13000 snat to 10.52.0.3:44100
		run ip netns exec "$NS_RB" nft insert rule ip nat postrouting ip saddr 10.52.2.2 ip daddr 10.52.0.2 udp dport 43088-43112 snat to 10.52.0.3:44088-44112
		run ip netns exec "$NS_RA" nft add rule ip nat prerouting iifname pub udp dport 43088-43112 dnat to 10.52.1.2:13001
		run ip netns exec "$NS_RB" nft add rule ip nat prerouting iifname pub udp dport 44088-44112 dnat to 10.52.2.2:13001
		write_hard_symmetric_confs
		start_fastds

		if ! wait_for_hard_symmetric_path; then
			fail 'hard-symmetric peers did not establish a direct path before iperf3'
		fi

		run ip -n "$NS_A" addr add 10.52.10.1/30 dev fda-b
		run ip -n "$NS_B" addr add 10.52.10.2/30 dev fdb-a
		run ip -n "$NS_A" link set fda-b up
		run ip -n "$NS_B" link set fdb-a up
		ip -n "$NS_A" addr show dev fda-b > "$WORK/a.ip" 2>&1 || true
		ip -n "$NS_B" addr show dev fdb-a > "$WORK/b.ip" 2>&1 || true
		wait_for_direct_ping 'hard-symmetric direct data path failed before iperf3'
		run_direct_iperf_after_transient_cut hard-symmetric-after-cut 5205
		printf 'ok %s - hard-symmetric direct path recovers and carries bidirectional iperf3 traffic after active cut\n' "$CURRENT_TEST"
	fi
}

run_tcp_tests() {
	printf '1..1\n'
	CURRENT_TEST=1

	start_fake_stun tcp
	write_tcp_punch_confs
	start_fastds

	ok=false
	for _ in $(seq 1 "$FAST_WAIT_ATTEMPTS"); do
		sleep "$FAST_WAIT_SLEEP"
		check_fastds_alive
		dump_statuses

		if [[ -f "$WORK/a.json" && -f "$WORK/b.json" && -f "$WORK/c.json" ]] &&
			tcp_nat_types_seen && direct_tcp_hole_punched && punch_results_seen; then
			ok=true
			break
		fi
	done

	[[ "$ok" == true ]] || fail 'direct TCP punch path was not established'

	run ip -n "$NS_A" addr add 10.52.10.1/30 dev fda-b
	run ip -n "$NS_B" addr add 10.52.10.2/30 dev fdb-a
	run ip -n "$NS_A" link set fda-b up
	run ip -n "$NS_B" link set fdb-a up
	ip -n "$NS_A" addr show dev fda-b > "$WORK/a.ip" 2>&1 || true
	ip -n "$NS_B" addr show dev fdb-a > "$WORK/b.ip" 2>&1 || true
	wait_for_direct_ping 'direct TCP-punched A/B data path failed'

	printf 'ok 1 - control relay establishes a direct TCP punch path through port-preserving mappings\n'
}

run_tcp_iperf_tests() {
	printf '1..1\n'
	CURRENT_TEST=1

	start_fake_stun tcp
	write_tcp_punch_confs
	start_fastds

	ok=false
	for _ in $(seq 1 "$FAST_WAIT_ATTEMPTS"); do
		sleep "$FAST_WAIT_SLEEP"
		check_fastds_alive
		dump_statuses

		if [[ -f "$WORK/a.json" && -f "$WORK/b.json" && -f "$WORK/c.json" ]] &&
			tcp_nat_types_seen && direct_tcp_hole_punched && punch_results_seen; then
			ok=true
			break
		fi
	done

	[[ "$ok" == true ]] || fail 'direct TCP punch path was not established before iperf3'

	run ip -n "$NS_A" addr add 10.52.10.1/30 dev fda-b
	run ip -n "$NS_B" addr add 10.52.10.2/30 dev fdb-a
	run ip -n "$NS_A" link set fda-b up
	run ip -n "$NS_B" link set fdb-a up
	ip -n "$NS_A" addr show dev fda-b > "$WORK/a.ip" 2>&1 || true
	ip -n "$NS_B" addr show dev fdb-a > "$WORK/b.ip" 2>&1 || true
	wait_for_direct_ping 'direct TCP-punched A/B data path failed before iperf3'
	run_direct_iperf_during_transient_cut tcp-after-cut 5206 tcp

	printf 'ok 1 - TCP direct punch path recovers and carries bidirectional iperf3 traffic after active cut\n'
}

run_hard_symmetric_failure_tests() {
	printf '1..1\n'
	CURRENT_TEST=1

	start_fake_stun hard_both
	block_direct_udp_between_nat_peers
	write_hard_symmetric_confs
	start_fastds

	ok=false
	for _ in $(seq 1 "$HARD_FAIL_WAIT_ATTEMPTS"); do
		sleep "$FAST_WAIT_SLEEP"
		check_fastds_alive
		dump_statuses

		if [[ -f "$WORK/a.json" && -f "$WORK/b.json" ]] && direct_peer_connected; then
			fail 'hard-symmetric direct path established even though A/B UDP was blocked'
		fi

		if [[ -f "$WORK/a.json" && -f "$WORK/b.json" && -f "$WORK/c.json" ]] &&
			hard_symmetric_nat_types_seen && hard_symmetric_failure_bounded; then
			ok=true
			break
		fi
	done

	[[ "$ok" == true ]] || fail 'hard-symmetric failure did not converge within bounded socket/task limits'

	printf 'ok 1 - hard-symmetric failure remains bounded when direct UDP is unreachable\n'
}

if [[ "$HARD_FAIL_MODE" == 1 ]]; then
	run_hard_symmetric_failure_tests
	exit 0
fi

if [[ "$IPERF_MODE" == 1 && "$TCP_MODE" == 1 ]]; then
	run_tcp_iperf_tests
	exit 0
fi

if [[ "$IPERF_MODE" == 1 ]]; then
	run_iperf_tests
	exit 0
fi

if [[ "$TCP_MODE" == 1 ]]; then
	run_tcp_tests
	exit 0
fi

printf '1..6\n'

CURRENT_TEST=1
write_c_data_relay_only_conf
start_fastds
setup_data_relay_interfaces
wait_for_data_relay_without_direct
wait_without_direct_path
stop_fastds
printf 'ok 1 - passive A/B use controlled data relay but do not direct-connect without punch control relay\n'

CURRENT_TEST=2
write_c_conf yes
start_fastds

if ! wait_for_direct_path; then
	fail 'direct UDP path was not established'
fi

run ip -n "$NS_C" addr add 10.52.20.1/30 dev fdc-a
run ip -n "$NS_A" addr add 10.52.20.2/30 dev fda-c
run ip -n "$NS_C" link set fdc-a up
run ip -n "$NS_A" link set fda-c up
ip -n "$NS_C" addr show dev fdc-a > "$WORK/c.ip" 2>&1 || true
ip -n "$NS_A" addr show dev fda-c >> "$WORK/a.ip" 2>&1 || true

ok=false
for _ in $(seq 1 "$PING_WAIT_ATTEMPTS"); do
	if ping_public_nat; then
		ok=true
		break
	fi
	sleep "$PING_WAIT_SLEEP"
done

if [[ "$ok" != true ]]; then
	dump_statuses
	fail 'public C to NAT A data path failed'
fi

printf 'ok 2 - public node exchanges data with a NAT peer\n'

CURRENT_TEST=3
run ip -n "$NS_A" addr add 10.52.10.1/30 dev fda-b
run ip -n "$NS_B" addr add 10.52.10.2/30 dev fdb-a
run ip -n "$NS_A" link set fda-b up
run ip -n "$NS_B" link set fdb-a up
ip -n "$NS_A" addr show dev fda-b > "$WORK/a.ip" 2>&1 || true
ip -n "$NS_B" addr show dev fdb-a > "$WORK/b.ip" 2>&1 || true

for _ in $(seq 1 "$PING_WAIT_ATTEMPTS"); do
	ping_direct && break
	sleep "$PING_WAIT_SLEEP"
done

kill "$PID_C" >/dev/null 2>&1 || true
sleep "$SHORT_WAIT_SLEEP"

ok=false
for _ in $(seq 1 "$PING_WAIT_ATTEMPTS"); do
	if ping_direct; then
		ok=true
		break
	fi
	sleep "$PING_WAIT_SLEEP"
done

if [[ "$ok" != true ]]; then
	dump_statuses
	fail 'direct A/B data path failed after control relay was stopped'
fi

printf 'ok 3 - control relay establishes direct UDP path through full-cone mappings and receives punch results\n'

CURRENT_TEST=4
stop_fastds
start_fake_stun
run ip netns exec "$NS_RA" nft insert rule ip nat postrouting ip saddr 10.52.1.2 ip daddr 10.52.0.1 udp dport 11000 snat to 10.52.0.2:41100
run ip netns exec "$NS_RA" nft insert rule ip nat postrouting ip saddr 10.52.1.2 ip daddr 10.52.0.3 udp dport 11001 snat to 10.52.0.2:41100-41124
run ip netns exec "$NS_RB" nft add rule ip nat prerouting iifname pub udp dport 11001 dnat to 10.52.2.2:11001
write_symmetric_to_cone_confs
start_fastds

if ! wait_for_symmetric_to_cone_path; then
	fail 'symmetric-to-cone UDP path was not established'
fi

run ip -n "$NS_A" addr add 10.52.10.1/30 dev fda-b
run ip -n "$NS_B" addr add 10.52.10.2/30 dev fdb-a
run ip -n "$NS_A" link set fda-b up
run ip -n "$NS_B" link set fdb-a up
ip -n "$NS_A" addr show dev fda-b > "$WORK/a.ip" 2>&1 || true
ip -n "$NS_B" addr show dev fdb-a > "$WORK/b.ip" 2>&1 || true
sleep "$SHORT_WAIT_SLEEP"

ok=false
for _ in $(seq 1 "$PING_WAIT_ATTEMPTS"); do
	if ping_direct; then
		ok=true
		break
	fi
	sleep "$PING_WAIT_SLEEP"
done

if [[ "$ok" != true ]]; then
	dump_statuses
	fail 'symmetric-to-cone direct data path failed'
fi

printf 'ok 4 - easy-symmetric NAT peer punches directly to a full-cone NAT peer\n'

CURRENT_TEST=5
stop_fastds
stop_stun
start_fake_stun both_easy
run ip netns exec "$NS_RA" nft insert rule ip nat postrouting ip saddr 10.52.1.2 ip daddr 10.52.0.1 udp dport 12000 snat to 10.52.0.2:41100
run ip netns exec "$NS_RA" nft insert rule ip nat postrouting ip saddr 10.52.1.2 ip daddr 10.52.0.3 udp dport 42139-42163 snat to 10.52.0.2:41100-41124
run ip netns exec "$NS_RB" nft insert rule ip nat postrouting ip saddr 10.52.2.2 ip daddr 10.52.0.1 udp dport 12000 snat to 10.52.0.3:42163
run ip netns exec "$NS_RB" nft insert rule ip nat postrouting ip saddr 10.52.2.2 ip daddr 10.52.0.2 udp dport 41100-41124 snat to 10.52.0.3:42139-42163
run ip netns exec "$NS_RA" nft add rule ip nat prerouting iifname pub udp dport 41100-41124 dnat to 10.52.1.2:12001
run ip netns exec "$NS_RB" nft add rule ip nat prerouting iifname pub udp dport 42139-42163 dnat to 10.52.2.2:12001
write_both_easy_symmetric_confs
start_fastds

if ! wait_for_both_easy_symmetric_path; then
	fail 'easy-symmetric to easy-symmetric UDP path was not established'
fi

run ip -n "$NS_A" addr add 10.52.10.1/30 dev fda-b
run ip -n "$NS_B" addr add 10.52.10.2/30 dev fdb-a
run ip -n "$NS_A" link set fda-b up
run ip -n "$NS_B" link set fdb-a up
ip -n "$NS_A" addr show dev fda-b > "$WORK/a.ip" 2>&1 || true
ip -n "$NS_B" addr show dev fdb-a > "$WORK/b.ip" 2>&1 || true
sleep "$SHORT_WAIT_SLEEP"

ok=false
for _ in $(seq 1 "$PING_WAIT_ATTEMPTS"); do
	if ping_direct; then
		ok=true
		break
	fi
	sleep "$PING_WAIT_SLEEP"
done

if [[ "$ok" != true ]]; then
	dump_statuses
	fail 'easy-symmetric to easy-symmetric direct data path failed'
fi

ok=false
for _ in $(seq 1 "$PING_WAIT_ATTEMPTS"); do
	ping_direct >/dev/null 2>&1 || true
	dump_statuses
	if direct_backups_payload_ready; then
		ok=true
		break
	fi
	sleep "$PING_WAIT_SLEEP"
done

if [[ "$ok" != true ]]; then
	dump_statuses
	fail 'easy-symmetric payload-proven backup path was not established before failover'
fi

dump_statuses
a_local=$(hole_punch_field a b local_port) || fail 'missing A active punch local port before failover'
a_remote=$(hole_punch_field a b remote_port) || fail 'missing A active punch remote port before failover'
b_local=$(hole_punch_field b a local_port) || fail 'missing B active punch local port before failover'
b_remote=$(hole_punch_field b a remote_port) || fail 'missing B active punch remote port before failover'
block_active_direct_path "$a_remote" "$b_remote" "$a_local" "$b_local"

ok=false
for _ in $(seq 1 "$FAILOVER_WAIT_ATTEMPTS"); do
	sleep "$FAILOVER_WAIT_SLEEP"
	check_fastds_alive
	dump_statuses

	if direct_active_ports_changed "$a_local" "$a_remote" "$b_local" "$b_remote"; then
		ok=true
		break
	fi
done

if [[ "$ok" != true ]]; then
	dump_statuses
	fail 'easy-symmetric backup path was not promoted after the active path was blocked'
fi

ok=false
for _ in $(seq 1 "$PING_WAIT_ATTEMPTS"); do
	if ping_direct; then
		ok=true
		break
	fi
	sleep "$PING_WAIT_SLEEP"
done

if [[ "$ok" != true ]]; then
	dump_statuses
	fail 'easy-symmetric backup path failed after promotion'
fi

printf 'ok 5 - easy-symmetric NAT peers punch directly, keep a backup path, and fail over\n'

CURRENT_TEST=6
stop_fastds
stop_stun
start_fake_stun hard_both
run ip netns exec "$NS_RA" nft insert rule ip nat postrouting ip saddr 10.52.1.2 ip daddr 10.52.0.1 udp dport 13000 snat to 10.52.0.2:43100
run ip netns exec "$NS_RA" nft insert rule ip nat postrouting ip saddr 10.52.1.2 ip daddr 10.52.0.3 udp dport 44088-44112 snat to 10.52.0.2:43088-43112
run ip netns exec "$NS_RB" nft insert rule ip nat postrouting ip saddr 10.52.2.2 ip daddr 10.52.0.1 udp dport 13000 snat to 10.52.0.3:44100
run ip netns exec "$NS_RB" nft insert rule ip nat postrouting ip saddr 10.52.2.2 ip daddr 10.52.0.2 udp dport 43088-43112 snat to 10.52.0.3:44088-44112
run ip netns exec "$NS_RA" nft add rule ip nat prerouting iifname pub udp dport 43088-43112 dnat to 10.52.1.2:13001
run ip netns exec "$NS_RB" nft add rule ip nat prerouting iifname pub udp dport 44088-44112 dnat to 10.52.2.2:13001
write_hard_symmetric_confs
start_fastds

if ! wait_for_hard_symmetric_path; then
	fail 'hard-symmetric peers did not establish a direct path'
fi

run ip -n "$NS_A" addr add 10.52.10.1/30 dev fda-b
run ip -n "$NS_B" addr add 10.52.10.2/30 dev fdb-a
run ip -n "$NS_A" link set fda-b up
run ip -n "$NS_B" link set fdb-a up
ip -n "$NS_A" addr show dev fda-b > "$WORK/a.ip" 2>&1 || true
ip -n "$NS_B" addr show dev fdb-a > "$WORK/b.ip" 2>&1 || true
sleep "$SHORT_WAIT_SLEEP"

ok=false
for _ in $(seq 1 "$PING_WAIT_ATTEMPTS"); do
	if ping_direct; then
		ok=true
		break
	fi
	sleep "$PING_WAIT_SLEEP"
done

if [[ "$ok" != true ]]; then
	dump_statuses
	fail 'hard-symmetric direct data path failed'
fi

printf 'ok 6 - hard-symmetric NAT peers punch directly with bounded port scans\n'
