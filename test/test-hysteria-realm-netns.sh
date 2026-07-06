#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
#
# Integration test for Hysteria realm-server assisted UDP hole punching.

set -u

FASTD=${1:?fastd binary path required}

CURRENT_TEST=1
WORK=
PIDS=()
STUN_PID=
REALM_PID=
REALM_BIN=

skip() {
	printf '1..0 # SKIP %s\n' "$1"
	exit 0
}

fail() {
	printf 'not ok %s - %s\n' "$CURRENT_TEST" "$1"
	if [[ -n "${WORK:-}" && -d "$WORK" ]]; then
		for file in clone.log go-build.log realm.log stun.log; do
			if [[ -f "$WORK/$file" ]]; then
				printf '# --- %s ---\n' "$file"
				tail -120 "$WORK/$file" | sed 's/^/# /'
			fi
		done
		for name in a b; do
			if [[ -f "$WORK/$name.ping" ]]; then
				printf '# --- %s ping ---\n' "$name"
				cat "$WORK/$name.ping" | sed 's/^/# /'
			fi
			if [[ -f "$WORK/$name.json" ]]; then
				printf '# --- %s status ---\n' "$name"
				python3 -m json.tool "$WORK/$name.json" 2>/dev/null | tail -160 | sed 's/^/# /'
			fi
			if [[ -f "$WORK/$name.log" ]]; then
				printf '# --- %s log ---\n' "$name"
				tail -120 "$WORK/$name.log" | sed 's/^/# /'
			fi
		done
	fi
	exit 1
}

printf '1..1\n'

for cmd in date git go ip nft ping python3 mktemp; do
	if ! command -v "$cmd" >/dev/null 2>&1; then
		fail "$cmd not available"
	fi
done

[[ -c /dev/net/tun ]] || skip '/dev/net/tun not available'

PROBE_NS="fastd-realm-probe-$$"
if ! ip netns add "$PROBE_NS" >/dev/null 2>&1; then
	skip 'network namespace creation is not permitted'
fi
ip netns del "$PROBE_NS" >/dev/null 2>&1 || true

WORK=$(mktemp -d)
PREFIX="h$$"
BR="${PREFIX}br"
NS_A="${PREFIX}a"
NS_B="${PREFIX}b"
NS_C="${PREFIX}c"
NS_RA1="${PREFIX}ra1"
NS_RA2="${PREFIX}ra2"
NS_RA3="${PREFIX}ra3"
NS_RA4="${PREFIX}ra4"
NS_RB1="${PREFIX}rb1"
NS_RB2="${PREFIX}rb2"
NS_RB3="${PREFIX}rb3"
NS_RB4="${PREFIX}rb4"
ALL_NS=(
	"$NS_A" "$NS_B" "$NS_C"
	"$NS_RA1" "$NS_RA2" "$NS_RA3" "$NS_RA4"
	"$NS_RB1" "$NS_RB2" "$NS_RB3" "$NS_RB4"
)

FAST_WAIT_ATTEMPTS=150
FAST_WAIT_SLEEP=0.25
PING_WAIT_ATTEMPTS=35
PING_WAIT_SLEEP=0.1
PING_TIMEOUT=0.4
REALM_TOKEN="fastd-realm-test-token"
REALM_URL="http://10.62.0.1:8443"
RUNTIME_DEADLINE=0

cleanup() {
	local pid ns

	if [[ -n "$REALM_PID" ]]; then
		kill "$REALM_PID" >/dev/null 2>&1 || true
		wait "$REALM_PID" >/dev/null 2>&1 || true
		REALM_PID=
	fi
	if [[ -n "$STUN_PID" ]]; then
		kill "$STUN_PID" >/dev/null 2>&1 || true
		wait "$STUN_PID" >/dev/null 2>&1 || true
		STUN_PID=
	fi
	for pid in "${PIDS[@]}"; do
		kill "$pid" >/dev/null 2>&1 || true
		wait "$pid" >/dev/null 2>&1 || true
	done

	ip link del "$BR" >/dev/null 2>&1 || true
	for ns in "${ALL_NS[@]}"; do
		ip netns del "$ns" >/dev/null 2>&1 || true
	done

	[[ -n "${WORK:-}" ]] && rm -rf "$WORK"
}
trap cleanup EXIT

run() {
	"$@" || fail "command failed: $*"
}

runtime_budget_check() {
	if ((RUNTIME_DEADLINE > 0 && $(date +%s) > RUNTIME_DEADLINE)); then
		fail 'hysteria realm netns runtime exceeded 60 seconds after build completed'
	fi
}

build_realm_server() {
	local src="$WORK/hysteria-realm-server"
	local built="$src/hysteria-realm-server"

	if ! git clone --depth 1 https://github.com/apernet/hysteria-realm-server.git "$src" > "$WORK/clone.log" 2>&1; then
		fail 'failed to clone hysteria-realm-server'
	fi

	if ! (cd "$src" && go build -o hysteria-realm-server .) > "$WORK/go-build.log" 2>&1; then
		fail 'failed to build hysteria-realm-server'
	fi

	cp "$built" "$WORK/hysteria-realm-server-bin" || fail 'failed to copy hysteria-realm-server binary'
	rm -rf "$src"
	[[ ! -d "$src" ]] || fail 'hysteria-realm-server source directory was not removed after build'
	REALM_BIN="$WORK/hysteria-realm-server-bin"
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

setup_nat() {
	local ns=$1 cidr=$2 out_if=$3

	run ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1
	run ip netns exec "$ns" nft add table ip nat
	run ip netns exec "$ns" nft 'add chain ip nat prerouting { type nat hook prerouting priority dstnat; policy accept; }'
	run ip netns exec "$ns" nft 'add chain ip nat postrouting { type nat hook postrouting priority srcnat; policy accept; }'
	run ip netns exec "$ns" nft add rule ip nat postrouting ip saddr "$cidr" oifname "$out_if" masquerade
}

setup_port_forward() {
	local ns=$1 in_if=$2 dport=$3 dest=$4 dest_port=$5

	run ip netns exec "$ns" nft add rule ip nat prerouting iifname "$in_if" udp dport "$dport" dnat to "$dest:$dest_port"
}

make_key() {
	"$FASTD" --machine-readable --generate-key
}

show_pub() {
	local file=$1 secret=$2
	printf '%s\n' 'method "salsa2012+umac";' "secret \"$secret\";" > "$file"
	"$FASTD" --machine-readable --show-key --config "$file"
}

punch_test_limits() {
	cat <<EOF
punch keepalive interval 2;
punch maintenance interval 2;
punch announce interval 1;
punch relay interval 1;
punch max backups 8;
punch max attempts 4;
punch max sockets 8;
punch max packets 240;
EOF
}

setup_netns() {
	local ns

	for ns in "${ALL_NS[@]}"; do
		run ip netns add "$ns"
		run ip -n "$ns" link set lo up
	done

	run ip link add "$BR" type bridge
	run ip link set "$BR" up

	make_public_link "$NS_C" pub "${PREFIX}hc"
	make_public_link "$NS_RA4" pub "${PREFIX}ha"
	make_public_link "$NS_RB4" pub "${PREFIX}hb"

	make_private_link "$NS_A" eth0 "$NS_RA1" lan 1
	make_private_link "$NS_RA1" wan "$NS_RA2" lan 2
	make_private_link "$NS_RA2" wan "$NS_RA3" lan 3
	make_private_link "$NS_RA3" wan "$NS_RA4" lan 4
	make_private_link "$NS_B" eth0 "$NS_RB1" lan 5
	make_private_link "$NS_RB1" wan "$NS_RB2" lan 6
	make_private_link "$NS_RB2" wan "$NS_RB3" lan 7
	make_private_link "$NS_RB3" wan "$NS_RB4" lan 8

	run ip -n "$NS_C" addr add 10.62.0.1/24 dev pub
	run ip -n "$NS_RA4" addr add 10.62.0.2/24 dev pub
	run ip -n "$NS_RB4" addr add 10.62.0.3/24 dev pub

	run ip -n "$NS_A" addr add 10.63.1.2/24 dev eth0
	run ip -n "$NS_RA1" addr add 10.63.1.1/24 dev lan
	run ip -n "$NS_RA1" addr add 10.63.2.2/24 dev wan
	run ip -n "$NS_RA2" addr add 10.63.2.1/24 dev lan
	run ip -n "$NS_RA2" addr add 10.63.3.2/24 dev wan
	run ip -n "$NS_RA3" addr add 10.63.3.1/24 dev lan
	run ip -n "$NS_RA3" addr add 10.63.4.2/24 dev wan
	run ip -n "$NS_RA4" addr add 10.63.4.1/24 dev lan

	run ip -n "$NS_B" addr add 10.64.1.2/24 dev eth0
	run ip -n "$NS_RB1" addr add 10.64.1.1/24 dev lan
	run ip -n "$NS_RB1" addr add 10.64.2.2/24 dev wan
	run ip -n "$NS_RB2" addr add 10.64.2.1/24 dev lan
	run ip -n "$NS_RB2" addr add 10.64.3.2/24 dev wan
	run ip -n "$NS_RB3" addr add 10.64.3.1/24 dev lan
	run ip -n "$NS_RB3" addr add 10.64.4.2/24 dev wan
	run ip -n "$NS_RB4" addr add 10.64.4.1/24 dev lan

	run ip -n "$NS_A" route add default via 10.63.1.1
	run ip -n "$NS_RA1" route add default via 10.63.2.1
	run ip -n "$NS_RA2" route add default via 10.63.3.1
	run ip -n "$NS_RA3" route add default via 10.63.4.1
	run ip -n "$NS_B" route add default via 10.64.1.1
	run ip -n "$NS_RB1" route add default via 10.64.2.1
	run ip -n "$NS_RB2" route add default via 10.64.3.1
	run ip -n "$NS_RB3" route add default via 10.64.4.1

	setup_nat "$NS_RA1" 10.63.1.0/24 wan
	setup_nat "$NS_RA2" 10.63.2.0/24 wan
	setup_nat "$NS_RA3" 10.63.3.0/24 wan
	setup_nat "$NS_RA4" 10.63.4.0/24 pub
	setup_nat "$NS_RB1" 10.64.1.0/24 wan
	setup_nat "$NS_RB2" 10.64.2.0/24 wan
	setup_nat "$NS_RB3" 10.64.3.0/24 wan
	setup_nat "$NS_RB4" 10.64.4.0/24 pub

	# Model a deep port-preserving/full-cone NAT path. Hysteria realm-server
	# only coordinates endpoints; data still has to traverse these NAT layers
	# directly after the realm server is stopped.
	setup_port_forward "$NS_RA4" pub 12001 10.63.4.2 12001
	setup_port_forward "$NS_RA3" wan 12001 10.63.3.2 12001
	setup_port_forward "$NS_RA2" wan 12001 10.63.2.2 12001
	setup_port_forward "$NS_RA1" wan 12001 10.63.1.2 12001
	setup_port_forward "$NS_RB4" pub 12001 10.64.4.2 12001
	setup_port_forward "$NS_RB3" wan 12001 10.64.3.2 12001
	setup_port_forward "$NS_RB2" wan 12001 10.64.2.2 12001
	setup_port_forward "$NS_RB1" wan 12001 10.64.1.2 12001
}

start_fake_stun() {
	rm -f "$WORK/stun.ready"
	: > "$WORK/stun.log"

	ip netns exec "$NS_C" python3 - "$WORK/stun.ready" > "$WORK/stun.log" 2>&1 <<'PY' &
import select
import signal
import socket
import struct
import sys
import zlib

COOKIE = 0x2112A442
SERVER_IP = "10.62.0.1"
READY = sys.argv[1]
running = True


def stop(signum, frame):
    global running
    running = False


def stun_response(data, source):
    if len(data) < 20:
        return None

    msg_type, msg_len, cookie = struct.unpack("!HHI", data[:8])
    if msg_type != 0x0001 or cookie != COOKIE or len(data) < 20 + msg_len:
        return None

    ip, port = source
    transaction = data[8:20]
    xport = port ^ (COOKIE >> 16)
    xaddr = struct.unpack("!I", socket.inet_aton(ip))[0] ^ COOKIE
    mapped = struct.pack("!HHBBHI", 0x0020, 8, 0, 1, xport, xaddr)
    fingerprint_header = struct.pack("!HH", 0x8028, 4)
    header = struct.pack("!HHI12s", 0x0101, len(mapped) + len(fingerprint_header) + 4, COOKIE, transaction)
    fingerprint = (zlib.crc32(header + mapped) & 0xFFFFFFFF) ^ 0x5354554E
    return header + mapped + fingerprint_header + struct.pack("!I", fingerprint)


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)

sockets = []
for port in (3478, 3479):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((SERVER_IP, port))
    sockets.append(sock)

open(READY, "w").close()

while running:
    readable, _, _ = select.select(sockets, [], [], 0.5)
    for sock in readable:
        data, source = sock.recvfrom(2048)
        response = stun_response(data, source)
        if response:
            sock.sendto(response, source)

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

start_realm_server() {
	: > "$WORK/realm.log"
	ip netns exec "$NS_C" "$REALM_BIN" \
		--listen 10.62.0.1:8443 \
		--token "$REALM_TOKEN" \
		--debug \
		--max-realms-per-ip 0 > "$WORK/realm.log" 2>&1 &
	REALM_PID=$!

	for _ in $(seq 1 50); do
		if ip netns exec "$NS_C" python3 - <<'PY' >/dev/null 2>&1
import socket

with socket.create_connection(("10.62.0.1", 8443), 0.2):
    pass
PY
		then
			return 0
		fi
		if ! kill -0 "$REALM_PID" >/dev/null 2>&1; then
			fail 'hysteria realm server exited before becoming ready'
		fi
		sleep 0.1
	done

	fail 'hysteria realm server did not become ready'
}

stop_realm_server() {
	if [[ -n "$REALM_PID" ]]; then
		kill "$REALM_PID" >/dev/null 2>&1 || true
		wait "$REALM_PID" >/dev/null 2>&1 || true
		REALM_PID=
	fi
}

write_fastd_confs() {
	local sec_a=$1 sec_b=$2 pub_a=$3 pub_b=$4

	cat > "$WORK/a.conf" <<EOF
mode multitap;
interface "fda-%n";
persist interface no;
method "salsa2012+umac";
secret "$sec_a";
bind 0.0.0.0:12001;
status socket "$WORK/a.status";
realm server "$REALM_URL" token "$REALM_TOKEN" id "node-a" stun server "10.62.0.1" port 3478;
$(punch_test_limits)
peer "b" {
	key "$pub_b";
	realm "node-b";
	nat traversal yes;
	transport udp;
}
EOF

	cat > "$WORK/b.conf" <<EOF
mode multitap;
interface "fdb-%n";
persist interface no;
method "salsa2012+umac";
secret "$sec_b";
bind 0.0.0.0:12001;
status socket "$WORK/b.status";
realm server "$REALM_URL" token "$REALM_TOKEN" id "node-b" stun server "10.62.0.1" port 3478;
$(punch_test_limits)
peer "a" {
	key "$pub_a";
	realm "node-a";
	nat traversal yes;
	transport udp;
}
EOF
}

start_fastds() {
	rm -f "$WORK/a.status" "$WORK/b.status" "$WORK/a.json" "$WORK/b.json"
	: > "$WORK/a.log"
	: > "$WORK/b.log"
	: > "$WORK/a.ping"

	ip netns exec "$NS_A" "$FASTD" --config "$WORK/a.conf" --log-level verbose > "$WORK/a.log" 2>&1 &
	PIDS+=("$!")
	ip netns exec "$NS_B" "$FASTD" --config "$WORK/b.conf" --log-level verbose > "$WORK/b.log" 2>&1 &
	PIDS+=("$!")
}

check_fastds_alive() {
	local pid

	for pid in "${PIDS[@]}"; do
		if ! kill -0 "$pid" >/dev/null 2>&1; then
			fail 'fastd process exited before realm punching completed'
		fi
	done
}

dump_statuses() {
	[[ -S "$WORK/a.status" ]] && "$FASTD" --status-socket "$WORK/a.status" --status --json > "$WORK/a.json" 2>/dev/null || true
	[[ -S "$WORK/b.status" ]] && "$FASTD" --status-socket "$WORK/b.status" --status --json > "$WORK/b.json" 2>/dev/null || true
}

realm_direct_path_ready() {
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


def ready(doc, name, public_ip):
    peer = find_peer(doc, name)
    connection = peer.get("connection") or {}
    hole_punch = peer.get("hole_punch") or {}
    address = peer.get("address") or ""
    return (
        "established" in connection
        and connection.get("transport") == "udp"
        and hole_punch.get("established")
        and hole_punch.get("transport") == "udp"
        and address.startswith(public_ip + ":")
    )


sys.exit(0 if ready(a, "b", "10.62.0.3") and ready(b, "a", "10.62.0.2") else 1)
PY
}

wait_for_realm_direct_path() {
	for _ in $(seq 1 "$FAST_WAIT_ATTEMPTS"); do
		runtime_budget_check
		sleep "$FAST_WAIT_SLEEP"
		check_fastds_alive
		dump_statuses

		if [[ -f "$WORK/a.json" && -f "$WORK/b.json" ]] && realm_direct_path_ready; then
			return 0
		fi
	done

	return 1
}

ping_direct() {
	ip netns exec "$NS_A" ping -I fda-b -n -c 1 -W "$PING_TIMEOUT" 10.66.0.2 >> "$WORK/a.ping" 2>&1
}

wait_for_direct_ping() {
	for _ in $(seq 1 "$PING_WAIT_ATTEMPTS"); do
		runtime_budget_check
		if ping_direct; then
			return 0
		fi
		sleep "$PING_WAIT_SLEEP"
	done

	return 1
}

build_realm_server
RUNTIME_DEADLINE=$(($(date +%s) + 60))
setup_netns
start_fake_stun
start_realm_server

SEC_A=$(make_key)
SEC_B=$(make_key)
PUB_A=$(show_pub "$WORK/show-a.conf" "$SEC_A")
PUB_B=$(show_pub "$WORK/show-b.conf" "$SEC_B")
write_fastd_confs "$SEC_A" "$SEC_B" "$PUB_A" "$PUB_B"
start_fastds

if ! wait_for_realm_direct_path; then
	fail 'hysteria realm server did not establish a direct UDP path through eight port-preserving NAT namespaces'
fi

stop_realm_server

run ip -n "$NS_A" addr add 10.66.0.1/30 dev fda-b
run ip -n "$NS_B" addr add 10.66.0.2/30 dev fdb-a
run ip -n "$NS_A" link set fda-b up
run ip -n "$NS_B" link set fdb-a up

if ! wait_for_direct_ping; then
	dump_statuses
	fail 'direct data path failed after stopping hysteria realm server'
fi

printf 'ok 1 - hysteria realm server assists direct UDP punching through eight port-preserving NAT namespaces\n'
