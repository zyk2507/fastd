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
			if [[ -f "$WORK/$name.json" ]]; then
				printf '# --- %s status ---\n' "$name"
				python3 -m json.tool "$WORK/$name.json" 2>/dev/null | tail -120 | sed 's/^/# /'
			fi
			if [[ -f "$WORK/$name.log" ]]; then
				printf '# --- %s log ---\n' "$name"
				tail -80 "$WORK/$name.log" | sed 's/^/# /'
			fi
		done
	fi
	exit 1
}

for cmd in ip nft ping python3 mktemp; do
	command -v "$cmd" >/dev/null 2>&1 || skip "$cmd not available"
done

[[ -c /dev/net/tun ]] || skip '/dev/net/tun not available'

PROBE_NS="fastd-probe-$$"
if ! ip netns add "$PROBE_NS" >/dev/null 2>&1; then
	skip 'network namespace creation is not permitted'
fi
ip netns del "$PROBE_NS" >/dev/null 2>&1 || true

WORK=$(mktemp -d)
PREFIX="f$(basename "$WORK" | tr -cd 'a-z0-9' | cut -c1-4)"
NS_A="${PREFIX}a"
NS_B="${PREFIX}b"
NS_C="${PREFIX}c"
NS_RA="${PREFIX}ra"
NS_RB="${PREFIX}rb"
BR="${PREFIX}br"
PIDS=()

stop_fastds() {
	for pid in "${PIDS[@]}"; do
		kill "$pid" >/dev/null 2>&1 || true
	done
	wait >/dev/null 2>&1 || true
	PIDS=()
}

cleanup() {
	stop_fastds

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
	ip netns exec "$NS_A" ping -I fda-b -n -c 1 -W 1 10.52.10.2 >> "$WORK/a.ping" 2>&1
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
punch max sockets 25;
punch max packets 800;
peer "c" { key "$PUB_C"; remote 10.52.0.1 port 10000; transport udp; }
peer "b" { key "$PUB_B"; transport udp; hole-punch udp; }
EOF

cat > "$WORK/b.conf" <<EOF
mode multitap;
interface "fdb-%n";
persist interface no;
method "salsa2012+umac";
secret "$SEC_B";
bind 0.0.0.0:10001;
status socket "$WORK/b.status";
punch max sockets 25;
punch max packets 800;
peer "c" { key "$PUB_C"; remote 10.52.0.1 port 10000; transport udp; }
peer "a" { key "$PUB_A"; transport udp; hole-punch udp; }
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
punch control relay $relay;
punch max sockets 25;
punch max packets 800;
peer "a" { key "$PUB_A"; transport udp; hole-punch udp; }
peer "b" { key "$PUB_B"; transport udp; hole-punch udp; }
EOF
}

start_fastds() {
	rm -f "$WORK/a.status" "$WORK/b.status" "$WORK/c.status" "$WORK/a.json" "$WORK/b.json" "$WORK/c.json" \
		"$WORK/a.ip" "$WORK/b.ip" "$WORK/c.ip"
	: > "$WORK/a.log"
	: > "$WORK/b.log"
	: > "$WORK/c.log"
	: > "$WORK/a.ping"

	ip netns exec "$NS_C" "$FASTD" --config "$WORK/c.conf" --log-level verbose > "$WORK/c.log" 2>&1 &
	PID_C=$!
	PIDS=("$PID_C")
	ip netns exec "$NS_A" "$FASTD" --config "$WORK/a.conf" --log-level verbose > "$WORK/a.log" 2>&1 &
	PIDS+=("$!")
	ip netns exec "$NS_B" "$FASTD" --config "$WORK/b.conf" --log-level verbose > "$WORK/b.log" 2>&1 &
	PIDS+=("$!")
}

wait_without_direct_path() {
	local saw_status=false

	for _ in $(seq 1 16); do
		sleep 0.5
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

wait_for_direct_path() {
	for _ in $(seq 1 120); do
		sleep 0.5
		check_fastds_alive
		dump_statuses

		if [[ -f "$WORK/a.json" && -f "$WORK/b.json" ]] && direct_hole_punched; then
			return 0
		fi
	done

	return 1
}

printf '1..2\n'

CURRENT_TEST=1
write_c_conf no
start_fastds
wait_without_direct_path
stop_fastds
printf 'ok 1 - passive A/B do not direct-connect without punch control relay\n'

CURRENT_TEST=2
write_c_conf yes
start_fastds

if ! wait_for_direct_path; then
	fail 'direct UDP path was not established'
fi

run ip -n "$NS_A" addr add 10.52.10.1/30 dev fda-b
run ip -n "$NS_B" addr add 10.52.10.2/30 dev fdb-a
run ip -n "$NS_A" link set fda-b up
run ip -n "$NS_B" link set fdb-a up
ip -n "$NS_A" addr show dev fda-b > "$WORK/a.ip" 2>&1 || true
ip -n "$NS_B" addr show dev fdb-a > "$WORK/b.ip" 2>&1 || true

for _ in $(seq 1 5); do
	ping_direct && break
	sleep 0.5
done

kill "$PID_C" >/dev/null 2>&1 || true
sleep 1

ok=false
for _ in $(seq 1 10); do
	if ping_direct; then
		ok=true
		break
	fi
	sleep 0.5
done

if [[ "$ok" != true ]]; then
	dump_statuses
	fail 'direct A/B data path failed after control relay was stopped'
fi

printf 'ok 2 - control relay establishes direct UDP path through full-cone mappings\n'
