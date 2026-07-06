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
STUN_PID=

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

cleanup() {
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
	ip netns exec "$NS_A" ping -I fda-b -n -c 1 -W 1 10.52.10.2 >> "$WORK/a.ping" 2>&1
}

ping_public_nat() {
	ip netns exec "$NS_C" ping -I fdc-a -n -c 1 -W 1 10.52.20.2 >> "$WORK/c.ping" 2>&1
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
punch max sockets 25;
punch max packets 800;
peer "c" { key "$PUB_C"; remote 10.52.0.1 port 11000; transport udp; }
peer "b" { key "$PUB_B"; transport udp; hole-punch udp; punch symmetric yes; }
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
punch max sockets 25;
punch max packets 800;
peer "c" { key "$PUB_C"; remote 10.52.0.1 port 11000; transport udp; }
peer "a" { key "$PUB_A"; transport udp; hole-punch udp; punch symmetric yes; }
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
punch control relay yes;
punch max sockets 25;
punch max packets 800;
peer "a" { key "$PUB_A"; transport udp; hole-punch udp; punch symmetric yes; }
peer "b" { key "$PUB_B"; transport udp; hole-punch udp; punch symmetric yes; }
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
punch max sockets 25;
punch max packets 800;
peer "c" { key "$PUB_C"; remote 10.52.0.1 port 12000; transport udp; }
peer "b" { key "$PUB_B"; transport udp; hole-punch udp; punch symmetric yes; }
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
punch max sockets 25;
punch max packets 800;
peer "c" { key "$PUB_C"; remote 10.52.0.1 port 12000; transport udp; }
peer "a" { key "$PUB_A"; transport udp; hole-punch udp; punch symmetric yes; }
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
punch control relay yes;
punch max sockets 25;
punch max packets 800;
peer "a" { key "$PUB_A"; transport udp; hole-punch udp; punch symmetric yes; }
peer "b" { key "$PUB_B"; transport udp; hole-punch udp; punch symmetric yes; }
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

start_fastds() {
	rm -f "$WORK/a.status" "$WORK/b.status" "$WORK/c.status" "$WORK/a.json" "$WORK/b.json" "$WORK/c.json" \
		"$WORK/a.ip" "$WORK/b.ip" "$WORK/c.ip"
	: > "$WORK/a.log"
	: > "$WORK/b.log"
	: > "$WORK/c.log"
	: > "$WORK/a.ping"
	: > "$WORK/c.ping"

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

		if [[ -f "$WORK/a.json" && -f "$WORK/b.json" && -f "$WORK/c.json" ]] &&
			direct_hole_punched && punch_results_seen; then
			return 0
		fi
	done

	return 1
}

wait_for_symmetric_to_cone_path() {
	for _ in $(seq 1 120); do
		sleep 0.5
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
	for _ in $(seq 1 120); do
		sleep 0.5
		check_fastds_alive
		dump_statuses

		if [[ -f "$WORK/a.json" && -f "$WORK/b.json" && -f "$WORK/c.json" ]] &&
			both_easy_nat_types_seen && direct_hole_punched && punch_results_seen; then
			return 0
		fi
	done

	return 1
}

printf '1..5\n'

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

run ip -n "$NS_C" addr add 10.52.20.1/30 dev fdc-a
run ip -n "$NS_A" addr add 10.52.20.2/30 dev fda-c
run ip -n "$NS_C" link set fdc-a up
run ip -n "$NS_A" link set fda-c up
ip -n "$NS_C" addr show dev fdc-a > "$WORK/c.ip" 2>&1 || true
ip -n "$NS_A" addr show dev fda-c >> "$WORK/a.ip" 2>&1 || true

ok=false
for _ in $(seq 1 5); do
	if ping_public_nat; then
		ok=true
		break
	fi
	sleep 0.5
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

printf 'ok 3 - control relay establishes direct UDP path through full-cone mappings and receives punch results\n'

CURRENT_TEST=4
stop_fastds
start_fake_stun
run ip netns exec "$NS_RA" nft insert rule ip nat postrouting ip saddr 10.52.1.2 ip daddr 10.52.0.1 udp dport 11000 snat to 10.52.0.2:41100
run ip netns exec "$NS_RA" nft insert rule ip nat postrouting ip saddr 10.52.1.2 ip daddr 10.52.0.3 udp dport 11001 snat to 10.52.0.2:41100-41163
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
sleep 1

ok=false
for _ in $(seq 1 20); do
	if ping_direct; then
		ok=true
		break
	fi
	sleep 0.5
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
sleep 1

ok=false
for _ in $(seq 1 20); do
	if ping_direct; then
		ok=true
		break
	fi
	sleep 0.5
done

if [[ "$ok" != true ]]; then
	dump_statuses
	fail 'easy-symmetric to easy-symmetric direct data path failed'
fi

printf 'ok 5 - easy-symmetric NAT peers punch directly with predicted port ranges\n'
