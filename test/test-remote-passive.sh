#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
#
# Integration coverage for the inbound-only `remote passive` peer setting.

set -u

FASTD=${1:?fastd binary path required}

skip() {
	printf '1..0 # SKIP %s\n' "$1"
	exit 0
}

fail() {
	printf 'not ok 1 - %s\n' "$1"
	[[ -f "$WORK/fastd.log" ]] && sed 's/^/# /' "$WORK/fastd.log"
	[[ -f "$WORK/probe.log" ]] && sed 's/^/# /' "$WORK/probe.log"
	exit 1
}

for cmd in mktemp python3; do
	command -v "$cmd" >/dev/null 2>&1 || skip "$cmd not available"
done
[[ -c /dev/net/tun ]] || skip '/dev/net/tun not available'
[[ "$(id -u)" -eq 0 ]] || skip 'root privileges required'

WORK=$(mktemp -d)
FASTD_PID=
ACTIVE_PID=
PROBE_PID=

cleanup() {
	if [[ -n "$FASTD_PID" ]]; then
		kill "$FASTD_PID" >/dev/null 2>&1 || true
		wait "$FASTD_PID" >/dev/null 2>&1 || true
	fi
	if [[ -n "$ACTIVE_PID" ]]; then
		kill "$ACTIVE_PID" >/dev/null 2>&1 || true
		wait "$ACTIVE_PID" >/dev/null 2>&1 || true
	fi
	if [[ -n "$PROBE_PID" ]]; then
		wait "$PROBE_PID" >/dev/null 2>&1 || true
	fi
	rm -rf "$WORK"
}
trap cleanup EXIT

SECRET=$("$FASTD" --machine-readable --generate-key)
PEER_SECRET=$("$FASTD" --machine-readable --generate-key)
PUBLIC=$(printf 'secret "%s";\n' "$SECRET" | "$FASTD" --machine-readable --show-key --config -) ||
	fail 'could not derive local public key'
PEER_PUBLIC=$(printf 'secret "%s";\n' "$PEER_SECRET" | "$FASTD" --machine-readable --show-key --config -) ||
	fail 'could not derive peer public key'
BIND_PORT=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')

python3 - "$WORK/probe.port" > "$WORK/probe.log" 2>&1 <<'PY' &
import socket
import sys

port_file = sys.argv[1]
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 0))
with open(port_file, "w", encoding="utf-8") as output:
    output.write(str(sock.getsockname()[1]))
sock.settimeout(2.0)

try:
    data, _ = sock.recvfrom(65535)
except TimeoutError:
    print("no outbound UDP observed")
    raise SystemExit(0)

print(f"unexpected outbound UDP: {len(data)} bytes")
raise SystemExit(1)
PY
PROBE_PID=$!

for _ in $(seq 1 20); do
	[[ -s "$WORK/probe.port" ]] && break
	sleep 0.1
done
[[ -s "$WORK/probe.port" ]] || fail 'UDP observer did not start'
PROBE_PORT=$(<"$WORK/probe.port")

cat > "$WORK/fastd.conf" <<EOF
mode tun;
persist interface no;
interface "fastd-passive-test";
bind 127.0.0.1:$BIND_PORT default ipv4;
status socket "$WORK/status.sock";
method "salsa2012+umac";
secret "$SECRET";
nat traversal yes;

peer "passive-site" {
	key "$PEER_PUBLIC";
	remote 127.0.0.1:$PROBE_PORT;
	remote passive;
	nat traversal yes;
}
EOF

"$FASTD" --config "$WORK/fastd.conf" --log-level error > "$WORK/fastd.log" 2>&1 &
FASTD_PID=$!

for _ in $(seq 1 30); do
	[[ -S "$WORK/status.sock" ]] && break
	if ! kill -0 "$FASTD_PID" >/dev/null 2>&1; then
		fail 'fastd exited before creating the status socket'
	fi
	sleep 0.1
done
[[ -S "$WORK/status.sock" ]] || fail 'status socket did not become available'

"$FASTD" --status-socket "$WORK/status.sock" --status --json > "$WORK/status.json" ||
	fail 'status query failed'

wait "$PROBE_PID" || fail 'passive peer sent an outbound UDP handshake'
PROBE_PID=

cat > "$WORK/active.conf" <<EOF
mode tun;
persist interface no;
interface "fastd-active-test";
bind 127.0.0.1:0 default ipv4;
status socket "$WORK/active.status.sock";
method "salsa2012+umac";
secret "$PEER_SECRET";

peer "passive-site" {
	key "$PUBLIC";
	remote 127.0.0.1:$BIND_PORT;
}
EOF

"$FASTD" --config "$WORK/active.conf" --log-level error > "$WORK/active.log" 2>&1 &
ACTIVE_PID=$!

connected=false
for _ in $(seq 1 50); do
	if ! kill -0 "$FASTD_PID" >/dev/null 2>&1; then
		fail 'passive fastd exited while waiting for inbound handshake'
	fi
	if ! kill -0 "$ACTIVE_PID" >/dev/null 2>&1; then
		fail 'active fastd exited before connecting'
	fi
	"$FASTD" --status-socket "$WORK/status.sock" --status --json > "$WORK/status.json" || true
	if python3 - "$WORK/status.json" <<'PY'
import json
import sys

try:
    status = json.load(open(sys.argv[1], encoding="utf-8"))
    peer = next(iter(status["peers"].values()))
except (OSError, ValueError, KeyError, StopIteration):
    raise SystemExit(1)

raise SystemExit(0 if peer.get("connection") else 1)
PY
	then
		connected=true
		break
	fi
	sleep 0.1
done
[[ "$connected" == true ]] || fail 'passive peer did not establish the inbound tunnel'

python3 - "$WORK/status.json" <<'PY' || fail 'status does not show passive traversal suppression'
import json
import sys

status = json.load(open(sys.argv[1], encoding="utf-8"))
peer = next(iter(status["peers"].values()))
hole = peer["hole_punch"]

if hole.get("remote_passive") is not True:
    raise SystemExit("remote_passive was not reported")
if hole.get("nat_traversal") is not False or hole.get("enabled") is not False:
    raise SystemExit(f"traversal was not disabled: {hole!r}")
if hole.get("direct_candidates") != 0:
    raise SystemExit(f"passive peer retained direct candidates: {hole!r}")
if peer["connection"].get("transport") != "udp":
    raise SystemExit(f"unexpected passive connection transport: {peer['connection']!r}")
PY

printf '1..1\n'
printf 'ok 1 - remote passive waits for inbound connections and disables NAT traversal\n'
