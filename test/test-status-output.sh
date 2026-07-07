#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
#
# Integration test for human-readable status table output.

set -u

FASTD=${1:?fastd binary path required}

skip() {
	printf '1..0 # SKIP %s\n' "$1"
	exit 0
}

fail() {
	printf 'not ok %s - %s\n' "${CURRENT_TEST:-1}" "$1"
	if [[ -n "${WORK:-}" && -d "$WORK" ]]; then
		if [[ -f "$WORK/human.status" ]]; then
			printf '# --- human status ---\n'
			sed 's/^/# /' "$WORK/human.status"
		fi
		if [[ -f "$WORK/fastd.log" ]]; then
			printf '# --- fastd log ---\n'
			sed 's/^/# /' "$WORK/fastd.log"
		fi
	fi
	exit 1
}

for cmd in mktemp python3; do
	command -v "$cmd" >/dev/null 2>&1 || skip "$cmd not available"
done

[[ -c /dev/net/tun ]] || skip '/dev/net/tun not available'
[[ "$(id -u)" -eq 0 ]] || skip 'root privileges required'

WORK=$(mktemp -d)
PID=

cleanup() {
	if [[ -n "$PID" ]]; then
		kill "$PID" >/dev/null 2>&1 || true
		wait "$PID" >/dev/null 2>&1 || true
	fi
	rm -rf "$WORK"
}
trap cleanup EXIT

make_key() {
	"$FASTD" --machine-readable --generate-key
}

show_pub() {
	local file=$1 secret=$2
	printf '%s\n' 'method "salsa2012+umac";' "secret \"$secret\";" > "$file"
	"$FASTD" --machine-readable --show-key --config "$file"
}

SEC=$(make_key)
PEER_SEC=$(make_key)
PUB=$(show_pub "$WORK/peer-show.conf" "$PEER_SEC")

cat > "$WORK/fastd.conf" <<EOF
mode tap;
interface "fdstatus";
persist interface no;
method "salsa2012+umac";
secret "$SEC";
bind 127.0.0.1:0;
status socket "$WORK/status.sock";
punch max attempts 3;
punch data relay yes;
peer "dummy" { key "$PUB"; hole-punch udp; }
EOF

"$FASTD" --config "$WORK/fastd.conf" --log-level error > "$WORK/fastd.log" 2>&1 &
PID=$!

for _ in $(seq 1 50); do
	if [[ -S "$WORK/status.sock" ]]; then
		break
	fi
	if ! kill -0 "$PID" >/dev/null 2>&1; then
		fail 'fastd exited before creating the status socket'
	fi
	sleep 0.1
done

[[ -S "$WORK/status.sock" ]] || fail 'status socket did not become available'

printf '1..2\n'

CURRENT_TEST=1
"$FASTD" --status-socket "$WORK/status.sock" --status > "$WORK/human.status" ||
	fail 'human status query failed'

python3 - "$WORK/human.status" <<'PY' || fail 'human status did not contain expected tables'
import sys

text = open(sys.argv[1], encoding="utf-8").read()
for section in ("Overview", "NAT", "Punch", "Traffic", "Peers", "Connections", "Hole Punch"):
    if section not in text:
        raise SystemExit(f"missing section {section}")

if "\u2554" not in text or "\u2566" not in text:
    raise SystemExit("libfort table borders not found")

if "dummy" not in text or "1 total, 0 established" not in text:
    raise SystemExit("peer summary not rendered")

if "Max attempts" not in text:
    raise SystemExit("punch attempt limit not rendered")
if "Data relay" not in text:
    raise SystemExit("punch data relay state not rendered")
PY

printf 'ok 1 - human status uses libfort tables\n'

CURRENT_TEST=2
"$FASTD" --status-socket "$WORK/status.sock" --status --json > "$WORK/status.json" ||
	fail 'JSON status query failed'
python3 -m json.tool "$WORK/status.json" >/dev/null || fail 'JSON status output is invalid'
python3 - "$WORK/status.json" <<'PY' || fail 'JSON status does not expose punch max_attempts'
import json
import sys

doc = json.load(open(sys.argv[1], encoding="utf-8"))
if (doc.get("punch") or {}).get("max_attempts") != 3:
    raise SystemExit("unexpected max_attempts")
if (doc.get("punch") or {}).get("data_relay") is not True:
    raise SystemExit("unexpected data_relay")
if (doc.get("punch") or {}).get("data_relay_explicit") is not True:
    raise SystemExit("unexpected data_relay_explicit")
PY

printf 'ok 2 - JSON status output remains parseable\n'
