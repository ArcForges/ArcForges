#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# AR-02 (development stage, Linux): a process of another uid cannot use the node's endpoint (R-SEC-001; 11 section 2; T-01).
# No second account is created: the other process runs under an unused uid through setpriv, as root.
#
#   sudo tests/ArcForges.ClosedLoop.Tests/Procedures/ar02-other-uid.sh <arcforges binary> <node owner user> [other uid (1077)]
#
# 1. The owner starts a test node (its own configuration, data root and socket under a fresh directory).
# 2. The other uid connects to the socket: refused by the 0700 socket directory (EACCES).
# 3. The directory and socket are opened up (0711 / 0666, as root): the connection is accepted by the kernel, and the node
#    drops it before HTTP/2 because SO_PEERCRED names another uid (GetHealth: rpc.peers_denied{reason=OtherUser} = 1).
# 4. The other uid's CLI (CI=true, so it never starts a node of its own) cannot use the node either.
# The node is stopped and every file is removed. Exit 0 only when every refusal happened.
set -euo pipefail
source=$(readlink -f "$1")
owner=$2
other=${3:-1077}
owner_uid=$(id -u "$owner")
work=$(mktemp -d /tmp/ar02-XXXXXX)
chmod 755 "$work"
chown "$owner" "$work"
# Both users run a copy of the binary (and its native SQLite library) from a directory each can read.
install -d -m 755 "$work/bin"
cp "$source" "$(dirname "$source")"/libe_sqlite3.so "$work/bin/" 2>/dev/null || cp "$source" "$work/bin/"
chmod 755 "$work/bin"/*
bin="$work/bin/$(basename "$source")"
python=$(command -v /usr/bin/python3 || command -v python3)
config="$work/config"
socket_dir="$work/sock"
socket="$socket_dir/node.sock"
as_owner() { runuser -u "$owner" -- env HOME="$(getent passwd "$owner" | cut -d: -f6)" DOTNET_ROOT="${DOTNET_ROOT:-}" \
  ARCFORGES_CONFIG_DIR="$config" ARCFORGES_ENDPOINT="$socket" DBUS_SESSION_BUS_ADDRESS="unix:path=$work/no-bus" "$@"; }
as_other() { setpriv --reuid="$other" --regid="$other" --clear-groups env HOME="$work/other" DOTNET_ROOT="${DOTNET_ROOT:-}" CI=true \
  ARCFORGES_CONFIG_DIR="$work/other/config" ARCFORGES_ENDPOINT="$socket" "$@"; }
cleanup() {
  chmod 700 "$socket_dir" 2>/dev/null || true
  as_owner "$bin" node stop --test-mode --timeout 15s >/dev/null 2>&1 || true
  pkill -u "$owner" -f "$work/bin/" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

install -d -o "$owner" -m 700 "$config"
printf '{ "dataRoot": "%s" }\n' "$work/data" > "$config/node.json"
chown "$owner" "$config/node.json"
install -d -o "$other" -g "$other" -m 700 "$work/other" "$work/other/config"
as_owner setsid -f "$bin" node run --test-mode </dev/null >/dev/null 2>&1
as_owner "$bin" node wait-ready --test-mode --timeout 30s >/dev/null
echo "node uid $owner_uid listening on $socket ($(stat -c '%a %U' "$socket_dir") directory)"

probe='import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect(sys.argv[1])
except OSError as error:
    print("connect refused:", error.strerror); sys.exit(2)
s.settimeout(5)
s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + bytes.fromhex("000000040000000000"))
try:
    data = s.recv(64)
except OSError as error:
    data = b""
print("connected; server answered %d bytes before closing" % len(data)); sys.exit(0 if data else 3)'

set +e
as_other "$python" -c "$probe" "$socket"; step2=$?
chmod 711 "$work/data" "$socket_dir"; chmod 666 "$socket"
as_other "$python" -c "$probe" "$socket"; step3=$?
as_other "$bin" status --test-mode >/dev/null 2>"$work/other/status.err"; step4=$?
# The owner's client requires the owner-only directory again.
chmod 700 "$socket_dir"
set -e
denied=$(as_owner "$bin" node health --test-mode --json | "$python" -c 'import json,sys
m=[x for x in json.load(sys.stdin)["metrics"] if x["name"]=="rpc.peers_denied" and x.get("labels",{}).get("reason")=="OtherUser"]
print(int(m[0].get("value",0)) if m else 0)')
echo "step 2 (0700 directory): exit $step2 (2 = connect refused)"
echo "step 3 (directory opened, SO_PEERCRED check): exit $step3 (3 = dropped before HTTP/2); rpc.peers_denied{OtherUser} = $denied"
echo "step 4 (other uid's CLI): exit $step4 ($(tr '\n' ' ' < "$work/other/status.err"))"
[ "$step2" -eq 2 ] && [ "$step3" -eq 3 ] && [ "$denied" -ge 1 ] && [ "$step4" -ne 0 ]
echo "AR-02 Linux other-uid refusal: PASS"
