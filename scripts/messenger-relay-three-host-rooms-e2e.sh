#!/bin/bash
# Run scripts/messenger-relay-three-host-rooms-e2e.py: private MLS rooms and
# invites between three OpenFox nodes A, B and C (milestone M-R2 of
# spec/docs/MESSENGER_RELAY_CARRIAGE_V1.md), carried only by two Agent Packet
# Relay daemons, in its own process group under a thermal guard.
#
# Local mode (the default): one host. A, B, C and the two filler joiners D and
# E each run in a network namespace with no path to each other; the two
# relays run in two more namespaces (scripts/messenger-relay-two-host-net.sh
# with MR_NET_NODES="a b c d e"), and the three-validator chain runs in the
# host namespace. The record is local-messenger-relay-rooms-<date>.json.
#
# Required environment:
#   TOS_SOURCE, TOS_BUILD, TOSCTL, E2E_WORKDIR (must not exist yet, outside
#   the home directory), REGISTRY_CODE_BOC, ACTOR_CODE_HASH, THERMAL_GUARD
#                     as for service-front-door-e2e.sh
#   E2E_AI_SOURCE     a clean ai checkout; tos-messengerd, tos-messenger-owner,
#                     tos-service-packet-relay and the OpenMLS driver are built
#                     from it
# Optional:
#   E2E_OPENFOX_SOURCE  a clean openfox checkout the openfox binary is built
#                       from (default: this repository); the harness and its
#                       tool always come from this repository
#   E2E_CARGO_TARGET    cargo target directory for the OpenMLS driver
#                       (default: inside the work directory)
#   E2E_BASE_PORT, E2E_RPC_PORTS as for the front-door run.
#   MR1_REDEPOSIT_SECONDS, MR1_DESCRIPTOR_LIFETIME as for the M-R1 run
#   MR2_RELAY_TTL       the local relays' -ttl in seconds (default 900, the
#                       stand-in for the test relays' 1 h)
#   MR2_ROOMTEST=1      build tos-messengerd with the roomtest tag; only then
#                       may MR2_ROOM_PART_BYTES, MR2_HANDSHAKE_RETENTION and
#                       MR2_AUTHORIZATION_SECONDS set the daemons' room test
#                       settings (a production build refuses them)
#   MR1_HOLD_AT         a development hold (voids the acceptance)
#
# Remote mode (MR2_REMOTE=1) runs B and C on two other hosts over SSH and uses
# the installed test relays; see messenger-relay-three-host-rooms-e2e-remote.py.
# Additionally required there:
#   B_SSH, B_SSH_KEY, C_SSH, C_SSH_KEY   user@host and SSH identity of B's and C's hosts
#   RELAY_URLS, RELAY_SSHS, RELAY_SSH_KEYS, RELAY_CA_FILE   as for the M-R1 remote run
# Optional: B_REMOTE_BASE, C_REMOTE_BASE (default /opt/tos-relay-test).
#
# Root (local mode): `sudo -n` creates and removes the namespaces, the bridge
# and the firewall rules and enters a namespace to start each process, which
# then runs as the invoking user (setpriv). The evidence lists every such
# command. The namespaces are removed on exit, also after a failure or an
# interrupt.
set -euo pipefail
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(dirname "$here")
: "${TOS_SOURCE:?}" "${TOS_BUILD:?}" "${TOSCTL:?}" "${E2E_WORKDIR:?}" "${REGISTRY_CODE_BOC:?}" "${ACTOR_CODE_HASH:?}"
: "${THERMAL_GUARD:?}" "${E2E_AI_SOURCE:?}"
export E2E_BASE_PORT=${E2E_BASE_PORT:-49800}
export E2E_RPC_PORTS=${E2E_RPC_PORTS:-49880,49881,49882}
export MR_NET_NODES="a b c d e"
openfox_source=${E2E_OPENFOX_SOURCE:-$repo}
export E2E_OPENFOX_SOURCE=$openfox_source
remote=${MR2_REMOTE:-0}
roomtest=${MR2_ROOMTEST:-0}
if [ "$roomtest" != 1 ]; then
  for name in MR2_ROOM_PART_BYTES MR2_HANDSHAKE_RETENTION MR2_AUTHORIZATION_SECONDS; do
    if [ -n "${!name:-}" ]; then
      echo "$name needs MR2_ROOMTEST=1: a production daemon build refuses room test settings" >&2
      exit 2
    fi
  done
fi
if [ "$remote" = 1 ]; then
  : "${B_SSH:?}" "${B_SSH_KEY:?}" "${C_SSH:?}" "${C_SSH_KEY:?}" "${RELAY_URLS:?}" "${RELAY_SSHS:?}"
  : "${RELAY_SSH_KEYS:?}" "${RELAY_CA_FILE:?}"
  echo "MR2_REMOTE=1: run it only after the owner's go-ahead; see the run plan" >&2
  if [ "${MR2_REMOTE_GO:-0}" != 1 ]; then exit 2; fi
fi
for port in $(seq "$E2E_BASE_PORT" $((E2E_BASE_PORT + 79))) ${E2E_RPC_PORTS//,/ }; do
  if ss -ltn "( sport = :$port )" | grep -q LISTEN; then
    echo "port $port is in use; choose another E2E_BASE_PORT/E2E_RPC_PORTS" >&2
    exit 2
  fi
done
if ip netns list | grep -q '^tosmr-'; then
  echo "a tosmr-* namespace exists: another run is active, or remove the leftover with messenger-relay-two-host-net.sh down" >&2
  exit 2
fi
case "$E2E_WORKDIR" in
  "$HOME"|"$HOME"/*) echo "choose a work directory outside the home directory" >&2; exit 2 ;;
esac
if [ -e "$E2E_WORKDIR" ]; then
  echo "$E2E_WORKDIR already exists; every run takes a fresh work directory" >&2
  exit 2
fi
for tree in "$E2E_AI_SOURCE" "$openfox_source"; do
  if [ -n "$(git -C "$tree" status --porcelain)" ]; then
    echo "$tree is not a clean checkout" >&2
    exit 2
  fi
done
mkdir -p "$E2E_WORKDIR" && chmod 700 "$E2E_WORKDIR"
work=$(CDPATH= cd -- "$E2E_WORKDIR" && pwd)
export E2E_WORKDIR=$work
export E2E_BIN="$work/bin"
mkdir -p "$E2E_BIN" "$work/private" "$work/tls/empty-certs"
chmod 700 "$work/private"
tags=()
[ "$roomtest" = 1 ] && tags=(-tags roomtest)
(cd "$openfox_source" && GOWORK=off GOFLAGS=-trimpath CGO_ENABLED=0 go build -tags goolm,stdjson -o "$E2E_BIN/openfox" ./cmd/openfox)
(cd "$repo" && GOWORK=off GOFLAGS=-trimpath CGO_ENABLED=0 go build -o "$E2E_BIN/messenger-relay-e2e-tool" \
  ./scripts/messenger-relay-e2e-tool)
(cd "$E2E_AI_SOURCE" && GOWORK=off GOFLAGS=-trimpath CGO_ENABLED=0 go build "${tags[@]}" -o "$E2E_BIN/" \
  ./messenger/cmd/tos-messengerd)
(cd "$E2E_AI_SOURCE" && GOWORK=off GOFLAGS=-trimpath CGO_ENABLED=0 go build -o "$E2E_BIN/" \
  ./messenger/cmd/tos-messenger-owner ./protocol/cmd/tos-service-packet-relay)
cargo_target=${E2E_CARGO_TARGET:-$work/cargo-target}
cargo build --locked --release --manifest-path "$E2E_AI_SOURCE/messenger/rust/openmls-driver/Cargo.toml" \
  --target-dir "$cargo_target"
cp "$cargo_target/release/tos-openmls-driver" "$E2E_BIN/"

tls=$work/tls
if [ "$remote" != 1 ]; then
  # A certificate authority for this run only, each relay's certificate for
  # its namespace address, and an unrelated authority for the negative control.
  key_dir=$work/private/tls
  mkdir -m 700 "$key_dir"
  ca() {
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$key_dir/$1-key.pem" \
      -out "$tls/$1.pem" -days 2 -subj "/CN=$2" -addext basicConstraints=critical,CA:TRUE \
      -addext keyUsage=critical,keyCertSign,cRLSign 2> /dev/null
  }
  ca ca "relay acceptance run CA"
  ca unrelated-ca "unrelated CA"
  for relay in relay1:10.231.78.20 relay2:10.231.78.21; do
    name=${relay%%:*} ip=${relay#*:}
    mkdir -p "$work/$name/state"
    chmod 700 "$work/$name" "$work/$name/state"
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$work/$name/tls-key.pem" \
      -out "$key_dir/$name.csr" -subj "/CN=$ip" 2> /dev/null
    printf 'subjectAltName=IP:%s\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' "$ip" > "$key_dir/$name.ext"
    openssl x509 -req -in "$key_dir/$name.csr" -CA "$tls/ca.pem" -CAkey "$key_dir/ca-key.pem" \
      -set_serial "0x$(openssl rand -hex 16)" -days 2 -extfile "$key_dir/$name.ext" \
      -out "$tls/$name-cert.pem" 2> /dev/null
    chmod 600 "$work/$name/tls-key.pem"
  done
else
  cp "$RELAY_CA_FILE" "$tls/ca.pem"
fi

teardown() {
  bash "$here/messenger-relay-two-host-net.sh" down "$work" || echo "teardown failed; run it again" >&2
}
trap teardown EXIT
pg=
interrupted() {
  if [ -n "$pg" ]; then
    kill -TERM -- "-$pg" 2> /dev/null || true
    for _ in $(seq 30); do kill -0 -- "-$pg" 2> /dev/null || break; sleep 1; done
    kill -KILL -- "-$pg" 2> /dev/null || true
  fi
  exit 130
}
trap interrupted INT TERM
bash "$here/messenger-relay-two-host-net.sh" up "$work"

export E2E_EXECUTOR_SOCKET=unused-no-sale
export E2E_REPO="$repo" E2E_ROOT_BASE="$work/nodes"
cd "$TOS_SOURCE"
export PYTHONPATH="$TOS_SOURCE/test/tostester/src"
export PYTHONDONTWRITEBYTECODE=1
script=messenger-relay-three-host-rooms-e2e.py
[ "$remote" = 1 ] && script=messenger-relay-three-host-rooms-e2e-remote.py
setsid uv run --frozen python -B "$here/$script" > "$work/run.log" 2>&1 &
pg=$!
echo "$pg" > "$work/run.pgid"
"$THERMAL_GUARD" "$pg" > "$work/guard.log" 2>&1 &
set +e
wait "$pg"
status=$?
set -e
# No artifact may hold a vault master key or an invite token; only file names
# are printed.
leaks=0
while IFS= read -r -d '' artifact; do
  if { [ -s "$work/private/scan-secrets" ] && grep -qF -f "$work/private/scan-secrets" "$artifact"; } ||
     grep -qE 'master_key=[0-9A-Fa-f]{8,}' "$artifact"; then
    echo "secret found in $artifact" >&2
    leaks=1
  fi
done < <(find "$work" -path "$work/private" -prune -o -path "$work/network" -prune -o -path "$work/bin" -prune -o \
  -path "$work/nodes" -prune -o -path "$work/cargo-target" -prune -o -type f -print0)
tail -n 2 "$work/run.log"
if [ "$status" = 0 ] && [ "$leaks" = 0 ]; then
  echo "ALL PASS"
  exit 0
fi
echo "FAIL"
exit 1
