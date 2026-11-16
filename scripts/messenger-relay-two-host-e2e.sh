#!/bin/bash
# Run scripts/messenger-relay-two-host-e2e.py: one-to-one Messenger chat
# between two OpenFox nodes A and B (milestone M-R1 of
# spec/docs/MESSENGER_RELAY_CARRIAGE_V1.md), carried only by two Agent Packet
# Relay daemons, in its own process group under a thermal guard.
#
# Local mode (the default): one host. A, B and a stranger node C each run in a
# network namespace with no path to each other; the two relays run in two
# more namespaces (scripts/messenger-relay-two-host-net.sh), and the
# three-validator chain runs in the host namespace.
#
# Required environment:
#   TOS_SOURCE, TOS_BUILD, TOSCTL, E2E_WORKDIR (must not exist yet, outside
#   the home directory), REGISTRY_CODE_BOC, ACTOR_CODE_HASH, THERMAL_GUARD
#                     as for service-front-door-e2e.sh
#   E2E_AI_SOURCE     a clean ai checkout; tos-messengerd, tos-messenger-owner
#                     and tos-service-packet-relay are built from it
# Optional:
#   E2E_BASE_PORT, E2E_RPC_PORTS as for the front-door run.
#   MR1_REDEPOSIT_SECONDS   the daemons' relay_carriage.redeposit_interval_seconds
#                           (default 600, the shortest the daemon accepts)
#   MR1_DESCRIPTOR_LIFETIME the descriptor policy's max_lifetime_seconds
#                           (default 1800)
#
# Remote mode (MR1_REMOTE=1, phase 2; validated here, then refused until the
# Python run implements it): node B runs on another host reached
# over SSH and the relays are installed systemd units on their own hosts, as
# in service-relay-multi-host-e2e.sh with RELAY_EXTERNAL=1. A and C run on
# this host, each in a network namespace whose only outgoing path is the
# relays' TLS port and the chain forwarder; the chain's JSON-RPC reaches B
# only through an SSH reverse tunnel to B's loopback. Additionally required:
#   B_SSH, B_SSH_KEY      user@host of B's host and its SSH identity
#   RELAY_URLS            https URL of each relay, two words
#   RELAY_SSHS            root@host of each relay host (systemctl, journalctl)
#   RELAY_SSH_KEYS        SSH identity file for each of RELAY_SSHS
#   RELAY_CA_FILE         PEM of the CA that issued the relay certificates
# Optional: B_REMOTE_BASE (default /opt/tos-relay-test), RELAY_UNITS (default
# tos-service-packet-relay each), RELAY_STATE_DIR, RELAY_BIN.
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
remote=${MR1_REMOTE:-0}
if [ "$remote" = 1 ]; then
  : "${B_SSH:?}" "${B_SSH_KEY:?}" "${RELAY_URLS:?}" "${RELAY_SSHS:?}" "${RELAY_SSH_KEYS:?}" "${RELAY_CA_FILE:?}"
  read -r -a relay_urls <<< "$RELAY_URLS"
  read -r -a relay_sshs <<< "$RELAY_SSHS"
  read -r -a relay_keys <<< "$RELAY_SSH_KEYS"
  if [ "${#relay_urls[@]}" != 2 ] || [ "${#relay_sshs[@]}" != 2 ] || [ "${#relay_keys[@]}" != 2 ]; then
    echo "RELAY_URLS, RELAY_SSHS and RELAY_SSH_KEYS must name exactly two relays" >&2
    exit 2
  fi
  for url in "${relay_urls[@]}"; do
    case "$url" in https://*) ;; *) echo "every relay URL must be https" >&2; exit 2 ;; esac
  done
  export B_REMOTE_BASE=${B_REMOTE_BASE:-/opt/tos-relay-test}
  # The environment above is the phase-2 contract. The remote executor for B
  # and the outage control of installed relays are not implemented in the
  # Python run yet, so remote mode refuses instead of running half of it.
  echo "MR1_REMOTE=1 (phase 2) is not implemented yet in messenger-relay-two-host-e2e.py" >&2
  exit 2
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
if [ -n "$(git -C "$E2E_AI_SOURCE" status --porcelain)" ]; then
  echo "$E2E_AI_SOURCE is not a clean checkout" >&2
  exit 2
fi
mkdir -p "$E2E_WORKDIR" && chmod 700 "$E2E_WORKDIR"
work=$(CDPATH= cd -- "$E2E_WORKDIR" && pwd)
export E2E_WORKDIR=$work
export E2E_BIN="$work/bin"
mkdir -p "$E2E_BIN" "$work/private" "$work/tls/empty-certs"
chmod 700 "$work/private"
(cd "$repo" && GOWORK=off GOFLAGS=-trimpath CGO_ENABLED=0 go build -tags goolm,stdjson -o "$E2E_BIN/openfox" ./cmd/openfox)
(cd "$repo" && GOWORK=off GOFLAGS=-trimpath CGO_ENABLED=0 go build -o "$E2E_BIN/messenger-relay-e2e-tool" \
  ./scripts/messenger-relay-e2e-tool)
(cd "$E2E_AI_SOURCE" && GOWORK=off GOFLAGS=-trimpath CGO_ENABLED=0 go build -o "$E2E_BIN/" \
  ./messenger/cmd/tos-messengerd ./messenger/cmd/tos-messenger-owner ./protocol/cmd/tos-service-packet-relay)

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
  # The run's process group holds the validators and every node, relay,
  # forwarder and probe launcher; stop it before the namespaces go.
  if [ -n "$pg" ]; then
    kill -TERM -- "-$pg" 2> /dev/null || true
    for _ in $(seq 30); do kill -0 -- "-$pg" 2> /dev/null || break; sleep 1; done
    kill -KILL -- "-$pg" 2> /dev/null || true
  fi
  exit 130
}
trap interrupted INT TERM
bash "$here/messenger-relay-two-host-net.sh" up "$work"

# The front-door module the run loads needs an executor socket to select its
# unprivileged mode; this run makes no sale and never contacts an executor.
export E2E_EXECUTOR_SOCKET=unused-no-sale
export E2E_REPO="$repo" E2E_ROOT_BASE="$work/nodes"
cd "$TOS_SOURCE"
export PYTHONPATH="$TOS_SOURCE/test/tostester/src"
export PYTHONDONTWRITEBYTECODE=1
setsid uv run --frozen python -B "$here/messenger-relay-two-host-e2e.py" > "$work/run.log" 2>&1 &
pg=$!
echo "$pg" > "$work/run.pgid"
"$THERMAL_GUARD" "$pg" > "$work/guard.log" 2>&1 &
set +e
wait "$pg"
status=$?
set -e
# No artifact may hold a vault master key; only file names are printed.
leaks=0
while IFS= read -r -d '' artifact; do
  if { [ -s "$work/private/scan-secrets" ] && grep -qF -f "$work/private/scan-secrets" "$artifact"; } ||
     grep -qE 'master_key=[0-9A-Fa-f]{8,}' "$artifact"; then
    echo "secret found in $artifact" >&2
    leaks=1
  fi
done < <(find "$work" -path "$work/private" -prune -o -path "$work/network" -prune -o -path "$work/bin" -prune -o \
  -path "$work/nodes" -prune -o -type f -print0)
tail -n 2 "$work/run.log"
if [ "$status" = 0 ] && [ "$leaks" = 0 ]; then
  echo "ALL PASS"
  exit 0
fi
echo "FAIL"
exit 1
