#!/bin/bash
# Run scripts/service-relay-multi-host-e2e.py: a paid sale between two OpenFox
# nodes on different machines, carried only by a tos-service-packet-relay
# daemon on a third machine over the public internet, with one live relay
# outage, in its own process group under a thermal guard.
#
# This host runs the three-validator chain and the provider node. The buyer
# node runs on another host, reached over SSH; the chain's JSON-RPC ports
# reach it only through an SSH reverse tunnel to that host's loopback. The
# relay runs on a third host as a transient systemd unit this script starts
# and stops over SSH.
#
# Required environment (the first nine as for service-relay-two-host-e2e.sh):
#   TOS_SOURCE, TOS_BUILD, TOSCTL, E2E_WORKDIR (must not exist yet, outside
#   the home directory), REGISTRY_CODE_BOC, ACTOR_CODE_HASH, THERMAL_GUARD,
#   E2E_EXECUTOR_SOCKET, E2E_RELAY_SOURCE (a clean ai checkout; the relay is
#   rebuilt from it and must hash to the binary on the relay host)
#   BUYER_SSH         user@host of the buyer host (the buyer node runs as
#                     that user; the host needs python3, ss and coreutils)
#   BUYER_SSH_KEY     SSH identity file for BUYER_SSH
#   RELAY_SSH         root@host of the relay host (systemd-run, journalctl)
#   RELAY_SSH_KEY     SSH identity file for RELAY_SSH
#   RELAY_URL         https://<relay public address>:<port>
#   RELAY_CA_FILE     PEM of the private CA that issued the relay certificate;
#                     both nodes pin it with `init --relay-ca-file`
#   RELAY_RUN_USER    the unprivileged user the relay daemon runs as
# Optional:
#   BUYER_REMOTE_BASE  parent of the buyer's run directory (default
#                      /opt/tos-relay-test); the run uses <base>/<run name>
#   RELAY_REMOTE_DIR   relay host directory holding bin/tos-service-packet-relay,
#                      tls/relay-cert.pem and tls/relay-key.pem (default
#                      /opt/tos-relay-test); the run's state goes to
#                      <dir>/runs/<run name>
#   RELAY_UNIT         transient unit name (default tos-relay-test)
#   E2E_BASE_PORT, E2E_RPC_PORTS as for the front-door run.
#
# External relays: with RELAY_EXTERNAL=1 the relays are installed systemd
# units the operator runs (one host each); the run names all of them on both
# nodes, stops and starts the named units for its outages and leaves every
# unit running. RELAY_SSH, RELAY_SSH_KEY, RELAY_URL, RELAY_RUN_USER,
# RELAY_REMOTE_DIR and RELAY_UNIT are not used; instead (one word per relay,
# in the same order):
#   RELAY_URLS        https://<relay public address>:<port> of each relay
#   RELAY_SSHS        root@host of each relay host (systemctl, journalctl)
#   RELAY_SSH_KEYS    SSH identity file for each of RELAY_SSHS
# Optional:
#   RELAY_UNITS       each relay's unit (default tos-service-packet-relay)
#   RELAY_DOWN        relay-<n>: that relay (by position) is stopped before
#                     the first purchase and started after the last sale step
#   RELAY_STATE_DIR, RELAY_BIN, RELAY_CERT_FILE  paths on the relay hosts
#                     (defaults: the shipped unit's state directory,
#                     /usr/local/bin/tos-service-packet-relay and
#                     /etc/tos-service/packet-relay/tls-cert.pem)
#
# The relay host's firewall rule for the relay port, its user and its
# directories are prepared by the operator beforehand; this script only
# starts and stops the relay unit. Remote run directories are left in place
# for inspection and listed in the evidence.
set -euo pipefail
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(dirname "$here")
: "${TOS_SOURCE:?}" "${TOS_BUILD:?}" "${TOSCTL:?}" "${E2E_WORKDIR:?}" "${REGISTRY_CODE_BOC:?}" "${ACTOR_CODE_HASH:?}"
: "${THERMAL_GUARD:?}" "${E2E_EXECUTOR_SOCKET:?}" "${E2E_RELAY_SOURCE:?}"
: "${BUYER_SSH:?}" "${BUYER_SSH_KEY:?}" "${RELAY_CA_FILE:?}"
export BUYER_REMOTE_BASE=${BUYER_REMOTE_BASE:-/opt/tos-relay-test}
export E2E_BASE_PORT=${E2E_BASE_PORT:-49800}
export E2E_RPC_PORTS=${E2E_RPC_PORTS:-49880,49881,49882}
if [ "${RELAY_EXTERNAL:-}" = 1 ]; then
  : "${RELAY_URLS:?}" "${RELAY_SSHS:?}" "${RELAY_SSH_KEYS:?}"
  read -r -a relay_urls <<< "$RELAY_URLS"
  read -r -a relay_sshs <<< "$RELAY_SSHS"
  read -r -a relay_keys <<< "$RELAY_SSH_KEYS"
  if [ -n "${RELAY_UNITS:-}" ]; then
    read -r -a relay_units <<< "$RELAY_UNITS"
  else
    relay_units=()
    for _ in "${relay_urls[@]}"; do relay_units+=(tos-service-packet-relay); done
  fi
  count=${#relay_urls[@]}
  if [ "$count" -lt 1 ] || [ "$count" -gt 4 ] || [ "${#relay_sshs[@]}" != "$count" ] ||
     [ "${#relay_keys[@]}" != "$count" ] || [ "${#relay_units[@]}" != "$count" ]; then
    echo "RELAY_URLS, RELAY_SSHS, RELAY_SSH_KEYS and RELAY_UNITS must name 1 to 4 relays each" >&2
    exit 2
  fi
  if [ -n "${RELAY_DOWN:-}" ]; then
    case "$RELAY_DOWN" in
      relay-[1-4]) [ "${RELAY_DOWN#relay-}" -le "$count" ] && [ "$count" -ge 2 ] ||
                     { echo "RELAY_DOWN names one of at least two relays" >&2; exit 2; } ;;
      *) echo "RELAY_DOWN must be relay-<n>" >&2; exit 2 ;;
    esac
  fi
  export E2E_RELAY_URLS="$RELAY_URLS"
  unset RELAY_URL
else
  : "${RELAY_SSH:?}" "${RELAY_SSH_KEY:?}" "${RELAY_URL:?}" "${RELAY_RUN_USER:?}"
  export RELAY_REMOTE_DIR=${RELAY_REMOTE_DIR:-/opt/tos-relay-test}
  export RELAY_UNIT=${RELAY_UNIT:-tos-relay-test}
  relay_urls=("$RELAY_URL")
  relay_sshs=("$RELAY_SSH")
  relay_keys=("$RELAY_SSH_KEY")
  relay_units=("$RELAY_UNIT")
  export E2E_RELAY_URL="$RELAY_URL"
fi
for url in "${relay_urls[@]}"; do
  case "$url" in
    https://*) ;;
    *) echo "every relay URL must be https" >&2; exit 2 ;;
  esac
done
for port in $(seq "$E2E_BASE_PORT" $((E2E_BASE_PORT + 79))) ${E2E_RPC_PORTS//,/ }; do
  if ss -ltn "( sport = :$port )" | grep -q LISTEN; then
    echo "port $port is in use; choose another E2E_BASE_PORT/E2E_RPC_PORTS" >&2
    exit 2
  fi
done
case "$E2E_WORKDIR" in
  "$HOME"|"$HOME"/*) echo "choose a work directory outside the home directory" >&2; exit 2 ;;
esac
if [ -e "$E2E_WORKDIR" ]; then
  echo "$E2E_WORKDIR already exists; every run takes a fresh work directory" >&2
  exit 2
fi
if [ -n "$(git -C "$E2E_RELAY_SOURCE" status --porcelain)" ]; then
  echo "$E2E_RELAY_SOURCE is not a clean checkout" >&2
  exit 2
fi
mkdir -p "$E2E_WORKDIR" && chmod 700 "$E2E_WORKDIR"
work=$(CDPATH= cd -- "$E2E_WORKDIR" && pwd)
export E2E_WORKDIR=$work
export E2E_BIN="$work/bin"
mkdir -p "$E2E_BIN" "$work/private"
chmod 700 "$work/private"
(cd "$repo" && GOWORK=off GOFLAGS=-trimpath CGO_ENABLED=0 go build -tags goolm,stdjson -o "$E2E_BIN/openfox" ./cmd/openfox)
(cd "$E2E_RELAY_SOURCE" && GOWORK=off GOFLAGS=-trimpath CGO_ENABLED=0 go build -o "$E2E_BIN/tos-service-packet-relay" ./protocol/cmd/tos-service-packet-relay)

ssh_opts=(-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=20)
run_name=$(basename "$work")
pg=
teardown() {
  # The run's process group holds the validators, the tunnel and every
  # local node; the remote buyer node and the relay unit are stopped over
  # SSH. Remote directories stay for inspection.
  if [ -n "$pg" ]; then
    kill -TERM -- "-$pg" 2> /dev/null || true
    for _ in $(seq 30); do kill -0 -- "-$pg" 2> /dev/null || break; sleep 1; done
    kill -KILL -- "-$pg" 2> /dev/null || true
  fi
  ssh "${ssh_opts[@]}" -i "$BUYER_SSH_KEY" "$BUYER_SSH" -- \
    "for f in $BUYER_REMOTE_BASE/$run_name/serve-*.pid; do [ -e \"\$f\" ] && kill -TERM \"\$(cat \"\$f\")\" 2> /dev/null; done; true" \
    > /dev/null 2>&1 || echo "could not reach the buyer host to stop its node" >&2
  # A transient relay is stopped; an installed relay is started again, so an
  # interrupted outage never leaves it down.
  local verb=stop
  [ "${RELAY_EXTERNAL:-}" = 1 ] && verb=start
  for index in "${!relay_urls[@]}"; do
    ssh "${ssh_opts[@]}" -i "${relay_keys[$index]}" "${relay_sshs[$index]}" -- \
      "systemctl $verb ${relay_units[$index]} 2> /dev/null; true" \
      > /dev/null 2>&1 || echo "could not reach relay host $((index + 1)) to $verb its relay" >&2
  done
  if [ "${RELAY_EXTERNAL:-}" = 1 ]; then
    echo "left for inspection: buyer host $BUYER_REMOTE_BASE/$run_name"
  else
    echo "left for inspection: buyer host $BUYER_REMOTE_BASE/$run_name, relay host $RELAY_REMOTE_DIR/runs/$run_name"
  fi
}
trap teardown EXIT
trap 'exit 130' INT TERM

export E2E_REPO="$repo" E2E_RELAY_CA_FILE="$RELAY_CA_FILE" E2E_ROOT_BASE="$work/nodes"
cd "$TOS_SOURCE"
export PYTHONPATH="$TOS_SOURCE/test/tostester/src"
export PYTHONDONTWRITEBYTECODE=1
setsid uv run --frozen python -B "$here/service-relay-multi-host-e2e.py" > "$work/run.log" 2>&1 &
pg=$!
echo "$pg" > "$work/run.pgid"
"$THERMAL_GUARD" "$pg" > "$work/guard.log" 2>&1 &
set +e
wait "$pg"
status=$?
set -e
pg=
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
