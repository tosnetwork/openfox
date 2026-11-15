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
# The relay host's firewall rule for the relay port, its user and its
# directories are prepared by the operator beforehand; this script only
# starts and stops the relay unit. Remote run directories are left in place
# for inspection and listed in the evidence.
set -euo pipefail
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(dirname "$here")
: "${TOS_SOURCE:?}" "${TOS_BUILD:?}" "${TOSCTL:?}" "${E2E_WORKDIR:?}" "${REGISTRY_CODE_BOC:?}" "${ACTOR_CODE_HASH:?}"
: "${THERMAL_GUARD:?}" "${E2E_EXECUTOR_SOCKET:?}" "${E2E_RELAY_SOURCE:?}"
: "${BUYER_SSH:?}" "${BUYER_SSH_KEY:?}" "${RELAY_SSH:?}" "${RELAY_SSH_KEY:?}" "${RELAY_URL:?}" "${RELAY_CA_FILE:?}"
: "${RELAY_RUN_USER:?}"
export BUYER_REMOTE_BASE=${BUYER_REMOTE_BASE:-/opt/tos-relay-test}
export RELAY_REMOTE_DIR=${RELAY_REMOTE_DIR:-/opt/tos-relay-test}
export RELAY_UNIT=${RELAY_UNIT:-tos-relay-test}
export E2E_BASE_PORT=${E2E_BASE_PORT:-49800}
export E2E_RPC_PORTS=${E2E_RPC_PORTS:-49880,49881,49882}
case "$RELAY_URL" in
  https://*) ;;
  *) echo "RELAY_URL must be https" >&2; exit 2 ;;
esac
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
  ssh "${ssh_opts[@]}" -i "$RELAY_SSH_KEY" "$RELAY_SSH" -- "systemctl stop $RELAY_UNIT 2> /dev/null; true" \
    > /dev/null 2>&1 || echo "could not reach the relay host to stop the relay" >&2
  echo "left for inspection: buyer host $BUYER_REMOTE_BASE/$run_name, relay host $RELAY_REMOTE_DIR/runs/$run_name"
}
trap teardown EXIT
trap 'exit 130' INT TERM

export E2E_REPO="$repo" E2E_RELAY_URL="$RELAY_URL" E2E_RELAY_CA_FILE="$RELAY_CA_FILE" E2E_ROOT_BASE="$work/nodes"
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
