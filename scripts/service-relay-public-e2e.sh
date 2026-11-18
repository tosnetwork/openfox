#!/bin/bash
# Run scripts/service-relay-public-e2e.py against a public TOS test network:
#
#   service-relay-public-e2e.sh prepare   create the wallets offline and print
#                                         their addresses and the live fees
#   service-relay-public-e2e.sh run       the sales, once the operator has
#                                         funded every wallet
#
# Both commands take the same work directory: `prepare` creates it, `run`
# continues in it. This host runs the provider node, the gateway and its
# protocol RPC; the buyer node runs on another host over SSH. The chain's
# JSON-RPC is reached through SSH forwards this script opens to three
# validators' loopback listeners; it changes nothing on those hosts. The
# installed relays are only reached over HTTPS: this script never logs in to
# a relay host and never stops or starts a relay.
#
# Required environment:
#   TOS_SOURCE        clean tos checkout at the network's commit (pytosiq_core)
#   TOSCTL            tosctl built from TOS_SOURCE
#   E2E_WORKDIR       work directory outside the home directory
#   REGISTRY_CODE_BOC Native Registry release code BOC (base64)
#   ACTOR_CODE_HASH   pinned Service Actor release code hash
#   E2E_REGISTRY_CODE_HASH  tvm-cell-sha256:<hex> of the registry release
#   E2E_GLOBAL_CONFIG the network's published global configuration
#   E2E_GENESIS_ROOT_HASH, E2E_GENESIS_FILE_HASH  sha256:<hex> genesis hashes
#   E2E_NETWORK_LABEL tos:global-id:<n>
#   E2E_VALIDATOR_SSHS      root@host of three validators (JSON-RPC on 127.0.0.1:8081)
#   E2E_VALIDATOR_SSH_KEYS  SSH identity file for each of them (same order)
#   E2E_RPC_PORTS     three local ports for the forwards, comma-separated
#   E2E_EXECUTOR_SOCKET  socket of the root-run executor service
#   E2E_GATEWAY_API, E2E_SERVICE_RPC  gateway/cmd/api and protocol tos-service-rpc
#   E2E_FUNDING_TOS   "provider=<TOS> buyer=<TOS> sweeper=<TOS>"
#   BUYER_SSH, BUYER_SSH_KEY  user@host of the buyer host and its identity file
#   RELAY_URLS        https://<relay>:<port> of each installed relay
#   RELAY_CA_FILE     PEM of the CA the relays' certificates chain to
#   THERMAL_GUARD     guard script, given the run's process group (run only)
# Optional:
#   BUYER_REMOTE_BASE parent of the buyer's run directory (default /opt/tos-gated-rehearsal)
#   E2E_GATEWAY_PORT  the gateway TLS port here and on the buyer host (default 18890;
#                     the next two ports are its HTTP backend and protocol RPC)
set -euo pipefail
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(dirname "$here")
command=${1:-}
case "$command" in
  prepare|run) ;;
  *) echo "usage: $0 prepare|run" >&2; exit 2 ;;
esac
: "${TOS_SOURCE:?}" "${TOSCTL:?}" "${E2E_WORKDIR:?}" "${REGISTRY_CODE_BOC:?}" "${ACTOR_CODE_HASH:?}"
: "${E2E_REGISTRY_CODE_HASH:?}" "${E2E_GLOBAL_CONFIG:?}" "${E2E_GENESIS_ROOT_HASH:?}" "${E2E_GENESIS_FILE_HASH:?}"
: "${E2E_NETWORK_LABEL:?}" "${E2E_VALIDATOR_SSHS:?}" "${E2E_VALIDATOR_SSH_KEYS:?}" "${E2E_RPC_PORTS:?}"
: "${E2E_EXECUTOR_SOCKET:?}" "${E2E_GATEWAY_API:?}" "${E2E_SERVICE_RPC:?}" "${E2E_FUNDING_TOS:?}"
: "${BUYER_SSH:?}" "${BUYER_SSH_KEY:?}" "${RELAY_URLS:?}" "${RELAY_CA_FILE:?}"
export BUYER_REMOTE_BASE=${BUYER_REMOTE_BASE:-/opt/tos-gated-rehearsal}
read -r -a validators <<< "$E2E_VALIDATOR_SSHS"
read -r -a validator_keys <<< "$E2E_VALIDATOR_SSH_KEYS"
IFS=, read -r -a ports <<< "$E2E_RPC_PORTS"
if [ "${#validators[@]}" != 3 ] || [ "${#validator_keys[@]}" != 3 ] || [ "${#ports[@]}" != 3 ]; then
  echo "name exactly three validators, three identity files and three local ports" >&2
  exit 2
fi
for url in $RELAY_URLS; do
  case "$url" in https://*) ;; *) echo "every relay URL must be https" >&2; exit 2 ;; esac
done
case "$E2E_WORKDIR" in
  "$HOME"|"$HOME"/*) echo "choose a work directory outside the home directory" >&2; exit 2 ;;
esac
if [ "$command" = prepare ]; then
  if [ -e "$E2E_WORKDIR" ]; then
    echo "$E2E_WORKDIR already exists; prepare takes a fresh work directory" >&2
    exit 2
  fi
  mkdir -p "$E2E_WORKDIR" && chmod 700 "$E2E_WORKDIR"
else
  [ -f "$E2E_WORKDIR/funding-plan.json" ] || { echo "run prepare first" >&2; exit 2; }
  : "${THERMAL_GUARD:?}"
  # A rerun keeps every earlier attempt's evidence and log beside it; the
  # attempt markers make sure no value step of it is sent again.
  if [ -e "$E2E_WORKDIR/evidence.json" ]; then
    n=1
    while [ -e "$E2E_WORKDIR/evidence-attempt-$n.json" ]; do n=$((n + 1)); done
    mv "$E2E_WORKDIR/evidence.json" "$E2E_WORKDIR/evidence-attempt-$n.json"
    [ -e "$E2E_WORKDIR/run.log" ] && mv "$E2E_WORKDIR/run.log" "$E2E_WORKDIR/run-attempt-$n.log"
  fi
fi
for port in "${ports[@]}" "${E2E_GATEWAY_PORT:-18890}" $(( ${E2E_GATEWAY_PORT:-18890} + 1 )) \
    $(( ${E2E_GATEWAY_PORT:-18890} + 2 )); do
  if ss -ltn "( sport = :$port )" | grep -q LISTEN; then
    echo "port $port is in use" >&2
    exit 2
  fi
done
work=$(CDPATH= cd -- "$E2E_WORKDIR" && pwd)
export E2E_WORKDIR=$work
export E2E_BIN="$work/bin"
mkdir -p "$E2E_BIN" "$work/private"
chmod 700 "$work/private"
if [ "$command" = run ]; then
  [ -z "$(git -C "$repo" status --porcelain)" ] || echo "warning: the OpenFox tree is not clean" >&2
  (cd "$repo" && GOWORK=off GOFLAGS=-trimpath CGO_ENABLED=0 go build -tags goolm,stdjson -o "$E2E_BIN/openfox" ./cmd/openfox)
fi

pids=()
teardown() {
  if [ -n "${pg:-}" ]; then
    kill -TERM -- "-$pg" 2> /dev/null || true
    for _ in $(seq 30); do kill -0 -- "-$pg" 2> /dev/null || break; sleep 1; done
    kill -KILL -- "-$pg" 2> /dev/null || true
  fi
  for pid in "${pids[@]}"; do kill -TERM "$pid" 2> /dev/null || true; done
  if [ "$command" = run ]; then
    ssh -o BatchMode=yes -o ConnectTimeout=20 -i "$BUYER_SSH_KEY" "$BUYER_SSH" -- \
      "for f in $BUYER_REMOTE_BASE/$(basename "$work")/serve-*.pid; do [ -e \"\$f\" ] && kill -TERM \"\$(cat \"\$f\")\" 2> /dev/null; done; true" \
      > /dev/null 2>&1 || echo "could not reach the buyer host to stop its node" >&2
    echo "left for inspection: buyer host $BUYER_REMOTE_BASE/$(basename "$work")"
  fi
}
trap teardown EXIT
trap 'exit 130' INT TERM

# Forwards to the validators' loopback JSON-RPC; nothing runs on those hosts.
for index in 0 1 2; do
  ssh -N -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=8 \
    -o ConnectTimeout=20 -i "${validator_keys[$index]}" \
    -L "127.0.0.1:${ports[$index]}:127.0.0.1:8081" "${validators[$index]}" > "$work/forward-$index.log" 2>&1 &
  pids+=("$!")
done
for _ in $(seq 30); do
  up=0
  for port in "${ports[@]}"; do
    curl -s -m 5 -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getMasterchainInfo","params":{}}' \
      "http://127.0.0.1:$port/jsonRPC" | grep -q '"result"' && up=$((up + 1))
  done
  [ "$up" = 3 ] && break
  sleep 2
done
[ "$up" = 3 ] || { echo "the validator forwards do not answer" >&2; exit 1; }

export E2E_REPO="$repo" E2E_RELAY_CA_FILE="$RELAY_CA_FILE" E2E_RELAY_URLS="$RELAY_URLS" E2E_ROOT_BASE="$work/nodes"
export RELAY_EXTERNAL=1 RELAY_OBSERVE_ONLY=1 TOS_BUILD="$TOS_SOURCE" E2E_BASE_PORT=0
export E2E_GATEWAY_PORT=${E2E_GATEWAY_PORT:-18890}
cd "$TOS_SOURCE"
export PYTHONPATH="$TOS_SOURCE/test/tostester/src"
export PYTHONDONTWRITEBYTECODE=1
if [ "$command" = prepare ]; then
  uv run --frozen python -B "$here/service-relay-public-e2e.py" prepare
  exit $?
fi
setsid uv run --frozen python -B "$here/service-relay-public-e2e.py" run > "$work/run.log" 2>&1 &
pg=$!
echo "$pg" > "$work/run.pgid"
"$THERMAL_GUARD" "$pg" > "$work/guard.log" 2>&1 &
set +e
wait "$pg"
status=$?
set -e
pg=
# No artifact may hold a vault master key or a gateway token; only file names are printed.
leaks=0
while IFS= read -r -d '' artifact; do
  if { [ -s "$work/private/scan-secrets" ] && grep -qF -f "$work/private/scan-secrets" "$artifact"; } ||
     grep -qE 'master_key=[0-9A-Fa-f]{8,}' "$artifact"; then
    echo "secret found in $artifact" >&2
    leaks=1
  fi
done < <(find "$work" -path "$work/private" -prune -o -path "$work/bin" -prune -o -path "$work/nodes" -prune -o \
  -type f -print0)
tail -n 2 "$work/run.log"
if [ "$status" = 0 ] && [ "$leaks" = 0 ]; then
  echo "ALL PASS"
  exit 0
fi
echo "FAIL"
exit 1
