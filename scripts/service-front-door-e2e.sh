#!/bin/bash
# Run scripts/service-front-door-e2e.py: a complete paid software-work sale
# between two OpenFox rail nodes on an isolated local network, driven only by
# `openfox earning service` commands (wallet funding and infrastructure boot
# excepted), in its own process group under a thermal guard.
#
# The network boot, faucet funding, RPC polling and secret scan follow the
# Service Actor buyer acceptance run (service-actor-buyer-e2e.sh).
#
# Required environment:
#   TOS_SOURCE        tos checkout providing test/tostester (run with its uv env)
#   TOS_BUILD         tos build directory with the PQ genesis tools
#   TOSCTL            tosctl release binary both nodes pin
#   E2E_WORKDIR       owner-private evidence directory (must not exist yet)
#   REGISTRY_CODE_BOC Native Registry code BOC (base64) that tosctl embeds
#   ACTOR_CODE_HASH   tvm-cell-sha256:<hex> of the pinned Service Actor release
#   E2E_EXECUTOR      the provider's software-work-execute binary
#   THERMAL_GUARD     script taking a process-group id to pause on heat
# Optional: E2E_BASE_PORT (tostester ports), E2E_RPC_PORTS (three JSON-RPC
#   ports), E2E_CONTAINERD_SOCKET (the private container runtime socket),
#   E2E_ROOT_BASE (default /var/lib/openfox-front-door-e2e; every ancestor
#   must be root-owned): both nodes' root-owned state is staged under
#   <E2E_ROOT_BASE>/<workdir name>, which must not exist yet, and
#   E2E_HOLD=1 (keep the network up after the run until <workdir>/release
#   exists, for inspection).
#
# Root: the executor only accepts a container runtime socket its own user
# owns, and OpenFox runs the executor as its own child, so the provider node
# runs as root (`sudo -n`). The direct transport joins nodes of one user, so
# the buyer node does too. The script lists every root command in its
# evidence. Nothing here changes a permission of the socket or the executor.
set -euo pipefail
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(dirname "$here")
: "${TOS_SOURCE:?}" "${TOS_BUILD:?}" "${TOSCTL:?}" "${E2E_WORKDIR:?}" "${REGISTRY_CODE_BOC:?}" "${ACTOR_CODE_HASH:?}"
: "${E2E_EXECUTOR:?}" "${THERMAL_GUARD:?}"
export E2E_BASE_PORT=${E2E_BASE_PORT:-49800}
export E2E_RPC_PORTS=${E2E_RPC_PORTS:-49880,49881,49882}
for port in $(seq "$E2E_BASE_PORT" $((E2E_BASE_PORT + 79))) ${E2E_RPC_PORTS//,/ }; do
  if ss -ltn "( sport = :$port )" | grep -q LISTEN; then
    echo "port $port is in use; choose another E2E_BASE_PORT/E2E_RPC_PORTS" >&2
    exit 2
  fi
done
if [ -e "$E2E_WORKDIR" ]; then
  echo "$E2E_WORKDIR already exists; every run takes a fresh work directory" >&2
  exit 2
fi
mkdir -p "$E2E_WORKDIR" && chmod 700 "$E2E_WORKDIR"
export E2E_BIN="$E2E_WORKDIR/bin"
mkdir -p "$E2E_BIN"
(cd "$repo" && GOWORK=off GOFLAGS=-trimpath CGO_ENABLED=0 go build -tags goolm,stdjson -o "$E2E_BIN/openfox" ./cmd/openfox)
export E2E_REPO="$repo"
cd "$TOS_SOURCE"
export PYTHONPATH="$TOS_SOURCE/test/tostester/src"
setsid uv run --frozen python "$here/service-front-door-e2e.py" > "$E2E_WORKDIR/run.log" 2>&1 &
pg=$!
echo "$pg" > "$E2E_WORKDIR/run.pgid"
"$THERMAL_GUARD" "$pg" > "$E2E_WORKDIR/guard.log" 2>&1 &
set +e
wait "$pg"
status=$?
set -e
# After the run has exited, no artifact may hold a vault master key or any
# master_key value. Only file names are printed, never the value.
leaks=0
while IFS= read -r -d '' artifact; do
  if { [ -s "$E2E_WORKDIR/private/scan-secrets" ] && grep -qF -f "$E2E_WORKDIR/private/scan-secrets" "$artifact"; } ||
     grep -qE 'master_key=[0-9A-Fa-f]{8,}' "$artifact"; then
    echo "secret found in $artifact" >&2
    leaks=1
  fi
done < <(find "$E2E_WORKDIR" -path "$E2E_WORKDIR/private" -prune -o -path "$E2E_WORKDIR/network" -prune -o \
  -path "$E2E_WORKDIR/bin" -prune -o -type f -print0)
tail -n 2 "$E2E_WORKDIR/run.log"
if [ "$status" = 0 ] && [ "$leaks" = 0 ]; then
  echo "ALL PASS"
  exit 0
fi
echo "FAIL"
exit 1
