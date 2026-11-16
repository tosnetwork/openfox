#!/bin/bash
# Phase 2 of the Messenger relay carriage M-R1 live acceptance: the same
# one-to-one chat as scripts/messenger-relay-two-host-e2e.sh, but across
# machines. Node A and a stranger node C run in network namespaces on this
# host; node B runs on another host over SSH; the two relays are installed
# systemd units on their own hosts; the chain runs here and reaches B only
# through an SSH reverse tunnel to B's loopback.
#
# This wrapper builds the binaries and runs
# scripts/messenger-relay-two-host-e2e-remote.py. The relay daemons are not
# started or installed here: the run stops and starts the named units for its
# outage and leaves every unit running, and a trap restarts only the units it
# stopped.
#
# Required environment (the local ones as for messenger-relay-two-host-e2e.sh):
#   TOS_SOURCE, TOS_BUILD, TOSCTL, E2E_WORKDIR (must not exist, outside the
#   home directory), REGISTRY_CODE_BOC, ACTOR_CODE_HASH, THERMAL_GUARD,
#   E2E_AI_SOURCE (a clean ai checkout)
#   B_SSH, B_SSH_KEY        user@host of B's host and its SSH identity
#   RELAY_URLS             https URL of each relay, two words
#   RELAY_SSHS             root@host of each relay host, two words
#   RELAY_SSH_KEYS         SSH identity file for each of RELAY_SSHS, two words
#   RELAY_CA_FILE          PEM of the CA both nodes pin
# Optional:
#   RELAY_UNITS            each relay's unit (default tos-service-packet-relay)
#   RELAY_STATE_DIR        the relay state directory on the hosts
#                          (default /var/lib/private/tos-service-packet-relay)
#   RELAY_BIN              the relay binary on the hosts
#                          (default /usr/local/bin/tos-service-packet-relay)
#   RELAY_METRICS          host:port of each relay's metrics (default
#                          127.0.0.1:9095, scraped on the relay host)
#   B_REMOTE_BASE          parent of B's scratch directory (default
#                          /opt/tos-relay-test); the run uses <base>/<run name>
#                          and removes it afterwards
#   MR1_REDEPOSIT_SECONDS, MR1_DESCRIPTOR_LIFETIME as for phase 1
#   MR1_DRYRUN=1           exercise only the non-destructive remote primitives
#                          (host facts, unit/binary/CA pinning, a metrics
#                          scrape, the tunnel, B's probes) and stop; no relay
#                          is stopped and no chat is sent
set -euo pipefail
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(dirname "$here")
: "${TOS_SOURCE:?}" "${TOS_BUILD:?}" "${TOSCTL:?}" "${E2E_WORKDIR:?}" "${REGISTRY_CODE_BOC:?}" "${ACTOR_CODE_HASH:?}"
: "${THERMAL_GUARD:?}" "${E2E_AI_SOURCE:?}"
: "${B_SSH:?}" "${B_SSH_KEY:?}" "${RELAY_URLS:?}" "${RELAY_SSHS:?}" "${RELAY_SSH_KEYS:?}" "${RELAY_CA_FILE:?}"
export E2E_BASE_PORT=${E2E_BASE_PORT:-49800}
export E2E_RPC_PORTS=${E2E_RPC_PORTS:-49880,49881,49882}
export B_REMOTE_BASE=${B_REMOTE_BASE:-/opt/tos-relay-test}
read -r -a relay_urls <<< "$RELAY_URLS"
read -r -a relay_sshs <<< "$RELAY_SSHS"
read -r -a relay_keys <<< "$RELAY_SSH_KEYS"
if [ "${#relay_urls[@]}" != 2 ] || [ "${#relay_sshs[@]}" != 2 ] || [ "${#relay_keys[@]}" != 2 ]; then
  echo "RELAY_URLS, RELAY_SSHS and RELAY_SSH_KEYS must each name exactly two relays" >&2
  exit 2
fi
if [ -n "${RELAY_UNITS:-}" ]; then
  read -r -a relay_units <<< "$RELAY_UNITS"
else
  relay_units=(tos-service-packet-relay tos-service-packet-relay)
fi
for url in "${relay_urls[@]}"; do
  case "$url" in https://*) ;; *) echo "every relay URL must be https" >&2; exit 2 ;; esac
done
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
mkdir -p "$E2E_BIN" "$work/private"
chmod 700 "$work/private"
(cd "$repo" && GOWORK=off GOFLAGS=-trimpath CGO_ENABLED=0 go build -tags goolm,stdjson -o "$E2E_BIN/openfox" ./cmd/openfox)
(cd "$repo" && GOWORK=off GOFLAGS=-trimpath CGO_ENABLED=0 go build -o "$E2E_BIN/messenger-relay-e2e-tool" \
  ./scripts/messenger-relay-e2e-tool)
(cd "$E2E_AI_SOURCE" && GOWORK=off GOFLAGS=-trimpath CGO_ENABLED=0 go build -o "$E2E_BIN/" \
  ./messenger/cmd/tos-messengerd ./messenger/cmd/tos-messenger-owner ./protocol/cmd/tos-service-packet-relay)

cp "$RELAY_CA_FILE" "$work/relay-ca.pem"

ssh_opts=(-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=20)
run_name=$(basename "$work")
teardown() {
  bash "$here/messenger-relay-two-host-net.sh" down "$work" 2> /dev/null || echo "namespace teardown failed; run it again" >&2
  # Remove B's scratch directory.
  ssh "${ssh_opts[@]}" -i "$B_SSH_KEY" "$B_SSH" -- \
    "for f in $B_REMOTE_BASE/$run_name/*.pid; do [ -e \"\$f\" ] && kill -TERM \"\$(cat \"\$f\")\" 2> /dev/null; done; \
     rm -rf $B_REMOTE_BASE/$run_name" > /dev/null 2>&1 || echo "could not clean B's scratch directory" >&2
  # Restart only the relay units this run stopped, named in the marker file.
  if [ -f "$work/stopped-units" ]; then
    while read -r index; do
      ssh "${ssh_opts[@]}" -i "${relay_keys[$index]}" "${relay_sshs[$index]}" -- \
        "systemctl start ${relay_units[$index]} 2> /dev/null; true" > /dev/null 2>&1 ||
        echo "could not restart relay $((index + 1))'s unit; restart ${relay_units[$index]} by hand" >&2
    done < "$work/stopped-units"
  fi
  echo "left for inspection: B host $B_REMOTE_BASE/$run_name was removed; relays left running"
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
export E2E_REPO="$repo" E2E_ROOT_BASE="$work/nodes" E2E_RELAY_CA_FILE="$work/relay-ca.pem"
export MR1_REMOTE=1
cd "$TOS_SOURCE"
export PYTHONPATH="$TOS_SOURCE/test/tostester/src"
export PYTHONDONTWRITEBYTECODE=1
setsid uv run --frozen python -B "$here/messenger-relay-two-host-e2e-remote.py" > "$work/run.log" 2>&1 &
pg=$!
echo "$pg" > "$work/run.pgid"
"$THERMAL_GUARD" "$pg" > "$work/guard.log" 2>&1 &
set +e
wait "$pg"
status=$?
set -e
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
