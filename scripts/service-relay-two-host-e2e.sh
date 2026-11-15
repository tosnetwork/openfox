#!/bin/bash
# Run scripts/service-relay-two-host-e2e.py: a paid sale between two OpenFox
# nodes in separate network namespaces with no path to each other, carried
# only by a tos-service-packet-relay daemon in a third namespace, with two
# live relay outages, in its own process group under a thermal guard.
#
# Required environment (the first eight as for service-front-door-e2e.sh):
#   TOS_SOURCE, TOS_BUILD, TOSCTL, E2E_WORKDIR (must not exist yet, outside
#   the home directory), REGISTRY_CODE_BOC, ACTOR_CODE_HASH, THERMAL_GUARD,
#   E2E_EXECUTOR_SOCKET (the root-run executor service; the invoking user
#   must be in its socket's group in the group database)
#   E2E_RELAY_SOURCE  a clean ai checkout; the relay daemon is built from it
# Optional: E2E_BASE_PORT, E2E_RPC_PORTS as for the front-door run.
#
# Root: `sudo -n` creates and removes the namespaces, the bridge and the
# firewall rules (service-relay-two-host-net.sh) and enters a namespace to
# start each node, relay, forwarder and probe process, which then runs as
# the invoking user (setpriv). The evidence lists every such command. The
# namespaces are removed on exit, also after a failure or an interrupt.
#
# Host requirements: iproute2, nftables, setpriv, openssl, /usr/bin/python3,
# and no namespace named tosrly-* (a leftover is removed with
# `service-relay-two-host-net.sh down <any work directory>`).
set -euo pipefail
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(dirname "$here")
: "${TOS_SOURCE:?}" "${TOS_BUILD:?}" "${TOSCTL:?}" "${E2E_WORKDIR:?}" "${REGISTRY_CODE_BOC:?}" "${ACTOR_CODE_HASH:?}"
: "${THERMAL_GUARD:?}" "${E2E_EXECUTOR_SOCKET:?}" "${E2E_RELAY_SOURCE:?}"
export E2E_BASE_PORT=${E2E_BASE_PORT:-49800}
export E2E_RPC_PORTS=${E2E_RPC_PORTS:-49880,49881,49882}
for port in $(seq "$E2E_BASE_PORT" $((E2E_BASE_PORT + 79))) ${E2E_RPC_PORTS//,/ }; do
  if ss -ltn "( sport = :$port )" | grep -q LISTEN; then
    echo "port $port is in use; choose another E2E_BASE_PORT/E2E_RPC_PORTS" >&2
    exit 2
  fi
done
if ip netns list | grep -q '^tosrly-'; then
  echo "a tosrly-* namespace exists: another run is active, or remove the leftover with service-relay-two-host-net.sh down" >&2
  exit 2
fi
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
mkdir -p "$E2E_BIN" "$work/private" "$work/relay/state" "$work/tls/empty-certs"
chmod 700 "$work/private" "$work/relay" "$work/relay/state"
(cd "$repo" && GOWORK=off GOFLAGS=-trimpath CGO_ENABLED=0 go build -tags goolm,stdjson -o "$E2E_BIN/openfox" ./cmd/openfox)
(cd "$E2E_RELAY_SOURCE" && GOWORK=off GOFLAGS=-trimpath CGO_ENABLED=0 go build -o "$E2E_BIN/tos-service-packet-relay" ./protocol/cmd/tos-service-packet-relay)

# A certificate authority for this run only, the relay's certificate for its
# namespace address, and an unrelated authority for the negative control.
tls=$work/tls
key_dir=$work/private/tls
mkdir -m 700 "$key_dir"
ca() {
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$key_dir/$1-key.pem" \
    -out "$tls/$1.pem" -days 2 -subj "/CN=$2" -addext basicConstraints=critical,CA:TRUE \
    -addext keyUsage=critical,keyCertSign,cRLSign 2> /dev/null
}
ca ca "relay acceptance run CA"
ca unrelated-ca "unrelated CA"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$work/relay/tls-key.pem" \
  -out "$key_dir/relay.csr" -subj "/CN=10.231.77.20" 2> /dev/null
printf 'subjectAltName=IP:10.231.77.20\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' > "$key_dir/relay.ext"
openssl x509 -req -in "$key_dir/relay.csr" -CA "$tls/ca.pem" -CAkey "$key_dir/ca-key.pem" \
  -set_serial "0x$(openssl rand -hex 16)" -days 2 -extfile "$key_dir/relay.ext" -out "$tls/relay-cert.pem" 2> /dev/null
chmod 600 "$work/relay/tls-key.pem"

teardown() {
  bash "$here/service-relay-two-host-net.sh" down "$work" || echo "teardown failed; run it again" >&2
}
trap teardown EXIT
trap 'exit 130' INT TERM
bash "$here/service-relay-two-host-net.sh" up "$work"

export E2E_REPO="$repo" E2E_RELAY_URL=https://10.231.77.20:8443 E2E_ROOT_BASE="$work/nodes"
cd "$TOS_SOURCE"
export PYTHONPATH="$TOS_SOURCE/test/tostester/src"
export PYTHONDONTWRITEBYTECODE=1
setsid uv run --frozen python -B "$here/service-relay-two-host-e2e.py" > "$work/run.log" 2>&1 &
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
