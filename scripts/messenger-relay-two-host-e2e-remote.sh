#!/bin/bash
# Phase 2 of the Messenger relay carriage M-R1 live acceptance: the same
# one-to-one chat as scripts/messenger-relay-two-host-e2e.sh, but across
# machines. Node A and a stranger node C run in network namespaces on this
# host and reach the relays through its uplink (NAT); node B runs on another
# host over SSH; the two relays are installed systemd units on their own
# hosts; the chain runs here and reaches B only through an SSH reverse tunnel
# to B's loopback.
#
# This wrapper builds the binaries and runs
# scripts/messenger-relay-two-host-e2e-remote.py. The relay daemons are not
# started or installed here: the run stops and starts relay 1's unit for its
# outage and leaves every unit running. Whatever happens, the exit trap
# removes this host's namespaces and forwarding rules, B's firewall table and
# scratch directory, and restarts only the relay units this run stopped (a
# marker file).
#
# Node B runs as root on B's host: the SSH login there is root, and B's
# processes (signer, tos-messengerd, `openfox earning service serve`) run as
# that user, confined to one 0700 scratch directory (HOME and TMPDIR point
# inside it). A and C run unprivileged here, as the invoking user.
#
# Required environment (the local ones as for messenger-relay-two-host-e2e.sh):
#   TOS_SOURCE, TOS_BUILD, TOSCTL, E2E_WORKDIR (must not exist, outside the
#   home directory), REGISTRY_CODE_BOC, ACTOR_CODE_HASH, THERMAL_GUARD,
#   E2E_AI_SOURCE (a clean ai checkout)
#   B_SSH, B_SSH_KEY        user@host of B's host and its SSH identity
#   RELAY_URLS             https URL of each relay, two words, IPv4 hosts
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
#   B_REMOTE_BASE          the scratch base (default /opt/tos-relay-test). The
#                          node files live at the same path on both hosts,
#                          <base>/<run name>/<run name>; B's copy is removed
#                          afterwards and this host's is moved into the work
#                          directory
#   MR1_REDEPOSIT_SECONDS, MR1_DESCRIPTOR_LIFETIME as for phase 1
#   MR1_DRYRUN=1           exercise only the non-destructive remote primitives
#                          (host facts, unit/binary/CA pinning, a metrics
#                          scrape, B's probes) and stop; no relay is stopped,
#                          no chat is sent and nothing is written to B
set -euo pipefail
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(dirname "$here")
: "${TOS_SOURCE:?}" "${TOS_BUILD:?}" "${TOSCTL:?}" "${E2E_WORKDIR:?}" "${REGISTRY_CODE_BOC:?}" "${ACTOR_CODE_HASH:?}"
: "${THERMAL_GUARD:?}" "${E2E_AI_SOURCE:?}"
: "${B_SSH:?}" "${B_SSH_KEY:?}" "${RELAY_URLS:?}" "${RELAY_SSHS:?}" "${RELAY_SSH_KEYS:?}" "${RELAY_CA_FILE:?}"
export E2E_BASE_PORT=${E2E_BASE_PORT:-49800}
export E2E_RPC_PORTS=${E2E_RPC_PORTS:-49880,49881,49882}
export B_REMOTE_BASE=${B_REMOTE_BASE:-/opt/tos-relay-test}
# Every name that reaches a remote command line is checked first: only
# letters, digits and / . _ -, and no "..". Remote strings still quote them.
plain_path() {
  [[ $1 =~ ^[A-Za-z0-9/._-]+$ ]] && [[ $1 != *..* ]]
}
if ! plain_path "$B_REMOTE_BASE"; then
  echo "B_REMOTE_BASE may hold only letters, digits and / . _ - (no ..)" >&2
  exit 2
fi
case "$B_REMOTE_BASE" in
  /opt/tos-relay-test|/opt/tos-relay-test/?*) ;;
  *) echo "B_REMOTE_BASE must be /opt/tos-relay-test or below it" >&2; exit 2 ;;
esac
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
if [ "${#relay_units[@]}" != 2 ]; then
  echo "RELAY_UNITS must name exactly two units" >&2
  exit 2
fi
for unit in "${relay_units[@]}"; do
  if ! plain_path "$unit" || [[ $unit == */* ]]; then
    echo "a relay unit name may hold only letters, digits and . _ - (no ..)" >&2
    exit 2
  fi
done
relay_addresses=()
for url in "${relay_urls[@]}"; do
  if ! [[ $url =~ ^https://([0-9]{1,3}(\.[0-9]{1,3}){3}):([0-9]{1,5})$ ]]; then
    echo "every relay URL must be https://<IPv4>:<port>" >&2
    exit 2
  fi
  relay_addresses+=("${BASH_REMATCH[1]}")
  export MR1_RELAY_PORT=${BASH_REMATCH[3]}
done
export MR1_RELAY_ADDRESSES="${relay_addresses[*]}"
for port in $(seq "$E2E_BASE_PORT" $((E2E_BASE_PORT + 79))) ${E2E_RPC_PORTS//,/ }; do
  if ss -ltn "( sport = :$port )" | grep -q LISTEN; then
    echo "port $port is in use; choose another E2E_BASE_PORT/E2E_RPC_PORTS" >&2
    exit 2
  fi
done
if ip netns list | grep -q '^tosmr-'; then
  echo "a tosmr-* namespace exists: another run is active, or remove the leftover with the net script's down" >&2
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
run_name=$(basename "$work")
if ! [[ $run_name =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || [[ $run_name == *..* ]]; then
  echo "the work directory name must be a plain word (letters, digits, . _ -, no ..)" >&2
  exit 2
fi
export E2E_WORKDIR=$work
export E2E_BIN="$work/bin"
mkdir -p "$E2E_BIN" "$work/private" "$work/tls" "$work/net"
chmod 700 "$work/private"
changes="$work/host-changes.log"
change() {
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$changes"
}
(cd "$repo" && GOWORK=off GOFLAGS=-trimpath CGO_ENABLED=0 go build -tags goolm,stdjson -o "$E2E_BIN/openfox" ./cmd/openfox)
(cd "$repo" && GOWORK=off GOFLAGS=-trimpath CGO_ENABLED=0 go build -o "$E2E_BIN/messenger-relay-e2e-tool" \
  ./scripts/messenger-relay-e2e-tool)
(cd "$E2E_AI_SOURCE" && GOWORK=off GOFLAGS=-trimpath CGO_ENABLED=0 go build -o "$E2E_BIN/" \
  ./messenger/cmd/tos-messengerd ./messenger/cmd/tos-messenger-owner ./protocol/cmd/tos-service-packet-relay)

# The pinned relay CA, and an unrelated CA for the TLS negative control (its
# key stays in the private directory).
cp "$RELAY_CA_FILE" "$work/tls/ca.pem"
mkdir -m 700 "$work/private/tls"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$work/private/tls/unrelated-ca-key.pem" \
  -out "$work/tls/unrelated-ca.pem" -days 2 -subj "/CN=unrelated CA" -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign,cRLSign 2> /dev/null

ssh_opts=(-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=20)
b_run="$B_REMOTE_BASE/$run_name"
b_table="tosmr_${run_name//[^A-Za-z0-9_]/_}"
netsh="$here/messenger-relay-two-host-e2e-remote-net.sh"

# The node files live at the same absolute path on this host and on B.
local_base_created=0
if [ ! -d "$B_REMOTE_BASE" ]; then
  sudo -n install -d -o "$(id -u)" -g "$(id -g)" -m 0700 "$B_REMOTE_BASE"
  local_base_created=1
  change "this host: created $B_REMOTE_BASE (owner the invoking user, 0700); reversal: rmdir at exit"
fi
[ -w "$B_REMOTE_BASE" ] || { echo "$B_REMOTE_BASE is not writable" >&2; exit 2; }
if [ -e "$b_run" ]; then
  echo "$b_run already exists on this host" >&2
  exit 2
fi

teardown() {
  set +e
  if [ "${MR1_DRYRUN:-}" != 1 ]; then
    bash "$netsh" down "$work" 2> /dev/null || echo "namespace teardown failed; run it again" >&2
  fi
  if [ -f "$work/net/iptables-before.txt" ] && [ -f "$work/net/iptables-after.txt" ]; then
    if cmp -s "$work/net/iptables-before.txt" "$work/net/iptables-after.txt"; then
      change "this host: forwarding rules removed; iptables-save identical to before"
    else
      change "this host: iptables-save DIFFERS from before; inspect $work/net"
      echo "this host's iptables rules differ from before the run; see $work/net" >&2
    fi
  fi
  # B: stop what is left of the run, remove its firewall table and scratch
  # directory (only below the scratch base, never anything else).
  # The script is fixed text on standard input; the run's names reach it
  # only as quoted arguments. A recorded PID is killed only while its
  # command line still names the run's directory, so a PID the system has
  # since reused for another process is left alone.
  ssh "${ssh_opts[@]}" -i "$B_SSH_KEY" "$B_SSH" -- \
    bash -s -- "$(printf '%q' "$b_run")" "$(printf '%q' "$b_table")" "$(printf '%q' "$B_REMOTE_BASE")" \
    > "$work/net/b-teardown.txt" 2>&1 <<'EOF' ||
run=$1 table=$2 base=$3
for f in "$run"/*.pid; do
  [ -e "$f" ] || continue
  pid=$(cat "$f")
  case $pid in '' | *[!0-9]*) echo "pid-file-not-a-pid $(basename "$f")"; continue ;; esac
  if [ -r "/proc/$pid/cmdline" ] && tr '\0' ' ' < "/proc/$pid/cmdline" | grep -qF -- "$run/"; then
    kill -KILL "$pid" 2> /dev/null && echo "killed $pid $(basename "$f" .pid)"
  else
    echo "left $pid $(basename "$f" .pid): not running, or no longer the run's process"
  fi
done
if nft list table inet "$table" > /dev/null 2>&1; then nft delete table inet "$table" && echo table-removed; fi
case $run in
  "$base"/?*) if [ -d "$run" ]; then find "$run" -depth -delete && echo scratch-removed; fi ;;
esac
test ! -e "$run"
EOF
    echo "could not clean B's scratch directory or firewall table; check by hand" >&2
  while read -r _ pid key; do
    change "B host: killed leftover process $pid ($key) of the run (exit trap)"
  done < <(grep '^killed ' "$work/net/b-teardown.txt" || true)
  grep -q table-removed "$work/net/b-teardown.txt" && change "B host: removed nft table inet $b_table (exit trap)"
  grep -q scratch-removed "$work/net/b-teardown.txt" && change "B host: removed $b_run (exit trap)"
  # Restart only the relay units this run stopped, named in the marker file.
  if [ -s "$work/stopped-units" ]; then
    while read -r index; do
      [[ $index =~ ^[01]$ ]] || continue
      if ssh "${ssh_opts[@]}" -i "${relay_keys[$index]}" "${relay_sshs[$index]}" -- \
        systemctl start -- "$(printf '%q' "${relay_units[$index]}")" > /dev/null 2>&1; then
        change "relay $((index + 1)) host: started ${relay_units[$index]} (exit trap; this run had stopped it)"
      else
        echo "could not restart relay $((index + 1))'s unit; restart ${relay_units[$index]} by hand" >&2
      fi
    done < "$work/stopped-units"
  fi
  # This host's copy of the node files is kept, inside the work directory.
  if [ -d "$b_run" ]; then
    mv "$b_run" "$work/nodes" && change "this host: moved $b_run into the work directory"
  fi
  if [ "$local_base_created" = 1 ]; then
    sudo -n rmdir "$B_REMOTE_BASE" && change "this host: removed $B_REMOTE_BASE"
  fi
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
if [ "${MR1_DRYRUN:-}" != 1 ]; then
  bash "$netsh" up "$work"
  change "this host: namespaces tosmr-a, tosmr-c, bridge tosmr-br0 and the tagged forwarding rules added; reversal: net script down"
fi

export E2E_EXECUTOR_SOCKET=unused-no-sale
export E2E_REPO="$repo" E2E_ROOT_BASE="$b_run" E2E_RELAY_CA_FILE="$work/tls/ca.pem"
export MR1_REMOTE=1 MR1_NETSH="$netsh" MR1_B_TABLE="$b_table"
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
pg=
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
