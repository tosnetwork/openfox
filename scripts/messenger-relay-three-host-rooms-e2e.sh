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
# A, D and E run in namespaces on this host (scripts/messenger-relay-two-host-
# e2e-remote-net.sh with MR_NET_NODES="a d e"), which forwards and
# masquerades only TCP to the relays' TLS port. The relay units are neither
# started nor stopped. Whatever happens, the exit trap removes this host's
# namespaces and forwarding rules and B's and C's scratch directories (and an
# nft table of the run, which this run never creates). The record is
# <workdir>/evidence.json (messenger-relay-rooms-<date>.json once copied).
# Additionally required there:
#   B_SSH, B_SSH_KEY, C_SSH, C_SSH_KEY   user@host and SSH identity of B's and C's hosts
#   RELAY_URLS, RELAY_SSHS, RELAY_SSH_KEYS, RELAY_CA_FILE   as for the M-R1 remote run
#   E2E_RELAY_SOURCE  a clean ai checkout at the commit the deployed relays
#                     were built from; the relay binary for the identity check
#                     is built from it, every node binary from E2E_AI_SOURCE
# Optional:
#   B_REMOTE_BASE, C_REMOTE_BASE   the scratch base (default
#                     /opt/tos-relay-test, the same on both: the node files
#                     live at <base>/<run name>/<run name> on every host)
#   C_SHARES_RELAY    relay1 or relay2 when C runs on that relay's host (it
#                     then reaches it only through its public TLS URL; the
#                     record states it)
#   RELAY_UNITS, RELAY_STATE_DIR, RELAY_BIN, RELAY_METRICS   as for the M-R1
#                     remote run
# Remote-mode defaults (the test-shortened values the record states):
# MR2_RELAY_TTL=3600 (required: the test relays' -ttl 1h), MR2_ROOMTEST=1,
# MR2_ROOM_PART_BYTES=8192 (8 parts of P must hold the largest roster of the
# run, 3 entries of about 11.2 KiB; 4096 caps an object at 32,768 bytes and a
# 4-member room's roster is 33,537), MR2_HANDSHAKE_RETENTION=10800,
# MR2_AUTHORIZATION_SECONDS=600, MR1_REDEPOSIT_SECONDS=600,
# MR1_DESCRIPTOR_LIFETIME=1800.
#
# Root (remote mode): this host's namespace, forwarding and teardown commands
# as in local mode; B's and C's processes run as the SSH login (root) of their
# hosts, confined to the run's 0700 scratch directory there.
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
export MR_NET_NODES="a b c d e f"
openfox_source=${E2E_OPENFOX_SOURCE:-$repo}
export E2E_OPENFOX_SOURCE=$openfox_source
remote=${MR2_REMOTE:-0}
if [ "$remote" = 1 ]; then
  export MR2_RELAY_TTL=${MR2_RELAY_TTL:-3600}
  if [ "$MR2_RELAY_TTL" != 3600 ]; then
    echo "MR2_REMOTE=1: MR2_RELAY_TTL must be 3600, the test relays' -ttl 1h" >&2
    exit 2
  fi
  export MR2_ROOMTEST=${MR2_ROOMTEST:-1}
  if [ "$MR2_ROOMTEST" = 1 ]; then
    export MR2_ROOM_PART_BYTES=${MR2_ROOM_PART_BYTES:-8192}
    export MR2_HANDSHAKE_RETENTION=${MR2_HANDSHAKE_RETENTION:-10800}
    export MR2_AUTHORIZATION_SECONDS=${MR2_AUTHORIZATION_SECONDS:-600}
  fi
  export MR1_REDEPOSIT_SECONDS=${MR1_REDEPOSIT_SECONDS:-600}
  export MR1_DESCRIPTOR_LIFETIME=${MR1_DESCRIPTOR_LIFETIME:-1800}
  export MR_NET_NODES="a d e f"
fi
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
  : "${E2E_RELAY_SOURCE:?a clean ai checkout at the build commit of the deployed relays}"
  if [ -n "$(git -C "$E2E_RELAY_SOURCE" status --porcelain)" ]; then
    echo "$E2E_RELAY_SOURCE is not a clean checkout" >&2
    exit 2
  fi
  echo "MR2_REMOTE=1: run it only after the owner's go-ahead; see the run plan" >&2
  if [ "${MR2_REMOTE_GO:-0}" != 1 ]; then exit 2; fi
  export B_REMOTE_BASE=${B_REMOTE_BASE:-/opt/tos-relay-test}
  export C_REMOTE_BASE=${C_REMOTE_BASE:-/opt/tos-relay-test}
  # Every name that reaches a remote command line is checked first: only
  # letters, digits and / . _ -, and no "..". Remote strings still quote them.
  plain_path() {
    [[ $1 =~ ^[A-Za-z0-9/._-]+$ ]] && [[ $1 != *..* ]]
  }
  for base in "$B_REMOTE_BASE" "$C_REMOTE_BASE"; do
    if ! plain_path "$base"; then
      echo "B_REMOTE_BASE and C_REMOTE_BASE may hold only letters, digits and / . _ - (no ..)" >&2
      exit 2
    fi
    case "$base" in
      /opt/tos-relay-test|/opt/tos-relay-test/?*) ;;
      *) echo "B_REMOTE_BASE and C_REMOTE_BASE must be /opt/tos-relay-test or below it" >&2; exit 2 ;;
    esac
  done
  if [ "$B_REMOTE_BASE" != "$C_REMOTE_BASE" ]; then
    echo "B_REMOTE_BASE and C_REMOTE_BASE must be the same: the node files live at the same path on every host" >&2
    exit 2
  fi
  case "${C_SHARES_RELAY:-}" in
    ''|relay1|relay2) ;;
    *) echo "C_SHARES_RELAY must be empty, relay1 or relay2" >&2; exit 2 ;;
  esac
  if [ -n "${B_SHARES_RELAY:-}" ]; then
    echo "B_SHARES_RELAY is not supported: B runs on a host of its own" >&2
    exit 2
  fi
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
run_name=$(basename "$work")
if [ "$remote" = 1 ] && { ! [[ $run_name =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || [[ $run_name == *..* ]]; }; then
  echo "the work directory name must be a plain word (letters, digits, . _ -, no ..)" >&2
  exit 2
fi
export E2E_WORKDIR=$work
export E2E_BIN="$work/bin"
mkdir -p "$E2E_BIN" "$work/private" "$work/tls/empty-certs" "$work/net"
chmod 700 "$work/private"
changes="$work/host-changes.log"
change() {
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$changes"
}
tags=()
[ "$roomtest" = 1 ] && tags=(-tags roomtest)
(cd "$openfox_source" && GOWORK=off GOFLAGS=-trimpath CGO_ENABLED=0 go build -tags goolm,stdjson -o "$E2E_BIN/openfox" ./cmd/openfox)
(cd "$repo" && GOWORK=off GOFLAGS=-trimpath CGO_ENABLED=0 go build -o "$E2E_BIN/messenger-relay-e2e-tool" \
  ./scripts/messenger-relay-e2e-tool)
(cd "$E2E_AI_SOURCE" && GOWORK=off GOFLAGS=-trimpath CGO_ENABLED=0 go build "${tags[@]}" -o "$E2E_BIN/" \
  ./messenger/cmd/tos-messengerd)
(cd "$E2E_AI_SOURCE" && GOWORK=off GOFLAGS=-trimpath CGO_ENABLED=0 go build -o "$E2E_BIN/" \
  ./messenger/cmd/tos-messenger-owner)
# The relay binary: in local mode the run's own relays, from the run's ai
# commit; in remote mode the identity check against the deployed relays, from
# the commit they were built from (E2E_RELAY_SOURCE), whose server code the
# run proves unchanged in the run's ai commit.
relay_source=$E2E_AI_SOURCE
[ "$remote" = 1 ] && relay_source=$E2E_RELAY_SOURCE
(cd "$relay_source" && GOWORK=off GOFLAGS=-trimpath CGO_ENABLED=0 go build -o "$E2E_BIN/" \
  ./protocol/cmd/tos-service-packet-relay)
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
  # The pinned relay CA, and an unrelated CA for the TLS negative control (its
  # key stays in the private directory).
  cp "$RELAY_CA_FILE" "$tls/ca.pem"
  mkdir -m 700 "$work/private/tls"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$work/private/tls/unrelated-ca-key.pem" -out "$tls/unrelated-ca.pem" -days 2 -subj "/CN=unrelated CA" \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign 2> /dev/null
fi

if [ "$remote" = 1 ]; then
  ssh_opts=(-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=20)
  remote_run="$B_REMOTE_BASE/$run_name"
  remote_table="tosmr_${run_name//[^A-Za-z0-9_]/_}"
  netsh="$here/messenger-relay-two-host-e2e-remote-net.sh"
  # The node files live at the same absolute path on this host and on B and C.
  local_base_created=0
  if [ ! -d "$B_REMOTE_BASE" ]; then
    sudo -n install -d -o "$(id -u)" -g "$(id -g)" -m 0700 "$B_REMOTE_BASE"
    local_base_created=1
    change "this host: created $B_REMOTE_BASE (owner the invoking user, 0700); reversal: rmdir at exit"
  fi
  [ -w "$B_REMOTE_BASE" ] || { echo "$B_REMOTE_BASE is not writable" >&2; exit 2; }
  if [ -e "$remote_run" ]; then
    echo "$remote_run already exists on this host" >&2
    exit 2
  fi
else
  netsh="$here/messenger-relay-two-host-net.sh"
fi

# One remote node's host: stop what is left of the run, remove its nft table
# (never created by this run, removed if present) and its scratch directory
# (only below the scratch base, never anything else). The script is fixed
# text on standard input; the run's names reach it only as quoted arguments.
# A recorded PID is killed only while its command line still names the run's
# directory, so a PID the system has since reused for another process is
# left alone.
remote_cleanup() {
  local node=$1 target=$2 key=$3 out="$work/net/$1-teardown.txt" upper
  upper=$(printf '%s' "$node" | tr a-z A-Z)
  ssh "${ssh_opts[@]}" -i "$key" "$target" -- \
    bash -s -- "$(printf '%q' "$remote_run")" "$(printf '%q' "$remote_table")" "$(printf '%q' "$B_REMOTE_BASE")" \
    > "$out" 2>&1 <<'EOF' ||
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
    echo "could not clean $upper's scratch directory or firewall table; check by hand" >&2
  while read -r _ pid name; do
    change "$upper host: killed leftover process $pid ($name) of the run (exit trap)"
  done < <(grep '^killed ' "$out" || true)
  grep -q table-removed "$out" && change "$upper host: removed nft table inet $remote_table (exit trap)"
  grep -q scratch-removed "$out" && change "$upper host: removed $remote_run (exit trap)"
  return 0
}

teardown() {
  set +e
  bash "$netsh" down "$work" || echo "teardown failed; run it again" >&2
  if [ "$remote" != 1 ]; then
    return
  fi
  if [ -f "$work/net/iptables-before.txt" ] && [ -f "$work/net/iptables-after.txt" ]; then
    if cmp -s "$work/net/iptables-before.txt" "$work/net/iptables-after.txt"; then
      change "this host: forwarding rules removed; iptables-save identical to before"
    else
      change "this host: iptables-save DIFFERS from before; inspect $work/net"
      echo "this host's iptables rules differ from before the run; see $work/net" >&2
    fi
  fi
  remote_cleanup b "$B_SSH" "$B_SSH_KEY"
  remote_cleanup c "$C_SSH" "$C_SSH_KEY"
  # The run never stops a relay unit; one named in the marker file would be
  # restarted here.
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
  if [ -d "$remote_run" ]; then
    mv "$remote_run" "$work/nodes" && change "this host: moved $remote_run into the work directory"
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
bash "$netsh" up "$work"

export E2E_EXECUTOR_SOCKET=unused-no-sale
if [ "$remote" = 1 ]; then
  change "this host: namespaces tosmr-a, tosmr-d, tosmr-e, tosmr-f, bridge tosmr-br0 and the tagged forwarding rules added; reversal: net script down"
  export E2E_REPO="$repo" E2E_ROOT_BASE="$remote_run" E2E_RELAY_CA_FILE="$work/tls/ca.pem"
  export MR1_NETSH="$netsh" MR1_B_TABLE="$remote_table" MR1_C_TABLE="$remote_table"
  export C_SHARES_RELAY=${C_SHARES_RELAY:-}
else
  export E2E_REPO="$repo" E2E_ROOT_BASE="$work/nodes"
fi
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
