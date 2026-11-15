#!/bin/bash
# Network namespaces for scripts/service-relay-two-host-e2e.sh.
#
#   service-relay-two-host-net.sh up       <workdir>
#   service-relay-two-host-net.sh firewall <workdir>
#   service-relay-two-host-net.sh down     <workdir>
#
# up: a private bridge tosrly-br0 (10.231.77.1/24, the host end) and three
# namespaces, each joined to it by one veth: tosrly-buyer (10.231.77.10),
# tosrly-provider (10.231.77.11) and tosrly-relay (10.231.77.20). No
# namespace has a default route, so none reaches anything beyond the bridge.
#
# firewall: in each node namespace, outgoing connections only to the relay's
# TLS port and to the chain RPC forwarder ports on the host end of the
# bridge, and no incoming connection at all; in the relay namespace, incoming
# connections only to its TLS port and no outgoing connection. On the host,
# a bridge-family table drops every frame between the buyer's and the
# provider's addresses in both directions, whatever the namespaces' own
# rules say.
#
# down: kills every process left in the namespaces and removes the
# namespaces, the bridge and the host table. Every step tolerates an object
# that is already gone, so down is safe to run any number of times, and up
# runs it first.
#
# Every root command is appended to <workdir>/net/root-commands.log before it
# runs. E2E_RPC_PORTS names the forwarded chain RPC ports (comma separated).
set -euo pipefail
action=${1:?up, firewall or down}
work=${2:?work directory}
: "${E2E_RPC_PORTS:?}"
net="$work/net"
mkdir -p "$net"
log="$net/root-commands.log"
bridge=tosrly-br0
prefix=10.231.77
host_ip=$prefix.1
relay_ip=$prefix.20
relay_port=8443
declare -A address=([buyer]=$prefix.10 [provider]=$prefix.11 [relay]=$relay_ip)
names=(buyer provider relay)
rpc_ports=${E2E_RPC_PORTS//,/, }

root() {
  printf '%s\n' "$*" >> "$log"
  sudo -n "$@"
}

down() {
  for name in "${names[@]}"; do
    ns=tosrly-$name
    if ip netns list | grep -qw "$ns"; then
      pids=$(root ip netns pids "$ns" || true)
      if [ -n "$pids" ]; then
        # shellcheck disable=SC2086
        root kill -TERM $pids || true
        sleep 2
        pids=$(root ip netns pids "$ns" || true)
        # shellcheck disable=SC2086
        [ -z "$pids" ] || root kill -KILL $pids || true
      fi
      root ip netns delete "$ns"
    fi
  done
  if ip link show "$bridge" > /dev/null 2>&1; then
    root ip link delete "$bridge"
  fi
  if root nft list table bridge tosrly > /dev/null 2>&1; then
    root nft delete table bridge tosrly
  fi
}

up() {
  down
  root ip link add "$bridge" type bridge
  root ip addr add "$host_ip/24" dev "$bridge"
  root ip link set "$bridge" up
  for name in "${names[@]}"; do
    ns=tosrly-$name
    root ip netns add "$ns"
    root ip link add "trv-$name" type veth peer name eth0 netns "$ns"
    root ip link set "trv-$name" master "$bridge" up
    root ip -n "$ns" addr add "${address[$name]}/24" dev eth0
    root ip -n "$ns" link set eth0 up
    root ip -n "$ns" link set lo up
  done
}

firewall() {
  for name in buyer provider; do
    cat > "$net/$name.nft" <<EOF
table inet tosrly {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
  }
  chain output {
    type filter hook output priority 0; policy drop;
    oif lo accept
    ct state established,related accept
    ip daddr $relay_ip tcp dport $relay_port accept
    ip daddr $host_ip tcp dport { $rpc_ports } accept
  }
}
EOF
  done
  cat > "$net/relay.nft" <<EOF
table inet tosrly {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
    tcp dport $relay_port accept
  }
  chain output {
    type filter hook output priority 0; policy drop;
    oif lo accept
    ct state established,related accept
  }
}
EOF
  cat > "$net/host.nft" <<EOF
table bridge tosrly {
  chain forward {
    type filter hook forward priority 0; policy accept;
    ip saddr ${address[buyer]} ip daddr ${address[provider]} drop
    ip saddr ${address[provider]} ip daddr ${address[buyer]} drop
  }
}
EOF
  for name in "${names[@]}"; do
    root ip netns exec "tosrly-$name" nft -f "$net/$name.nft"
  done
  root nft -f "$net/host.nft"
}

case "$action" in
  up) up ;;
  firewall) firewall ;;
  down) down ;;
  *) echo "unknown action $action" >&2; exit 2 ;;
esac
