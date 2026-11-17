#!/bin/bash
# Network namespaces for scripts/messenger-relay-two-host-e2e.sh.
#
#   messenger-relay-two-host-net.sh up       <workdir>
#   messenger-relay-two-host-net.sh firewall <workdir>
#   messenger-relay-two-host-net.sh block    <workdir> <node> <relay>
#   messenger-relay-two-host-net.sh unblock  <workdir> <node> <relay>
#   messenger-relay-two-host-net.sh down     <workdir>
#
# up: a private bridge tosmr-br0 (10.231.78.1/24, the host end) and five
# namespaces, each joined to it by one veth: tosmr-a (10.231.78.10) and
# tosmr-b (10.231.78.11) for the two OpenFox nodes, tosmr-c (10.231.78.12)
# for a stranger node, tosmr-relay1 (10.231.78.20) and tosmr-relay2
# (10.231.78.21) for the two relays. No namespace has a default route, so
# none reaches anything beyond the bridge. MR_NET_NODES names the node
# namespaces (default "a b c"); the private-room run adds d (10.231.78.13)
# and e (10.231.78.14).
#
# firewall: in each node namespace, outgoing connections only to the two
# relays' TLS port and to the chain RPC forwarder ports on the host end of the
# bridge, and no incoming connection at all; in each relay namespace, incoming
# connections only to its TLS port and no outgoing connection. On the host, a
# bridge-family table drops every frame between any two node addresses in
# both directions, whatever the namespaces' own rules say.
#
# block / unblock: drop (or stop dropping) the node's new connections to one
# relay, for the run's public-id race.
#
# down: kills every process left in the namespaces and removes the
# namespaces, the bridge and the host table. Every step tolerates an object
# that is already gone, so down is safe to run any number of times, and up
# runs it first.
#
# Every root command is appended to <workdir>/net/root-commands.log before it
# runs. E2E_RPC_PORTS names the forwarded chain RPC ports (comma separated);
# only firewall needs it.
set -euo pipefail
action=${1:?up, firewall, block, unblock or down}
work=${2:?work directory}
net="$work/net"
mkdir -p "$net"
log="$net/root-commands.log"
bridge=tosmr-br0
prefix=10.231.78
host_ip=$prefix.1
relay_port=8443
declare -A address=([a]=$prefix.10 [b]=$prefix.11 [c]=$prefix.12 [d]=$prefix.13 [e]=$prefix.14
  [relay1]=$prefix.20 [relay2]=$prefix.21)
read -r -a nodes <<< "${MR_NET_NODES:-a b c}"
for node in "${nodes[@]}"; do
  case "$node" in a|b|c|d|e) ;; *) echo "MR_NET_NODES: unknown node $node" >&2; exit 2 ;; esac
done
# down removes every namespace this script can make, whatever MR_NET_NODES
# says, so a leftover of another run's node set is removed too.
all_names=(a b c d e relay1 relay2)
names=("${nodes[@]}" relay1 relay2)
relays=(relay1 relay2)

root() {
  printf '%s\n' "$*" >> "$log"
  sudo -n "$@"
}

down() {
  for name in "${all_names[@]}"; do
    ns=tosmr-$name
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
  if root nft list table bridge tosmr > /dev/null 2>&1; then
    root nft delete table bridge tosmr
  fi
}

up() {
  down
  root ip link add "$bridge" type bridge
  root ip addr add "$host_ip/24" dev "$bridge"
  root ip link set "$bridge" up
  for name in "${names[@]}"; do
    ns=tosmr-$name
    root ip netns add "$ns"
    root ip link add "tmv-$name" type veth peer name eth0 netns "$ns"
    root ip link set "tmv-$name" master "$bridge" up
    root ip -n "$ns" addr add "${address[$name]}/24" dev eth0
    root ip -n "$ns" link set eth0 up
    root ip -n "$ns" link set lo up
  done
}

firewall() {
  local ports=${E2E_RPC_PORTS:-}
  if ! [[ $ports =~ ^[0-9]{1,5}(,[0-9]{1,5})*$ ]]; then
    echo "firewall: E2E_RPC_PORTS must name the forwarded chain RPC ports, comma separated" >&2
    exit 2
  fi
  local rpc_ports=${ports//,/, }
  for name in "${nodes[@]}"; do
    cat > "$net/$name.nft" <<EOF
table inet tosmr {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
  }
  chain output {
    type filter hook output priority 0; policy drop;
    oif lo accept
    ct state established,related accept
    ip daddr { ${address[relay1]}, ${address[relay2]} } tcp dport $relay_port accept
    ip daddr $host_ip tcp dport { $rpc_ports } accept
  }
}
EOF
  done
  for name in "${relays[@]}"; do
    cat > "$net/$name.nft" <<EOF
table inet tosmr {
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
  done
  {
    echo "table bridge tosmr {"
    echo "  chain forward {"
    echo "    type filter hook forward priority 0; policy accept;"
    for from in "${nodes[@]}"; do
      for to in "${nodes[@]}"; do
        [ "$from" = "$to" ] || echo "    ip saddr ${address[$from]} ip daddr ${address[$to]} drop"
      done
    done
    echo "  }"
    echo "}"
  } > "$net/host.nft"
  for name in "${names[@]}"; do
    root ip netns exec "tosmr-$name" nft -f "$net/$name.nft"
  done
  root nft -f "$net/host.nft"
}

block() {
  local node=${1:?node} relay=${2:?relay}
  [[ " ${nodes[*]} " == *" $node "* ]] && [[ " ${relays[*]} " == *" $relay "* ]] ||
    { echo "block: unknown node or relay" >&2; exit 2; }
  # Inserted first in the chain, so a new connection is refused at once and
  # one already open is cut too.
  root ip netns exec "tosmr-$node" nft insert rule inet tosmr output ip daddr "${address[$relay]}" tcp dport $relay_port \
    reject with tcp reset
}

unblock() {
  local node=${1:?node} relay=${2:?relay}
  [[ " ${nodes[*]} " == *" $node "* ]] && [[ " ${relays[*]} " == *" $relay "* ]] ||
    { echo "unblock: unknown node or relay" >&2; exit 2; }
  local handles
  handles=$(sudo -n ip netns exec "tosmr-$node" nft -a list chain inet tosmr output |
    grep "${address[$relay]}" | grep "reject with tcp reset" | grep -o 'handle [0-9]*' | cut -d' ' -f2 || true)
  for handle in $handles; do
    root ip netns exec "tosmr-$node" nft delete rule inet tosmr output handle "$handle"
  done
}

case "$action" in
  up) up ;;
  firewall) firewall ;;
  block) block "${3:-}" "${4:-}" ;;
  unblock) unblock "${3:-}" "${4:-}" ;;
  down) down ;;
  *) echo "unknown action $action" >&2; exit 2 ;;
esac
