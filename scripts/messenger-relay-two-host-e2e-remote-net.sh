#!/bin/bash
# Network namespaces for scripts/messenger-relay-two-host-e2e-remote.sh, the
# two-host (phase 2) M-R1 run: only node A and the stranger C run on this
# host; node B and the two relays are other machines.
#
#   messenger-relay-two-host-e2e-remote-net.sh up       <workdir>
#   messenger-relay-two-host-e2e-remote-net.sh firewall <workdir>
#   messenger-relay-two-host-e2e-remote-net.sh block    <workdir> <node> <relay>
#   messenger-relay-two-host-e2e-remote-net.sh unblock  <workdir> <node> <relay>
#   messenger-relay-two-host-e2e-remote-net.sh hold     <workdir> <node> <relay>
#   messenger-relay-two-host-e2e-remote-net.sh release  <workdir> <node> <relay>
#   messenger-relay-two-host-e2e-remote-net.sh down     <workdir>
#
# up: a private bridge tosmr-br0 (10.231.78.1/24, the host end) and two
# namespaces joined to it by one veth each: tosmr-a (10.231.78.10) and
# tosmr-c (10.231.78.12). Each namespace routes through the host end, and
# the host forwards and masquerades (through its uplink) only TCP to the two
# relays' TLS port: three iptables rules per relay, each tagged with the
# comment "tosmr-remote", inserted first in their chains and removed by
# down. iptables-save (rules only, no counters) is recorded before up and
# after down in <workdir>/net and must be identical.
#
# firewall: in each node namespace, outgoing connections only to the two
# relays' TLS port and to the chain RPC forwarder ports on the host end of the
# bridge, and no incoming connection at all. On the host, a bridge-family
# table drops every frame between A's and C's addresses in both directions.
#
# block / unblock: refuse (tcp reset), or stop refusing, the node's
# connections to one relay. hold / release: silently drop, or stop dropping,
# every packet between the node and one relay in both directions, so a
# deposit in flight stalls and completes once released.
#
# down: kills every process left in the namespaces and removes the
# namespaces, the bridge, the host table and the forwarding rules. Every step
# tolerates an object that is already gone, so down is safe to run any number
# of times, and up runs it first.
#
# MR1_RELAY_ADDRESSES names the relays' IPv4 addresses, relay 1 first (two
# words); MR1_RELAY_PORT their TLS port (default 8443). Every root command is
# appended to <workdir>/net/root-commands.log before it runs. E2E_RPC_PORTS
# names the forwarded chain RPC ports (comma separated); only firewall needs it.
set -euo pipefail
action=${1:?up, firewall, block, unblock, hold, release or down}
work=${2:?work directory}
net="$work/net"
mkdir -p "$net"
log="$net/root-commands.log"
bridge=tosmr-br0
prefix=10.231.78
host_ip=$prefix.1
subnet=$prefix.0/24
relay_port=${MR1_RELAY_PORT:-8443}
read -r -a relay_ips <<< "${MR1_RELAY_ADDRESSES:-}"
if [ "${#relay_ips[@]}" != 2 ]; then
  echo "MR1_RELAY_ADDRESSES must name the two relays' IPv4 addresses" >&2
  exit 2
fi
for ip in "${relay_ips[@]}"; do
  [[ $ip =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "relay address $ip is not IPv4" >&2; exit 2; }
done
declare -A address=([a]=$prefix.10 [c]=$prefix.12 [relay1]=${relay_ips[0]} [relay2]=${relay_ips[1]})
nodes=(a c)
relays=(relay1 relay2)
tag=tosmr-remote

root() {
  printf '%s\n' "$*" >> "$log"
  sudo -n "$@"
}

uplink() {
  ip -o route get "${relay_ips[0]}" | grep -o 'dev [^ ]*' | cut -d' ' -f2
}

# The host rules, one line per rule: table, chain, then the rule.
host_rules() {
  local dev=$1 ip
  for ip in "${relay_ips[@]}"; do
    echo "filter FORWARD -i $bridge -o $dev -s $subnet -d $ip/32 -p tcp --dport $relay_port -m comment --comment $tag -j ACCEPT"
    echo "filter FORWARD -i $dev -o $bridge -s $ip/32 -d $subnet -p tcp --sport $relay_port -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment $tag -j ACCEPT"
    echo "nat POSTROUTING -s $subnet -d $ip/32 -o $dev -p tcp --dport $relay_port -m comment --comment $tag -j MASQUERADE"
  done
}

rules_snapshot() {
  sudo -n iptables-save | grep -v '^#' | sed -E 's/ \[[0-9]+:[0-9]+\]$//' > "$1"
}

down() {
  for name in "${nodes[@]}"; do
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
  # Every tagged rule, whatever uplink it was added for.
  local table line spec
  for table in filter nat; do
    while IFS= read -r line; do
      spec=${line#-A }
      # shellcheck disable=SC2086
      root iptables -t "$table" -D $spec
    done < <(sudo -n iptables -t "$table" -S | grep -- "--comment $tag" || true)
  done
  if [ -f "$net/iptables-before.txt" ]; then
    rules_snapshot "$net/iptables-after.txt"
  fi
}

up() {
  down
  rm -f "$net/iptables-after.txt"
  rules_snapshot "$net/iptables-before.txt"
  local dev
  dev=$(uplink)
  [ -n "$dev" ] || { echo "no route to the relays" >&2; exit 2; }
  root ip link add "$bridge" type bridge
  root ip addr add "$host_ip/24" dev "$bridge"
  root ip link set "$bridge" up
  for name in "${nodes[@]}"; do
    ns=tosmr-$name
    root ip netns add "$ns"
    root ip link add "tmv-$name" type veth peer name eth0 netns "$ns"
    root ip link set "tmv-$name" master "$bridge" up
    root ip -n "$ns" addr add "${address[$name]}/24" dev eth0
    root ip -n "$ns" link set eth0 up
    root ip -n "$ns" link set lo up
    root ip -n "$ns" route add default via "$host_ip"
  done
  [ "$(sysctl -n net.ipv4.ip_forward)" = 1 ] || { echo "IPv4 forwarding is off on this host" >&2; exit 2; }
  local table chain rule
  while read -r table chain rule; do
    # shellcheck disable=SC2086
    root iptables -t "$table" -I "$chain" 1 $rule
  done < <(host_rules "$dev")
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
  cat > "$net/host.nft" <<EOF
table bridge tosmr {
  chain forward {
    type filter hook forward priority 0; policy accept;
    ip saddr ${address[a]} ip daddr ${address[c]} drop
    ip saddr ${address[c]} ip daddr ${address[a]} drop
  }
}
EOF
  for name in "${nodes[@]}"; do
    root ip netns exec "tosmr-$name" nft -f "$net/$name.nft"
  done
  root nft -f "$net/host.nft"
}

check_names() {
  [[ " ${nodes[*]} " == *" $1 "* ]] && [[ " ${relays[*]} " == *" $2 "* ]] ||
    { echo "$action: unknown node or relay" >&2; exit 2; }
}

# Inserted first in the chain, so a new connection is affected at once and
# one already open is too.
block() {
  check_names "$1" "$2"
  root ip netns exec "tosmr-$1" nft insert rule inet tosmr output ip daddr "${address[$2]}" tcp dport "$relay_port" \
    reject with tcp reset comment "\"block-$2\""
}

hold() {
  check_names "$1" "$2"
  root ip netns exec "tosmr-$1" nft insert rule inet tosmr output ip daddr "${address[$2]}" tcp dport "$relay_port" \
    drop comment "\"hold-$2\""
  root ip netns exec "tosmr-$1" nft insert rule inet tosmr input ip saddr "${address[$2]}" tcp sport "$relay_port" \
    drop comment "\"hold-$2\""
}

remove_tagged() {
  local node=$1 name=$2 chain handle handles
  for chain in input output; do
    handles=$(sudo -n ip netns exec "tosmr-$node" nft -a list chain inet tosmr "$chain" |
      grep -F "comment \"$name\"" | grep -o 'handle [0-9]*' | cut -d' ' -f2 || true)
    for handle in $handles; do
      root ip netns exec "tosmr-$node" nft delete rule inet tosmr "$chain" handle "$handle"
    done
  done
}

case "$action" in
  up) up ;;
  firewall) firewall ;;
  block) block "${3:-}" "${4:-}" ;;
  unblock) check_names "${3:-}" "${4:-}"; remove_tagged "$3" "block-$4" ;;
  hold) hold "${3:-}" "${4:-}" ;;
  release) check_names "${3:-}" "${4:-}"; remove_tagged "$3" "hold-$4" ;;
  down) down ;;
  *) echo "unknown action $action" >&2; exit 2 ;;
esac
