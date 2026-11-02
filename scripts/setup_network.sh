#!/usr/bin/env bash
set -euo pipefail

# Four isolated Linux network namespaces
NAMES=(sic-pc1 sic-dev1 sic-dev2 sic-pc2)

if [[ $EUID -ne 0 ]]; then
    echo "Run with sudo"
    exit 1
fi

# Prevent overwriting an existing laboratory
for ns in "${NAMES[@]}"; do
    if ip netns list | grep -q "^${ns} "; then
        echo "Namespace $ns already exists."
        echo "Clean up before rebuilding."
        exit 1
    fi
done

echo "[1/5] Creating namespaces..."

for ns in "${NAMES[@]}"; do
    ip netns add "$ns"
    ip -n "$ns" link set lo up
done

echo "[2/5] Creating virtual Ethernet links..."

ip link add v-pc1 type veth peer name v-d1a
ip link add v-d1b type veth peer name v-d2a
ip link add v-d2b type veth peer name v-pc2

ip link set v-pc1 netns sic-pc1
ip link set v-d1a netns sic-dev1
ip link set v-d1b netns sic-dev1
ip link set v-d2a netns sic-dev2
ip link set v-d2b netns sic-dev2
ip link set v-pc2 netns sic-pc2

echo "[3/5] Assigning IPv4 addresses..."

ip -n sic-pc1 addr add 10.10.1.1/30 dev v-pc1
ip -n sic-dev1 addr add 10.10.1.2/30 dev v-d1a

ip -n sic-dev1 addr add 10.10.2.1/30 dev v-d1b
ip -n sic-dev2 addr add 10.10.2.2/30 dev v-d2a

ip -n sic-dev2 addr add 10.10.3.1/30 dev v-d2b
ip -n sic-pc2 addr add 10.10.3.2/30 dev v-pc2

for entry in \
    "sic-pc1 v-pc1" \
    "sic-dev1 v-d1a" \
    "sic-dev1 v-d1b" \
    "sic-dev2 v-d2a" \
    "sic-dev2 v-d2b" \
    "sic-pc2 v-pc2"; do
    read -r ns iface <<< "$entry"
    ip -n "$ns" link set "$iface" up
done

echo "[4/5] Configuring routing..."

ip -n sic-pc1 route add default via 10.10.1.2
ip -n sic-pc2 route add default via 10.10.3.1

ip -n sic-dev1 route add 10.10.3.0/30 via 10.10.2.2
ip -n sic-dev2 route add 10.10.1.0/30 via 10.10.2.1

ip netns exec sic-dev1 sysctl -qw net.ipv4.ip_forward=1
ip netns exec sic-dev2 sysctl -qw net.ipv4.ip_forward=1

echo "[5/5] Network laboratory ready!"
ip netns list
