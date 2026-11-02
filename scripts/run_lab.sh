#!/usr/bin/env bash
# Execute under sudo on a *dedicated* four-namespace test topology.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
[[ $EUID -eq 0 ]] || { echo 'Run: sudo bash scripts/run_lab.sh' >&2; exit 1; }
for n in sic-pc1 sic-dev1 sic-dev2 sic-pc2; do
    ip netns exec "$n" true || { echo "Missing $n; run scripts/setup_network.sh first" >&2; exit 1; }
done
[[ -x "$ROOT/nfq_gateway" ]] || { echo 'Build first: make all' >&2; exit 1; }
for f in secrets/device1.key secrets/device1.pub.pem secrets/device2.key secrets/device2.pub.pem; do
    [[ -f "$f" ]] || { echo "Missing $f; run scripts/generate_lab_identities.sh" >&2; exit 1; }
done
mkdir -p captures
chmod 700 captures
logdir=$(mktemp -d)
chmod 700 "$logdir"
server_pid='' dev1_pid='' dev2_pid=''
rule_one=(-s 10.10.1.1 -d 10.10.3.2 -p tcp --dport 5201 -j NFQUEUE --queue-num 10)
rule_two=(-s 10.10.1.1 -d 10.10.3.2 -p tcp --dport 5201 -j NFQUEUE --queue-num 11)
mss_rule=(-p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1200)
cleanup() {
    status=$?
    trap - EXIT INT TERM
    ip netns exec sic-dev1 iptables -D FORWARD "${rule_one[@]}" 2>/dev/null || true
    ip netns exec sic-dev2 iptables -D FORWARD "${rule_two[@]}" 2>/dev/null || true
    ip netns exec sic-dev1 iptables -t mangle -D FORWARD "${mss_rule[@]}" 2>/dev/null || true
    for p in "$dev1_pid" "$dev2_pid" "$server_pid"; do
        [[ -z "$p" ]] || { kill -INT "$p" 2>/dev/null || true; }
    done
    for p in "$dev1_pid" "$dev2_pid" "$server_pid"; do
        [[ -z "$p" ]] || wait "$p" 2>/dev/null || true
    done
    echo '----- Device1 gateway -----'
    cat "$logdir/device1.log" 2>/dev/null || true
    echo '----- Device2 gateway -----'
    cat "$logdir/device2.log" 2>/dev/null || true
    if [[ -f "$logdir/device1.log" && -f "$logdir/device2.log" ]]; then
        cp "$logdir/device1.log" captures/last_device1.log
        cp "$logdir/device2.log" captures/last_device2.log
    fi
    rm -rf "$logdir"
    [[ $status -eq 0 ]] || echo 'LAB TEST FAILED (rules removed)' >&2
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Enforce a modest TCP MSS via SYN option rewriting *before* filter/FORWARD.
# This leaves enough room for the GCM tag and TCP timestamp options.
ip netns exec sic-dev1 iptables -t mangle -I FORWARD 1 "${mss_rule[@]}"

# Turn off packet aggregation on the six veth interfaces where supported.
# Fail if ethtool is absent. Disabled offloads are limited to the virtual lab.
command -v ethtool >/dev/null || { echo 'Install ethtool: sudo apt install ethtool' >&2; exit 1; }
for pair in 'sic-pc1 v-pc1' 'sic-dev1 v-d1a' 'sic-dev1 v-d1b' \
            'sic-dev2 v-d2a' 'sic-dev2 v-d2b' 'sic-pc2 v-pc2'; do
    read -r ns iface <<< "$pair"
    ip netns exec "$ns" ethtool -K "$iface" gro off gso off tso off >/dev/null 2>&1 || {
        echo "WARNING: unable to disable every offload on $ns/$iface" >&2
    }
done

# Each gateway conducts authenticated X25519 session establishment itself.
# No shared local AES key file and no counter reuse across sessions.
ip netns exec sic-dev2 "$ROOT/nfq_gateway" device2 11 10.10.2.2 \
    "$ROOT/secrets/device2.key" "$ROOT/secrets/device1.pub.pem" >"$logdir/device2.log" 2>&1 &
dev2_pid=$!
sleep 0.4
ip netns exec sic-dev1 "$ROOT/nfq_gateway" device1 10 10.10.2.2 \
    "$ROOT/secrets/device1.key" "$ROOT/secrets/device2.pub.pem" >"$logdir/device1.log" 2>&1 &
dev1_pid=$!

ready=0
for i in $(seq 1 50); do
    if grep -q 'Authenticated session active:' "$logdir/device1.log" && \
       grep -q 'Authenticated session active:' "$logdir/device2.log"; then
        ready=1; break
    fi
    kill -0 "$dev1_pid" 2>/dev/null || break
    kill -0 "$dev2_pid" 2>/dev/null || break
    sleep 0.1
done
[[ $ready -eq 1 ]] || { echo 'Session did not become active' >&2; exit 1; }

ip netns exec sic-pc2 iperf3 -s -1 >"$logdir/iperf_server.log" 2>&1 &
server_pid=$!
sleep 0.2
ip netns exec sic-dev1 iptables -I FORWARD 1 "${rule_one[@]}"
ip netns exec sic-dev2 iptables -I FORWARD 1 "${rule_two[@]}"

set +e
ip netns exec sic-pc1 timeout 20s iperf3 -c 10.10.3.2 -n 16K >"$logdir/iperf_client.log" 2>&1
result=$?
set -e
cat "$logdir/iperf_client.log"
[[ $result -eq 0 ]] || { echo "iperf3 failed with exit code $result" >&2; exit 1; }
# Verify this wasn't an unprotected bypass: the queued gateways must have
# both processed real packets; final counters are validated post-shutdown.
kill -INT "$dev1_pid" "$dev2_pid" 2>/dev/null || true
wait "$dev1_pid" 2>/dev/null || true
wait "$dev2_pid" 2>/dev/null || true
dev1_pid='' dev2_pid=''
for side in device1 device2; do
    log="$logdir/$side.log"
    grep -Eq 'data=[1-9][0-9]*' "$log" || { echo "$side handled no protected data packets" >&2; exit 1; }
    grep -q 'dropped=0' "$log" || { echo "$side dropped packets" >&2; exit 1; }
done
echo 'PASS: end-to-end selected TCP flow traversed both authenticated NFQUEUE gateways'
