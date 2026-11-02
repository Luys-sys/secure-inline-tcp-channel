#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
if [[ $EUID -ne 0 ]]; then echo 'Run: sudo bash scripts/wire_verify.sh' >&2; exit 1; fi
for name in sic-dev1 sic-dev2; do ip netns exec "$name" true || exit 1; done
command -v tcpdump >/dev/null || { echo 'tcpdump is required' >&2; exit 1; }
mkdir -p captures
chmod 700 captures
for p in captures/wire_before.pcap captures/wire_link.pcap captures/wire_after.pcap; do rm -f "$p"; done
pids=()
cleanup() {
  for pid in "${pids[@]}"; do kill -INT "$pid" 2>/dev/null || true; done
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT
filter='tcp and src host 10.10.1.1 and dst host 10.10.3.2 and dst port 5201'
ip netns exec sic-dev1 tcpdump -i v-d1a -U -s 0 -w captures/wire_before.pcap "$filter" >/dev/null 2>&1 & pids+=("$!")
ip netns exec sic-dev1 tcpdump -i v-d1b -U -s 0 -w captures/wire_link.pcap "$filter" >/dev/null 2>&1 & pids+=("$!")
ip netns exec sic-dev2 tcpdump -i v-d2b -U -s 0 -w captures/wire_after.pcap "$filter" >/dev/null 2>&1 & pids+=("$!")
sleep 0.8
for pid in "${pids[@]}"; do kill -0 "$pid" || { echo 'tcpdump failed to start' >&2; exit 1; }; done
bash scripts/run_lab.sh
cleanup
pids=()
python3 scripts/analyze_wire.py captures/wire_before.pcap captures/wire_link.pcap captures/wire_after.pcap
