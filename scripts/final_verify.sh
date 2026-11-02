#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."

step() { printf '\n===== %s =====\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

step 'Repository safety'
[[ -d .git ]] || fail 'Not inside Git repository'
# Check *tracked* paths, not ignored or untracked working files.
bad_paths=$(git ls-files | grep -E '(^|/)(secrets|private|captures)/|\.(pem|p12|pfx|pcap|pcapng|key|bin)$' || true)
if [[ -n "$bad_paths" ]]; then
    printf 'Tracked potentially sensitive files:\n%s\n' "$bad_paths" >&2
    fail 'Review and remove private/capture files from Git index before publishing'
fi
printf 'PASS: no matching secret/capture paths tracked\n'

step 'C build'
make all

step 'C tests'
make test

step 'Authenticated handshake integration'
bash scripts/test_handshake.sh

step 'Network gateway integration'
[[ -f scripts/run_lab.sh ]] || fail 'Missing scripts/run_lab.sh'
sudo bash scripts/run_lab.sh

step 'Git check'
git diff --check
printf '\nPASS: verification steps completed\n'
printf 'NOTE: This proves the configured lab scenario only; it does not independently validate all retransmission, reordering, or bidirectional cases.\n'
