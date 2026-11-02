#!/usr/bin/env bash
set -euo pipefail
umask 077
mkdir -p secrets
if [[ -e secrets/lab-forward.bin ]]; then
  echo 'ERROR: Existing lab key. Do not reuse after restarting encryption counters.' >&2
  exit 1
fi
openssl rand -out secrets/lab-forward.bin 36
chmod 600 secrets/lab-forward.bin
echo 'Created fresh lab-only key; never commit it. Remove after this run.'
