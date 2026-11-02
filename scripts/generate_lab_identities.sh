#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p secrets
chmod 700 secrets
umask 077
for device in device1 device2; do
  if [[ -e "secrets/$device.key" ]]; then
    echo "Refusing to overwrite secrets/$device.key" >&2; exit 1
  fi
  openssl genpkey -algorithm ED25519 -out "secrets/$device.key"
  openssl pkey -in "secrets/$device.key" -pubout -out "secrets/$device.pub.pem"
done
echo 'Generated lab-only identities. Never commit secrets/.'
