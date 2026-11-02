# Secure Inline TCP Communication Channel

C11 / Linux network namespaces / Netfilter NFQUEUE / OpenSSL 3.

The project implements a four-node laboratory topology:

`PC1 -> Device1 -> Device2 -> PC2`

For selected IPv4/TCP payload-bearing packets travelling from PC1 to PC2,
Device1 encrypts the payload with AES-256-GCM and appends a 16-byte tag.
Device2 authenticates and decrypts the payload, restores the original payload
length and recomputes IPv4 and TCP checksums. The protected link does not
use UDP encapsulation or add a custom data-plane header.

The gateways establish an authenticated X25519 session using pinned Ed25519
peer identity public keys and derive direction-separated AES keys and nonce
salts with HKDF-SHA256. The symmetric keys remain in process memory.

## Requirements

Ubuntu Linux (WSL2 works for the namespace lab), GCC, OpenSSL 3,
Netfilter Queue, iproute2, iptables, ethtool, and iperf3.

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev libnetfilter-queue-dev \
  iproute2 iptables iputils-ping ethtool iperf3 tcpdump
```

## Build and tests

```bash
make all
make test
bash scripts/test_handshake.sh
```

## Four-node lab

Run these commands from a clean, isolated WSL2 Ubuntu environment:

```bash
sudo bash scripts/setup_network.sh
bash scripts/generate_lab_identities.sh
make all
sudo bash scripts/run_lab.sh
```

The lab runner configures SYN MSS, attempts to disable veth offloads, launches
both authenticated gateway processes, runs a selected TCP data test, checks
packet forwarding counters and removes its own NFQUEUE / MSS rules on exit.
It writes diagnostic logs to `captures/` (ignored by Git).

## Design

- Per-direction HKDF-derived AES-256 key + independent 4-byte nonce salt
- 96-bit GCM nonce: 4-byte salt + monotonic 64-bit encryption counter
- Authentication-tag-only suffix; no UDP tunnel or custom protected header
- AAD includes stable IP/TCP identifiers; mutable TTL, lengths and checksums
  are excluded
- Bounded nonce candidate recovery with replay bitmap
- Empty-payload TCP packets are forwarded unchanged

See `docs/protected-packet-design.md` for precise supported traffic conditions,
nonce recovery bounds, forwarding semantics, and network lab assumptions.

This repository is an educational prototype for a controlled namespace lab,
not a general-purpose VPN or production security gateway.
