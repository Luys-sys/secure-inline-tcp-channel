# Secure Inline TCP Communication Channel

A Linux-based network security prototype implemented in C.

## Project Objective

Build a secure inline communication channel:

PC1 → Device1 → Device2 → PC2

Device1 and Device2 are intended to protect selected TCP/IPv4
traffic using authenticated key exchange and AES-256-GCM.

The design aims to preserve IP/TCP headers and avoid UDP
encapsulation or custom headers in protected packets.

## Technology Stack

- C11 and GCC
- Linux network namespaces and veth
- OpenSSL 3
- X25519 key agreement
- Ed25519 digital signatures
- HKDF-SHA256 key derivation
- AES-256-GCM authenticated encryption
- IPv4/TCP packet parsing
- Linux Netfilter / NFQUEUE (planned)

## Implemented Components

- Individual cryptographic unit tests
- Simulated authenticated handshake integration test
- IPv4/TCP packet parser and checksum tests
- Four-node virtual Linux network topology
- End-to-end TCP connectivity testing
- Baseline traffic inspection with tcpdump

## Build and Test

Install dependencies on Ubuntu:

sudo apt install build-essential libssl-dev iproute2 \
iputils-ping iperf3 tcpdump libnetfilter-queue-dev

Build and run the individual tests using the commands
documented in their respective source files or test setup.

## Current Status

Development prototype. The cryptographic tests and baseline
network topology have been validated.

A real network handshake, NFQUEUE-based inline forwarding,
nonce synchronization, TCP stream correctness and full
encrypted end-to-end transmission are not yet implemented.

## Security Considerations

- Fresh ephemeral session key agreement is required.
- Peer identity must be authenticated.
- AES-GCM nonce uniqueness is mandatory.
- Packets must fail closed on authentication errors.
- Packet expansion and TCP sequence semantics require
  explicit design and validation.
- The current prototype is not production-ready.

## License

Not yet selected.
