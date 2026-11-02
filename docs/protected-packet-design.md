# Protected TCP packet design — prototype decision (Step 23)

**Scope:** controlled Linux namespace lab, IPv4/TCP only, no NAT, no IPv4 fragmentation, no TCP segmentation offload, explicit small MSS, protected traffic restricted to an allowlisted TCP flow. Not a production VPN.

## On-wire data plane

`[original IPv4 header*][original TCP header*][AES-GCM ciphertext (same length as TCP payload)][16-byte GCM tag]`

`*` The address/port/sequence/ACK/flags/options fields are preserved, but IPv4 Total Length, IPv4 checksum, and TCP checksum MUST change to describe the modified packet. Receiving gateway restores original IPv4 Total Length and recalculates both checksums after authentication succeeds. Nothing is appended to zero-payload packets. No UDP tunnel or custom data-plane header is used.

**Gateways must intercept before TCP endpoints.** Only the on-wire link between Device1 and Device2 carries the extra tag; PC1 and PC2 see the original payload length and normal sequence space. Do NOT perform TCP sequence translation simply because a tag travels between gateways. Intermediate stateful TCP firewalls, hardware offloads, PMTU constraints and fragmentation can still make this design incompatible with arbitrary traffic.

## Session and direction

The separate authenticated handshake/control connection derives independent 256-bit AES keys and independent four-byte nonce salts for each direction (HKDF context separation). This is **not yet implemented by the actual gateway**. Keys/salts must be fresh per session; on crash/restart, never reuse a key/salt with a reset counter. Counter state is in-memory in this educational module and is not crash-safe.

## Nonce without a custom header

For each protected, nonempty TCP payload, the sender assigns a strictly increasing `uint64` packet counter. Nonce is 12 bytes: `4-byte per-direction session salt || 8-byte big-endian packet counter`.

The packet carries **no counter header**. Receiver authenticates by trying candidate counters in a bounded window (up to 64 future and 64 recent candidates) and rejects an already-seen counter using a replay bitmap. This is a computationally expensive lab-only mechanism; it supports limited loss/reordering but will lose synchronization after larger gaps. Resynchronization/rekey and counter exhaustion policy are not implemented. Authentication of a packet is the only way to accept a candidate counter. Replay rejection can be at odds with forwarding genuine duplicate TCP segments after network retransmission; re-encryption of retransmissions must allocate a fresh counter and tag.

## Additional authenticated data (AAD)

The gateway will construct a stable, canonical AAD from selected immutable header fields (addresses, ports, seq, ack, flags and TCP options as applicable). Do not authenticate mutable fields such as TTL, checksums or IPv4 Total Length. Current `wire_aead` module accepts caller-provided AAD; header canonicalization and integration remain TODO.

## Packet sizing and checksums

Encryption adds exactly 16 bytes. Before enabling the data plane, enforce `original IP packet total length + 16 <= outgoing MTU`, e.g. clamp both TCP MSS directions at SYN to account for 16-byte tag and options, or use a deliberately low configured MSS. Disable GRO/GSO/TSO for lab interfaces. IPv4 fragmentation is rejected, not decrypted. Recalculate IP/TCP checksums after every transformation and verify against actual packet captures. A fail-closed verdict is required for non-handshaken protected traffic or failed authentication; observer's `--queue-bypass` is not appropriate for deployment.

## Acceptance tests still required

1. Two namespace processes hold the same live session and keys, and successfully protect an end-to-end TCP payload.
2. tcpdump on Device1↔Device2 confirms ciphertext and 16-byte tag; PC2 sees plaintext.
3. Modified tag, header AAD, replayed packets fail closed.
4. Loss/reordering/retransmission, counter exhaustion, reboot/rekey, small MTU and bidirectional flows tested.
5. Actual NFQUEUE gateway integrations tested with normal iperf3 transfer; note explicit limitations transparently.

**Status:** Step 23 implements and tests a standalone wire-AEAD counter/replay module; it is NOT wired to NFQUEUE or handshake process yet.
