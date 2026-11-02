# Protocol design – development decisions

## Current implemented scope

The `handshake` binary is a **control-plane-only proof of concept**. It authenticates the two gateways using *offline provisioned* Ed25519 public keys, exchanges fresh X25519 ephemeral public keys over a dedicated TCP connection between Device1 and Device2, derives keys with HKDF-SHA256, and confirms possession of the negotiated shared secret using HMAC-SHA256. It does not encrypt or forward PC1/PC2 data traffic. Ephemeral keys and session keys are process-local and erased on exit.

The fixed-size control messages are **not headers on protected TCP packets**. The protected data plane remains unimplemented. Transport security of the handshake assumes both pinned identities were correctly provisioned. The client is Device1, the server is Device2, on TCP port 45454.

## Critical open design issue

The assignment asks to preserve original IP/TCP headers and append a 16-byte GCM tag to every encrypted TCP payload, with no encapsulation or custom header. These requirements do not by themselves specify a recoverable unique nonce per packet, a safe response to loss and reordering, or how an expanded packet fits within the path MTU. TCP sequence numbers represent the original plaintext byte stream, not authenticated ciphertext+tags. An inline gateway must remove tags before delivery and must avoid exposing their additional bytes to endpoint TCP sequence accounting. However, in-network TCP normalization/offload/segmentation and packet retransmission can alter packet boundaries, so packet-by-packet nonce recovery is not automatically reliable.

Do **not** claim secure inline data transport until an explicit, tested mechanism for the nonce, retransmission, packet boundary, replay and MTU constraints is specified. The present handshake is not a complete secure channel.

## Future acceptance tests

- A real TCP client on PC1 connects to PC2 through both gateways.
- Packet capture on Device1–Device2 link demonstrates payload confidentiality and the exact on-wire format.
- PC2 receives byte-identical plaintext.
- Corrupted tags fail closed.
- Duplicates, packet reordering and retransmission are safely handled.
- No nonce repeats under the same directional key, including after restarts.
- Path MTU and checksum corrections are demonstrated.
