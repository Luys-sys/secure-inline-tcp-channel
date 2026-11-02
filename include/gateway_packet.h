#ifndef SIC_GATEWAY_PACKET_H
#define SIC_GATEWAY_PACKET_H
#include <stddef.h>
#include <stdint.h>
#include "wire_aead.h"
/* Return 1 transformed, 0 unprotected/unsupported, -1 invalid/auth failure.
 * Packet input/output are IP datagrams (not Ethernet frames).
 * Only non-empty TCP payloads are transformed. On failure, receiver state
 * remains unchanged, and no candidate plaintext is released. */
int sic_protect_packet(sic_sender *s, const uint8_t *in, size_t len,
                       uint8_t *out, size_t cap, size_t mtu, size_t *out_len);
int sic_unprotect_packet(sic_receiver *r, const uint8_t *in, size_t len,
                         uint8_t *out, size_t cap, size_t *out_len);
#endif
