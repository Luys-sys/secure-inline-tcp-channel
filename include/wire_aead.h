#ifndef SIC_WIRE_AEAD_H
#define SIC_WIRE_AEAD_H
#include <stddef.h>
#include <stdint.h>

#define SIC_KEY_BYTES 32U
#define SIC_SALT_BYTES 4U
#define SIC_TAG_BYTES 16U
#define SIC_NONCE_BYTES 12U
#define SIC_REPLAY_WINDOW 64U

typedef struct {
    uint8_t key[SIC_KEY_BYTES];
    uint8_t salt[SIC_SALT_BYTES];
    uint64_t next_counter;
} sic_sender;

typedef struct {
    uint8_t key[SIC_KEY_BYTES];
    uint8_t salt[SIC_SALT_BYTES];
    uint64_t highest;
    uint64_t seen_bitmap;
    int initialized;
} sic_receiver;

/* Returns 1 on success, 0 on failure. Output is ciphertext || 16-byte tag.
   Caller must ensure out_cap >= plain_len + SIC_TAG_BYTES. */
int sic_encrypt(sic_sender *s, const uint8_t *aad, size_t aad_len,
                const uint8_t *plain, size_t plain_len,
                uint8_t *out, size_t out_cap, size_t *out_len);

/* Returns 1 only for an authenticated, non-replayed packet. On failure,
   plaintext is not made visible through out and receiver state is unchanged.
   This bounded receiver searches at most 64 future packet counters and
   64 recent counters. NOT a general-purpose high-throughput design. */
int sic_decrypt(sic_receiver *r, const uint8_t *aad, size_t aad_len,
                const uint8_t *packet, size_t packet_len,
                uint8_t *out, size_t out_cap, size_t *out_len);
#endif
