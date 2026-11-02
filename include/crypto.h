#ifndef SIC_CRYPTO_H
#define SIC_CRYPTO_H
#include <stddef.h>
#include <stdint.h>
#define SIC_KEY_LEN 32
#define SIC_NONCE_LEN 12
#define SIC_TAG_LEN 16
int sic_encrypt(const uint8_t key[SIC_KEY_LEN], const uint8_t nonce[SIC_NONCE_LEN], const uint8_t *aad, size_t aad_len, const uint8_t *plaintext, size_t len, uint8_t *ciphertext, uint8_t tag[SIC_TAG_LEN]);
int sic_decrypt(const uint8_t key[SIC_KEY_LEN], const uint8_t nonce[SIC_NONCE_LEN], const uint8_t *aad, size_t aad_len, const uint8_t *ciphertext, size_t len, const uint8_t tag[SIC_TAG_LEN], uint8_t *plaintext);
#endif
