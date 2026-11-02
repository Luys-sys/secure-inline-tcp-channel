#include "wire_aead.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

static void nonce_for(const uint8_t salt[4], uint64_t counter, uint8_t nonce[12]) {
    memcpy(nonce, salt, 4);
    for (int i = 0; i < 8; ++i) nonce[4 + i] = (uint8_t)(counter >> (56 - 8 * i));
}

static int valid_inputs(const uint8_t *aad, size_t aad_len,
                        const uint8_t *data, size_t data_len) {
    return (aad_len == 0 || aad != NULL) && (data_len == 0 || data != NULL)
           && aad_len <= INT_MAX && data_len <= INT_MAX;
}

int sic_encrypt(sic_sender *s, const uint8_t *aad, size_t aad_len,
                const uint8_t *plain, size_t plain_len,
                uint8_t *out, size_t out_cap, size_t *out_len) {
    if (!s || !out || !out_len || !valid_inputs(aad, aad_len, plain, plain_len)
        || plain_len > SIZE_MAX - SIC_TAG_BYTES
        || out_cap < plain_len + SIC_TAG_BYTES || s->next_counter == UINT64_MAX)
        return 0;
    *out_len = 0;
    uint8_t nonce[12]; nonce_for(s->salt, s->next_counter, nonce);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;
    int n = 0, total = 0, ok = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, s->key, nonce) != 1) goto done;
    if (aad_len && EVP_EncryptUpdate(ctx, NULL, &n, aad, (int)aad_len) != 1) goto done;
    if (plain_len && EVP_EncryptUpdate(ctx, out, &n, plain, (int)plain_len) != 1) goto done;
    total = n;
    if (EVP_EncryptFinal_ex(ctx, out + total, &n) != 1) goto done;
    total += n;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out + total) != 1) goto done;
    *out_len = (size_t)total + 16;
    s->next_counter++;
    ok = 1;
done:
    if (!ok) OPENSSL_cleanse(out, out_cap);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int trial(const sic_receiver *r, uint64_t counter,
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *packet, size_t cipher_len,
                 uint8_t *tmp) {
    uint8_t nonce[12]; nonce_for(r->salt, counter, nonce);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;
    int n = 0, total = 0, ok = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, r->key, nonce) != 1) goto done;
    if (aad_len && EVP_DecryptUpdate(ctx, NULL, &n, aad, (int)aad_len) != 1) goto done;
    if (cipher_len && EVP_DecryptUpdate(ctx, tmp, &n, packet, (int)cipher_len) != 1) goto done;
    total = n;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                             (void *)(packet + cipher_len)) != 1) goto done;
    if (EVP_DecryptFinal_ex(ctx, tmp + total, &n) != 1) goto done;
    ok = 1;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

int sic_decrypt(sic_receiver *r, const uint8_t *aad, size_t aad_len,
                const uint8_t *packet, size_t packet_len,
                uint8_t *out, size_t out_cap, size_t *out_len) {
    if (!r || !out || !out_len || packet_len < SIC_TAG_BYTES
        || !valid_inputs(aad, aad_len, packet, packet_len)) return 0;
    size_t cipher_len = packet_len - SIC_TAG_BYTES;
    if (out_cap < cipher_len || cipher_len == SIZE_MAX) return 0;
    *out_len = 0;
    uint8_t *tmp = malloc(cipher_len + 1);
    if (!tmp) return 0;
    int success = 0;
    uint64_t start = r->initialized ? r->highest + (r->highest != UINT64_MAX) : 0;
    for (uint64_t d = 0; d < SIC_REPLAY_WINDOW; ++d) {
        if (d > UINT64_MAX - start) break;
        uint64_t c = start + d;
        if (r->initialized && c <= r->highest) break;
        if (trial(r, c, aad, aad_len, packet, cipher_len, tmp)) {
            if (!r->initialized) {
                r->seen_bitmap = 1;
            } else {
                uint64_t shift = c - r->highest;
                r->seen_bitmap = shift >= 64 ? 1 : (r->seen_bitmap << shift) | 1U;
            }
            r->highest = c;
            r->initialized = 1;
            success = 1;
            break;
        }
    }
    if (!success && r->initialized) {
        for (uint64_t diff = 0; diff < SIC_REPLAY_WINDOW && diff <= r->highest; ++diff) {
            if ((r->seen_bitmap >> diff) & 1U) continue;
            uint64_t c = r->highest - diff;
            if (trial(r, c, aad, aad_len, packet, cipher_len, tmp)) {
                r->seen_bitmap |= (UINT64_C(1) << diff);
                success = 1;
                break;
            }
        }
    }
    if (success) {
        if (cipher_len) memcpy(out, tmp, cipher_len);
        *out_len = cipher_len;
    }
    OPENSSL_cleanse(tmp, cipher_len + 1);
    free(tmp);
    return success;
}
