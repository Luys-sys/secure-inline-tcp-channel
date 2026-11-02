#include "crypto.h"
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

static int valid_args(const uint8_t *key, const uint8_t *nonce,
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t *input, size_t len, uint8_t *output)
{
    return key && nonce && (aad_len == 0 || aad) && input && output &&
           len <= INT_MAX && aad_len <= INT_MAX;
}

int sic_encrypt(const uint8_t key[SIC_KEY_LEN], const uint8_t nonce[SIC_NONCE_LEN],
                const uint8_t *aad, size_t aad_len,
                const uint8_t *plaintext, size_t len,
                uint8_t *ciphertext, uint8_t tag[SIC_TAG_LEN])
{
    if (!tag || !valid_args(key, nonce, aad, aad_len, plaintext, len, ciphertext)) return 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;
    int n = 0, final_n = 0, ok = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto end;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, SIC_NONCE_LEN, NULL) != 1) goto end;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto end;
    if (aad_len && EVP_EncryptUpdate(ctx, NULL, &n, aad, (int)aad_len) != 1) goto end;
    if (EVP_EncryptUpdate(ctx, ciphertext, &n, plaintext, (int)len) != 1) goto end;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + n, &final_n) != 1) goto end;
    if ((size_t)(n + final_n) != len) goto end;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, SIC_TAG_LEN, tag) != 1) goto end;
    ok = 1;
end:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

int sic_decrypt(const uint8_t key[SIC_KEY_LEN], const uint8_t nonce[SIC_NONCE_LEN],
                const uint8_t *aad, size_t aad_len,
                const uint8_t *ciphertext, size_t len,
                const uint8_t tag[SIC_TAG_LEN], uint8_t *plaintext)
{
    if (!tag || !valid_args(key, nonce, aad, aad_len, ciphertext, len, plaintext)) return 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;
    int n = 0, final_n = 0, ok = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto end;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, SIC_NONCE_LEN, NULL) != 1) goto end;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto end;
    if (aad_len && EVP_DecryptUpdate(ctx, NULL, &n, aad, (int)aad_len) != 1) goto end;
    if (EVP_DecryptUpdate(ctx, plaintext, &n, ciphertext, (int)len) != 1) goto end;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, SIC_TAG_LEN, (void *)tag) != 1) goto end;
    if (EVP_DecryptFinal_ex(ctx, plaintext + n, &final_n) != 1) goto end;
    if ((size_t)(n + final_n) != len) goto end;
    ok = 1;
end:
    if (!ok) OPENSSL_cleanse(plaintext, len);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}
