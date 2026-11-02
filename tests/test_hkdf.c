#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>

#define KEY_LEN 32

static int derive_key(const unsigned char *secret, size_t secret_len,
                      const unsigned char *salt, size_t salt_len,
                      const char *label, unsigned char output[KEY_LEN])
{
    int ok = 0;
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *ctx = NULL;
    if (kdf == NULL) return 0;
    ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (ctx == NULL) return 0;

    char digest[] = "SHA256";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)secret, secret_len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, salt_len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)label, strlen(label)),
        OSSL_PARAM_construct_end()
    };
    ok = EVP_KDF_derive(ctx, output, KEY_LEN, params) == 1;
    EVP_KDF_CTX_free(ctx);
    return ok;
}

int main(void)
{
    /* Fixed vectors are ONLY for reproducible unit tests, never real sessions. */
    const unsigned char shared_secret[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    const unsigned char salt[16] = {
        0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
        0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f
    };
    unsigned char d1_to_d2[KEY_LEN] = {0};
    unsigned char d2_to_d1[KEY_LEN] = {0};
    unsigned char repeat[KEY_LEN] = {0};
    int result = 1;

    if (!derive_key(shared_secret, sizeof shared_secret, salt, sizeof salt,
                    "secure-inline/v1/device1-to-device2", d1_to_d2)) goto done;
    if (!derive_key(shared_secret, sizeof shared_secret, salt, sizeof salt,
                    "secure-inline/v1/device2-to-device1", d2_to_d1)) goto done;
    if (!derive_key(shared_secret, sizeof shared_secret, salt, sizeof salt,
                    "secure-inline/v1/device1-to-device2", repeat)) goto done;
    if (CRYPTO_memcmp(d1_to_d2, repeat, KEY_LEN) != 0) goto done;
    if (CRYPTO_memcmp(d1_to_d2, d2_to_d1, KEY_LEN) == 0) goto done;
    puts("PASS: HKDF-SHA256 deterministic derivation and directional key separation");
    result = 0;
done:
    if (result) fputs("FAIL: HKDF-SHA256 test\n", stderr);
    OPENSSL_cleanse(d1_to_d2, sizeof d1_to_d2);
    OPENSSL_cleanse(d2_to_d1, sizeof d2_to_d1);
    OPENSSL_cleanse(repeat, sizeof repeat);
    return result;
}
