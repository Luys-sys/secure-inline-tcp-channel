#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#define SECRET_SIZE 32

int main(void)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY_CTX *derive_ctx = NULL;
    EVP_PKEY *device1 = NULL;
    EVP_PKEY *device2 = NULL;

    unsigned char secret1[SECRET_SIZE] = {0};
    unsigned char secret2[SECRET_SIZE] = {0};

    size_t len1 = sizeof(secret1);
    size_t len2 = sizeof(secret2);
    int result = 1;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx) goto cleanup;

    if (EVP_PKEY_keygen_init(ctx) <= 0) goto cleanup;
    if (EVP_PKEY_keygen(ctx, &device1) <= 0) goto cleanup;
    if (EVP_PKEY_keygen(ctx, &device2) <= 0) goto cleanup;

    derive_ctx = EVP_PKEY_CTX_new(device1, NULL);
    if (!derive_ctx) goto cleanup;

    if (EVP_PKEY_derive_init(derive_ctx) <= 0) goto cleanup;
    if (EVP_PKEY_derive_set_peer(derive_ctx, device2) <= 0)
        goto cleanup;
    if (EVP_PKEY_derive(derive_ctx, secret1, &len1) <= 0)
        goto cleanup;

    EVP_PKEY_CTX_free(derive_ctx);
    derive_ctx = EVP_PKEY_CTX_new(device2, NULL);
    if (!derive_ctx) goto cleanup;

    if (EVP_PKEY_derive_init(derive_ctx) <= 0) goto cleanup;
    if (EVP_PKEY_derive_set_peer(derive_ctx, device1) <= 0)
        goto cleanup;
    if (EVP_PKEY_derive(derive_ctx, secret2, &len2) <= 0)
        goto cleanup;

    if (len1 != SECRET_SIZE || len2 != SECRET_SIZE)
        goto cleanup;

    if (CRYPTO_memcmp(secret1, secret2, SECRET_SIZE) != 0)
        goto cleanup;

    printf("PASS: X25519 shared secrets match.\n");
    result = 0;

cleanup:
    if (result != 0)
        fprintf(stderr, "FAIL: X25519 key exchange.\n");

    OPENSSL_cleanse(secret1, sizeof(secret1));
    OPENSSL_cleanse(secret2, sizeof(secret2));

    EVP_PKEY_CTX_free(derive_ctx);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(device1);
    EVP_PKEY_free(device2);

    return result;
}
