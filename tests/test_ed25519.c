#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

int main(void)
{
    EVP_PKEY_CTX *key_ctx = NULL;
    EVP_PKEY *identity_key = NULL;
    EVP_MD_CTX *sign_ctx = NULL;
    EVP_MD_CTX *verify_ctx = NULL;

    const unsigned char message[] =
        "Device1 ephemeral key and handshake transcript";

    const unsigned char modified[] =
        "Device2 ephemeral key and handshake transcript";

    unsigned char signature[64];
    size_t signature_len = sizeof(signature);

    int result = 1;

    key_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!key_ctx) goto cleanup;

    if (EVP_PKEY_keygen_init(key_ctx) <= 0)
        goto cleanup;

    if (EVP_PKEY_keygen(key_ctx, &identity_key) <= 0)
        goto cleanup;

    sign_ctx = EVP_MD_CTX_new();
    verify_ctx = EVP_MD_CTX_new();

    if (!sign_ctx || !verify_ctx)
        goto cleanup;

    if (EVP_DigestSignInit(
            sign_ctx, NULL, NULL, NULL, identity_key) <= 0)
        goto cleanup;

    if (EVP_DigestSign(
            sign_ctx,
            signature,
            &signature_len,
            message,
            sizeof(message) - 1) <= 0)
        goto cleanup;

    if (EVP_DigestVerifyInit(
            verify_ctx, NULL, NULL, NULL, identity_key) <= 0)
        goto cleanup;

    if (EVP_DigestVerify(
            verify_ctx,
            signature,
            signature_len,
            message,
            sizeof(message) - 1) != 1)
        goto cleanup;

    printf("PASS: Valid Ed25519 signature verified.\n");

    if (EVP_DigestVerify(
            verify_ctx,
            signature,
            signature_len,
            modified,
            sizeof(modified) - 1) != 0)
        goto cleanup;

    printf("PASS: Modified handshake rejected.\n");

    result = 0;

cleanup:
    if (result != 0)
        fprintf(stderr, "FAIL: Ed25519 authentication.\n");

    EVP_MD_CTX_free(sign_ctx);
    EVP_MD_CTX_free(verify_ctx);
    EVP_PKEY_CTX_free(key_ctx);
    EVP_PKEY_free(identity_key);

    return result;
}
