#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>

#define PUB_LEN 32
#define NONCE_LEN 32
#define SIG_LEN 64
#define KEY_LEN 32
#define TRANSCRIPT_LEN (sizeof("INLINE-C-SESSION-v1") - 1 + 2*PUB_LEN + 2*NONCE_LEN)

static EVP_PKEY *new_key(int type) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(type, NULL);
    EVP_PKEY *key = NULL;
    if (!ctx) return NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &key) <= 0) {
        EVP_PKEY_free(key); key = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
}
static int public_bytes(EVP_PKEY *key, unsigned char out[PUB_LEN]) {
    size_t len = PUB_LEN;
    return EVP_PKEY_get_raw_public_key(key, out, &len) == 1 && len == PUB_LEN;
}
static int derive(EVP_PKEY *own, const unsigned char peer[PUB_LEN], unsigned char secret[KEY_LEN]) {
    EVP_PKEY *peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer, PUB_LEN);
    EVP_PKEY_CTX *ctx = NULL;
    size_t len = KEY_LEN;
    int ok = 0;
    if (!peer_key) goto done;
    ctx = EVP_PKEY_CTX_new(own, NULL);
    if (!ctx || EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0 ||
        EVP_PKEY_derive(ctx, secret, &len) <= 0 || len != KEY_LEN) goto done;
    ok = 1;
done:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_key);
    return ok;
}
static int sign_data(EVP_PKEY *identity, const unsigned char *data, size_t len,
                     unsigned char sig[SIG_LEN]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    size_t size = SIG_LEN;
    int ok = ctx && EVP_DigestSignInit(ctx, NULL, NULL, NULL, identity) == 1 &&
             EVP_DigestSign(ctx, sig, &size, data, len) == 1 && size == SIG_LEN;
    EVP_MD_CTX_free(ctx);
    return ok;
}
static int verify_data(EVP_PKEY *trusted, const unsigned char *data, size_t len,
                       const unsigned char sig[SIG_LEN]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = ctx && EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, trusted) == 1 &&
             EVP_DigestVerify(ctx, sig, SIG_LEN, data, len) == 1;
    EVP_MD_CTX_free(ctx);
    return ok;
}
static int hkdf(const unsigned char secret[KEY_LEN], const unsigned char *salt,
                size_t salt_len, const char *direction, unsigned char key[KEY_LEN]) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    size_t len = KEY_LEN;
    int ok = ctx && EVP_PKEY_derive_init(ctx) == 1 &&
             EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) == 1 &&
             EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, (int)salt_len) == 1 &&
             EVP_PKEY_CTX_set1_hkdf_key(ctx, secret, KEY_LEN) == 1 &&
             EVP_PKEY_CTX_add1_hkdf_info(ctx, (const unsigned char *)direction,
                                         (int)strlen(direction)) == 1 &&
             EVP_PKEY_derive(ctx, key, &len) == 1 && len == KEY_LEN;
    EVP_PKEY_CTX_free(ctx);
    return ok;
}
int main(void) {
    EVP_PKEY *id1 = NULL, *id2 = NULL, *eph1 = NULL, *eph2 = NULL;
    unsigned char p1[PUB_LEN], p2[PUB_LEN], n1[NONCE_LEN], n2[NONCE_LEN];
    unsigned char transcript[TRANSCRIPT_LEN], msg1[TRANSCRIPT_LEN + 2], msg2[TRANSCRIPT_LEN + 2];
    unsigned char sig1[SIG_LEN], sig2[SIG_LEN], s1[KEY_LEN] = {0}, s2[KEY_LEN] = {0};
    unsigned char k12a[KEY_LEN] = {0}, k12b[KEY_LEN] = {0};
    unsigned char k21a[KEY_LEN] = {0}, k21b[KEY_LEN] = {0};
    unsigned char salt[NONCE_LEN * 2];
    size_t offset = 0;
    int rc = 1;

    /* In this test each endpoint trusts the other endpoint's pre-provisioned identity key. */
    id1 = new_key(EVP_PKEY_ED25519); id2 = new_key(EVP_PKEY_ED25519);
    eph1 = new_key(EVP_PKEY_X25519); eph2 = new_key(EVP_PKEY_X25519);
    if (!id1 || !id2 || !eph1 || !eph2 ||
        !public_bytes(eph1,p1) || !public_bytes(eph2,p2) ||
        RAND_bytes(n1, sizeof n1) != 1 || RAND_bytes(n2, sizeof n2) != 1) goto done;

    const char domain[] = "INLINE-C-SESSION-v1";
    memcpy(transcript + offset, domain, sizeof(domain)-1); offset += sizeof(domain)-1;
    memcpy(transcript + offset, p1, PUB_LEN); offset += PUB_LEN;
    memcpy(transcript + offset, p2, PUB_LEN); offset += PUB_LEN;
    memcpy(transcript + offset, n1, NONCE_LEN); offset += NONCE_LEN;
    memcpy(transcript + offset, n2, NONCE_LEN); offset += NONCE_LEN;
    if (offset != sizeof transcript) goto done;
    memcpy(msg1, "I:", 2); memcpy(msg1+2, transcript, sizeof transcript);
    memcpy(msg2, "R:", 2); memcpy(msg2+2, transcript, sizeof transcript);
    if (!sign_data(id1, msg1, sizeof msg1, sig1) ||
        !sign_data(id2, msg2, sizeof msg2, sig2) ||
        !verify_data(id1, msg1, sizeof msg1, sig1) ||
        !verify_data(id2, msg2, sizeof msg2, sig2)) goto done;
    puts("PASS: Both authenticated handshake signatures verified");

    /* A modified transcript MUST fail authentication. */
    msg2[sizeof(msg2)-1] ^= 0x01;
    if (verify_data(id2, msg2, sizeof msg2, sig2)) goto done;
    msg2[sizeof(msg2)-1] ^= 0x01;
    puts("PASS: Modified handshake transcript rejected");

    if (!derive(eph1, p2, s1) || !derive(eph2, p1, s2) ||
        CRYPTO_memcmp(s1, s2, KEY_LEN) != 0) goto done;
    memcpy(salt, n1, NONCE_LEN); memcpy(salt + NONCE_LEN, n2, NONCE_LEN);
    if (!hkdf(s1, salt, sizeof salt, "inline-v1 key initiator-to-responder", k12a) ||
        !hkdf(s2, salt, sizeof salt, "inline-v1 key initiator-to-responder", k12b) ||
        !hkdf(s1, salt, sizeof salt, "inline-v1 key responder-to-initiator", k21a) ||
        !hkdf(s2, salt, sizeof salt, "inline-v1 key responder-to-initiator", k21b) ||
        CRYPTO_memcmp(k12a, k12b, KEY_LEN) != 0 ||
        CRYPTO_memcmp(k21a, k21b, KEY_LEN) != 0 ||
        CRYPTO_memcmp(k12a, k21a, KEY_LEN) == 0) goto done;
    puts("PASS: Direction-separated session keys match across endpoints");
    rc = 0;
done:
    if (rc) fputs("FAIL: Authenticated session test\n", stderr);
    OPENSSL_cleanse(s1, sizeof s1); OPENSSL_cleanse(s2, sizeof s2);
    OPENSSL_cleanse(k12a, sizeof k12a); OPENSSL_cleanse(k12b, sizeof k12b);
    OPENSSL_cleanse(k21a, sizeof k21a); OPENSSL_cleanse(k21b, sizeof k21b);
    EVP_PKEY_free(id1); EVP_PKEY_free(id2); EVP_PKEY_free(eph1); EVP_PKEY_free(eph2);
    return rc;
}
