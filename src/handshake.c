#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include "handshake.h"

#define HELLO_SIZE 68
#define SIG_SIZE 64
#define FIN_SIZE 32
#define KEY_SIZE 32
#define PORT 45454
#define VERSION 1
static const unsigned char prefix[] = "SIC-control-v1";

static int read_exact(int fd, void *buf, size_t n) {
    unsigned char *p = buf;
    while (n) { ssize_t r = recv(fd, p, n, 0); if (r <= 0) return 0; p += r; n -= (size_t)r; }
    return 1;
}
static int write_exact(int fd, const void *buf, size_t n) {
    const unsigned char *p = buf;
    while (n) { ssize_t r = send(fd, p, n, MSG_NOSIGNAL); if (r <= 0) return 0; p += r; n -= (size_t)r; }
    return 1;
}
static EVP_PKEY *load_private(const char *file) {
    FILE *f = fopen(file, "r"); if (!f) return NULL;
    EVP_PKEY *p = PEM_read_PrivateKey(f, NULL, NULL, NULL); fclose(f);
    if (p && EVP_PKEY_id(p) != EVP_PKEY_ED25519) { EVP_PKEY_free(p); return NULL; }
    return p;
}
static EVP_PKEY *load_public(const char *file) {
    FILE *f = fopen(file, "r"); if (!f) return NULL;
    EVP_PKEY *p = PEM_read_PUBKEY(f, NULL, NULL, NULL); fclose(f);
    if (p && EVP_PKEY_id(p) != EVP_PKEY_ED25519) { EVP_PKEY_free(p); return NULL; }
    return p;
}
static EVP_PKEY *make_ephemeral(unsigned char pub[32]) {
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    size_t len = 32;
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &key) <= 0 ||
        EVP_PKEY_get_raw_public_key(key, pub, &len) <= 0 || len != 32) {
        EVP_PKEY_free(key); key = NULL;
    }
    EVP_PKEY_CTX_free(ctx); return key;
}
static int sign_data(EVP_PKEY *key, const unsigned char *msg, size_t n, unsigned char sig[SIG_SIZE]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new(); size_t len = SIG_SIZE;
    int ok = ctx && EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) > 0 &&
        EVP_DigestSign(ctx, sig, &len, msg, n) > 0 && len == SIG_SIZE;
    EVP_MD_CTX_free(ctx); return ok;
}
static int verify_data(EVP_PKEY *key, const unsigned char *msg, size_t n, const unsigned char sig[SIG_SIZE]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = ctx && EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) > 0 &&
        EVP_DigestVerify(ctx, sig, SIG_SIZE, msg, n) == 1;
    EVP_MD_CTX_free(ctx); return ok;
}
static int derive_key(EVP_PKEY *my_eph, const unsigned char peer_pub[32],
                      const unsigned char digest[32], const char *label, unsigned char *out, size_t requested) {
    int ok = 0; unsigned char shared[32] = {0}; size_t shared_n = 32, out_n = requested;
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub, 32);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(my_eph, NULL);
    EVP_PKEY_CTX *kdf = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (peer && ctx && kdf && EVP_PKEY_derive_init(ctx) > 0 &&
        EVP_PKEY_derive_set_peer(ctx, peer) > 0 && EVP_PKEY_derive(ctx, shared, &shared_n) > 0 && shared_n == 32 &&
        EVP_PKEY_derive_init(kdf) > 0 && EVP_PKEY_CTX_set_hkdf_md(kdf, EVP_sha256()) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_salt(kdf, digest, 32) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_key(kdf, shared, 32) > 0 &&
        EVP_PKEY_CTX_add1_hkdf_info(kdf, (const unsigned char *)label, (int)strlen(label)) > 0 &&
        EVP_PKEY_derive(kdf, out, &out_n) > 0 && out_n == requested) ok = 1;
    OPENSSL_cleanse(shared, sizeof(shared)); EVP_PKEY_CTX_free(kdf); EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(peer);
    return ok;
}
static int mac(const unsigned char key[32], const unsigned char digest[32], const char *role, unsigned char out[32]) {
    unsigned char msg[64]; size_t n = strlen(role); unsigned int out_n = 0;
    if (n > 32) return 0;
    memcpy(msg, role, n); memcpy(msg+n, digest, 32);
    return HMAC(EVP_sha256(), key, 32, msg, n+32, out, &out_n) && out_n == 32;
}
static int run_handshake(int fd, int server, EVP_PKEY *identity, EVP_PKEY *trusted,
                         unsigned char out_tx[36], unsigned char out_rx[36]) {
    int ok = 0;
    unsigned char mine[HELLO_SIZE] = {0}, theirs[HELLO_SIZE] = {0};
    unsigned char signature[SIG_SIZE], peer_sig[SIG_SIZE];
    unsigned char transcript[sizeof(prefix)-1+2*HELLO_SIZE];
    unsigned char digest[32], confirm_key[32] = {0}, tx_key[36] = {0}, rx_key[36] = {0};
    unsigned char finished[FIN_SIZE], peer_finished[FIN_SIZE], expected[FIN_SIZE], public_eph[32];
    EVP_PKEY *eph = make_ephemeral(public_eph);
    if (!eph) goto end;
    memcpy(mine, "SIC1", 4); mine[4] = VERSION; mine[5] = server ? 2 : 1;
    if (RAND_bytes(mine+8, 28) != 1) goto end;
    memcpy(mine+36, public_eph, 32);
    // Both ends send first; short fixed-size handshake messages avoid framing ambiguity.
    if (!write_exact(fd, mine, HELLO_SIZE) || !read_exact(fd, theirs, HELLO_SIZE)) goto end;
    if (memcmp(theirs, "SIC1", 4) || theirs[4] != VERSION || theirs[5] != (server ? 1 : 2) ||
        theirs[6] != 0 || theirs[7] != 0) goto end;
    memcpy(transcript, prefix, sizeof(prefix)-1);
    if (server) {
        memcpy(transcript+sizeof(prefix)-1, theirs, HELLO_SIZE);
        memcpy(transcript+sizeof(prefix)-1+HELLO_SIZE, mine, HELLO_SIZE);
    } else {
        memcpy(transcript+sizeof(prefix)-1, mine, HELLO_SIZE);
        memcpy(transcript+sizeof(prefix)-1+HELLO_SIZE, theirs, HELLO_SIZE);
    }
    if (!SHA256(transcript, sizeof(transcript), digest)) goto end;
    // Both identities sign the same transcript, with explicit role binding.
    unsigned char signed_msg[33]; memcpy(signed_msg, digest, 32);
    signed_msg[32] = server ? 2 : 1;
    if (!sign_data(identity, signed_msg, sizeof(signed_msg), signature) ||
        !write_exact(fd, signature, SIG_SIZE) || !read_exact(fd, peer_sig, SIG_SIZE)) goto end;
    signed_msg[32] = server ? 1 : 2;
    if (!verify_data(trusted, signed_msg, sizeof(signed_msg), peer_sig)) goto end;
    if (!derive_key(eph, theirs+36, digest, "SIC1 confirmation", confirm_key, 32) ||
        !derive_key(eph, theirs+36, digest, server ? "SIC1 device2-to-device1" : "SIC1 device1-to-device2", tx_key, 36) ||
        !derive_key(eph, theirs+36, digest, server ? "SIC1 device1-to-device2" : "SIC1 device2-to-device1", rx_key, 36)) goto end;
    if (!mac(confirm_key, digest, server ? "server" : "client", finished) ||
        !mac(confirm_key, digest, server ? "client" : "server", expected)) goto end;
    if (!write_exact(fd, finished, FIN_SIZE) || !read_exact(fd, peer_finished, FIN_SIZE) ||
        CRYPTO_memcmp(peer_finished, expected, FIN_SIZE) != 0) goto end;
    memcpy(out_tx, tx_key, 36);
    memcpy(out_rx, rx_key, 36);
    printf("PASS: authenticated X25519 handshake and key confirmation (%s)\n", server ? "device2" : "device1");
    printf("PASS: directional session keys derived; keys are not printed or persisted\n");
    ok = 1;
end:
    OPENSSL_cleanse(signature, sizeof(signature)); OPENSSL_cleanse(peer_sig, sizeof(peer_sig));
    OPENSSL_cleanse(confirm_key, sizeof(confirm_key)); OPENSSL_cleanse(tx_key, sizeof(tx_key));
    OPENSSL_cleanse(rx_key, sizeof(rx_key)); OPENSSL_cleanse(finished, sizeof(finished));
    OPENSSL_cleanse(peer_finished, sizeof(peer_finished)); OPENSSL_cleanse(expected, sizeof(expected));
    EVP_PKEY_free(eph); return ok;
}
static int open_socket(int server, const char *ip) {
    int fd = socket(AF_INET, SOCK_STREAM, 0); if (fd < 0) return -1;
    struct timeval tv = { .tv_sec = 8, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_in addr = {0}; addr.sin_family = AF_INET; addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) { close(fd); return -1; }
    if (server) {
        int one = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) || listen(fd, 1)) { close(fd); return -1; }
        fprintf(stderr, "Device2 listening on %s:%d\n", ip, PORT);
        int c = accept(fd, NULL, NULL); close(fd); if (c < 0) return -1;
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        return c;
    }
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr))) { close(fd); return -1; }
    return fd;
}
int sic_authenticated_handshake(int server, const char *ip, const char *private_path,
                                const char *peer_public_path,
                                unsigned char tx_material[36], unsigned char rx_material[36]) {
    if (!ip || !private_path || !peer_public_path || !tx_material || !rx_material) return 0;
    memset(tx_material, 0, 36); memset(rx_material, 0, 36);
    signal(SIGPIPE, SIG_IGN);
    EVP_PKEY *own = load_private(private_path);
    EVP_PKEY *peer = load_public(peer_public_path);
    if (!own || !peer) {
        fprintf(stderr, "Cannot load identity keys\n");
        EVP_PKEY_free(own); EVP_PKEY_free(peer); return 0;
    }
    int fd = open_socket(server, ip);
    if (fd < 0) {
        perror("socket/connection");
        EVP_PKEY_free(own); EVP_PKEY_free(peer); return 0;
    }
    int ok = run_handshake(fd, server, own, peer, tx_material, rx_material);
    if (!ok) {
        fprintf(stderr, "FAIL: handshake authentication or key confirmation\n");
        OPENSSL_cleanse(tx_material, 36); OPENSSL_cleanse(rx_material, 36);
    }
    close(fd); EVP_PKEY_free(own); EVP_PKEY_free(peer);
    return ok;
}
#ifndef SIC_HANDSHAKE_LIBRARY
int main(int argc, char **argv) {
    if (argc != 5 || (strcmp(argv[1], "device1") && strcmp(argv[1], "device2"))) {
        fprintf(stderr, "Usage: %s device1|device2 peer-ip own-private.pem trusted-peer-public.pem\n", argv[0]); return 2;
    }
    unsigned char tx[36], rx[36];
    int ok = sic_authenticated_handshake(strcmp(argv[1], "device2") == 0,
                                          argv[2], argv[3], argv[4], tx, rx);
    OPENSSL_cleanse(tx, sizeof(tx)); OPENSSL_cleanse(rx, sizeof(rx));
    return ok ? 0 : 1;
}
#endif
