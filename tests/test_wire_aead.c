#include "wire_aead.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void init(sic_sender *s, sic_receiver *r) {
    memset(s, 0, sizeof(*s)); memset(r, 0, sizeof(*r));
    for (int i = 0; i < 32; ++i) s->key[i] = (uint8_t)(i + 5);
    memcpy(r->key, s->key, 32);
    s->salt[0] = 0xA1; s->salt[1] = 0xB2; s->salt[2] = 0xC3; s->salt[3] = 0xD4;
    memcpy(r->salt, s->salt, 4);
}
int main(void) {
    sic_sender s; sic_receiver r; init(&s, &r);
    const uint8_t aad[] = "fixed canonical TCP header fields";
    uint8_t c[5][100], out[100]; size_t lengths[5], n;
    for (int i = 0; i < 5; i++) {
        const uint8_t p[] = "hello from PC1";
        assert(sic_encrypt(&s, aad, sizeof(aad), p, sizeof(p), c[i], sizeof(c[i]), &lengths[i]));
        assert(lengths[i] == sizeof(p) + SIC_TAG_BYTES);
        assert(memcmp(c[0], c[i], lengths[0]) != 0 || i == 0);
    }
    /* Deliberate packet reordering: 0,2,1,4,3. */
    int order[] = {0,2,1,4,3};
    for (int i=0; i<5; i++) {
        int j=order[i];
        assert(sic_decrypt(&r, aad, sizeof(aad), c[j], lengths[j], out, sizeof(out), &n));
        assert(n == sizeof("hello from PC1"));
        assert(memcmp(out, "hello from PC1", n) == 0);
    }
    puts("PASS: distinct nonces, authenticated decrypt, bounded reordering");
    assert(!sic_decrypt(&r, aad, sizeof(aad), c[2], lengths[2], out, sizeof(out), &n));
    puts("PASS: packet replay rejected");
    sic_sender s2; sic_receiver r2; init(&s2, &r2);
    uint8_t tampered[100]; memcpy(tampered, c[0], lengths[0]);
    tampered[0] ^= 1;
    memset(out, 0xA5, sizeof(out));
    assert(!sic_decrypt(&r2, aad, sizeof(aad), tampered, lengths[0], out, sizeof(out), &n));
    assert(out[0] == 0xA5);
    assert(!sic_decrypt(&r2, (const uint8_t *)"wrong", 5, c[0], lengths[0], out, sizeof(out), &n));
    assert(sic_decrypt(&r2, aad, sizeof(aad), c[0], lengths[0], out, sizeof(out), &n));
    puts("PASS: tampering/AAD mismatch rejected without releasing plaintext");
    return 0;
}
