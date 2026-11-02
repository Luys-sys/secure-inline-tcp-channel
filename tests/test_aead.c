#include <stdio.h>
#include <string.h>
#include "crypto.h"

int main(void)
{
    const uint8_t key[SIC_KEY_LEN] = {1};
    const uint8_t nonce[SIC_NONCE_LEN] = {2};
    const uint8_t aad[] = "authenticated metadata";
    const uint8_t input[] = "hello from PC1";
    uint8_t encrypted[sizeof(input)] = {0};
    uint8_t output[sizeof(input)] = {0};
    uint8_t tag[SIC_TAG_LEN] = {0};
    if (!sic_encrypt(key, nonce, aad, sizeof(aad), input, sizeof(input), encrypted, tag)) return 1;
    if (!sic_decrypt(key, nonce, aad, sizeof(aad), encrypted, sizeof(input), tag, output)) return 2;
    if (memcmp(input, output, sizeof(input)) != 0) return 3;
    tag[0] ^= 1;
    memset(output, 0xAA, sizeof(output));
    if (sic_decrypt(key, nonce, aad, sizeof(aad), encrypted, sizeof(input), tag, output)) return 4;
    for (size_t i = 0; i < sizeof(output); i++) if (output[i] != 0) return 5;
    puts("PASS: AES-256-GCM roundtrip and tamper rejection");
    return 0;
}
