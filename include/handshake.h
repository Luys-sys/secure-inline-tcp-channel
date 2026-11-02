#ifndef SIC_HANDSHAKE_H
#define SIC_HANDSHAKE_H
/* 36-byte HKDF output: AES-256 key (32) || nonce salt (4), per direction.
   Nothing is stored on disk; caller must cleanse these buffers. */
int sic_authenticated_handshake(int server, const char *ip,
                                const char *private_path,
                                const char *peer_public_path,
                                unsigned char tx_material[36],
                                unsigned char rx_material[36]);
#endif
