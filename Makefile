CC = gcc
CFLAGS = -std=c11 -O2 -Wall -Wextra -Werror -Iinclude
CRYPTO = -lcrypto
NFQLIBS = $(shell pkg-config --cflags --libs libnetfilter_queue 2>/dev/null)
.PHONY: all test clean
all: handshake nfq_gateway
handshake: src/handshake.c include/handshake.h
	$(CC) $(CFLAGS) $< -o $@ $(CRYPTO)
nfq_gateway: src/nfq_gateway.c src/packet.c src/wire_aead.c src/gateway_packet.c src/handshake.c include/handshake.h
	$(CC) $(CFLAGS) -DSIC_HANDSHAKE_LIBRARY src/nfq_gateway.c src/packet.c src/wire_aead.c src/gateway_packet.c src/handshake.c -o $@ $(NFQLIBS) $(CRYPTO)
test_packet: src/packet.c tests/test_packet.c
	$(CC) $(CFLAGS) $^ -o $@
test_gateway_packet: src/packet.c src/wire_aead.c src/gateway_packet.c tests/test_gateway_packet.c
	$(CC) $(CFLAGS) $^ -o $@ $(CRYPTO)
test_wire_aead: src/wire_aead.c tests/test_wire_aead.c
	$(CC) $(CFLAGS) $^ -o $@ $(CRYPTO)
test_aead: src/crypto.c tests/test_aead.c
	$(CC) $(CFLAGS) $^ -o $@ $(CRYPTO)
test_hkdf: tests/test_hkdf.c
	$(CC) $(CFLAGS) $^ -o $@ $(CRYPTO)
test_session: tests/test_session.c
	$(CC) $(CFLAGS) $^ -o $@ $(CRYPTO)
test: test_packet test_gateway_packet test_wire_aead test_aead test_hkdf test_session
	@for t in test_packet test_gateway_packet test_wire_aead test_aead test_hkdf test_session; do ./$$t || exit 1; done
clean:
	rm -f handshake nfq_gateway test_packet test_gateway_packet test_wire_aead test_aead test_hkdf test_session test_live_handshake

# Two independent processes exchange ephemeral public keys and validate
# cross-direction equality without persisting session material.
test_live_handshake: src/handshake.c tests/test_live_handshake.c include/handshake.h
	$(CC) $(CFLAGS) -DSIC_HANDSHAKE_LIBRARY src/handshake.c tests/test_live_handshake.c -o $@ $(CRYPTO)
