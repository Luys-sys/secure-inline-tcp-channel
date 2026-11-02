CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -Werror -O2
handshake:
	$(CC) $(CFLAGS) src/handshake.c -o handshake -lcrypto
