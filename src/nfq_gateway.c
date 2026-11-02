#define _POSIX_C_SOURCE 200809L
#include "gateway_packet.h"
#include "packet.h"
#include "handshake.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <openssl/crypto.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define LAB_KEY_LENGTH 36U
#define DATAGRAM_CAPACITY 65535U
static volatile sig_atomic_t keep_running = 1;
static void on_signal(int sig) { (void)sig; keep_running = 0; }

typedef struct {
    int encrypt;
    sic_sender tx;
    sic_receiver rx;
    unsigned long accepted;
    unsigned long dropped;
    unsigned long forwarded_data;
    unsigned long forwarded_control;
    unsigned long failed_parse;
    unsigned long failed_transform;
} gateway_ctx;

static int packet_callback(struct nfq_q_handle *queue, struct nfgenmsg *unused,
                           struct nfq_data *data, void *opaque) {
    (void)unused;
    gateway_ctx *ctx = opaque;
    struct nfqnl_msg_packet_hdr *hdr = nfq_get_msg_packet_hdr(data);
    if (!hdr) return -1; /* Cannot safely issue a verdict without an ID. */
    uint32_t id = ntohl(hdr->packet_id);
    unsigned char *payload = NULL;
    int len = nfq_get_payload(data, &payload);
    if (len < 0 || !payload) goto drop;
    sic_tcp_view view;
    if (sic_parse_tcp4(payload, (size_t)len, &view) != 0) {
        ctx->failed_parse++;
        fprintf(stderr, "DROP parse: packet_id=%u input_len=%d\n", id, len);
        goto drop;
    }
    /* Lab rule must select a single TCP data direction. ACK/control frames
       without payload are passed through unchanged. */
    if (view.payload_len == 0) {
        ctx->accepted++;
        ctx->forwarded_control++;
        return nfq_set_verdict(queue, id, NF_ACCEPT, 0, NULL);
    }
    uint8_t modified[DATAGRAM_CAPACITY];
    size_t new_len = 0;
    int rc = ctx->encrypt
        ? sic_protect_packet(&ctx->tx, payload, (size_t)len, modified,
                             sizeof(modified), 1500U, &new_len)
        : sic_unprotect_packet(&ctx->rx, payload, (size_t)len, modified,
                               sizeof(modified), &new_len);
    if (rc != 1 || new_len > UINT16_MAX) {
        ctx->failed_transform++;
        fprintf(stderr, "DROP transform: mode=%s packet_id=%u input_len=%d payload_len=%zu output_len=%zu rc=%d\n",
                ctx->encrypt ? "encrypt" : "decrypt", id, len, view.payload_len, new_len, rc);
        goto drop;
    }
    ctx->accepted++;
    ctx->forwarded_data++;
    return nfq_set_verdict(queue, id, NF_ACCEPT, (uint32_t)new_len, modified);
drop:
    ctx->dropped++;
    return nfq_set_verdict(queue, id, NF_DROP, 0, NULL);
}

int main(int argc, char **argv) {
    if (argc != 6 || (strcmp(argv[1], "device1") && strcmp(argv[1], "device2"))) {
        fprintf(stderr, "Usage: %s device1|device2 queue-number peer-ip own-private.pem trusted-peer-public.pem\n", argv[0]);
        return 2;
    }
    char *end = NULL;
    errno = 0;
    unsigned long q = strtoul(argv[2], &end, 10);
    if (errno || !end || *end || q > 65535UL) {
        fprintf(stderr, "Invalid queue number\n"); return 2;
    }
    uint8_t tx_material[36] = {0}, rx_material[36] = {0};
    int server = strcmp(argv[1], "device2") == 0;
    /* No local symmetric-key file: session secrets come from authenticated
       ephemeral X25519 and exist only for the lifetime of this process. */
    if (!sic_authenticated_handshake(server, argv[3], argv[4], argv[5],
                                     tx_material, rx_material)) return 1;
    gateway_ctx state = {0};
    state.encrypt = !server; /* Selected protected direction: PC1 -> PC2. */
    if (state.encrypt) {
        memcpy(state.tx.key, tx_material, SIC_KEY_BYTES);
        memcpy(state.tx.salt, tx_material + SIC_KEY_BYTES, SIC_SALT_BYTES);
    } else {
        memcpy(state.rx.key, rx_material, SIC_KEY_BYTES);
        memcpy(state.rx.salt, rx_material + SIC_KEY_BYTES, SIC_SALT_BYTES);
    }
    OPENSSL_cleanse(tx_material, sizeof(tx_material));
    OPENSSL_cleanse(rx_material, sizeof(rx_material));

    struct sigaction action = {0};
    action.sa_handler = on_signal;
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);

    struct nfq_handle *h = nfq_open();
    if (!h) { perror("nfq_open"); return 1; }
    /* Existing IPv4 binding might already exist on some kernels. */
    (void)nfq_unbind_pf(h, AF_INET);
    if (nfq_bind_pf(h, AF_INET) < 0) {
        perror("nfq_bind_pf"); nfq_close(h); return 1;
    }
    struct nfq_q_handle *queue = nfq_create_queue(h, (uint16_t)q, packet_callback, &state);
    if (!queue || nfq_set_mode(queue, NFQNL_COPY_PACKET, DATAGRAM_CAPACITY) < 0) {
        fprintf(stderr, "Failed to create/configure NFQUEUE\n");
        if (queue) nfq_destroy_queue(queue);
        nfq_close(h); return 1;
    }
    int fd = nfq_fd(h);
    uint8_t recvbuf[131072];
    fprintf(stderr, "Authenticated session active: %s queue=%lu\n",
            state.encrypt ? "encrypt" : "decrypt", q);
    while (keep_running) {
        ssize_t n = recv(fd, recvbuf, sizeof(recvbuf), 0);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { perror("nfqueue recv"); break; }
        if (n > 0 && nfq_handle_packet(h, (char *)recvbuf, (int)n) < 0) {
            fprintf(stderr, "nfqueue handler error\n"); break;
        }
    }
    fprintf(stderr, "accepted=%lu dropped=%lu data=%lu control=%lu parse_failed=%lu transform_failed=%lu\n",
            state.accepted, state.dropped, state.forwarded_data, state.forwarded_control,
            state.failed_parse, state.failed_transform);
    nfq_destroy_queue(queue);
    nfq_close(h);
    OPENSSL_cleanse(&state, sizeof(state));
    return 0;
}
