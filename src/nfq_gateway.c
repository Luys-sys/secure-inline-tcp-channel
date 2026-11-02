#define _POSIX_C_SOURCE 200809L
#include "gateway_packet.h"
#include "packet.h"
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
} gateway_ctx;

static int load_lab_key(const char *path, uint8_t material[LAB_KEY_LENGTH]) {
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode) ||
        (st.st_mode & (S_IRWXG | S_IRWXO)) != 0 ||
        st.st_size != (off_t)LAB_KEY_LENGTH) return 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return 0;
    size_t done = 0;
    while (done < LAB_KEY_LENGTH) {
        ssize_t n = read(fd, material + done, LAB_KEY_LENGTH - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { close(fd); return 0; }
        done += (size_t)n;
    }
    close(fd);
    return 1;
}

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
    if (sic_parse_tcp4(payload, (size_t)len, &view) != 0) goto drop;
    /* Lab rule must select a single TCP data direction. ACK/control frames
       without payload are passed through unchanged. */
    if (view.payload_len == 0) {
        ctx->accepted++;
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
    fprintf(stderr,
        "[GATEWAY DROP] mode=%s "
        "packet_len=%d payload_len=%zu "
        "expanded_len=%zu result=%d\n",
        ctx->encrypt ? "encrypt" : "decrypt",
        len,
        view.payload_len,
        (size_t)len + SIC_TAG_BYTES,
        rc);
    goto drop;
}

    ctx->accepted++;
    return nfq_set_verdict(queue, id, NF_ACCEPT, (uint32_t)new_len, modified);
drop:
    ctx->dropped++;
    return nfq_set_verdict(queue, id, NF_DROP, 0, NULL);
}

int main(int argc, char **argv) {
    if (argc != 4 || (strcmp(argv[1], "encrypt") && strcmp(argv[1], "decrypt"))) {
        fprintf(stderr, "Usage: %s encrypt|decrypt queue-number secrets/lab-direction.bin\n", argv[0]);
        return 2;
    }
    char *end = NULL;
    errno = 0;
    unsigned long q = strtoul(argv[2], &end, 10);
    if (errno || !end || *end || q > 65535UL) {
        fprintf(stderr, "Invalid queue number\n"); return 2;
    }
    uint8_t material[LAB_KEY_LENGTH] = {0};
    if (!load_lab_key(argv[3], material)) {
        fprintf(stderr, "Key must be exactly 36 bytes in a private mode-0600 regular file\n");
        return 1;
    }
    gateway_ctx state = {0};
    state.encrypt = strcmp(argv[1], "encrypt") == 0;
    if (state.encrypt) {
        memcpy(state.tx.key, material, SIC_KEY_BYTES);
        memcpy(state.tx.salt, material + SIC_KEY_BYTES, SIC_SALT_BYTES);
    } else {
        memcpy(state.rx.key, material, SIC_KEY_BYTES);
        memcpy(state.rx.salt, material + SIC_KEY_BYTES, SIC_SALT_BYTES);
    }
    OPENSSL_cleanse(material, sizeof(material));

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
    fprintf(stderr, "LAB-ONLY %s queue=%lu: authenticated handshake NOT connected; do not deploy\n",
            state.encrypt ? "encrypt" : "decrypt", q);
    while (keep_running) {
        ssize_t n = recv(fd, recvbuf, sizeof(recvbuf), 0);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { perror("nfqueue recv"); break; }
        if (n > 0 && nfq_handle_packet(h, (char *)recvbuf, (int)n) < 0) {
            fprintf(stderr, "nfqueue handler error\n"); break;
        }
    }
    fprintf(stderr, "accepted=%lu dropped=%lu\n", state.accepted, state.dropped);
    nfq_destroy_queue(queue);
    nfq_close(h);
    OPENSSL_cleanse(&state, sizeof(state));
    return 0;
}
