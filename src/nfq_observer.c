
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

static volatile sig_atomic_t running = 1;

static void stop_handler(int sig)
{
    (void)sig;
    running = 0;
}

static int on_packet(
    struct nfq_q_handle *queue,
    struct nfgenmsg *msg,
    struct nfq_data *data,
    void *context)
{
    (void)msg;
    (void)context;

    uint32_t id = 0;
    struct nfqnl_msg_packet_hdr *header =
        nfq_get_msg_packet_hdr(data);

    if (header != NULL)
        id = ntohl(header->packet_id);

    unsigned char *packet = NULL;
    int length = nfq_get_payload(data, &packet);

    if (length >= 20 && packet != NULL) {
        unsigned int version = packet[0] >> 4;
        unsigned int ip_len = (packet[0] & 0x0f) * 4U;

        if (version == 4 &&
            ip_len >= 20 &&
            ip_len <= (unsigned int)length &&
            packet[9] == 6 &&
            (unsigned int)length >= ip_len + 20U) {

            unsigned int tcp_len =
                ((packet[ip_len + 12] >> 4) & 0x0f) * 4U;

            unsigned int total_len =
                ((unsigned int)packet[2] << 8) | packet[3];

            if (tcp_len >= 20 &&
                total_len <= (unsigned int)length &&
                total_len >= ip_len + tcp_len) {

                unsigned int payload_len =
                    total_len - ip_len - tcp_len;

                printf(
                    "packet=%u IP/TCP payload=%u bytes\n",
                    id,
                    payload_len
                );
                fflush(stdout);
            }
        }
    }

    return nfq_set_verdict(
        queue,
        id,
        NF_ACCEPT,
        0,
        NULL
    );
}

int main(void)
{
    signal(SIGINT, stop_handler);
    signal(SIGTERM, stop_handler);

    struct nfq_handle *handle = nfq_open();
    if (handle == NULL) {
        perror("nfq_open");
        return EXIT_FAILURE;
    }

    if (nfq_unbind_pf(handle, AF_INET) < 0) {
        fprintf(stderr, "nfq_unbind_pf failed\n");
    }

    if (nfq_bind_pf(handle, AF_INET) < 0) {
        perror("nfq_bind_pf");
        nfq_close(handle);
        return EXIT_FAILURE;
    }

    struct nfq_q_handle *queue =
        nfq_create_queue(handle, 10, on_packet, NULL);

    if (queue == NULL) {
        fprintf(stderr, "Cannot create NFQUEUE 10\n");
        nfq_close(handle);
        return EXIT_FAILURE;
    }

    if (nfq_set_mode(queue, NFQNL_COPY_PACKET, 65535) < 0) {
        fprintf(stderr, "Cannot configure packet copy\n");
        nfq_destroy_queue(queue);
        nfq_close(handle);
        return EXIT_FAILURE;
    }

    int fd = nfq_fd(handle);
    unsigned char buffer[65536];

    printf("NFQUEUE observer started (queue 10)\n");
    fflush(stdout);

    while (running) {
        ssize_t received = recv(fd, buffer, sizeof(buffer), 0);

        if (received < 0) {
            if (errno == EINTR)
                continue;

            perror("NFQUEUE recv");
            break;
        }

        if (received > 0) {
            if (nfq_handle_packet(
                    handle,
                    (char *)buffer,
                    (int)received) < 0) {
                fprintf(stderr, "Packet handling failed\n");
            }
        }
    }

    nfq_destroy_queue(queue);
    nfq_close(handle);

    return EXIT_SUCCESS;
}
