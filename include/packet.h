#ifndef SIC_PACKET_H
#define SIC_PACKET_H
#include <stddef.h>
#include <stdint.h>

typedef struct {
    size_t ip_header_len;
    size_t tcp_header_len;
    size_t payload_offset;
    size_t payload_len;
    size_t packet_len;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t tcp_flags;
} sic_tcp_view;

/* Parses an IPv4 datagram (without Ethernet header). Rejects fragmentation,
 * malformed headers and trailing bytes. The caller owns buf. */
int sic_parse_tcp4(const uint8_t *buf, size_t len, sic_tcp_view *out);
/* Return 1 if a full checksum is correct, 0 otherwise. */
int sic_verify_ipv4_checksum(const uint8_t *buf, size_t len);
int sic_verify_tcp_checksum(const uint8_t *buf, size_t len);
/* Recalculate IPv4 header and TCP checksums in-place on valid packets. */
int sic_update_checksums(uint8_t *buf, size_t len);
#endif
