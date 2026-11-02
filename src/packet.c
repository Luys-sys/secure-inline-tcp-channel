#include "packet.h"
#include <limits.h>
#include <string.h>

static uint16_t read_be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}
static uint32_t read_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}
static void write_be16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v;
}
static uint32_t sum_words(uint32_t sum, const uint8_t *p, size_t n) {
    while (n >= 2) {
        sum += read_be16(p);
        p += 2; n -= 2;
    }
    if (n) sum += (uint32_t)p[0] << 8;
    return sum;
}
static uint16_t fold(uint32_t sum) {
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)sum;
}
static uint16_t checksum(uint32_t sum) {
    return (uint16_t)~fold(sum);
}
int sic_parse_tcp4(const uint8_t *b, size_t len, sic_tcp_view *out) {
    if (!b || !out || len < 40 || len > UINT16_MAX) return -1;
    if ((b[0] >> 4) != 4 || (b[0] & 15) < 5) return -1;
    size_t ihl = (size_t)(b[0] & 15) * 4u;
    if (ihl > len || len < ihl + 20) return -1;
    if (read_be16(b + 2) != len || b[9] != 6) return -1;
    /* No fragmented packets in this initial prototype. */
    if ((read_be16(b + 6) & 0x3fffu) != 0) return -1;
    const uint8_t *t = b + ihl;
    size_t thl = (size_t)(t[12] >> 4) * 4u;
    if (thl < 20 || thl > len - ihl) return -1;
    if ((t[12] & 0x0fu) != 0) return -1; /* reserved bits/NS not supported */
    sic_tcp_view v = {0};
    v.ip_header_len = ihl;
    v.tcp_header_len = thl;
    v.payload_offset = ihl + thl;
    v.payload_len = len - v.payload_offset;
    v.packet_len = len;
    v.src_ip = read_be32(b + 12);
    v.dst_ip = read_be32(b + 16);
    v.src_port = read_be16(t);
    v.dst_port = read_be16(t + 2);
    v.tcp_flags = t[13];
    *out = v;
    return 0;
}
int sic_verify_ipv4_checksum(const uint8_t *b, size_t len) {
    sic_tcp_view v;
    if (sic_parse_tcp4(b,len,&v) != 0) return 0;
    return fold(sum_words(0,b,v.ip_header_len)) == 0xffffu;
}
static uint32_t tcp_sum(const uint8_t *b, const sic_tcp_view *v) {
    uint32_t sum = 0;
    sum = sum_words(sum, b + 12, 8);
    sum += 6;
    size_t tcp_len = v->packet_len - v->ip_header_len;
    sum += (uint32_t)tcp_len;
    return sum_words(sum, b + v->ip_header_len, tcp_len);
}
int sic_verify_tcp_checksum(const uint8_t *b, size_t len) {
    sic_tcp_view v;
    if (sic_parse_tcp4(b,len,&v) != 0) return 0;
    return fold(tcp_sum(b,&v)) == 0xffffu;
}
int sic_update_checksums(uint8_t *b, size_t len) {
    sic_tcp_view v;
    if (sic_parse_tcp4(b,len,&v) != 0) return -1;
    b[10] = b[11] = 0;
    write_be16(b + 10, checksum(sum_words(0,b,v.ip_header_len)));
    uint8_t *t = b + v.ip_header_len;
    t[16] = t[17] = 0;
    write_be16(t + 16, checksum(tcp_sum(b,&v)));
    return 0;
}
