#include "gateway_packet.h"
#include "packet.h"
#include <string.h>
#include <limits.h>

/* 12 IP bytes (src/dst and protocol-bound), 4 ports, seq+ack, flags,
 * tcp options, and IP identification: all fields required to stay
 * unchanged between the gateways. TTL and checksums are excluded. */
static size_t make_aad(const uint8_t *ip, const sic_tcp_view *v,
                       uint8_t aad[128]) {
    const uint8_t *tcp = ip + v->ip_header_len;
    size_t opts = v->tcp_header_len - 20;
    size_t n = 0;
    memcpy(aad+n, "SIC-DATA-v1", 11); n += 11;
    memcpy(aad+n, ip+12, 8); n += 8;
    aad[n++] = ip[9];
    memcpy(aad+n, ip+4, 2); n += 2; /* IPv4 identification */
    memcpy(aad+n, tcp, 12); n += 12; /* ports, seq, ack */
    aad[n++] = tcp[12];
    aad[n++] = tcp[13];
    if (opts) { memcpy(aad+n, tcp+20, opts); n += opts; }
    return n;
}
static void put16(uint8_t *p, size_t v) { p[0]=(uint8_t)(v>>8); p[1]=(uint8_t)v; }

int sic_protect_packet(sic_sender *s, const uint8_t *in, size_t len,
                       uint8_t *out, size_t cap, size_t mtu, size_t *out_len) {
    if (!s || !in || !out || !out_len) return -1;
    *out_len=0;
    sic_tcp_view v;
    if (sic_parse_tcp4(in,len,&v) != 0) return -1;
    if (!v.payload_len) return 0;
    if (len > UINT16_MAX-SIC_TAG_BYTES || len > mtu ||
        len+SIC_TAG_BYTES > mtu || cap < len+SIC_TAG_BYTES) return -1;
    if (in == out) return -1;
    uint8_t aad[128]; size_t aad_len = make_aad(in,&v,aad);
    memcpy(out,in,v.payload_offset);
    size_t crypt_len=0;
    if (!sic_encrypt(s,aad,aad_len,in+v.payload_offset,v.payload_len,
                     out+v.payload_offset,cap-v.payload_offset,&crypt_len)) return -1;
    if (crypt_len != v.payload_len+SIC_TAG_BYTES) return -1;
    put16(out+2,len+SIC_TAG_BYTES);
    if (sic_update_checksums(out,len+SIC_TAG_BYTES) != 0) return -1;
    *out_len=len+SIC_TAG_BYTES;
    return 1;
}
int sic_unprotect_packet(sic_receiver *r, const uint8_t *in, size_t len,
                         uint8_t *out, size_t cap, size_t *out_len) {
    if (!r || !in || !out || !out_len) return -1;
    *out_len=0;
    sic_tcp_view v;
    if (sic_parse_tcp4(in,len,&v) != 0) return -1;
    if (!v.payload_len) return 0;
    if (v.payload_len <= SIC_TAG_BYTES || len < SIC_TAG_BYTES ||
        cap < len-SIC_TAG_BYTES || in == out) return -1;
    uint8_t aad[128]; size_t aad_len=make_aad(in,&v,aad);
    memcpy(out,in,v.payload_offset);
    size_t plain_len=0;
    if (!sic_decrypt(r,aad,aad_len,in+v.payload_offset,v.payload_len,
                     out+v.payload_offset,cap-v.payload_offset,&plain_len)) return -1;
    if (plain_len != v.payload_len-SIC_TAG_BYTES) return -1;
    put16(out+2,len-SIC_TAG_BYTES);
    if (sic_update_checksums(out,len-SIC_TAG_BYTES) != 0) return -1;
    *out_len=len-SIC_TAG_BYTES;
    return 1;
}
