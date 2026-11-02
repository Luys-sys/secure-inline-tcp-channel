#include "packet.h"
#include <stdio.h>
#include <string.h>

#define CHECK(expr) do { if (!(expr)) { fprintf(stderr,"FAIL line %d: %s\n", __LINE__,#expr); return 1; } } while (0)

int main(void) {
    /* IPv4 header 20, TCP header 24 with NOP options, 5-byte payload. */
    uint8_t b[49] = {0};
    b[0]=0x45; b[2]=0; b[3]=49; b[4]=0x12; b[5]=0x34;
    b[6]=0x40; b[8]=64; b[9]=6;
    b[12]=10; b[13]=10; b[14]=1; b[15]=1;
    b[16]=10; b[17]=10; b[18]=3; b[19]=2;
    b[20]=0xc0; b[21]=0x01; b[22]=0x14; b[23]=0x51;
    b[24]=0; b[25]=0; b[26]=0; b[27]=1;
    b[28]=0; b[29]=0; b[30]=0; b[31]=1;
    b[32]=0x60; b[33]=0x18; b[34]=0x20; b[35]=0;
    b[40]=1; b[41]=1; b[42]=1; b[43]=1;
    memcpy(b+44,"hello",5);
    sic_tcp_view v;
    CHECK(sic_parse_tcp4(b,sizeof(b),&v)==0);
    CHECK(v.payload_offset==44 && v.payload_len==5 && v.tcp_header_len==24);
    CHECK(v.src_port==49153 && v.dst_port==5201);
    CHECK(sic_update_checksums(b,sizeof(b))==0);
    CHECK(sic_verify_ipv4_checksum(b,sizeof(b)));
    CHECK(sic_verify_tcp_checksum(b,sizeof(b)));
    puts("PASS: IPv4/TCP parse with options and checksum verification");
    b[44]^=1;
    CHECK(!sic_verify_tcp_checksum(b,sizeof(b)));
    b[44]^=1;
    CHECK(sic_verify_tcp_checksum(b,sizeof(b)));
    puts("PASS: Payload tampering detected by TCP checksum");
    CHECK(sic_parse_tcp4(b,40,&v)!=0);
    b[6]=0x20; CHECK(sic_parse_tcp4(b,sizeof(b),&v)!=0);
    b[6]=0x40;
    b[32]=0x40; CHECK(sic_parse_tcp4(b,sizeof(b),&v)!=0);
    b[32]=0x60;
    b[0]=0x65; CHECK(sic_parse_tcp4(b,sizeof(b),&v)!=0);
    puts("PASS: Truncated, fragmented and invalid packets rejected");
    return 0;
}
