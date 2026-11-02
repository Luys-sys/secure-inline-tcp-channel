#include "gateway_packet.h"
#include "packet.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
static void init(sic_sender *s, sic_receiver *r) {
    memset(s,0,sizeof(*s)); memset(r,0,sizeof(*r));
    for (size_t i=0;i<32;i++) s->key[i]=(uint8_t)(i+1);
    memcpy(r->key,s->key,32);
    for (size_t i=0;i<4;i++) s->salt[i]=(uint8_t)(0xb0+i);
    memcpy(r->salt,s->salt,4);
}
int main(void) {
    /* Minimal IPv4 / TCP packet with 12-byte application payload. */
    uint8_t p[52]={0};
    p[0]=0x45; p[2]=0; p[3]=sizeof(p); p[8]=64; p[9]=6;
    p[12]=10;p[13]=10;p[14]=1;p[15]=1;
    p[16]=10;p[17]=10;p[18]=3;p[19]=2;
    p[20]=0xc0;p[21]=0x01;p[22]=0x14;p[23]=0x51;
    p[24]=0x12;p[28]=0x24;
    p[32]=0x50;p[33]=0x18;p[34]=0x20;
    memcpy(p+40,"Hello there!",12);
    assert(sic_update_checksums(p,sizeof(p))==0);
    sic_sender s; sic_receiver r; init(&s,&r);
    uint8_t enc[256],dec[256];size_t en=0,de=0;
    assert(sic_protect_packet(&s,p,sizeof(p),enc,sizeof(enc),1500,&en)==1);
    assert(en==sizeof(p)+16);
    assert(memcmp(enc,p,40)!=0); /* length/checksums updated */
    assert(memcmp(enc+40,p+40,12)!=0);
    assert(sic_verify_ipv4_checksum(enc,en));
    assert(sic_verify_tcp_checksum(enc,en));
    assert(sic_unprotect_packet(&r,enc,en,dec,sizeof(dec),&de)==1);
    assert(de==sizeof(p));
    assert(memcmp(dec,p,sizeof(p))==0);
    puts("PASS: TCP payload encrypted + tag; headers restored; checksums valid");
    assert(sic_unprotect_packet(&r,enc,en,dec,sizeof(dec),&de)==-1);
    puts("PASS: packet replay rejected");
    sic_receiver r2; init(&s,&r2);
    enc[41]^=1;
    assert(sic_unprotect_packet(&r2,enc,en,dec,sizeof(dec),&de)==-1);
    puts("PASS: modified ciphertext rejected");
    enc[41]^=1;
    enc[27]^=1; /* sequence field is authenticated AAD */
    assert(sic_unprotect_packet(&r2,enc,en,dec,sizeof(dec),&de)==-1);
    puts("PASS: modified TCP sequence rejected");
    assert(sic_protect_packet(&s,p,sizeof(p),enc,sizeof(enc),60,&en)==-1);
    puts("PASS: expansion beyond MTU rejected");
    return 0;
}
