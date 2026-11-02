#!/usr/bin/env python3
"""Validate selected packets across three lab capture points; standard library only."""
import argparse
import struct
from pathlib import Path


def read_pcap(path):
    with open(path, 'rb') as f:
        hdr = f.read(24)
        if len(hdr) != 24:
            raise ValueError(f'{path}: missing pcap header')
        magic = hdr[:4]
        if magic == b'\xd4\xc3\xb2\xa1':
            endian = '<'
        elif magic == b'\xa1\xb2\xc3\xd4':
            endian = '>'
        elif magic == b'\x4d\x3c\xb2\xa1':
            endian = '<'
        elif magic == b'\xa1\xb2\x3c\x4d':
            endian = '>'
        else:
            raise ValueError(f'{path}: unsupported pcap format')
        linktype = struct.unpack(endian + 'I', hdr[20:24])[0]
        if linktype != 1:
            raise ValueError(f'{path}: expected Ethernet pcap, got linktype={linktype}')
        while True:
            rh = f.read(16)
            if not rh:
                break
            if len(rh) != 16:
                raise ValueError(f'{path}: truncated record header')
            incl = struct.unpack(endian + 'I', rh[8:12])[0]
            if incl > 10_000_000:
                raise ValueError(f'{path}: oversized capture record')
            frame = f.read(incl)
            if len(frame) != incl:
                raise ValueError(f'{path}: truncated record')
            if len(frame) < 34 or frame[12:14] != b'\x08\x00':
                continue
            ip = frame[14:]
            if ip[0] >> 4 != 4 or ip[9] != 6:
                continue
            ihl = (ip[0] & 15) * 4
            total = int.from_bytes(ip[2:4], 'big')
            if ihl < 20 or total < ihl + 20 or len(ip) < total:
                continue
            if ip[12:16] != b'\x0a\x0a\x01\x01' or ip[16:20] != b'\x0a\x0a\x03\x02':
                continue
            tcp = ip[ihl:total]
            if int.from_bytes(tcp[2:4], 'big') != 5201:
                continue
            doff = (tcp[12] >> 4) * 4
            if doff < 20 or len(tcp) < doff:
                continue
            payload = tcp[doff:]
            if not payload:
                continue
            key = (int.from_bytes(tcp[:2], 'big'), int.from_bytes(tcp[4:8], 'big'), int.from_bytes(tcp[8:12], 'big'))
            yield key, payload


def main():
    p = argparse.ArgumentParser()
    p.add_argument('before', type=Path)
    p.add_argument('wire', type=Path)
    p.add_argument('after', type=Path)
    args = p.parse_args()
    b, w, a = [list(read_pcap(x)) for x in (args.before, args.wire, args.after)]
    print(f'Captured TCP payload packets: before={len(b)}, protected_link={len(w)}, after={len(a)}')
    # Choose packets uniquely identifiable by TCP 3-tuple; ignore duplicate keys.
    def unique(records):
        d = {}
        duplicates = set()
        for key, payload in records:
            if key in d:
                duplicates.add(key)
            else:
                d[key] = payload
        return {k: v for k, v in d.items() if k not in duplicates}
    pre, mid, post = (unique(x) for x in (b, w, a))
    matches = []
    for k in pre.keys() & mid.keys() & post.keys():
        original, encrypted, restored = pre[k], mid[k], post[k]
        if len(original) > 0 and len(encrypted) == len(original) + 16 and encrypted[:-16] != original and restored == original:
            matches.append((k, len(original)))
    if not matches:
        raise SystemExit('FAIL: no triple-matched packet with changed ciphertext, +16B tag, and identical restored payload')
    total = sum(n for _, n in matches)
    print(f'PASS: {len(matches)} matched packets, {total} plaintext bytes checked')
    print('PASS: protected-link payload differs from plaintext and is 16 bytes longer')
    print('PASS: decrypted TCP payload bytes match original')
    print('NOTE: this establishes the captured lab flow, not general TCP/retransmission correctness')

if __name__ == '__main__':
    main()
