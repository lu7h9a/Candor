#!/usr/bin/env python3
"""png_colours.py MIN FILE... - fails unless every PNG (8-bit RGBA or RGB,
non-interlaced) has at least MIN distinct colours. Standard library only."""
import struct, sys, zlib

def colours(path):
    data = open(path, "rb").read()
    assert data[:8] == b"\x89PNG\r\n\x1a\n", "not a PNG"
    pos, idat, w = 8, b"", 0
    while pos < len(data):
        n, typ = struct.unpack(">I4s", data[pos:pos + 8])
        body = data[pos + 8:pos + 8 + n]
        if typ == b"IHDR":
            w, h, depth, ctype = struct.unpack(">IIBB", body[:10])
            bpp = {6: 4, 2: 3}[ctype]
            assert depth == 8
        elif typ == b"IDAT":
            idat += body
        pos += 12 + n
    raw = zlib.decompress(idat)
    stride = w * bpp
    prev = bytearray(stride)
    seen = set()
    for y in range(h):
        f = raw[y * (stride + 1)]
        line = bytearray(raw[y * (stride + 1) + 1:(y + 1) * (stride + 1)])
        for i in range(stride):
            a = line[i - bpp] if i >= bpp else 0
            b = prev[i]
            c = prev[i - bpp] if i >= bpp else 0
            if f == 1: line[i] = (line[i] + a) & 255
            elif f == 2: line[i] = (line[i] + b) & 255
            elif f == 3: line[i] = (line[i] + (a + b) // 2) & 255
            elif f == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                line[i] = (line[i] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 255
        for x in range(0, stride, bpp):
            seen.add(bytes(line[x:x + 3]))
        prev = line
    return len(seen), w, h

minimum = int(sys.argv[1])
bad = 0
for p in sys.argv[2:]:
    n, w, h = colours(p)
    ok = n >= minimum
    bad += not ok
    print("%s %dx%d %d colours %s" % (p, w, h, n, "OK" if ok else "BLANK?"))
sys.exit(1 if bad else 0)
