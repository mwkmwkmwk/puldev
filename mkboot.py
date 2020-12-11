with open('main.bin', 'rb') as f:
    d = f.read()

res = bytearray(0xa0) + 0x100 * b'\xff\xff\xff\xff\0\0\0\0' + bytes(0x20)

assert len(res) % 0x40 == 0

hdrw = [
        0xaa995566,
        0x584c4e58,
        0,
        0x01010000,
        len(res),
        len(d),
        0,
        0,
        len(d),
        1,
]

hdrw.append(~sum(hdrw) & 0xffffffff)

for i, x in enumerate(hdrw):
    res[0x20 + i * 4 : 0x20 + i * 4 + 4] = x.to_bytes(4, 'little')

res += d

with open('BOOT.BIN', 'wb') as f:
    f.write(res)
