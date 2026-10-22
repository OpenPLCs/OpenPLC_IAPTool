"""Differential test of the bootloader's SHA-256 against hashlib.

This is a Python transcription of IAPServer/sha256.c, deliberately including
its unusual bits rather than a clean reimplementation. The point is to catch a
divergence between that C code and the standard, so anywhere the transcription
"looks wrong" it is meant to: sha256_final() pads one byte at a time through
the same update path the C code uses, which is exactly the sort of construction
that quietly mis-handles the block boundary at 55/56/63/64 bytes.

Those boundaries are the interesting inputs and they are all covered below. A
firmware hash that is wrong only for certain lengths would make signature
verification fail for some images and pass for others -- the worst possible
failure mode to debug in the field.

This does not test the compiled C. host/bootloader_unit/ does that, by
compiling the real sha256.c on the host. The two are complementary: this one
runs anywhere Python does and needs no toolchain.

Exit 0 = every vector matched, 1 = at least one mismatch.
"""
import hashlib
import random
import sys

MASK = 0xFFFFFFFF

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]


def rotr32(x, n):
    return ((x >> n) | (x << (32 - n))) & MASK


class Ctx(object):
    def __init__(self):
        self.state = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
        self.bitlen = 0
        self.buf = bytearray()


def process_block(ctx, block):
    w = [0] * 64
    for i in range(16):
        w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3]
    for i in range(16, 64):
        s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & MASK

    a, b, c, d, e, f, g, h = ctx.state
    for i in range(64):
        S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)
        ch = (e & f) ^ ((~e & MASK) & g)
        temp1 = (h + S1 + ch + K[i] + w[i]) & MASK
        S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj) & MASK
        h = g
        g = f
        f = e
        e = (d + temp1) & MASK
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & MASK

    for i, v in enumerate((a, b, c, d, e, f, g, h)):
        ctx.state[i] = (ctx.state[i] + v) & MASK


def sha256_update(ctx, data):
    ctx.bitlen += len(data) * 8
    ctx.buf += data
    while len(ctx.buf) >= 64:
        process_block(ctx, ctx.buf[:64])
        ctx.buf = ctx.buf[64:]


def sha256_final(ctx):
    bitlen = ctx.bitlen
    sha256_update(ctx, b'\x80')
    # The C code appends zero bytes one at a time until the buffer reaches 56.
    # Transcribed as-is: the question this test answers is whether that loop
    # handles the block boundary correctly, so a tidier padding here would
    # defeat the purpose.
    while len(ctx.buf) != 56:
        ctx.buf += b'\x00'
        if len(ctx.buf) == 64:
            process_block(ctx, ctx.buf[:64])
            ctx.buf = bytearray()
    lenbuf = bytearray(8)
    for i in range(8):
        lenbuf[i] = (bitlen >> (56 - 8 * i)) & 0xFF
    ctx.buf += lenbuf
    process_block(ctx, ctx.buf[:64])
    return b''.join(v.to_bytes(4, 'big') for v in ctx.state)


def my_sha256(data):
    ctx = Ctx()
    sha256_update(ctx, data)
    return sha256_final(ctx)


def main():
    fail = 0
    random.seed(1234)   # fixed: a failing run must be reproducible

    # 0..199 covers every offset within a block; the rest are the boundaries
    # either side of one, two and many blocks.
    lengths = list(range(0, 200)) + [255, 256, 257, 511, 512, 513, 1000, 8192, 8193]
    for n in lengths:
        data = bytes(random.randrange(256) for _ in range(n))
        got, want = my_sha256(data), hashlib.sha256(data).digest()
        if got != want:
            print("SHA256 MISMATCH at len=%d: got=%s want=%s" % (n, got.hex(), want.hex()))
            fail += 1

    total = len(lengths)
    if fail:
        print("%d of %d vectors FAILED" % (fail, total))
        return 1
    print("all %d vectors match hashlib" % total)
    return 0


if __name__ == "__main__":
    sys.exit(main())
