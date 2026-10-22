"""An independent P-256 ECDSA verifier, used to check IAPTool's signatures.

Three implementations of this signature exist in the product: Go's crypto/ecdsa
(IAPTool, signing), micro-ecc (the bootloader, verifying), and nothing on the
host that can arbitrate between them. If the two disagreed about encoding --
r||s byte order, integer padding, which bytes are hashed -- the symptom is a
board that rejects every image, with each side insisting it is correct.

This file is that arbitrator: plain modular arithmetic, no crypto library, no
shared code with either side. It is slow (seconds per verification) and that is
fine; it runs over a handful of signatures, not a firmware image.

Usage:
    ecdsa_verify.py <pubkey-hex-128> <message-file> <sig-file>

  pubkey-hex   uncompressed point X||Y as 128 hex chars (what IAPTool pubkey prints)
  message-file the bytes that were signed; SHA-256 of them is the digest
  sig-file     64 raw bytes, r||s big-endian -- the format IAPTool writes

Exit 0 = the signature verifies, 1 = it does not, 2 = bad arguments.
Also runs two negative checks on every call: the same signature against a
tampered digest and against a tampered r must both fail. A verifier that
returns True unconditionally would otherwise pass this script.
"""
import hashlib
import sys

# A Windows console on a legacy codepage cannot encode the warning signs in
# the docstring above, and argparse writes --help straight to stdout.
try:
    sys.stdout.reconfigure(errors="replace")
    sys.stderr.reconfigure(errors="replace")
except (AttributeError, ValueError):
    pass

# secp256r1 domain parameters (NIST P-256)
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = -3 % P
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def inv_mod(x, m):
    return pow(x, -1, m)


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * inv_mod(2 * y1, P) % P
    else:
        lam = (y2 - y1) * inv_mod(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_mult(k, point):
    r = None
    q = point
    while k > 0:
        if k & 1:
            r = point_add(r, q)
        q = point_add(q, q)
        k >>= 1
    return r


def on_curve(point):
    x, y = point
    return (y * y - (x * x * x + A * x + 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B)) % P == 0


def ecdsa_verify(pub_xy, digest, r, s):
    qx = int.from_bytes(pub_xy[:32], 'big')
    qy = int.from_bytes(pub_xy[32:], 'big')
    if not on_curve((qx, qy)):
        return False
    if not (1 <= r < N and 1 <= s < N):
        return False
    z = int.from_bytes(digest, 'big')
    w = inv_mod(s, N)
    u1 = (z * w) % N
    u2 = (r * w) % N
    point = point_add(scalar_mult(u1, (GX, GY)), scalar_mult(u2, (qx, qy)))
    if point is None:
        return False
    return (point[0] % N) == r


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        return 2

    pub_hex, msg_path, sig_path = sys.argv[1], sys.argv[2], sys.argv[3]
    pub_hex = pub_hex.strip().lower()
    if len(pub_hex) != 128:
        print("pubkey must be 128 hex chars, got %d" % len(pub_hex))
        return 2
    pub = bytes.fromhex(pub_hex)

    with open(msg_path, "rb") as f:
        digest = hashlib.sha256(f.read()).digest()
    with open(sig_path, "rb") as f:
        sig = f.read()
    if len(sig) != 64:
        print("signature must be 64 raw bytes (r||s), got %d" % len(sig))
        return 2

    r = int.from_bytes(sig[:32], 'big')
    s = int.from_bytes(sig[32:], 'big')

    ok = ecdsa_verify(pub, digest, r, s)
    bad_digest = bytes([digest[0] ^ 0xFF]) + digest[1:]
    ok_tampered_msg = ecdsa_verify(pub, bad_digest, r, s)
    ok_tampered_sig = ecdsa_verify(pub, digest, r ^ 1, s)

    print("  signature valid          : %s (want True)" % ok)
    print("  tampered digest rejected : %s (want True)" % (not ok_tampered_msg))
    print("  tampered r rejected      : %s (want True)" % (not ok_tampered_sig))

    if ok and not ok_tampered_msg and not ok_tampered_sig:
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
