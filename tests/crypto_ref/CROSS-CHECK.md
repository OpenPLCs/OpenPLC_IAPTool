# crypto_ref — arbitrating between the product's crypto implementations

## The problem this solves

The same two primitives exist three times in this product, in three languages,
with no shared code:

| | SHA-256 | ECDSA P-256 |
|---|---|---|
| bootloader | `IAPServer/sha256.c` | micro-ecc, verify only |
| Arduino core | `libraries/OpenPLC_IAP/src/sha256.c` | — |
| IAPTool | Go `crypto/sha256` | Go `crypto/ecdsa`, sign only |

If the signer and the verifier disagree — about r‖s byte order, integer padding,
which bytes get hashed, how the last block is padded — the symptom is a board
that rejects every image while each side insists it is correct. Neither side can
settle it, because each is one of the two suspects.

These scripts are the third party. They share no code with either side.

## What runs

| File | Checks | Depends on |
|---|---|---|
| `sha256_ref.py` | a transcription of the bootloader's `sha256.c` against Python `hashlib`, 309 vectors | python only |
| `ecdsa_verify.py` | one signature, using plain modular arithmetic — no crypto library | python only |
| `run_checks.py` | both, driving real `IAPTool sign` for the signatures | python, go |

```
python run_checks.py             # 12 signatures
python run_checks.py --rounds 64  # after touching the signer or rotating keys
```

Also run as steps X1-X2 of `tools/selfcheck.py`.

## Design notes

**`sha256_ref.py` is a transcription, not a clean implementation.** It keeps the
C code's byte-at-a-time padding loop verbatim, because that loop is precisely
what could mis-handle the 55/56/63/64-byte block boundary. A tidier rewrite
would agree with hashlib while telling us nothing about the C. Those boundary
lengths are all in the vector list.

It does **not** test the compiled C — `host/bootloader_unit/` does that by
compiling the real `sha256.c` on the host. The two are complementary: this one
needs no toolchain and runs anywhere.

**Signing is randomised, so one signature is not enough.** `run_checks.py`
signs the same blob N times and verifies each. A leading zero byte in r or s
appears in roughly one signature in 256 — rare enough to reach the field, common
enough that it eventually will. One passing signature proves the encoding
round-trips; a dozen proves it does not depend on a lucky value.

**Every verification also runs two negative checks** — the same signature
against a tampered digest and against a tampered r, both of which must fail.
Without them, a verifier that returned `True` unconditionally would pass.

**The public key is parsed from `IAPServer/keys/fw_pubkey.inc`**, the file the
bootloader compiles in, so what gets checked is the committed key pair rather
than an ad-hoc one, and a rotation cannot leave a stale copy here.

`ecdsa_verify.py` is slow — seconds per verification, scalar multiplication in
Python integers. That is the right trade for a dozen signatures, and being
obviously-correct-by-inspection is the whole point.
