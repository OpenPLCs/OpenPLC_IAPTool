"""Cross-checks the product's crypto against independent implementations.

  1. sha256_ref.py   the bootloader's SHA-256 construction vs hashlib
  2. ecdsa_verify.py signatures IAPTool actually produced, verified by hand-
                     rolled modular arithmetic that shares no code with Go

Signing is randomised, so step 2 signs the same blob several times and verifies
every result. One passing signature proves the encoding round-trips; several
prove it does not depend on a lucky value of r or s (a leading zero byte in
either integer is the classic case, and it shows up roughly once in 256
signatures -- rare enough to reach the field, common enough to be certain it
eventually will).

    python run_checks.py                default 12 signatures
    python run_checks.py --rounds 64    more, when key or signer code changed

No interpreter check up front: this one is already running, and it is the one
used to launch both reference scripts.

Exit 0 = everything verified, 1 = something did not, 2 = prerequisites missing.
"""

import argparse
import os
import shutil
import sys
import tempfile
from pathlib import Path

import platform
import subprocess

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
EXE = ".exe" if os.name == "nt" else ""
GOOS_DIR = {"Windows": "windows", "Linux": "linux", "Darwin": "darwin"}.get(platform.system(), "linux")


def Section(t):
    print("\n===== %s" % t, flush=True)


def Ok(t):
    print(t, flush=True)


Fail = Warn = Ok


def have_cmd(name):
    return shutil.which(name) is not None


def python_exe():
    return sys.executable


def run_capture(argv):
    proc = subprocess.run([str(a) for a in argv], stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True, errors="replace")
    return proc.stdout or "", proc.returncode


def run_emit(argv, cwd=None):
    return subprocess.call([str(a) for a in argv], cwd=None if cwd is None else str(cwd))


def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--rounds", type=int, default=12)
    args = ap.parse_args()
    rounds = args.rounds

    bad = 0

    Section("1. SHA-256 construction")
    if run_emit([python_exe(), HERE / "sha256_ref.py"]) != 0:
        Fail("SHA-256 reference check failed")
        bad += 1
    else:
        Ok("PASS")

    Section("2. ECDSA P-256 signatures from IAPTool")

    if not have_cmd("go"):
        Warn("SKIP - go is not on PATH, cannot produce signatures")
    else:
        # On macOS Output/darwin/IAPTool is the launcher, so build the CPU's own binary.
        name = "IAPTool" + EXE
        if GOOS_DIR == "darwin":
            name = "IAPTool-" + ("arm64" if platform.machine() == "arm64" else "amd64")
        iap_tool = REPO / "Output" / GOOS_DIR / name
        if not iap_tool.exists():
            run_emit(["go", "build", "-o", "Output/%s/%s" % (GOOS_DIR, name), "."],
                     cwd=REPO)

        if not Path(iap_tool).exists():
            Fail("not found: %s" % iap_tool)
            return 2

        # A throwaway key pair from the shipping tool: no key is committed any
        # more (decision 72), and the public half comes from the tool's own
        # "pubkey", the form a board answers to getpubkey.
        scratch = Path(tempfile.mkdtemp(prefix="cryptoref-"))
        key = scratch / "k.pem"
        run_capture([iap_tool, "genkey", scratch / "k"])
        out, rc = run_capture([iap_tool, "pubkey", key])
        pub_hex = out.strip().splitlines()[-1].strip().lower() if out.strip() else ""
        if (rc != 0) or (len(pub_hex) != 128):
            Fail("IAPTool genkey/pubkey gave no 128-hex-char public key: %r" % out)
            return 2
        print("  key pair: fresh from IAPTool genkey -> %s..." % pub_hex[:16])

        msg = scratch / "msg.bin"
        msg.write_bytes(bytes((i * 17 + 3) % 256 for i in range(4096)))

        verified = 0
        for n in range(1, rounds + 1):
            prefix = scratch / ("run%d" % n)
            run_capture_quiet([iap_tool, "sign", msg, key, "--out=%s" % prefix])
            sig = Path(str(prefix) + ".sig")
            if not sig.exists():
                Fail("round %d: IAPTool produced no .sig" % n)
                bad += 1
                continue

            print("  round %d" % n)
            if run_emit([python_exe(), HERE / "ecdsa_verify.py", pub_hex, msg, sig]) != 0:
                Fail("round %d: independent verification FAILED" % n)
                bad += 1
            else:
                verified += 1

        shutil.rmtree(str(scratch), ignore_errors=True)

        if verified == rounds:
            Ok("PASS - %d/%d signatures verified independently" % (verified, rounds))
        else:
            Fail("only %d of %d verified" % (verified, rounds))

    Section("result")
    if bad > 0:
        Fail("%d check(s) failed" % bad)
        return 1
    Ok("the shipping signer and an independent verifier agree")
    return 0


def run_capture_quiet(argv):
    """`... 2>&1 | Out-Null` -- run it, throw the output away."""
    import subprocess
    subprocess.run([str(a) for a in argv],
                   stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)


if __name__ == "__main__":
    sys.exit(main())
