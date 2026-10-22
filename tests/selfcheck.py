"""IAPTool's own checks: nothing here needs a board or another repository.

    python tests/selfcheck.py          vet, unit tests, crypto cross-check
    python tests/selfcheck.py --list   what each step proves

Tests that need the bootloader, the board package or a board live in
OpenPLC_Test (decision 78).

Exit 0 = every step passed, 1 = a step failed, 2 = a tool is missing.
"""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# (id, requirement, what it proves) -- the docs' P7 reads this table.
CATALOG = [
    ("H3",          "-",      "go vet over the whole module"),
    ("T1-15",       "R1-20",  "host Go tests: certificate issuance, serial counter, challenge signing"),
    ("T1-35",       "R1-38",  "IAPTool unit tests: key lookup order, serial layer, protocol and dialing"),
    ("T1-19-T1-20", "R1-24",  "crypto cross-check against independent implementations"),
]

STEPS = {
    "H3": ["go", "vet", "./..."],
    "T1-15": ["go", "test", "./tests/..."],
    "T1-35": ["go", "test", ".", "./internal/...", "./iapproto/...", "./netiface/..."],
    "T1-19-T1-20": [sys.executable, str(REPO / "tests" / "crypto_ref" / "run_checks.py")],
}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()
    if args.list:
        for cid, covers, what in CATALOG:
            print("  %-12s %-6s %s" % (cid, covers, what))
        return 0
    if shutil.which("go") is None:
        print("go is not on PATH")
        return 2

    results = []
    for cid, _, what in CATALOG:
        print("\n===== %s  %s" % (cid, what), flush=True)
        rc = subprocess.call(STEPS[cid], cwd=str(REPO))
        results.append((cid, what, rc))
        print("PASS" if rc == 0 else "FAIL (exit %d)" % rc, flush=True)

    print("\n===== summary")
    for cid, what, rc in results:
        print("%-12s %-72s %s" % (cid, what, "PASS" if rc == 0 else "FAIL (exit %d)" % rc))
    failed = [r for r in results if r[2] != 0]
    print("\n%s" % ("%d failed" % len(failed) if failed else "IAPTool checks pass"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
