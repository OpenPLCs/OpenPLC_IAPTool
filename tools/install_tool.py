"""Copy the freshly built IAPTool into the Arduino board package.

The IDE's Upload button runs the copy inside the board package, not the one in
Output/. Every build has to land there or the menu keeps driving an old binary;
OpenPLC_Test's P11 catches a forgotten copy.

    python3 tools/install_tool.py            copy every platform it can find
    python3 tools/install_tool.py --check    only report what would be copied

Called at the end of build.py, so building is installing. The old binary
is overwritten, not kept: a stale copy beside a fresh one only ever gets picked
up by mistake.

The board package is found under Arduino's default data directory for this
platform; set ARDUINO15 to use another one.

Exit 0 = the package now holds this build, 1 = something could not be copied,
2 = no board package or nothing built.
"""

import argparse
import glob
import os
import platform
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Output/<GOOS> in this repo -> <platform> directory in the board package, and
# the files copied. macOS's IAPTool is the launcher for the two builds (IDE-18).
TARGETS = [("windows", "win", ["IAPTool.exe"]),
           ("darwin", "macosx", ["IAPTool", "IAPTool-amd64", "IAPTool-arm64"]),
           ("linux", "linux", ["IAPTool"])]

# No longer shipped: boards leave the factory with no root (decision 72). A copy
# an older build left in the package is removed so nothing can pick it up.
PUBLISHED_KEY = "published_root.TEST_ONLY.pem"


def arduino15():
    named = os.environ.get("ARDUINO15", "")
    if named:
        return Path(named)
    system = platform.system()
    if system == "Windows":
        return Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))) / "Arduino15"
    if system == "Darwin":
        return Path.home() / "Library" / "Arduino15"
    return Path.home() / ".arduino15"


def package_root():
    """The newest STM32Tools/<version> directory the IDE loads."""
    hits = glob.glob(str(arduino15() / "packages" / "OpenPLC_Alpha" / "tools" / "STM32Tools" / "*"))
    hits = [h for h in hits if Path(h).is_dir()]
    return Path(max(hits, key=os.path.getmtime)) if hits else None


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="report, do not copy")
    args = ap.parse_args()

    root = package_root()
    if root is None:
        print("no board package under %s - install it in the Arduino IDE, or set ARDUINO15" % arduino15())
        return 2
    print("board package: %s" % root)

    copied, problems = 0, 0
    for goos, plat, names in TARGETS:
        srcs = [REPO / "Output" / goos / n for n in names]
        dst_dir = root / plat
        missing = [s for s in srcs if not s.exists()]
        if missing:
            print("  %-8s no build at %s" % (goos, missing[0]))
            continue
        if not dst_dir.exists():
            print("  %-8s no %s/ directory in the package" % (goos, plat))
            continue
        for src in srcs:
            print("  %-8s %s -> %s" % (goos, src.name, dst_dir / src.name))
        stale_key = dst_dir / "keys" / PUBLISHED_KEY
        if not args.check:
            try:
                for src in srcs:
                    shutil.copy2(src, dst_dir / src.name)
                if stale_key.exists():
                    stale_key.unlink()
                copied += 1
            except OSError as e:
                print("  %-8s %s" % (goos, e))
                problems += 1

    if args.check:
        print("nothing written (--check)")
        return 0
    if problems:
        print("%d platform(s) could not be copied" % problems)
        return 1
    if copied == 0:
        print("nothing was copied - run build.py first")
        return 2
    print("%d platform(s) installed; the IDE now drives this build" % copied)
    return 0


if __name__ == "__main__":
    sys.exit(main())
