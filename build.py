#!/usr/bin/env python3
"""Builds IAPTool for the three platforms and installs it into the board package.

    python build.py        (Linux / macOS: ./build.py; Windows: double-click build.cmd)

The bootloader is built in STM32CubeIDE; the headless build the tests use lives
in OpenPLC_Test (decision 78). This script owns the output layout, the
platforms and the copy into the board package.

Exit 0 = built, 1 = the build failed.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUTPUT = HERE / "Output"
DARWIN = OUTPUT / "darwin"

# (GOOS, GOARCH, output file)
# macOS: Output/darwin/IAPTool is a launcher that picks IAPTool-arm64 or
# IAPTool-amd64 by CPU, so platform.txt keeps calling macosx/IAPTool (IDE-18).
TARGETS = [
    ("windows", "amd64", OUTPUT / "windows" / "IAPTool.exe"),
    ("linux", "amd64", OUTPUT / "linux" / "IAPTool"),
    ("darwin", "amd64", DARWIN / "IAPTool-amd64"),
    ("darwin", "arm64", DARWIN / "IAPTool-arm64"),
]


def go_build(goos, goarch, out):
    out.parent.mkdir(parents=True, exist_ok=True)
    print("Building IAPTool for '%s/%s'..." % (goos, goarch), flush=True)
    env = dict(os.environ, GOOS=goos, GOARCH=goarch)
    if subprocess.call(["go", "build", "-o", str(out), "."], cwd=str(HERE), env=env) != 0:
        print("Build failed for IAPTool on '%s/%s'. Please check the error messages." % (goos, goarch))
        return False
    print("Build succeeded! The executable is saved at: %s" % out)
    return True


def make_executable(path):
    # No-op on Windows; the bit matters when Output/ is used on Linux / macOS.
    path.chmod(path.stat().st_mode | 0o111)


def main():
    for goos, goarch, out in TARGETS:
        if not go_build(goos, goarch, out):
            print("\n有东西没编过 —— 看上面。")
            return 1

    launcher = DARWIN / "IAPTool"
    shutil.copyfile(str(HERE / "tools" / "macos-launcher.sh"), str(launcher))
    for p in (launcher, DARWIN / "IAPTool-amd64", DARWIN / "IAPTool-arm64"):
        make_executable(p)
    print("macOS launcher installed at: %s" % launcher)

    # The Arduino IDE's Upload button runs the copy inside the board package, not
    # the one in Output/. Every build lands there too, so the menu can never drive
    # an older binary -- OpenPLC_Test's P11 catches it when this step is skipped.
    print(flush=True)
    if subprocess.call([sys.executable, str(HERE / "tools" / "install_tool.py")], cwd=str(HERE)) != 0:
        print("Could not install into the board package - the IDE keeps using the previous build.")

    print("\n编好了：IAPTool")
    return 0


if __name__ == "__main__":
    sys.exit(main())
