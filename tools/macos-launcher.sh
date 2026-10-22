#!/bin/sh
# Installed as macosx/IAPTool. platform.txt picks a binary per OS, not per CPU,
# so this picks the arm64 or amd64 build beside it.
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
case "$(uname -m)" in
  arm64) exec "$DIR/IAPTool-arm64" "$@" ;;
  *)     exec "$DIR/IAPTool-amd64" "$@" ;;
esac
