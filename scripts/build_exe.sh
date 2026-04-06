#!/usr/bin/env bash
# scripts/build_exe.sh
# Build IconCacheReader binary locally on Linux or macOS.
# Note: this produces a Linux/macOS binary. For the Windows .exe,
# use the GitHub Actions release workflow or run scripts/build_exe.bat on Windows.

set -euo pipefail

echo "[*] Installing / upgrading PyInstaller..."
pip install --upgrade pyinstaller

echo "[*] Building..."
pyinstaller IconCacheReader.spec \
  --distpath dist \
  --workpath /tmp/pyibuild \
  --specpath .

echo ""
echo "[+] Build complete: dist/IconCacheReader"
./dist/IconCacheReader --help
