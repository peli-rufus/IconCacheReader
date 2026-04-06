# -*- mode: python ; coding: utf-8 -*-
# IconCacheReader.spec
# PyInstaller build spec for IconCacheReader.exe
#
# Build locally (requires Windows + PyInstaller):
#   pip install pyinstaller
#   pyinstaller IconCacheReader.spec
#
# The GitHub Actions workflow (release.yml) builds this automatically on
# every tagged release and attaches the .exe to the GitHub Release.

a = Analysis(
    ['IconCacheReader.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='IconCacheReader',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,       # CLI tool — keep console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
