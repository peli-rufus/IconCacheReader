@echo off
REM build_exe.bat — Build IconCacheReader.exe locally on Windows
REM Requirements: Python 3.8+, pip

echo [*] Installing / upgrading PyInstaller...
pip install --upgrade pyinstaller
if errorlevel 1 (
    echo [!] pip install failed. Ensure Python and pip are in your PATH.
    exit /b 1
)

echo [*] Building IconCacheReader.exe...
pyinstaller IconCacheReader.spec
if errorlevel 1 (
    echo [!] PyInstaller build failed.
    exit /b 1
)

echo.
echo [+] Build complete.
echo     Output: dist\IconCacheReader.exe
echo.
echo [*] Verifying...
dist\IconCacheReader.exe --help
