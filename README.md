# IconCacheReader

[![CI](https://github.com/peli-rufus/IconCacheReader/actions/workflows/ci.yml/badge.svg)](https://github.com/peli-rufus/IconCacheReader/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-blue)](https://github.com/peli-rufus/IconCacheReader/releases)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://www.python.org/)

A DFIR tool that extracts historical binary paths from Windows
**`IconCache.db`** databases, with optional **`Amcache.hve`** SHA1 enrichment.

Built for incident response workflows and can run directly from a mounted forensic
image, produces table / JSON / CSV output
dependencies.

---

## Table of Contents

- [What is IconCache.db?](#what-is-iconcachedb)
- [Forensic Value](#forensic-value)
- [Download](#download)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Output](#output)
- [Building from Source / EXE](#building-from-source--exe)
- [Research Credit](#research-credit)
- [Contributing](#contributing)
- [License](#license)

---

## What is IconCache.db?

Windows maintains an icon cache so it can render file icons without
re-reading the source binary every time. The **path database** lives at:

```
%LOCALAPPDATA%\IconCache.db
  → C:\Users\<username>\AppData\Local\IconCache.db
```

It stores the **full file paths** that Explorer requested icons for, along
with a CRC hash linking each path to icon pixel data stored separately in
the `iconcache_*.db` image stores.

> **Note** — `iconcache_*.db` (in the `Explorer\` sub-folder) are icon
> image stores, not path databases. They contain no file paths. This tool
> correctly targets `IconCache.db` only.

The database is written on **shutdown or reboot**. It survives file deletion —
a path can appear even after the binary has been removed from the system.

Format research: Phill Moore & Yogesh Khatri — [Examining the IconCache database](https://thinkdfir.com/2025/12/28/examining-the-iconcache-database/) (ThinkDFIR, 2025-12-28).

---

## Forensic Value

| Question | IconCache answer |
|----------|-----------------|
| Was this binary present on the system? | ✅ Strong evidence |
| Was it executed? | ❌ Not alone — correlate with Prefetch / Shimcache |
| Was it present after a user browsed to it in Explorer? | ✅ Yes |
| Does it survive file deletion? | ✅ Yes |
| Is data flushed live? | ❌ Written at shutdown/reboot only |

Combine with **Prefetch** (execution), **Shimcache** (existence + load order),
and **Amcache** (SHA1, first-run) for a complete picture.

---

## Download

### Pre-built Windows EXE (recommended)

Download `IconCacheReader.exe` from the [Releases](https://github.com/peli-rufus/IconCacheReader/releases) page.

No Python installation required — copy and run.

```powershell
# Verify integrity (compare with .sha256 file in the release)
Get-FileHash .\IconCacheReader.exe -Algorithm SHA256
```

### Python script (any OS)

```bash
# Clone or download IconCacheReader.py directly
git clone https://github.com/peli-rufus/IconCacheReader.git
cd IconCacheReader

# No pip install needed — pure stdlib
python IconCacheReader.py --help
```

---

## Quick Start

```cmd
REM Single user profile
IconCacheReader.exe -user-profile "E:\Image\C\Users\Admin"

REM All users, export CSV
IconCacheReader.exe -users-dir "E:\Image\C\Users" -csv results.csv

REM With Amcache SHA1 enrichment
IconCacheReader.exe -users-dir "E:\Image\C\Users" ^
    -amcache "E:\Image\C\Windows\AppCompat\Programs\Amcache.hve" ^
    -csv results.csv -json results.json

REM Include all file types (not just executables)
IconCacheReader.exe -users-dir "E:\Image\C\Users" -include-non-exe -csv results.csv
```

---

## Usage

```
IconCacheReader.exe [SOURCE] [OPTIONS]
```

### Source (one required)

| Flag | Description |
|------|-------------|
| `-user-profile PATH` | Single user profile directory |
| `-users-dir PATH` | Users directory — all sub-profiles processed |

### Options

| Flag | Description |
|------|-------------|
| `-amcache PATH` | Path to `Amcache.hve` for SHA1 enrichment |
| `-json FILE` | Write JSON output to FILE |
| `-csv FILE` | Write CSV output to FILE (UTF-8 BOM, opens in Excel) |
| `-include-non-exe` | Include all file types (default: `.exe .dll .sys .com .scr .cpl .ocx .drv .mui .ax`) |
| `-recursive` | Recursively search for `IconCache.db` in non-standard locations |
| `-no-dedupe` | Disable deduplication (default: on) |
| `-verbose` / `-v` | Verbose logging |
| `-debug` | Debug logging (very noisy) |

### Examples

```cmd
REM --- Offline forensic image mounted at E:\ ---

REM All users, default filter (.exe/.dll/.sys etc.)
IconCacheReader.exe -users-dir "E:\Image\C\Users" -csv results.csv

REM With Amcache — adds SHA1, first-run, product name columns
IconCacheReader.exe -users-dir "E:\Image\C\Users" ^
    -amcache "E:\Image\C\Windows\AppCompat\Programs\Amcache.hve" ^
    -csv results.csv -json results.json

REM Single user, all file types (reveals shortcuts, images, etc.)
IconCacheReader.exe -user-profile "E:\Image\C\Users\Admin" ^
    -include-non-exe -csv admin_full.csv

REM Verbose — shows which DB version was parsed (0x0507/0x0506/fallback-scan)
IconCacheReader.exe -users-dir "E:\Image\C\Users" -verbose

REM Non-standard image path (analyst profile in the path — user is still inferred correctly)
IconCacheReader.exe -users-dir ^
    "C:\Cases\2026-04-ACME\evidence\1771235791-HOST1\C\Users" ^
    -csv results.csv
```

---

## Output

### Console table (default)

```
+-------+----------------+----------------------------------------------+-----------+------------+
| USER  | ICONCACHE_FILE | BINARY_PATH                                  | EXTENSION | DB_VERSION |
+-------+----------------+----------------------------------------------+-----------+------------+
| Admin | IconCache.db   | C:\Windows\System32\cmd.exe                  | .exe      | 0x0507     |
| Admin | IconCache.db   | C:\forensic_program_files\pestudio\pest...   | .exe      | 0x0507     |
| Admin | IconCache.db   | \\vmware-host\shared folders\tools\psex...   | .exe      | 0x0507     |
+-------+----------------+----------------------------------------------+-----------+------------+
```

With `-amcache`:

```
+-------+----------------+----------------------------------+-----------+------------+------------------------------------------+------------+
| USER  | ICONCACHE_FILE | BINARY_PATH                      | EXTENSION | DB_VERSION | SHA1                                     | MATCH_TYPE |
+-------+----------------+----------------------------------+-----------+------------+------------------------------------------+------------+
| Admin | IconCache.db   | C:\Windows\System32\cmd.exe      | .exe      | 0x0507     | AABBCCDD...                              | FULL_PATH  |
| Admin | IconCache.db   | C:\tools\mimikatz\mimikatz.exe   | .exe      | 0x0507     |                                          | NONE       |
+-------+----------------+----------------------------------+-----------+------------+------------------------------------------+------------+
```

### CSV columns

`user`, `iconcache_file`, `binary_path`, `raw_path`, `extension`, `db_version`,
`sha1`, `match_type`, `size`, `first_run`, `product_name`, `notes`


### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Partial success (some files failed to parse) |
| 2 | Invalid arguments |

---

## Building from Source / EXE

### Run as Python script (no build needed)

```bash
python IconCacheReader.py -users-dir /mnt/image/Users
```

### Build Windows EXE locally

Requires Python 3.8+ and Windows (or a Windows cross-compile toolchain).

```cmd
pip install pyinstaller
pyinstaller IconCacheReader.spec
REM Output: dist\IconCacheReader.exe
```

Or use the helper script:
```cmd
scripts\build_exe.bat
```

---

## Research Credit

This tool's binary format parser is based on:

- **Jan Collie** — [The windows IconCache.db: A resource for forensic artifacts from USB connectable devices](https://www.sciencedirect.com/science/article/abs/pii/S1742287613000078)
- **Phill Moore & Yogesh Khatri** — [Examining the IconCache database](https://thinkdfir.com/2025/12/28/examining-the-iconcache-database/) (ThinkDFIR, 2025-12-28)
- **010 Editor template `IconCache.bt`** — Moore & Khatri, v1.0, 2025-11-07
  ([download](https://www.sweetscape.com/010editor/repository/templates/file_info.php?file=IconCache.bt))
- **DFIR Artifact Museum** — real-world sample files
  ([Windows/IconCache](https://github.com/AndrewRathbun/DFIRArtifactMuseum/tree/main/Windows/IconCache))

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Bug reports with real-world `db_version`
values and sample files are especially valuable.

---

## License

[MIT](LICENSE) — free to use in commercial and non-commercial DFIR work.
