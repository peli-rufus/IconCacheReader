# Changelog

All notable changes to `IconCacheReader` are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [2.1.0] — 2026-04-05

### Added
- `_infer_user()` now splits on both `/` and `\` — correctly identifies the
  target username when the forensic image is mounted deep inside an analyst's
  own profile path (e.g. `C:\Users\analyst\...\image\C\Users\target\...`).
- `_clean_extension()` — strips non-ASCII garbage bytes from extension fields
  that the fallback scanner picks up from adjacent binary icon metadata.
- `_trim_path_garbage()` — truncates paths at the first non-ASCII character
  after the last path separator, eliminating Devanagari/Telugu/CJK bleed-through.
- `_is_plausible_path()` — rejects malformed paths such as `A:c:\...` and
  `\c:\...` produced by misaligned fallback reads.
- `_sanitise_str()` / `_safe_print()` — eliminates surrogate code points
  (`\udf2c`, etc.) that caused `UnicodeEncodeError` on Windows consoles.
- Windows console reconfigured to UTF-8 with `errors="replace"` at startup.
- CSV written as `utf-8-sig` (UTF-8 BOM) so Excel opens it without encoding issues.

### Fixed
- **User column** showed analyst's own username instead of target profile username
  when image was mounted under a deep analyst home path.
- **UnicodeEncodeError** crash when `-include-non-exe` was used and the fallback
  scanner returned strings containing surrogate code points.
- Garbage characters in extension column (`.lnkᜢʋȁ耀`, `.exe텀ిЈ`, etc.).
- Duplicate fallback-scan entries for the same base path with different trailing garbage.

---

## [2.0.0] — 2026-03-20

### Breaking changes
- Parser now targets `%LOCALAPPDATA%\IconCache.db` **only** (the path database).
  `iconcache_*.db` image stores are explicitly rejected — they contain no file paths.

### Added
- Correct binary format parser per ThinkDFIR research (Phill Moore, 2025-12-28):
  magic `48 00 00 00 57 69 6E 34`, header at 0x00–0x47, structured entry walk.
- Support for both v0x0507 (current Win10/11) and v0x0506 (older) database formats.
- UTF-16LE fallback scanner with anchor-based reads to prevent substring explosion.
- Amcache.hve enrichment via pure-Python REGF hive parser (zero external deps).
  Supports modern `InventoryApplicationFile` and legacy `File\{VolumeGUID}` layouts.
- FULL_PATH > BASENAME > NONE join priority with O(1) lookup tables.
- Deduplication by (user, binary_path) with match-type priority.
- JSON, CSV, and ASCII table output modes.
- Windows UNC path preservation, device-path heuristic normalisation.
- 51 unit + integration tests.

### Research credit
- Phill Moore & Yogesh Khatri — "Examining the IconCache database" (2025-12-28)
  https://thinkdfir.com/2025/12/28/examining-the-iconcache-database/
- 010 Editor template `IconCache.bt` (Moore, Khatri; 2025-11-07)

---

## [1.0.0] — 2026-02-24  *(internal)*

Initial implementation — CMMM-format parser (incorrect target files).
Superseded by v2.0.0.
