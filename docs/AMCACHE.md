# Amcache.hve Enrichment

`IconCacheReader` can enrich path entries with SHA1 hashes, file sizes, first-run
timestamps, and product names from the Windows Application Compatibility Cache
(`Amcache.hve`).

---

## What Amcache adds

| Field | Source | Forensic value |
|-------|--------|----------------|
| `sha1` | Amcache SHA1 (point-in-time) | Identify the binary via VirusTotal / NSRL |
| `size` | File size in bytes | Corroborate file identity |
| `first_run` | `LinkDate` or first observation | Earliest evidence of file on system |
| `product_name` | PE version resource | Identify vendor / product |
| `match_type` | Join result | Confidence indicator |

---

## Amcache location

```
%SystemRoot%\AppCompat\Programs\Amcache.hve
```

Typical path on a mounted forensic image:
```
E:\Image\C\Windows\AppCompat\Programs\Amcache.hve
```

---

## Match types

| match_type | Meaning | Confidence |
|------------|---------|------------|
| `FULL_PATH` | Exact case-insensitive path match | High |
| `BASENAME` | Matched on filename only (different directory) | Low — review manually |
| `NONE` | No Amcache record found | N/A |
| `N/A` | Amcache not provided | N/A |

`BASENAME` matches are flagged with `low-confidence basename match` in the
`notes` column. Two different executables named `update.exe` in different
directories will collide — always verify these manually.

---

## Amcache layouts supported

### Modern (Windows 8.1+)

```
Root\InventoryApplicationFile\<AppId>
  LowerCaseLongPath  REG_SZ   full path (lowercase)
  FileId             REG_SZ   "0000" + SHA1 (44 chars) or bare SHA1 (40 chars)
  Size               REG_SZ   decimal file size
  LinkDate           REG_SZ   first-run datetime string
  ProductName        REG_SZ   PE product name
```

### Legacy (Windows 7)

```
Root\File\{VolumeGUID}\<sequence>
  "0"    REG_SZ   full path
  "101"  REG_SZ   SHA1 hash
  "6"    REG_DWORD file size
  "f"    REG_SZ   last-modified FILETIME (hex)
  "d"    REG_SZ   product name
```

---

## Important caveats

1. **SHA1 is point-in-time** — the hash reflects the file at first observation.
   Malware that overwrites a legitimate binary will not update the Amcache record
   until the next execution (if at all).

2. **Amcache ≠ execution** — Amcache records are written when a PE is *loaded*,
   which includes DLL loads, setup programs that inspect binaries, and AV scans.
   It is stronger evidence of execution than IconCache alone but is not definitive.

3. **Missing records are normal** — not every file that appears in IconCache
   will have an Amcache record. Explorer can cache an icon without the binary
   being executed.

4. **Hive must be offline** — the live `Amcache.hve` is locked by Windows.
   Always work from a forensic copy.
