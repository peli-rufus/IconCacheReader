# IconCache.db Binary Format Reference

This document captures the binary format of Windows `IconCache.db` as
understood from the ThinkDFIR research by Phill Moore & Yogesh Khatri
(December 2025) and the 010 Editor template `IconCache.bt`.

---

## Overview

`IconCache.db` is the **path/metadata database** of the Windows icon cache
system. It stores the file paths that Windows Explorer used to look up icons,
along with a CRC hash linking each path to the actual icon pixel data stored
in the per-resolution image databases.

**This file is the forensic target** — it contains file paths.

### File locations

| File | Purpose |
|------|---------|
| `%LOCALAPPDATA%\IconCache.db` | **Path database** ← forensic value |
| `%LOCALAPPDATA%\Microsoft\Windows\Explorer\iconcache_16.db` | 16px icon images |
| `%LOCALAPPDATA%\Microsoft\Windows\Explorer\iconcache_32.db` | 32px icon images |
| `%LOCALAPPDATA%\Microsoft\Windows\Explorer\iconcache_48.db` | … |
| `%LOCALAPPDATA%\Microsoft\Windows\Explorer\iconcache_*.db` | (various sizes) |

The `iconcache_*.db` image stores use a different magic (`CMMM`, thumbcache
format) and contain no file paths.

---

## Magic / Identification

```
Offset  Size  Value               Description
------  ----  ------------------  -----------
0x00    4     48 00 00 00         header_size as LE uint32 = 0x48 (72)
0x04    4     57 69 6E 34         ASCII "Win4"
```

Combined ID bytes: `48 00 00 00 57 69 6E 34`

The 010 Editor template uses these as the file mask for `IconCache.db`.

---

## Header (72 bytes, offset 0x00–0x47)

| Offset | Type    | Field            | Notes |
|--------|---------|------------------|-------|
| 0x00   | UINT32  | header_size      | Always 0x48 |
| 0x04   | CHAR[4] | magic            | "Win4" |
| 0x08   | UINT32  | version          | 0x0507 (current) or 0x0506 (older) |
| 0x0C   | UINT32  | num_entries      | Number of path entries |
| 0x10   | UINT32  | unknown1         | Reserved |
| 0x14   | UINT32  | unknown2         | Reserved |
| 0x18   | UINT32  | unknown3         | Reserved |
| 0x1C   | UINT32  | unknown4         | Reserved |
| 0x20   | UINT64  | last_modified    | Windows FILETIME (100-ns since 1601-01-01) |
| 0x28   | UINT32  | entry_data_size  | Total bytes of all entry data |
| 0x2C   | UINT32  | unknown5–11      | Reserved |
| 0x44   | UINT32  | unknown11        | Reserved |

All multi-byte integers are little-endian.

---

## Entries (from offset 0x48)

Entries are laid out contiguously from the end of the header. Walk by
advancing `offset += entry_size` after each entry.

### Entry header (20 bytes fixed)

| Offset | Type   | Field          | Notes |
|--------|--------|----------------|-------|
| +0x00  | UINT32 | entry_size     | Total byte size of this entry (including header) |
| +0x04  | UINT32 | entry_hash     | CRC linking to the corresponding icon in `iconcache_*.db` |
| +0x08  | UINT32 | flags          | Entry flags (not fully documented) |
| +0x0C  | UINT32 | path_size      | Byte length of the UTF-16LE path string |
| +0x10  | UINT32 | extension_size | Byte length of the UTF-16LE extension string |

### Variable-length fields

```
+0x14                          [path_size bytes]     UTF-16LE path string
+0x14 + path_size              [extension_size bytes] UTF-16LE extension (e.g. ".exe")
+0x14 + path_size + ext_size   [remaining bytes]     Shell item blob (optional, not parsed)
```

---

## Version differences

| Version | Path case | Notes |
|---------|-----------|-------|
| 0x0507  | **Lowercase** | Current format on Win10/11. Drive letter normalised to uppercase by this tool. |
| 0x0506  | Mixed case | Older format. Structurally identical, paths may be mixed-case. |

Per ThinkDFIR: Windows 11 does not automatically upgrade a 0x0506 database
to 0x0507. If a system was upgraded from Win10 to Win11 without the cache
being rebuilt, the database retains the older version string.

---

## Write timing

The database is written **on shutdown or reboot**, not in real time. This means:

- A live acquisition may not contain data from the current session.
- The `last_modified` FILETIME reflects the last shutdown, not the last file
  access.
- Always check VSS shadow copies for historical versions of the database.

---

## Forensic interpretation

| Evidence type | Yes/No |
|---------------|--------|
| File existed on the system at some point | ✅ Yes |
| File was executed | ❌ No (use Prefetch, Shimcache, Amcache for execution) |
| File existed at the timestamp shown | ⚠️ Uncertain (timestamp = last db write, not file access) |
| File still exists | ❌ No — paths survive file deletion |

---

## References

- Phill Moore & Yogesh Khatri, "Examining the IconCache database," ThinkDFIR, 2025-12-28
  https://thinkdfir.com/2025/12/28/examining-the-iconcache-database/
- 010 Editor template `IconCache.bt` (Moore, Khatri; v1.0, 2025-11-07)
  https://www.sweetscape.com/010editor/repository/templates/file_info.php?file=IconCache.bt
- Sutherland, I., et al., "An investigation of the Windows thumbnail database format,"
  Digital Investigation, 2014. DOI: 10.1016/j.diin.2014.05.006
- DFIR Artifact Museum — sample IconCache.db files:
  https://github.com/AndrewRathbun/DFIRArtifactMuseum/tree/main/Windows/IconCache
