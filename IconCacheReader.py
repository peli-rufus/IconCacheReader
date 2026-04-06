#!/usr/bin/env python3
"""
IconCacheReader.py  v2.1.0
Cross-platform DFIR tool: extract historical binary paths from Windows
IconCache.db, with optional Amcache.hve SHA1 enrichment.

Python  : 3.8+   |   Dependencies : stdlib only

Research credit
---------------
  Phill Moore & Yogesh Khatri, "Examining the IconCache database" (2025-12-28)
  https://thinkdfir.com/2025/12/28/examining-the-iconcache-database/
  010 Editor template IconCache.bt (Moore, Khatri; 2025-11-07)

================================================================================
Target files
================================================================================
  PRIMARY  %LOCALAPPDATA%\\IconCache.db          <- PATH DATABASE (this tool)
           => <profile>\\AppData\\Local\\IconCache.db
  NOTE     iconcache_*.db in the Explorer sub-folder are icon IMAGE stores
           (CMMM format, no paths inside).  This tool does NOT parse them.

================================================================================
IconCache.db binary format
================================================================================
  Magic / ID bytes: 48 00 00 00 57 69 6E 34   ("H\\0\\0\\0Win4")
  Header  (0x48 bytes):
    0x00  UINT32  header_size  = 0x48
    0x04  CHAR[4] "Win4"
    0x08  UINT32  version      0x0507 (Win10/11 current) | 0x0506 (older)
    0x0C  UINT32  num_entries
    0x20  UINT64  last_modified  (Windows FILETIME, written at shutdown/reboot)
    ...   (remaining header fields reserved)
  Entry  (from offset 0x48, walk entry_size bytes each):
    +0x00  UINT32  entry_size
    +0x04  UINT32  entry_hash    (CRC linking to iconcache_*.db image stores)
    +0x08  UINT32  flags
    +0x0C  UINT32  path_size     (bytes of the UTF-16LE path)
    +0x10  UINT32  extension_size
    +0x14  <path_size bytes>     UTF-16LE path (lowercase in v0x0507)
    +0x14+path_size  <extension_size bytes>  UTF-16LE extension (e.g. ".exe")

Forensic notes:
  * Written on SHUTDOWN/REBOOT — live data is NOT yet flushed.
  * Evidence of EXISTENCE (Explorer rendered the icon), NOT execution.
  * v0x0507 stores lowercase paths; drive letter is uppercased during output.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import pathlib
import re
import struct
import sys
import textwrap
from dataclasses import asdict, dataclass, field
from typing import Dict, Iterator, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG = logging.getLogger("IconCacheReader")


def _setup_logging(verbose: bool, debug: bool) -> None:
    level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        level=level,
    )


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BINARY_EXTENSIONS: Set[str] = {
    ".exe", ".dll", ".sys", ".com", ".scr",
    ".cpl", ".ocx", ".drv", ".mui", ".ax",
}

# Magic: header_size (LE uint32 = 0x48) immediately followed by "Win4" (ASCII)
ICONCACHE_MAGIC      = b"\x48\x00\x00\x00\x57\x69\x6E\x34"
ICONCACHE_HEADER_SIZE = 0x48   # 72 bytes

ICONCACHE_VERSION_0506 = 0x0506
ICONCACHE_VERSION_0507 = 0x0507
SUPPORTED_VERSIONS     = {ICONCACHE_VERSION_0506, ICONCACHE_VERSION_0507}

# Glob patterns relative to a user profile root, resolving %LOCALAPPDATA%
ICONCACHE_GLOBS = [
    "AppData/Local/IconCache.db",
    "Local Settings/Application Data/IconCache.db",
    "AppData/Roaming/IconCache.db",
]


# ---------------------------------------------------------------------------
# String sanitisation helpers
# ---------------------------------------------------------------------------

def _sanitise_str(s: str) -> str:
    """
    Remove surrogate code points and other characters that cause
    UnicodeEncodeError on Windows consoles (cp1252 / cp850 / utf-8 strict).

    Round-trips through UTF-8 with 'replace', which substitutes U+FFFD for
    any unpaired surrogate or otherwise unrepresentable code point.
    """
    if not s:
        return s
    return s.encode("utf-8", errors="replace").decode("utf-8", errors="replace")


def _clean_extension(ext: str) -> str:
    """
    Normalise a file extension: keep the leading dot plus ASCII alnum/underscore
    characters only, stopping at the first non-ASCII character.

    This strips garbage bytes that the fallback scanner appends when it reads
    past the null terminator into adjacent binary metadata, e.g.:
        '.exe\\u1234garbage'  ->  '.exe'
        '.lnk\\u9a4b\\u0c6a'  ->  '.lnk'
    """
    if not ext:
        return ""
    if not ext.startswith("."):
        ext = "." + ext
    clean = "."
    for ch in ext[1:]:
        if ch.isascii() and (ch.isalnum() or ch == "_"):
            clean += ch
        else:
            break
    return clean if len(clean) > 1 else ""


def _trim_path_garbage(path: str) -> str:
    """
    Remove non-ASCII garbage characters that the fallback scanner sometimes
    appends to a path when it reads past the null terminator into adjacent
    binary icon metadata (Devanagari, Telugu, CJK, private-use, surrogates, etc.).

    Strategy: scan the string character by character.  Once we are past the
    'filename' portion (after the last path separator), stop at the first
    code point >= U+0100 or any surrogate (>= U+D800).  Before the separator
    we allow all printable ASCII only.
    """
    last_sep = max(path.rfind("\\"), path.rfind("/"))
    prefix   = path[:last_sep + 1]   # include the separator
    suffix   = path[last_sep + 1:]   # filename + potential garbage

    # Clean prefix: allow only printable ASCII + colon (for drive letters)
    clean_prefix = ""
    for ch in prefix:
        cp = ord(ch)
        if cp < 0x20 or cp >= 0x0100:
            break
        clean_prefix += ch

    # Clean suffix: stop at first non-ASCII character
    clean_suffix = ""
    for ch in suffix:
        cp = ord(ch)
        if cp < 0x20 or cp >= 0x0100:
            break
        clean_suffix += ch

    result = clean_prefix + clean_suffix
    return result if result else path


def _is_plausible_path(path: str) -> bool:
    """
    Reject obviously malformed paths produced by the fallback scanner:
      - 'A:c:\\...'  (drive letter stuck onto another absolute path)
      - '\\c:\\...'  (backslash prefix before a drive letter)
      - very short paths (< 5 chars after trimming)
      - paths containing only a separator or extension
    """
    if not path or len(path) < 5:
        return False
    # Reject '\c:\...' style (backslash before drive letter)
    if re.match(r"^\\[A-Za-z]:\\", path):
        return False
    # Reject 'A:c:\...' style (extra drive letter prefix)
    if re.match(r"^[A-Za-z]:[A-Za-z]:\\", path):
        return False
    # Must have at least one separator to be a real path
    if "\\" not in path and "/" not in path:
        return False
    return True


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class IconCacheEntry:
    user:           str
    iconcache_file: str
    binary_path:    str    # normalised, garbage-trimmed
    raw_path:       str    # as extracted from db
    extension:      str    # cleaned extension e.g. ".exe"
    db_version:     str    # "0x0506" / "0x0507" / "fallback-scan" / …
    notes:          str = ""


@dataclass
class AmcacheEntry:
    full_path:    str
    sha1:         str
    size:         Optional[int]
    first_run:    Optional[str]
    product_name: str
    basename:     str = field(init=False)

    def __post_init__(self) -> None:
        self.basename = pathlib.PureWindowsPath(self.full_path).name.lower()


@dataclass
class ResultRow:
    user:           str
    iconcache_file: str
    binary_path:    str
    raw_path:       str
    extension:      str
    db_version:     str
    sha1:           str
    match_type:     str   # FULL_PATH | BASENAME | NONE | N/A
    size:           Optional[int]
    first_run:      Optional[str]
    product_name:   str
    notes:          str


# ---------------------------------------------------------------------------
# Path normalisation
# ---------------------------------------------------------------------------

_DEVICE_VOLUME_RE = re.compile(
    r"^\\Device\\HarddiskVolume(\d+)\\(.*)$", re.IGNORECASE
)
# Heuristic mapping — flagged in notes on every conversion
_DEVICE_DRIVE_MAP: Dict[int, str] = {
    1: "C:", 2: "C:", 3: "D:", 4: "E:", 5: "F:", 6: "G:",
}


def normalize_path(raw: str) -> Tuple[str, str]:
    """Return (normalised_path, notes_string)."""
    notes: List[str] = []
    path = raw.strip().rstrip("\x00")

    # Trim any trailing garbage characters before normalisation
    path = _trim_path_garbage(path)

    m = _DEVICE_VOLUME_RE.match(path)
    if m:
        vol   = int(m.group(1))
        rest  = m.group(2)
        drive = _DEVICE_DRIVE_MAP.get(vol, f"?{vol}:")
        path  = f"{drive}\\{rest}"
        notes.append(f"device-path-heuristic(Vol{vol}->{drive})")

    path = path.replace("/", "\\")

    if path.startswith("\\\\"):
        path = "\\\\" + re.sub(r"\\{2,}", "\\\\", path[2:])
    else:
        path = re.sub(r"\\{2,}", "\\\\", path)

    if len(path) >= 2 and path[1] == ":" and path[0].isalpha():
        path = path[0].upper() + path[1:]

    return path, "; ".join(notes)


def is_binary_ext(ext: str, path: str, include_non_exe: bool) -> bool:
    if include_non_exe:
        return True
    effective = ext.lower() if ext else pathlib.PureWindowsPath(path).suffix.lower()
    return effective in BINARY_EXTENSIONS


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def discover_iconcache_files(
    profile_dir: pathlib.Path,
    recursive: bool = False,
) -> List[pathlib.Path]:
    """Find IconCache.db file(s) under a single user profile directory."""
    found: List[pathlib.Path] = []
    for pattern in ICONCACHE_GLOBS:
        candidate = profile_dir / pathlib.Path(pattern)
        if candidate.is_file() and candidate not in found:
            found.append(candidate)
    if recursive:
        for p in profile_dir.rglob("IconCache.db"):
            if p not in found:
                found.append(p)
    LOG.info("Profile %s: %d IconCache.db file(s)", profile_dir, len(found))
    return found


def discover_profiles(users_dir: pathlib.Path) -> List[pathlib.Path]:
    """Return child directories of a Users directory, excluding system dirs."""
    exclude = {"all users", "default", "default user", "public"}
    profiles = [
        p for p in users_dir.iterdir()
        if p.is_dir() and p.name.lower() not in exclude
    ]
    LOG.info("Users dir %s: %d profile(s)", users_dir, len(profiles))
    return profiles


# ---------------------------------------------------------------------------
# Username inference
# ---------------------------------------------------------------------------

def _infer_user(db_path: pathlib.Path) -> str:
    """
    Extract the target username from the file path.

    Uses the LAST occurrence of "Users" or "Documents and Settings" in the
    path so that analyst home directories in the path prefix do not shadow
    the target profile, e.g.:

        ...\\Users\\VERGIO\\...\\image\\C\\Users\\Admin\\AppData\\...
                analyst ^^^^^^                       ^^^^^ target  <- we want this

    Splits on BOTH forward-slash and backslash so the function works
    correctly on Linux/macOS (where pathlib.Path treats a Windows-style
    backslash path as a single-component string).

    Fallback: look for "AppData" and return the segment immediately before it.
    """
    import re as _re
    # Split on forward-slash AND backslash to handle paths on any OS
    raw  = str(db_path)
    parts = [p for p in _re.split(r"[/\\]", raw) if p]

    # Collect ALL "Users" markers; take the last one
    hits = [
        parts[i + 1]
        for i, part in enumerate(parts[:-1])
        if part.lower() in ("users", "documents and settings")
    ]
    if hits:
        return hits[-1]

    # AppData fallback
    try:
        idx = next(i for i, p in enumerate(parts) if p.lower() == "appdata")
        if idx > 0:
            return parts[idx - 1]
    except StopIteration:
        pass

    return "unknown"


# ---------------------------------------------------------------------------
# UTF-16LE path scanner  (fallback for corrupt / unrecognised files)
# ---------------------------------------------------------------------------

def _scan_utf16le_paths(data: bytes, min_len: int = 8) -> List[str]:
    """
    Scan raw bytes for UTF-16LE strings that look like Windows paths.

    Only anchors at positions whose first UTF-16 code unit could start a path:
      - Drive letter (A-Z/a-z) followed immediately by ':'
      - Backslash '\\' (device path / UNC / relative)
      - Forward slash '/'

    This prevents the O(n) substring explosion that a naïve sliding-window
    scan produces (e.g. ".exe", "xe", "e" from a single ".exe" suffix).

    Each candidate is trimmed with _trim_path_garbage() before being returned.
    Plausibility-checked with _is_plausible_path().
    """
    results: List[str] = []
    seen:    Set[str]  = set()
    length = len(data)

    for alignment in (0, 1):
        i = alignment
        while i < length - 3:
            try:
                code0 = struct.unpack_from("<H", data, i)[0]
            except struct.error:
                break

            is_drive     = (0x41 <= code0 <= 0x5A) or (0x61 <= code0 <= 0x7A)
            is_backslash = code0 == 0x005C
            is_fwdslash  = code0 == 0x002F

            if not (is_drive or is_backslash or is_fwdslash):
                i += 2
                continue

            # Drive letter must be followed immediately by ':'
            if is_drive:
                if i + 2 >= length:
                    i += 2
                    continue
                if struct.unpack_from("<H", data, i + 2)[0] != 0x003A:
                    i += 2
                    continue

            # Read the string from this anchor position
            j = i
            chars: List[str] = []
            while j + 1 < length:
                try:
                    code = struct.unpack_from("<H", data, j)[0]
                except struct.error:
                    break
                if code == 0:
                    break
                if code < 0x20 and code != 0x09:
                    break
                if code > 0xFFFD:
                    break
                chars.append(chr(code))
                j += 2

            if len(chars) >= min_len:
                raw = "".join(chars)
                if "\\" in raw or "/" in raw:
                    cleaned = _trim_path_garbage(raw)
                    if _is_plausible_path(cleaned) and cleaned not in seen:
                        seen.add(cleaned)
                        results.append(cleaned)
                    i = j + 2
                    continue

            i += 2

    return results


# ---------------------------------------------------------------------------
# IconCache.db structured parser
# ---------------------------------------------------------------------------

def _read_utf16le(data: bytes, offset: int, byte_len: int) -> str:
    return (data[offset: offset + byte_len]
            .decode("utf-16-le", errors="replace")
            .rstrip("\x00"))


def parse_iconcache_db(
    path: pathlib.Path,
) -> Tuple[List[Tuple[str, str]], str, Optional[int]]:
    """
    Structured parse of a single IconCache.db file.

    Returns: (list of (raw_path, extension), version_str, num_entries_from_header)
    On magic mismatch:  ([], "bad_magic",  None)
    On parse error:     ([], "error:<…>",  None)
    """
    try:
        data = path.read_bytes()
    except OSError as exc:
        LOG.warning("%s: cannot read: %s", path, exc)
        return [], f"error:{exc}", None

    if len(data) < 8:
        LOG.warning("%s: file too small (%d bytes)", path, len(data))
        return [], "too_small", None

    if data[:8] != ICONCACHE_MAGIC:
        LOG.warning("%s: magic mismatch (got %s)", path, data[:8].hex())
        return [], "bad_magic", None

    if len(data) < ICONCACHE_HEADER_SIZE:
        LOG.warning("%s: header truncated", path)
        return [], "truncated_header", None

    try:
        version     = struct.unpack_from("<I", data, 0x08)[0]
        num_entries = struct.unpack_from("<I", data, 0x0C)[0]
    except struct.error as exc:
        LOG.warning("%s: header parse error: %s", path, exc)
        return [], f"header_error:{exc}", None

    version_str = f"0x{version:04X}"
    if version not in SUPPORTED_VERSIONS:
        LOG.warning("%s: unknown version %s — attempting anyway", path, version_str)

    LOG.info("%s: version=%s num_entries=%d", path, version_str, num_entries)

    results: List[Tuple[str, str]] = []
    offset    = ICONCACHE_HEADER_SIZE
    entry_num = 0
    max_iter  = min(num_entries + 500, 500_000)

    while offset < len(data) - 4 and entry_num < max_iter:
        try:
            entry_size = struct.unpack_from("<I", data, offset)[0]
        except struct.error:
            break

        if entry_size == 0:
            offset += 4
            continue

        if entry_size < 20 or offset + entry_size > len(data):
            LOG.debug("%s: entry %d @0x%X bad size %d — stopping",
                      path, entry_num, offset, entry_size)
            break

        try:
            path_size  = struct.unpack_from("<I", data, offset + 0x0C)[0]
            ext_size   = struct.unpack_from("<I", data, offset + 0x10)[0]
        except struct.error as exc:
            LOG.debug("%s: entry %d field error: %s", path, entry_num, exc)
            offset += entry_size
            entry_num += 1
            continue

        field_start = offset + 0x14
        path_end    = field_start + path_size
        ext_end     = path_end + ext_size

        if ext_end > offset + entry_size:
            LOG.debug("%s: entry %d field sizes overflow entry — skipping",
                      path, entry_num)
            offset += entry_size
            entry_num += 1
            continue

        raw_path = ext = ""
        if path_size >= 2:
            try:
                raw_path = _read_utf16le(data, field_start, path_size)
            except Exception as exc:
                LOG.debug("%s: entry %d path decode: %s", path, entry_num, exc)

        if ext_size >= 2:
            try:
                ext = _read_utf16le(data, path_end, ext_size)
            except Exception as exc:
                LOG.debug("%s: entry %d ext decode: %s", path, entry_num, exc)

        if raw_path:
            results.append((raw_path, ext))
            LOG.debug("%s: entry %d path=%r ext=%r", path, entry_num, raw_path, ext)

        offset    += entry_size
        entry_num += 1

    LOG.info("%s: structured parse: %d path(s)", path, len(results))
    return results, version_str, num_entries


def parse_iconcache_file(
    db_path:        pathlib.Path,
    include_non_exe: bool,
) -> List[IconCacheEntry]:
    """
    Parse one IconCache.db.  Applies structured parser; falls back to the
    UTF-16LE string scanner when the structured parse yields nothing.
    Returns a deduplicated list of IconCacheEntry objects.
    """
    user = _infer_user(db_path)
    raw_results, version_str, _ = parse_iconcache_db(db_path)

    fallback_used = False
    if not raw_results:
        LOG.info("%s: structured parse empty — trying fallback scan", db_path)
        try:
            data = db_path.read_bytes()
        except OSError:
            data = b""
        scan = _scan_utf16le_paths(data, min_len=8)
        raw_results   = [(p, "") for p in scan]
        fallback_used = bool(raw_results)
        version_str   = "fallback-scan" if fallback_used else version_str

    entries: List[IconCacheEntry] = []
    seen:    Set[str]             = set()

    for raw_path, ext in raw_results:
        if not raw_path or len(raw_path) < 3:
            continue

        # Normalise and trim garbage from the path
        normalised, norm_notes = normalize_path(raw_path)

        # Reject malformed paths (A:c:\..., \c:\..., etc.)
        if not _is_plausible_path(normalised):
            LOG.debug("Rejecting malformed path: %r", normalised)
            continue

        # Clean the extension — strip any garbage bytes
        safe_ext = _clean_extension(
            ext.lower() if ext else pathlib.PureWindowsPath(normalised).suffix.lower()
        )

        if not is_binary_ext(safe_ext, normalised, include_non_exe):
            continue

        # Deduplicate on normalised lowercase path
        key = normalised.lower()
        if key in seen:
            continue
        seen.add(key)

        all_notes = "; ".join(filter(None, [
            norm_notes,
            "fallback-scan" if fallback_used else "",
        ]))

        entries.append(IconCacheEntry(
            user=user,
            iconcache_file=str(db_path),
            binary_path=normalised,
            raw_path=raw_path,
            extension=safe_ext,
            db_version=version_str,
            notes=all_notes,
        ))

    LOG.info("%s: %d unique entry/entries after filtering", db_path, len(entries))
    return entries


# ---------------------------------------------------------------------------
# Minimal pure-Python Windows Registry Hive parser  (Amcache support)
# ---------------------------------------------------------------------------

REGF_MAGIC    = b"regf"
REG_SZ        = 1
REG_EXPAND_SZ = 2
REG_BINARY    = 3
REG_DWORD     = 4
REG_QWORD     = 11


class HiveParseError(Exception):
    pass


class RegistryHive:
    def __init__(self, data: bytes) -> None:
        if data[:4] != REGF_MAGIC:
            raise HiveParseError("Not a registry hive (missing 'regf')")
        self._data       = data
        self._hive_start = 0x1000
        root_rel         = struct.unpack_from("<I", data, 36)[0]
        self._root       = self._read_nk(self._abs(root_rel))

    def _abs(self, rel: int) -> int:
        return self._hive_start + rel

    def _read_nk(self, abs_off: int) -> Optional["NKCell"]:
        d = self._data
        if abs_off + 4 > len(d):
            return None
        if struct.unpack_from("<i", d, abs_off)[0] >= 0:
            return None
        sig_off = abs_off + 4
        if sig_off + 2 > len(d) or d[sig_off: sig_off + 2] != b"nk":
            return None
        return NKCell(d, sig_off, self)

    def open_key(self, path: str) -> Optional["NKCell"]:
        parts = [p for p in path.replace("\\", "/").split("/") if p]
        key   = self._root
        for part in parts:
            if key is None:
                return None
            key = key.subkey(part)
        return key


class NKCell:
    __slots__ = ("_data", "_o", "_hive")

    def __init__(self, data: bytes, offset: int, hive: RegistryHive) -> None:
        self._data = data
        self._o    = offset
        self._hive = hive

    @property
    def name(self) -> str:
        d, o     = self._data, self._o
        flags    = struct.unpack_from("<H", d, o + 2)[0]
        name_len = struct.unpack_from("<H", d, o + 72)[0]
        raw = d[o + 76: o + 76 + name_len]
        return (raw.decode("ascii",    errors="replace") if (flags & 0x20)
                else raw.decode("utf-16-le", errors="replace"))

    def subkeys(self) -> List["NKCell"]:
        cnt = struct.unpack_from("<I", self._data, self._o + 24)[0]
        if cnt == 0:
            return []
        list_abs = self._hive._abs(
            struct.unpack_from("<I", self._data, self._o + 28)[0]
        )
        return list(self._walk_list(list_abs))

    def _walk_list(self, abs_off: int) -> Iterator["NKCell"]:
        d = self._data
        if abs_off + 4 > len(d):
            return
        if struct.unpack_from("<i", d, abs_off)[0] >= 0:
            return
        sig_off = abs_off + 4
        if sig_off + 2 > len(d):
            return
        sig = d[sig_off: sig_off + 2]
        if sig in (b"lf", b"lh"):
            cnt = struct.unpack_from("<H", d, sig_off + 2)[0]
            for i in range(cnt):
                rel = struct.unpack_from("<I", d, sig_off + 4 + i * 8)[0]
                nk  = self._hive._read_nk(self._hive._abs(rel))
                if nk:
                    yield nk
        elif sig == b"li":
            cnt = struct.unpack_from("<H", d, sig_off + 2)[0]
            for i in range(cnt):
                rel = struct.unpack_from("<I", d, sig_off + 4 + i * 4)[0]
                nk  = self._hive._read_nk(self._hive._abs(rel))
                if nk:
                    yield nk
        elif sig == b"ri":
            cnt = struct.unpack_from("<H", d, sig_off + 2)[0]
            for i in range(cnt):
                sub = struct.unpack_from("<I", d, sig_off + 4 + i * 4)[0]
                yield from self._walk_list(self._hive._abs(sub))

    def subkey(self, name: str) -> Optional["NKCell"]:
        nl = name.lower()
        for sk in self.subkeys():
            try:
                if sk.name.lower() == nl:
                    return sk
            except Exception:
                continue
        return None

    def values(self) -> List["VKCell"]:
        cnt = struct.unpack_from("<I", self._data, self._o + 40)[0]
        if cnt == 0:
            return []
        list_abs = self._hive._abs(
            struct.unpack_from("<I", self._data, self._o + 44)[0]
        )
        out: List[VKCell] = []
        for i in range(cnt):
            ptr_off = list_abs + 4 + i * 4
            if ptr_off + 4 > len(self._data):
                break
            vk_rel  = struct.unpack_from("<I", self._data, ptr_off)[0]
            vk_abs  = self._hive._abs(vk_rel)
            if vk_abs + 4 > len(self._data):
                continue
            if struct.unpack_from("<i", self._data, vk_abs)[0] >= 0:
                continue
            sig_off = vk_abs + 4
            if self._data[sig_off: sig_off + 2] == b"vk":
                out.append(VKCell(self._data, sig_off, self._hive))
        return out

    def value(self, name: str) -> Optional["VKCell"]:
        nl = name.lower()
        for v in self.values():
            try:
                if v.name.lower() == nl:
                    return v
            except Exception:
                continue
        return None


class VKCell:
    __slots__ = ("_data", "_o", "_hive")

    def __init__(self, data: bytes, offset: int, hive: RegistryHive) -> None:
        self._data = data
        self._o    = offset
        self._hive = hive

    @property
    def name(self) -> str:
        d, o     = self._data, self._o
        flags    = struct.unpack_from("<H", d, o + 12)[0]
        name_len = struct.unpack_from("<H", d, o + 2)[0]
        raw = d[o + 20: o + 20 + name_len]
        return (raw.decode("ascii",    errors="replace") if (flags & 1)
                else raw.decode("utf-16-le", errors="replace"))

    def _raw_bytes(self) -> bytes:
        d, o     = self._data, self._o
        size_raw = struct.unpack_from("<I", d, o + 4)[0]
        data_off = struct.unpack_from("<I", d, o + 16)[0]
        if size_raw & 0x80000000:
            real = size_raw & 0x7FFFFFFF
            return struct.pack("<I", data_off)[:real]
        data_abs = self._hive._abs(data_off)
        real     = size_raw & 0x7FFFFFFF
        return d[data_abs + 4: data_abs + 4 + real]

    def string_value(self) -> Optional[str]:
        dt = struct.unpack_from("<I", self._data, self._o + 8)[0] & 0xFFFF
        if dt not in (REG_SZ, REG_EXPAND_SZ):
            return None
        try:
            return self._raw_bytes().decode("utf-16-le", errors="replace").rstrip("\x00")
        except Exception:
            return None

    def dword_value(self) -> Optional[int]:
        dt = struct.unpack_from("<I", self._data, self._o + 8)[0] & 0xFFFF
        if dt != REG_DWORD:
            return None
        try:
            return struct.unpack_from("<I", self._raw_bytes())[0]
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Amcache.hve parser
# ---------------------------------------------------------------------------

def _filetime_to_iso(ft: int) -> Optional[str]:
    if not ft:
        return None
    try:
        import datetime
        ts = (ft - 116444736000000000) / 10_000_000
        dt = datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=ts)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None


def parse_amcache(amcache_path: pathlib.Path) -> Dict[str, AmcacheEntry]:
    """
    Parse Amcache.hve.  Returns dict keyed by lower-case normalised full path.
    Supports modern (InventoryApplicationFile) and legacy (File\\{VolumeGUID}) layouts.
    """
    try:
        data = amcache_path.read_bytes()
    except OSError as exc:
        LOG.error("Cannot read Amcache: %s", exc)
        return {}
    try:
        hive = RegistryHive(data)
    except HiveParseError as exc:
        LOG.error("Amcache hive error: %s", exc)
        return {}

    entries: Dict[str, AmcacheEntry] = {}

    modern = hive.open_key("Root\\InventoryApplicationFile")
    if modern:
        LOG.info("Amcache: modern InventoryApplicationFile layout")
        for app_key in modern.subkeys():
            try:
                _amcache_modern(app_key, entries)
            except Exception as exc:
                LOG.debug("Amcache modern %s: %s", app_key.name, exc)

    legacy = hive.open_key("Root\\File")
    if legacy:
        LOG.info("Amcache: legacy File layout")
        for vol_key in legacy.subkeys():
            for seq_key in vol_key.subkeys():
                try:
                    _amcache_legacy(seq_key, entries)
                except Exception as exc:
                    LOG.debug("Amcache legacy: %s", exc)

    LOG.info("Amcache: %d entries loaded", len(entries))
    return entries


def _amcache_modern(key: NKCell, out: Dict[str, AmcacheEntry]) -> None:
    pv        = key.value("LowerCaseLongPath") or key.value("LowercaseLongPath")
    full_path = pv.string_value() if pv else None
    if not full_path:
        return

    sha1 = ""
    fid  = key.value("FileId")
    if fid:
        raw = fid.string_value() or ""
        sha1 = (raw[4:44] if (len(raw) >= 44 and raw.startswith("0000"))
                else raw[:40] if len(raw) >= 40 else raw).upper()

    size: Optional[int] = None
    sv = key.value("Size")
    if sv:
        s = sv.string_value()
        if s and s.isdigit():
            size = int(s)

    ld = key.value("LinkDate")
    first_run = ld.string_value() if ld else None

    pn           = key.value("ProductName") or key.value("Name")
    product_name = pn.string_value() if pn else ""

    key_norm = full_path.lower().replace("/", "\\")
    out[key_norm] = AmcacheEntry(full_path=full_path, sha1=sha1, size=size,
                                 first_run=first_run, product_name=product_name or "")


def _amcache_legacy(key: NKCell, out: Dict[str, AmcacheEntry]) -> None:
    pv        = key.value("0")
    full_path = pv.string_value() if pv else None
    if not full_path:
        return

    sha1 = ""
    sv   = key.value("101")
    if sv:
        raw  = sv.string_value() or ""
        sha1 = (raw[-40:] if len(raw) >= 40 else raw).upper()

    size: Optional[int] = None
    szv = key.value("6")
    if szv:
        size = szv.dword_value()

    first_run: Optional[str] = None
    mtv = key.value("f")
    if mtv:
        raw_ft = mtv.string_value()
        if raw_ft:
            try:
                first_run = _filetime_to_iso(int(raw_ft, 16))
            except ValueError:
                pass

    pn           = key.value("d")
    product_name = pn.string_value() if pn else ""

    key_norm = full_path.lower().replace("/", "\\")
    out[key_norm] = AmcacheEntry(full_path=full_path, sha1=sha1, size=size,
                                 first_run=first_run, product_name=product_name or "")


# ---------------------------------------------------------------------------
# Join / enrichment
# ---------------------------------------------------------------------------

def join_with_amcache(
    icon_entries: List[IconCacheEntry],
    amcache:      Dict[str, AmcacheEntry],
) -> List[ResultRow]:
    """O(1) lookup per entry via full-path dict + basename index."""
    basename_index: Dict[str, List[AmcacheEntry]] = {}
    for entry in amcache.values():
        basename_index.setdefault(entry.basename, []).append(entry)

    rows: List[ResultRow] = []
    for ic in icon_entries:
        norm_lower = ic.binary_path.lower().replace("/", "\\")
        am         = amcache.get(norm_lower)
        if am:
            match_type = "FULL_PATH"
            notes      = ic.notes
        else:
            bname      = pathlib.PureWindowsPath(norm_lower).name
            candidates = basename_index.get(bname, [])
            if candidates:
                am         = candidates[0]
                match_type = "BASENAME"
                notes      = "; ".join(filter(None, [ic.notes, "low-confidence basename match"]))
            else:
                am         = None
                match_type = "NONE"
                notes      = ic.notes

        rows.append(ResultRow(
            user=ic.user, iconcache_file=ic.iconcache_file,
            binary_path=ic.binary_path, raw_path=ic.raw_path,
            extension=ic.extension, db_version=ic.db_version,
            sha1=am.sha1 if am else "",
            match_type=match_type,
            size=am.size if am else None,
            first_run=am.first_run if am else None,
            product_name=am.product_name if am else "",
            notes=notes,
        ))
    return rows


def make_result_rows_no_amcache(entries: List[IconCacheEntry]) -> List[ResultRow]:
    return [
        ResultRow(
            user=ic.user, iconcache_file=ic.iconcache_file,
            binary_path=ic.binary_path, raw_path=ic.raw_path,
            extension=ic.extension, db_version=ic.db_version,
            sha1="", match_type="N/A",
            size=None, first_run=None, product_name="", notes=ic.notes,
        )
        for ic in entries
    ]


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def dedupe_results(rows: List[ResultRow]) -> List[ResultRow]:
    """Keep one row per (user, binary_path); prefer FULL_PATH > BASENAME > NONE."""
    _rank = {"FULL_PATH": 0, "BASENAME": 1, "NONE": 2, "N/A": 3}
    best: Dict[Tuple[str, str], ResultRow] = {}
    for row in rows:
        key = (row.user.lower(), row.binary_path.lower())
        ex  = best.get(key)
        if ex is None or _rank.get(row.match_type, 9) < _rank.get(ex.match_type, 9):
            best[key] = row
    return list(best.values())


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------

def _safe_print(line: str) -> None:
    """Print a line, replacing any unencodable characters for the current console."""
    try:
        print(line)
    except UnicodeEncodeError:
        enc = getattr(sys.stdout, "encoding", None) or "utf-8"
        print(line.encode(enc, errors="replace").decode(enc, errors="replace"))


def _trunc(s: str, n: int) -> str:
    return s if len(s) <= n else s[:n - 1] + "…"


def print_table(rows: List[ResultRow], use_amcache: bool) -> None:
    if not rows:
        print("(no results)")
        return

    cols = (
        ["user", "iconcache_file", "binary_path", "extension",
         "db_version", "sha1", "match_type", "first_run", "notes"]
        if use_amcache else
        ["user", "iconcache_file", "binary_path", "extension",
         "db_version", "notes"]
    )

    def rdict(r: ResultRow) -> Dict[str, str]:
        return {
            "user":           _sanitise_str(r.user),
            "iconcache_file": os.path.basename(r.iconcache_file),
            "binary_path":    _sanitise_str(r.binary_path),
            "extension":      _sanitise_str(r.extension),
            "db_version":     r.db_version,
            "sha1":           r.sha1,
            "match_type":     r.match_type,
            "first_run":      r.first_run or "",
            "notes":          _sanitise_str(r.notes),
        }

    widths = {c: len(c) for c in cols}
    dicts  = [rdict(r) for r in rows]
    for d in dicts:
        for c in cols:
            widths[c] = max(widths[c], len(d.get(c, "")))

    # Cap wide columns so the table doesn't explode
    widths["binary_path"]    = min(widths["binary_path"],    60)
    widths["iconcache_file"] = min(widths["iconcache_file"], 18)
    widths["notes"]          = min(widths["notes"],          40)
    widths["sha1"]           = min(widths.get("sha1", 0),    40)

    sep    = "+-" + "-+-".join("-" * widths[c] for c in cols) + "-+"
    header = "| " + " | ".join(c.upper().ljust(widths[c]) for c in cols) + " |"
    _safe_print(sep)
    _safe_print(header)
    _safe_print(sep)
    for d in dicts:
        line = "| " + " | ".join(
            _trunc(d.get(c, ""), widths[c]).ljust(widths[c]) for c in cols
        ) + " |"
        _safe_print(line)
    _safe_print(sep)
    print(f"\n{len(rows)} result(s)")


def write_json(rows: List[ResultRow], out_path: str) -> None:
    with open(out_path, "w", encoding="utf-8", errors="replace") as f:
        json.dump([asdict(r) for r in rows], f, indent=2, default=str,
                  ensure_ascii=False)
    print(f"[+] JSON written -> {out_path}")


def write_csv(rows: List[ResultRow], out_path: str) -> None:
    fields = [
        "user", "iconcache_file", "binary_path", "raw_path",
        "extension", "db_version",
        "sha1", "match_type", "size", "first_run", "product_name", "notes",
    ]
    with open(out_path, "w", newline="", encoding="utf-8-sig",
              errors="replace") as f:
        # utf-8-sig writes the UTF-8 BOM so Excel opens it correctly
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for row in rows:
            w.writerow(asdict(row))
    print(f"[+] CSV written -> {out_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="IconCacheReader",
        description=textwrap.dedent("""\
            DFIR tool: extract historical binary paths from Windows
            IconCache.db, with optional Amcache.hve SHA1 enrichment.

            Target file (per ThinkDFIR research, Phill Moore 2025-12-28):
              %LOCALAPPDATA%\\IconCache.db
              => <profile>\\AppData\\Local\\IconCache.db

            NOTE: iconcache_*.db in the Explorer sub-folder are icon IMAGE stores
            (CMMM format, no paths inside). This tool does NOT parse them.

            Forensic caveats:
              * Written at shutdown/reboot - live data may not be flushed yet.
              * Evidence of EXISTENCE only (Explorer rendered the icon).
              * NOT evidence of execution.
              * v0x0507 stores paths in lowercase.
        """),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python IconCacheReader.py -user-profile C:\\Cases\\Image\\Users\\Bob
              python IconCacheReader.py -users-dir C:\\Cases\\Image\\Users -csv out.csv
              python IconCacheReader.py -users-dir C:\\Cases\\Image\\Users \\
                  -amcache C:\\Cases\\Image\\Windows\\AppCompat\\Programs\\Amcache.hve \\
                  -json out.json -csv out.csv
              python IconCacheReader.py -user-profile ... -include-non-exe -verbose
        """),
    )
    src = p.add_mutually_exclusive_group()
    src.add_argument("-user-profile", metavar="PATH",
                     help="Single user profile directory")
    src.add_argument("-users-dir",    metavar="PATH",
                     help="Users directory - all sub-profiles processed")

    p.add_argument("-amcache",         metavar="PATH",
                   help="Amcache.hve for SHA1 enrichment (optional)")
    p.add_argument("-json",            metavar="FILE", help="Write JSON output")
    p.add_argument("-csv",             metavar="FILE", help="Write CSV output")
    p.add_argument("-recursive",       action="store_true",
                   help="Recursively search for IconCache.db in non-standard locations")
    p.add_argument("-no-dedupe",       action="store_true",
                   help="Disable deduplication (default: enabled)")
    p.add_argument("-include-non-exe", action="store_true",
                   help="Include all file types (default: .exe/.dll/.sys etc. only)")
    p.add_argument("-verbose", "-v",   action="store_true", help="Verbose output")
    p.add_argument("-debug",           action="store_true", help="Debug output (very noisy)")
    return p


def main() -> int:
    # On Windows, reconfigure stdout/stderr to UTF-8 so non-ASCII paths in
    # the output don't crash with UnicodeEncodeError on cp1252/cp850 consoles.
    if sys.platform == "win32":
        try:
            import io
            sys.stdout = io.TextIOWrapper(
                sys.stdout.buffer, encoding="utf-8", errors="replace"
            )
            sys.stderr = io.TextIOWrapper(
                sys.stderr.buffer, encoding="utf-8", errors="replace"
            )
        except Exception:
            pass  # best-effort; don't break if buffer unavailable

    parser = build_parser()
    args   = parser.parse_args()
    _setup_logging(args.verbose, args.debug)

    if not args.user_profile and not args.users_dir:
        parser.print_help()
        print("\n[ERROR] Specify -user-profile or -users-dir", file=sys.stderr)
        return 2

    # --- Discover profiles ---
    if args.user_profile:
        p = pathlib.Path(args.user_profile)
        if not p.is_dir():
            print(f"[ERROR] Profile dir not found: {p}", file=sys.stderr)
            return 2
        profiles = [p]
    else:
        ud = pathlib.Path(args.users_dir)
        if not ud.is_dir():
            print(f"[ERROR] Users dir not found: {ud}", file=sys.stderr)
            return 2
        profiles = discover_profiles(ud)
        if not profiles:
            print(f"[ERROR] No user profiles found under {ud}", file=sys.stderr)
            return 2

    print(f"[*] Processing {len(profiles)} user profile(s)...")

    # --- Parse IconCache.db files ---
    all_entries: List[IconCacheEntry] = []
    failed = 0

    for profile in profiles:
        dbs = discover_iconcache_files(profile, args.recursive)
        if not dbs:
            if args.verbose:
                print(f"  [!] No IconCache.db found under: {profile}")
            continue
        for db_path in dbs:
            print(f"  [+] Parsing: {db_path}")
            try:
                entries = parse_iconcache_file(db_path, args.include_non_exe)
                all_entries.extend(entries)
                print(f"      -> {len(entries)} path(s) extracted")
            except Exception as exc:
                LOG.error("Failed: %s - %s", db_path, exc, exc_info=args.debug)
                print(f"      [!] Error: {exc}", file=sys.stderr)
                failed += 1

    if not all_entries:
        print("[!] No paths extracted from any IconCache.db.")
        return 1 if failed else 0

    # --- Amcache ---
    use_amcache = bool(args.amcache)
    amcache_data: Dict[str, AmcacheEntry] = {}
    if args.amcache:
        ap = pathlib.Path(args.amcache)
        if not ap.is_file():
            print(f"[ERROR] Amcache not found: {ap}", file=sys.stderr)
            return 2
        print(f"[*] Parsing Amcache: {ap}")
        amcache_data = parse_amcache(ap)
        print(f"    -> {len(amcache_data)} Amcache entries loaded")

    # --- Join ---
    rows = (join_with_amcache(all_entries, amcache_data)
            if use_amcache else make_result_rows_no_amcache(all_entries))

    # --- Deduplicate ---
    if not args.no_dedupe:
        before = len(rows)
        rows   = dedupe_results(rows)
        LOG.info("Dedupe: %d -> %d", before, len(rows))

    rows.sort(key=lambda r: (r.user.lower(), r.binary_path.lower()))

    # --- Output ---
    print()
    print_table(rows, use_amcache)
    if args.json:
        write_json(rows, args.json)
    if args.csv:
        write_csv(rows, args.csv)

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
