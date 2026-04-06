#!/usr/bin/env python3
"""
tests/test_IconCacheReader.py — Validation tests for IconCacheReader.py v2.0

Format reference (ThinkDFIR, 2025-12-28):
  %LOCALAPPDATA%\\IconCache.db
  Magic: 48 00 00 00 57 69 6E 34
  Version 0x0507 (current) / 0x0506 (older)
  Entry layout: entry_size, entry_hash, flags, path_size, extension_size,
                <path UTF-16LE>, <extension UTF-16LE>

Run with:  python tests/test_IconCacheReader.py
      or:  python -m pytest tests/ -v
"""

import csv
import json
import os
import pathlib
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
import IconCacheReader as tool


# ---------------------------------------------------------------------------
# Synthetic IconCache.db builder helpers
# ---------------------------------------------------------------------------

ICONCACHE_MAGIC   = b"\x48\x00\x00\x00\x57\x69\x6E\x34"
HEADER_SIZE       = 0x48
VERSION_0507      = 0x0507
VERSION_0506      = 0x0506


def _utf16le(s: str) -> bytes:
    return s.encode("utf-16-le")


def _make_entry(path: str, extension: str = "") -> bytes:
    """Build a single IconCache.db entry in the correct binary format."""
    path_bytes = _utf16le(path)
    ext_bytes  = _utf16le(extension)
    # field layout: entry_size(4) + hash(4) + flags(4) + path_size(4)
    #               + ext_size(4) + path_bytes + ext_bytes
    fixed_hdr  = 5 * 4   # 20 bytes of fixed fields
    entry_size = fixed_hdr + len(path_bytes) + len(ext_bytes)
    entry = struct.pack(
        "<IIIII",
        entry_size,       # total entry size
        0xDEADBEEF,       # entry_hash (arbitrary)
        0,                # flags
        len(path_bytes),  # path_size
        len(ext_bytes),   # extension_size
    )
    entry += path_bytes
    entry += ext_bytes
    return entry


def make_iconcache_db(
    entries: list,            # list of (path, extension) tuples
    version: int = VERSION_0507,
) -> bytes:
    """
    Build a minimal valid IconCache.db binary matching the ThinkDFIR-documented
    format.

    entries: list of (path_str, extension_str) pairs.
    """
    entry_data = b"".join(_make_entry(p, e) for p, e in entries)

    # Header (0x48 bytes)
    header = b""
    header += struct.pack("<I", HEADER_SIZE)           # 0x00: header_size
    header += b"Win4"                                   # 0x04: magic
    header += struct.pack("<I", version)                # 0x08: version
    header += struct.pack("<I", len(entries))           # 0x0C: num_entries
    header += b"\x00" * (0x20 - len(header))            # 0x10–0x1F: unknowns
    header += struct.pack("<Q", 0)                      # 0x20: last_modified FILETIME
    header += struct.pack("<I", len(entry_data))        # 0x28: entry_data_size
    header += b"\x00" * (HEADER_SIZE - len(header))    # pad to 0x48

    assert len(header) == HEADER_SIZE, f"Header wrong size: {len(header)}"
    return header + entry_data


def make_profile(tmpdir: pathlib.Path, username: str,
                 entries: list, version: int = VERSION_0507) -> pathlib.Path:
    """
    Create a minimal Windows-like user profile tree with an IconCache.db at
    <tmpdir>/Users/<username>/AppData/Local/IconCache.db
    """
    profile = tmpdir / "Users" / username
    local_appdata = profile / "AppData" / "Local"
    local_appdata.mkdir(parents=True)
    db = local_appdata / "IconCache.db"
    db.write_bytes(make_iconcache_db(entries, version))
    return profile


# ---------------------------------------------------------------------------
# Magic / header tests
# ---------------------------------------------------------------------------

class TestMagicAndHeader(unittest.TestCase):

    def test_correct_magic_accepted(self):
        with tempfile.TemporaryDirectory() as td:
            db = pathlib.Path(td) / "IconCache.db"
            db.write_bytes(make_iconcache_db([
                (r"c:\windows\notepad.exe", ".exe")
            ]))
            results, version_str, num = tool.parse_iconcache_db(db)
            self.assertIsNotNone(num)
            self.assertEqual(version_str, "0x0507")
            self.assertGreater(len(results), 0)

    def test_bad_magic_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            db = pathlib.Path(td) / "IconCache.db"
            db.write_bytes(b"JUNK" + b"\x00" * 200)
            results, version_str, num = tool.parse_iconcache_db(db)
            self.assertEqual(results, [])
            self.assertEqual(version_str, "bad_magic")
            self.assertIsNone(num)

    def test_cmmm_magic_rejected_as_bad_magic(self):
        """iconcache_*.db (CMMM image stores) must NOT be mistaken for path DBs."""
        with tempfile.TemporaryDirectory() as td:
            db = pathlib.Path(td) / "iconcache_256.db"
            # CMMM magic — this is an image store, not a path database
            db.write_bytes(b"CMMM" + b"\x00" * 200)
            results, version_str, num = tool.parse_iconcache_db(db)
            self.assertEqual(results, [])
            self.assertEqual(version_str, "bad_magic")

    def test_version_0506_accepted(self):
        with tempfile.TemporaryDirectory() as td:
            db = pathlib.Path(td) / "IconCache.db"
            db.write_bytes(make_iconcache_db(
                [(r"c:\windows\cmd.exe", ".exe")],
                version=VERSION_0506,
            ))
            results, version_str, _ = tool.parse_iconcache_db(db)
            self.assertEqual(version_str, "0x0506")
            self.assertGreater(len(results), 0)

    def test_truncated_file(self):
        with tempfile.TemporaryDirectory() as td:
            db = pathlib.Path(td) / "IconCache.db"
            db.write_bytes(ICONCACHE_MAGIC)   # magic only, no full header
            results, version_str, num = tool.parse_iconcache_db(db)
            self.assertEqual(results, [])
            self.assertIn("truncated", version_str)

    def test_corrupt_entries_handled_gracefully(self):
        """Corrupt entry data after a valid header must not raise."""
        with tempfile.TemporaryDirectory() as td:
            db = pathlib.Path(td) / "IconCache.db"
            # Valid header, then garbage entries
            header = make_iconcache_db([], version=VERSION_0507)[:HEADER_SIZE]
            db.write_bytes(header + b"\xff" * 200)
            try:
                results, _, _ = tool.parse_iconcache_db(db)
                # Any result is acceptable — we just must not raise
            except Exception as exc:
                self.fail(f"parse_iconcache_db raised on corrupt data: {exc}")


# ---------------------------------------------------------------------------
# Entry parsing tests
# ---------------------------------------------------------------------------

class TestEntryParsing(unittest.TestCase):

    def test_extracts_path_and_extension(self):
        with tempfile.TemporaryDirectory() as td:
            db = pathlib.Path(td) / "IconCache.db"
            db.write_bytes(make_iconcache_db([
                (r"c:\windows\system32\cmd.exe", ".exe"),
                (r"c:\program files\evil.dll",   ".dll"),
            ]))
            results, _, _ = tool.parse_iconcache_db(db)
            paths = [r[0] for r in results]
            exts  = [r[1] for r in results]
            self.assertIn(r"c:\windows\system32\cmd.exe", paths)
            self.assertIn(r"c:\program files\evil.dll",   paths)
            self.assertIn(".exe", exts)
            self.assertIn(".dll", exts)

    def test_multiple_entries_all_returned(self):
        n = 50
        entries = [(f"c:\\tools\\prog{i}.exe", ".exe") for i in range(n)]
        with tempfile.TemporaryDirectory() as td:
            db = pathlib.Path(td) / "IconCache.db"
            db.write_bytes(make_iconcache_db(entries))
            results, _, num = tool.parse_iconcache_db(db)
            self.assertEqual(num, n)
            self.assertEqual(len(results), n)

    def test_device_path_in_entry(self):
        with tempfile.TemporaryDirectory() as td:
            db = pathlib.Path(td) / "IconCache.db"
            db.write_bytes(make_iconcache_db([
                (r"\Device\HarddiskVolume2\Windows\System32\lsass.exe", ".exe"),
            ]))
            results, _, _ = tool.parse_iconcache_db(db)
            self.assertEqual(len(results), 1)
            self.assertIn("lsass.exe", results[0][0])

    def test_unc_path_in_entry(self):
        with tempfile.TemporaryDirectory() as td:
            db = pathlib.Path(td) / "IconCache.db"
            db.write_bytes(make_iconcache_db([
                (r"\\server\share\tools\psexec.exe", ".exe"),
            ]))
            results, _, _ = tool.parse_iconcache_db(db)
            self.assertEqual(len(results), 1)
            self.assertIn("psexec.exe", results[0][0])


# ---------------------------------------------------------------------------
# Discovery tests
# ---------------------------------------------------------------------------

class TestDiscovery(unittest.TestCase):

    def test_finds_iconcache_db_in_standard_location(self):
        with tempfile.TemporaryDirectory() as td:
            tmpdir = pathlib.Path(td)
            profile = make_profile(tmpdir, "Alice",
                                   [(r"c:\windows\notepad.exe", ".exe")])
            found = tool.discover_iconcache_files(profile)
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0].name, "IconCache.db")

    def test_does_not_find_iconcache_star_db(self):
        """
        iconcache_*.db (image stores) must NOT be discovered as path databases.
        They live in AppData\\Local\\Microsoft\\Windows\\Explorer\\ and contain
        no file paths — only icon pixel data.
        """
        with tempfile.TemporaryDirectory() as td:
            tmpdir = pathlib.Path(td)
            profile = tmpdir / "Users" / "Bob"
            explorer_dir = profile / "AppData" / "Local" / "Microsoft" / "Windows" / "Explorer"
            explorer_dir.mkdir(parents=True)
            # Write a fake CMMM image store — should NOT be picked up
            for size in (16, 32, 256):
                (explorer_dir / f"iconcache_{size}.db").write_bytes(b"CMMM" + b"\x00" * 100)
            found = tool.discover_iconcache_files(profile)
            self.assertEqual(found, [],
                             "iconcache_*.db image stores should NOT be discovered")

    def test_recursive_finds_non_standard_location(self):
        with tempfile.TemporaryDirectory() as td:
            tmpdir = pathlib.Path(td)
            profile = tmpdir / "Users" / "Charlie"
            # Non-standard location
            odd_dir = profile / "OddFolder" / "Cache"
            odd_dir.mkdir(parents=True)
            db = odd_dir / "IconCache.db"
            db.write_bytes(make_iconcache_db([(r"c:\test.exe", ".exe")]))
            found = tool.discover_iconcache_files(profile, recursive=True)
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0], db)

    def test_recursive_off_does_not_find_non_standard(self):
        with tempfile.TemporaryDirectory() as td:
            tmpdir = pathlib.Path(td)
            profile = tmpdir / "Users" / "Dave"
            odd_dir = profile / "OddFolder"
            odd_dir.mkdir(parents=True)
            (odd_dir / "IconCache.db").write_bytes(
                make_iconcache_db([(r"c:\test.exe", ".exe")])
            )
            found = tool.discover_iconcache_files(profile, recursive=False)
            self.assertEqual(found, [])

    def test_discover_profiles_excludes_system_dirs(self):
        with tempfile.TemporaryDirectory() as td:
            tmpdir = pathlib.Path(td)
            users_dir = tmpdir / "Users"
            users_dir.mkdir()
            for name in ("Alice", "Bob", "Public", "Default", "Default User", "All Users"):
                (users_dir / name).mkdir()
            profiles = tool.discover_profiles(users_dir)
            names = [p.name for p in profiles]
            self.assertIn("Alice", names)
            self.assertIn("Bob", names)
            for excluded in ("Public", "Default", "Default User", "All Users"):
                self.assertNotIn(excluded, names)


# ---------------------------------------------------------------------------
# Normalisation tests
# ---------------------------------------------------------------------------

class TestPathNormalisation(unittest.TestCase):

    def test_dos_path_unchanged(self):
        norm, notes = tool.normalize_path(r"C:\Windows\System32\cmd.exe")
        self.assertEqual(norm, r"C:\Windows\System32\cmd.exe")
        self.assertEqual(notes, "")

    def test_device_path_normalised(self):
        norm, notes = tool.normalize_path(
            r"\Device\HarddiskVolume2\Windows\explorer.exe"
        )
        self.assertIn("C:", norm)
        self.assertIn("explorer.exe", norm)
        self.assertIn("device-path-heuristic", notes)

    def test_drive_letter_uppercased(self):
        # v0x0507 stores lowercase paths — drive letter must be uppercased
        norm, _ = tool.normalize_path(r"c:\windows\system32\notepad.exe")
        self.assertTrue(norm.startswith("C:"))

    def test_forward_slashes_converted(self):
        norm, _ = tool.normalize_path(r"C:/Windows/notepad.exe")
        self.assertNotIn("/", norm)

    def test_unc_prefix_preserved(self):
        norm, _ = tool.normalize_path(r"\\server\share\tool.exe")
        self.assertTrue(norm.startswith("\\\\"))

    def test_null_bytes_stripped(self):
        norm, _ = tool.normalize_path("C:\\test.exe\x00\x00")
        self.assertNotIn("\x00", norm)

    def test_duplicate_slashes_collapsed(self):
        norm, _ = tool.normalize_path(r"C:\\Windows\\\\System32\\cmd.exe")
        self.assertNotIn("\\\\\\", norm)


# ---------------------------------------------------------------------------
# Filter tests
# ---------------------------------------------------------------------------

class TestBinaryFilter(unittest.TestCase):

    def test_exe_passes(self):
        self.assertTrue(tool.is_binary_ext(".exe", "C:\\a.exe", False))

    def test_dll_passes(self):
        self.assertTrue(tool.is_binary_ext(".dll", "C:\\a.dll", False))

    def test_sys_passes(self):
        self.assertTrue(tool.is_binary_ext(".sys", "C:\\a.sys", False))

    def test_txt_blocked(self):
        self.assertFalse(tool.is_binary_ext(".txt", "C:\\readme.txt", False))

    def test_txt_passes_with_flag(self):
        self.assertTrue(tool.is_binary_ext(".txt", "C:\\readme.txt", True))

    def test_empty_ext_falls_back_to_path_suffix(self):
        self.assertTrue(tool.is_binary_ext("", r"C:\Windows\cmd.exe", False))


# ---------------------------------------------------------------------------
# parse_iconcache_file (full pipeline) tests
# ---------------------------------------------------------------------------

class TestParseIconCacheFile(unittest.TestCase):

    def test_extracts_entries_with_correct_normalisation(self):
        with tempfile.TemporaryDirectory() as td:
            tmpdir = pathlib.Path(td)
            # v0x0507 stores lowercase paths
            profile = make_profile(tmpdir, "Alice", [
                (r"c:\windows\system32\cmd.exe",           ".exe"),
                (r"c:\users\alice\downloads\payload.dll",  ".dll"),
                (r"c:\windows\readme.txt",                 ".txt"),  # filtered
            ])
            db = profile / "AppData" / "Local" / "IconCache.db"
            entries = tool.parse_iconcache_file(db, include_non_exe=False)
            paths = [e.binary_path.lower() for e in entries]
            self.assertTrue(any("cmd.exe" in p for p in paths))
            self.assertTrue(any("payload.dll" in p for p in paths))
            self.assertFalse(any(".txt" in p for p in paths))

    def test_drive_letter_uppercased_in_result(self):
        with tempfile.TemporaryDirectory() as td:
            tmpdir = pathlib.Path(td)
            profile = make_profile(tmpdir, "Bob", [
                (r"c:\windows\notepad.exe", ".exe"),
            ])
            db = profile / "AppData" / "Local" / "IconCache.db"
            entries = tool.parse_iconcache_file(db, include_non_exe=False)
            self.assertTrue(any(e.binary_path.startswith("C:") for e in entries))

    def test_include_non_exe_flag(self):
        with tempfile.TemporaryDirectory() as td:
            tmpdir = pathlib.Path(td)
            profile = make_profile(tmpdir, "Carol", [
                (r"c:\docs\report.txt", ".txt"),
                (r"c:\tools\run.exe",   ".exe"),
            ])
            db = profile / "AppData" / "Local" / "IconCache.db"
            entries_all = tool.parse_iconcache_file(db, include_non_exe=True)
            paths = [e.binary_path.lower() for e in entries_all]
            self.assertTrue(any(".txt" in p for p in paths))

    def test_duplicate_paths_deduplicated(self):
        with tempfile.TemporaryDirectory() as td:
            tmpdir = pathlib.Path(td)
            profile = make_profile(tmpdir, "Dan", [
                (r"c:\windows\notepad.exe", ".exe"),
                (r"c:\windows\notepad.exe", ".exe"),
                (r"C:\Windows\notepad.exe", ".exe"),   # same, different case
            ])
            db = profile / "AppData" / "Local" / "IconCache.db"
            entries = tool.parse_iconcache_file(db, include_non_exe=False)
            # Should have exactly 1 after dedup inside parse_iconcache_file
            self.assertEqual(len(entries), 1)

    def test_db_version_recorded(self):
        with tempfile.TemporaryDirectory() as td:
            tmpdir = pathlib.Path(td)
            profile = make_profile(tmpdir, "Eve", [
                (r"c:\windows\cmd.exe", ".exe"),
            ], version=VERSION_0506)
            db = profile / "AppData" / "Local" / "IconCache.db"
            entries = tool.parse_iconcache_file(db, include_non_exe=False)
            self.assertTrue(any(e.db_version == "0x0506" for e in entries))

    def test_fallback_scan_on_bad_magic(self):
        """
        File with bad magic but containing valid UTF-16LE paths should still
        yield results via the fallback scanner.
        """
        with tempfile.TemporaryDirectory() as td:
            tmpdir = pathlib.Path(td)
            profile = tmpdir / "Users" / "Frank"
            local = profile / "AppData" / "Local"
            local.mkdir(parents=True)
            db = local / "IconCache.db"
            # Bad magic, but embed a valid UTF-16LE path
            payload = b"BADM" + b"\x00" * 60
            payload += r"C:\evil\malware.exe".encode("utf-16-le") + b"\x00\x00"
            db.write_bytes(payload)
            entries = tool.parse_iconcache_file(db, include_non_exe=False)
            # Fallback scan should recover the path
            paths = [e.binary_path.lower() for e in entries]
            self.assertTrue(any("malware.exe" in p for p in paths),
                            f"Fallback scan failed. Got paths: {paths}")
            self.assertTrue(any("fallback-scan" in e.notes for e in entries))


# ---------------------------------------------------------------------------
# Amcache joiner tests
# ---------------------------------------------------------------------------

class TestJoiner(unittest.TestCase):

    def _ic(self, path: str, user: str = "Alice") -> tool.IconCacheEntry:
        return tool.IconCacheEntry(
            user=user, iconcache_file="IconCache.db",
            binary_path=path, raw_path=path.lower(),
            extension=pathlib.PureWindowsPath(path).suffix.lower(),
            db_version="0x0507", notes="",
        )

    def _am(self, path: str, sha1: str = "A" * 40) -> tool.AmcacheEntry:
        return tool.AmcacheEntry(
            full_path=path, sha1=sha1, size=12345,
            first_run="2024-01-01T00:00:00Z", product_name="TestApp",
        )

    def test_full_path_match(self):
        ic = [self._ic(r"C:\Windows\notepad.exe")]
        am = {r"c:\windows\notepad.exe": self._am(r"C:\Windows\notepad.exe")}
        rows = tool.join_with_amcache(ic, am)
        self.assertEqual(rows[0].match_type, "FULL_PATH")
        self.assertEqual(rows[0].sha1, "A" * 40)

    def test_basename_match(self):
        ic = [self._ic(r"C:\Downloads\notepad.exe")]
        am = {r"c:\windows\notepad.exe": self._am(r"C:\Windows\notepad.exe", "B" * 40)}
        rows = tool.join_with_amcache(ic, am)
        self.assertEqual(rows[0].match_type, "BASENAME")
        self.assertIn("low-confidence", rows[0].notes)

    def test_no_match(self):
        ic = [self._ic(r"C:\mystery\unknown_tool.exe")]
        rows = tool.join_with_amcache(ic, {})
        self.assertEqual(rows[0].match_type, "NONE")
        self.assertEqual(rows[0].sha1, "")

    def test_full_path_preferred_over_basename(self):
        """When both a full-path and basename match exist, full-path wins."""
        ic = [self._ic(r"C:\Windows\notepad.exe")]
        am = {
            r"c:\windows\notepad.exe":           self._am(r"C:\Windows\notepad.exe", "F" * 40),
            r"c:\other\something\notepad.exe":   self._am(r"C:\other\something\notepad.exe", "B" * 40),
        }
        rows = tool.join_with_amcache(ic, am)
        self.assertEqual(rows[0].match_type, "FULL_PATH")
        self.assertEqual(rows[0].sha1, "F" * 40)


# ---------------------------------------------------------------------------
# Deduplication tests
# ---------------------------------------------------------------------------

class TestDeduplication(unittest.TestCase):

    def _row(self, path: str, match: str, user: str = "Alice") -> tool.ResultRow:
        return tool.ResultRow(
            user=user, iconcache_file="IconCache.db",
            binary_path=path, raw_path=path.lower(),
            extension=".exe", db_version="0x0507",
            sha1="", match_type=match,
            size=None, first_run=None, product_name="", notes="",
        )

    def test_dedupe_keeps_full_path_over_basename(self):
        rows = [
            self._row(r"C:\notepad.exe", "BASENAME"),
            self._row(r"C:\notepad.exe", "FULL_PATH"),
            self._row(r"C:\notepad.exe", "NONE"),
        ]
        result = tool.dedupe_results(rows)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].match_type, "FULL_PATH")

    def test_different_users_not_deduped(self):
        rows = [
            self._row(r"C:\notepad.exe", "NONE", "Alice"),
            self._row(r"C:\notepad.exe", "NONE", "Bob"),
        ]
        result = tool.dedupe_results(rows)
        self.assertEqual(len(result), 2)

    def test_case_insensitive_dedup(self):
        rows = [
            self._row(r"C:\Windows\notepad.exe",          "NONE"),
            self._row(r"C:\windows\notepad.exe",           "FULL_PATH"),
            self._row(r"C:\WINDOWS\NOTEPAD.EXE",           "BASENAME"),
        ]
        result = tool.dedupe_results(rows)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].match_type, "FULL_PATH")


# ---------------------------------------------------------------------------
# UTF-16LE fallback scanner tests
# ---------------------------------------------------------------------------

class TestUTF16Scanner(unittest.TestCase):

    def test_finds_dos_path(self):
        path = r"C:\Windows\System32\notepad.exe"
        data = b"\x00" * 20 + path.encode("utf-16-le") + b"\x00\x00"
        found = tool._scan_utf16le_paths(data)
        self.assertTrue(any(path.lower() in f.lower() for f in found),
                        f"Path not found. Got: {found}")

    def test_finds_unc_path(self):
        path = r"\\server\share\evil.exe"
        data = b"\x00" * 10 + path.encode("utf-16-le") + b"\x00\x00"
        found = tool._scan_utf16le_paths(data)
        self.assertTrue(any("evil.exe" in f for f in found))

    def test_does_not_produce_substring_explosion(self):
        """
        A single long path must yield roughly O(1) results, not O(n) substrings.
        """
        long_path = r"C:\Program Files\SomeVendor\SomeTool\subdir1\subdir2\tool.exe"
        data = long_path.encode("utf-16-le") + b"\x00\x00"
        found = tool._scan_utf16le_paths(data)
        # With anchor-based scanning, we expect at most a handful of results
        # (some overlap from alignment 0 and 1 is acceptable)
        self.assertLessEqual(len(found), 5,
                             f"Too many results ({len(found)}), possible substring explosion")

    def test_ignores_short_strings(self):
        data = r"C:\ab".encode("utf-16-le") + b"\x00\x00"
        found = tool._scan_utf16le_paths(data, min_len=8)
        self.assertEqual(found, [])

    def test_multiple_distinct_paths(self):
        paths = [
            r"C:\Windows\explorer.exe",
            r"C:\Program Files\app.exe",
        ]
        data = b"\x00" * 8
        for p in paths:
            data += p.encode("utf-16-le") + b"\x00\x00" + b"\x00" * 4
        found = tool._scan_utf16le_paths(data)
        found_lower = [f.lower() for f in found]
        for p in paths:
            self.assertTrue(any(p.lower() in f for f in found_lower),
                            f"{p} not found in {found}")


# ---------------------------------------------------------------------------
# Output writer tests
# ---------------------------------------------------------------------------

class TestOutputWriters(unittest.TestCase):

    def _sample(self) -> list[tool.ResultRow]:
        return [tool.ResultRow(
            user="Alice", iconcache_file="IconCache.db",
            binary_path=r"C:\Windows\notepad.exe",
            raw_path=r"c:\windows\notepad.exe",
            extension=".exe", db_version="0x0507",
            sha1="A" * 40, match_type="FULL_PATH",
            size=100000, first_run="2024-01-01T00:00:00Z",
            product_name="Microsoft Windows", notes="",
        )]

    def test_json_output(self):
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "out.json")
            tool.write_json(self._sample(), out)
            with open(out, encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(len(data), 1)
            self.assertEqual(data[0]["user"], "Alice")
            self.assertEqual(data[0]["sha1"], "A" * 40)
            self.assertEqual(data[0]["db_version"], "0x0507")

    def test_csv_output(self):
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "out.csv")
            tool.write_csv(self._sample(), out)
            with open(out, newline="", encoding="utf-8-sig") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["user"], "Alice")
            self.assertEqual(rows[0]["binary_path"], r"C:\Windows\notepad.exe")
            self.assertEqual(rows[0]["db_version"], "0x0507")


# ---------------------------------------------------------------------------
# Registry hive parser smoke tests
# ---------------------------------------------------------------------------

class TestRegistryHive(unittest.TestCase):

    def test_non_hive_raises(self):
        with self.assertRaises(tool.HiveParseError):
            tool.RegistryHive(b"JUNK" * 100)

    def test_null_bytes_raises(self):
        with self.assertRaises(tool.HiveParseError):
            tool.RegistryHive(b"\x00" * 4096)


# ---------------------------------------------------------------------------
# End-to-end integration test
# ---------------------------------------------------------------------------

class TestEndToEnd(unittest.TestCase):

    def test_full_pipeline_two_users_no_amcache(self):
        with tempfile.TemporaryDirectory() as td:
            tmpdir = pathlib.Path(td)

            make_profile(tmpdir, "Alice", [
                (r"c:\windows\system32\cmd.exe",               ".exe"),
                (r"c:\users\alice\downloads\suspicious.exe",   ".exe"),
                (r"c:\windows\system32\kernel32.dll",          ".dll"),
                (r"c:\windows\readme.txt",                     ".txt"),   # filtered
            ])
            make_profile(tmpdir, "Bob", [
                (r"c:\program files\notepad++\notepad++.exe",  ".exe"),
                (r"\\fileserver\share\tools\psexec.exe",       ".exe"),
                (r"\Device\HarddiskVolume2\Windows\System32\lsass.exe", ".exe"),
            ])

            users_dir = tmpdir / "Users"
            profiles = tool.discover_profiles(users_dir)
            self.assertEqual(len(profiles), 2)

            all_entries = []
            for p in profiles:
                for db in tool.discover_iconcache_files(p):
                    all_entries.extend(
                        tool.parse_iconcache_file(db, include_non_exe=False)
                    )

            self.assertGreater(len(all_entries), 0)

            rows = tool.make_result_rows_no_amcache(all_entries)
            rows = tool.dedupe_results(rows)
            rows.sort(key=lambda r: (r.user.lower(), r.binary_path.lower()))

            bp_lower = [r.binary_path.lower() for r in rows]

            # Paths must be present and normalised
            self.assertTrue(any("cmd.exe" in p for p in bp_lower))
            self.assertTrue(any("suspicious.exe" in p for p in bp_lower))
            self.assertTrue(any("kernel32.dll" in p for p in bp_lower))
            self.assertTrue(any("notepad++.exe" in p for p in bp_lower))
            self.assertTrue(any("psexec.exe" in p for p in bp_lower))

            # txt must be filtered
            self.assertFalse(any(".txt" in p for p in bp_lower))

            # Device path must be normalised to C:
            self.assertTrue(any("c:\\" in p and "lsass.exe" in p for p in bp_lower))

            # Drive letters in the actual binary_path (not lowercased copy) must be uppercase
            for r in rows:
                p = r.binary_path
                if len(p) >= 2 and p[1] == ":":
                    self.assertTrue(p[0].isupper(),
                                    f"Drive letter not uppercased: {p}")

            # Users must be correctly inferred
            users_in_rows = {r.user for r in rows}
            self.assertIn("Alice", users_in_rows)
            self.assertIn("Bob", users_in_rows)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite  = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
