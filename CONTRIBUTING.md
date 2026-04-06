# Contributing to IconCacheReader

Contributions are welcome — bug reports, format corrections, test cases,
and documentation improvements are all valuable.

## What we need most

- **Real-world test samples** — IconCache.db files from different Windows
  versions (XP, 7, 8.1, 10, 11) donated to the
  [DFIR Artifact Museum](https://github.com/AndrewRathbun/DFIRArtifactMuseum)
  help validate the parser against real data.
- **Amcache layout variations** — the legacy `File\{VolumeGUID}` layout has
  many sub-variants. PRs with additional field mappings are welcome.
- **Bug reports** — open an issue with the `db_version` reported by the tool,
  the OS version, and (if possible) a sanitised/truncated sample of the file.

## Development setup

```bash
git clone https://github.com/<you>/IconCacheReader.git
cd IconCacheReader

# No external deps needed — pure stdlib
python IconCacheReader.py --help

# Run tests
python tests/test_IconCacheReader.py -v
```

## Coding conventions

- Python 3.8+ compatible (no walrus operator, no match/case).
- Zero external dependencies — the tool must run from a single `.py` file
  or the compiled `.exe` in air-gapped forensic environments.
- New functionality must come with tests in `tests/test_IconCacheReader.py`.
- All path-handling code must be cross-platform (Linux analyst workstation
  parsing a Windows image).

## Pull request process

1. Fork → feature branch → PR against `main`.
2. Ensure `python tests/test_IconCacheReader.py` passes locally.
3. Update `CHANGELOG.md` under `[Unreleased]`.
4. Reference any relevant research or format documentation in comments.

## Reporting issues

Please include:
- OS and Python version you ran the tool on.
- The exact command line used.
- The `db_version` field shown in output (or `bad_magic` / `fallback-scan`).
- Expected vs actual behaviour.
- A sanitised sample if possible (even just the first 256 bytes in hex).
