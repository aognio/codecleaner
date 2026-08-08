# Agent Notes

## Project

`codecleaner.py` is a single-file Python CLI with a small `unittest` suite.
Keep changes conservative and avoid changing cleanup behavior unless explicitly
requested.

## Development

- Use Python standard library APIs only unless a dependency is explicitly added.
- Preserve symlink safety: do not follow symlinked directories.
- Keep `.git` opaque during normal cleanup.
- Keep inspection modes read-only unless the mode is explicitly interactive
  cleanup, such as `--clean-by-census`.
- Reuse existing cleanup policy helpers when adding reporting, so cleanup and
  observability do not drift.

## Verification

Run:

```bash
python3 -m py_compile codecleaner.py tests/test_codecleaner.py
python3 -m unittest discover -s tests -v
```
