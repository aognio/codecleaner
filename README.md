<p align="center">
  <img
    src="https://raw.githubusercontent.com/aognio/codecleaner/main/assets/images/codecleaner-logo.png"
    alt="codecleaner logo"
    width="240"
  />
</p>

# codecleaner

Version: `0.1.0`

`codecleaner` is a conservative cleanup tool for development directories. It
removes reproducible dependencies, caches, build artifacts, Python bytecode,
and macOS Mach-O binaries while preserving Git metadata and configured
preserved trees. It can also sanitize a tree for a target operating system and
CPU architecture before or after migration.

## Usage

Install locally:

```bash
python3 -m pip install .
```

Print the version:

```bash
codecleaner --version
```

Preview cleanup:

```bash
codecleaner ~/code --dry-run
```

Clean:

```bash
codecleaner ~/code
```

Preserve directories:

```bash
codecleaner ~/code \
  --preserve ~/code/floss \
  --preserve ~/code/experiments
```

Remember preserved directories:

```bash
codecleaner ~/code \
  --preserve ~/code/floss \
  --remember
```

Remembered paths are stored in:

```text
~/.config/codecleaner/config.toml
```

## Inspection Modes

Concise disk usage stats:

```bash
codecleaner ~/code --stats
```

Extended cleanup category stats:

```bash
codecleaner ~/code --stats --extended
```

Explain the reclaimable-space total:

```bash
codecleaner ~/code --stats --extended --explain-reclaimable
```

Show every reclaimable item instead of the default bounded list:

```bash
codecleaner ~/code --stats --extended --explain-reclaimable --all
```

Print scanner diagnostics:

```bash
codecleaner ~/code --stats --extended --verbose
```

Clean every item classified as reclaimable by extended stats:

```bash
codecleaner ~/code --clean-reclaimable
```

Walk through reclaimable items interactively:

```bash
codecleaner ~/code --clean-reclaimable --interactive
```

Safely rehearse interactive reclaimable cleanup:

```bash
codecleaner ~/code --clean-reclaimable --interactive --dry-run
```

## Target-Platform Sanitization

Prepare a tree for a different platform before migration:

```bash
codecleaner ~/code \
  --sanitize-for linux-amd64 \
  --dry-run
```

Sanitize a copied tree for the machine running CodeCleaner:

```bash
codecleaner ~/code \
  --sanitize-for native \
  --dry-run
```

`native` resolves to the current host platform, such as `linux-amd64` or
`macos-arm64`. Use `--sanitize` as a shortcut for `--sanitize-for native`.

Supported initial targets:

```text
freebsd-amd64
freebsd-arm64
linux-amd64
linux-arm64
macos-amd64
macos-arm64
netbsd-amd64
netbsd-arm64
openbsd-amd64
openbsd-arm64
windows-amd64
windows-arm64
native
```

Explain the exact sanitization items:

```bash
codecleaner ~/code \
  --sanitize-for linux-amd64 \
  --explain-sanitization
```

Walk through sanitization candidates interactively:

```bash
codecleaner ~/code \
  --sanitize-for linux-amd64 \
  --interactive
```

Largest repository/directory census:

```bash
codecleaner ~/code --census
```

Interactive census-based cleanup:

```bash
codecleaner ~/code --clean-by-census
```

During interactive cleanup:

```text
y  delete
n  keep
s  skip subtree
q  quit
```

Use `--include-preserved` with `--clean-by-census` to allow scanning and
deleting inside preserved directories.

## Safety Notes

- Symlinks are not followed.
- `.git` directories are preserved during normal cleanup.
- Preserved paths are opaque during cleanup.
- `--stats`, `--stats --extended`, and `--census` are read-only.
- Mach-O files are detected by magic bytes, not by executable permissions.

## Tests

Run the test suite:

```bash
python3 -m unittest discover -s tests -v
```

## Packaging

Build and check local distributions:

```bash
python3 -m pip install build twine
python3 -m build
python3 -m twine check dist/*
```

Upload to PyPI when ready:

```bash
python3 -m twine upload dist/*
```

## License

MIT License - Copyright (c) 2026 Antonio Ognio

Made with ❤️ from 🇵🇪. El Perú es clave 🔑.
