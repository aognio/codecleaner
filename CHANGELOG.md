# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
<<<<<<< Updated upstream
=======

### Added

- Detection for Windows PE binaries and common BSD ELF OSABI variants.
- Sanitization targets for Windows, FreeBSD, OpenBSD, and NetBSD on amd64 and
  arm64.

## [0.2.0] - 2026-08-08
>>>>>>> Stashed changes

### Added

- Target-platform sanitization with `--sanitize-for TARGET` and `--sanitize`
  for preparing development trees for Linux/macOS amd64/arm64 targets.
- Native platform detection via `--sanitize-for native`.
- Direct Python inspection for Mach-O and ELF artifacts, including Mach-O
  universal binaries and ELF amd64/arm64 headers.
- Sanitization categories for incompatible native artifacts, regenerable
  dependency/build environments, disposable caches, compatible native files,
  preserved trees, and protected Git metadata.
- Sanitization explainability with `--explain-sanitization` and `--all`.
- Interactive and dry-run sanitization using the existing confirmation
  vocabulary and cleanup executor behavior.

## [0.1.0] - 2026-08-08

### Added

- Conservative cleanup for reproducible dependencies, caches, build artifacts,
  Python bytecode, and macOS Mach-O files.
- Preserve support via `--preserve` and remembered preserves in
  `~/.config/codecleaner/config.toml`.
- Read-only stats modes with `--stats`, `--stats --extended`, and
  `--stats --extended --explain-reclaimable`.
- Reclaimable cleanup using the same candidate collection as reclaimable
  explanation via `--clean-reclaimable`.
- Interactive cleanup flows for reclaimable items and census results.
- Census mode for finding large Git repositories and shallow non-Git
  directories.
- Verbose traversal and classification diagnostics.
- Installable Python package metadata with a `codecleaner` console script.
- MIT license, README, project metadata files, logo assets, and test suite.
