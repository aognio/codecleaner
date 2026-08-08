#!/usr/bin/env python3
"""
codecleaner

Clean reproducible dependencies, caches, build artifacts, and macOS Mach-O
binaries from a development tree before migrating it to another machine.

The cleaner is intentionally conservative.

Examples
--------

Preview:

    codecleaner ~/code \
        --preserve ~/code/floss \
        --preserve ~/code/experiments \
        --dry-run

Actually clean:

    codecleaner ~/code \
        --preserve ~/code/floss \
        --preserve ~/code/experiments

Remember preserved paths for future runs:

    codecleaner ~/code \
        --preserve ~/code/floss \
        --preserve ~/code/experiments \
        --remember

Preserved paths are completely opaque: they are not scanned or modified.
Remembered paths are stored in ~/.config/codecleaner/config.toml.
Git repositories retain their complete .git directories.
Use --stats to report disk usage, .git usage, and estimated non-git usage
without cleaning anything.
Use --stats --extended to analyze cleanup categories without cleaning anything.
Add --explain-reclaimable to --stats --extended to list the filesystem
objects behind reclaimable-space totals.
Use --census to list the largest Git repos and shallow non-git directories
without cleaning anything.
Use --clean-by-census to interactively delete census entries.
Use --clean-reclaimable to delete items classified as reclaimable by the
extended statistics engine.
Add --exclude-preserved to --stats or --census to skip remembered preserved
directories from the inspection scan.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11 fallback
    tomllib = None


# ---------------------------------------------------------------------------
# Cleanup policy
# ---------------------------------------------------------------------------

VERSION = "0.1.0"


# These directories are completely opaque to the cleaner.
ALWAYS_PRESERVE_DIRS = {
    ".git",
}


CONFIG_PATH = Path.home() / ".config" / "codecleaner" / "config.toml"
CENSUS_LIMIT = 50
GIT_STATS_LIMIT = 20
RECLAIMABLE_EXPLAIN_LIMIT = 50


# Reproducible dependency/cache/build directories.
#
# Keep this list conservative. In particular, generic directories such as
# "build", "dist", "bin", and "out" are NOT included because projects often
# store valuable artifacts there.
REMOVABLE_DIRS = {
    # Python
    ".venv",
    "venv",
    "__pycache__",
    ".eggs",
    "htmlcov",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    ".hypothesis",
    ".pytype",
    ".pyre",

    # JavaScript / TypeScript
    "node_modules",
    "bower_components",
    "jspm_packages",
    ".pnpm-store",
    ".next",
    ".nuxt",
    ".vite",
    ".parcel-cache",
    ".turbo",
    ".svelte-kit",

    # Go
    ".gocache",
    ".gomodcache",
    "go-build",

    # Java / JVM
    ".gradle",

    # Rust
    "target",

    # Zig
    "zig-cache",
    ".zig-cache",
    "zig-out",

    # Generic caches
    ".cache",
}


PYTHON_PROJECT_MARKERS = {
    "pyproject.toml",
    "requirements.txt",
    "setup.py",
    "setup.cfg",
    "Pipfile",
    "poetry.lock",
    "uv.lock",
}


NODE_PROJECT_MARKERS = {
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
    "bun.lockb",
}


GO_PROJECT_MARKERS = {
    "go.mod",
    "go.work",
}


JAVA_PROJECT_MARKERS = {
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
    "gradlew",
    "mvnw",
}


REMOVABLE_SUFFIXES = {
    ".pyc",
    ".pyo",
}


DEPENDENCY_DIRS = {
    ".venv",
    "venv",
    "env",
    ".env",
    ".eggs",
    ".tox",
    ".nox",
    "node_modules",
    "bower_components",
    "jspm_packages",
    "vendor",
}


BUILD_DIRS = {
    "htmlcov",
    ".next",
    ".nuxt",
    ".vite",
    ".parcel-cache",
    ".turbo",
    ".svelte-kit",
    "dist",
    "build",
    "out",
    "target",
    "zig-cache",
    ".zig-cache",
    "zig-out",
}


CACHE_DIRS = {
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".hypothesis",
    ".pytype",
    ".pyre",
    ".pnpm-store",
    ".gocache",
    ".gomodcache",
    "go-build",
    ".gradle",
    ".cache",
    "cache",
}


# Mach-O magic numbers.
#
# Includes normal Mach-O executables/libraries and universal ("fat") binaries.
MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",  # MH_MAGIC
    b"\xce\xfa\xed\xfe",  # MH_CIGAM
    b"\xfe\xed\xfa\xcf",  # MH_MAGIC_64
    b"\xcf\xfa\xed\xfe",  # MH_CIGAM_64
    b"\xca\xfe\xba\xbe",  # FAT_MAGIC
    b"\xbe\xba\xfe\xca",  # FAT_CIGAM
    b"\xca\xfe\xba\xbf",  # FAT_MAGIC_64
    b"\xbf\xba\xfe\xca",  # FAT_CIGAM_64
}


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Clean reproducible dependencies, caches, build artifacts, "
            "and macOS Mach-O binaries from a development tree."
        )
    )

    parser.add_argument(
        "root",
        type=Path,
        help="Root development directory to clean",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"codecleaner {VERSION}",
    )

    parser.add_argument(
        "--preserve",
        action="append",
        default=[],
        metavar="PATH",
        help=(
            "Subdirectory to leave completely untouched. "
            "May be specified multiple times."
        ),
    )

    parser.add_argument(
        "--remember",
        action="store_true",
        help=(
            "Remember the current --preserve paths in "
            f"{CONFIG_PATH} for future runs."
        ),
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be removed without modifying anything",
    )

    parser.add_argument(
        "--stats",
        action="store_true",
        help=(
            "Only report disk usage, .git directory usage, and estimated "
            "non-git usage. Can be combined with --extended or "
            "--exclude-preserved."
        ),
    )

    parser.add_argument(
        "--extended",
        action="store_true",
        help=(
            "With --stats, report detailed cleanup category statistics. "
            "Never deletes anything."
        ),
    )

    parser.add_argument(
        "--explain-reclaimable",
        action="store_true",
        help=(
            "With --stats --extended, append the actual filesystem objects "
            "that make up reclaimable space."
        ),
    )

    parser.add_argument(
        "--all",
        action="store_true",
        help=(
            "With --stats --extended --explain-reclaimable, show every "
            "reclaimable item instead of the largest bounded set."
        ),
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print scanner and classification diagnostics.",
    )

    parser.add_argument(
        "--census",
        action="store_true",
        help=(
            "Only list the largest Git repos and non-git directories up to "
            "5 levels deep. Can only be combined with --exclude-preserved."
        ),
    )

    parser.add_argument(
        "--clean-by-census",
        action="store_true",
        help=(
            "Interactively delete directories from the census list. Prompts "
            "for each shown entry."
        ),
    )

    parser.add_argument(
        "--clean-reclaimable",
        action="store_true",
        help=(
            "Delete all items classified as reclaimable by extended stats. "
            "Can be combined with --interactive and --dry-run."
        ),
    )

    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Prompt before each cleanup action where supported.",
    )

    parser.add_argument(
        "--exclude-preserved",
        action="store_true",
        help=(
            "With --stats or --census, exclude remembered preserved trees "
            "from the inspection scan."
        ),
    )

    parser.add_argument(
        "--include-preserved",
        action="store_true",
        help=(
            "With --clean-by-census, include remembered and explicit preserved "
            "trees in the interactive cleanup scan."
        ),
    )

    args = parser.parse_args()

    action_modes = sum([
        args.stats,
        args.census,
        args.clean_by_census,
        args.clean_reclaimable,
    ])

    if action_modes > 1:
        parser.error(
            "--stats, --census, --clean-by-census, and --clean-reclaimable "
            "cannot be combined"
        )

    if args.exclude_preserved and not (args.stats or args.census):
        parser.error("--exclude-preserved requires --stats or --census")

    if args.include_preserved and not args.clean_by_census:
        parser.error("--include-preserved requires --clean-by-census")

    if args.interactive and not args.clean_reclaimable:
        parser.error("--interactive is currently supported with --clean-reclaimable")

    if args.extended and not args.stats:
        parser.error("--extended requires --stats")

    if args.explain_reclaimable and not (args.stats and args.extended):
        parser.error("--explain-reclaimable requires --stats --extended")

    if args.all and not args.explain_reclaimable:
        parser.error("--all requires --explain-reclaimable")

    if args.stats and (args.remember or args.dry_run):
        parser.error("--stats cannot be combined with other switches")

    if args.stats and args.preserve and not args.extended:
        parser.error("--preserve with --stats requires --extended")

    if args.census and (args.preserve or args.remember or args.dry_run):
        parser.error("--census cannot be combined with other switches")

    if args.clean_by_census and (
        args.remember
        or args.dry_run
        or args.exclude_preserved
        or args.extended
        or args.explain_reclaimable
        or args.all
        or args.interactive
    ):
        parser.error("--clean-by-census cannot be combined with other switches")

    if args.clean_reclaimable and (
        args.remember
        or args.exclude_preserved
        or args.extended
        or args.explain_reclaimable
        or args.all
        or args.include_preserved
    ):
        parser.error("--clean-reclaimable cannot be combined with other switches")

    return args


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def normalize(path: Path) -> Path:
    return path.expanduser().resolve()


def is_inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def is_preserved(path: Path, preserved: list[Path]) -> bool:
    """
    Return True when path is equal to or inside an explicitly preserved tree.
    """
    return any(is_inside(path, parent) for parent in preserved)


def verbose_log(enabled: bool, message: str) -> None:
    if enabled:
        print(f"VERBOSE: {message}", file=sys.stderr)


def has_marker(path: Path, markers: set[str]) -> bool:
    return any((path / marker).exists() for marker in markers)


def is_removable_project_dir(path: Path) -> bool:
    """
    Return True for dependency/build directories whose names are too generic
    to remove everywhere, but are reproducible inside known project types.
    """
    parent = path.parent
    dirname = path.name

    if dirname == "vendor" and has_marker(parent, GO_PROJECT_MARKERS):
        return True

    if dirname == "dist" and has_marker(parent, NODE_PROJECT_MARKERS):
        return True

    if (
        dirname == "cache"
        and parent.name == ".yarn"
        and has_marker(parent.parent, NODE_PROJECT_MARKERS)
    ):
        return True

    if dirname == "build" and has_marker(parent, JAVA_PROJECT_MARKERS):
        return True

    if dirname == "out" and has_marker(parent, JAVA_PROJECT_MARKERS):
        return True

    if dirname == "target" and has_marker(parent, JAVA_PROJECT_MARKERS):
        return True

    if dirname in {"env", ".env"} and has_marker(parent, PYTHON_PROJECT_MARKERS):
        return True

    return False


def is_cleanup_removable_dir(path: Path) -> bool:
    return path.name in REMOVABLE_DIRS or is_removable_project_dir(path)


def removable_dir_category(path: Path) -> tuple[str, str] | None:
    """
    Return the extended-stats section and label for a removable directory.

    The removal decision itself is delegated to is_cleanup_removable_dir so
    stats and cleanup do not diverge on what is removable.
    """
    if not is_cleanup_removable_dir(path):
        return None

    name = path.name

    if name == "cache" and path.parent.name == ".yarn":
        return "caches", ".yarn/cache"

    if name in DEPENDENCY_DIRS:
        return "dependencies", name

    if name in BUILD_DIRS:
        return "build_artifacts", name

    if name in CACHE_DIRS:
        return "caches", name

    return "caches", name


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def parse_simple_config(text: str) -> dict[str, list[str]]:
    """
    Parse the small TOML subset written by this script.

    This fallback exists for Python versions without tomllib.
    """
    lines = []

    for line in text.splitlines():
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        lines.append(stripped)

    source = " ".join(lines)

    if not source.startswith("preserve"):
        return {}

    _, value = source.split("=", 1)
    value = value.strip()

    if not value.startswith("[") or not value.endswith("]"):
        raise ValueError("expected preserve to be a TOML array")

    items: list[str] = []
    decoder = json.JSONDecoder()
    index = 1

    while index < len(value) - 1:
        while index < len(value) - 1 and value[index] in " \t\r\n,":
            index += 1

        if index >= len(value) - 1:
            break

        item, next_index = decoder.raw_decode(value, index)

        if not isinstance(item, str):
            raise ValueError("preserve entries must be strings")

        items.append(item)
        index = next_index

    return {"preserve": items}


def load_config() -> list[Path]:
    if not CONFIG_PATH.exists():
        return []

    try:
        text = CONFIG_PATH.read_text(encoding="utf-8")

        if tomllib is not None:
            data = tomllib.loads(text)
        else:
            data = parse_simple_config(text)

    except (OSError, ValueError) as exc:
        print(
            f"WARNING: could not read config {CONFIG_PATH}: {exc}",
            file=sys.stderr,
        )
        return []

    values = data.get("preserve", [])

    if not isinstance(values, list):
        print(
            f"WARNING: ignoring config {CONFIG_PATH}: preserve is not a list",
            file=sys.stderr,
        )
        return []

    paths: list[Path] = []

    for value in values:
        if not isinstance(value, str):
            print(
                f"WARNING: ignoring non-string preserved path in {CONFIG_PATH}",
                file=sys.stderr,
            )
            continue

        paths.append(Path(value).expanduser())

    return paths


def write_config(preserved: list[Path]) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "# codecleaner remembered preserved directories",
        "preserve = [",
    ]

    for path in preserved:
        lines.append(f"  {json.dumps(str(path))},")

    lines.append("]")
    lines.append("")

    CONFIG_PATH.write_text("\n".join(lines), encoding="utf-8")


def normalize_preserve_path(
    value: Path,
    *,
    root: Path,
    source: str,
    strict: bool,
) -> Path | None:
    candidate = value.expanduser()

    if not candidate.is_absolute():
        candidate = root / candidate

    candidate = candidate.resolve()

    def reject(message: str) -> None:
        if not strict and message == "is outside root":
            return

        prefix = "ERROR" if strict else "WARNING"
        print(
            f"{prefix}: {source} preserved path {message}: {candidate}",
            file=sys.stderr,
        )

    if candidate == root:
        reject("is the root itself")
        return None

    if not is_inside(candidate, root):
        reject("is outside root")
        return None

    if not candidate.exists():
        reject("does not exist")
        return None

    if not candidate.is_dir():
        reject("is not a directory")
        return None

    return candidate


def remembered_preserved_for_root(root: Path) -> list[Path]:
    preserved: list[Path] = []

    for value in load_config():
        candidate = normalize_preserve_path(
            value,
            root=root,
            source="remembered",
            strict=False,
        )

        if candidate is not None:
            preserved.append(candidate)

    return sorted(set(preserved))


def load_cleanup_preserved_paths(
    root: Path,
    explicit_values: list[str],
) -> tuple[list[Path], list[Path] | None]:
    remembered_values = load_config()
    preserved: list[Path] = []

    for value in remembered_values:
        candidate = normalize_preserve_path(
            value,
            root=root,
            source="remembered",
            strict=False,
        )

        if candidate is not None:
            preserved.append(candidate)

    for value in explicit_values:
        candidate = normalize_preserve_path(
            Path(value),
            root=root,
            source="explicit",
            strict=True,
        )

        if candidate is None:
            return [], None

        preserved.append(candidate)

    return remembered_values, sorted(set(preserved))


def load_explicit_preserved_paths(
    root: Path,
    explicit_values: list[str],
) -> list[Path] | None:
    preserved: list[Path] = []

    for value in explicit_values:
        candidate = normalize_preserve_path(
            Path(value),
            root=root,
            source="explicit",
            strict=True,
        )

        if candidate is None:
            return None

        preserved.append(candidate)

    return sorted(set(preserved))


# ---------------------------------------------------------------------------
# File identification
# ---------------------------------------------------------------------------

def is_macho_file(path: Path) -> bool:
    """
    Identify a Mach-O or universal/fat Mach-O file by its magic bytes.

    This deliberately does NOT use the Unix executable bit.

    Consequently:

        deploy.sh
        script.py
        tool.js
        Makefile helpers

    remain untouched even when chmod +x.
    """
    if path.is_symlink():
        return False

    try:
        if not path.is_file():
            return False

        with path.open("rb") as handle:
            magic = handle.read(4)

    except (OSError, PermissionError):
        return False

    return magic in MACHO_MAGICS


# ---------------------------------------------------------------------------
# Size helpers
# ---------------------------------------------------------------------------

def format_size(size: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]

    value = float(size)

    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f} {unit}"

        value /= 1024

    return f"{size} B"


def file_size(path: Path) -> int:
    try:
        if path.is_symlink():
            return 0

        return path.stat().st_size

    except OSError:
        return 0


def directory_size(path: Path) -> int:
    """
    Calculate the size of regular files below a directory.

    Symlinks are not followed.
    """
    total = 0

    def onerror(error: OSError) -> None:
        print(
            f"WARNING: cannot inspect {error.filename}: {error}",
            file=sys.stderr,
        )

    for current, dirs, files in os.walk(
        path,
        topdown=True,
        followlinks=False,
        onerror=onerror,
    ):
        current_path = Path(current)

        # Never follow directory symlinks while calculating sizes.
        dirs[:] = [
            dirname
            for dirname in dirs
            if not (current_path / dirname).is_symlink()
        ]

        for filename in files:
            candidate = current_path / filename

            if candidate.is_symlink():
                continue

            try:
                total += candidate.stat().st_size
            except OSError:
                pass

    return total


def disk_usage(path: Path) -> int:
    """
    Return filesystem disk usage for one directory entry.

    st_blocks is reported in 512-byte units on POSIX. Fall back to st_size on
    filesystems that do not provide block counts.
    """
    try:
        stat = path.lstat()
    except OSError:
        return 0

    blocks = getattr(stat, "st_blocks", None)

    if blocks is None:
        return stat.st_size

    return blocks * 512


def tree_disk_usage(path: Path, preserved: list[Path] | None = None) -> int:
    """
    Calculate disk usage below a path without following symlinks.
    """
    preserved = preserved or []

    if is_preserved(path, preserved):
        return 0

    if not path.is_dir() or path.is_symlink():
        return disk_usage(path)

    total = 0

    def onerror(error: OSError) -> None:
        print(
            f"WARNING: cannot inspect {error.filename}: {error}",
            file=sys.stderr,
        )

    for current, dirs, files in os.walk(
        path,
        topdown=True,
        followlinks=False,
        onerror=onerror,
    ):
        current_path = Path(current)
        total += disk_usage(current_path)

        surviving_dirs: list[str] = []

        for dirname in dirs:
            candidate = current_path / dirname

            if candidate.is_symlink():
                total += disk_usage(candidate)
                continue

            if is_preserved(candidate, preserved):
                continue

            surviving_dirs.append(dirname)

        dirs[:] = surviving_dirs

        for filename in files:
            total += disk_usage(current_path / filename)

    return total


def collect_stats(
    root: Path,
    preserved: list[Path],
    verbose: bool = False,
) -> tuple[int, int, int]:
    """
    Return scanned disk usage, .git disk usage, and skipped preserved count.
    """
    scanned_size = 0
    git_size = 0
    skipped_preserved = 0

    def onerror(error: OSError) -> None:
        print(
            f"WARNING: cannot inspect {error.filename}: {error}",
            file=sys.stderr,
        )

    for current, dirs, files in os.walk(
        root,
        topdown=True,
        followlinks=False,
        onerror=onerror,
    ):
        current_path = Path(current)
        verbose_log(verbose, f"scanning directory {current_path}")
        scanned_size += disk_usage(current_path)

        surviving_dirs: list[str] = []

        for dirname in dirs:
            path = current_path / dirname

            if path.is_symlink():
                verbose_log(verbose, f"encountered symlink {path}")
                scanned_size += disk_usage(path)
                continue

            if is_preserved(path, preserved):
                verbose_log(verbose, f"skipping preserved tree {path}")
                skipped_preserved += 1
                continue

            if dirname in ALWAYS_PRESERVE_DIRS:
                verbose_log(verbose, f"skipping .git directory {path}")
                size = tree_disk_usage(path)
                scanned_size += size
                git_size += size
                continue

            surviving_dirs.append(dirname)

        dirs[:] = surviving_dirs

        for filename in files:
            scanned_size += disk_usage(current_path / filename)

    return scanned_size, git_size, skipped_preserved


@dataclass
class SizeCount:
    size: int = 0
    count: int = 0

    def add(self, size: int) -> None:
        self.size += size
        self.count += 1


@dataclass
class ReclaimableItem:
    section: str
    label: str
    path: Path
    size: int
    kind: str
    rule: str


@dataclass
class CleanupSummary:
    candidates: int = 0
    removed: int = 0
    declined: int = 0
    skipped: int = 0
    errors: int = 0
    reclaimed_size: int = 0
    selected_size: int = 0
    stopped_early: bool = False
    processed: int = 0

    @property
    def remaining_unseen(self) -> int:
        return max(self.candidates - self.processed, 0)


@dataclass
class ExtendedStats:
    scanned_size: int = 0
    git_size: int = 0
    explicit_preserved_size: int = 0
    reclaimable_size: int = 0
    other_retained_size: int = 0
    macho_size: int = 0
    macho_count: int = 0
    skipped_preserved: int = 0
    dependencies: dict[str, SizeCount] = field(default_factory=dict)
    build_artifacts: dict[str, SizeCount] = field(default_factory=dict)
    caches: dict[str, SizeCount] = field(default_factory=dict)
    git_dirs: list[tuple[int, Path]] = field(default_factory=list)
    explicit_preserved_dirs: list[tuple[int, Path]] = field(default_factory=list)
    reclaimable_items: list[ReclaimableItem] = field(default_factory=list)


def compact_preserved(paths: list[Path]) -> list[Path]:
    compacted: list[Path] = []

    for path in sorted(set(paths)):
        if any(is_inside(path, parent) for parent in compacted):
            continue

        compacted.append(path)

    return compacted


def add_category(
    categories: dict[str, SizeCount],
    label: str,
    size: int,
) -> None:
    if label not in categories:
        categories[label] = SizeCount()

    categories[label].add(size)


def add_removable_category(
    stats: ExtendedStats,
    section: str,
    label: str,
    size: int,
    path: Path,
    kind: str,
    rule: str,
) -> None:
    if section == "dependencies":
        add_category(stats.dependencies, label, size)
    elif section == "build_artifacts":
        add_category(stats.build_artifacts, label, size)
    elif section == "caches":
        add_category(stats.caches, label, size)
    else:
        add_category(stats.caches, label, size)

    stats.reclaimable_size += size
    stats.reclaimable_items.append(
        ReclaimableItem(
            section=section,
            label=label,
            path=path,
            size=size,
            kind=kind,
            rule=rule,
        )
    )


def relative_display_path(path: Path, root: Path) -> Path:
    try:
        return path.relative_to(root)
    except ValueError:
        return path


def collect_extended_stats(
    root: Path,
    explicit_preserved: list[Path],
    excluded_preserved: list[Path],
    verbose: bool = False,
) -> ExtendedStats:
    """
    Collect cleanup-aligned disk usage categories without deleting anything.
    """
    stats = ExtendedStats(
        dependencies=defaultdict(SizeCount),
        build_artifacts=defaultdict(SizeCount),
        caches=defaultdict(SizeCount),
    )
    explicit_preserved = compact_preserved(explicit_preserved)
    excluded_preserved = compact_preserved([
        path
        for path in excluded_preserved
        if not is_preserved(path, explicit_preserved)
    ])

    def onerror(error: OSError) -> None:
        print(
            f"WARNING: cannot inspect {error.filename}: {error}",
            file=sys.stderr,
        )

    for current, dirs, files in os.walk(
        root,
        topdown=True,
        followlinks=False,
        onerror=onerror,
    ):
        current_path = Path(current)
        verbose_log(verbose, f"scanning directory {current_path}")
        current_size = disk_usage(current_path)
        stats.scanned_size += current_size
        stats.other_retained_size += current_size

        surviving_dirs: list[str] = []

        for dirname in dirs:
            path = current_path / dirname

            if path.is_symlink():
                verbose_log(verbose, f"encountered symlink {path}")
                size = disk_usage(path)
                stats.scanned_size += size
                stats.other_retained_size += size
                continue

            if is_preserved(path, explicit_preserved):
                verbose_log(verbose, f"skipping explicitly preserved tree {path}")
                size = tree_disk_usage(path)
                stats.scanned_size += size
                stats.explicit_preserved_size += size
                stats.explicit_preserved_dirs.append((size, path))
                continue

            if is_preserved(path, excluded_preserved):
                verbose_log(verbose, f"skipping remembered preserved tree {path}")
                stats.skipped_preserved += 1
                continue

            if dirname in ALWAYS_PRESERVE_DIRS:
                verbose_log(verbose, f"skipping .git directory {path}")
                size = tree_disk_usage(path)
                stats.scanned_size += size
                stats.git_size += size
                stats.git_dirs.append((size, path))
                continue

            category = removable_dir_category(path)

            if category is not None:
                section, label = category
                size = tree_disk_usage(path)
                stats.scanned_size += size
                verbose_log(
                    verbose,
                    f"recognized removable directory {path} as {section}/{label}",
                )
                add_removable_category(
                    stats,
                    section,
                    label,
                    size,
                    path,
                    "directory",
                    f'removable directory "{path.name}"',
                )
                continue

            surviving_dirs.append(dirname)

        dirs[:] = surviving_dirs

        for filename in files:
            path = current_path / filename
            size = disk_usage(path)
            stats.scanned_size += size

            if path.is_symlink():
                stats.other_retained_size += size
                continue

            if path.suffix.lower() in REMOVABLE_SUFFIXES:
                verbose_log(verbose, f"recognized removable file {path} as cache")
                add_removable_category(
                    stats,
                    "caches",
                    "Python bytecode files",
                    size,
                    path,
                    "file",
                    f'removable suffix "{path.suffix.lower()}"',
                )
                continue

            if is_macho_file(path):
                verbose_log(verbose, f"recognized Mach-O file {path}")
                stats.macho_size += size
                stats.macho_count += 1
                stats.reclaimable_size += size
                stats.reclaimable_items.append(
                    ReclaimableItem(
                        section="native_macos",
                        label="Mach-O files",
                        path=path,
                        size=size,
                        kind="file",
                        rule="Mach-O magic bytes",
                    )
                )
                continue

            stats.other_retained_size += size

    stats.git_dirs.sort(key=lambda item: (item[0], str(item[1])), reverse=True)
    stats.explicit_preserved_dirs.sort(
        key=lambda item: (item[0], str(item[1])),
        reverse=True,
    )

    return stats


def print_size_count_section(
    title: str,
    values: dict[str, SizeCount],
    noun: str,
) -> None:
    if not values:
        return

    print()
    print(title)

    for label, value in sorted(
        values.items(),
        key=lambda item: (item[1].size, item[0]),
        reverse=True,
    ):
        print(
            f"  {label:<24} "
            f"{format_size(value.size):>10} "
            f"{value.count:6} {noun}"
        )


def print_extended_stats(root: Path, stats: ExtendedStats) -> None:
    print()
    print("=" * 78)
    print("CODE CLEANER EXTENDED STATS")
    print("=" * 78)
    print()
    print(f"Root:               {root}")

    print_size_count_section("DEPENDENCIES", stats.dependencies, "dirs")
    print_size_count_section("BUILD ARTIFACTS", stats.build_artifacts, "dirs")
    print_size_count_section("CACHES", stats.caches, "items")

    if stats.macho_count:
        print()
        print("NATIVE MACOS")
        print(
            f"  {'Mach-O files':<24} "
            f"{format_size(stats.macho_size):>10} "
            f"{stats.macho_count:6} files"
        )

    if stats.git_dirs:
        print()
        print("LARGEST GIT DIRECTORIES")

        for size, path in stats.git_dirs[:GIT_STATS_LIMIT]:
            display_path = relative_display_path(path, root)
            print(f"  {format_size(size):>10}   {display_path}")

    if stats.explicit_preserved_dirs:
        print()
        print("EXPLICITLY PRESERVED TREES")

        for size, path in stats.explicit_preserved_dirs:
            display_path = relative_display_path(path, root)
            print(f"  {format_size(size):>10}   {display_path}")

    if stats.skipped_preserved:
        print()
        print(f"Remembered preserved trees skipped: {stats.skipped_preserved}")

    estimated_after_clean = max(stats.scanned_size - stats.reclaimable_size, 0)
    savings_percent = (
        (stats.reclaimable_size / stats.scanned_size) * 100
        if stats.scanned_size
        else 0.0
    )

    print()
    print("=" * 78)
    print("EXTENDED SUMMARY")
    print("=" * 78)
    print()
    print(f"Scanned total:          {format_size(stats.scanned_size):>10}")
    print(f"Git:                    {format_size(stats.git_size):>10}")
    print(
        "Explicitly preserved:  "
        f"{format_size(stats.explicit_preserved_size):>10}"
    )
    print(f"Reclaimable:            {format_size(stats.reclaimable_size):>10}")
    print(f"Other retained:         {format_size(stats.other_retained_size):>10}")
    print()
    print(f"Estimated after clean:  {format_size(estimated_after_clean):>10}")
    print(
        "Potential savings:      "
        f"{format_size(stats.reclaimable_size):>10} "
        f"({savings_percent:.1f}%)"
    )
    print()


RECLAIMABLE_SECTION_TITLES = {
    "dependencies": "DEPENDENCIES",
    "build_artifacts": "BUILD ARTIFACTS",
    "caches": "CACHES",
    "native_macos": "NATIVE MACOS",
}


RECLAIMABLE_SECTION_ORDER = [
    "dependencies",
    "build_artifacts",
    "caches",
    "native_macos",
]


def print_reclaimable_items(
    root: Path,
    items: list[ReclaimableItem],
    *,
    show_all: bool,
) -> None:
    items = materialize_reclaimable_items(items)
    displayed = items if show_all else items[:RECLAIMABLE_EXPLAIN_LIMIT]

    print()
    print("RECLAIMABLE ITEMS")
    print()

    if not items:
        print("  (none)")
        return

    if not show_all and len(items) > len(displayed):
        print(
            f"Showing {len(displayed)} of {len(items)} reclaimable items."
        )
        print("Use --all to display every item.")
        print()

    sections = RECLAIMABLE_SECTION_ORDER + sorted(
        {
            item.section
            for item in displayed
            if item.section not in RECLAIMABLE_SECTION_ORDER
        }
    )

    for section in sections:
        section_items = [
            item
            for item in displayed
            if item.section == section
        ]

        if not section_items:
            continue

        print(RECLAIMABLE_SECTION_TITLES.get(section, section.upper()))

        for item in sorted(
            section_items,
            key=lambda value: (value.size, str(value.path)),
            reverse=True,
        ):
            display_path = relative_display_path(item.path, root)
            print(f"  {format_size(item.size):>10}   {display_path}")

        print()


def path_depth(path: Path, root: Path) -> int:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return 0

    if relative == Path("."):
        return 0

    return len(relative.parts)


def collect_census(
    root: Path,
    preserved: list[Path],
    max_depth: int = 5,
    verbose: bool = False,
) -> tuple[list[tuple[int, str, Path]], int]:
    """
    Return census entries and skipped preserved count.
    """
    entries: list[tuple[int, str, Path]] = []
    skipped_preserved = 0

    def onerror(error: OSError) -> None:
        print(
            f"WARNING: cannot inspect {error.filename}: {error}",
            file=sys.stderr,
        )

    for current, dirs, _files in os.walk(
        root,
        topdown=True,
        followlinks=False,
        onerror=onerror,
    ):
        current_path = Path(current)
        verbose_log(verbose, f"scanning directory {current_path}")
        current_depth = path_depth(current_path, root)

        surviving_dirs: list[str] = []

        for dirname in dirs:
            path = current_path / dirname

            if path.is_symlink():
                verbose_log(verbose, f"encountered symlink {path}")
                continue

            if is_preserved(path, preserved):
                verbose_log(verbose, f"skipping preserved tree {path}")
                skipped_preserved += 1
                continue

            surviving_dirs.append(dirname)

        dirs[:] = surviving_dirs

        if ".git" in dirs:
            verbose_log(verbose, f"recognized git repository {current_path}")
            entries.append((
                tree_disk_usage(current_path, preserved),
                "git",
                current_path,
            ))
            dirs[:] = []
            continue

        if current_path != root and current_depth <= max_depth:
            entries.append((
                tree_disk_usage(current_path, preserved),
                "dir",
                current_path,
            ))

    return (
        sorted(
            entries,
            key=lambda item: (-item[0], path_depth(item[2], root), str(item[2])),
        ),
        skipped_preserved,
    )


def print_census_report(
    root: Path,
    entries: list[tuple[int, str, Path]],
    *,
    skipped_preserved: int = 0,
    show_preserved_skipped: bool = False,
) -> None:
    print()
    print("=" * 78)
    print("CODE CLEANER CENSUS")
    print("=" * 78)
    print()
    print(f"Root:               {root}")
    print(f"Candidates:         {len(entries)}")
    print(f"Shown:              {min(len(entries), CENSUS_LIMIT)}")

    if show_preserved_skipped:
        print(f"Preserved skipped:  {skipped_preserved}")

    print()
    print(f"{'SIZE':>10}  {'KIND':4}  PATH")

    for size, kind, path in entries[:CENSUS_LIMIT]:
        print(f"{format_size(size):>10}  {kind:4}  {path}")

    print()


# ---------------------------------------------------------------------------
# Removal operations
# ---------------------------------------------------------------------------

def report_action(
    *,
    dry_run: bool,
    kind: str,
    size: int,
    path: Path,
) -> None:
    action = "WOULD REMOVE" if dry_run else "REMOVE"

    print(
        f"{action:12} "
        f"{kind:5} "
        f"{format_size(size):>10}  "
        f"{path}"
    )


def remove_file(path: Path, dry_run: bool) -> tuple[int, bool]:
    size = file_size(path)

    report_action(
        dry_run=dry_run,
        kind="FILE",
        size=size,
        path=path,
    )

    if dry_run:
        return size, True

    try:
        path.unlink()
        return size, True

    except OSError as exc:
        print(
            f"ERROR: could not remove {path}: {exc}",
            file=sys.stderr,
        )
        return 0, False


def remove_directory(path: Path, dry_run: bool) -> tuple[int, bool]:
    """
    Remove an entire disposable directory.

    It is deliberately reported as ONE operation rather than printing every
    node_modules/target/.venv file individually.
    """
    size = directory_size(path)

    report_action(
        dry_run=dry_run,
        kind="DIR",
        size=size,
        path=path,
    )

    if dry_run:
        return size, True

    try:
        shutil.rmtree(path)
        return size, True

    except OSError as exc:
        print(
            f"ERROR: could not remove {path}: {exc}",
            file=sys.stderr,
        )
        return 0, False


def remove_census_directory(path: Path, size: int) -> bool:
    report_action(
        dry_run=False,
        kind="DIR",
        size=size,
        path=path,
    )

    try:
        shutil.rmtree(path)
        return True
    except OSError as exc:
        print(
            f"ERROR: could not remove {path}: {exc}",
            file=sys.stderr,
        )
        return False


def sorted_reclaimable_items(items: list[ReclaimableItem]) -> list[ReclaimableItem]:
    return materialize_reclaimable_items(items)


def collect_reclaimable_items(stats: ExtendedStats) -> list[ReclaimableItem]:
    return list(stats.reclaimable_items)


def materialize_reclaimable_items(
    items: list[ReclaimableItem],
    *,
    verbose: bool = False,
) -> list[ReclaimableItem]:
    materialized = list(items)
    verbose_log(verbose, "candidates materialized")
    sorted_items = sorted(
        materialized,
        key=lambda item: (item.size, str(item.path)),
        reverse=True,
    )
    verbose_log(verbose, "candidates sorted by size descending")
    return sorted_items


def reclaimable_type(item: ReclaimableItem) -> str:
    if item.section == "dependencies":
        return "dependency"
    if item.section == "build_artifacts":
        return "build artifact"
    if item.section == "caches":
        return "cache"
    if item.section == "native_macos":
        return "native macOS"
    return item.section.replace("_", " ")


def remove_reclaimable_item(item: ReclaimableItem, dry_run: bool) -> tuple[int, bool]:
    kind = "DIR" if item.kind == "directory" else "FILE"

    report_action(
        dry_run=dry_run,
        kind=kind,
        size=item.size,
        path=item.path,
    )

    if dry_run:
        return item.size, True

    try:
        if item.kind == "directory":
            shutil.rmtree(item.path)
        else:
            item.path.unlink()

        return item.size, True

    except OSError as exc:
        print(
            f"ERROR: could not remove {item.path}: {exc}",
            file=sys.stderr,
        )
        return 0, False


def prompt_reclaimable_decision(
    *,
    item: ReclaimableItem,
    root: Path,
    index: int,
    total: int,
) -> str:
    display_path = relative_display_path(item.path, root)

    while True:
        print(f"[{index}/{total}] RECLAIMABLE")
        print()
        print(f"Path:      {display_path}")
        print(f"Type:      {reclaimable_type(item)}")
        print(f"Rule:      {item.rule}")
        print(f"Size:      {format_size(item.size)}")
        print()

        try:
            answer = input("Remove? [y]es / [n]o / [s]kip / [q]uit: ")
        except EOFError:
            return "quit"

        answer = answer.strip().lower()

        if answer in {"y", "yes"}:
            return "yes"

        if answer in {"n", "no"}:
            return "no"

        if answer in {"s", "skip"}:
            return "skip"

        if answer in {"q", "quit"}:
            return "quit"

        print("Please answer yes, no, skip, or quit.")
        print()


def execute_reclaimable_cleanup(
    *,
    root: Path,
    items: list[ReclaimableItem],
    interactive: bool,
    dry_run: bool,
    verbose: bool = False,
) -> CleanupSummary:
    ordered_items = materialize_reclaimable_items(items, verbose=verbose)
    summary = CleanupSummary(candidates=len(ordered_items))
    candidate_bytes = sum(item.size for item in ordered_items)

    verbose_log(verbose, f"reclaimable candidates: {len(ordered_items)}")
    verbose_log(verbose, f"reclaimable bytes: {format_size(candidate_bytes)}")

    if interactive:
        print(
            f"Found {len(ordered_items):,} reclaimable items totaling "
            f"{format_size(candidate_bytes)}."
        )
        print()
        verbose_log(verbose, "starting interactive executor")

    try:
        for index, item in enumerate(ordered_items, start=1):
            verbose_log(
                verbose,
                f"candidate {index}/{len(ordered_items)}: {item.path}",
            )

            if not item.path.exists() and not item.path.is_symlink():
                summary.errors += 1
                summary.processed += 1
                print(
                    f"ERROR: reclaimable item no longer exists: {item.path}",
                    file=sys.stderr,
                )
                continue

            if interactive:
                decision = prompt_reclaimable_decision(
                    item=item,
                    root=root,
                    index=index,
                    total=len(ordered_items),
                )

                if decision == "quit":
                    verbose_log(verbose, "decision: quit")
                    summary.stopped_early = True
                    break

                if decision == "no":
                    verbose_log(verbose, "decision: no")
                    summary.declined += 1
                    summary.processed += 1
                    verbose_log(
                        verbose,
                        f"advancing to candidate {index + 1}/{len(ordered_items)}",
                    )
                    continue

                if decision == "skip":
                    verbose_log(verbose, "decision: skip")
                    summary.skipped += 1
                    summary.processed += 1
                    verbose_log(
                        verbose,
                        f"advancing to candidate {index + 1}/{len(ordered_items)}",
                    )
                    continue

                verbose_log(verbose, "decision: yes")

            size, success = remove_reclaimable_item(item, dry_run)

            if success:
                verbose_log(verbose, "deletion succeeded")
                summary.removed += 1
                summary.selected_size += item.size

                if not dry_run:
                    summary.reclaimed_size += size
            else:
                verbose_log(verbose, "deletion failed")
                summary.errors += 1

            summary.processed += 1
            verbose_log(
                verbose,
                f"advancing to candidate {index + 1}/{len(ordered_items)}",
            )

    except KeyboardInterrupt:
        print()
        print("Interrupted; stopping cleanup.")
        summary.stopped_early = True

    return summary


def print_reclaimable_cleanup_summary(
    summary: CleanupSummary,
    *,
    interactive: bool,
    dry_run: bool,
) -> None:
    print()
    print("=" * 78)
    print("RECLAIMABLE CLEANUP SUMMARY")
    print("=" * 78)
    print()

    if interactive:
        print(f"Candidates:          {summary.candidates}")

        if dry_run:
            print(f"Selected:            {summary.removed}")
        else:
            print(f"Removed:             {summary.removed}")

        print(f"Declined:            {summary.declined}")
        print(f"Skipped:             {summary.skipped}")
        print(f"Remaining/unseen:    {summary.remaining_unseen}")

        if dry_run:
            print(f"Selected savings:    {format_size(summary.selected_size)}")
            print(f"Reclaimed space:     {format_size(0)}")
        else:
            print(f"Reclaimed space:     {format_size(summary.reclaimed_size)}")

        print(f"Errors:              {summary.errors}")
        print(f"Stopped early:       {'yes' if summary.stopped_early else 'no'}")
    else:
        if dry_run:
            print(f"Items selected:      {summary.removed}")
        else:
            print(f"Items removed:       {summary.removed}")

        print(f"Items skipped:       {summary.skipped + summary.declined}")

        if dry_run:
            print(f"Potential savings:   {format_size(summary.selected_size)}")
            print(f"Reclaimed space:     {format_size(0)}")
        else:
            print(f"Reclaimed space:     {format_size(summary.reclaimed_size)}")

        print(f"Errors:              {summary.errors}")

    if dry_run:
        print()
        print("DRY RUN: nothing was modified.")

    print()


def prompt_census_cleanup(entries: list[tuple[int, str, Path]]) -> tuple[int, int, int]:
    removed_items = 0
    reclaimed_size = 0
    errors = 0
    skipped_roots: list[Path] = []
    removed_roots: list[Path] = []

    print("Interactive cleanup: [y] delete, [n] keep, [s] skip subtree, [q] quit.")
    print()

    for size, kind, path in entries[:CENSUS_LIMIT]:
        if any(is_inside(path, parent) for parent in skipped_roots):
            continue

        if any(is_inside(path, parent) for parent in removed_roots):
            continue

        if not path.exists():
            continue

        while True:
            try:
                answer = input(
                    f"{format_size(size):>10}  {kind:4}  {path}  [y/n/s/q] "
                ).strip().lower()
            except EOFError:
                return removed_items, reclaimed_size, errors

            if answer in {"y", "yes"}:
                if remove_census_directory(path, size):
                    removed_items += 1
                    reclaimed_size += size
                    removed_roots.append(path)
                else:
                    errors += 1
                break

            if answer in {"n", "no", ""}:
                break

            if answer in {"s", "skip"}:
                skipped_roots.append(path)
                break

            if answer in {"q", "quit"}:
                return removed_items, reclaimed_size, errors

            print("Please answer y, n, s, or q.")

    return removed_items, reclaimed_size, errors


# ---------------------------------------------------------------------------
# Main cleaner
# ---------------------------------------------------------------------------

def main() -> int:
    args = parse_args()

    root = normalize(args.root)

    if not root.exists():
        print(
            f"ERROR: root does not exist: {root}",
            file=sys.stderr,
        )
        return 2

    if not root.is_dir():
        print(
            f"ERROR: root is not a directory: {root}",
            file=sys.stderr,
        )
        return 2

    if args.stats:
        if args.extended:
            explicit_preserved = load_explicit_preserved_paths(
                root,
                args.preserve,
            )

            if explicit_preserved is None:
                return 2

            excluded_preserved = (
                remembered_preserved_for_root(root)
                if args.exclude_preserved
                else []
            )
            extended_stats = collect_extended_stats(
                root,
                explicit_preserved,
                excluded_preserved,
                verbose=args.verbose,
            )
            print_extended_stats(root, extended_stats)

            if args.explain_reclaimable:
                reclaimable_items = collect_reclaimable_items(extended_stats)
                print_reclaimable_items(
                    root,
                    reclaimable_items,
                    show_all=args.all,
                )

            return 0

        preserved = remembered_preserved_for_root(root) if args.exclude_preserved else []
        scanned_size, git_size, skipped_preserved = collect_stats(
            root,
            preserved,
            verbose=args.verbose,
        )
        non_git_size = max(scanned_size - git_size, 0)

        print()
        print("=" * 78)
        print("CODE CLEANER STATS")
        print("=" * 78)
        print()
        print(f"Root:               {root}")
        print(f"Scanned total:      {format_size(scanned_size)}")
        print(f".git directories:   {format_size(git_size)}")
        print(f"Estimated non-git:  {format_size(non_git_size)}")

        if args.exclude_preserved:
            print(f"Preserved skipped:  {skipped_preserved}")

        print()

        return 0

    if args.clean_reclaimable:
        preserved = load_explicit_preserved_paths(
            root,
            args.preserve,
        )

        if preserved is None:
            return 2

        extended_stats = collect_extended_stats(
            root,
            preserved,
            [],
            verbose=args.verbose,
        )
        verbose_log(args.verbose, "census complete")
        reclaimable_items = collect_reclaimable_items(extended_stats)
        summary = execute_reclaimable_cleanup(
            root=root,
            items=reclaimable_items,
            interactive=args.interactive,
            dry_run=args.dry_run,
            verbose=args.verbose,
        )
        print_reclaimable_cleanup_summary(
            summary,
            interactive=args.interactive,
            dry_run=args.dry_run,
        )

        return 1 if summary.errors else 0

    if args.census:
        preserved = remembered_preserved_for_root(root) if args.exclude_preserved else []
        entries, skipped_preserved = collect_census(
            root,
            preserved,
            verbose=args.verbose,
        )
        print_census_report(
            root,
            entries,
            skipped_preserved=skipped_preserved,
            show_preserved_skipped=args.exclude_preserved,
        )

        return 0

    if args.clean_by_census:
        preserved: list[Path] = []

        if not args.include_preserved:
            preserved.extend(remembered_preserved_for_root(root))

            for value in args.preserve:
                candidate = normalize_preserve_path(
                    Path(value),
                    root=root,
                    source="explicit",
                    strict=True,
                )

                if candidate is None:
                    return 2

                preserved.append(candidate)

            preserved = sorted(set(preserved))

        entries, skipped_preserved = collect_census(
            root,
            preserved,
            verbose=args.verbose,
        )
        print_census_report(
            root,
            entries,
            skipped_preserved=skipped_preserved,
            show_preserved_skipped=not args.include_preserved,
        )

        removed_items, reclaimed_size, errors = prompt_census_cleanup(entries)

        print()
        print("=" * 78)
        print("CENSUS CLEANUP SUMMARY")
        print("=" * 78)
        print(f"Items removed:      {removed_items}")
        print(f"Reclaimed space:    {format_size(reclaimed_size)}")
        print(f"Errors:             {errors}")
        print()

        return 1 if errors else 0

    # -----------------------------------------------------------------------
    # Normalize preserved paths
    # -----------------------------------------------------------------------

    remembered_values, preserved = load_cleanup_preserved_paths(
        root,
        args.preserve,
    )

    if preserved is None:
        return 2

    if args.remember:
        remembered_for_config = {
            path.expanduser().resolve()
            for path in remembered_values
            if path.expanduser().exists()
        }
        remembered_for_config.update(preserved)

        try:
            write_config(sorted(remembered_for_config))
        except OSError as exc:
            print(
                f"ERROR: could not write config {CONFIG_PATH}: {exc}",
                file=sys.stderr,
            )
            return 2

    # -----------------------------------------------------------------------
    # Header
    # -----------------------------------------------------------------------

    print()
    print("=" * 78)
    print("CODE CLEANER")
    print("=" * 78)
    print()

    print(f"Root:       {root}")
    print(f"Mode:       {'DRY RUN' if args.dry_run else 'DELETE'}")

    print()
    print(f"Config:     {CONFIG_PATH}")

    print()
    print("Preserved trees:")

    if preserved:
        for path in preserved:
            print(f"  {path}")
    else:
        print("  (none)")

    print()
    print("Automatically preserved directory names:")

    for name in sorted(ALWAYS_PRESERVE_DIRS):
        print(f"  {name}/")

    print()
    print("-" * 78)

    # -----------------------------------------------------------------------
    # Walk
    # -----------------------------------------------------------------------

    total_reclaimable = 0
    removed_items = 0
    errors = 0

    for current, dirs, files in os.walk(
        root,
        topdown=True,
        followlinks=False,
    ):
        current_path = Path(current)
        verbose_log(args.verbose, f"scanning directory {current_path}")

        surviving_dirs: list[str] = []

        # -------------------------------------------------------------------
        # Directory pruning
        # -------------------------------------------------------------------

        for dirname in dirs:
            path = current_path / dirname

            # Never follow symlinked directories.
            if path.is_symlink():
                verbose_log(args.verbose, f"encountered symlink {path}")
                surviving_dirs.append(dirname)
                continue

            # Explicitly preserved subtree.
            if is_preserved(path, preserved):
                verbose_log(args.verbose, f"skipping preserved tree {path}")
                print(f"PRESERVE                {path}")
                continue

            # Git metadata is completely opaque.
            if dirname in ALWAYS_PRESERVE_DIRS:
                verbose_log(args.verbose, f"skipping .git directory {path}")
                surviving_dirs.append(dirname)

                # Important:
                # Do NOT let os.walk descend into it.
                #
                # We temporarily append it here only for conceptual clarity;
                # it is filtered below.
                continue

            # Disposable dependency/cache/build tree.
            if is_cleanup_removable_dir(path):
                category = removable_dir_category(path)
                if category is not None:
                    section, label = category
                    verbose_log(
                        args.verbose,
                        f"recognized removable directory {path} as "
                        f"{section}/{label}",
                    )
                size, success = remove_directory(
                    path,
                    args.dry_run,
                )

                if success:
                    total_reclaimable += size
                    removed_items += 1
                else:
                    errors += 1

                # Do not descend into something we're deleting.
                continue

            surviving_dirs.append(dirname)

        # Remove automatically preserved directory names from the walk.
        #
        # This means .git is not merely protected from deletion:
        # its contents are never inspected at all.
        dirs[:] = [
            dirname
            for dirname in surviving_dirs
            if dirname not in ALWAYS_PRESERVE_DIRS
        ]

        # -------------------------------------------------------------------
        # Individual files
        # -------------------------------------------------------------------

        for filename in files:
            path = current_path / filename

            if path.is_symlink():
                verbose_log(args.verbose, f"encountered symlink {path}")
                continue

            if is_preserved(path, preserved):
                continue

            remove = False

            # Python bytecode.
            if path.suffix.lower() in REMOVABLE_SUFFIXES:
                verbose_log(args.verbose, f"recognized removable file {path}")
                remove = True

            # macOS native binary.
            elif is_macho_file(path):
                verbose_log(args.verbose, f"recognized Mach-O file {path}")
                remove = True

            if not remove:
                continue

            size, success = remove_file(
                path,
                args.dry_run,
            )

            if success:
                total_reclaimable += size
                removed_items += 1
            else:
                errors += 1

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------

    print()
    print("=" * 78)
    print("SUMMARY")
    print("=" * 78)

    print(f"Items:             {removed_items}")
    print(f"Reclaimable space: {format_size(total_reclaimable)}")
    print(f"Errors:            {errors}")

    print()

    if args.dry_run:
        print("DRY RUN: nothing was modified.")
        print("Review the list carefully before running without --dry-run.")
    else:
        print("Cleanup complete.")

    print()

    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
