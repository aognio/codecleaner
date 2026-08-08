import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "codecleaner.py"
sys.path.insert(0, str(ROOT))

import codecleaner  # noqa: E402


MACHO_MAGIC = b"\xfe\xed\xfa\xcf"


def macho_thin(arch: str) -> bytes:
    cputype = {
        "amd64": 0x01000007,
        "arm64": 0x0100000C,
    }[arch]
    return b"\xcf\xfa\xed\xfe" + cputype.to_bytes(4, "little") + b"\x00" * 64


def macho_fat(*architectures: str) -> bytes:
    data = bytearray(b"\xca\xfe\xba\xbe")
    data.extend(len(architectures).to_bytes(4, "big"))

    for architecture in architectures:
        cputype = {
            "amd64": 0x01000007,
            "arm64": 0x0100000C,
        }[architecture]
        data.extend(cputype.to_bytes(4, "big"))
        data.extend(b"\x00" * 16)

    data.extend(b"\x00" * 64)
    return bytes(data)


def elf_file(arch: str) -> bytes:
    machine = {
        "amd64": 62,
        "arm64": 183,
    }[arch]
    data = bytearray(b"\x7fELF")
    data.extend(b"\x02")  # 64-bit
    data.extend(b"\x01")  # little endian
    data.extend(b"\x01")
    data.extend(b"\x00" * 9)
    data.extend((2).to_bytes(2, "little"))
    data.extend(machine.to_bytes(2, "little"))
    data.extend(b"\x00" * 64)
    return bytes(data)


def create_reclaimable_mix(root: Path) -> list[Path]:
    paths = [
        root / "project-a" / ".venv",
        root / "project-b" / "node_modules",
        root / "project-c" / "target",
        root / "project-d" / ".cache",
        root / "project-e" / "native-mach-o",
    ]

    for path in paths[:4]:
        path.mkdir(parents=True)
        (path / "payload").write_bytes(b"x")

    paths[4].parent.mkdir(parents=True)
    paths[4].write_bytes(MACHO_MAGIC + b"x")

    return paths


def reclaimable_identity(item: codecleaner.ReclaimableItem) -> tuple[Path, str, str, str]:
    return (item.path, item.section, item.kind, item.rule)


class CodeCleanerExtendedStatsTests(unittest.TestCase):
    def run_script(
        self,
        root: Path,
        *args: str,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()

        with tempfile.TemporaryDirectory() as home:
            env["HOME"] = home

            return subprocess.run(
                [sys.executable, str(SCRIPT), str(root), *args],
                text=True,
                capture_output=True,
                input=input_text,
                env=env,
            )

    def test_version_prints_without_root(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--version"],
            text=True,
            capture_output=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "codecleaner 0.1.0")

    def test_stats_retains_concise_behavior(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "repo" / ".git").mkdir(parents=True)
            (root / "repo" / "node_modules").mkdir()

            result = self.run_script(root, "--stats")

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("CODE CLEANER STATS", result.stdout)
            self.assertNotIn("CODE CLEANER EXTENDED STATS", result.stdout)
            self.assertNotIn("DEPENDENCIES", result.stdout)
            self.assertTrue((root / "repo" / "node_modules").exists())

    def test_stats_extended_produces_extended_statistics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "repo" / ".git").mkdir(parents=True)
            (root / "repo" / ".git" / "pack").write_bytes(b"g" * 4096)
            (root / "repo" / "node_modules").mkdir()
            (root / "repo" / "node_modules" / "dep.js").write_text("x")
            (root / "repo" / ".next").mkdir()
            (root / "repo" / ".next" / "page").write_text("x")
            (root / "repo" / "__pycache__").mkdir()
            (root / "repo" / "__pycache__" / "mod.pyc").write_bytes(b"x")

            result = self.run_script(root, "--stats", "--extended")

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("CODE CLEANER EXTENDED STATS", result.stdout)
            self.assertIn("DEPENDENCIES", result.stdout)
            self.assertIn("BUILD ARTIFACTS", result.stdout)
            self.assertIn("CACHES", result.stdout)
            self.assertIn("LARGEST GIT DIRECTORIES", result.stdout)
            self.assertIn("EXTENDED SUMMARY", result.stdout)

    def test_extended_without_stats_fails_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_script(Path(tmp), "--extended")

            self.assertEqual(result.returncode, 2)
            self.assertIn("--extended requires --stats", result.stderr)

    def test_removable_directories_are_not_double_counted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nested_cache = root / "node_modules" / "__pycache__"
            nested_cache.mkdir(parents=True)
            (nested_cache / "mod.pyc").write_bytes(b"x")
            (root / "node_modules" / "native").write_bytes(MACHO_MAGIC + b"x")

            stats = codecleaner.collect_extended_stats(root, [], [])

            self.assertEqual(stats.dependencies["node_modules"].count, 1)
            self.assertNotIn("__pycache__", stats.caches)
            self.assertEqual(stats.macho_count, 0)

    def test_git_sizing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            git = root / "repo" / ".git"
            git.mkdir(parents=True)
            (git / "pack").write_bytes(b"x" * 4096)

            stats = codecleaner.collect_extended_stats(root, [], [])

            self.assertEqual(stats.git_size, codecleaner.tree_disk_usage(git))
            self.assertEqual(stats.git_dirs[0][1], git)

    def test_explicit_preserved_trees_are_accounted_for(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            keep = root / "keep"
            keep.mkdir()
            (keep / "native").write_bytes(MACHO_MAGIC + b"x")

            stats = codecleaner.collect_extended_stats(root, [keep], [])

            self.assertEqual(
                stats.explicit_preserved_size,
                codecleaner.tree_disk_usage(keep),
            )
            self.assertEqual(stats.macho_count, 0)
            self.assertEqual(stats.explicit_preserved_dirs[0][1], keep)

    def test_macho_inside_removable_directory_is_not_double_counted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            venv = root / ".venv"
            venv.mkdir()
            (venv / "python").write_bytes(MACHO_MAGIC + b"x")

            stats = codecleaner.collect_extended_stats(root, [], [])

            self.assertEqual(stats.dependencies[".venv"].count, 1)
            self.assertEqual(stats.macho_count, 0)

    def test_symlinks_are_not_followed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            external = Path(tmp) / "external"
            (external / "repo" / ".git").mkdir(parents=True)
            root.mkdir()
            (root / "linked").symlink_to(external, target_is_directory=True)

            stats = codecleaner.collect_extended_stats(root, [], [])

            self.assertEqual(stats.git_size, 0)
            self.assertEqual(stats.git_dirs, [])
            self.assertEqual(stats.scanned_size, stats.other_retained_size)

    def test_summary_totals_reconcile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "repo" / ".git").mkdir(parents=True)
            (root / "repo" / ".git" / "pack").write_bytes(b"g" * 4096)
            (root / "node_modules").mkdir()
            (root / "node_modules" / "dep.js").write_text("x")
            (root / "keep").mkdir()
            (root / "keep" / "data").write_text("x")
            (root / "ordinary.txt").write_text("x")
            (root / "native").write_bytes(MACHO_MAGIC + b"x")

            stats = codecleaner.collect_extended_stats(root, [root / "keep"], [])

            categorized_total = (
                stats.git_size
                + stats.explicit_preserved_size
                + stats.reclaimable_size
                + stats.other_retained_size
            )
            estimated_after_clean = stats.scanned_size - stats.reclaimable_size

            self.assertEqual(stats.scanned_size, categorized_total)
            self.assertEqual(
                estimated_after_clean,
                stats.git_size
                + stats.explicit_preserved_size
                + stats.other_retained_size,
            )
            self.assertEqual(
                stats.reclaimable_size,
                sum(item.size for item in stats.reclaimable_items),
            )

    def test_explain_reclaimable_reconciles_with_extended_totals(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "node_modules").mkdir()
            (root / "node_modules" / "dep.js").write_text("x")
            (root / "__pycache__").mkdir()
            (root / "__pycache__" / "mod.pyc").write_bytes(b"x")
            (root / "native").write_bytes(MACHO_MAGIC + b"x")

            stats = codecleaner.collect_extended_stats(root, [], [])

            self.assertEqual(
                stats.reclaimable_size,
                sum(item.size for item in stats.reclaimable_items),
            )

            result = self.run_script(
                root,
                "--stats",
                "--extended",
                "--explain-reclaimable",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("RECLAIMABLE ITEMS", result.stdout)
            self.assertIn("DEPENDENCIES", result.stdout)
            self.assertIn("CACHES", result.stdout)
            self.assertIn("NATIVE MACOS", result.stdout)

    def test_explain_reclaimable_directories_are_single_items(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nested = root / "node_modules" / "__pycache__"
            nested.mkdir(parents=True)
            (nested / "mod.pyc").write_bytes(b"x")

            stats = codecleaner.collect_extended_stats(root, [], [])
            node_items = [
                item
                for item in stats.reclaimable_items
                if item.path == root / "node_modules"
            ]

            self.assertEqual(len(node_items), 1)
            self.assertFalse(any(item.path == nested for item in stats.reclaimable_items))

    def test_explain_reclaimable_excludes_preserved_and_git(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            keep = root / "keep"
            git = root / "repo" / ".git"
            (keep / "node_modules").mkdir(parents=True)
            (git / "objects").mkdir(parents=True)
            (keep / "node_modules" / "dep").write_text("x")
            (git / "objects" / "pack").write_bytes(b"x")

            stats = codecleaner.collect_extended_stats(root, [keep], [])

            self.assertFalse(
                any(codecleaner.is_inside(item.path, keep) for item in stats.reclaimable_items)
            )
            self.assertFalse(
                any(codecleaner.is_inside(item.path, git) for item in stats.reclaimable_items)
            )

    def test_explain_reclaimable_lists_macho_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            native = root / "tool"
            native.write_bytes(MACHO_MAGIC + b"x")

            result = self.run_script(
                root,
                "--stats",
                "--extended",
                "--explain-reclaimable",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("NATIVE MACOS", result.stdout)
            self.assertIn("tool", result.stdout)

    def test_explain_reclaimable_default_output_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            for index in range(codecleaner.RECLAIMABLE_EXPLAIN_LIMIT + 5):
                (root / f"file_{index}.pyc").write_bytes(b"x")

            result = self.run_script(
                root,
                "--stats",
                "--extended",
                "--explain-reclaimable",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(
                f"Showing {codecleaner.RECLAIMABLE_EXPLAIN_LIMIT} of "
                f"{codecleaner.RECLAIMABLE_EXPLAIN_LIMIT + 5} reclaimable items.",
                result.stdout,
            )
            self.assertIn("Use --all to display every item.", result.stdout)

    def test_explain_reclaimable_all_removes_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            for index in range(codecleaner.RECLAIMABLE_EXPLAIN_LIMIT + 5):
                (root / f"file_{index}.pyc").write_bytes(b"x")

            result = self.run_script(
                root,
                "--stats",
                "--extended",
                "--explain-reclaimable",
                "--all",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("Showing 50 of", result.stdout)
            self.assertIn(f"file_{codecleaner.RECLAIMABLE_EXPLAIN_LIMIT + 4}.pyc", result.stdout)

    def test_verbose_does_not_change_extended_classification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "node_modules").mkdir()
            (root / "node_modules" / "dep").write_text("x")
            (root / "native").write_bytes(MACHO_MAGIC + b"x")

            quiet = codecleaner.collect_extended_stats(root, [], [], verbose=False)

            with redirect_stderr(StringIO()):
                verbose = codecleaner.collect_extended_stats(root, [], [], verbose=True)

            self.assertEqual(quiet.scanned_size, verbose.scanned_size)
            self.assertEqual(quiet.reclaimable_size, verbose.reclaimable_size)
            self.assertEqual(
                [(item.path, item.size, item.section) for item in quiet.reclaimable_items],
                [(item.path, item.size, item.section) for item in verbose.reclaimable_items],
            )

    def test_explanation_uses_cleanup_removable_directory_rule(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            venv = root / ".venv"
            venv.mkdir()
            (venv / "bin").mkdir()

            stats = codecleaner.collect_extended_stats(root, [], [])
            items = [
                item
                for item in stats.reclaimable_items
                if item.path == venv
            ]

            self.assertTrue(codecleaner.is_cleanup_removable_dir(venv))
            self.assertEqual(len(items), 1)
            self.assertEqual(items[0].rule, 'removable directory ".venv"')

    def test_verbose_does_not_change_cleanup_behavior(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root_quiet = Path(tmp) / "quiet"
            root_verbose = Path(tmp) / "verbose"

            for root in [root_quiet, root_verbose]:
                node_modules = root / "node_modules"
                node_modules.mkdir(parents=True)
                (node_modules / "dep").write_text("x")

            quiet = self.run_script(root_quiet)
            verbose = self.run_script(root_verbose, "--verbose")

            self.assertEqual(quiet.returncode, 0, quiet.stderr)
            self.assertEqual(verbose.returncode, 0, verbose.stderr)
            self.assertFalse((root_quiet / "node_modules").exists())
            self.assertFalse((root_verbose / "node_modules").exists())
            self.assertIn("VERBOSE:", verbose.stderr)

    def test_explain_reclaimable_requires_extended_stats(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_script(Path(tmp), "--stats", "--explain-reclaimable")

            self.assertEqual(result.returncode, 2)
            self.assertIn(
                "--explain-reclaimable requires --stats --extended",
                result.stderr,
            )

    def test_clean_reclaimable_uses_explain_reclaimable_classification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            node_modules = root / "node_modules"
            pyc = root / "module.pyc"
            native = root / "native"
            ordinary = root / "main.py"
            node_modules.mkdir()
            (node_modules / "dep").write_text("x")
            pyc.write_bytes(b"x")
            native.write_bytes(MACHO_MAGIC + b"x")
            ordinary.write_text("print('x')\n")

            before = codecleaner.collect_extended_stats(root, [], [])
            expected = {item.path for item in before.reclaimable_items}

            result = self.run_script(root, "--clean-reclaimable")

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("RECLAIMABLE CLEANUP SUMMARY", result.stdout)
            self.assertEqual(expected, {node_modules, pyc, native})
            self.assertFalse(node_modules.exists())
            self.assertFalse(pyc.exists())
            self.assertFalse(native.exists())
            self.assertTrue(ordinary.exists())

    def test_reclaimable_explain_and_interactive_use_same_complete_collection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_reclaimable_mix(root)
            stats = codecleaner.collect_extended_stats(root, [], [])
            explain_candidates = {
                reclaimable_identity(item)
                for item in codecleaner.collect_reclaimable_items(stats)
            }
            interactive_candidates = {
                reclaimable_identity(item)
                for item in codecleaner.materialize_reclaimable_items(
                    codecleaner.collect_reclaimable_items(stats)
                )
            }

            self.assertEqual(explain_candidates, interactive_candidates)

    def test_clean_reclaimable_does_not_apply_hidden_remembered_preserves(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            home = base / "home"
            root = base / "root"
            (home / ".config" / "codecleaner").mkdir(parents=True)
            create_reclaimable_mix(root)
            config = home / ".config" / "codecleaner" / "config.toml"
            config.write_text(f'preserve = ["{root / "project-a"}"]\n')

            env = os.environ.copy()
            env["HOME"] = str(home)

            explain = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    str(root),
                    "--stats",
                    "--extended",
                    "--explain-reclaimable",
                    "--all",
                ],
                text=True,
                capture_output=True,
                env=env,
            )
            clean = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    str(root),
                    "--clean-reclaimable",
                    "--interactive",
                    "--dry-run",
                ],
                text=True,
                capture_output=True,
                input="q\n",
                env=env,
            )

            self.assertEqual(explain.returncode, 0, explain.stderr)
            self.assertEqual(clean.returncode, 0, clean.stderr)
            self.assertIn("RECLAIMABLE ITEMS", explain.stdout)
            self.assertIn("Found 5 reclaimable items", clean.stdout)
            self.assertIn("[1/5] RECLAIMABLE", clean.stdout)

    def test_clean_reclaimable_interactive_presents_all_five_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_reclaimable_mix(root)

            result = self.run_script(
                root,
                "--clean-reclaimable",
                "--interactive",
                input_text="y\nn\ns\ny\nn\n",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Found 5 reclaimable items", result.stdout)

            for index in range(1, 6):
                self.assertIn(f"[{index}/5] RECLAIMABLE", result.stdout)

            self.assertIn("Removed:             2", result.stdout)
            self.assertIn("Declined:            2", result.stdout)
            self.assertIn("Skipped:             1", result.stdout)
            self.assertIn("Stopped early:       no", result.stdout)

    def test_clean_reclaimable_interactive_quit_after_second_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_reclaimable_mix(root)

            result = self.run_script(
                root,
                "--clean-reclaimable",
                "--interactive",
                input_text="y\nq\n",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("[1/5] RECLAIMABLE", result.stdout)
            self.assertIn("[2/5] RECLAIMABLE", result.stdout)
            self.assertNotIn("[3/5] RECLAIMABLE", result.stdout)
            self.assertIn("Removed:             1", result.stdout)
            self.assertIn("Stopped early:       yes", result.stdout)

    def test_clean_reclaimable_deletion_failure_still_presents_next_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = root / "first.pyc"
            second = root / "second.pyc"
            first.write_bytes(b"x" * 8192)
            second.write_bytes(b"x")
            stats = codecleaner.collect_extended_stats(root, [], [])
            items = codecleaner.collect_reclaimable_items(stats)
            calls = []

            def fake_remove(
                item: codecleaner.ReclaimableItem,
                dry_run: bool,
            ) -> tuple[int, bool]:
                calls.append(item.path)

                if len(calls) == 1:
                    return 0, False

                return item.size, True

            with (
                patch("builtins.input", side_effect=["y", "y"]),
                patch.object(codecleaner, "remove_reclaimable_item", fake_remove),
                redirect_stdout(StringIO()) as output,
                redirect_stderr(StringIO()),
            ):
                summary = codecleaner.execute_reclaimable_cleanup(
                    root=root,
                    items=items,
                    interactive=True,
                    dry_run=False,
                )

            self.assertIn("[1/2] RECLAIMABLE", output.getvalue())
            self.assertIn("[2/2] RECLAIMABLE", output.getvalue())
            self.assertEqual(summary.errors, 1)
            self.assertEqual(summary.removed, 1)
            self.assertEqual(len(calls), 2)

    def test_clean_reclaimable_interactive_uses_all_candidates_beyond_explain_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            total = codecleaner.RECLAIMABLE_EXPLAIN_LIMIT + 5

            for index in range(total):
                (root / f"file_{index}.pyc").write_bytes(b"x")

            result = self.run_script(
                root,
                "--clean-reclaimable",
                "--interactive",
                "--dry-run",
                input_text="n\n" * total,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(f"Found {total} reclaimable items", result.stdout)
            self.assertIn(f"[{total}/{total}] RECLAIMABLE", result.stdout)
            self.assertIn(f"Declined:            {total}", result.stdout)

    def test_clean_reclaimable_verbose_reports_materialized_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_reclaimable_mix(root)

            result = self.run_script(
                root,
                "--clean-reclaimable",
                "--interactive",
                "--verbose",
                input_text="q\n",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("VERBOSE: census complete", result.stderr)
            self.assertIn("VERBOSE: reclaimable candidates: 5", result.stderr)
            self.assertIn("VERBOSE: candidates materialized", result.stderr)
            self.assertIn("VERBOSE: candidates sorted by size descending", result.stderr)
            self.assertIn("VERBOSE: starting interactive executor", result.stderr)

    def test_clean_reclaimable_preserved_trees_never_offered_or_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            keep = root / "keep"
            node_modules = keep / "node_modules"
            node_modules.mkdir(parents=True)
            (node_modules / "dep").write_text("x")

            result = self.run_script(
                root,
                "--clean-reclaimable",
                "--interactive",
                "--preserve",
                str(keep),
                input_text="y\n",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("Path:", result.stdout)
            self.assertTrue(node_modules.exists())

    def test_clean_reclaimable_git_is_never_offered_or_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            git = root / "repo" / ".git"
            git.mkdir(parents=True)
            (git / "pack").write_bytes(MACHO_MAGIC + b"x")

            result = self.run_script(
                root,
                "--clean-reclaimable",
                "--interactive",
                input_text="y\n",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("Path:", result.stdout)
            self.assertTrue(git.exists())

    def test_clean_reclaimable_interactive_yes_removes_item(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pyc = root / "module.pyc"
            pyc.write_bytes(b"x")

            result = self.run_script(
                root,
                "--clean-reclaimable",
                "--interactive",
                input_text="yes\n",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(pyc.exists())
            self.assertIn("Removed:             1", result.stdout)

    def test_clean_reclaimable_interactive_no_retains_and_continues(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = root / "first.pyc"
            second = root / "second.pyc"
            first.write_bytes(b"x" * 8192)
            second.write_bytes(b"x")

            result = self.run_script(
                root,
                "--clean-reclaimable",
                "--interactive",
                input_text="no\nyes\n",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(first.exists())
            self.assertFalse(second.exists())
            self.assertIn("Declined:            1", result.stdout)
            self.assertIn("Removed:             1", result.stdout)

    def test_clean_reclaimable_interactive_skip_retains_and_continues(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = root / "first.pyc"
            second = root / "second.pyc"
            first.write_bytes(b"x" * 8192)
            second.write_bytes(b"x")

            result = self.run_script(
                root,
                "--clean-reclaimable",
                "--interactive",
                input_text="skip\nyes\n",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(first.exists())
            self.assertFalse(second.exists())
            self.assertIn("Skipped:             1", result.stdout)
            self.assertIn("Removed:             1", result.stdout)

    def test_clean_reclaimable_interactive_quit_stops_with_partial_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = root / "first.pyc"
            second = root / "second.pyc"
            first.write_bytes(b"x" * 8192)
            second.write_bytes(b"x")

            result = self.run_script(
                root,
                "--clean-reclaimable",
                "--interactive",
                input_text="quit\n",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(first.exists())
            self.assertTrue(second.exists())
            self.assertIn("Stopped early:       yes", result.stdout)
            self.assertIn("Remaining/unseen:    2", result.stdout)

    def test_clean_reclaimable_invalid_and_blank_input_reprompt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pyc = root / "module.pyc"
            pyc.write_bytes(b"x")

            result = self.run_script(
                root,
                "--clean-reclaimable",
                "--interactive",
                input_text="\nmaybe\ny\n",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(pyc.exists())
            self.assertGreaterEqual(
                result.stdout.count("Please answer yes, no, skip, or quit."),
                2,
            )

    def test_clean_reclaimable_interactive_dry_run_modifies_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pyc = root / "module.pyc"
            pyc.write_bytes(b"x")

            result = self.run_script(
                root,
                "--clean-reclaimable",
                "--interactive",
                "--dry-run",
                input_text="y\n",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(pyc.exists())
            self.assertIn("WOULD REMOVE", result.stdout)
            self.assertIn("Selected savings:", result.stdout)
            self.assertIn("Reclaimed space:     0.0 B", result.stdout)

    def test_clean_reclaimable_directory_candidate_is_single_operation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nested = root / "node_modules" / "__pycache__"
            nested.mkdir(parents=True)
            (nested / "module.pyc").write_bytes(b"x")

            result = self.run_script(root, "--clean-reclaimable")

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Items removed:       1", result.stdout)
            self.assertFalse((root / "node_modules").exists())

    def test_clean_reclaimable_interactive_orders_largest_first(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            small = root / "small.pyc"
            large = root / "large.pyc"
            small.write_bytes(b"x")
            large.write_bytes(b"x" * 16384)

            result = self.run_script(
                root,
                "--clean-reclaimable",
                "--interactive",
                input_text="q\n",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            first_prompt = result.stdout.split("[1/2] RECLAIMABLE", 1)[1]
            self.assertIn("large.pyc", first_prompt)

    def test_clean_reclaimable_symlinks_keep_existing_safety_behavior(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            external = Path(tmp) / "external"
            external_node_modules = external / "node_modules"
            root.mkdir()
            external_node_modules.mkdir(parents=True)
            (external_node_modules / "dep").write_text("x")
            (root / "linked").symlink_to(external_node_modules, target_is_directory=True)

            result = self.run_script(root, "--clean-reclaimable")

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((root / "linked").is_symlink())
            self.assertTrue(external_node_modules.exists())
            self.assertIn("Items removed:       0", result.stdout)

    def test_clean_reclaimable_deletion_errors_do_not_corrupt_session_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing = root / "missing.pyc"
            existing = root / "existing.pyc"
            existing.write_bytes(b"x")
            items = [
                codecleaner.ReclaimableItem(
                    section="caches",
                    label="Python bytecode files",
                    path=missing,
                    size=4096,
                    kind="file",
                    rule='removable suffix ".pyc"',
                ),
                codecleaner.ReclaimableItem(
                    section="caches",
                    label="Python bytecode files",
                    path=existing,
                    size=4096,
                    kind="file",
                    rule='removable suffix ".pyc"',
                ),
            ]

            with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                summary = codecleaner.execute_reclaimable_cleanup(
                    root=root,
                    items=items,
                    interactive=False,
                    dry_run=False,
                )

            self.assertEqual(summary.errors, 1)
            self.assertEqual(summary.removed, 1)
            self.assertFalse(existing.exists())

    def test_reclaimable_executor_is_reusable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pyc = root / "module.pyc"
            pyc.write_bytes(b"x")
            item = codecleaner.ReclaimableItem(
                section="caches",
                label="Python bytecode files",
                path=pyc,
                size=4096,
                kind="file",
                rule='removable suffix ".pyc"',
            )

            with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                summary = codecleaner.execute_reclaimable_cleanup(
                    root=root,
                    items=[item],
                    interactive=False,
                    dry_run=True,
                )

            self.assertEqual(summary.candidates, 1)
            self.assertEqual(summary.removed, 1)
            self.assertTrue(pyc.exists())

    def test_clean_by_census_deletes_confirmed_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = root / "candidate"
            candidate.mkdir()
            (candidate / "data").write_text("x")

            result = self.run_script(
                root,
                "--clean-by-census",
                input_text="y\n",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("CODE CLEANER CENSUS", result.stdout)
            self.assertIn("CENSUS CLEANUP SUMMARY", result.stdout)
            self.assertIn("Items removed:      1", result.stdout)
            self.assertFalse(candidate.exists())

    def test_clean_by_census_honors_preserved_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            home = base / "home"
            root = base / "root"
            keep = root / "keep"
            (home / ".config" / "codecleaner").mkdir(parents=True)
            keep.mkdir(parents=True)
            (keep / "data").write_text("x")
            config = home / ".config" / "codecleaner" / "config.toml"
            config.write_text(f'preserve = ["{keep}"]\n')

            env = os.environ.copy()
            env["HOME"] = str(home)
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(root), "--clean-by-census"],
                text=True,
                capture_output=True,
                input="q\n",
                env=env,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Preserved skipped:  1", result.stdout)
            self.assertNotIn(str(keep), result.stdout)
            self.assertTrue(keep.exists())

    def test_clean_by_census_include_preserved_allows_deletion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            home = base / "home"
            root = base / "root"
            keep = root / "keep"
            (home / ".config" / "codecleaner").mkdir(parents=True)
            keep.mkdir(parents=True)
            (keep / "data").write_text("x")
            config = home / ".config" / "codecleaner" / "config.toml"
            config.write_text(f'preserve = ["{keep}"]\n')

            env = os.environ.copy()
            env["HOME"] = str(home)
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    str(root),
                    "--clean-by-census",
                    "--include-preserved",
                ],
                text=True,
                capture_output=True,
                input="y\n",
                env=env,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(str(keep), result.stdout)
            self.assertFalse(keep.exists())

    def test_clean_by_census_skip_skips_descendants(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            parent = root / "parent"
            child = parent / "child"
            child.mkdir(parents=True)
            (child / "data").write_text("x")

            result = self.run_script(
                root,
                "--clean-by-census",
                input_text="s\ny\n",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Items removed:      0", result.stdout)
            self.assertTrue(parent.exists())
            self.assertTrue(child.exists())

    def test_include_preserved_without_clean_by_census_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_script(Path(tmp), "--include-preserved")

            self.assertEqual(result.returncode, 2)
            self.assertIn(
                "--include-preserved requires --clean-by-census",
                result.stderr,
            )

    def test_sanitization_native_platform_detection(self) -> None:
        with patch.object(codecleaner.platform, "system", return_value="Linux"):
            with patch.object(codecleaner.platform, "machine", return_value="x86_64"):
                self.assertEqual(str(codecleaner.detect_native_platform()), "linux-amd64")

    def test_sanitization_platform_alias_normalization(self) -> None:
        self.assertEqual(
            str(codecleaner.normalize_platform_identifier("darwin-aarch64")),
            "macos-arm64",
        )
        self.assertEqual(
            str(codecleaner.normalize_platform_identifier("linux-x64")),
            "linux-amd64",
        )

    def test_sanitization_explicit_target_differs_from_host(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "tool").write_bytes(macho_thin("arm64"))

            with patch.object(codecleaner, "detect_native_platform", return_value=codecleaner.PlatformId("macos", "arm64")):
                result = self.run_script(root, "--sanitize-for", "linux-amd64", "--dry-run")

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Target platform:     linux-amd64", result.stdout)

    def test_sanitization_macho_arm64_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tool"
            path.write_bytes(macho_thin("arm64"))
            artifact = codecleaner.inspect_native_artifact(path)

            self.assertIsNotNone(artifact)
            self.assertEqual(artifact.format, "Mach-O")
            self.assertEqual(artifact.architectures, frozenset({"arm64"}))

    def test_sanitization_macho_amd64_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tool"
            path.write_bytes(macho_thin("amd64"))
            artifact = codecleaner.inspect_native_artifact(path)

            self.assertIsNotNone(artifact)
            self.assertEqual(artifact.architectures, frozenset({"amd64"}))

    def test_sanitization_fat_macho_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "universal"
            path.write_bytes(macho_fat("amd64", "arm64"))
            artifact = codecleaner.inspect_native_artifact(path)

            self.assertIsNotNone(artifact)
            self.assertEqual(artifact.architectures, frozenset({"amd64", "arm64"}))

    def test_sanitization_elf_amd64_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tool"
            path.write_bytes(elf_file("amd64"))
            artifact = codecleaner.inspect_native_artifact(path)

            self.assertIsNotNone(artifact)
            self.assertEqual(artifact.format, "ELF")
            self.assertEqual(artifact.architectures, frozenset({"amd64"}))

    def test_sanitization_elf_arm64_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tool"
            path.write_bytes(elf_file("arm64"))
            artifact = codecleaner.inspect_native_artifact(path)

            self.assertIsNotNone(artifact)
            self.assertEqual(artifact.architectures, frozenset({"arm64"}))

    def test_sanitization_macho_rejected_for_linux_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tool = root / "tool"
            tool.write_bytes(macho_thin("arm64"))
            stats = codecleaner.collect_extended_stats(
                root,
                [],
                [],
                sanitization_target=codecleaner.PlatformId("linux", "amd64"),
            )

            self.assertEqual({item.path for item in stats.sanitization_items}, {tool})
            self.assertEqual(stats.sanitization_items[0].decision, "incompatible")

    def test_sanitization_elf_rejected_for_macos_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tool = root / "tool"
            tool.write_bytes(elf_file("amd64"))
            stats = codecleaner.collect_extended_stats(
                root,
                [],
                [],
                sanitization_target=codecleaner.PlatformId("macos", "amd64"),
            )

            self.assertEqual(stats.sanitization_items[0].decision, "incompatible")

    def test_sanitization_elf_amd64_retained_for_linux_amd64(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "tool").write_bytes(elf_file("amd64"))
            stats = codecleaner.collect_extended_stats(
                root,
                [],
                [],
                sanitization_target=codecleaner.PlatformId("linux", "amd64"),
            )

            self.assertEqual(stats.sanitization_items, [])
            self.assertIn("ELF amd64", stats.compatible_native)

    def test_sanitization_elf_arm64_rejected_for_linux_amd64(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "tool").write_bytes(elf_file("arm64"))
            stats = codecleaner.collect_extended_stats(
                root,
                [],
                [],
                sanitization_target=codecleaner.PlatformId("linux", "amd64"),
            )

            self.assertEqual(len(stats.sanitization_items), 1)
            self.assertEqual(stats.sanitization_items[0].label, "ELF arm64")

    def test_sanitization_executable_scripts_are_not_native(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = root / "deploy.sh"
            script.write_text("#!/bin/sh\necho ok\n")
            script.chmod(0o755)
            stats = codecleaner.collect_extended_stats(
                root,
                [],
                [],
                sanitization_target=codecleaner.PlatformId("linux", "amd64"),
            )

            self.assertEqual(stats.sanitization_items, [])

    def test_sanitization_venv_node_modules_and_target_regenerate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in [".venv", "node_modules", "target"]:
                (root / name).mkdir()
                (root / name / "payload").write_text("x")

            stats = codecleaner.collect_extended_stats(
                root,
                [],
                [],
                sanitization_target=codecleaner.PlatformId("linux", "amd64"),
            )
            by_path = {item.path.name: item.decision for item in stats.sanitization_items}

            self.assertEqual(by_path[".venv"], "regenerate")
            self.assertEqual(by_path["node_modules"], "regenerate")
            self.assertEqual(by_path["target"], "regenerate")

    def test_sanitization_known_caches_are_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ["__pycache__", ".gocache", ".gomodcache", ".cache"]:
                (root / name).mkdir()
                (root / name / "payload").write_text("x")

            stats = codecleaner.collect_extended_stats(
                root,
                [],
                [],
                sanitization_target=codecleaner.PlatformId("linux", "amd64"),
            )

            self.assertEqual({item.decision for item in stats.sanitization_items}, {"cache"})

    def test_sanitization_source_manifests_lockfiles_retained(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ["pyproject.toml", "requirements.txt", "uv.lock", "package.json", "Cargo.lock", "go.mod"]:
                (root / name).write_text("x")

            stats = codecleaner.collect_extended_stats(
                root,
                [],
                [],
                sanitization_target=codecleaner.PlatformId("linux", "amd64"),
            )

            self.assertEqual(stats.sanitization_items, [])

    def test_sanitization_git_is_protected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            git_tool = root / "repo" / ".git" / "tool"
            git_tool.parent.mkdir(parents=True)
            git_tool.write_bytes(macho_thin("arm64"))

            result = self.run_script(root, "--sanitize-for", "linux-amd64")

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(git_tool.exists())
            self.assertNotIn(".git/tool", result.stdout)

    def test_sanitization_preserved_trees_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            keep = root / "keep"
            venv = keep / ".venv"
            venv.mkdir(parents=True)
            (venv / "payload").write_text("x")

            result = self.run_script(root, "--sanitize-for", "linux-amd64", "--preserve", str(keep))

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(venv.exists())
            self.assertNotIn("keep/.venv", result.stdout)

    def test_sanitization_dry_run_performs_no_mutations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            venv = root / ".venv"
            venv.mkdir()
            (venv / "payload").write_text("x")

            result = self.run_script(root, "--sanitize-for", "linux-amd64", "--dry-run")

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(venv.exists())
            self.assertIn("DRY RUN: nothing was modified.", result.stdout)

    def test_sanitization_interactive_yes_no_skip_quit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ["a.pyc", "b.pyc", "c.pyc", "d.pyc"]:
                (root / name).write_bytes(b"x")

            result = self.run_script(
                root,
                "--sanitize-for",
                "linux-amd64",
                "--interactive",
                input_text="y\nn\ns\nq\n",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Declined:            1", result.stdout)
            self.assertIn("Skipped:             1", result.stdout)
            self.assertIn("Stopped early:       yes", result.stdout)

    def test_sanitization_deletion_failures_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing = root / "missing.pyc"
            item = codecleaner.SanitizationItem(
                decision="cache",
                label="Python bytecode files",
                path=missing,
                size=1,
                kind="file",
                rule='removable suffix ".pyc"',
                reason="cache",
                target=codecleaner.PlatformId("linux", "amd64"),
            )

            with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                summary = codecleaner.execute_sanitization_cleanup(
                    root=root,
                    items=[item],
                    interactive=False,
                    dry_run=False,
                )

            self.assertEqual(summary.errors, 1)

    def test_sanitization_directory_candidate_subsumes_descendants(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nested = root / ".venv" / "__pycache__"
            nested.mkdir(parents=True)
            (nested / "module.pyc").write_bytes(b"x")
            (root / ".venv" / "native").write_bytes(macho_thin("arm64"))
            stats = codecleaner.collect_extended_stats(
                root,
                [],
                [],
                sanitization_target=codecleaner.PlatformId("linux", "amd64"),
            )

            self.assertEqual(len(stats.sanitization_items), 1)
            self.assertEqual(stats.sanitization_items[0].path, root / ".venv")

    def test_sanitization_plan_materialized_before_deletion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = root / ".venv"
            second = root / "node_modules"
            first.mkdir()
            second.mkdir()
            (first / "payload").write_bytes(b"x" * 8192)
            (second / "payload").write_bytes(b"x")
            stats = codecleaner.collect_extended_stats(
                root,
                [],
                [],
                sanitization_target=codecleaner.PlatformId("linux", "amd64"),
            )
            items = codecleaner.collect_sanitization_items(stats)

            with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                summary = codecleaner.execute_sanitization_cleanup(
                    root=root,
                    items=items,
                    interactive=False,
                    dry_run=False,
                )

            self.assertEqual(summary.candidates, 2)
            self.assertFalse(first.exists())
            self.assertFalse(second.exists())

    def test_sanitization_cross_target_independent_of_host_architecture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "linux-tool").write_bytes(elf_file("amd64"))

            with patch.object(codecleaner, "detect_native_platform", return_value=codecleaner.PlatformId("macos", "arm64")):
                result = self.run_script(root, "--sanitize-for", "linux-amd64", "--dry-run")

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("COMPATIBLE NATIVE", result.stdout)
            self.assertIn("Total removable:          0.0 B", result.stdout)

    def test_sanitization_native_cli_resolves_linux_amd64(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env = os.environ.copy()
            with patch.object(codecleaner.platform, "system", return_value="Linux"):
                with patch.object(codecleaner.platform, "machine", return_value="x86_64"):
                    native = codecleaner.detect_native_platform()

            self.assertEqual(str(native), "linux-amd64")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(root), "--sanitize-for", "native", "--dry-run"],
                text=True,
                capture_output=True,
                env=env,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Target source:       native", result.stdout)

    def test_sanitization_unknown_formats_default_to_retain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            unknown = root / "blob.bin"
            unknown.write_bytes(b"\x00\x01\x02\x03" * 10)

            result = self.run_script(root, "--sanitize-for", "linux-amd64")

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(unknown.exists())
            self.assertIn("Candidates:          0", result.stdout)

    def test_sanitization_explain_all_lists_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".venv").mkdir()
            (root / ".venv" / "payload").write_text("x")
            (root / "tool").write_bytes(macho_thin("arm64"))

            result = self.run_script(
                root,
                "--sanitize-for",
                "linux-amd64",
                "--dry-run",
                "--explain-sanitization",
                "--all",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("SANITIZATION ITEMS", result.stdout)
            self.assertIn(".venv", result.stdout)
            self.assertIn("tool", result.stdout)


if __name__ == "__main__":
    unittest.main()
