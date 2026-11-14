"""Crash-recovery contracts for the Linux amd64 candidate lifecycle."""

import hashlib
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import linux_distribution_runtime as runtime
from test_linux_distribution import _build, _rewrite_controls_as_legacy


def _crash_worker(arguments: list[str]) -> int:
    action, archive_value, destdir_value, kill_value, trace_value = arguments
    archive = Path(archive_value)
    destdir = Path(destdir_value)
    kill_at = int(kill_value)
    trace = Path(trace_value)
    original_fsync = runtime.os.fsync
    original_rename = runtime._rename_noreplace
    count = 0

    def boundary(label: str) -> None:
        nonlocal count
        count += 1
        with trace.open("a", encoding="ascii") as destination:
            destination.write(f"{count} {label}\n")
            destination.flush()
        if count == kill_at:
            os.kill(os.getpid(), signal.SIGKILL)

    def traced_fsync(descriptor: int) -> None:
        original_fsync(descriptor)
        boundary("fsync")

    def traced_rename(parent: Path, source: str, destination: str) -> tuple[int, int]:
        result = original_rename(parent, source, destination)
        boundary(f"rename:{source}:{destination}")
        return result

    runtime.os.fsync = traced_fsync
    runtime._rename_noreplace = traced_rename
    if action == "install":
        runtime.install(archive, destdir)
    elif action == "upgrade":
        runtime.upgrade(archive, destdir)
    elif action == "rollback-version":
        runtime.rollback_version(archive, destdir)
    elif action == "recover":
        runtime.recover(destdir)
    else:
        raise ValueError("unknown crash worker action")
    return 0


def _trace_events(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line.split(" ", 1)[1] for line in path.read_text().splitlines()]


def _synthetic_install_plan(transaction: str) -> dict[str, object]:
    generation = runtime._generation_core("2" * 64, "3" * 64, "1.0.0", ())
    entries = []
    for relative, digest in (
        (runtime.RECEIPT_PATH, "4" * 64),
        (runtime.JOURNAL_PATH, "5" * 64),
    ):
        staged, quarantine = runtime._transaction_names(relative, transaction)
        entries.append({
            "final": relative,
            "new": {"elf": False, "gid": None, "mode": 0o444, "sha256": digest, "size": 1, "uid": None},
            "old": None,
            "quarantine": quarantine,
            "staged": staged,
        })
    return runtime._transaction_plan(
        action="install",
        transaction=transaction,
        old_generation=None,
        new_generation=generation,
        old_receipt_sha256=None,
        old_journal_sha256=None,
        new_receipt_sha256="4" * 64,
        new_journal_sha256="5" * 64,
        created_directories=[],
        obsolete_directories=[],
        paths=entries,
        discarded_previous=None,
    )


def _schema_1_envelope(plan: dict[str, object]) -> bytes:
    """Re-express a plan with no discarded predecessor as an earlier lifecycle wrote it."""
    if plan["discarded_previous"] is not None:
        raise ValueError("schema 1 plans cannot discard a predecessor")
    legacy = {key: value for key, value in plan.items() if key != "discarded_previous"}
    return runtime._canonical_json({
        "plan": legacy,
        "plan_sha256": hashlib.sha256(runtime.TRANSACTION_DOMAIN + runtime._canonical_json(legacy)).hexdigest(),
        "schema_version": 1,
    })


def _tree(destdir: Path) -> dict[str, object]:
    return {
        str(path.relative_to(destdir)): (
            os.readlink(path) if path.is_symlink()
            else (stat.S_IMODE(path.lstat().st_mode), path.read_bytes() if path.is_file() else None)
        )
        for path in destdir.rglob("*")
    }


class RecoveryIdentityTest(unittest.TestCase):
    def test_generation_identity_is_canonical_and_domain_separated(self):
        files = (
            runtime.InstalledFile("usr/local/bin/trestle", 0o555, 3, "1" * 64, True),
        )
        core = runtime._generation_core("2" * 64, "3" * 64, "1.0.0", files)
        expected = hashlib.sha256(
            b"open-trestle-linux-generation-v1\0" + runtime._canonical_json(core)
        ).hexdigest()
        self.assertEqual(runtime._generation_identity(core), expected)
        self.assertNotEqual(expected, hashlib.sha256(runtime._canonical_json(core)).hexdigest())

    def test_plan_envelope_rejects_tamper_duplicate_keys_and_unsafe_paths(self):
        plan = _synthetic_install_plan("a" * 32)
        body = runtime._transaction_envelope(plan)
        self.assertEqual(runtime._parse_transaction_envelope(body), plan)

        document = json.loads(body)
        document["plan"]["paths"][0]["final"] = "../escape"
        with self.assertRaises(ValueError):
            runtime._parse_transaction_envelope(runtime._canonical_json(document))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            runtime._parse_transaction_envelope(b'{"schema_version":1,"schema_version":1}\n')
        with self.assertRaises(ValueError):
            runtime._parse_transaction_envelope(b"x" * ((1 << 20) + 1))
        unsafe_directories = _synthetic_install_plan("d" * 32)
        unsafe_directories["created_directories"] = ["etc/open-trestle"]
        with self.assertRaises(ValueError):
            runtime._transaction_envelope(unsafe_directories)

    def test_schema_1_plan_envelope_still_parses_without_a_discarded_predecessor(self):
        plan = _synthetic_install_plan("f" * 32)
        self.assertEqual(json.loads(runtime._transaction_envelope(plan))["schema_version"], 2)
        legacy = _schema_1_envelope(plan)
        self.assertEqual(runtime._parse_transaction_envelope(legacy), plan)

        document = json.loads(legacy)
        document["plan"]["discarded_previous"] = None
        document["plan_sha256"] = hashlib.sha256(
            runtime.TRANSACTION_DOMAIN + runtime._canonical_json(document["plan"])
        ).hexdigest()
        with self.assertRaisesRegex(ValueError, "plan fields"):
            runtime._parse_transaction_envelope(runtime._canonical_json(document))
        for version in (3, True, "2"):
            document = json.loads(runtime._transaction_envelope(plan))
            document["schema_version"] = version
            with self.subTest(version=version), self.assertRaisesRegex(ValueError, "schema"):
                runtime._parse_transaction_envelope(runtime._canonical_json(document))

    def test_only_an_upgrade_plan_may_discard_a_predecessor(self):
        plan = _synthetic_install_plan("9" * 32)
        generation = runtime._generation_core("6" * 64, "7" * 64, "0.9.0", ())
        plan["discarded_previous"] = {
            "generation": generation,
            "generation_id": runtime._generation_identity(generation),
            "journal_sha256": "8" * 64,
            "receipt_sha256": "9" * 64,
        }
        with self.assertRaisesRegex(ValueError, "only an upgrade"):
            runtime._transaction_envelope(plan)
        plan["discarded_previous"]["generation_id"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "identity"):
            runtime._transaction_envelope(plan)

    def test_legacy_controls_receive_the_same_canonical_generation_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive, _ = _build(root / "build", b"legacy", "1.0.0")
            destdir = root / "root"
            destdir.mkdir()
            runtime.install(archive, destdir)
            current, _, _ = runtime._load_control(destdir)
            expected = current["generation_id"]
            _rewrite_controls_as_legacy(destdir)
            legacy, _, _ = runtime._load_control(destdir)
            self.assertEqual(legacy["generation_id"], expected)

    def test_owner_policy_is_root_only_in_production_and_nullable_in_destdir(self):
        synthetic = os.stat_result((stat.S_IFREG | 0o444, 0, 0, 1, 2, 0, 1, 0, 0, 0))
        self.assertTrue(runtime._owner_matches(synthetic, None, None))
        self.assertFalse(runtime._owner_matches(synthetic, 0, 0))


class RecoveryStateTest(unittest.TestCase):
    def test_bootstrap_recovery_is_explicit_idempotent_and_preserves_operator_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive, _ = _build(root / "build", b"one", "1.0.0")
            destdir = root / "root"
            destdir.mkdir()
            operator = destdir / "etc/open-trestle/config.json"
            operator.parent.mkdir(parents=True)
            operator.write_text("operator\n")

            validated = runtime.validate_archive(archive)
            files = runtime._managed_generation(validated)
            plan = _synthetic_install_plan("b" * 32)
            anchor = destdir / runtime.BOOTSTRAP_ANCHOR
            anchor.write_bytes(runtime._transaction_envelope(plan))
            anchor.chmod(0o444)

            runtime.recover(destdir)
            runtime.recover(destdir)
            self.assertFalse(anchor.exists())
            self.assertEqual(operator.read_text(), "operator\n")

    def test_pending_schema_1_record_from_an_earlier_lifecycle_restores_the_old_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, _ = _build(root / "first", b"first", "1.0.0")
            second, _ = _build(root / "second", b"second", "1.1.0")
            destdir = root / "root"
            destdir.mkdir()
            runtime.install(first, destdir)
            before = _tree(destdir)
            # Stop after every live file was replaced but before the commit decision,
            # and keep the failure path from recovering, so the pending record stays.
            with patch.object(runtime, "_commit_transaction", side_effect=KeyboardInterrupt("stop before commit")), \
                    patch.object(runtime, "recover", return_value=None):
                with self.assertRaises(KeyboardInterrupt):
                    runtime.upgrade(second, destdir)
            anchor = destdir / runtime.PENDING_ANCHOR
            _, plan = runtime._read_transaction_anchor(destdir, runtime.PENDING_ANCHOR)
            self.assertTrue((destdir / runtime.PREVIOUS_ARCHIVE_PATH).exists())
            anchor.chmod(0o644)
            anchor.write_bytes(_schema_1_envelope(plan))
            anchor.chmod(0o444)

            runtime.recover(destdir)
            runtime.recover(destdir)
            self.assertEqual(_tree(destdir), before)
            runtime.verify_installed(first, destdir)

    def test_mutation_gate_rejects_unanchored_transaction_debris(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive, _ = _build(root / "build", b"one", "1.0.0")
            destdir = root / "root"
            debris = destdir / ("usr/local/bin/.trestle.open-trestle-old-" + "e" * 32)
            debris.parent.mkdir(parents=True)
            debris.write_bytes(b"operator")
            before = debris.read_bytes()
            with self.assertRaisesRegex(ValueError, "transaction-looking"):
                runtime.install(archive, destdir)
            self.assertEqual(debris.read_bytes(), before)
            self.assertIsNone(runtime._active_transaction(destdir))

    def test_pending_unsafe_or_tampered_object_fails_closed(self):
        for fault in ("digest", "symlink", "unexpected"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                parent = root / "usr/local/share/open-trestle/distribution"
                parent.mkdir(parents=True)
                transaction = "c" * 32
                body = b"expected\n"
                plan = _synthetic_install_plan(transaction)
                entry = plan["paths"][1]
                runtime._start_transaction(root, plan)
                if fault == "unexpected":
                    target = parent / ".operator.open-trestle-unknown"
                    target.write_bytes(b"keep")
                else:
                    target = root / entry["staged"]
                    if fault == "digest":
                        target.write_bytes(b"tampered\n")
                        target.chmod(0o444)
                    else:
                        outside = root / "outside"
                        outside.write_bytes(body)
                        target.symlink_to(outside)
                before = sorted(str(path.relative_to(root)) for path in root.rglob("*"))
                with self.assertRaises(ValueError):
                    runtime.recover(root)
                after = sorted(str(path.relative_to(root)) for path in root.rglob("*"))
                self.assertEqual(after, before)
                self.assertTrue((root / runtime.PENDING_ANCHOR).exists())

    def test_multiple_or_malformed_anchors_fail_closed_without_mutation(self):
        for case in ("multiple", "malformed"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                operator = root / "operator"
                operator.write_text("keep")
                first = root / runtime.BOOTSTRAP_ANCHOR
                first.write_bytes(b"{}\n")
                first.chmod(0o444)
                if case == "multiple":
                    second = root / runtime.PENDING_ANCHOR
                    second.write_bytes(b"{}\n")
                    second.chmod(0o444)
                before = {p.name: p.read_bytes() for p in root.iterdir()}
                with self.assertRaises(ValueError):
                    runtime.recover(root)
                after = {p.name: p.read_bytes() for p in root.iterdir()}
                self.assertEqual(after, before)


class CrashMatrixTest(unittest.TestCase):
    @unittest.skipUnless(
        os.environ.get("OPEN_TRESTLE_RUN_CRASH_MATRIX") == "1",
        "set OPEN_TRESTLE_RUN_CRASH_MATRIX=1 for SIGKILL coverage",
    )
    def test_sigkill_after_every_fsync_and_rename_for_lifecycle_and_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, _ = _build(root / "first", b"first", "1.0.0")
            second, _ = _build(root / "second", b"second", "1.1.0")
            script = Path(__file__).resolve()
            for action in ("install", "upgrade", "rollback-version"):
                with self.subTest(action=action):
                    template = root / f"{action}-template"
                    self._prepare(template, action, first, second)
                    trace_root = root / f"{action}-trace-root"
                    shutil.copytree(template, trace_root)
                    trace = root / f"{action}-trace"
                    archive = first if action == "install" else second
                    completed = self._worker(script, action, archive, trace_root, 0, trace)
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    events = _trace_events(trace)
                    self.assertTrue(events)
                    shutil.rmtree(trace_root)
                    trace.unlink()
                    commit_label = f"rename:{runtime.PENDING_ANCHOR}:{runtime.COMMITTED_ANCHOR}"
                    commit_index = events.index(commit_label) + 1
                    for kill_at in range(1, len(events) + 1):
                        case_root = root / f"{action}-kill-{kill_at}"
                        shutil.copytree(template, case_root)
                        case_trace = root / f"{action}-kill-{kill_at}.trace"
                        killed = self._worker(script, action, archive, case_root, kill_at, case_trace)
                        self.assertEqual(
                            killed.returncode,
                            -signal.SIGKILL,
                            f"{action} kill {kill_at}: {killed.stderr}",
                        )
                        active = runtime._active_transaction(case_root)
                        state = None if active is None else active[0]
                        runtime.recover(case_root)
                        runtime.recover(case_root)
                        expected_new = state == runtime.COMMITTED_ANCHOR or (
                            state is None and kill_at > commit_index
                        )
                        self._assert_generation(case_root, action, first, second, expected_new)
                        self._assert_clean(case_root)
                        shutil.rmtree(case_root)
                        case_trace.unlink()

                    for state_name, operation_kill in (
                        ("pending", commit_index - 1),
                        ("committed", commit_index + 1),
                    ):
                        recovery_template = root / f"{action}-{state_name}-recovery-template"
                        shutil.copytree(template, recovery_template)
                        operation_trace = root / f"{action}-{state_name}-operation.trace"
                        killed = self._worker(
                            script, action, archive, recovery_template, operation_kill, operation_trace
                        )
                        self.assertEqual(
                            killed.returncode,
                            -signal.SIGKILL,
                            f"{action} {state_name} setup kill {operation_kill}: {killed.stderr}",
                        )
                        expected_anchor = (
                            runtime.PENDING_ANCHOR if state_name == "pending" else runtime.COMMITTED_ANCHOR
                        )
                        self.assertEqual(runtime._active_transaction(recovery_template)[0], expected_anchor)
                        discovery = root / f"{action}-{state_name}-recovery-discovery"
                        shutil.copytree(recovery_template, discovery)
                        recovery_trace = root / f"{action}-{state_name}-recovery.trace"
                        finished = self._worker(script, "recover", archive, discovery, 0, recovery_trace)
                        self.assertEqual(finished.returncode, 0, finished.stderr)
                        recovery_events = _trace_events(recovery_trace)
                        self.assertTrue(recovery_events)
                        shutil.rmtree(discovery)
                        recovery_trace.unlink()
                        for recover_kill in range(1, len(recovery_events) + 1):
                            case_root = root / f"{action}-{state_name}-recover-{recover_kill}"
                            shutil.copytree(recovery_template, case_root)
                            case_trace = root / f"{action}-{state_name}-recover-{recover_kill}.trace"
                            killed = self._worker(
                                script, "recover", archive, case_root, recover_kill, case_trace
                            )
                            self.assertEqual(
                                killed.returncode,
                                -signal.SIGKILL,
                                f"{action} {state_name} recovery kill {recover_kill}: {killed.stderr}",
                            )
                            runtime.recover(case_root)
                            runtime.recover(case_root)
                            self._assert_generation(
                                case_root, action, first, second, state_name == "committed"
                            )
                            self._assert_clean(case_root)
                            shutil.rmtree(case_root)
                            case_trace.unlink()
                        shutil.rmtree(recovery_template)
                    shutil.rmtree(template)

    def _worker(
        self,
        script: Path,
        action: str,
        archive: Path,
        destdir: Path,
        kill_at: int,
        trace: Path,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(script), "--crash-worker", action, str(archive), str(destdir), str(kill_at), str(trace)],
            text=True,
            capture_output=True,
            check=False,
        )

    def _prepare(self, destdir: Path, action: str, first: Path, second: Path) -> None:
        destdir.mkdir()
        for relative in (
            "etc/open-trestle/config.json",
            "var/lib/open-trestle/state",
            "usr/local/share/open-trestle/operator-note",
        ):
            path = destdir / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("operator\n")
        if action != "install":
            runtime.install(first, destdir)
        if action == "rollback-version":
            runtime.upgrade(second, destdir)

    def _assert_generation(
        self,
        destdir: Path,
        action: str,
        first: Path,
        second: Path,
        expected_new: bool,
    ) -> None:
        if action == "install":
            if expected_new:
                runtime.verify_installed(first, destdir)
            else:
                self.assertFalse((destdir / runtime.RECEIPT_PATH).exists())
        elif action == "upgrade":
            runtime.verify_installed(second if expected_new else first, destdir)
        else:
            runtime.verify_installed(first if expected_new else second, destdir)
        for relative in (
            "etc/open-trestle/config.json",
            "var/lib/open-trestle/state",
            "usr/local/share/open-trestle/operator-note",
        ):
            self.assertEqual((destdir / relative).read_text(), "operator\n")

    def _assert_clean(self, destdir: Path) -> None:
        self.assertIsNone(runtime._active_transaction(destdir))
        leftovers = [
            path for path in destdir.rglob("*")
            if ".open-trestle-" in path.name
        ]
        self.assertEqual(leftovers, [])


if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] == "--crash-worker":
    raise SystemExit(_crash_worker(sys.argv[2:]))

if __name__ == "__main__":
    unittest.main()
