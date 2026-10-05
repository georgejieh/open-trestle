"""Focused reliability regressions for the packaged local-alpha driver."""

from __future__ import annotations

import hashlib
import http.server
import json
import os
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import zipfile
import zlib
from pathlib import Path

import local_alpha_system


class _ThreadingServer(http.server.ThreadingHTTPServer):
    daemon_threads = True


class LocalAlphaSystemTest(unittest.TestCase):
    def candidate(self, root: Path, revision: str) -> tuple[Path, bytes]:
        archive = root / "candidate.pyz"
        manifest = (json.dumps({"revision": revision}, sort_keys=True, separators=(",", ":")) + "\n").encode()
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr("manifest.json", manifest)
        archive.chmod(0o700)
        Path(str(archive) + ".sha256").write_text(f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n")
        return archive, manifest

    def png(self, width: int, height: int) -> bytes:
        def chunk(kind: bytes, data: bytes) -> bytes:
            return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
        header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
        return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(b"")) + chunk(b"IEND", b"")

    def rewrite_browser_receipt(self, root: Path, record: dict) -> None:
        receipt = root / record["receipt"]
        raw = {key: value for key, value in record.items() if key not in {"receipt", "receipt_sha256"}}
        receipt.write_text(json.dumps(raw) + "\n")
        record["receipt_sha256"] = hashlib.sha256(receipt.read_bytes()).hexdigest()

    def browser_expected(self):
        return {
            "scope": {"tenant": "tenant-a", "repository": "repository-a", "run": "local-alpha"},
            "run_identity": "1" * 64,
            "diagnostic_set_identity": "2" * 64,
            "deterministic_check_identity": "3" * 64,
            "deterministic_check_state": "failed",
            "observation_count": 1,
            "observation_identities": ["4" * 64],
        }

    def runtime_status(self, observed_at: str) -> dict:
        configuration = {
            "tenant_id": "tenant-a",
            "repository_ids": ["repository-a"],
            "metadata_backend": "local",
            "artifact_backend": "local",
            "artifact_protection": "process_private",
            "notification_backend": "process_local",
            "rate_limit_backend": "process_local",
            "review_mode": "local",
            "webhook_ingress": False,
            "local_workers": True,
            "publication_enabled": False,
            "publication_fence_verified": False,
            "route_count": 0,
            "handlers": [
                {"kind": "acquire_source", "identity": "a" * 64},
                {"kind": "build_change", "identity": "b" * 64},
                {"kind": "inspect_deterministic", "identity": "c" * 64},
            ],
        }
        configuration_identity = local_alpha_system._runtime_digest(configuration, b"open-trestle/runtime-configuration/v1\0")
        unsigned = {"contract": "open-trestle/runtime-status", "schema_version": 1, "identity": "", "configuration_identity": configuration_identity, "tenant_id": "tenant-a", "repository_id": "repository-a", "observed_at": observed_at, "ready": True, "configuration": configuration, "components": [{"name": "local_workers", "state": "ready"}, {"name": "task_notifications", "state": "ready"}]}
        return {**unsigned, "identity": local_alpha_system._runtime_digest(unsigned, b"open-trestle/runtime-status/v1\0")}

    def browser_record(self, root: Path, phase: str, expected: dict):
        prefix = phase.replace("_", "-")
        phase_root = root / "daemon-console" / prefix
        phase_root.mkdir(parents=True)
        specifications = [
            ("desktop-overview", "overview", 1440, 1000),
            ("desktop-findings", "review", 1440, 1000),
            ("desktop-runtime", "runtime", 1440, 1000),
            ("tablet-findings", "review", 900, 1000),
            ("mobile-390-findings", "review", 390, 844),
        ]
        captures = []
        for name, view, width, height in specifications:
            file_name = f"{prefix}-{name}.png"
            image_height = height + 7
            body = self.png(width, image_height)
            (phase_root / file_name).write_bytes(body)
            captures.append({"name": file_name, "view": view, "width": width, "height": height, "image_width": width, "image_height": image_height, "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()})
        base_milliseconds = 1791003600000 if phase == "before_restart" else 1791003660000
        displayed = self.runtime_status("2026-10-03T05:00:00.000Z" if phase == "before_restart" else "2026-10-03T05:01:00.000Z")
        post = self.runtime_status("2026-10-03T05:00:00.100Z" if phase == "before_restart" else "2026-10-03T05:01:00.100Z")
        runtime = {
            "phase": phase,
            "endpoint": "/api/v1/tenants/tenant-a/repositories/repository-a/runtime",
            "displayed_received_at_milliseconds": base_milliseconds + 10,
            "post_capture_received_at_milliseconds": base_milliseconds + 110,
            "displayed": {"contract": "open-trestle/runtime-status-response", "schema_version": 1, "request_id": f"{phase}-displayed", "status": displayed},
            "post_capture": {"contract": "open-trestle/runtime-status-response", "schema_version": 1, "request_id": f"{phase}-post", "status": post},
            "dom": {"status_identity": displayed["identity"], "configuration_identity": displayed["configuration_identity"], "observed_at": displayed["observed_at"], "ready": displayed["ready"], "configuration": displayed["configuration"], "components": displayed["components"]},
            "runtime_screenshot_sha256": next(capture["sha256"] for capture in captures if capture["view"] == "runtime"),
        }
        raw = {"contract": "open-trestle/daemon-console-visual-receipt", "schema_version": 3, "phase": phase, **expected, "runtime": runtime, "reduced_motion": True, "horizontal_overflow": False, "keyboard_focus_visible": True, "evidence_disclosure_focus_visible": True, "focus_order_steps": 1, "unexpected_egress": 0, "console_errors": 0, "tap_targets_minimum": 44, "captures": captures}
        receipt = phase_root / "receipt.json"
        receipt.write_text(json.dumps(raw) + "\n")
        return {**raw, "receipt": str(receipt.relative_to(root)), "receipt_sha256": hashlib.sha256(receipt.read_bytes()).hexdigest()}

    def test_candidate_manifest_binds_matching_source_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            revision = "1" * 40
            archive, manifest = self.candidate(Path(directory), revision)
            record = local_alpha_system.read_candidate_manifest(archive, revision)
            self.assertEqual(record["revision"], revision)
            self.assertEqual(record["manifest_sha256"], hashlib.sha256(manifest).hexdigest())
            self.assertEqual(record["archive_sha256"], hashlib.sha256(archive.read_bytes()).hexdigest())

    def test_candidate_manifest_rejects_mismatched_source_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, _ = self.candidate(Path(directory), "1" * 40)
            with self.assertRaisesRegex(RuntimeError, "candidate manifest revision does not match source HEAD"):
                local_alpha_system.read_candidate_manifest(archive, "2" * 40)

    def test_browser_phase_evidence_rejects_unbound_capture_fields(self):
        expected = self.browser_expected()
        before = {**expected, "phase": "before_restart", "captures": [{}]}
        after = {**expected, "phase": "after_restart", "captures": [{}]}
        with self.assertRaisesRegex(RuntimeError, "browser evidence"):
            local_alpha_system.validate_browser_phase_evidence(before, after, expected)

    def test_browser_script_must_be_canonical_tracked_source(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory); self.provenance_repository(source)
            dependency = source / "web/node_modules/playwright-core/index.js"; dependency.parent.mkdir(parents=True); dependency.write_text("export {}\n")
            canonical = source / "web/scripts/daemon-visual-check.mjs"
            state = local_alpha_system.capture_source_state(source)
            with patch.object(local_alpha_system, "BROWSER_DEPENDENCY_SHA256", state.browser_dependency_sha256):
                self.assertEqual(local_alpha_system.validate_browser_script(source, canonical, False, state), canonical.resolve())
            outside = source / "other.mjs"; outside.write_text("export {}\n")
            with self.assertRaisesRegex(RuntimeError, "canonical browser script"):
                with patch.object(local_alpha_system, "BROWSER_DEPENDENCY_SHA256", state.browser_dependency_sha256):
                    local_alpha_system.validate_browser_script(source, outside, False, state)
            canonical.write_bytes(b"X" * canonical.stat().st_size)
            with self.assertRaisesRegex(RuntimeError, "bytes do not match HEAD"):
                with patch.object(local_alpha_system, "BROWSER_DEPENDENCY_SHA256", state.browser_dependency_sha256):
                    local_alpha_system.validate_browser_script(source, canonical, False, state)

    def test_browser_dependency_symlink_escape_is_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside_directory, tempfile.TemporaryDirectory() as candidate_directory, tempfile.TemporaryDirectory() as output_parent:
            source = Path(directory); self.provenance_repository(source)
            external = Path(outside_directory); (external / "index.js").write_text("malicious")
            package = source / "web/node_modules/playwright-core"; package.parent.mkdir(parents=True); package.symlink_to(external, target_is_directory=True)
            revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=source, check=True, capture_output=True, text=True).stdout.strip()
            candidate, _ = self.candidate(Path(candidate_directory), revision); output = Path(output_parent) / "must-not-exist"
            arguments = ["local_alpha_system.py", "--candidate", str(candidate), "--source-root", str(source), "--browser-script", str(source / "web/scripts/daemon-visual-check.mjs"), "--output", str(output)]
            with patch.object(sys, "argv", arguments), self.assertRaisesRegex(SystemExit, "browser dependency closure"):
                local_alpha_system.main()
            self.assertFalse(output.exists())

    def test_browser_modules_are_sealed_from_exact_head_blobs(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as output_directory:
            source = Path(directory); self.provenance_repository(source)
            contract = source / "web/scripts/daemon-visual-contract.mjs"
            dependency = source / "web/node_modules/playwright-core/index.js"; dependency.parent.mkdir(parents=True); dependency.write_text("export {}\n")
            state = local_alpha_system.capture_source_state(source)
            with patch.object(local_alpha_system, "BROWSER_DEPENDENCY_SHA256", state.browser_dependency_sha256):
                script, record = local_alpha_system.seal_browser_modules(source, state, Path(output_directory) / "sealed")
            self.assertEqual(script.read_bytes(), (source / "web/scripts/daemon-visual-check.mjs").read_bytes())
            self.assertEqual((script.parent / "daemon-visual-contract.mjs").read_bytes(), contract.read_bytes())
            self.assertEqual(record["daemon-visual-check.mjs_head_blob"], state.browser_script_head_blob)
            self.assertEqual(stat.S_IMODE(script.stat().st_mode), 0o444)
            self.assertFalse((Path(output_directory) / "sealed/web/node_modules").is_symlink())
            self.assertEqual((Path(output_directory) / "sealed/web/node_modules/playwright-core/index.js").read_text(), "export {}\n")

    def test_candidate_execution_copy_is_output_owned_and_digest_fenced(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, _ = self.candidate(root, "1" * 40)
            expected = hashlib.sha256(source.read_bytes()).hexdigest()
            sandbox = root / "sandbox"; sandbox.mkdir()
            copied = local_alpha_system.copy_candidate_archive(source, Path(str(source) + ".sha256"), sandbox, expected)
            self.assertEqual(copied.parent, sandbox)
            self.assertEqual(hashlib.sha256(copied.read_bytes()).hexdigest(), expected)
            self.assertEqual(stat.S_IMODE(copied.stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE(Path(str(copied) + ".sha256").stat().st_mode), 0o444)
            local_alpha_system.assert_candidate_digest(copied, expected)
            copied.chmod(0o700); copied.write_bytes(copied.read_bytes() + b"mutation")
            with self.assertRaisesRegex(RuntimeError, "candidate archive changed"):
                local_alpha_system.assert_candidate_digest(copied, expected)

    def test_source_state_rejects_tracked_and_untracked_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", root], check=True)
            subprocess.run(["git", "config", "user.name", "test"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
            tracked = root / "tracked.txt"
            tracked.write_text("original\n")
            subprocess.run(["git", "add", "tracked.txt"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)
            before = local_alpha_system.capture_source_state(root)
            for name, mutate in (
                ("tracked", lambda: tracked.write_text("changed\n")),
                ("untracked", lambda: (root / "untracked.txt").write_text("new\n")),
            ):
                with self.subTest(name=name):
                    mutate()
                    with self.assertRaisesRegex(RuntimeError, "source state changed during system verification"):
                        local_alpha_system.verify_source_state(root, before)
                    subprocess.run(["git", "reset", "--hard", "-q", "HEAD"], cwd=root, check=True)
                    (root / "untracked.txt").unlink(missing_ok=True)

    def test_worktree_snapshot_never_follows_replaced_directory(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside_directory:
            root = Path(directory); victim = root / "victim"; victim.mkdir(); (victim / "inside").write_text("inside")
            outside = Path(outside_directory); (outside / "outside").write_text("outside")
            moved = root / "moved"
            original_scandir = os.scandir
            calls = 0
            def replacing_scandir(path):
                nonlocal calls
                calls += 1
                if calls == 2:
                    victim.rename(moved)
                    victim.symlink_to(outside, target_is_directory=True)
                return original_scandir(path)
            with patch.object(local_alpha_system.os, "scandir", replacing_scandir):
                with self.assertRaisesRegex(RuntimeError, "source worktree changed while captured"):
                    local_alpha_system.capture_worktree(root)

    def test_worktree_snapshot_enforces_actual_read_byte_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); growing = root / "growing.bin"; growing.write_bytes(b"1234")
            original_read = os.read
            grown = False
            def growing_read(descriptor, size):
                nonlocal grown
                if not grown:
                    grown = True
                    with growing.open("ab") as stream:
                        stream.write(b"56789012")
                return original_read(descriptor, size)
            with patch.object(local_alpha_system, "MAX_SOURCE_BYTES", 8), patch.object(local_alpha_system.os, "read", growing_read):
                with self.assertRaisesRegex(RuntimeError, "source worktree byte limit exceeded"):
                    local_alpha_system.capture_worktree(root)

    def test_source_state_rejects_index_flag_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", root], check=True)
            subprocess.run(["git", "config", "user.name", "test"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
            tracked = root / "tracked.txt"; tracked.write_text("tracked\n")
            subprocess.run(["git", "add", "tracked.txt"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)
            for enable, disable in (("--assume-unchanged", "--no-assume-unchanged"), ("--skip-worktree", "--no-skip-worktree")):
                with self.subTest(flag=enable):
                    before = local_alpha_system.capture_source_state(root)
                    subprocess.run(["git", "update-index", enable, "tracked.txt"], cwd=root, check=True)
                    self.assertEqual(subprocess.run(["git", "status", "--porcelain=v2", "--untracked-files=all"], cwd=root, check=True, capture_output=True).stdout, b"")
                    with self.assertRaisesRegex(RuntimeError, "source state changed during system verification"):
                        local_alpha_system.verify_source_state(root, before)
                    subprocess.run(["git", "update-index", disable, "tracked.txt"], cwd=root, check=True)

    def test_source_state_rejects_assume_unchanged_tracked_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", root], check=True)
            subprocess.run(["git", "config", "user.name", "test"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
            tracked = root / "tracked.txt"; tracked.write_bytes(b"before")
            subprocess.run(["git", "add", "tracked.txt"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)
            subprocess.run(["git", "update-index", "--assume-unchanged", "tracked.txt"], cwd=root, check=True)
            tracked.write_bytes(b"mutate")
            self.assertEqual(subprocess.run(["git", "status", "--porcelain=v2", "--untracked-files=all"], cwd=root, check=True, capture_output=True).stdout, b"")
            with self.assertRaisesRegex(RuntimeError, "source provenance rejects assume-unchanged index flags"):
                local_alpha_system.capture_source_state(root)

    def test_source_state_rejects_ignored_same_status_content_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", root], check=True)
            subprocess.run(["git", "config", "user.name", "test"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
            (root / ".gitignore").write_text("ignored.bin\nweb/node_modules/\n")
            (root / "tracked.txt").write_text("tracked\n")
            subprocess.run(["git", "add", ".gitignore", "tracked.txt"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)
            ignored = root / "ignored.bin"
            ignored.write_bytes(b"before")
            before = local_alpha_system.capture_source_state(root)
            self.assertTrue(before.clean)
            ignored.write_bytes(b"mutate")
            self.assertEqual(subprocess.run(["git", "status", "--porcelain=v2", "--untracked-files=all"], cwd=root, check=True, capture_output=True).stdout, b"")
            with self.assertRaisesRegex(RuntimeError, "source state changed during system verification"):
                local_alpha_system.verify_source_state(root, before)

    def test_source_state_rejects_ignored_type_mode_and_target_mutation(self):
        for mutation in ("mode", "type", "target"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                subprocess.run(["git", "init", "-q", root], check=True)
                subprocess.run(["git", "config", "user.name", "test"], cwd=root, check=True)
                subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
                (root / ".gitignore").write_text("ignored.bin\n")
                (root / "tracked.txt").write_text("tracked")
                subprocess.run(["git", "add", ".gitignore", "tracked.txt"], cwd=root, check=True)
                subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)
                ignored = root / "ignored.bin"
                if mutation == "target": ignored.symlink_to("tracked.txt")
                else: ignored.write_bytes(b"ignored")
                before = local_alpha_system.capture_source_state(root)
                if mutation == "mode": ignored.chmod(0o755)
                elif mutation == "type": ignored.unlink(); ignored.symlink_to("tracked.txt")
                else: ignored.unlink(); ignored.symlink_to(".gitignore")
                with self.assertRaisesRegex(RuntimeError, "source state changed during system verification"):
                    local_alpha_system.verify_source_state(root, before)

    def provenance_repository(self, root: Path) -> None:
        subprocess.run(["git", "init", "-q", root], check=True)
        subprocess.run(["git", "config", "user.name", "test"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
        (root / ".gitignore").write_text("ignored.bin\nweb/node_modules/\n")
        (root / "build.txt").write_bytes(b"build-before")
        browser = root / "web/scripts/daemon-visual-check.mjs"; browser.parent.mkdir(parents=True); browser.write_bytes(b"browser-before")
        (root / "web/scripts/daemon-visual-contract.mjs").write_bytes(b"contract-before")
        subprocess.run(["git", "add", ".gitignore", "build.txt", "web/scripts/daemon-visual-check.mjs", "web/scripts/daemon-visual-contract.mjs"], cwd=root, check=True)
        subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)
        (root / "ignored.bin").write_bytes(b"ignored-stable")

    def test_hidden_tracked_mutation_stops_before_output_or_execution(self):
        for relative, flag, visual in (("build.txt", "--assume-unchanged", False), ("web/scripts/daemon-visual-check.mjs", "--skip-worktree", True)):
            with self.subTest(path=relative), tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as candidate_directory, tempfile.TemporaryDirectory() as output_parent:
                root = Path(directory); self.provenance_repository(root)
                revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True).stdout.strip()
                candidate, _ = self.candidate(Path(candidate_directory), revision)
                subprocess.run(["git", "update-index", flag, relative], cwd=root, check=True)
                target = root / relative; target.write_bytes(b"X" * target.stat().st_size)
                output = Path(output_parent) / "must-not-exist"
                arguments = ["local_alpha_system.py", "--candidate", str(candidate), "--source-root", str(root), "--output", str(output)]
                if visual: arguments.extend(["--browser-script", str(root / relative)])
                else: arguments.append("--skip-browser")
                with patch.object(sys, "argv", arguments), self.assertRaisesRegex(SystemExit, "source provenance"):
                    local_alpha_system.main()
                self.assertFalse(output.exists())

    def test_source_provenance_rejects_hidden_tracked_byte_mutation(self):
        for relative, flag in (("build.txt", "--assume-unchanged"), ("web/scripts/daemon-visual-check.mjs", "--skip-worktree")):
            with self.subTest(path=relative, flag=flag), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); self.provenance_repository(root)
                subprocess.run(["git", "update-index", flag, relative], cwd=root, check=True)
                target = root / relative; target.write_bytes(b"X" * target.stat().st_size)
                self.assertEqual(subprocess.run(["git", "status", "--porcelain=v2", "--untracked-files=all"], cwd=root, check=True, capture_output=True).stdout, b"")
                with self.assertRaisesRegex(RuntimeError, "source provenance"):
                    local_alpha_system.capture_source_state(root)

    def test_source_provenance_rejects_hidden_deletion_type_and_mode_drift(self):
        for mode in ("delete", "symlink", "executable"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); self.provenance_repository(root)
                subprocess.run(["git", "update-index", "--assume-unchanged", "build.txt"], cwd=root, check=True)
                target = root / "build.txt"
                if mode == "delete": target.unlink()
                elif mode == "symlink": target.unlink(); target.symlink_to("ignored.bin")
                else: target.chmod(0o755)
                with self.assertRaisesRegex(RuntimeError, "source provenance"):
                    local_alpha_system.capture_source_state(root)

    def test_source_provenance_uses_git_owner_executable_semantics(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self.provenance_repository(root)
            executable = root / "executable.sh"; executable.write_text("#!/bin/sh\n"); executable.chmod(0o755)
            subprocess.run(["git", "add", "executable.sh"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "executable"], cwd=root, check=True)
            executable.chmod(0o700)
            state = local_alpha_system.capture_source_state(root)
            self.assertTrue(state.clean)
            executable.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError, "source provenance|tracked source"):
                local_alpha_system.capture_source_state(root)

    def test_source_provenance_rejects_staged_and_nonignored_untracked_state(self):
        for mode in ("staged", "untracked"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); self.provenance_repository(root)
                if mode == "staged":
                    (root / "build.txt").write_text("staged")
                    subprocess.run(["git", "add", "build.txt"], cwd=root, check=True)
                else:
                    (root / "untracked.txt").write_text("untracked")
                with self.assertRaisesRegex(RuntimeError, "source provenance"):
                    local_alpha_system.capture_source_state(root)

    def test_source_provenance_rejects_unresolved_index_stage_without_git_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self.provenance_repository(root)
            blob = subprocess.run(["git", "rev-parse", "HEAD:build.txt"], cwd=root, check=True, capture_output=True, text=True).stdout.strip()
            subprocess.run(["git", "update-index", "--force-remove", "build.txt"], cwd=root, check=True)
            subprocess.run(["git", "update-index", "--index-info"], cwd=root, check=True, input=f"100644 {blob} 2\tbuild.txt\n", text=True)
            objects_before = sorted(str(path.relative_to(root / ".git/objects")) for path in (root / ".git/objects").rglob("*") if path.is_file())
            index_before = (root / ".git/index").read_bytes()
            with self.assertRaisesRegex(RuntimeError, "source provenance"):
                local_alpha_system.capture_source_state(root)
            self.assertEqual((root / ".git/index").read_bytes(), index_before)
            self.assertEqual(sorted(str(path.relative_to(root / ".git/objects")) for path in (root / ".git/objects").rglob("*") if path.is_file()), objects_before)
            self.assertFalse((root / ".git/index.lock").exists())

    def test_source_provenance_fails_closed_on_tracked_open_race(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self.provenance_repository(root)
            target = root / "build.txt"; original_open = os.open; raced = False
            def racing_open(path, flags, *arguments, **keywords):
                nonlocal raced
                descriptor = original_open(path, flags, *arguments, **keywords)
                if path == b"build.txt" and not raced:
                    raced = True; target.write_bytes(b"race-mutated")
                return descriptor
            with patch.object(local_alpha_system.os, "open", racing_open):
                with self.assertRaisesRegex(RuntimeError, "source provenance changed while captured"):
                    local_alpha_system.capture_source_state(root)
            self.assertTrue(raced)

    def test_source_provenance_does_not_execute_repo_local_fsmonitor(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside_directory:
            root = Path(directory); self.provenance_repository(root)
            marker = Path(outside_directory) / "fsmonitor-ran"
            hook = root / ".git/fsmonitor-hook"
            hook.write_text(f"#!/bin/sh\nprintf ran > {marker}\n")
            hook.chmod(0o755)
            subprocess.run(["git", "config", "core.fsmonitor", str(hook)], cwd=root, check=True)
            local_alpha_system.capture_source_state(root)
            self.assertFalse(marker.exists())

    def test_source_provenance_read_is_index_and_object_store_side_effect_free(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self.provenance_repository(root)
            index = root / ".git/index"; index_before = index.read_bytes(); stat_before = index.stat()
            objects_before = sorted(str(path.relative_to(root / ".git/objects")) for path in (root / ".git/objects").rglob("*") if path.is_file())
            local_alpha_system.capture_source_state(root)
            stat_after = index.stat()
            self.assertEqual(index.read_bytes(), index_before)
            self.assertEqual((stat_after.st_ino, stat_after.st_size, stat_after.st_mtime_ns), (stat_before.st_ino, stat_before.st_size, stat_before.st_mtime_ns))
            self.assertEqual(sorted(str(path.relative_to(root / ".git/objects")) for path in (root / ".git/objects").rglob("*") if path.is_file()), objects_before)
            self.assertFalse((root / ".git/index.lock").exists())

    def test_source_provenance_captures_ignored_nested_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", root], check=True)
            subprocess.run(["git", "config", "user.name", "test"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
            (root / ".gitignore").write_text("refs/\n")
            (root / "tracked.txt").write_text("tracked")
            subprocess.run(["git", "add", ".gitignore", "tracked.txt"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)
            nested = root / "refs/nested"; nested.mkdir(parents=True)
            subprocess.run(["git", "init", "-q", nested], check=True)
            subprocess.run(["git", "config", "user.name", "nested"], cwd=nested, check=True)
            subprocess.run(["git", "config", "user.email", "nested@example.invalid"], cwd=nested, check=True)
            (nested / "inside.txt").write_text("inside")
            subprocess.run(["git", "add", "inside.txt"], cwd=nested, check=True)
            subprocess.run(["git", "commit", "-qm", "nested"], cwd=nested, check=True)
            before = local_alpha_system.capture_source_state(root)
            self.assertGreater(before.ignored_worktree_entries, 1)
            (nested / "inside.txt").write_text("mutated")
            with self.assertRaisesRegex(RuntimeError, "source state changed during system verification"):
                local_alpha_system.verify_source_state(root, before)

    def test_source_provenance_rejects_stable_replace_ref(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self.provenance_repository(root)
            original = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True).stdout.strip()
            (root / "build.txt").write_bytes(b"replacement!!")
            subprocess.run(["git", "add", "build.txt"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "replacement"], cwd=root, check=True)
            replacement = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True).stdout.strip()
            subprocess.run(["git", "reset", "--hard", "-q", original], cwd=root, check=True, env={**os.environ, "GIT_NO_REPLACE_OBJECTS": "1"})
            subprocess.run(["git", "update-ref", f"refs/replace/{original}", replacement], cwd=root, check=True)
            subprocess.run(["git", "reset", "--hard", "-q", "HEAD"], cwd=root, check=True)
            self.assertEqual(subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True).stdout.strip(), original)
            self.assertEqual((root / "build.txt").read_bytes(), b"replacement!!")
            self.assertEqual(subprocess.run(["git", "status", "--porcelain=v2", "--untracked-files=all"], cwd=root, check=True, capture_output=True).stdout, b"")
            with self.assertRaisesRegex(RuntimeError, "replace|literal Git"):
                local_alpha_system.capture_source_state(root)

    def test_source_provenance_rejects_legacy_graft_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self.provenance_repository(root)
            head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True).stdout.strip()
            grafts = root / ".git/info/grafts"; grafts.parent.mkdir(parents=True, exist_ok=True); grafts.write_text(f"{head}\n")
            with self.assertRaisesRegex(RuntimeError, "graft|literal Git"):
                local_alpha_system.capture_source_state(root)

    def test_source_provenance_rejects_redirected_core_worktree(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as external_directory:
            root = Path(directory); self.provenance_repository(root)
            external = Path(external_directory)
            for relative in (".gitignore", "build.txt", "web/scripts/daemon-visual-check.mjs", "web/scripts/daemon-visual-contract.mjs"):
                target = external / relative; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes((root / relative).read_bytes())
            (root / "untracked.go").write_text("package hidden\n")
            subprocess.run(["git", "config", "core.worktree", str(external)], cwd=root, check=True)
            self.assertEqual(subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=root, check=True, capture_output=True, text=True).stdout.strip(), str(external))
            with self.assertRaisesRegex(RuntimeError, "top-level|worktree|source root"):
                local_alpha_system.capture_source_state(root)

    def test_source_provenance_rejects_ambient_git_authority_overrides(self):
        variables = {
            "GIT_INDEX_FILE": "/dev/null/index",
            "GIT_COMMON_DIR": "/dev/null/common",
            "GIT_NO_REPLACE_OBJECTS": "0",
            "GIT_CONFIG_COUNT": "1",
            "GIT_DIR": "/dev/null/git",
            "GIT_WORK_TREE": "/dev/null/worktree",
            "GIT_OBJECT_DIRECTORY": "/dev/null/objects",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/dev/null/alternate",
            "GIT_NAMESPACE": "alternate",
            "GIT_REPLACE_REF_BASE": "refs/other-replacements",
        }
        for name, value in variables.items():
            with self.subTest(variable=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); self.provenance_repository(root)
                with patch.dict(os.environ, {name: value}, clear=False):
                    with self.assertRaisesRegex(RuntimeError, "Git environment|authority override"):
                        local_alpha_system.capture_source_state(root)

    def test_source_provenance_accepts_valid_linked_worktree(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as linked_parent:
            root = Path(directory); self.provenance_repository(root)
            linked = Path(linked_parent) / "linked"
            subprocess.run(["git", "worktree", "add", "-q", "--detach", str(linked), "HEAD"], cwd=root, check=True)
            state = local_alpha_system.capture_source_state(linked)
            self.assertTrue(state.clean)
            self.assertEqual(state.revision, subprocess.run(["git", "rev-parse", "HEAD"], cwd=linked, check=True, capture_output=True, text=True).stdout.strip())
            self.assertNotEqual(subprocess.run(["git", "rev-parse", "--path-format=absolute", "--git-common-dir"], cwd=linked, check=True, capture_output=True, text=True).stdout.strip(), str(linked / ".git"))

    def test_source_provenance_rejects_symlinked_git_object_storage(self):
        for mode in ("fanout", "pack", "ref", "config"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside_directory:
                root = Path(directory); self.provenance_repository(root)
                objects = root / ".git/objects"; outside = Path(outside_directory)
                if mode == "fanout":
                    fanout = next(path for path in objects.iterdir() if path.is_dir() and len(path.name) == 2)
                    moved = outside / fanout.name; fanout.rename(moved); fanout.symlink_to(moved, target_is_directory=True)
                elif mode == "pack":
                    pack = objects / "pack"; pack.mkdir(exist_ok=True)
                    target = outside / "evil.pack"; target.write_bytes(b"outside")
                    (pack / "evil.pack").symlink_to(target)
                elif mode == "ref":
                    reference = next(path for path in (root / ".git/refs/heads").rglob("*") if path.is_file())
                    target = outside / "ref"; reference.rename(target); reference.symlink_to(target)
                else:
                    config = root / ".git/config"; target = outside / "config"; config.rename(target); config.symlink_to(target)
                with self.assertRaisesRegex(RuntimeError, "symlink|redirected Git control"):
                    local_alpha_system.capture_source_state(root)

    def test_source_provenance_rejects_bare_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "--bare", "-q", root], check=True)
            with self.assertRaisesRegex(RuntimeError, "non-bare|work tree|top-level"):
                local_alpha_system.capture_source_state(root)

    def test_source_provenance_rejects_redirected_linked_worktree(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as linked_parent, tempfile.TemporaryDirectory() as external_directory:
            root = Path(directory); self.provenance_repository(root)
            linked = Path(linked_parent) / "linked"
            subprocess.run(["git", "worktree", "add", "-q", "--detach", str(linked), "HEAD"], cwd=root, check=True)
            subprocess.run(["git", "config", "extensions.worktreeConfig", "true"], cwd=root, check=True)
            external = Path(external_directory)
            for relative in (".gitignore", "build.txt", "web/scripts/daemon-visual-check.mjs", "web/scripts/daemon-visual-contract.mjs"):
                target = external / relative; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes((linked / relative).read_bytes())
            (linked / "hidden.go").write_text("package hidden\n")
            subprocess.run(["git", "config", "--worktree", "core.worktree", str(external)], cwd=linked, check=True)
            with self.assertRaisesRegex(RuntimeError, "top-level|worktree|source root"):
                local_alpha_system.capture_source_state(linked)

    def test_invalid_git_authority_stops_before_output_creation(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as candidate_directory, tempfile.TemporaryDirectory() as output_parent:
            root = Path(directory); self.provenance_repository(root)
            raw = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True).stdout.strip()
            (root / "build.txt").write_bytes(b"replacement!!")
            subprocess.run(["git", "add", "build.txt"], cwd=root, check=True)
            tree = subprocess.run(["git", "write-tree"], cwd=root, check=True, capture_output=True, text=True).stdout.strip()
            replacement = subprocess.run(["git", "commit-tree", tree, "-m", "replacement"], cwd=root, check=True, capture_output=True, text=True).stdout.strip()
            subprocess.run(["git", "reset", "--hard", "-q", raw], cwd=root, check=True)
            subprocess.run(["git", "replace", raw, replacement], cwd=root, check=True)
            subprocess.run(["git", "checkout", "-q", replacement, "--", "build.txt"], cwd=root, check=True)
            candidate, _ = self.candidate(Path(candidate_directory), raw)
            output = Path(output_parent) / "must-not-exist"
            arguments = ["local_alpha_system.py", "--candidate", str(candidate), "--source-root", str(root), "--skip-browser", "--output", str(output)]
            with patch.object(sys, "argv", arguments), self.assertRaisesRegex(SystemExit, "replacement"):
                local_alpha_system.main()
            self.assertFalse(output.exists())

    def test_git_authority_drift_after_capture_stops_before_output(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as candidate_directory, tempfile.TemporaryDirectory() as output_parent:
            root = Path(directory); self.provenance_repository(root)
            revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True).stdout.strip()
            tree = subprocess.run(["git", "rev-parse", "HEAD^{tree}"], cwd=root, check=True, capture_output=True, text=True).stdout.strip()
            replacement = subprocess.run(["git", "commit-tree", tree, "-m", "replacement"], cwd=root, check=True, capture_output=True, text=True).stdout.strip()
            candidate, _ = self.candidate(Path(candidate_directory), revision)
            output = Path(output_parent) / "must-not-exist"
            def mutate_authority(*_arguments):
                subprocess.run(["git", "replace", revision, replacement], cwd=root, check=True)
                return None
            arguments = ["local_alpha_system.py", "--candidate", str(candidate), "--source-root", str(root), "--skip-browser", "--output", str(output)]
            with patch.object(sys, "argv", arguments), patch.object(local_alpha_system, "validate_browser_script", mutate_authority), self.assertRaisesRegex(SystemExit, "authority changed|replacement"):
                local_alpha_system.main()
            self.assertFalse(output.exists())

    def test_source_provenance_accepts_canonical_head_with_stable_ignored_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self.provenance_repository(root)
            before = local_alpha_system.capture_source_state(root)
            after = local_alpha_system.verify_source_state(root, before)
            self.assertEqual(before, after)
            self.assertTrue(before.clean)

    def test_browser_phase_evidence_validates_without_artifact_filesystem(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); expected = self.browser_expected()
            before = self.browser_record(root, "before_restart", expected)
            after = self.browser_record(root, "after_restart", expected)
            result = local_alpha_system.validate_browser_phase_evidence(before, after, expected)
            self.assertEqual(result["status"], "passed")
            self.assertTrue(result["runtime"]["configuration_stable"])

    def test_browser_phase_evidence_binds_same_review_before_and_after_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = self.browser_expected()
            before = self.browser_record(root, "before_restart", expected)
            after = self.browser_record(root, "after_restart", expected)
            record = local_alpha_system.validate_browser_phase_evidence(before, after, expected, root)
            self.assertEqual(record["status"], "passed")
            self.assertEqual([phase["phase"] for phase in record["phases"]], ["before_restart", "after_restart"])

    def test_runtime_identity_validator_matches_go_golden(self):
        status = self.runtime_status("2026-10-03T05:00:00Z")
        self.assertEqual(status["configuration_identity"], "f89cbad323eb45449637dd40eba77f7eb63a987754270b85c2f9ec2db5c9be98")
        self.assertEqual(status["identity"], "7140112d9eee5bd9287fe98dc1a2985e79ebf4c00baf33975504c8691830c576")
        envelope = {"contract": "open-trestle/runtime-status-response", "schema_version": 1, "request_id": "go-golden", "status": status}
        parsed = local_alpha_system._runtime_envelope(envelope, {"tenant": "tenant-a", "repository": "repository-a"})
        self.assertEqual(parsed["identity"], status["identity"])


    def test_runtime_identity_validator_reconstructs_handler_key_order(self):
        status = self.runtime_status("2026-10-03T05:00:00.000Z")
        status["configuration"]["handlers"] = [
            {"identity": handler["identity"], "kind": handler["kind"]}
            for handler in status["configuration"]["handlers"]
        ]
        envelope = {"contract": "open-trestle/runtime-status-response", "schema_version": 1, "request_id": "reordered", "status": status}
        parsed = local_alpha_system._runtime_envelope(envelope, {"tenant": "tenant-a", "repository": "repository-a"})
        self.assertEqual(parsed["identity"], status["identity"])

    def test_runtime_identity_validator_normalizes_go_null_handlers(self):
        status = json.loads('{"contract":"open-trestle/runtime-status","schema_version":1,"identity":"8e915eaca0878ba00b7acc3c2ed907333b13e1ff1b825f60c43b8ab0832dd931","configuration_identity":"26ab6e2eb1f2b47d3c8e7f6b8eacb65c76d3594a223a7c9c73ac23f8b08b2d5a","tenant_id":"tenant-a","repository_id":"repository-a","observed_at":"2026-10-03T05:00:00Z","ready":true,"configuration":{"tenant_id":"tenant-a","repository_ids":["repository-a"],"metadata_backend":"local","artifact_backend":"local","artifact_protection":"process_private","notification_backend":"process_local","rate_limit_backend":"process_local","review_mode":"disabled","webhook_ingress":false,"local_workers":false,"publication_enabled":false,"publication_fence_verified":false,"route_count":0,"handlers":null},"components":[]}')
        envelope = {"contract": "open-trestle/runtime-status-response", "schema_version": 1, "request_id": "go-empty-golden", "status": status}
        parsed = local_alpha_system._runtime_envelope(envelope, {"tenant": "tenant-a", "repository": "repository-a"})
        self.assertEqual(parsed["configuration"]["handlers"], [])
        self.assertEqual(parsed["identity"], status["identity"])

    def test_browser_runtime_binding_rejects_hostile_receipts(self):
        expected = self.browser_expected()
        mutations = (
            ("missing_runtime", lambda record: record.pop("runtime")),
            ("boolean_route_count", lambda record: record["runtime"]["displayed"]["status"]["configuration"].__setitem__("route_count", True)),
            ("zero_identity", lambda record: record["runtime"]["displayed"]["status"].__setitem__("identity", "0" * 64)),
            ("unknown_component", lambda record: record["runtime"]["displayed"]["status"]["components"][0].__setitem__("name", "unknown_component")),
            ("dom_disagreement", lambda record: record["runtime"]["dom"].__setitem__("status_identity", "f" * 64)),
            ("stale_response", lambda record: record["runtime"]["displayed"].__setitem__("status", self.runtime_status("1970-01-01T00:00:00.000Z"))),
            ("capture_mutation", lambda record: record["runtime"]["post_capture"]["status"]["components"][0].__setitem__("state", "starting")),
        )
        import copy
        for label, mutate in mutations:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); record = self.browser_record(root, "before_restart", expected)
                mutate(record); self.rewrite_browser_receipt(root, record)
                with self.assertRaisesRegex(RuntimeError, "browser (evidence|runtime)"):
                    local_alpha_system.validate_browser_phase_record(record, expected, root)


    def test_browser_runtime_rejects_cross_phase_receipt_substitution(self):
        import copy
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); expected = self.browser_expected()
            before = self.browser_record(root, "before_restart", expected)
            after = self.browser_record(root, "after_restart", expected)
            after["runtime"] = copy.deepcopy(before["runtime"])
            self.rewrite_browser_receipt(root, after)
            with self.assertRaisesRegex(RuntimeError, "browser runtime"):
                local_alpha_system.validate_browser_phase_evidence(before, after, expected, root)


    def test_browser_phase_evidence_rejects_unknown_deterministic_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); expected = self.browser_expected(); expected["deterministic_check_state"] = "active"
            record = self.browser_record(root, "before_restart", expected)
            with self.assertRaisesRegex(RuntimeError, "scope or state"):
                local_alpha_system.validate_browser_phase_record(record, expected, root)

    def test_browser_phase_evidence_rejects_boolean_numeric_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = self.browser_expected()
            cases = (
                ("observation_count_bool", "observation_count", True),
                ("observation_count_float", "observation_count", 1.0),
                ("console_errors_bool", "console_errors", False),
                ("unexpected_egress_bool", "unexpected_egress", False),
                ("horizontal_overflow_int", "horizontal_overflow", 0),
                ("keyboard_focus_int", "keyboard_focus_visible", 1),
                ("disclosure_focus_int", "evidence_disclosure_focus_visible", 1),
                ("reduced_motion_int", "reduced_motion", 1),
                ("tap_targets_float", "tap_targets_minimum", 44.0),
                ("schema_version_float", "schema_version", 3.0),
            )
            for label, field, value in cases:
                with self.subTest(case=label):
                    phase_root = root / label
                    before = self.browser_record(phase_root, "before_restart", expected)
                    after = self.browser_record(phase_root, "after_restart", expected)
                    before[field] = value
                    after[field] = value
                    self.rewrite_browser_receipt(phase_root, before)
                    self.rewrite_browser_receipt(phase_root, after)
                    with self.assertRaisesRegex(RuntimeError, "browser evidence"):
                        local_alpha_system.validate_browser_phase_evidence(before, after, expected, phase_root)

    def test_browser_phase_evidence_rejects_non_integer_capture_dimensions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = self.browser_expected()
            before = self.browser_record(root, "before_restart", expected)
            after = self.browser_record(root, "after_restart", expected)
            before["captures"][0]["width"] = float(before["captures"][0]["width"])
            self.rewrite_browser_receipt(root, before)
            with self.assertRaisesRegex(RuntimeError, "capture metadata"):
                local_alpha_system.validate_browser_phase_evidence(before, after, expected, root)

    def test_browser_phase_evidence_rejects_non_png_screenshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = self.browser_expected()
            before = self.browser_record(root, "before_restart", expected)
            after = self.browser_record(root, "after_restart", expected)
            capture_path = (root / before["receipt"]).parent / before["captures"][0]["name"]
            body = b"not a png"
            capture_path.write_bytes(body)
            before["captures"][0]["bytes"] = len(body)
            before["captures"][0]["sha256"] = hashlib.sha256(body).hexdigest()
            self.rewrite_browser_receipt(root, before)
            with self.assertRaisesRegex(RuntimeError, "PNG"):
                local_alpha_system.validate_browser_phase_evidence(before, after, expected, root)

    def test_browser_phase_evidence_rejects_png_dimension_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = self.browser_expected()
            before = self.browser_record(root, "before_restart", expected)
            after = self.browser_record(root, "after_restart", expected)
            capture = before["captures"][0]
            capture_path = (root / before["receipt"]).parent / capture["name"]
            body = self.png(capture["image_width"] + 1, capture["image_height"])
            capture_path.write_bytes(body)
            capture["bytes"] = len(body)
            capture["sha256"] = hashlib.sha256(body).hexdigest()
            self.rewrite_browser_receipt(root, before)
            with self.assertRaisesRegex(RuntimeError, "PNG dimensions mismatch"):
                local_alpha_system.validate_browser_phase_evidence(before, after, expected, root)

    def test_browser_phase_evidence_rejects_tampered_screenshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = self.browser_expected()
            before = self.browser_record(root, "before_restart", expected)
            after = self.browser_record(root, "after_restart", expected)
            capture = root / before["receipt"]
            (capture.parent / before["captures"][0]["name"]).write_bytes(b"tampered")
            with self.assertRaisesRegex(RuntimeError, "screenshot digest mismatch"):
                local_alpha_system.validate_browser_phase_evidence(before, after, expected, root)

    def test_browser_phase_evidence_rejects_missing_pre_restart_phase(self):
        expected = self.browser_expected()
        after = {**expected, "phase": "after_restart", "captures": []}
        with self.assertRaisesRegex(RuntimeError, "browser evidence requires before and after restart phases"):
            local_alpha_system.validate_browser_phase_evidence(None, after, expected)

    def test_private_tmp_alias_is_short_and_output_owned(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "owned-tmp"; target.mkdir(mode=0o700)
            alias = local_alpha_system.create_private_tmp_alias(target)
            try:
                self.assertLess(len(str(alias)), 48)
                self.assertTrue(alias.is_symlink())
                self.assertEqual(alias.resolve(), target.resolve())
            finally:
                local_alpha_system.remove_private_tmp_alias(alias, target)
            self.assertFalse(alias.exists())

    def test_private_tmp_alias_rejects_nonprivate_target(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "shared-tmp"; target.mkdir(mode=0o755)
            with self.assertRaisesRegex(RuntimeError, "private temporary target"):
                local_alpha_system.create_private_tmp_alias(target)

    def test_command_runs_from_output_sandbox_with_private_tmp(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sandbox = root / "sandbox"; private_tmp = root / "tmp"
            sandbox.mkdir(); private_tmp.mkdir()
            env = {**os.environ, "TMPDIR": str(private_tmp)}
            result = local_alpha_system.run([sys.executable, "-c", "import os; print(os.getcwd()); print(os.environ['TMPDIR'])"], env, sandbox)
            self.assertEqual(result.stdout.decode().splitlines(), [str(sandbox), str(private_tmp)])

    def test_port_probe_rejects_stale_listener(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0)); listener.listen()
            with self.assertRaises(OSError):
                local_alpha_system.prove_port_reusable(listener.getsockname()[1])

    def test_command_output_flood_is_bounded(self):
        with self.assertRaisesRegex(RuntimeError, "output byte limit"):
            local_alpha_system.run(
                [sys.executable, "-c", "import os; os.write(1, b'x' * (2 << 20))"],
                dict(os.environ),
                timeout=2,
            )

    def test_oversized_http_body_is_bounded(self):
        body = b"x" * (2 << 20)
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            def log_message(self, *_):
                pass
        server = _ThreadingServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with self.assertRaisesRegex(RuntimeError, "HTTP body byte limit"):
                local_alpha_system.request(f"http://127.0.0.1:{server.server_port}/")
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)

    def test_nonterminating_http_response_has_total_deadline(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200); self.end_headers()
                try:
                    while True:
                        self.wfile.write(b"x"); self.wfile.flush(); time.sleep(0.02)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            def log_message(self, *_):
                pass
        server = _ThreadingServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        started = time.monotonic()
        try:
            with self.assertRaisesRegex(RuntimeError, "HTTP total deadline"):
                local_alpha_system.request(f"http://127.0.0.1:{server.server_port}/", total_timeout=0.25)
            self.assertLess(time.monotonic() - started, 1.0)
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)

    def test_command_timeout_kills_surviving_process_group(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_path = Path(directory) / "child.pid"
            child = "import os,pathlib,sys,time; pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(30)"
            parent = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); time.sleep(30)"
            try:
                with self.assertRaisesRegex(RuntimeError, "total deadline"):
                    local_alpha_system.run([sys.executable, "-c", parent, child, str(pid_path)], dict(os.environ), timeout=1.0)
                deadline = time.monotonic() + 2
                while not pid_path.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(pid_path.exists())
                child_pid = int(pid_path.read_text())
                with self.assertRaises(ProcessLookupError):
                    os.kill(child_pid, 0)
            finally:
                if pid_path.exists():
                    try: os.kill(int(pid_path.read_text()), signal.SIGKILL)
                    except ProcessLookupError: pass

    def test_stop_daemon_kills_group_after_parent_exit_and_releases_port(self):
        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / "ready"
            child = "import os,pathlib,socket,sys,time; s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(); pathlib.Path(sys.argv[1]).write_text(str(s.getsockname()[1])+' '+str(os.getpid())); time.sleep(30)"
            parent = subprocess.Popen(
                [sys.executable, "-c", "import os,subprocess,sys; child_process=subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); os._exit(0)", child, str(ready)],
                start_new_session=True,
            )
            parent.wait(timeout=2)
            deadline = time.monotonic() + 2
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(ready.exists())
            port, child_pid = map(int, ready.read_text().split())
            try:
                local_alpha_system.stop_daemon(parent)
                with socket.socket() as probe:
                    probe.bind(("127.0.0.1", port))
                with self.assertRaises(ProcessLookupError):
                    os.kill(child_pid, 0)
            finally:
                try: os.killpg(parent.pid, signal.SIGKILL)
                except ProcessLookupError: pass

    def test_daemon_log_flood_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "daemon.py"
            binary.write_text("#!/usr/bin/env python3\nimport os,time\nos.write(1,b'x'*(2<<20))\ntime.sleep(30)\n")
            binary.chmod(0o700)
            log = root / "daemon.log"
            with self.assertRaisesRegex(RuntimeError, "daemon log byte limit"):
                local_alpha_system.start_daemon(binary, [], dict(os.environ), log, "http://127.0.0.1:1", total_timeout=1)
            self.assertLessEqual(log.stat().st_size, 1 << 20)


if __name__ == "__main__":
    unittest.main()
