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
        raw = {"contract": "open-trestle/daemon-console-visual-receipt", "schema_version": 2, "phase": phase, **expected, "reduced_motion": True, "horizontal_overflow": False, "keyboard_focus_visible": True, "evidence_disclosure_focus_visible": True, "focus_order_steps": 1, "unexpected_egress": 0, "console_errors": 0, "tap_targets_minimum": 44, "captures": captures}
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
            source = Path(directory); canonical = source / "web/scripts/daemon-visual-check.mjs"
            canonical.parent.mkdir(parents=True); canonical.write_text("export {}\n")
            self.assertEqual(local_alpha_system.validate_browser_script(source, canonical, False), canonical.resolve())
            outside = source / "other.mjs"; outside.write_text("export {}\n")
            with self.assertRaisesRegex(RuntimeError, "canonical browser script"):
                local_alpha_system.validate_browser_script(source, outside, False)

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
            before = local_alpha_system.capture_source_state(root)
            tracked.write_bytes(b"mutate")
            self.assertEqual(subprocess.run(["git", "status", "--porcelain=v2", "--untracked-files=all"], cwd=root, check=True, capture_output=True).stdout, b"")
            with self.assertRaisesRegex(RuntimeError, "source state changed during system verification"):
                local_alpha_system.verify_source_state(root, before)

    def test_source_state_rejects_ignored_same_status_content_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", root], check=True)
            subprocess.run(["git", "config", "user.name", "test"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
            (root / ".gitignore").write_text("ignored.bin\n")
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

    def test_browser_phase_evidence_binds_same_review_before_and_after_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = self.browser_expected()
            before = self.browser_record(root, "before_restart", expected)
            after = self.browser_record(root, "after_restart", expected)
            record = local_alpha_system.validate_browser_phase_evidence(before, after, expected, root)
            self.assertEqual(record["status"], "passed")
            self.assertEqual([phase["phase"] for phase in record["phases"]], ["before_restart", "after_restart"])

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
