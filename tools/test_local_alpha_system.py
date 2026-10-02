"""Focused reliability regressions for the packaged local-alpha driver."""

from __future__ import annotations

import hashlib
import http.server
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zipfile
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

    def test_browser_phase_evidence_binds_same_review_before_and_after_restart(self):
        expected = {
            "scope": {"tenant": "tenant-a", "repository": "repository-a", "run": "local-alpha"},
            "run_identity": "1" * 64,
            "diagnostic_set_identity": "2" * 64,
            "deterministic_check_identity": "3" * 64,
            "deterministic_check_state": "failed",
            "observation_count": 1,
        }
        before = {**expected, "phase": "before_restart", "captures": [{"name": "desktop-overview.png", "sha256": "4" * 64, "bytes": 10}]}
        after = {**expected, "phase": "after_restart", "captures": [{"name": "desktop-overview.png", "sha256": "5" * 64, "bytes": 11}]}
        record = local_alpha_system.validate_browser_phase_evidence(before, after, expected)
        self.assertEqual(record["status"], "passed")
        self.assertEqual([phase["phase"] for phase in record["phases"]], ["before_restart", "after_restart"])

    def test_browser_phase_evidence_rejects_missing_pre_restart_phase(self):
        expected = {
            "scope": {"tenant": "tenant-a", "repository": "repository-a", "run": "local-alpha"},
            "run_identity": "1" * 64,
            "diagnostic_set_identity": "2" * 64,
            "deterministic_check_identity": "3" * 64,
            "deterministic_check_state": "failed",
            "observation_count": 1,
        }
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
                [sys.executable, "-c", "import subprocess,sys; subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)", child, str(ready)],
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
