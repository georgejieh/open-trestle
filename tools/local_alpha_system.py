#!/usr/bin/env python3
"""Run the bounded local single-node evaluation journey with real product binaries."""
from __future__ import annotations

import argparse
import atexit
import hashlib
import http.client
import json
import os
import re
import secrets
import selectors
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import urllib.parse
import zipfile
from dataclasses import dataclass
from pathlib import Path

MAX_COMMAND_OUTPUT_BYTES = 1 << 20
MAX_HTTP_BODY_BYTES = 1 << 20
MAX_DAEMON_LOG_BYTES = 1 << 20
MAX_MANIFEST_BYTES = 1 << 20
MAX_FAILURE_LOG_BYTES = 64 << 10
MAX_SOURCE_ENTRIES = 100_000
MAX_SOURCE_BYTES = 8 << 30
MAX_CANDIDATE_BYTES = 256 << 20
PROCESS_TERM_SECONDS = 2.0
PROCESS_KILL_SECONDS = 2.0


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    path.chmod(0o600)


def assert_candidate_digest(candidate: Path, expected: str) -> None:
    if sha256(candidate) != expected:
        raise RuntimeError("candidate archive changed after verification")


def copy_candidate_archive(source: Path, sidecar: Path, sandbox: Path, expected: str) -> Path:
    try:
        before = source.lstat()
        sidecar_status = sidecar.lstat()
    except OSError as error:
        raise RuntimeError("candidate archive copy source is unavailable") from error
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode) or before.st_size <= 0 or before.st_size > MAX_CANDIDATE_BYTES or not stat.S_ISREG(sidecar_status.st_mode) or stat.S_ISLNK(sidecar_status.st_mode):
        raise RuntimeError("candidate archive copy source is invalid")
    destination = sandbox / "open-trestle-linux-amd64.pyz"
    destination_sidecar = Path(str(destination) + ".sha256")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    source_descriptor = os.open(source, flags)
    try:
        opened = os.fstat(source_descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_size) != (before.st_dev, before.st_ino, before.st_mode, before.st_size):
            raise RuntimeError("candidate archive changed while copied")
        destination_descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0), 0o500)
        digest = hashlib.sha256()
        copied = 0
        try:
            while True:
                chunk = os.read(source_descriptor, 1 << 20)
                if not chunk:
                    break
                copied += len(chunk)
                if copied > MAX_CANDIDATE_BYTES:
                    raise RuntimeError("candidate archive byte limit exceeded")
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(destination_descriptor, view)
                    view = view[written:]
            os.fsync(destination_descriptor)
        finally:
            os.close(destination_descriptor)
        after = os.fstat(source_descriptor)
    finally:
        os.close(source_descriptor)
    try:
        path_after = source.lstat()
    except OSError as error:
        raise RuntimeError("candidate archive changed while copied") from error
    if (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns) != (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns) or (path_after.st_dev, path_after.st_ino, path_after.st_mode, path_after.st_size, path_after.st_mtime_ns) != (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns) or digest.hexdigest() != expected:
        raise RuntimeError("candidate archive changed while copied")
    destination.chmod(0o555)
    sidecar_body = read_bounded(sidecar, 4096)
    fields = sidecar_body.decode("ascii").strip().split()
    if not fields or fields[0] != expected:
        raise RuntimeError("candidate checksum does not match detached sidecar")
    write(destination_sidecar, sidecar_body)
    destination_sidecar.chmod(0o444)
    assert_candidate_digest(destination, expected)
    return destination


def create_private_tmp_alias(target: Path) -> Path:
    root = Path("/dev/shm")
    if not root.is_dir() or not os.access(root, os.W_OK | os.X_OK):
        raise RuntimeError("private short temporary root is unavailable")
    try:
        information = target.lstat()
    except OSError as error:
        raise RuntimeError("private temporary target is unavailable") from error
    if not stat.S_ISDIR(information.st_mode) or stat.S_ISLNK(information.st_mode) or stat.S_IMODE(information.st_mode) != 0o700 or information.st_uid != os.geteuid():
        raise RuntimeError("private temporary target must be an owned mode-0700 directory")
    target = target.resolve()
    for _ in range(8):
        alias = root / ("ot-" + secrets.token_hex(8))
        try:
            alias.symlink_to(target, target_is_directory=True)
            return alias
        except FileExistsError:
            continue
    raise RuntimeError("private short temporary alias is unavailable")


def remove_private_tmp_alias(alias: Path, target: Path) -> None:
    try:
        information = alias.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISLNK(information.st_mode) or alias.resolve() != target.resolve():
        raise RuntimeError("private short temporary alias changed")
    alias.unlink()


def read_bounded(path: Path, maximum: int) -> bytes:
    with path.open("rb") as stream:
        body = stream.read(maximum + 1)
    if len(body) > maximum:
        raise RuntimeError(f"bounded file exceeds {maximum} bytes")
    return body


def process_group_alive(group: int) -> bool:
    try:
        os.killpg(group, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    group = process.pid
    if process_group_alive(group):
        try:
            os.killpg(group, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + PROCESS_TERM_SECONDS
    while process_group_alive(group) and time.monotonic() < deadline:
        process.poll()
        time.sleep(0.01)
    if process_group_alive(group):
        try:
            os.killpg(group, signal.SIGKILL)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + PROCESS_KILL_SECONDS
    while process_group_alive(group) and time.monotonic() < deadline:
        process.poll()
        time.sleep(0.01)
    try:
        process.wait(timeout=PROCESS_KILL_SECONDS)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("direct child did not become quiescent") from error
    if process_group_alive(group):
        raise RuntimeError("process group did not become quiescent")


def run(
    command: list[str],
    env: dict[str, str],
    cwd: Path | None = None,
    accepted: tuple[int, ...] = (0,),
    timeout: float = 120,
    maximum_output_bytes: int = MAX_COMMAND_OUTPUT_BYTES,
) -> subprocess.CompletedProcess[bytes]:
    if timeout <= 0 or maximum_output_bytes <= 0:
        raise RuntimeError("invalid command execution bound")
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    assert process.stdout is not None and process.stderr is not None
    streams = selectors.DefaultSelector()
    streams.register(process.stdout, selectors.EVENT_READ, "stdout")
    streams.register(process.stderr, selectors.EVENT_READ, "stderr")
    bodies = {"stdout": bytearray(), "stderr": bytearray()}
    total = 0
    deadline = time.monotonic() + timeout
    failure = ""
    try:
        while streams.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = "command total deadline exceeded"
                break
            for key, _ in streams.select(min(0.05, remaining)):
                chunk = os.read(key.fileobj.fileno(), 64 << 10)
                if not chunk:
                    streams.unregister(key.fileobj)
                    continue
                permitted = max(0, maximum_output_bytes - total)
                bodies[key.data].extend(chunk[:permitted])
                total += len(chunk)
                if total > maximum_output_bytes:
                    failure = "command output byte limit exceeded"
                    break
            if failure:
                break
        if not failure:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = "command total deadline exceeded"
            else:
                try:
                    returncode = process.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    failure = "command total deadline exceeded"
        if failure:
            terminate_process_group(process)
            raise RuntimeError(failure)
        if process_group_alive(process.pid):
            terminate_process_group(process)
        stdout = bytes(bodies["stdout"])
        stderr = bytes(bodies["stderr"])
        if returncode not in accepted:
            detail = stderr.decode("utf-8", "replace")
            raise RuntimeError(f"command failed ({returncode}): {command[0]} {command[1:]}\n{detail}")
        return subprocess.CompletedProcess(command, returncode, stdout, stderr)
    except BaseException:
        if process_group_alive(process.pid):
            terminate_process_group(process)
        raise
    finally:
        streams.close()
        process.stdout.close()
        process.stderr.close()


def request(
    url: str,
    token: str | None = None,
    total_timeout: float = 5,
    maximum_body_bytes: int = MAX_HTTP_BODY_BYTES,
) -> bytes:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "::1"} or parsed.port is None or parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise RuntimeError("invalid loopback HTTP URL")
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    target = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    deadline = time.monotonic() + total_timeout
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=total_timeout)
    try:
        connection.request("GET", target, headers=headers)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("HTTP total deadline exceeded")
        if connection.sock is not None:
            connection.sock.settimeout(remaining)
        response = connection.getresponse()
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status}: {url}")
        declared = response.getheader("Content-Length")
        if declared is not None:
            try:
                if int(declared) > maximum_body_bytes:
                    raise RuntimeError("HTTP body byte limit exceeded")
            except ValueError as error:
                raise RuntimeError("invalid HTTP content length") from error
        body = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("HTTP total deadline exceeded")
            if connection.sock is not None:
                connection.sock.settimeout(remaining)
            try:
                chunk = response.read1(min(64 << 10, maximum_body_bytes + 1 - len(body)))
            except TimeoutError as error:
                raise RuntimeError("HTTP total deadline exceeded") from error
            if not chunk:
                break
            body.extend(chunk)
            if len(body) > maximum_body_bytes:
                raise RuntimeError("HTTP body byte limit exceeded")
        return bytes(body)
    except OSError as error:
        raise RuntimeError("HTTP request unavailable") from error
    finally:
        connection.close()


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def prove_port_reusable(port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        probe.bind(("127.0.0.1", port))


class DaemonLog:
    def __init__(self, process: subprocess.Popen[bytes], path: Path, maximum: int) -> None:
        self.process = process
        self.path = path
        self.maximum = maximum
        self.error: str | None = None
        self._stream = path.open("wb")
        self._thread = threading.Thread(target=self._pump, name="trestled-log", daemon=True)
        self._thread.start()

    def _pump(self) -> None:
        assert self.process.stdout is not None
        total = 0
        try:
            while True:
                chunk = self.process.stdout.read(64 << 10)
                if not chunk:
                    break
                permitted = max(0, self.maximum - total)
                if permitted:
                    self._stream.write(chunk[:permitted])
                    self._stream.flush()
                total += len(chunk)
                if total > self.maximum:
                    self.error = "daemon log byte limit exceeded"
                    try:
                        os.killpg(self.process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    break
        finally:
            self._stream.flush()

    def close(self) -> None:
        self._thread.join(timeout=PROCESS_TERM_SECONDS + PROCESS_KILL_SECONDS)
        if self._thread.is_alive() and self.error is None:
            self.error = "daemon log reader did not stop"
        if self.process.stdout is not None:
            self.process.stdout.close()
        self._stream.close()


def start_daemon(
    binary: Path,
    args: list[str],
    env: dict[str, str],
    log: Path,
    url: str,
    cwd: Path | None = None,
    total_timeout: float = 15,
    maximum_log_bytes: int = MAX_DAEMON_LOG_BYTES,
) -> subprocess.Popen[bytes]:
    process: subprocess.Popen[bytes] | None = None
    capture: DaemonLog | None = None
    deadline = time.monotonic() + total_timeout
    try:
        process = subprocess.Popen(
            [str(binary), *args],
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        capture = DaemonLog(process, log, maximum_log_bytes)
        process._trestle_log_capture = capture  # type: ignore[attr-defined]
        while True:
            if capture.error:
                raise RuntimeError(capture.error)
            if process.poll() is not None:
                tail = read_bounded(log, maximum_log_bytes)[-MAX_FAILURE_LOG_BYTES:].decode("utf-8", "replace")
                raise RuntimeError(f"trestled exited {process.returncode}: {tail}")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("trestled readiness total deadline exceeded")
            try:
                request(url + "/readyz", total_timeout=min(0.5, remaining))
                time.sleep(0.05)
                if process.poll() is not None or capture.error:
                    continue
                return process
            except RuntimeError:
                time.sleep(min(0.05, max(0, deadline - time.monotonic())))
    except BaseException as primary:
        cleanup_error: Exception | None = None
        if process is not None:
            try:
                stop_daemon(process)
            except Exception as caught:
                cleanup_error = caught
        if cleanup_error is not None:
            raise RuntimeError(f"daemon startup failed and cleanup failed: {cleanup_error}") from primary
        raise


def stop_daemon(process: subprocess.Popen[bytes] | None) -> None:
    if process is None:
        return
    capture: DaemonLog | None = getattr(process, "_trestle_log_capture", None)
    error: Exception | None = None
    try:
        terminate_process_group(process)
    except Exception as caught:
        error = caught
    finally:
        if capture is not None:
            capture.close()
            if capture.error and error is None:
                error = RuntimeError(capture.error)
    if error is not None:
        raise error


def canonical_json(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def capture_worktree(source: Path) -> tuple[str, int, int]:
    digest = hashlib.sha256()
    entries = 0
    total_bytes = 0
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)

    def add(value: bytes) -> None:
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)

    def identity(information: os.stat_result) -> tuple[int, int, int, int, int]:
        return (information.st_dev, information.st_ino, information.st_mode, information.st_size, information.st_mtime_ns)

    def visit(directory_descriptor: int, relative: bytes) -> None:
        nonlocal entries, total_bytes
        directory_before = os.fstat(directory_descriptor)
        try:
            with os.scandir(directory_descriptor) as scanned:
                children = sorted(scanned, key=lambda item: os.fsencode(item.name))
        except OSError as error:
            raise RuntimeError("source worktree is unavailable") from error
        for child in children:
            name = os.fsencode(child.name)
            child_relative = name if not relative else relative + b"/" + name
            if not relative and name == b".git":
                continue
            try:
                before = child.stat(follow_symlinks=False)
            except OSError as error:
                raise RuntimeError("source worktree entry is unavailable") from error
            entries += 1
            if entries > MAX_SOURCE_ENTRIES:
                raise RuntimeError("source worktree entry limit exceeded")
            add(child_relative)
            add(stat.S_IMODE(before.st_mode).to_bytes(4, "big"))
            if stat.S_ISDIR(before.st_mode):
                add(b"directory")
                try:
                    child_descriptor = os.open(child.name, directory_flags, dir_fd=directory_descriptor)
                except OSError as error:
                    raise RuntimeError("source worktree changed while captured") from error
                try:
                    if identity(os.fstat(child_descriptor)) != identity(before):
                        raise RuntimeError("source worktree changed while captured")
                    visit(child_descriptor, child_relative)
                    opened_after = os.fstat(child_descriptor)
                finally:
                    os.close(child_descriptor)
                try:
                    path_after = os.stat(child.name, dir_fd=directory_descriptor, follow_symlinks=False)
                except OSError as error:
                    raise RuntimeError("source worktree changed while captured") from error
                if identity(opened_after) != identity(before) or identity(path_after) != identity(before):
                    raise RuntimeError("source worktree changed while captured")
                continue
            if stat.S_ISLNK(before.st_mode):
                add(b"symlink")
                try:
                    add(os.fsencode(os.readlink(child.name, dir_fd=directory_descriptor)))
                    path_after = os.stat(child.name, dir_fd=directory_descriptor, follow_symlinks=False)
                except OSError as error:
                    raise RuntimeError("source worktree symlink is unavailable") from error
                if identity(path_after) != identity(before):
                    raise RuntimeError("source worktree changed while captured")
                continue
            if not stat.S_ISREG(before.st_mode):
                raise RuntimeError("source worktree contains unsupported entry")
            add(b"regular")
            add(before.st_size.to_bytes(8, "big"))
            try:
                descriptor = os.open(child.name, file_flags, dir_fd=directory_descriptor)
            except OSError as error:
                raise RuntimeError("source worktree file is unavailable") from error
            read_bytes = 0
            try:
                if identity(os.fstat(descriptor)) != identity(before):
                    raise RuntimeError("source worktree changed while captured")
                while True:
                    chunk = os.read(descriptor, 1 << 20)
                    if not chunk:
                        break
                    if total_bytes + len(chunk) > MAX_SOURCE_BYTES:
                        raise RuntimeError("source worktree byte limit exceeded")
                    total_bytes += len(chunk)
                    read_bytes += len(chunk)
                    digest.update(chunk)
                opened_after = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            try:
                path_after = os.stat(child.name, dir_fd=directory_descriptor, follow_symlinks=False)
            except OSError as error:
                raise RuntimeError("source worktree changed while captured") from error
            if read_bytes != before.st_size or identity(opened_after) != identity(before) or identity(path_after) != identity(before):
                raise RuntimeError("source worktree changed while captured")
        directory_after = os.fstat(directory_descriptor)
        if identity(directory_after) != identity(directory_before):
            raise RuntimeError("source worktree changed while captured")

    try:
        source_before = source.lstat()
        root_descriptor = os.open(source, directory_flags)
    except OSError as error:
        raise RuntimeError("source worktree root is unavailable") from error
    try:
        if not stat.S_ISDIR(source_before.st_mode) or stat.S_ISLNK(source_before.st_mode) or identity(os.fstat(root_descriptor)) != identity(source_before):
            raise RuntimeError("source worktree root is invalid")
        add(b".")
        add(stat.S_IMODE(source_before.st_mode).to_bytes(4, "big"))
        add(b"directory")
        visit(root_descriptor, b"")
        root_after = os.fstat(root_descriptor)
    finally:
        os.close(root_descriptor)
    try:
        source_after = source.lstat()
    except OSError as error:
        raise RuntimeError("source worktree changed while captured") from error
    if identity(root_after) != identity(source_before) or identity(source_after) != identity(source_before):
        raise RuntimeError("source worktree changed while captured")
    return digest.hexdigest(), entries, total_bytes


@dataclass(frozen=True)
class SourceState:
    revision: str
    tree_identity: str
    index_tree_identity: str
    tracked_index_sha256: str
    status_sha256: str
    worktree_sha256: str
    worktree_entries: int
    worktree_bytes: int
    clean: bool

    def identity(self) -> str:
        return hashlib.sha256(canonical_json({
            "revision": self.revision,
            "tree_identity": self.tree_identity,
            "index_tree_identity": self.index_tree_identity,
            "tracked_index_sha256": self.tracked_index_sha256,
            "status_sha256": self.status_sha256,
            "worktree_sha256": self.worktree_sha256,
            "worktree_entries": self.worktree_entries,
            "worktree_bytes": self.worktree_bytes,
            "clean": self.clean,
        })).hexdigest()


def git_output(source: Path, *arguments: str) -> bytes:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/nonexistent"),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
    }
    result = run(["git", *arguments], env, source, timeout=15)
    return result.stdout


def capture_source_state(source: Path) -> SourceState:
    revision = git_output(source, "rev-parse", "HEAD").decode("ascii").strip()
    tree = git_output(source, "rev-parse", "HEAD^{tree}").decode("ascii").strip()
    index_tree = git_output(source, "write-tree").decode("ascii").strip()
    tracked_index = git_output(source, "ls-files", "--stage", "-z")
    status = git_output(source, "status", "--porcelain=v2", "-z", "--untracked-files=all")
    worktree_sha256, worktree_entries, worktree_bytes = capture_worktree(source)
    return SourceState(revision, tree, index_tree, hashlib.sha256(tracked_index).hexdigest(), hashlib.sha256(status).hexdigest(), worktree_sha256, worktree_entries, worktree_bytes, len(status) == 0)


def verify_source_state(source: Path, expected: SourceState) -> SourceState:
    observed = capture_source_state(source)
    if observed != expected or not observed.clean:
        raise RuntimeError("source state changed during system verification")
    return observed


def read_candidate_manifest(candidate: Path, source_revision: str) -> dict[str, str]:
    archive_digest = sha256(candidate)
    try:
        with zipfile.ZipFile(candidate) as archive:
            if archive.namelist().count("manifest.json") != 1:
                raise RuntimeError("candidate manifest is unavailable")
            information = archive.getinfo("manifest.json")
            if information.is_dir() or information.file_size > MAX_MANIFEST_BYTES:
                raise RuntimeError("candidate manifest exceeds byte limit")
            manifest = archive.read(information)
    except (OSError, KeyError, zipfile.BadZipFile) as error:
        raise RuntimeError("candidate manifest is unavailable") from error
    if len(manifest) > MAX_MANIFEST_BYTES:
        raise RuntimeError("candidate manifest exceeds byte limit")
    try:
        document = json.loads(manifest)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("candidate manifest is invalid") from error
    revision = document.get("revision") if isinstance(document, dict) else None
    if not isinstance(revision, str):
        raise RuntimeError("candidate manifest revision is invalid")
    if revision != source_revision:
        raise RuntimeError("candidate manifest revision does not match source HEAD")
    return {"revision": revision, "manifest_sha256": hashlib.sha256(manifest).hexdigest(), "archive_sha256": archive_digest}


def validate_browser_script(source: Path, browser_script: Path | None, skip_browser: bool) -> Path | None:
    if skip_browser:
        if browser_script is not None:
            raise RuntimeError("browser script must be absent in nonvisual mode")
        return None
    canonical = source / "web/scripts/daemon-visual-check.mjs"
    if browser_script is None:
        raise RuntimeError("canonical browser script is required")
    try:
        canonical_resolved = canonical.resolve(strict=True)
        supplied_resolved = browser_script.resolve(strict=True)
        information = canonical.lstat()
    except OSError as error:
        raise RuntimeError("canonical browser script is unavailable") from error
    if supplied_resolved != canonical_resolved or not stat.S_ISREG(information.st_mode) or stat.S_ISLNK(information.st_mode):
        raise RuntimeError("canonical browser script is required")
    return canonical_resolved


def validate_browser_phase_record(record: dict, expected: dict, artifacts_root: Path | None) -> None:
    phase = record.get("phase")
    if phase not in {"before_restart", "after_restart"}:
        raise RuntimeError("browser evidence phase is invalid")
    if record.get("contract") != "open-trestle/daemon-console-visual-receipt" or record.get("schema_version") != 2:
        raise RuntimeError("browser evidence contract is invalid")
    for key, value in expected.items():
        if record.get(key) != value:
            raise RuntimeError(f"browser evidence {key} mismatch")
    digest = re.compile(r"^[0-9a-f]{64}$")
    for key in ("run_identity", "diagnostic_set_identity", "deterministic_check_identity"):
        if not isinstance(record.get(key), str) or not digest.fullmatch(record[key]) or record[key] == "0" * 64:
            raise RuntimeError("browser evidence identity is invalid")
    observations = record.get("observation_identities")
    if not isinstance(observations, list) or len(observations) != record.get("observation_count") or len(set(observations)) != len(observations) or any(not isinstance(value, str) or not digest.fullmatch(value) or value == "0" * 64 for value in observations):
        raise RuntimeError("browser evidence observations are invalid")
    exact_metrics = {
        "console_errors": 0,
        "unexpected_egress": 0,
        "horizontal_overflow": False,
        "keyboard_focus_visible": True,
        "evidence_disclosure_focus_visible": True,
        "reduced_motion": True,
        "tap_targets_minimum": 44,
    }
    if any(record.get(key) != value for key, value in exact_metrics.items()):
        raise RuntimeError("browser evidence metrics are invalid")
    focus_steps = record.get("focus_order_steps")
    if isinstance(focus_steps, bool) or not isinstance(focus_steps, int) or focus_steps < 1 or focus_steps > 32:
        raise RuntimeError("browser evidence focus order is invalid")
    prefix = phase.replace("_", "-")
    expected_captures = {
        f"{prefix}-desktop-overview.png": ("overview", 1440, 1000),
        f"{prefix}-desktop-findings.png": ("review", 1440, 1000),
        f"{prefix}-desktop-runtime.png": ("runtime", 1440, 1000),
        f"{prefix}-tablet-findings.png": ("review", 900, 1000),
        f"{prefix}-mobile-390-findings.png": ("review", 390, 844),
    }
    captures = record.get("captures")
    if not isinstance(captures, list) or len(captures) != len(expected_captures):
        raise RuntimeError("browser evidence captures are invalid")
    observed_names: set[str] = set()
    for capture in captures:
        if not isinstance(capture, dict) or set(capture) != {"name", "view", "width", "height", "bytes", "sha256"}:
            raise RuntimeError("browser evidence capture is invalid")
        name = capture.get("name")
        if name not in expected_captures or name in observed_names:
            raise RuntimeError("browser evidence capture name is invalid")
        observed_names.add(name)
        view, width, height = expected_captures[name]
        if capture.get("view") != view or capture.get("width") != width or capture.get("height") != height or isinstance(capture.get("bytes"), bool) or not isinstance(capture.get("bytes"), int) or capture["bytes"] <= 0 or not isinstance(capture.get("sha256"), str) or not digest.fullmatch(capture["sha256"]) or capture["sha256"] == "0" * 64:
            raise RuntimeError("browser evidence capture metadata is invalid")
    if observed_names != set(expected_captures):
        raise RuntimeError("browser evidence capture inventory is invalid")
    receipt_name = record.get("receipt")
    receipt_sha256 = record.get("receipt_sha256")
    if not isinstance(receipt_name, str) or not isinstance(receipt_sha256, str) or not digest.fullmatch(receipt_sha256):
        raise RuntimeError("browser evidence receipt binding is invalid")
    if artifacts_root is None:
        return
    receipt_path = artifacts_root / receipt_name
    try:
        receipt_relative = receipt_path.resolve().relative_to(artifacts_root.resolve())
        receipt_status = receipt_path.lstat()
    except (OSError, ValueError) as error:
        raise RuntimeError("browser evidence receipt is unavailable") from error
    if not stat.S_ISREG(receipt_status.st_mode) or stat.S_ISLNK(receipt_status.st_mode) or sha256(receipt_path) != receipt_sha256:
        raise RuntimeError("browser evidence receipt digest mismatch")
    raw_record = json.loads(read_bounded(receipt_path, MAX_HTTP_BODY_BYTES))
    augmented = {key: value for key, value in record.items() if key not in {"receipt", "receipt_sha256"}}
    if raw_record != augmented or receipt_relative.parent.name != phase.replace("_", "-"):
        raise RuntimeError("browser evidence receipt content mismatch")
    for capture in captures:
        capture_path = receipt_path.parent / capture["name"]
        try:
            information = capture_path.lstat()
        except OSError as error:
            raise RuntimeError("browser evidence screenshot is unavailable") from error
        if not stat.S_ISREG(information.st_mode) or stat.S_ISLNK(information.st_mode) or information.st_size != capture["bytes"] or sha256(capture_path) != capture["sha256"]:
            raise RuntimeError("browser evidence screenshot digest mismatch")


def validate_browser_phase_evidence(before: dict | None, after: dict | None, expected: dict, artifacts_root: Path | None = None) -> dict:
    if before is None or after is None or before.get("phase") != "before_restart" or after.get("phase") != "after_restart":
        raise RuntimeError("browser evidence requires before and after restart phases")
    validate_browser_phase_record(before, expected, artifacts_root)
    validate_browser_phase_record(after, expected, artifacts_root)
    return {"status": "passed", "phases": [before, after]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, default=Path.cwd())
    parser.add_argument("--browser-script", type=Path)
    parser.add_argument("--skip-browser", action="store_true")
    args = parser.parse_args()
    candidate = args.candidate.resolve()
    output = args.output.resolve()
    source = args.source_root.resolve()
    supplied_browser_script = args.browser_script.resolve() if args.browser_script else None
    try:
        browser_script = validate_browser_script(source, supplied_browser_script, args.skip_browser)
    except RuntimeError as error:
        raise SystemExit(str(error)) from error
    sidecar = Path(str(candidate) + ".sha256")
    if not candidate.is_file() or not sidecar.is_file() or output.exists():
        raise SystemExit("candidate/checksum must be valid and output must not exist")
    sidecar_fields = read_bounded(sidecar, 4096).decode("ascii").strip().split()
    candidate_digest = sha256(candidate)
    if len(sidecar_fields) < 1 or sidecar_fields[0] != candidate_digest:
        raise SystemExit("candidate checksum does not match detached sidecar")
    source_before = capture_source_state(source)
    if not source_before.clean:
        raise SystemExit("source tree must be clean before system verification")

    output.mkdir(mode=0o700, parents=True)
    home = output / "home"
    runtime = output / "runtime"
    setup_dir = output / "setup"
    repository = output / "repository"
    artifacts = output / "artifacts"
    sandbox = output / "sandbox"
    private_tmp = output / "tmp"
    cache = output / "cache"
    for directory in (home, runtime, setup_dir, repository, artifacts, sandbox, private_tmp, cache):
        directory.mkdir(mode=0o700)
    execution_candidate = copy_candidate_archive(candidate, sidecar, sandbox, candidate_digest)
    private_tmp_alias = create_private_tmp_alias(private_tmp)
    atexit.register(remove_private_tmp_alias, private_tmp_alias, private_tmp)
    private_tmp_alias_removed = False
    token = secrets.token_hex(32)
    env = {
        "HOME": str(home),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "TMPDIR": str(private_tmp_alias),
        "XDG_CACHE_HOME": str(cache),
        "OPEN_TRESTLE_API_TOKEN": token,
        "HTTP_PROXY": "http://127.0.0.1:9",
        "HTTPS_PROXY": "http://127.0.0.1:9",
        "ALL_PROXY": "http://127.0.0.1:9",
        "NO_PROXY": "127.0.0.1,::1",
        "GOTELEMETRY": "off",
    }
    if os.environ.get("OPEN_TRESTLE_CHROMIUM_PATH"):
        env["OPEN_TRESTLE_CHROMIUM_PATH"] = os.environ["OPEN_TRESTLE_CHROMIUM_PATH"]
    commands: list[list[str]] = []

    def execute(command: list[str], cwd: Path | None = None, accepted: tuple[int, ...] = (0,), timeout: float = 120) -> subprocess.CompletedProcess[bytes]:
        commands.append(command)
        return run(command, env, cwd or sandbox, accepted, timeout)

    def execute_candidate(arguments: list[str], timeout: float = 120) -> subprocess.CompletedProcess[bytes]:
        assert_candidate_digest(execution_candidate, candidate_digest)
        result = execute([str(execution_candidate), *arguments], timeout=timeout)
        assert_candidate_digest(execution_candidate, candidate_digest)
        return result

    candidate_root = output / "candidate-root"
    candidate_root.mkdir(mode=0o700)
    for sentinel in (candidate_root / "etc/open-trestle/operator.conf", candidate_root / "var/lib/open-trestle/operator.state"):
        sentinel.parent.mkdir(mode=0o700, parents=True)
        write(sentinel, b"operator-owned\n")

    verify_archive = execute_candidate(["verify-archive"])
    write(artifacts / "candidate-verify-archive.txt", verify_archive.stdout)
    candidate_manifest = read_candidate_manifest(execution_candidate, source_before.revision)
    if candidate_manifest["archive_sha256"] != candidate_digest:
        raise RuntimeError("candidate archive changed after manifest verification")
    lifecycle = candidate_root / "usr/local/libexec/open-trestle/open-trestle-distribution.pyz"
    trestle = candidate_root / "usr/local/bin/trestle"
    trestled = candidate_root / "usr/local/bin/trestled"
    install_attempted = False
    daemon_holder: list[subprocess.Popen[bytes] | None] = [None]
    port = 0
    port_before_restart = False
    port_after_cleanup = False
    process_groups_quiescent = False
    browser_before: dict | None = None
    browser_after: dict | None = None
    try:
        install_attempted = True
        install_result = execute_candidate(["install", "--destdir", str(candidate_root)])
        write(artifacts / "candidate-install.txt", install_result.stdout)
        verified = execute([str(lifecycle), "verify-installed", "--destdir", str(candidate_root)])
        write(artifacts / "candidate-verify-installed.txt", verified.stdout)
        execute([str(lifecycle), "smoke", "--destdir", str(candidate_root), "--output", str(artifacts / "candidate-smoke.json")])
        if not trestle.is_file() or not trestled.is_file():
            raise RuntimeError("candidate did not install product binaries")
        execute(["git", "init", "--object-format=sha1", str(repository)])
        execute(["git", "config", "user.name", "Open Trestle evaluator"], repository)
        execute(["git", "config", "user.email", "evaluator@example.invalid"], repository)
        (repository / "main.go").write_text("package main\n\nfunc main() {}\n")
        execute(["git", "add", "main.go"], repository)
        execute(["git", "commit", "-m", "base"], repository)
        base = execute(["git", "rev-parse", "HEAD"], repository).stdout.decode().strip()
        (repository / "main.go").write_text('package main\n\nimport "fmt"\n\nfunc main() { fmt.Println("debug") }\n')
        execute(["git", "add", "main.go"], repository)
        execute(["git", "commit", "-m", "head"], repository)
        head = execute(["git", "rev-parse", "HEAD"], repository).stdout.decode().strip()
        objects = (repository / ".git/objects").resolve()
        setup_path = setup_dir / "plan.json"
        setup = execute([str(trestle), "setup", "init", "--profile", "local_single_node", "--tenant", "tenant-a", "--repository", "repository-a", "--recovery-owner", "platform-owner", "--state", str(setup_path)])
        write(artifacts / "setup-init.json", setup.stdout)
        setup_root = json.loads(setup.stdout)["plan_identity"]
        inspect = execute([str(trestle), "setup", "inspect", "--state", str(setup_path), "--expected-root-identity", setup_root])
        write(artifacts / "setup-plan.json", inspect.stdout)
        inspected_setup = json.loads(inspect.stdout)
        if inspected_setup["ready"] is not False or inspected_setup["status"] != "incomplete":
            raise RuntimeError("deterministic alpha must not imply setup readiness")
        port = free_port()
        prove_port_reusable(port)
        url = f"http://127.0.0.1:{port}"
        daemon_args = ["--listen", f"127.0.0.1:{port}", "--state-dir", str(runtime), "--tenant", "tenant-a", "--repository", "repository-a", "--setup-state", str(setup_path), "--expected-setup-root-identity", setup_root, "--local-git-objects-root", str(objects), "--local-git-repository-authority", "local.test", "--local-git-repository-namespace", "team", "--local-git-repository-name", "repository"]
        daemon: subprocess.Popen[bytes] | None = None

        def run_browser_phase(phase: str, expected: dict) -> dict:
            assert browser_script is not None
            root = artifacts / "daemon-console"
            root.mkdir(mode=0o700, exist_ok=True)
            phase_output = root / phase.replace("_", "-")
            visual_env = {**env, "OPEN_TRESTLE_DAEMON_URL": url, "OPEN_TRESTLE_DAEMON_VISUAL_OUTPUT": str(phase_output), "OPEN_TRESTLE_TENANT": "tenant-a", "OPEN_TRESTLE_REPOSITORY": "repository-a", "OPEN_TRESTLE_RUN": run_id, "OPEN_TRESTLE_BROWSER_PHASE": phase}
            commands.append(["node", str(browser_script), phase])
            visual = run(["node", str(browser_script)], visual_env, sandbox, timeout=120)
            if visual.stdout:
                write(artifacts / f"daemon-console-{phase}.stdout", visual.stdout)
            if visual.stderr:
                write(artifacts / f"daemon-console-{phase}.stderr", visual.stderr)
            receipt_path = phase_output / "receipt.json"
            manifest = json.loads(read_bounded(receipt_path, MAX_HTTP_BODY_BYTES))
            for key, value in expected.items():
                if manifest.get(key) != value:
                    raise RuntimeError(f"browser evidence {key} mismatch")
            return {**manifest, "receipt": str(receipt_path.relative_to(artifacts)), "receipt_sha256": sha256(receipt_path)}

        try:
            daemon = start_daemon(trestled, daemon_args, env, artifacts / "trestled-first.log", url, sandbox)
            daemon_holder[0] = daemon
            submit_args = [str(trestle), "local-git", "review", "--objects-root", str(objects), "--repository-authority", "local.test", "--repository-namespace", "team", "--repository-name", "repository", "--revision-algorithm", "sha1", "--base-revision-digest", base, "--head-revision-digest", head, "--tenant", "tenant-a", "--repository", "repository-a", "--run", "local-alpha", "--server", url]
            submitted = execute(submit_args)
            write(artifacts / "submission.json", submitted.stdout)
            run_id = json.loads(submitted.stdout)["review_run_id"]
            status_args = [str(trestle), "runs", "status", "--tenant", "tenant-a", "--repository", "repository-a", "--run", run_id, "--server", url]
            deadline = time.monotonic() + 20
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("review did not become terminal")
                status = execute(status_args, timeout=min(5, remaining))
                status_value = json.loads(status.stdout)
                if status_value["status"] != "active":
                    break
                time.sleep(min(1, max(0, deadline - time.monotonic())))
            if status_value["status"] != "succeeded" or len(status_value["tasks"]) != 4:
                raise RuntimeError("review did not succeed through four durable tasks")
            write(artifacts / "status-before-restart.json", status.stdout)
            diagnostics_body = request(url + f"/api/v1/tenants/tenant-a/repositories/repository-a/runs/{run_id}/diagnostics", token)
            write(artifacts / "diagnostics-before-restart.json", diagnostics_body)
            diagnostics_value = json.loads(diagnostics_body)["diagnostics"]
            console = request(url + "/console/")
            write(artifacts / "console.html", console)
            tui = execute([str(trestle), "tui", "--server", url, "--tenant", "tenant-a", "--repository", "repository-a", "--run", run_id, "--plain", "--once"])
            write(artifacts / "tui-before-restart.txt", tui.stdout)
            json_first = execute([*status_args, "--format", "json"])
            sarif_first = execute([*status_args, "--format", "sarif"])
            write(artifacts / "result-before-restart.json", json_first.stdout)
            write(artifacts / "result-before-restart.sarif.json", sarif_first.stdout)
            if json.loads(json_first.stdout)["schema_version"] != 6 or len(json.loads(sarif_first.stdout)["runs"][0]["results"]) != 1:
                raise RuntimeError("deterministic exports are incomplete")
            expected_browser = {
                "scope": {"tenant": "tenant-a", "repository": "repository-a", "run": run_id},
                "run_identity": status_value["identity"],
                "diagnostic_set_identity": diagnostics_value["identity"],
                "deterministic_check_identity": diagnostics_value["checks"][0]["identity"],
                "deterministic_check_state": diagnostics_value["checks"][0]["state"],
                "observation_count": len(diagnostics_value["observations"]),
                "observation_identities": [value["identity"] for value in diagnostics_value["observations"]],
            }
            if not args.skip_browser:
                browser_before = run_browser_phase("before_restart", {**expected_browser, "phase": "before_restart"})
            stop_daemon(daemon)
            daemon = None
            daemon_holder[0] = None
            prove_port_reusable(port)
            port_before_restart = True
            daemon = start_daemon(trestled, daemon_args, env, artifacts / "trestled-restart.log", url, sandbox)
            daemon_holder[0] = daemon
            status_after = execute(status_args)
            diagnostics_after = request(url + f"/api/v1/tenants/tenant-a/repositories/repository-a/runs/{run_id}/diagnostics", token)
            json_after = execute([*status_args, "--format", "json"])
            sarif_after = execute([*status_args, "--format", "sarif"])
            write(artifacts / "status-after-restart.json", status_after.stdout)
            write(artifacts / "diagnostics-after-restart.json", diagnostics_after)
            write(artifacts / "result-after-restart.json", json_after.stdout)
            write(artifacts / "result-after-restart.sarif.json", sarif_after.stdout)
            write(artifacts / "tui-after-restart.txt", execute([str(trestle), "tui", "--server", url, "--tenant", "tenant-a", "--repository", "repository-a", "--run", run_id, "--plain", "--once"]).stdout)
            if not args.skip_browser:
                browser_after = run_browser_phase("after_restart", {**expected_browser, "phase": "after_restart"})
            if json.loads(status_after.stdout)["identity"] != status_value["identity"] or json.loads(diagnostics_after)["diagnostics"] != diagnostics_value or json_after.stdout != json_first.stdout or sarif_after.stdout != sarif_first.stdout:
                raise RuntimeError("restart or deterministic readback mismatch")
        finally:
            daemon_errors: list[str] = []
            try:
                stop_daemon(daemon)
            except Exception as error:
                daemon_errors.append(str(error))
            daemon_holder[0] = None
            if port:
                try:
                    prove_port_reusable(port)
                    port_after_cleanup = True
                except OSError as error:
                    daemon_errors.append(f"daemon port is not reusable: {error}")
            process_groups_quiescent = not daemon_errors
            if daemon_errors:
                raise RuntimeError("daemon cleanup failed: " + "; ".join(daemon_errors))
        binary_records = [{"name": "trestle", "path": str(trestle), "sha256": sha256(trestle)}, {"name": "trestled", "path": str(trestled), "sha256": sha256(trestled)}]
    finally:
        cleanup_errors: list[str] = []
        try:
            stop_daemon(daemon_holder[0])
        except Exception as error:
            cleanup_errors.append(f"daemon: {error}")
        daemon_holder[0] = None
        if install_attempted:
            try:
                recovered = execute_candidate(["recover", "--destdir", str(candidate_root)])
                if recovered.stdout:
                    write(artifacts / "candidate-recover.txt", recovered.stdout)
            except Exception as error:
                cleanup_errors.append(f"candidate recovery: {error}")
            if lifecycle.is_file():
                try:
                    uninstalled = execute([str(lifecycle), "uninstall", "--destdir", str(candidate_root)])
                    write(artifacts / "candidate-uninstall.txt", uninstalled.stdout)
                except Exception as error:
                    cleanup_errors.append(f"candidate uninstall: {error}")
            sentinels = (candidate_root / "etc/open-trestle/operator.conf", candidate_root / "var/lib/open-trestle/operator.state")

            def exact_sentinel(path: Path) -> bool:
                try:
                    information = path.lstat()
                except OSError:
                    return False
                return stat.S_ISREG(information.st_mode) and stat.S_IMODE(information.st_mode) == 0o600 and path.read_bytes() == b"operator-owned\n"

            if trestle.exists() or trestled.exists() or not all(exact_sentinel(path) for path in sentinels):
                cleanup_errors.append("candidate cleanup did not preserve exact operator state or remove binaries")
        try:
            remove_private_tmp_alias(private_tmp_alias, private_tmp)
            atexit.unregister(remove_private_tmp_alias)
            private_tmp_alias_removed = True
        except Exception as error:
            cleanup_errors.append(f"temporary alias: {error}")
        if cleanup_errors:
            raise RuntimeError("local alpha cleanup failed: " + "; ".join(cleanup_errors))
    assert_candidate_digest(execution_candidate, candidate_digest)
    source_after = verify_source_state(source, source_before)
    artifact_records = []
    for path in sorted(artifacts.rglob("*")):
        if path.is_file():
            artifact_records.append({"name": str(path.relative_to(artifacts)), "sha256": sha256(path), "bytes": path.stat().st_size})
    if args.skip_browser:
        browser_record = {"status": "not_run", "reason": "explicit_nonvisual_verification"}
    else:
        browser_record = validate_browser_phase_evidence(browser_before, browser_after, {
            "scope": {"tenant": "tenant-a", "repository": "repository-a", "run": run_id},
            "run_identity": status_value["identity"],
            "diagnostic_set_identity": diagnostics_value["identity"],
            "deterministic_check_identity": diagnostics_value["checks"][0]["identity"],
            "deterministic_check_state": diagnostics_value["checks"][0]["state"],
            "observation_count": len(diagnostics_value["observations"]),
            "observation_identities": [value["identity"] for value in diagnostics_value["observations"]],
        }, artifacts)
    receipt = {
        "contract": "open-trestle/local-alpha-system-receipt",
        "schema_version": 2,
        "source_revision": source_after.revision,
        "source_tree_identity": source_after.tree_identity,
        "source_state_identity": source_after.identity(),
        "source_worktree_identity": source_after.worktree_sha256,
        "source_worktree_entries": source_after.worktree_entries,
        "source_worktree_bytes": source_after.worktree_bytes,
        "source_tree_clean": source_after.clean,
        "candidate": {"path": str(candidate), "execution_path": str(execution_candidate), "sha256": candidate_digest, "sidecar_sha256": sha256(sidecar), "manifest_revision": candidate_manifest["revision"], "manifest_sha256": candidate_manifest["manifest_sha256"], "archive_sha256": candidate_manifest["archive_sha256"], "lifecycle": "verified_install_smoke_recover_uninstall", "operator_state_preserved": True},
        "binaries": binary_records,
        "repository": {"base_revision": base, "head_revision": head},
        "review": {"tenant_id": "tenant-a", "repository_id": "repository-a", "review_run_id": run_id, "run_receipt_identity": status_value["identity"], "diagnostic_set_identity": diagnostics_value["identity"]},
        "commands": commands,
        "artifacts": artifact_records,
        "restart": {"status_identity_stable": True, "diagnostics_set_stable": True, "json_bytes_stable": True, "sarif_bytes_stable": True},
        "browser": browser_record,
        "setup": {"profile": "local_single_node", "plan_identity": setup_root, "ready": False, "authority": "scope_and_denied_effect_posture_only"},
        "network": {"configured_url": url, "readyz_observed": True, "http_proxies": "non_loopback_http_proxies_point_to_closed_loopback", "browser_request_guard": "not_run" if args.skip_browser else "abort_non_loopback"},
        "cleanup": {"daemon_stopped": True, "process_group_quiescent": process_groups_quiescent, "port_rebind_before_restart": port_before_restart, "port_rebind_after_cleanup": port_after_cleanup, "private_temporary_alias_removed": private_tmp_alias_removed, "candidate_recovered": True, "candidate_uninstalled": True, "operator_state_preserved": True},
    }
    if not all((process_groups_quiescent, port_before_restart, port_after_cleanup, private_tmp_alias_removed)):
        raise RuntimeError("daemon cleanup evidence is incomplete")
    write(output / "receipt.json", canonical_json(receipt) + b"\n")
    print(output / "receipt.json")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"local alpha system verification failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
