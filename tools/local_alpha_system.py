#!/usr/bin/env python3
"""Run the bounded local single-node evaluation journey with real product binaries."""
from __future__ import annotations

import argparse
import atexit
import dataclasses
import datetime
import hashlib
import http.client
import io
import json
import os
import re
import secrets
import selectors
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import zlib
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

MAX_COMMAND_OUTPUT_BYTES = 1 << 20
MAX_HTTP_BODY_BYTES = 1 << 20
MAX_DAEMON_LOG_BYTES = 1 << 20
MAX_MANIFEST_BYTES = 1 << 20
MAX_FAILURE_LOG_BYTES = 64 << 10
MAX_SOURCE_ENTRIES = 100_000
MAX_SOURCE_BYTES = 8 << 30
MAX_SOURCE_GIT_OUTPUT_BYTES = 32 << 20
MAX_CANDIDATE_BYTES = 256 << 20
MAX_SCREENSHOT_BYTES = 16 << 20
MAX_BROWSER_MODULE_BYTES = 1 << 20
GIT_EXECUTABLE = "/usr/bin/git"
BROWSER_DEPENDENCY_PREFIX = b"web/node_modules/playwright-core/"
BROWSER_DEPENDENCY_VERSION = "1.62.1"
BROWSER_DEPENDENCY_SHA256 = "90abfaf282ebeb89837d8c86e74e372f77d2ee0d93a8eba9d183fef237cdee37"
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


def _source_identity(information: os.stat_result) -> tuple[int, int, int, int, int]:
    return (information.st_dev, information.st_ino, information.st_mode, information.st_size, information.st_mtime_ns)


def _valid_git_path(path: bytes) -> bool:
    return bool(path) and not path.startswith(b"/") and all(part not in (b"", b".", b"..") for part in path.split(b"/"))


def _parse_head_entries(raw: bytes) -> list[tuple[bytes, str, str]]:
    entries: list[tuple[bytes, str, str]] = []
    seen: set[bytes] = set()
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            metadata, path = record.split(b"\t", 1)
            mode_raw, kind_raw, oid_raw = metadata.split(b" ", 2)
            mode, kind, oid = mode_raw.decode("ascii"), kind_raw.decode("ascii"), oid_raw.decode("ascii")
        except (ValueError, UnicodeDecodeError) as error:
            raise RuntimeError("source provenance HEAD tree is malformed") from error
        if not _valid_git_path(path) or path in seen or kind != "blob" or mode not in {"100644", "100755", "120000"} or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", oid):
            raise RuntimeError("source provenance HEAD tree contains an unsupported entry")
        seen.add(path); entries.append((path, mode, oid))
        if len(entries) > MAX_SOURCE_ENTRIES:
            raise RuntimeError("source provenance entry limit exceeded")
    if entries != sorted(entries, key=lambda item: item[0]):
        raise RuntimeError("source provenance HEAD tree is not canonical")
    return entries


def _parse_index_entries(raw: bytes) -> list[tuple[bytes, str, str]]:
    entries: list[tuple[bytes, str, str]] = []
    seen: set[bytes] = set()
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            metadata, path = record.split(b"\t", 1)
            mode_raw, oid_raw, stage_raw = metadata.split(b" ", 2)
            mode, oid, stage = mode_raw.decode("ascii"), oid_raw.decode("ascii"), int(stage_raw)
        except (ValueError, UnicodeDecodeError) as error:
            raise RuntimeError("source provenance index is malformed") from error
        if not _valid_git_path(path) or path in seen or stage != 0 or mode not in {"100644", "100755", "120000"} or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", oid):
            raise RuntimeError("source provenance index contains unresolved or unsupported entries")
        seen.add(path); entries.append((path, mode, oid))
        if len(entries) > MAX_SOURCE_ENTRIES:
            raise RuntimeError("source provenance entry limit exceeded")
    return entries


def _framed_sha256(records: list[bytes]) -> str:
    digest = hashlib.sha256()
    for record in records:
        digest.update(len(record).to_bytes(8, "big")); digest.update(record)
    return digest.hexdigest()


def _records_sha256(entries: list[tuple[bytes, str, str]]) -> str:
    return _framed_sha256([path + b"\0" + mode.encode() + b"\0" + oid.encode() for path, mode, oid in entries])


def _parse_flag_listing(raw: bytes, label: str, rejected: Callable[[bytes], bool]) -> list[bytes]:
    records: list[bytes] = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        if len(record) < 3 or record[1:2] != b" " or not _valid_git_path(record[2:]):
            raise RuntimeError(f"source provenance {label} flags are malformed")
        if rejected(record[:1]):
            raise RuntimeError(f"source provenance rejects {label} index flags")
        records.append(record)
    return records


def _open_source_parent(root_descriptor: int, path: bytes) -> tuple[list[int], list[tuple[bytes, os.stat_result]]]:
    descriptors = [os.dup(root_descriptor)]
    chain: list[tuple[bytes, os.stat_result]] = []
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        for component in path.split(b"/")[:-1]:
            before = os.stat(component, dir_fd=descriptors[-1], follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
                raise RuntimeError("tracked source does not match HEAD")
            child = os.open(component, flags, dir_fd=descriptors[-1])
            if _source_identity(os.fstat(child)) != _source_identity(before):
                os.close(child); raise RuntimeError("source provenance changed while captured")
            descriptors.append(child); chain.append((component, before))
        return descriptors, chain
    except Exception:
        for descriptor in reversed(descriptors): os.close(descriptor)
        raise


def _close_source_parent(descriptors: list[int], chain: list[tuple[bytes, os.stat_result]]) -> None:
    try:
        for index in range(len(chain) - 1, -1, -1):
            component, before = chain[index]
            after = os.stat(component, dir_fd=descriptors[index], follow_symlinks=False)
            if _source_identity(after) != _source_identity(before) or _source_identity(os.fstat(descriptors[index + 1])) != _source_identity(before):
                raise RuntimeError("source provenance changed while captured")
    finally:
        for descriptor in reversed(descriptors): os.close(descriptor)


def _capture_ignored_directory(directory_descriptor: int, budget: dict[str, int]) -> tuple[str, int]:
    records: list[bytes] = []
    subtree_bytes = 0
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)

    def visit(descriptor: int, relative: bytes) -> None:
        nonlocal subtree_bytes
        directory_before = os.fstat(descriptor)
        with os.scandir(descriptor) as scanned:
            children = sorted(scanned, key=lambda item: os.fsencode(item.name))
        for child in children:
            name = os.fsencode(child.name); path = name if not relative else relative + b"/" + name
            before = child.stat(follow_symlinks=False); mode = stat.S_IMODE(before.st_mode)
            budget["entries"] += 1
            if budget["entries"] > MAX_SOURCE_ENTRIES:
                raise RuntimeError("source provenance entry limit exceeded")
            if stat.S_ISDIR(before.st_mode):
                child_descriptor = os.open(child.name, directory_flags, dir_fd=descriptor)
                try:
                    if _source_identity(os.fstat(child_descriptor)) != _source_identity(before):
                        raise RuntimeError("source provenance changed while captured")
                    records.append(path + b"\0directory\0" + str(mode).encode())
                    visit(child_descriptor, path)
                    opened_after = os.fstat(child_descriptor)
                finally:
                    os.close(child_descriptor)
                path_after = os.stat(child.name, dir_fd=descriptor, follow_symlinks=False)
                if _source_identity(opened_after) != _source_identity(before) or _source_identity(path_after) != _source_identity(before):
                    raise RuntimeError("source provenance changed while captured")
                continue
            if stat.S_ISLNK(before.st_mode):
                target = os.fsencode(os.readlink(child.name, dir_fd=descriptor))
                path_after = os.stat(child.name, dir_fd=descriptor, follow_symlinks=False)
                if _source_identity(path_after) != _source_identity(before):
                    raise RuntimeError("source provenance changed while captured")
                records.append(path + b"\0symlink\0" + str(mode).encode() + b"\0" + hashlib.sha256(target).hexdigest().encode())
                continue
            if not stat.S_ISREG(before.st_mode):
                raise RuntimeError("source provenance ignored directory contains unsupported entry")
            opened = os.open(child.name, file_flags, dir_fd=descriptor); content = hashlib.sha256(); size = 0
            try:
                if _source_identity(os.fstat(opened)) != _source_identity(before):
                    raise RuntimeError("source provenance changed while captured")
                while True:
                    chunk = os.read(opened, 1 << 20)
                    if not chunk: break
                    size += len(chunk); subtree_bytes += len(chunk); budget["bytes"] += len(chunk)
                    if budget["bytes"] > MAX_SOURCE_BYTES:
                        raise RuntimeError("source provenance byte limit exceeded")
                    content.update(chunk)
                opened_after = os.fstat(opened)
            finally:
                os.close(opened)
            path_after = os.stat(child.name, dir_fd=descriptor, follow_symlinks=False)
            if size != before.st_size or _source_identity(opened_after) != _source_identity(before) or _source_identity(path_after) != _source_identity(before):
                raise RuntimeError("source provenance changed while captured")
            records.append(path + b"\0regular\0" + str(mode).encode() + b"\0" + str(size).encode() + b"\0" + content.hexdigest().encode())
        if _source_identity(os.fstat(descriptor)) != _source_identity(directory_before):
            raise RuntimeError("source provenance changed while captured")

    visit(directory_descriptor, b"")
    return _framed_sha256(records), subtree_bytes


def _read_source_entry(root_descriptor: int, path: bytes, object_format: str, expected_mode: str | None, expected_oid: str | None, budget: dict[str, int]) -> tuple[str, int, str, int]:
    descriptors, chain = _open_source_parent(root_descriptor, path)
    name = path.split(b"/")[-1]
    try:
        before = os.stat(name, dir_fd=descriptors[-1], follow_symlinks=False)
        mode = stat.S_IMODE(before.st_mode)
        if stat.S_ISDIR(before.st_mode):
            if expected_mode is not None:
                raise RuntimeError("tracked source does not match HEAD")
            kind = "directory"
            directory_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(name, directory_flags, dir_fd=descriptors[-1])
            try:
                if _source_identity(os.fstat(descriptor)) != _source_identity(before):
                    raise RuntimeError("source provenance changed while captured")
                content_sha256, size = _capture_ignored_directory(descriptor, budget)
                opened_after = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            after = os.stat(name, dir_fd=descriptors[-1], follow_symlinks=False)
            if _source_identity(opened_after) != _source_identity(before) or _source_identity(after) != _source_identity(before):
                raise RuntimeError("source provenance changed while captured")
            object_hash = hashlib.new(object_format); object_hash.update(content_sha256.encode())
        elif stat.S_ISLNK(before.st_mode):
            kind = "symlink"
            if expected_mode is not None and expected_mode != "120000": raise RuntimeError("tracked source does not match HEAD")
            payload = os.fsencode(os.readlink(name, dir_fd=descriptors[-1]))
            after = os.stat(name, dir_fd=descriptors[-1], follow_symlinks=False)
            if _source_identity(after) != _source_identity(before): raise RuntimeError("source provenance changed while captured")
            content_sha256 = hashlib.sha256(payload).hexdigest()
            object_hash = hashlib.new(object_format); object_hash.update(f"blob {len(payload)}\0".encode()); object_hash.update(payload)
            size = len(payload)
        elif stat.S_ISREG(before.st_mode):
            kind = "regular"
            if expected_mode is not None:
                live_mode = "100755" if before.st_mode & stat.S_IXUSR else "100644"
                if expected_mode != live_mode:
                    raise RuntimeError("tracked source does not match HEAD")
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(name, flags, dir_fd=descriptors[-1])
            content = hashlib.sha256(); object_hash = hashlib.new(object_format); object_hash.update(f"blob {before.st_size}\0".encode())
            size = 0
            try:
                if _source_identity(os.fstat(descriptor)) != _source_identity(before): raise RuntimeError("source provenance changed while captured")
                while True:
                    chunk = os.read(descriptor, 1 << 20)
                    if not chunk: break
                    size += len(chunk); budget["bytes"] += len(chunk)
                    if budget["bytes"] > MAX_SOURCE_BYTES: raise RuntimeError("source provenance byte limit exceeded")
                    content.update(chunk); object_hash.update(chunk)
                opened_after = os.fstat(descriptor)
            finally: os.close(descriptor)
            after = os.stat(name, dir_fd=descriptors[-1], follow_symlinks=False)
            if size != before.st_size or _source_identity(opened_after) != _source_identity(before) or _source_identity(after) != _source_identity(before): raise RuntimeError("source provenance changed while captured")
            content_sha256 = content.hexdigest()
        else:
            raise RuntimeError("tracked source does not match HEAD" if expected_mode is not None else "source provenance ignored entry is unsupported")
        budget["entries"] += 1
        if budget["entries"] > MAX_SOURCE_ENTRIES: raise RuntimeError("source provenance entry limit exceeded")
        oid = object_hash.hexdigest()
        if expected_oid is not None and oid != expected_oid: raise RuntimeError("tracked source does not match HEAD")
        return kind, size, content_sha256, mode
    except FileNotFoundError as error:
        raise RuntimeError("tracked source does not match HEAD" if expected_mode is not None else "source provenance ignored entry is unavailable") from error
    finally:
        _close_source_parent(descriptors, chain)


def _metadata_paths(raw: bytes, label: str) -> list[tuple[bytes, bool]]:
    entries: list[tuple[bytes, bool]] = []
    seen: set[bytes] = set()
    for raw_path in raw.split(b"\0"):
        if not raw_path:
            continue
        directory = raw_path.endswith(b"/"); path = raw_path[:-1] if directory else raw_path
        if not _valid_git_path(path) or path in seen:
            raise RuntimeError(f"source provenance {label} paths are malformed")
        seen.add(path); entries.append((path, directory))
        if len(entries) > MAX_SOURCE_ENTRIES:
            raise RuntimeError("source provenance entry limit exceeded")
    return sorted(entries, key=lambda item: item[0])


_PROHIBITED_GIT_ENV = {
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_DIR",
    "GIT_INDEX_FILE",
    "GIT_NAMESPACE",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_OBJECT_DIRECTORY",
    "GIT_REPLACE_REF_BASE",
    "GIT_WORK_TREE",
}


@dataclass(frozen=True)
class GitAuthority:
    source: Path
    git_dir: Path
    common_dir: Path
    index_path: Path
    object_dir: Path
    revision: str
    tree: str
    commit_sha256: str


def _git_environment() -> dict[str, str]:
    attempted = sorted(name for name, value in os.environ.items() if value and (name in _PROHIBITED_GIT_ENV or name.startswith("GIT_CONFIG_")))
    if attempted:
        raise RuntimeError(f"source provenance rejects Git environment authority overrides: {', '.join(attempted)}")
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_NOGLOBAL": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
    }


def _git_run(source: Path, arguments: list[str], *, authority: GitAuthority | None = None, accepted: tuple[int, ...] = (0,)) -> subprocess.CompletedProcess[bytes]:
    env = _git_environment()
    try:
        git_information = Path(GIT_EXECUTABLE).lstat()
    except OSError as error:
        raise RuntimeError("source provenance trusted Git executable is unavailable") from error
    if not stat.S_ISREG(git_information.st_mode) or stat.S_ISLNK(git_information.st_mode) or not git_information.st_mode & stat.S_IXUSR or git_information.st_uid != 0 or stat.S_IMODE(git_information.st_mode) & 0o022:
        raise RuntimeError("source provenance trusted Git executable is invalid")
    for ancestor in (Path(GIT_EXECUTABLE).parent, Path(GIT_EXECUTABLE).parent.parent, Path("/")):
        information = ancestor.lstat()
        if not stat.S_ISDIR(information.st_mode) or stat.S_ISLNK(information.st_mode) or information.st_uid != 0 or stat.S_IMODE(information.st_mode) & 0o022:
            raise RuntimeError("source provenance trusted Git executable ancestry is invalid")
    command = [GIT_EXECUTABLE, "--no-replace-objects"]
    if authority is None:
        command.extend(["-C", str(source)])
    else:
        command.extend([f"--git-dir={authority.git_dir}", f"--work-tree={authority.source}"])
    command.extend(["-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", *arguments])
    return run(command, env, source, accepted=accepted, timeout=30, maximum_output_bytes=MAX_SOURCE_GIT_OUTPUT_BYTES)


def _reject_symlinked_path_components(path: Path, label: str) -> None:
    if not path.is_absolute():
        raise RuntimeError(f"source provenance {label} must be absolute")
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        if current.is_symlink():
            raise RuntimeError(f"source provenance {label} has a symlinked path component")


def _read_git_pointer(path: Path, base: Path, label: str, prefix: str = "") -> Path:
    information = path.lstat()
    if stat.S_ISLNK(information.st_mode) or not stat.S_ISREG(information.st_mode) or information.st_size <= 0 or information.st_size > 4096:
        raise RuntimeError(f"source provenance {label} is invalid")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        if _source_identity(os.fstat(descriptor)) != _source_identity(information):
            raise RuntimeError(f"source provenance {label} changed while inspected")
        body = os.read(descriptor, 4097)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if len(body) != information.st_size or len(body) > 4096 or _source_identity(after) != _source_identity(information):
        raise RuntimeError(f"source provenance {label} changed while inspected")
    try:
        value = body.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise RuntimeError(f"source provenance {label} is malformed") from error
    if prefix:
        if not value.startswith(prefix):
            raise RuntimeError(f"source provenance {label} is malformed")
        value = value[len(prefix):].strip()
    target = Path(value)
    if not target.is_absolute():
        target = base / target
    target = Path(os.path.abspath(target))
    _reject_symlinked_path_components(target, label)
    try:
        return target.resolve(strict=True)
    except OSError as error:
        raise RuntimeError(f"source provenance {label} target is unavailable") from error


def _resolved_git_path(value: bytes, label: str, *, reject_symlink: bool = False) -> Path:
    try:
        raw = Path(value.decode("utf-8").strip())
        if reject_symlink:
            _reject_symlinked_path_components(raw, label)
        path = raw.resolve(strict=True)
    except (OSError, UnicodeDecodeError) as error:
        raise RuntimeError(f"source provenance {label} is unavailable") from error
    return path


def _optional_git_config(source: Path, git_dir: Path, scope: str, key: str) -> str:
    result = _git_run(source, [f"--git-dir={git_dir}", "config", scope, "--get", key], accepted=(0, 1))
    if result.returncode == 1:
        return ""
    try:
        return result.stdout.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise RuntimeError("source provenance Git configuration is malformed") from error


def _configured_worktree_path(value: str, git_dir: Path) -> Path:
    configured = Path(value)
    if not configured.is_absolute():
        configured = git_dir / configured
    try:
        return configured.resolve(strict=True)
    except OSError as error:
        raise RuntimeError("source provenance configured worktree is unavailable") from error


def _validate_git_storage_tree(root_path: Path, label: str) -> None:
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    entries = 0
    def visit(descriptor: int) -> None:
        nonlocal entries
        before_directory = os.fstat(descriptor)
        with os.scandir(descriptor) as scanned:
            children = sorted(scanned, key=lambda child: os.fsencode(child.name))
        for child in children:
            before = child.stat(follow_symlinks=False)
            entries += 1
            if entries > MAX_SOURCE_ENTRIES:
                raise RuntimeError(f"source provenance {label} entry limit exceeded")
            if stat.S_ISLNK(before.st_mode):
                raise RuntimeError(f"source provenance rejects symlinks in {label}")
            if stat.S_ISDIR(before.st_mode):
                opened = os.open(child.name, directory_flags, dir_fd=descriptor)
                try:
                    if _source_identity(os.fstat(opened)) != _source_identity(before):
                        raise RuntimeError(f"source provenance {label} changed while inspected")
                    visit(opened)
                    opened_after = os.fstat(opened)
                finally:
                    os.close(opened)
                path_after = os.stat(child.name, dir_fd=descriptor, follow_symlinks=False)
                if _source_identity(opened_after) != _source_identity(before) or _source_identity(path_after) != _source_identity(before):
                    raise RuntimeError(f"source provenance {label} changed while inspected")
            elif not stat.S_ISREG(before.st_mode):
                raise RuntimeError(f"source provenance {label} contains unsupported entries")
        if _source_identity(os.fstat(descriptor)) != _source_identity(before_directory):
            raise RuntimeError(f"source provenance {label} changed while inspected")
    root = os.open(root_path, directory_flags)
    try:
        visit(root)
    finally:
        os.close(root)


def _validate_git_grafts(git_dir: Path, common_dir: Path) -> None:
    for grafts in {git_dir / "info/grafts", common_dir / "info/grafts"}:
        if not grafts.exists() and not grafts.is_symlink():
            continue
        try:
            information = grafts.lstat()
        except OSError as error:
            raise RuntimeError("source provenance graft file is unavailable") from error
        if stat.S_ISLNK(information.st_mode) or not stat.S_ISREG(information.st_mode) or information.st_size != 0:
            raise RuntimeError("source provenance rejects legacy Git graft entries")


def _validate_git_control_files(git_dir: Path, common_dir: Path) -> None:
    for control in (git_dir / "HEAD", git_dir / "index", git_dir / "commondir", git_dir / "gitdir", git_dir / "config.worktree", common_dir / "HEAD", common_dir / "config", common_dir / "packed-refs"):
        if not control.exists() and not control.is_symlink():
            continue
        information = control.lstat()
        if stat.S_ISLNK(information.st_mode) or not stat.S_ISREG(information.st_mode):
            raise RuntimeError("source provenance rejects redirected Git control files")


def _validate_git_alternates(object_dir: Path) -> None:
    for name in ("alternates", "http-alternates"):
        alternate = object_dir / f"info/{name}"
        if not alternate.exists() and not alternate.is_symlink():
            continue
        information = alternate.lstat()
        if stat.S_ISLNK(information.st_mode) or not stat.S_ISREG(information.st_mode) or information.st_size != 0:
            raise RuntimeError("source provenance rejects alternate Git object directories")


def _validate_git_storage_authority(git_dir: Path, common_dir: Path, object_dir: Path) -> None:
    _validate_git_storage_tree(object_dir, "Git object storage")
    refs = common_dir / "refs"
    if refs.exists() or refs.is_symlink():
        if refs.is_symlink() or not refs.is_dir():
            raise RuntimeError("source provenance Git refs storage is unsupported")
        _validate_git_storage_tree(refs, "Git refs storage")
    _validate_git_control_files(git_dir, common_dir)
    _validate_git_grafts(git_dir, common_dir)
    _validate_git_alternates(object_dir)


def _validate_literal_commit(commit: bytes, object_format: str) -> str:
    if not commit or len(commit) > 1 << 20 or b"\0" in commit:
        raise RuntimeError("source provenance literal HEAD commit is outside bounds")
    headers, separator, _message = commit.partition(b"\n\n")
    if not separator:
        raise RuntimeError("source provenance literal HEAD commit is malformed")
    lines = headers.split(b"\n")
    oid_length = 40 if object_format == "sha1" else 64
    oid = re.compile(rb"[0-9a-f]{" + str(oid_length).encode() + rb"}")
    if not lines or not lines[0].startswith(b"tree ") or not oid.fullmatch(lines[0][5:]):
        raise RuntimeError("source provenance literal HEAD tree is malformed")
    tree = lines[0][5:].decode("ascii")
    index = 1
    while index < len(lines) and lines[index].startswith(b"parent "):
        if not oid.fullmatch(lines[index][7:]):
            raise RuntimeError("source provenance literal HEAD parent is malformed")
        index += 1
    identity = rb"[^\x00-\x1f<>]+ <[^\x00-\x1f<>]+> [0-9]+ [+-][0-9]{4}"
    if index >= len(lines) or not re.fullmatch(rb"author " + identity, lines[index]):
        raise RuntimeError("source provenance literal HEAD author is malformed")
    index += 1
    if index >= len(lines) or not re.fullmatch(rb"committer " + identity, lines[index]):
        raise RuntimeError("source provenance literal HEAD committer is malformed")
    index += 1
    continuation = False
    for line in lines[index:]:
        if line.startswith(b" "):
            if not continuation:
                raise RuntimeError("source provenance literal HEAD header continuation is malformed")
            continue
        if not re.fullmatch(rb"[A-Za-z0-9-]+ .+", line):
            raise RuntimeError("source provenance literal HEAD header is malformed")
        continuation = True
    return tree


def _reject_unsupported_git_authority_stores(authority: GitAuthority) -> None:
    for directory in {authority.git_dir, authority.common_dir}:
        with os.scandir(directory) as entries:
            for entry in entries:
                if entry.name == "reftable" or entry.name.startswith("sharedindex."):
                    raise RuntimeError("source provenance rejects reftable or split index authority")
    reference_format = _git_run(authority.source, ["rev-parse", "--show-ref-format"], authority=authority).stdout.strip()
    if reference_format != b"files":
        raise RuntimeError("source provenance rejects non-files Git reference backend")
    shared_index = _git_run(authority.source, ["rev-parse", "--shared-index-path"], authority=authority).stdout.strip()
    if shared_index:
        raise RuntimeError("source provenance rejects active split index authority")


def validate_git_authority(source: Path) -> GitAuthority:
    _git_environment()
    try:
        canonical_source = source.resolve(strict=True)
    except OSError as error:
        raise RuntimeError("source provenance source root is unavailable") from error
    if not canonical_source.is_dir() or canonical_source.is_symlink():
        raise RuntimeError("source provenance source root is invalid")
    dot_git = canonical_source / ".git"
    try:
        dot_git_information = dot_git.lstat()
    except OSError as error:
        raise RuntimeError("source provenance requires .git control for a non-bare work tree") from error
    if stat.S_ISLNK(dot_git_information.st_mode) or not (stat.S_ISDIR(dot_git_information.st_mode) or stat.S_ISREG(dot_git_information.st_mode)):
        raise RuntimeError("source provenance rejects redirected .git control")
    top = _resolved_git_path(_git_run(canonical_source, ["rev-parse", "--show-toplevel"]).stdout, "Git top-level")
    if top != canonical_source:
        raise RuntimeError("source provenance Git top-level does not equal supplied source root")
    bare = _git_run(canonical_source, ["rev-parse", "--is-bare-repository"]).stdout.strip()
    inside = _git_run(canonical_source, ["rev-parse", "--is-inside-work-tree"]).stdout.strip()
    if bare != b"false" or inside != b"true":
        raise RuntimeError("source provenance requires a non-bare working tree")
    git_dir = _resolved_git_path(_git_run(canonical_source, ["rev-parse", "--absolute-git-dir"]).stdout, "per-worktree Git directory", reject_symlink=True)
    common_dir = _resolved_git_path(_git_run(canonical_source, ["rev-parse", "--path-format=absolute", "--git-common-dir"]).stdout, "common Git directory", reject_symlink=True)
    if not git_dir.is_dir() or git_dir.is_symlink() or not common_dir.is_dir() or common_dir.is_symlink():
        raise RuntimeError("source provenance Git directory is unsupported")
    if stat.S_ISREG(dot_git_information.st_mode):
        if _read_git_pointer(dot_git, canonical_source, ".git pointer", "gitdir:") != git_dir:
            raise RuntimeError("source provenance .git pointer does not match Git directory")
    commondir_pointer = git_dir / "commondir"
    if commondir_pointer.exists() or commondir_pointer.is_symlink():
        if _read_git_pointer(commondir_pointer, git_dir, "commondir pointer") != common_dir:
            raise RuntimeError("source provenance commondir pointer does not match common Git directory")
    gitdir_pointer = git_dir / "gitdir"
    if gitdir_pointer.exists() or gitdir_pointer.is_symlink():
        _read_git_pointer(gitdir_pointer, git_dir, "gitdir pointer")
    configured_scopes = ["--local"]
    worktree_config = _git_run(canonical_source, [f"--git-dir={git_dir}", "config", "--local", "--type=bool", "--get", "extensions.worktreeConfig"], accepted=(0, 1))
    if worktree_config.returncode == 0 and worktree_config.stdout.strip() == b"true":
        configured_scopes.append("--worktree")
    for scope in configured_scopes:
        configured = _optional_git_config(canonical_source, git_dir, scope, "core.worktree")
        if configured and _configured_worktree_path(configured, git_dir) != canonical_source:
            raise RuntimeError("source provenance configured worktree does not equal supplied source root")
    provisional = GitAuthority(canonical_source, git_dir, common_dir, git_dir / "index", common_dir / "objects", "", "", "")
    index_path = _resolved_git_path(_git_run(canonical_source, ["rev-parse", "--path-format=absolute", "--git-path", "index"], authority=provisional).stdout, "Git index", reject_symlink=True)
    object_dir = _resolved_git_path(_git_run(canonical_source, ["rev-parse", "--path-format=absolute", "--git-path", "objects"], authority=provisional).stdout, "Git object directory", reject_symlink=True)
    if index_path != (git_dir / "index").resolve(strict=True) or object_dir != (common_dir / "objects").resolve(strict=True):
        raise RuntimeError("source provenance Git index or object directory is redirected")
    authority = GitAuthority(canonical_source, git_dir, common_dir, index_path, object_dir, "", "", "")
    _reject_unsupported_git_authority_stores(authority)
    replace_refs = _git_run(canonical_source, ["for-each-ref", "--format=%(refname)", "refs/replace"], authority=authority).stdout
    if replace_refs.strip():
        raise RuntimeError("source provenance rejects active Git replacement refs")
    _validate_git_grafts(git_dir, common_dir)
    _validate_git_storage_authority(git_dir, common_dir, object_dir)
    revision = _git_run(canonical_source, ["rev-parse", "--verify", "HEAD"], authority=authority).stdout.decode("ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", revision):
        raise RuntimeError("source provenance HEAD identity is malformed")
    object_format = _git_run(canonical_source, ["rev-parse", "--show-object-format"], authority=authority).stdout.decode("ascii").strip()
    if object_format not in {"sha1", "sha256"}:
        raise RuntimeError("source provenance Git object format is unsupported")
    commit = _git_run(canonical_source, ["cat-file", "commit", revision], authority=authority).stdout
    tree = _validate_literal_commit(commit, object_format)
    interpreted_tree = _git_run(canonical_source, ["rev-parse", f"{revision}^{{tree}}"], authority=authority).stdout.decode("ascii").strip()
    if interpreted_tree != tree:
        raise RuntimeError("source provenance literal Git commit interpretation changed")
    _validate_git_storage_authority(git_dir, common_dir, object_dir)
    _reject_unsupported_git_authority_stores(authority)
    replace_refs_after = _git_run(canonical_source, ["for-each-ref", "--format=%(refname)", "refs/replace"], authority=authority).stdout
    if replace_refs_after.strip():
        raise RuntimeError("source provenance rejects active Git replacement refs")
    return dataclasses.replace(authority, revision=revision, tree=tree, commit_sha256=hashlib.sha256(commit).hexdigest())


def git_output(source: Path, *arguments: str, authority: GitAuthority | None = None) -> bytes:
    bound = authority or validate_git_authority(source)
    return _git_run(bound.source, list(arguments), authority=bound).stdout


def _source_metadata(source: Path, authority: GitAuthority | None = None) -> tuple[bytes, ...]:
    bound = authority or validate_git_authority(source)
    revision = git_output(bound.source, "rev-parse", "--verify", "HEAD", authority=bound)
    commit = git_output(bound.source, "cat-file", "commit", bound.revision, authority=bound)
    if revision.decode("ascii").strip() != bound.revision or hashlib.sha256(commit).hexdigest() != bound.commit_sha256:
        raise RuntimeError("source provenance literal HEAD changed while captured")
    return (
        revision,
        (bound.tree + "\n").encode("ascii"),
        git_output(bound.source, "rev-parse", "--show-object-format", authority=bound),
        git_output(bound.source, "ls-tree", "-rz", "--full-tree", bound.tree, "--", authority=bound),
        git_output(bound.source, "ls-files", "--stage", "-z", authority=bound),
        git_output(bound.source, "ls-files", "-v", "-z", authority=bound),
        git_output(bound.source, "ls-files", "-t", "-z", authority=bound),
        git_output(bound.source, "ls-files", "-f", "-z", authority=bound),
        git_output(bound.source, "status", "--porcelain=v2", "-z", "--untracked-files=all", authority=bound),
        git_output(bound.source, "ls-files", "--others", "--exclude-standard", "-z", authority=bound),
        git_output(bound.source, "ls-files", "--others", "--ignored", "--exclude-standard", "-z", authority=bound),
    )


@dataclass(frozen=True)
class SourceState:
    revision: str
    tree_identity: str
    git_authority_sha256: str
    committed_tree_sha256: str
    live_tracked_tree_sha256: str
    live_tracked_entries: int
    live_tracked_bytes: int
    index_sha256: str
    index_flags_sha256: str
    status_sha256: str
    ignored_worktree_sha256: str
    ignored_worktree_entries: int
    ignored_worktree_bytes: int
    browser_dependency_sha256: str
    browser_dependency_entries: int
    browser_dependency_bytes: int
    browser_script_head_blob: str
    browser_script_head_mode: str
    browser_contract_head_blob: str
    browser_contract_head_mode: str
    object_format: str
    clean: bool

    @property
    def index_tree_identity(self) -> str: return self.index_sha256
    @property
    def tracked_index_sha256(self) -> str: return self.index_sha256
    @property
    def worktree_sha256(self) -> str: return _framed_sha256([self.live_tracked_tree_sha256.encode(), self.ignored_worktree_sha256.encode()])
    @property
    def worktree_entries(self) -> int: return self.live_tracked_entries + self.ignored_worktree_entries
    @property
    def worktree_bytes(self) -> int: return self.live_tracked_bytes + self.ignored_worktree_bytes

    def identity(self) -> str:
        return hashlib.sha256(canonical_json(dataclasses.asdict(self))).hexdigest()


def git_authority_identity(authority: GitAuthority) -> str:
    return hashlib.sha256(canonical_json({"source": str(authority.source), "git_dir": str(authority.git_dir), "common_dir": str(authority.common_dir), "index": str(authority.index_path), "objects": str(authority.object_dir), "revision": authority.revision, "tree": authority.tree, "commit_sha256": authority.commit_sha256})).hexdigest()


def verify_git_authority(source: Path, expected_sha256: str) -> None:
    if git_authority_identity(validate_git_authority(source)) != expected_sha256:
        raise RuntimeError("source provenance Git authority changed before output creation")


def capture_source_state(source: Path) -> SourceState:
    authority = validate_git_authority(source)
    source = authority.source
    before = _source_metadata(source, authority)
    revision = before[0].decode("ascii").strip(); tree = before[1].decode("ascii").strip(); object_format = before[2].decode("ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", revision) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", tree) or object_format not in {"sha1", "sha256"}:
        raise RuntimeError("source provenance Git identity is malformed")
    committed = _parse_head_entries(before[3]); index = _parse_index_entries(before[4])
    if index != committed: raise RuntimeError("source provenance index does not match HEAD")
    assume = _parse_flag_listing(before[5], "assume-unchanged", lambda tag: tag.islower())
    skip = _parse_flag_listing(before[6], "skip-worktree", lambda tag: tag == b"S")
    fsmonitor = _parse_flag_listing(before[7], "fsmonitor", lambda tag: tag.islower())
    committed_paths = [path for path, _, _ in committed]
    if [record[2:] for record in assume] != committed_paths or [record[2:] for record in skip] != committed_paths or [record[2:] for record in fsmonitor] != committed_paths:
        raise RuntimeError("source provenance index flag paths do not match HEAD")
    if before[8]: raise RuntimeError("source provenance status is not clean")
    untracked = _metadata_paths(before[9], "untracked")
    if untracked:
        raise RuntimeError("source provenance contains nonignored untracked paths")
    ignored = _metadata_paths(before[10], "ignored")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    source_before = source.lstat(); root_descriptor = os.open(source, directory_flags)
    budget = {"entries": 0, "bytes": 0}; live_records: list[bytes] = []; ignored_records: list[bytes] = []; browser_dependency_records: list[bytes] = []
    browser_dependency_bytes = 0
    try:
        if not stat.S_ISDIR(source_before.st_mode) or stat.S_ISLNK(source_before.st_mode) or _source_identity(os.fstat(root_descriptor)) != _source_identity(source_before): raise RuntimeError("source provenance root is invalid")
        for path, mode, oid in committed:
            kind, size, content, live_mode = _read_source_entry(root_descriptor, path, object_format, mode, oid, budget)
            live_records.append(path + b"\0" + mode.encode() + b"\0" + oid.encode() + b"\0" + kind.encode() + b"\0" + str(size).encode() + b"\0" + content.encode())
        tracked_entries, tracked_bytes = budget["entries"], budget["bytes"]
        for path, directory_hint in ignored:
            kind, size, content, live_mode = _read_source_entry(root_descriptor, path, object_format, None, None, budget)
            if directory_hint is not (kind == "directory"):
                raise RuntimeError("source provenance ignored entry type changed")
            record = path + b"\0" + kind.encode() + b"\0" + str(live_mode).encode() + b"\0" + str(size).encode() + b"\0" + content.encode()
            ignored_records.append(record)
            if path.startswith(BROWSER_DEPENDENCY_PREFIX):
                if directory_hint or kind != "regular":
                    raise RuntimeError("browser dependency closure contains unsupported entries")
                browser_dependency_records.append(record); browser_dependency_bytes += size
        root_after = os.fstat(root_descriptor)
    finally: os.close(root_descriptor)
    source_after = source.lstat()
    if _source_identity(root_after) != _source_identity(source_before) or _source_identity(source_after) != _source_identity(source_before): raise RuntimeError("source provenance changed while captured")
    authority_after = validate_git_authority(source)
    if authority_after != authority:
        raise RuntimeError("source provenance Git authority changed while captured")
    after = _source_metadata(source, authority_after)
    if after != before:
        raise RuntimeError("source provenance changed while captured")
    head = {path: (mode, oid) for path, mode, oid in committed}
    browser_path = b"web/scripts/daemon-visual-check.mjs"; contract_path = b"web/scripts/daemon-visual-contract.mjs"
    browser_mode, browser_blob = head.get(browser_path, ("", "")); contract_mode, contract_blob = head.get(contract_path, ("", ""))
    flags = b"assume\0" + before[5] + b"skip\0" + before[6] + b"fsmonitor\0" + before[7]
    authority_identity = git_authority_identity(authority)
    return SourceState(revision, tree, authority_identity, _records_sha256(committed), _framed_sha256(live_records), tracked_entries, tracked_bytes, _records_sha256(index), hashlib.sha256(flags).hexdigest(), hashlib.sha256(before[8]).hexdigest(), _framed_sha256(ignored_records), budget["entries"] - tracked_entries, budget["bytes"] - tracked_bytes, _framed_sha256(browser_dependency_records), len(browser_dependency_records), browser_dependency_bytes, browser_blob, browser_mode, contract_blob, contract_mode, object_format, True)


def verify_source_state(source: Path, expected: SourceState) -> SourceState:
    try: observed = capture_source_state(source)
    except RuntimeError as error: raise RuntimeError("source state changed during system verification") from error
    if observed != expected or not observed.clean: raise RuntimeError("source state changed during system verification")
    return observed


def read_candidate_sidecar(sidecar: Path, candidate_name: str) -> tuple[bytes, str]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        before = sidecar.lstat()
        if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode) or before.st_size <= 0 or before.st_size > 4096:
            raise RuntimeError("candidate checksum sidecar is invalid")
        descriptor = os.open(sidecar, flags)
    except OSError as error:
        raise RuntimeError("candidate checksum sidecar is unavailable") from error
    try:
        if _source_identity(os.fstat(descriptor)) != _source_identity(before):
            raise RuntimeError("candidate checksum sidecar changed while inspected")
        body = os.read(descriptor, 4097)
        opened_after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        path_after = sidecar.lstat()
    except OSError as error:
        raise RuntimeError("candidate checksum sidecar changed while inspected") from error
    if len(body) != before.st_size or len(body) > 4096 or _source_identity(opened_after) != _source_identity(before) or _source_identity(path_after) != _source_identity(before):
        raise RuntimeError("candidate checksum sidecar changed while inspected")
    try:
        fields = body.decode("ascii").strip().split()
    except UnicodeDecodeError as error:
        raise RuntimeError("candidate checksum sidecar is invalid") from error
    if len(fields) != 2 or not re.fullmatch(r"[0-9a-f]{64}", fields[0]) or fields[1] != candidate_name:
        raise RuntimeError("candidate checksum sidecar is invalid")
    return body, fields[0]


def inspect_candidate_manifest(candidate: Path, source_revision: str | None, expected_digest: str | None = None) -> tuple[dict[str, str], bytes]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        before = candidate.lstat()
        if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode) or before.st_size <= 0 or before.st_size > MAX_CANDIDATE_BYTES:
            raise RuntimeError("candidate archive is unavailable or outside bounds")
        descriptor = os.open(candidate, flags)
    except OSError as error:
        raise RuntimeError("candidate archive is unavailable") from error
    body = bytearray()
    try:
        if _source_identity(os.fstat(descriptor)) != _source_identity(before):
            raise RuntimeError("candidate archive changed while inspected")
        while True:
            chunk = os.read(descriptor, 1 << 20)
            if not chunk:
                break
            body.extend(chunk)
            if len(body) > MAX_CANDIDATE_BYTES:
                raise RuntimeError("candidate archive exceeds byte limit")
        opened_after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        path_after = candidate.lstat()
    except OSError as error:
        raise RuntimeError("candidate archive changed while inspected") from error
    if len(body) != before.st_size or _source_identity(opened_after) != _source_identity(before) or _source_identity(path_after) != _source_identity(before):
        raise RuntimeError("candidate archive changed while inspected")
    archive_digest = hashlib.sha256(body).hexdigest()
    if expected_digest is not None and archive_digest != expected_digest:
        raise RuntimeError("candidate archive digest does not match detached checksum")
    try:
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
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
    if source_revision is not None and revision != source_revision:
        raise RuntimeError("candidate manifest revision does not match source HEAD")
    return {"revision": revision, "manifest_sha256": hashlib.sha256(manifest).hexdigest(), "archive_sha256": archive_digest}, bytes(body)


def read_candidate_manifest(candidate: Path, source_revision: str, expected_digest: str | None = None) -> dict[str, str]:
    record, _body = inspect_candidate_manifest(candidate, source_revision, expected_digest)
    return record


def copy_candidate_snapshot(name: str, body: bytes, sidecar_body: bytes, sandbox: Path, expected: str) -> Path:
    if not name or name in {".", ".."} or "/" in name or "\\" in name or len(body) == 0 or len(body) > MAX_CANDIDATE_BYTES or hashlib.sha256(body).hexdigest() != expected:
        raise RuntimeError("candidate snapshot is invalid")
    target = sandbox / name
    try:
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0), 0o500)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        target.chmod(0o555)
        copied_sidecar = Path(str(target) + ".sha256")
        write(copied_sidecar, sidecar_body)
        copied_sidecar.chmod(0o444)
    except OSError as error:
        raise RuntimeError("candidate snapshot copy failed") from error
    assert_candidate_digest(target, expected)
    return target


def validate_png(body: bytes) -> tuple[int, int]:
    if len(body) < 45 or body[:8] != b"\x89PNG\r\n\x1a\n":
        raise RuntimeError("browser evidence screenshot is not a PNG")
    offset = 8
    chunks = 0
    width = height = 0
    saw_idat = False
    saw_iend = False
    while offset < len(body):
        if offset + 12 > len(body):
            raise RuntimeError("browser evidence PNG is truncated")
        length = struct.unpack(">I", body[offset:offset + 4])[0]
        kind = body[offset + 4:offset + 8]
        end = offset + 12 + length
        if length > MAX_SCREENSHOT_BYTES or end > len(body) or not re.fullmatch(rb"[A-Za-z]{4}", kind):
            raise RuntimeError("browser evidence PNG chunk is invalid")
        data = body[offset + 8:offset + 8 + length]
        recorded_crc = struct.unpack(">I", body[offset + 8 + length:end])[0]
        if zlib.crc32(kind + data) & 0xFFFFFFFF != recorded_crc:
            raise RuntimeError("browser evidence PNG checksum is invalid")
        chunks += 1
        if chunks > 100_000:
            raise RuntimeError("browser evidence PNG chunk limit exceeded")
        if chunks == 1:
            if kind != b"IHDR" or length != 13:
                raise RuntimeError("browser evidence PNG header is invalid")
            width, height, bit_depth, color_type, compression, filter_method, interlace = struct.unpack(">IIBBBBB", data)
            valid_depths = {0: {1, 2, 4, 8, 16}, 2: {8, 16}, 3: {1, 2, 4, 8}, 4: {8, 16}, 6: {8, 16}}
            if width < 1 or height < 1 or width > 100_000 or height > 100_000 or color_type not in valid_depths or bit_depth not in valid_depths[color_type] or compression != 0 or filter_method != 0 or interlace not in {0, 1}:
                raise RuntimeError("browser evidence PNG dimensions or format are invalid")
        elif kind == b"IHDR":
            raise RuntimeError("browser evidence PNG has duplicate header")
        if kind == b"IDAT":
            saw_idat = True
        if kind == b"IEND":
            if length != 0 or end != len(body):
                raise RuntimeError("browser evidence PNG ending is invalid")
            saw_iend = True
        elif saw_iend:
            raise RuntimeError("browser evidence PNG has trailing chunks")
        offset = end
    if not saw_idat or not saw_iend or offset != len(body):
        raise RuntimeError("browser evidence PNG structure is incomplete")
    return width, height


def _git_blob_digest(payload: bytes, object_format: str) -> str:
    digest = hashlib.new(object_format); digest.update(f"blob {len(payload)}\0".encode()); digest.update(payload)
    return digest.hexdigest()


def _read_bound_head_blob(source: Path, state: SourceState, oid: str) -> bytes:
    if not oid or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", oid): raise RuntimeError("canonical browser module is not bound to HEAD")
    if git_output(source, "rev-parse", "HEAD").decode("ascii").strip() != state.revision or git_output(source, "rev-parse", "HEAD^{tree}").decode("ascii").strip() != state.tree_identity: raise RuntimeError("source state changed before browser module sealing")
    payload = git_output(source, "cat-file", "blob", oid)
    if not payload or len(payload) > MAX_BROWSER_MODULE_BYTES:
        raise RuntimeError("canonical browser module is outside bounds")
    if _git_blob_digest(payload, state.object_format) != oid: raise RuntimeError("canonical browser module Git object is invalid")
    return payload


def _browser_dependency_snapshot(source: Path, state: SourceState) -> tuple[list[tuple[bytes, int]], str, int, int]:
    ignored = _metadata_paths(git_output(source, "ls-files", "--others", "--ignored", "--exclude-standard", "-z"), "ignored")
    selected = [(path, directory) for path, directory in ignored if path.startswith(BROWSER_DEPENDENCY_PREFIX)]
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    root_descriptor = os.open(source, directory_flags); budget = {"entries": 0, "bytes": 0}; records: list[bytes] = []; details: list[tuple[bytes, int]] = []
    try:
        for path, directory_hint in selected:
            kind, size, content, mode = _read_source_entry(root_descriptor, path, state.object_format, None, None, budget)
            if directory_hint or kind != "regular":
                raise RuntimeError("browser dependency closure contains unsupported entries")
            records.append(path + b"\0" + kind.encode() + b"\0" + str(mode).encode() + b"\0" + str(size).encode() + b"\0" + content.encode())
            details.append((path, mode))
    finally:
        os.close(root_descriptor)
    return details, _framed_sha256(records), budget["entries"], budget["bytes"]


def _validate_browser_dependency_closure(source: Path, state: SourceState) -> list[tuple[bytes, int]]:
    details, identity, entries, size = _browser_dependency_snapshot(source, state)
    if identity != state.browser_dependency_sha256 or entries != state.browser_dependency_entries or size != state.browser_dependency_bytes:
        raise RuntimeError("browser dependency closure changed after source capture")
    if identity != BROWSER_DEPENDENCY_SHA256 or entries == 0 or size <= 0:
        raise RuntimeError("browser dependency closure does not match the pinned Playwright payload")
    return details


def _seal_browser_dependency_closure(source: Path, state: SourceState, destination: Path) -> dict[str, object]:
    details = _validate_browser_dependency_closure(source, state)
    for path, mode in details:
        target = destination / os.fsdecode(path); target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copyfile(source / os.fsdecode(path), target, follow_symlinks=False); target.chmod(mode)
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    root_descriptor = os.open(destination, directory_flags); budget = {"entries": 0, "bytes": 0}; records: list[bytes] = []
    try:
        for path, _ in details:
            kind, size, content, mode = _read_source_entry(root_descriptor, path, state.object_format, None, None, budget)
            if kind != "regular":
                raise RuntimeError("sealed browser dependency closure contains unsupported entries")
            records.append(path + b"\0" + kind.encode() + b"\0" + str(mode).encode() + b"\0" + str(size).encode() + b"\0" + content.encode())
    finally:
        os.close(root_descriptor)
    identity = _framed_sha256(records)
    if identity != BROWSER_DEPENDENCY_SHA256 or budget["entries"] != state.browser_dependency_entries or budget["bytes"] != state.browser_dependency_bytes:
        raise RuntimeError("sealed browser dependency closure does not match the pinned payload")
    return {"package": "playwright-core", "version": BROWSER_DEPENDENCY_VERSION, "payload_sha256": identity, "entries": budget["entries"], "bytes": budget["bytes"], "authority": "pinned_installed_payload"}


def validate_browser_script(source: Path, browser_script: Path | None, skip_browser: bool, state: SourceState | None = None) -> Path | None:
    if skip_browser:
        if browser_script is not None: raise RuntimeError("browser script must be absent in nonvisual mode")
        return None
    canonical = source / "web/scripts/daemon-visual-check.mjs"
    if browser_script is None or state is None or not state.browser_script_head_blob or state.browser_script_head_mode not in {"100644", "100755"}: raise RuntimeError("canonical browser script is required and must be bound to HEAD")
    try:
        canonical_information = canonical.lstat(); supplied_information = browser_script.lstat()
        canonical_resolved = canonical.resolve(strict=True); supplied_resolved = browser_script.resolve(strict=True)
    except OSError as error: raise RuntimeError("canonical browser script is unavailable") from error
    if supplied_resolved != canonical_resolved or _source_identity(supplied_information) != _source_identity(canonical_information) or not stat.S_ISREG(canonical_information.st_mode) or stat.S_ISLNK(canonical_information.st_mode): raise RuntimeError("canonical browser script is required")
    live_mode = "100755" if canonical_information.st_mode & stat.S_IXUSR else "100644"
    if live_mode != state.browser_script_head_mode: raise RuntimeError("canonical browser script executable mode does not match HEAD")
    payload = _read_bound_head_blob(source, state, state.browser_script_head_blob)
    if hashlib.sha256(payload).hexdigest() != sha256(canonical):
        raise RuntimeError("canonical browser script bytes do not match HEAD")
    if not state.browser_contract_head_blob or state.browser_contract_head_mode not in {"100644", "100755"}:
        raise RuntimeError("canonical browser contract is required and must be bound to HEAD")
    _read_bound_head_blob(source, state, state.browser_contract_head_blob)
    _validate_browser_dependency_closure(source, state)
    return canonical_resolved


def seal_browser_modules(source: Path, state: SourceState, destination: Path) -> tuple[Path, dict[str, str]]:
    if destination.exists(): raise RuntimeError("browser execution sandbox already exists")
    scripts = destination / "web/scripts"; scripts.mkdir(parents=True, mode=0o700)
    modules = (
        ("daemon-visual-check.mjs", state.browser_script_head_blob, state.browser_script_head_mode),
        ("daemon-visual-contract.mjs", state.browser_contract_head_blob, state.browser_contract_head_mode),
    )
    record: dict[str, str] = {}
    for name, oid, mode in modules:
        if mode not in {"100644", "100755"}: raise RuntimeError("canonical browser module mode is unsupported")
        payload = _read_bound_head_blob(source, state, oid)
        target = scripts / name; target.write_bytes(payload); target.chmod(0o555 if mode == "100755" else 0o444)
        if _git_blob_digest(target.read_bytes(), state.object_format) != oid: raise RuntimeError("sealed browser module does not match HEAD")
        record[f"{name}_head_blob"] = oid; record[f"{name}_sha256"] = hashlib.sha256(payload).hexdigest(); record[f"{name}_mode"] = mode
    dependency = _seal_browser_dependency_closure(source, state, destination)
    script = scripts / "daemon-visual-check.mjs"
    record["execution_path"] = str(script); record["source_revision"] = state.revision; record["source_tree_identity"] = state.tree_identity
    record["dependency_package"] = str(dependency["package"]); record["dependency_version"] = str(dependency["version"]); record["dependency_payload_sha256"] = str(dependency["payload_sha256"]); record["dependency_entries"] = str(dependency["entries"]); record["dependency_bytes"] = str(dependency["bytes"]); record["dependency_authority"] = str(dependency["authority"])
    return script, record


def _runtime_digest(value: object, prefix: bytes) -> str:
    encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(prefix + encoded).hexdigest()


def _runtime_observed_milliseconds(value: object) -> int:
    if not isinstance(value, str): raise RuntimeError("browser runtime observed_at is invalid")
    match = re.fullmatch(r"(\d{4})-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.(\d{1,3}))?Z", value)
    if not match or int(match.group(1)) < 1970: raise RuntimeError("browser runtime observed_at is invalid")
    base = value[:-1].split(".", 1)[0]
    normalized = base + "." + (match.group(2) or "").ljust(3, "0") + "+00:00"
    try: parsed = datetime.datetime.fromisoformat(normalized)
    except ValueError as error: raise RuntimeError("browser runtime observed_at is invalid") from error
    milliseconds = int(parsed.timestamp() * 1000)
    if datetime.datetime.fromtimestamp(milliseconds / 1000, datetime.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z") != normalized.replace("+00:00", "Z"):
        raise RuntimeError("browser runtime observed_at is invalid")
    return milliseconds


def _runtime_configuration(value: object, scope: dict) -> dict:
    if not isinstance(value, dict): raise RuntimeError("browser runtime configuration is invalid")
    has_database = "database_authority_identity" in value; has_rate = "rate_limit_authority_identity" in value
    has_routes = "route_inventory_identity" in value or "runtime_policy_identity" in value
    keys = ["tenant_id", "repository_ids", "metadata_backend"] + (["database_authority_identity"] if has_database else []) + ["artifact_backend", "artifact_protection", "notification_backend", "rate_limit_backend"] + (["rate_limit_authority_identity"] if has_rate else []) + ["review_mode", "webhook_ingress", "local_workers", "publication_enabled", "publication_fence_verified"] + (["route_inventory_identity", "runtime_policy_identity"] if has_routes else []) + ["route_count", "handlers"]
    digest = re.compile(r"^[0-9a-f]{64}$")
    valid_digest = lambda item: isinstance(item, str) and digest.fullmatch(item) is not None and item != "0" * 64
    raw_handlers = value.get("handlers")
    handlers = [] if raw_handlers is None else raw_handlers
    if set(value) != set(keys) or value.get("tenant_id") != scope["tenant"] or value.get("repository_ids") != [scope["repository"]] or value.get("metadata_backend") not in {"local", "postgres"} or value.get("artifact_backend") not in {"local", "s3"} or value.get("artifact_protection") not in {"process_private", "envelope_encrypted"} or value.get("notification_backend") not in {"process_local", "postgres"} or value.get("rate_limit_backend") not in {"process_local", "postgres"} or value.get("review_mode") not in {"disabled", "local", "advisory", "required"} or any(type(value.get(key)) is not bool for key in ("webhook_ingress", "local_workers", "publication_enabled", "publication_fence_verified")) or type(value.get("route_count")) is not int or not 0 <= value["route_count"] <= 64 or (not isinstance(raw_handlers, list) and raw_handlers is not None) or len(handlers) > 64:
        raise RuntimeError("browser runtime configuration is invalid")
    if has_database != (value["metadata_backend"] == "postgres") or has_rate != (value["rate_limit_backend"] == "postgres") or has_routes != (value["route_count"] > 0) or has_database and not valid_digest(value["database_authority_identity"]) or has_rate and not valid_digest(value["rate_limit_authority_identity"]) or has_routes and (not valid_digest(value["route_inventory_identity"]) or not valid_digest(value["runtime_policy_identity"])) or value["route_count"] > 0 and value["local_workers"] is not True or value["review_mode"] == "disabled" and (value["local_workers"] or value["route_count"] or handlers) or value["local_workers"] and not handlers or value["publication_enabled"] != (value["review_mode"] == "required") or value["publication_enabled"] and not value["publication_fence_verified"] or value["publication_fence_verified"] and value["metadata_backend"] != "postgres" or value["metadata_backend"] == "local" and (value["artifact_backend"] != "local" or value["artifact_protection"] != "process_private" or value["notification_backend"] != "process_local" or value["rate_limit_backend"] != "process_local") or value["artifact_backend"] == "local" and value["artifact_protection"] != "process_private" or value["artifact_backend"] == "s3" and (value["metadata_backend"] != "postgres" or value["artifact_protection"] != "envelope_encrypted") or value["notification_backend"] == "postgres" and value["metadata_backend"] != "postgres" or value["rate_limit_backend"] == "postgres" and value["metadata_backend"] != "postgres" or value["metadata_backend"] == "postgres" and value["rate_limit_backend"] != "postgres":
        raise RuntimeError("browser runtime configuration is invalid")
    task_kinds = {"acquire_source", "build_change", "inspect_deterministic", "retrieve_context", "assemble_context", "generate_candidates", "verify_candidates", "evaluate_publication", "publish_result"}
    previous = ""
    for handler in handlers:
        if not isinstance(handler, dict) or set(handler) != {"kind", "identity"} or handler.get("kind") not in task_kinds or handler["kind"] <= previous or not valid_digest(handler.get("identity")): raise RuntimeError("browser runtime handler is invalid")
        previous = handler["kind"]
    canonical = {"tenant_id": value["tenant_id"], "repository_ids": list(value["repository_ids"]), "metadata_backend": value["metadata_backend"]}
    if has_database: canonical["database_authority_identity"] = value["database_authority_identity"]
    canonical.update({"artifact_backend": value["artifact_backend"], "artifact_protection": value["artifact_protection"], "notification_backend": value["notification_backend"], "rate_limit_backend": value["rate_limit_backend"]})
    if has_rate: canonical["rate_limit_authority_identity"] = value["rate_limit_authority_identity"]
    canonical.update({"review_mode": value["review_mode"], "webhook_ingress": value["webhook_ingress"], "local_workers": value["local_workers"], "publication_enabled": value["publication_enabled"], "publication_fence_verified": value["publication_fence_verified"]})
    if has_routes: canonical.update({"route_inventory_identity": value["route_inventory_identity"], "runtime_policy_identity": value["runtime_policy_identity"]})
    canonical.update({"route_count": value["route_count"], "handlers": None if raw_handlers is None else [{"kind": handler["kind"], "identity": handler["identity"]} for handler in handlers]})
    return canonical


def _runtime_envelope(value: object, scope: dict) -> dict:
    if not isinstance(value, dict) or set(value) != {"contract", "schema_version", "request_id", "status"} or value.get("contract") != "open-trestle/runtime-status-response" or type(value.get("schema_version")) is not int or value["schema_version"] != 1 or not isinstance(value.get("request_id"), str) or not 1 <= len(value["request_id"]) <= 128 or not isinstance(value.get("status"), dict): raise RuntimeError("browser runtime envelope is invalid")
    status = value["status"]
    required = {"contract", "schema_version", "identity", "configuration_identity", "tenant_id", "repository_id", "observed_at", "ready", "configuration", "components"}
    digest = re.compile(r"^[0-9a-f]{64}$"); valid_digest = lambda item: isinstance(item, str) and digest.fullmatch(item) is not None and item != "0" * 64
    if set(status) != required or status.get("contract") != "open-trestle/runtime-status" or type(status.get("schema_version")) is not int or status["schema_version"] != 1 or not valid_digest(status.get("identity")) or not valid_digest(status.get("configuration_identity")) or status.get("tenant_id") != scope["tenant"] or status.get("repository_id") != scope["repository"] or type(status.get("ready")) is not bool or not isinstance(status.get("components"), list) or len(status["components"]) > 64: raise RuntimeError("browser runtime status is invalid")
    _runtime_observed_milliseconds(status.get("observed_at")); configuration = _runtime_configuration(status["configuration"], scope)
    if status["configuration_identity"] != _runtime_digest(configuration, b"open-trestle/runtime-configuration/v1\0"): raise RuntimeError("browser runtime configuration identity is invalid")
    components = []; previous = ""; ready = True
    for component in status["components"]:
        if not isinstance(component, dict) or set(component) != {"name", "state"} or component.get("name") not in {"local_workers", "task_notifications"} or component["name"] <= previous or component.get("state") not in {"starting", "ready"}: raise RuntimeError("browser runtime component is invalid")
        previous = component["name"]; ready = ready and component["state"] == "ready"; components.append(dict(component))
    if status["ready"] is not ready: raise RuntimeError("browser runtime readiness is invalid")
    unsigned = {"contract": "open-trestle/runtime-status", "schema_version": 1, "identity": "", "configuration_identity": status["configuration_identity"], "tenant_id": status["tenant_id"], "repository_id": status["repository_id"], "observed_at": status["observed_at"], "ready": status["ready"], "configuration": configuration, "components": components}
    if status["identity"] != _runtime_digest(unsigned, b"open-trestle/runtime-status/v1\0"):
        raise RuntimeError("browser runtime status identity is invalid")
    normalized_configuration = {**configuration, "handlers": [] if configuration["handlers"] is None else configuration["handlers"]}
    return {**unsigned, "identity": status["identity"], "configuration": normalized_configuration}


def validate_browser_runtime(runtime: object, phase: str, scope: dict, captures: list[dict]) -> dict:
    keys = {"phase", "endpoint", "displayed_received_at_milliseconds", "post_capture_received_at_milliseconds", "displayed", "post_capture", "dom", "runtime_screenshot_sha256"}
    expected_endpoint = f"/api/v1/tenants/{urllib.parse.quote(scope['tenant'], safe='')}/repositories/{urllib.parse.quote(scope['repository'], safe='')}/runtime"
    digest = re.compile(r"^[0-9a-f]{64}$")
    if not isinstance(runtime, dict) or set(runtime) != keys or runtime.get("phase") != phase or runtime.get("endpoint") != expected_endpoint or type(runtime.get("displayed_received_at_milliseconds")) is not int or type(runtime.get("post_capture_received_at_milliseconds")) is not int or runtime["displayed_received_at_milliseconds"] < 0 or runtime["post_capture_received_at_milliseconds"] < runtime["displayed_received_at_milliseconds"] or not isinstance(runtime.get("runtime_screenshot_sha256"), str) or not digest.fullmatch(runtime["runtime_screenshot_sha256"]) or runtime["runtime_screenshot_sha256"] == "0" * 64: raise RuntimeError("browser runtime evidence is invalid")
    displayed = _runtime_envelope(runtime["displayed"], scope); post = _runtime_envelope(runtime["post_capture"], scope)
    displayed_at = _runtime_observed_milliseconds(displayed["observed_at"]); post_at = _runtime_observed_milliseconds(post["observed_at"])
    if displayed_at > runtime["displayed_received_at_milliseconds"] + 1000 or runtime["displayed_received_at_milliseconds"] - displayed_at > 30_000 or post_at > runtime["post_capture_received_at_milliseconds"] + 1000 or runtime["post_capture_received_at_milliseconds"] - post_at > 30_000 or post_at < displayed_at or displayed["configuration_identity"] != post["configuration_identity"] or displayed["tenant_id"] != post["tenant_id"] or displayed["repository_id"] != post["repository_id"] or displayed["ready"] is not post["ready"] or displayed["configuration"] != post["configuration"] or displayed["components"] != post["components"]: raise RuntimeError("browser runtime changed during screenshot capture")
    expected_dom = {"status_identity": displayed["identity"], "configuration_identity": displayed["configuration_identity"], "observed_at": displayed["observed_at"], "ready": displayed["ready"], "configuration": displayed["configuration"], "components": displayed["components"]}
    if runtime.get("dom") != expected_dom: raise RuntimeError("browser runtime DOM does not match response")
    runtime_captures = [capture for capture in captures if capture.get("view") == "runtime"]
    if len(runtime_captures) != 1 or runtime_captures[0].get("sha256") != runtime["runtime_screenshot_sha256"]: raise RuntimeError("browser runtime screenshot is not bound")
    return {"displayed": displayed, "post_capture": post}


def validate_browser_phase_record(record: dict, expected: dict, artifacts_root: Path | None) -> dict:
    phase = record.get("phase")
    if phase not in {"before_restart", "after_restart"}:
        raise RuntimeError("browser evidence phase is invalid")
    required_keys = {"contract", "schema_version", "phase", "scope", "run_identity", "diagnostic_set_identity", "deterministic_check_identity", "deterministic_check_state", "observation_count", "observation_identities", "runtime", "console_errors", "unexpected_egress", "horizontal_overflow", "keyboard_focus_visible", "evidence_disclosure_focus_visible", "focus_order_steps", "reduced_motion", "tap_targets_minimum", "captures", "receipt", "receipt_sha256"}
    if set(record) != required_keys or record.get("contract") != "open-trestle/daemon-console-visual-receipt" or type(record.get("schema_version")) is not int or record["schema_version"] != 3:
        raise RuntimeError("browser evidence contract is invalid")
    scope = record.get("scope")
    if not isinstance(scope, dict) or set(scope) != {"tenant", "repository", "run"} or any(not isinstance(value, str) for value in scope.values()) or record.get("deterministic_check_state") not in {"passed", "failed"}:
        raise RuntimeError("browser evidence scope or state is invalid")
    observation_count = record.get("observation_count")
    if type(observation_count) is not int or observation_count < 0 or observation_count > 8192:
        raise RuntimeError("browser evidence observation count is invalid")
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
    for key in ("console_errors", "unexpected_egress"):
        if type(record.get(key)) is not int or record[key] != 0:
            raise RuntimeError("browser evidence metrics are invalid")
    for key, value in (("horizontal_overflow", False), ("keyboard_focus_visible", True), ("evidence_disclosure_focus_visible", True), ("reduced_motion", True)):
        if type(record.get(key)) is not bool or record[key] is not value:
            raise RuntimeError("browser evidence metrics are invalid")
    if type(record.get("tap_targets_minimum")) is not int or record["tap_targets_minimum"] != 44:
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
        if not isinstance(capture, dict) or set(capture) != {"name", "view", "width", "height", "image_width", "image_height", "bytes", "sha256"}:
            raise RuntimeError("browser evidence capture is invalid")
        name = capture.get("name")
        if name not in expected_captures or name in observed_names:
            raise RuntimeError("browser evidence capture name is invalid")
        observed_names.add(name)
        view, width, height = expected_captures[name]
        if capture.get("view") != view or type(capture.get("width")) is not int or capture["width"] != width or type(capture.get("height")) is not int or capture["height"] != height or type(capture.get("image_width")) is not int or capture["image_width"] != width or type(capture.get("image_height")) is not int or capture["image_height"] < height or capture["image_height"] > 100_000 or type(capture.get("bytes")) is not int or capture["bytes"] <= 0 or capture["bytes"] > MAX_SCREENSHOT_BYTES or not isinstance(capture.get("sha256"), str) or not digest.fullmatch(capture["sha256"]) or capture["sha256"] == "0" * 64:
            raise RuntimeError("browser evidence capture metadata is invalid")
    if observed_names != set(expected_captures):
        raise RuntimeError("browser evidence capture inventory is invalid")
    runtime = validate_browser_runtime(record.get("runtime"), phase, scope, captures)
    receipt_name = record.get("receipt")
    receipt_sha256 = record.get("receipt_sha256")
    if not isinstance(receipt_name, str) or not isinstance(receipt_sha256, str) or not digest.fullmatch(receipt_sha256):
        raise RuntimeError("browser evidence receipt binding is invalid")
    if artifacts_root is None:
        return runtime
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
        if not stat.S_ISREG(information.st_mode) or stat.S_ISLNK(information.st_mode) or information.st_size != capture["bytes"]:
            raise RuntimeError("browser evidence screenshot digest mismatch")
        body = read_bounded(capture_path, MAX_SCREENSHOT_BYTES)
        if hashlib.sha256(body).hexdigest() != capture["sha256"]:
            raise RuntimeError("browser evidence screenshot digest mismatch")
        image_width, image_height = validate_png(body)
        if image_width != capture["image_width"] or image_height != capture["image_height"]:
            raise RuntimeError("browser evidence PNG dimensions mismatch")
    return runtime


def validate_browser_phase_evidence(before: dict | None, after: dict | None, expected: dict, artifacts_root: Path | None = None) -> dict:
    if before is None or after is None or before.get("phase") != "before_restart" or after.get("phase") != "after_restart":
        raise RuntimeError("browser evidence requires before and after restart phases")
    before_runtime = validate_browser_phase_record(before, expected, artifacts_root)
    after_runtime = validate_browser_phase_record(after, expected, artifacts_root)
    before_status = before_runtime["displayed"]; after_status = after_runtime["displayed"]
    if before_status["configuration_identity"] != after_status["configuration_identity"] or before_status["tenant_id"] != after_status["tenant_id"] or before_status["repository_id"] != after_status["repository_id"] or before_status["ready"] is not after_status["ready"] or before_status["configuration"] != after_status["configuration"] or before_status["components"] != after_status["components"] or _runtime_observed_milliseconds(after_status["observed_at"]) < _runtime_observed_milliseconds(before_status["observed_at"]):
        raise RuntimeError("browser runtime semantics changed across restart")
    return {"status": "passed", "runtime": {"configuration_identity": before_status["configuration_identity"], "ready": before_status["ready"], "components": before_status["components"], "configuration_stable": True, "components_stable": True, "per_phase": {"before_restart": {"status_identity": before_status["identity"], "observed_at": before_status["observed_at"]}, "after_restart": {"status_identity": after_status["identity"], "observed_at": after_status["observed_at"]}}}, "phases": [before, after]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, default=Path.cwd())
    parser.add_argument("--browser-script", type=Path)
    parser.add_argument("--skip-browser", action="store_true")
    args = parser.parse_args()
    candidate = args.candidate
    output = args.output.resolve()
    source = args.source_root.resolve()
    supplied_browser_script = Path(os.path.abspath(args.browser_script)) if args.browser_script else None
    sidecar = Path(str(candidate) + ".sha256")
    if output.exists():
        raise SystemExit("candidate/checksum must be valid and output must not exist")
    try:
        candidate_manifest, candidate_snapshot = inspect_candidate_manifest(candidate, None)
        sidecar_body, candidate_digest = read_candidate_sidecar(sidecar, candidate.name)
        if candidate_manifest["archive_sha256"] != candidate_digest:
            raise RuntimeError("candidate archive digest does not match detached checksum")
    except RuntimeError as error:
        raise SystemExit(str(error)) from error
    try:
        source_before = capture_source_state(source)
        browser_script = validate_browser_script(source, supplied_browser_script, args.skip_browser, source_before)
    except RuntimeError as error:
        raise SystemExit(str(error)) from error
    if not source_before.clean:
        raise SystemExit("source tree must be clean before system verification")
    if candidate_manifest["revision"] != source_before.revision:
        raise RuntimeError("candidate manifest revision does not match source HEAD")
    try:
        verify_git_authority(source, source_before.git_authority_sha256)
    except RuntimeError as error:
        raise SystemExit(str(error)) from error

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
    execution_candidate = copy_candidate_snapshot(candidate.name, candidate_snapshot, sidecar_body, sandbox, candidate_digest)
    copied_manifest = read_candidate_manifest(execution_candidate, source_before.revision, candidate_digest)
    if copied_manifest != candidate_manifest:
        raise RuntimeError("copied candidate manifest binding mismatch")
    browser_provenance: dict[str, str] | None = None
    browser_execution_script: Path | None = None
    if not args.skip_browser:
        assert browser_script is not None
        browser_execution_script, browser_provenance = seal_browser_modules(source, source_before, output / "browser-runtime")
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

    verify_source_state(source, source_before)
    candidate_root = output / "candidate-root"
    candidate_root.mkdir(mode=0o700)
    for sentinel in (candidate_root / "etc/open-trestle/operator.conf", candidate_root / "var/lib/open-trestle/operator.state"):
        sentinel.parent.mkdir(mode=0o700, parents=True)
        write(sentinel, b"operator-owned\n")

    verify_archive = execute_candidate(["verify-archive"])
    write(artifacts / "candidate-verify-archive.txt", verify_archive.stdout)
    verified_manifest = read_candidate_manifest(execution_candidate, source_before.revision, candidate_digest)
    if verified_manifest != candidate_manifest:
        raise RuntimeError("verified candidate manifest binding mismatch")
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
            assert browser_execution_script is not None
            root = artifacts / "daemon-console"
            root.mkdir(mode=0o700, exist_ok=True)
            phase_output = root / phase.replace("_", "-")
            visual_env = {**env, "OPEN_TRESTLE_DAEMON_URL": url, "OPEN_TRESTLE_DAEMON_VISUAL_OUTPUT": str(phase_output), "OPEN_TRESTLE_TENANT": "tenant-a", "OPEN_TRESTLE_REPOSITORY": "repository-a", "OPEN_TRESTLE_RUN": run_id, "OPEN_TRESTLE_BROWSER_PHASE": phase}
            commands.append(["node", str(browser_execution_script)])
            visual = run(["node", str(browser_execution_script)], visual_env, sandbox, timeout=120)
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
        assert browser_provenance is not None
        browser_record["provenance"] = browser_provenance
    receipt = {
        "contract": "open-trestle/local-alpha-system-receipt",
        "schema_version": 3,
        "source_revision": source_after.revision,
        "source_tree_identity": source_after.tree_identity,
        "source_state_identity": source_after.identity(),
        "source_index_flags_identity": source_after.index_flags_sha256,
        "source_tree_clean": source_after.clean,
        "source_provenance": {
            "object_format": source_after.object_format,
            "git_authority": {"sha256": source_after.git_authority_sha256, "literal_unreplaced_head": True, "top_level_matches_source_root": True, "reference_format": "files", "split_index": False, "replacement_refs": False, "legacy_grafts": False, "alternate_objects": False},
            "committed_tree": {"tree_oid": source_after.tree_identity, "entries_sha256": source_after.committed_tree_sha256, "entry_count": source_after.live_tracked_entries},
            "live_tracked_tree": {"entries_sha256": source_after.live_tracked_tree_sha256, "entry_count": source_after.live_tracked_entries, "bytes": source_after.live_tracked_bytes, "matches_committed_head": True},
            "index": {"entries_sha256": source_after.index_sha256, "stage_zero_matches_committed_head": True},
            "index_flags": {"sha256": source_after.index_flags_sha256, "assume_unchanged": False, "skip_worktree": False, "fsmonitor_valid": False},
            "status": {"sha256": source_after.status_sha256, "porcelain_empty": True, "nonignored_untracked_count": 0},
            "ignored_worktree": {"entries_sha256": source_after.ignored_worktree_sha256, "entry_count": source_after.ignored_worktree_entries, "bytes": source_after.ignored_worktree_bytes, "stable_during_run": True},
            "browser_dependency": {"package": "playwright-core", "version": BROWSER_DEPENDENCY_VERSION, "payload_sha256": source_after.browser_dependency_sha256, "entry_count": source_after.browser_dependency_entries, "bytes": source_after.browser_dependency_bytes, "authority": "pinned_installed_payload"},
            "browser_modules": {"script_head_blob": source_after.browser_script_head_blob, "script_head_mode": source_after.browser_script_head_mode, "contract_head_blob": source_after.browser_contract_head_blob, "contract_head_mode": source_after.browser_contract_head_mode},
        },
        "candidate": {"path": str(candidate), "execution_path": str(execution_candidate), "sha256": candidate_digest, "sidecar_sha256": sha256(sidecar), "manifest_revision": candidate_manifest["revision"], "manifest_sha256": candidate_manifest["manifest_sha256"], "archive_sha256": candidate_manifest["archive_sha256"], "lifecycle": "verified_install_smoke_recover_uninstall", "operator_state_preserved": True},
        "binaries": binary_records,
        "repository": {"base_revision": base, "head_revision": head},
        "review": {"tenant_id": "tenant-a", "repository_id": "repository-a", "review_run_id": run_id, "run_receipt_identity": status_value["identity"], "diagnostic_set_identity": diagnostics_value["identity"]},
        "commands": commands,
        "artifacts": artifact_records,
        "restart": {"status_identity_stable": True, "diagnostics_set_stable": True, "json_bytes_stable": True, "sarif_bytes_stable": True},
        "browser": browser_record,
        "runtime": browser_record.get("runtime", {"status": "not_run", "reason": "explicit_nonvisual_verification"}),
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
