"""Build the deterministic unsigned Open Trestle Linux amd64 candidate."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import re
import stat
import struct
import sys
import uuid
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import BinaryIO

SCHEMA_VERSION = 1
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
SHEBANG = b"#!/usr/bin/env python3\n"
RELEASE_FILES = frozenset(
    {
        "release/secret-scanner-release.json",
        "release/secret-scanner.spdx.json",
        "release/vulnerability-scan.json",
    }
)
EXECUTABLES = {
    "trestle": ("usr/local/bin/trestle", 2),
    "trestled": ("usr/local/bin/trestled", 2),
    "libexec/open-trestle/open-trestle-secret-scanner": (
        "usr/local/libexec/open-trestle/open-trestle-secret-scanner",
        3,
    ),
    "libexec/open-trestle/open-trestle-secret-scanner-worker": (
        "usr/local/libexec/open-trestle/open-trestle-secret-scanner-worker",
        2,
    ),
}
EXPECTED_ROOT = frozenset(
    {
        "LICENSE",
        "NOTICE",
        "ca-certificates.crt",
        "data",
        "libexec",
        "licenses",
        "release",
        "trestle",
        "trestled",
    }
)
MAX_FILE_SIZE = 128 * 1024 * 1024


@dataclass(frozen=True)
class Payload:
    source: str
    path: str
    mode: int
    size: int
    sha256: str
    elf: bool
    body: bytes


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def _validate_metadata(version: str, revision: str, created: str) -> None:
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", version):
        raise ValueError("version must be semantic version text")
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", revision):
        raise ValueError("revision must be a lowercase Git object ID")
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", created):
        raise ValueError("created must be a UTC whole-second timestamp")
    try:
        datetime.strptime(created, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise ValueError("created must be a valid UTC timestamp") from error


def _safe_source_name(relative: str) -> str:
    if not relative or len(relative) > 240 or "\\" in relative or "\x00" in relative:
        raise ValueError("staging path is invalid")
    path = PurePosixPath(relative)
    if path.is_absolute() or str(path) != relative or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("staging path is invalid")
    if not all(re.fullmatch(r"[A-Za-z0-9._+@=-]+", part) for part in path.parts):
        raise ValueError("staging path is invalid")
    forbidden_parts = {"build", "private", "source", "src", "test", "tests", "tool", "tools"}
    if any(part.startswith(".") or part.lower() in forbidden_parts for part in path.parts):
        raise ValueError("staging path contains forbidden material")
    return relative


def _open_beneath(root_descriptor: int, relative: str) -> int:
    parts = PurePosixPath(relative).parts
    descriptor = os.dup(root_descriptor)
    try:
        for part in parts[:-1]:
            next_descriptor = os.open(part, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0), dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return os.open(parts[-1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=descriptor)
    finally:
        os.close(descriptor)


def _read_stable(
    path: Path,
    expected_mode: int,
    label: str,
    root_descriptor: int | None = None,
    expected_status: os.stat_result | None = None,
) -> bytes:
    if root_descriptor is None:
        try:
            expected_status = os.lstat(path)
        except OSError as error:
            raise ValueError(f"staging file is unavailable: {label}") from error
    assert expected_status is not None
    if not stat.S_ISREG(expected_status.st_mode) or stat.S_ISLNK(expected_status.st_mode):
        raise ValueError(f"staging member is not a regular file: {label}")
    if stat.S_IMODE(expected_status.st_mode) != expected_mode:
        raise ValueError(f"staging file mode is invalid: {label}")
    if expected_status.st_size <= 0 or expected_status.st_size > MAX_FILE_SIZE:
        raise ValueError(f"staging file size is invalid: {label}")
    try:
        descriptor = _open_beneath(root_descriptor, label) if root_descriptor is not None else os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as source:
            before = os.fstat(source.fileno())
            if (before.st_dev, before.st_ino) != (expected_status.st_dev, expected_status.st_ino) or not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != expected_mode:
                raise ValueError(f"staging file metadata is invalid: {label}")
            chunks: list[bytes] = []
            size = 0
            while chunk := source.read(1 << 20):
                chunks.append(chunk)
                size += len(chunk)
                if size > MAX_FILE_SIZE:
                    raise ValueError(f"staging file size is invalid: {label}")
            after = os.fstat(source.fileno())
    except OSError as error:
        raise ValueError(f"staging file could not be read: {label}") from error
    stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if size != before.st_size or any(getattr(before, key) != getattr(after, key) for key in stable):
        raise ValueError(f"staging file changed while read: {label}")
    return b"".join(chunks)


def _validate_elf(body: bytes, label: str, expected_type: int) -> None:
    if len(body) < 64 or body[:16] != b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 8):
        raise ValueError(f"staging executable is not a canonical ELF64 file: {label}")
    elf_type, machine, version = struct.unpack_from("<HHI", body, 16)
    if elf_type != expected_type or machine != 62 or version != 1:
        raise ValueError(f"staging executable target is invalid: {label}")
    program_offset = struct.unpack_from("<Q", body, 32)[0]
    program_entry_size, program_count = struct.unpack_from("<HH", body, 54)
    if program_entry_size not in {0, 56} or program_count > 128:
        raise ValueError(f"staging executable program headers are invalid: {label}")
    if program_count and (program_offset < 64 or program_offset + program_entry_size * program_count > len(body)):
        raise ValueError(f"staging executable program headers are invalid: {label}")
    for index in range(program_count):
        offset = program_offset + index * program_entry_size
        program_type = struct.unpack_from("<I", body, offset)[0]
        if program_type == 3:
            raise ValueError(f"staging executable has a dynamic interpreter: {label}")
        if program_type == 2:
            file_offset, file_size = struct.unpack_from("<QQ", body, offset + 8)[0], struct.unpack_from("<Q", body, offset + 32)[0]
            if file_offset + file_size > len(body) or file_size % 16:
                raise ValueError(f"staging executable dynamic table is invalid: {label}")
            for dynamic_offset in range(file_offset, file_offset + file_size, 16):
                tag = struct.unpack_from("<q", body, dynamic_offset)[0]
                if tag == 1:
                    raise ValueError(f"staging executable has a shared-library dependency: {label}")
                if tag == 0:
                    break


def _walk_staging(root_descriptor: int) -> tuple[dict[str, os.stat_result], set[str]]:
    files: dict[str, os.stat_result] = {}
    directories: set[str] = set()

    def visit(directory_descriptor: int, prefix: PurePosixPath) -> None:
        try:
            entries = sorted(os.scandir(directory_descriptor), key=lambda entry: entry.name)
        except OSError as error:
            raise ValueError("staging directory could not be read") from error
        for entry in entries:
            relative = str(prefix / entry.name) if str(prefix) != "." else entry.name
            _safe_source_name(relative)
            try:
                status = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise ValueError(f"staging member could not be inspected: {relative}") from error
            if stat.S_ISDIR(status.st_mode) and not stat.S_ISLNK(status.st_mode):
                if stat.S_IMODE(status.st_mode) != 0o755:
                    raise ValueError(f"staging directory metadata is invalid: {relative}")
                directories.add(relative)
                child_descriptor = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_descriptor)
                try:
                    opened = os.fstat(child_descriptor)
                    if (opened.st_dev, opened.st_ino) != (status.st_dev, status.st_ino):
                        raise ValueError(f"staging directory changed while traversed: {relative}")
                    visit(child_descriptor, PurePosixPath(relative))
                finally:
                    os.close(child_descriptor)
            elif stat.S_ISREG(status.st_mode) and not stat.S_ISLNK(status.st_mode):
                files[relative] = status
            else:
                raise ValueError(f"staging member is not a regular file or directory: {relative}")

    visit(root_descriptor, PurePosixPath("."))
    return files, directories


def _collect_payload(staging: Path) -> tuple[Payload, ...]:
    try:
        path_status = os.lstat(staging)
        root_descriptor = os.open(staging, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise ValueError("staging directory is unavailable") from error
    try:
        root_before = os.fstat(root_descriptor)
        if (
            not stat.S_ISDIR(root_before.st_mode)
            or stat.S_ISLNK(path_status.st_mode)
            or (root_before.st_dev, root_before.st_ino) != (path_status.st_dev, path_status.st_ino)
            or stat.S_IMODE(root_before.st_mode) != 0o755
        ):
            raise ValueError("staging path must be a stable mode-0755 directory")
        file_statuses, directories = _walk_staging(root_descriptor)
        files = set(file_statuses)
        root_members = {path.split("/", 1)[0] for path in files | directories}
        if root_members != EXPECTED_ROOT:
            raise ValueError("staging root inventory is invalid")
        if any(path.startswith("data/") for path in files | directories):
            raise ValueError("staging data directory must be empty")
        if {path for path in files if path.startswith("libexec/")} != set(EXECUTABLES) - {"trestle", "trestled"}:
            raise ValueError("staging libexec inventory is invalid")
        if {path for path in files if path.startswith("release/")} != RELEASE_FILES:
            raise ValueError("staging release evidence inventory is invalid")
        license_files = sorted(path for path in files if path.startswith("licenses/"))
        if not license_files:
            raise ValueError("staging license inventory is empty")
        expected_files = set(EXECUTABLES) | {"LICENSE", "NOTICE", "ca-certificates.crt"} | RELEASE_FILES | set(license_files)
        if files != expected_files:
            raise ValueError("staging file inventory is invalid")
        payload: list[Payload] = []
        for source, (target, elf_type) in EXECUTABLES.items():
            body = _read_stable(staging / source, 0o555, source, root_descriptor, file_statuses[source])
            _validate_elf(body, source, elf_type)
            payload.append(Payload(source, target, 0o555, len(body), hashlib.sha256(body).hexdigest(), True, body))
        document_sources = ["LICENSE", "NOTICE", *license_files, *sorted(RELEASE_FILES)]
        for source in document_sources:
            body = _read_stable(staging / source, 0o444, source, root_descriptor, file_statuses[source])
            if source == "LICENSE" or source == "NOTICE":
                target = f"usr/local/share/licenses/open-trestle/{source}"
            elif source.startswith("licenses/"):
                target = "usr/local/share/licenses/open-trestle/third-party/" + source.removeprefix("licenses/")
            else:
                target = "usr/local/share/open-trestle/" + source
            payload.append(Payload(source, target, 0o444, len(body), hashlib.sha256(body).hexdigest(), False, body))
        root_after = os.fstat(root_descriptor)
        stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(root_before, key) != getattr(root_after, key) for key in stable):
            raise ValueError("staging directory changed while read")
    finally:
        os.close(root_descriptor)
    result = tuple(sorted(payload, key=lambda item: item.path))
    if len({item.path for item in result}) != len(result):
        raise ValueError("distribution target inventory is not unique")
    return result


def _zip_info(name: str, mode: int) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, FIXED_ZIP_TIME)
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | mode) << 16
    info.internal_attr = 0
    info.extra = b""
    info.comment = b""
    return info


def _write_archive(destination: BinaryIO, runtime: bytes, manifest: bytes, payload: tuple[Payload, ...]) -> None:
    destination.write(SHEBANG)
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
        members: dict[str, tuple[int, bytes]] = {
            "__main__.py": (0o555, runtime),
            "manifest.json": (0o444, manifest),
        }
        members.update({"payload/" + item.path: (item.mode, item.body) for item in payload})
        for name in sorted(members):
            mode, body = members[name]
            archive.writestr(_zip_info(name, mode), body)
    destination.flush()
    os.fsync(destination.fileno())


def _new_output(path: Path, mode: int) -> BinaryIO:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, mode)
    os.fchmod(descriptor, mode)
    return os.fdopen(descriptor, "w+b")


def _assert_absent(path: Path) -> None:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return
    raise ValueError(f"output already exists: {path.name}")


def _rename_noreplace(parent: Path, source_name: str, destination_name: str) -> None:
    renameat2 = getattr(ctypes.CDLL(None, use_errno=True), "renameat2", None)
    if renameat2 is None:
        raise OSError(errno.ENOSYS, "renameat2 is required for output cleanup")
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        result = renameat2(descriptor, os.fsencode(source_name), descriptor, os.fsencode(destination_name), 1)
        if result != 0:
            error_number = ctypes.get_errno()
            raise OSError(error_number, os.strerror(error_number))
    finally:
        os.close(descriptor)


def _remove_published_link(temporary: Path, output: Path) -> bool:
    quarantine = output.parent / f".{output.name}.remove-{uuid.uuid4().hex}"
    try:
        _rename_noreplace(output.parent, output.name, quarantine.name)
    except FileNotFoundError:
        return False
    try:
        if not os.path.samestat(os.stat(temporary, follow_symlinks=False), os.stat(quarantine, follow_symlinks=False)):
            try:
                _rename_noreplace(output.parent, quarantine.name, output.name)
            except OSError as error:
                raise ValueError(f"could not restore changed output: {output.name}") from error
            return False
        os.unlink(quarantine)
        return True
    finally:
        descriptor = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _publish_pair(archive_temp: Path, archive_output: Path, sidecar_temp: Path, sidecar_output: Path) -> None:
    linked: list[tuple[Path, Path]] = []
    try:
        os.link(archive_temp, archive_output, follow_symlinks=False)
        linked.append((archive_temp, archive_output))
        os.link(sidecar_temp, sidecar_output, follow_symlinks=False)
        linked.append((sidecar_temp, sidecar_output))
        directory_fd = os.open(archive_output.parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as error:
        for temporary, output in reversed(linked):
            _remove_published_link(temporary, output)
        try:
            directory_fd = os.open(archive_output.parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass
        if error.errno == errno.EEXIST:
            raise ValueError("output already exists") from error
        raise


def build_distribution(
    staging: Path,
    runtime: Path,
    output: Path,
    version: str,
    revision: str,
    created: str,
) -> tuple[Path, Path]:
    if sys.platform != "linux" or os.uname().machine not in {"x86_64", "amd64"}:
        raise ValueError("the Linux amd64 distribution must be built on Linux amd64")
    _validate_metadata(version, revision, created)
    staging = Path(os.path.abspath(staging))
    runtime = Path(os.path.abspath(runtime))
    output = Path(os.path.abspath(output))
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\.pyz", output.name):
        raise ValueError("output name must be a portable .pyz filename")
    sidecar = Path(str(output) + ".sha256")
    if not output.parent.is_dir() or output.parent.is_symlink():
        raise ValueError("output parent must be a real existing directory")
    _assert_absent(output)
    _assert_absent(sidecar)
    runtime_body = _read_stable(runtime, stat.S_IMODE(os.lstat(runtime).st_mode), "lifecycle runtime")
    if b"extractall" in runtime_body or b".extract(" in runtime_body:
        raise ValueError("lifecycle runtime must not use ZIP extraction APIs")
    payload = _collect_payload(staging)
    manifest_document = {
        "created": created,
        "files": [
            {
                "elf": item.elf,
                "mode": item.mode,
                "path": "payload/" + item.path,
                "sha256": item.sha256,
                "size": item.size,
                "source": item.source,
            }
            for item in payload
        ],
        "name": "open-trestle",
        "revision": revision,
        "schema_version": SCHEMA_VERSION,
        "target": "linux-amd64",
        "version": version,
    }
    manifest = _canonical_json(manifest_document)
    token = uuid.uuid4().hex
    archive_temp = output.parent / f".{output.name}.{token}.tmp"
    sidecar_temp = output.parent / f".{sidecar.name}.{token}.tmp"
    try:
        with _new_output(archive_temp, 0o555) as destination:
            _write_archive(destination, runtime_body, manifest, payload)
        digest = hashlib.sha256()
        with archive_temp.open("rb") as source:
            while chunk := source.read(1 << 20):
                digest.update(chunk)
        sidecar_body = f"{digest.hexdigest()}  {output.name}\n".encode("ascii")
        with _new_output(sidecar_temp, 0o444) as destination:
            destination.write(sidecar_body)
            destination.flush()
            os.fsync(destination.fileno())
        _publish_pair(archive_temp, output, sidecar_temp, sidecar)
    finally:
        for temporary in (archive_temp, sidecar_temp):
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    return output, sidecar


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build the deterministic unsigned Open Trestle Linux amd64 candidate.")
    parser.add_argument("--staging", type=Path, default=Path(".container"))
    parser.add_argument("--runtime", type=Path, default=Path(__file__).with_name("linux_distribution_runtime.py"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--created", required=True)
    return parser


def main(arguments: list[str] | None = None) -> int:
    options = _parser().parse_args(arguments)
    try:
        archive, sidecar = build_distribution(options.staging, options.runtime, options.output, options.version, options.revision, options.created)
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(archive)
    print(sidecar)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
