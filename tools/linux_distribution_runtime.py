"""Embedded lifecycle for the unsigned Open Trestle Linux amd64 candidate."""

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
import subprocess
import sys
import uuid
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Callable

SCHEMA_VERSION = 1
TARGET = "linux-amd64"
SHEBANG = b"#!/usr/bin/env python3\n"
MAX_ARCHIVE_SIZE = 256 * 1024 * 1024
MAX_MEMBER_SIZE = 128 * 1024 * 1024
MAX_FILES = 512
LIFECYCLE_PATH = "usr/local/libexec/open-trestle/open-trestle-distribution.pyz"
SIDECAR_PATH = LIFECYCLE_PATH + ".sha256"
RECEIPT_PATH = "usr/local/share/open-trestle/distribution/receipt.json"
JOURNAL_PATH = "usr/local/share/open-trestle/distribution/journal.json"
EXECUTABLE_PATHS = frozenset(
    {
        "usr/local/bin/trestle",
        "usr/local/bin/trestled",
        "usr/local/libexec/open-trestle/open-trestle-secret-scanner",
        "usr/local/libexec/open-trestle/open-trestle-secret-scanner-worker",
    }
)
EXECUTABLE_SOURCES = {
    "trestle": "usr/local/bin/trestle",
    "trestled": "usr/local/bin/trestled",
    "libexec/open-trestle/open-trestle-secret-scanner": "usr/local/libexec/open-trestle/open-trestle-secret-scanner",
    "libexec/open-trestle/open-trestle-secret-scanner-worker": "usr/local/libexec/open-trestle/open-trestle-secret-scanner-worker",
}
RELEASE_SOURCES = frozenset(
    {
        "release/secret-scanner-release.json",
        "release/secret-scanner.spdx.json",
        "release/vulnerability-scan.json",
    }
)
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)


@dataclass(frozen=True)
class InstalledFile:
    path: str
    mode: int
    size: int
    sha256: str
    elf: bool


@dataclass(frozen=True)
class ValidatedArchive:
    path: Path
    sha256: str
    size: int
    sidecar: Path
    manifest: dict[str, object]
    files: tuple[InstalledFile, ...]


def _json_loads(raw: bytes, label: str) -> object:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label} has duplicate keys")
            result[key] = value
        return result

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is not canonical JSON") from error


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def _sha256_stream(source: BinaryIO) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    while chunk := source.read(1 << 20):
        digest.update(chunk)
        size += len(chunk)
    return digest.hexdigest(), size


def _sha256_path(path: Path) -> tuple[str, int]:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("file is not regular")
            digest, size = _sha256_stream(source)
            after = os.fstat(source.fileno())
    except OSError as error:
        raise ValueError("file could not be read") from error
    stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if size != before.st_size or any(getattr(before, key) != getattr(after, key) for key in stable):
        raise ValueError("file changed while read")
    return digest, size


def _safe_relative_path(value: object, *, payload: bool = False) -> str:
    if not isinstance(value, str) or not value or len(value) > 240 or "\\" in value or "\x00" in value:
        raise ValueError("invalid distribution path")
    path = PurePosixPath(value)
    if path.is_absolute() or str(path) != value or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("invalid distribution path")
    if not all(re.fullmatch(r"[A-Za-z0-9._+-]+", part) for part in path.parts):
        raise ValueError("invalid distribution path")
    if payload and not value.startswith("payload/"):
        raise ValueError("payload path is required")
    return value


def _validate_elf(body: bytes, label: str) -> None:
    if len(body) < 64 or body[:16] != b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 8):
        raise ValueError(f"{label} is not a canonical ELF64 file")
    elf_type, machine, version = struct.unpack_from("<HHI", body, 16)
    expected_type = 3 if label.endswith("open-trestle-secret-scanner") else 2
    if elf_type != expected_type or machine != 62 or version != 1:
        raise ValueError(f"{label} is not the expected Linux amd64 executable")
    program_offset = struct.unpack_from("<Q", body, 32)[0]
    program_entry_size, program_count = struct.unpack_from("<HH", body, 54)
    if program_entry_size not in {0, 56} or program_count > 128:
        raise ValueError(f"{label} has invalid program headers")
    if program_count and (program_offset < 64 or program_offset + program_entry_size * program_count > len(body)):
        raise ValueError(f"{label} has invalid program headers")
    for index in range(program_count):
        offset = program_offset + index * program_entry_size
        program_type = struct.unpack_from("<I", body, offset)[0]
        if program_type == 3:
            raise ValueError(f"{label} has a dynamic interpreter")
        if program_type == 2:
            file_offset = struct.unpack_from("<Q", body, offset + 8)[0]
            file_size = struct.unpack_from("<Q", body, offset + 32)[0]
            if file_offset + file_size > len(body) or file_size % 16:
                raise ValueError(f"{label} has an invalid dynamic table")
            for dynamic_offset in range(file_offset, file_offset + file_size, 16):
                tag = struct.unpack_from("<q", body, dynamic_offset)[0]
                if tag == 1:
                    raise ValueError(f"{label} has a shared-library dependency")
                if tag == 0:
                    break


def _validate_sidecar(archive_path: Path, sidecar_path: Path, digest: str) -> None:
    try:
        descriptor = os.open(sidecar_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o444:
                raise ValueError("checksum sidecar is not a protected regular file")
            raw = source.read(1025)
            after = os.fstat(source.fileno())
    except OSError as error:
        raise ValueError("checksum sidecar is unavailable") from error
    stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if len(raw) != before.st_size or any(getattr(before, key) != getattr(after, key) for key in stable):
        raise ValueError("checksum sidecar changed while read")
    expected = f"{digest}  {archive_path.name}\n".encode("ascii")
    if raw != expected:
        raise ValueError("checksum sidecar does not match the archive")


def _manifest_files(document: object) -> tuple[InstalledFile, ...]:
    if not isinstance(document, dict) or set(document) != {"schema_version", "name", "version", "target", "revision", "created", "files"}:
        raise ValueError("manifest fields are invalid")
    if document["schema_version"] != SCHEMA_VERSION or document["name"] != "open-trestle":
        raise ValueError("manifest identity is invalid")
    if document["target"] != TARGET:
        raise ValueError("manifest target is invalid")
    if not isinstance(document["version"], str) or not re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", document["version"]):
        raise ValueError("manifest version is invalid")
    if not isinstance(document["revision"], str) or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", document["revision"]):
        raise ValueError("manifest revision is invalid")
    if not isinstance(document["created"], str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", document["created"]):
        raise ValueError("manifest creation time is invalid")
    try:
        datetime.strptime(document["created"], "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise ValueError("manifest creation time is invalid") from error
    raw_files = document["files"]
    if not isinstance(raw_files, list) or not raw_files or len(raw_files) > MAX_FILES:
        raise ValueError("manifest file inventory is invalid")
    files: list[InstalledFile] = []
    for raw in raw_files:
        if not isinstance(raw, dict) or set(raw) != {"path", "source", "mode", "size", "sha256", "elf"}:
            raise ValueError("manifest file fields are invalid")
        archive_name = _safe_relative_path(raw["path"], payload=True)
        source_name = _safe_relative_path(raw["source"])
        install_path = archive_name.removeprefix("payload/")
        if source_name in EXECUTABLE_SOURCES:
            expected_path = EXECUTABLE_SOURCES[source_name]
        elif source_name in {"LICENSE", "NOTICE"}:
            expected_path = "usr/local/share/licenses/open-trestle/" + source_name
        elif source_name.startswith("licenses/"):
            expected_path = "usr/local/share/licenses/open-trestle/third-party/" + source_name.removeprefix("licenses/")
        elif source_name in RELEASE_SOURCES:
            expected_path = "usr/local/share/open-trestle/" + source_name
        else:
            raise ValueError("manifest source inventory is invalid")
        if install_path != expected_path:
            raise ValueError("manifest source and target do not match")
        mode = raw["mode"]
        size = raw["size"]
        digest = raw["sha256"]
        elf = raw["elf"]
        if mode not in {0o444, 0o555} or not isinstance(size, int) or isinstance(size, bool) or size <= 0 or size > MAX_MEMBER_SIZE:
            raise ValueError("manifest file metadata is invalid")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest) or not isinstance(elf, bool):
            raise ValueError("manifest file metadata is invalid")
        if elf != (install_path in EXECUTABLE_PATHS) or mode != (0o555 if elf else 0o444):
            raise ValueError("manifest executable inventory is invalid")
        files.append(InstalledFile(install_path, mode, size, digest, elf))
    if [item.path for item in files] != sorted(item.path for item in files) or len({item.path for item in files}) != len(files):
        raise ValueError("manifest inventory is not unique and sorted")
    if {item.path for item in files if item.elf} != EXECUTABLE_PATHS:
        raise ValueError("manifest executable inventory is incomplete")
    required_docs = {
        "usr/local/share/licenses/open-trestle/LICENSE",
        "usr/local/share/licenses/open-trestle/NOTICE",
        "usr/local/share/open-trestle/release/secret-scanner-release.json",
        "usr/local/share/open-trestle/release/secret-scanner.spdx.json",
        "usr/local/share/open-trestle/release/vulnerability-scan.json",
    }
    paths = {item.path for item in files}
    if not required_docs <= paths or not any(path.startswith("usr/local/share/licenses/open-trestle/third-party/") for path in paths):
        raise ValueError("manifest documentation inventory is incomplete")
    forbidden = ("ca-certificates", "/data/", "/src/", "/source/", "/tests/", "/tools/", "private")
    if any(any(token in ("/" + path.lower() + "/") for token in forbidden) for path in paths):
        raise ValueError("manifest contains forbidden material")
    return tuple(files)




def _validate_local_headers(source: BinaryIO, infos: list[zipfile.ZipInfo], central_offset: int) -> None:
    expected_offset = len(SHEBANG)
    for item in infos:
        if item.header_offset != expected_offset:
            raise ValueError("distribution local records are not contiguous")
        source.seek(item.header_offset)
        header = source.read(30)
        if len(header) != 30:
            raise ValueError("distribution local header is truncated")
        signature, version, flags, method, modified_time, modified_date, crc, compressed_size, file_size, name_size, extra_size = struct.unpack("<IHHHHHIIIHH", header)
        name = source.read(name_size)
        extra = source.read(extra_size)
        if (
            signature != 0x04034B50
            or version != 20
            or flags != 0
            or method != zipfile.ZIP_STORED
            or modified_time != 0
            or modified_date != 33
            or crc != item.CRC
            or compressed_size != item.compress_size
            or file_size != item.file_size
            or name != item.filename.encode("ascii")
            or extra
        ):
            raise ValueError("distribution local header is invalid")
        expected_offset = item.header_offset + 30 + name_size + extra_size + item.compress_size
    if expected_offset != central_offset:
        raise ValueError("distribution local records do not end at the central directory")
    source.seek(central_offset)
    central_cursor = central_offset
    for item in infos:
        header = source.read(46)
        if len(header) != 46 or struct.unpack_from("<I", header)[0] != 0x02014B50:
            raise ValueError("distribution central directory is invalid")
        name_size, extra_size, comment_size = struct.unpack_from("<HHH", header, 28)
        name = source.read(name_size)
        extra = source.read(extra_size)
        comment = source.read(comment_size)
        if name != item.filename.encode("ascii") or extra or comment:
            raise ValueError("distribution central directory member is invalid")
        central_cursor += 46 + name_size + extra_size + comment_size
    end_record = source.read(22)
    if len(end_record) != 22:
        raise ValueError("distribution end record is invalid")
    signature, disk, central_disk, disk_count, total_count, central_size, recorded_offset, comment_size = struct.unpack("<IHHHHIIH", end_record)
    if (
        central_cursor != central_offset + central_size
        or signature != 0x06054B50
        or disk != 0
        or central_disk != 0
        or disk_count != len(infos)
        or total_count != len(infos)
        or recorded_offset != central_offset
        or comment_size != 0
        or source.read(1)
    ):
        raise ValueError("distribution end record is invalid")

def validate_archive(archive_path: Path, checksum_path: Path | None = None) -> ValidatedArchive:
    archive_path = Path(os.path.abspath(archive_path))
    checksum_path = Path(str(archive_path) + ".sha256") if checksum_path is None else Path(os.path.abspath(checksum_path))
    try:
        descriptor = os.open(archive_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        archive_source = os.fdopen(descriptor, "rb")
    except OSError as error:
        raise ValueError("distribution archive is unavailable") from error
    with archive_source:
        before = os.fstat(archive_source.fileno())
        if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o555:
            raise ValueError("distribution archive is not a protected regular file")
        digest, archive_size = _sha256_stream(archive_source)
        if archive_size != before.st_size or archive_size <= len(SHEBANG) or archive_size > MAX_ARCHIVE_SIZE:
            raise ValueError("distribution archive size is invalid")
        archive_source.seek(0)
        if archive_source.read(len(SHEBANG)) != SHEBANG:
            raise ValueError("distribution archive shebang is invalid")
        _validate_sidecar(archive_path, checksum_path, digest)
        archive_source.seek(0)
        try:
            archive = zipfile.ZipFile(archive_source)
        except (OSError, zipfile.BadZipFile) as error:
            raise ValueError("distribution archive is invalid") from error
        with archive:
            if archive.comment:
                raise ValueError("distribution archive comment is forbidden")
            infos = archive.infolist()
            _validate_local_headers(archive_source, infos, archive.start_dir)
            names = [item.filename for item in infos]
            if len(infos) < 3 or len(infos) > MAX_FILES + 2 or len(set(names)) != len(names) or names != sorted(names):
                raise ValueError("distribution archive inventory is invalid")
            for item in infos:
                _safe_relative_path(item.filename)
                mode = (item.external_attr >> 16) & 0o777777
                allowed_modes = {0o100555} if item.filename == "__main__.py" else ({0o100444} if item.filename == "manifest.json" else {0o100444, 0o100555})
                allowed_external_attributes = {value << 16 for value in allowed_modes}
                if item.create_system != 3 or item.create_version != 20 or item.extract_version != 20 or item.reserved != 0 or item.volume != 0 or item.internal_attr != 0 or item.external_attr not in allowed_external_attributes or item.compress_type != zipfile.ZIP_STORED or item.date_time != FIXED_ZIP_TIME or item.extra or item.comment or item.flag_bits != 0 or mode not in allowed_modes:
                    raise ValueError("distribution archive member metadata is invalid")
                if item.file_size <= 0 or item.file_size > MAX_MEMBER_SIZE or item.compress_size != item.file_size:
                    raise ValueError("distribution archive member size is invalid")
            if names[:1] != ["__main__.py"] or "manifest.json" not in names:
                raise ValueError("distribution archive control files are missing")
            manifest_raw = archive.read("manifest.json")
            manifest = _json_loads(manifest_raw, "manifest")
            if _canonical_json(manifest) != manifest_raw:
                raise ValueError("manifest is not canonical")
            files = _manifest_files(manifest)
            expected_names = {"__main__.py", "manifest.json"} | {"payload/" + item.path for item in files}
            if set(names) != expected_names:
                raise ValueError("distribution archive does not match its manifest")
            for item in files:
                info = archive.getinfo("payload/" + item.path)
                if info.file_size != item.size or ((info.external_attr >> 16) & 0o777777) != (stat.S_IFREG | item.mode):
                    raise ValueError("distribution member metadata does not match its manifest")
                with archive.open(info) as member_source:
                    member_digest, size = _sha256_stream(member_source)
                if size != item.size or member_digest != item.sha256:
                    raise ValueError("distribution member digest does not match its manifest")
                if item.elf:
                    with archive.open(info) as member_source:
                        _validate_elf(member_source.read(item.size + 1), item.path)
        after = os.fstat(archive_source.fileno())
        stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, key) != getattr(after, key) for key in stable):
            raise ValueError("distribution archive changed while verified")
    return ValidatedArchive(archive_path, digest, archive_size, checksum_path, manifest, files)


def _installation_root(destdir: Path | None) -> Path:
    if destdir is None:
        if os.geteuid() != 0:
            raise PermissionError("production lifecycle commands require root")
        return Path("/")
    root = Path(destdir)
    if not root.is_absolute() or root == Path("/"):
        raise ValueError("--destdir must be an absolute path other than /")
    root = Path(os.path.abspath(root))
    current = Path("/")
    for part in root.parts[1:]:
        current = current / part
        try:
            status = os.lstat(current)
        except OSError as error:
            raise ValueError("--destdir must be an existing real directory") from error
        if not stat.S_ISDIR(status.st_mode) or stat.S_ISLNK(status.st_mode):
            raise ValueError("--destdir must not contain symlink components")
    return root


def _is_production(root: Path) -> bool:
    return root == Path("/")


def _ensure_directory(root: Path, relative: str, created: list[str]) -> Path:
    current = root
    root_status = os.lstat(current)
    if not stat.S_ISDIR(root_status.st_mode) or stat.S_ISLNK(root_status.st_mode):
        raise ValueError("destination root is not a safe directory")
    for part in PurePosixPath(relative).parts:
        current = current / part
        try:
            status = os.lstat(current)
        except FileNotFoundError:
            os.mkdir(current, 0o755)
            if _is_production(root):
                os.chown(current, 0, 0)
            created.append(str(current.relative_to(root)))
            status = os.lstat(current)
        if not stat.S_ISDIR(status.st_mode) or stat.S_ISLNK(status.st_mode):
            raise ValueError("destination path contains a non-directory or symlink")
        if status.st_mode & 0o022:
            raise ValueError("destination directory is group or world writable")
        if _is_production(root) and (status.st_uid != 0 or status.st_gid != 0):
            raise ValueError("production destination directory is not root-owned")
    return current


def _open_new_file(parent: Path, name: str, mode: int) -> BinaryIO:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    parent_descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        descriptor = os.open(name, flags, mode, dir_fd=parent_descriptor)
    finally:
        os.close(parent_descriptor)
    os.fchmod(descriptor, mode)
    return os.fdopen(descriptor, "wb")


def _stage_file(parent: Path, final_name: str, mode: int, writer: Callable[[BinaryIO], None], transaction: str, production: bool = False) -> str:
    temporary = f".{final_name}.open-trestle-{transaction}"
    handle = _open_new_file(parent, temporary, mode)
    try:
        writer(handle)
        handle.flush()
        os.fsync(handle.fileno())
        if os.fstat(handle.fileno()).st_mode & 0o777 != mode:
            raise ValueError("staged file mode is invalid")
        if production:
            os.fchown(handle.fileno(), 0, 0)
    except BaseException:
        handle.close()
        try:
            os.unlink(parent / temporary)
        except FileNotFoundError:
            pass
        raise
    handle.close()
    return temporary


def _rename_noreplace(parent: Path, source_name: str, destination_name: str) -> tuple[int, int]:
    renameat2 = getattr(ctypes.CDLL(None, use_errno=True), "renameat2", None)
    if renameat2 is None:
        raise OSError(errno.ENOSYS, "renameat2 is required for no-replace lifecycle operations")
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    parent_descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        result = renameat2(parent_descriptor, os.fsencode(source_name), parent_descriptor, os.fsencode(destination_name), 1)
        if result != 0:
            error_number = ctypes.get_errno()
            if error_number == errno.EEXIST:
                raise FileExistsError(f"destination already exists: {destination_name}")
            raise OSError(error_number, os.strerror(error_number))
        status = os.stat(destination_name, dir_fd=parent_descriptor, follow_symlinks=False)
        return status.st_dev, status.st_ino
    finally:
        os.close(parent_descriptor)


def _publish_staged(parent: Path, temporary: str, final_name: str) -> tuple[int, int]:
    return _rename_noreplace(parent, temporary, final_name)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_staged_file(parent: Path, temporary: str, item: InstalledFile) -> None:
    path = parent / temporary
    status = os.lstat(path)
    if not stat.S_ISREG(status.st_mode) or stat.S_ISLNK(status.st_mode) or stat.S_IMODE(status.st_mode) != item.mode or status.st_size != item.size:
        raise ValueError(f"staged file metadata is invalid: {item.path}")
    digest, size = _sha256_path(path)
    if digest != item.sha256 or size != item.size:
        raise ValueError(f"staged file digest is invalid: {item.path}")
    if item.elf:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as source:
            _validate_elf(source.read(item.size + 1), item.path)

def _write_bytes(body: bytes) -> Callable[[BinaryIO], None]:
    return lambda destination: destination.write(body)


def _preflight_absent(root: Path, paths: tuple[str, ...]) -> None:
    for relative in paths:
        target = root / relative
        try:
            os.lstat(target)
        except FileNotFoundError:
            continue
        raise FileExistsError(f"destination already exists: {relative}")


def _receipt_file(item: InstalledFile) -> dict[str, object]:
    return {"elf": item.elf, "mode": item.mode, "path": item.path, "sha256": item.sha256, "size": item.size}


def _file_identity(path: Path) -> tuple[int, int]:
    status = os.lstat(path)
    return status.st_dev, status.st_ino


def _matches_owned_file(path: Path, item: InstalledFile, identity: tuple[int, int]) -> bool:
    try:
        status = os.lstat(path)
        if (
            not stat.S_ISREG(status.st_mode)
            or stat.S_ISLNK(status.st_mode)
            or (status.st_dev, status.st_ino) != identity
            or stat.S_IMODE(status.st_mode) != item.mode
            or status.st_size != item.size
        ):
            return False
        digest, size = _sha256_path(path)
        return digest == item.sha256 and size == item.size
    except (OSError, ValueError):
        return False


def _unlink_owned_file(path: Path, item: InstalledFile, identity: tuple[int, int]) -> bool:
    parent = path.parent
    quarantine_name = f".{path.name}.open-trestle-remove-{uuid.uuid4().hex}"
    try:
        captured_identity = _rename_noreplace(parent, path.name, quarantine_name)
    except FileNotFoundError:
        return False
    quarantine_path = parent / quarantine_name
    if captured_identity != identity or not _matches_owned_file(quarantine_path, item, identity):
        try:
            _rename_noreplace(parent, quarantine_name, path.name)
            _fsync_directory(parent)
        except OSError as error:
            raise ValueError(f"could not restore changed file: {item.path}") from error
        return False
    parent_descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.unlink(quarantine_name, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)
    return True


def install(archive_path: Path, destdir: Path | None = None) -> None:
    root = _installation_root(destdir)
    validated = validate_archive(archive_path)
    installed_sidecar_body = f"{validated.sha256}  {PurePosixPath(LIFECYCLE_PATH).name}\n".encode("ascii")
    archive_mode = 0o555
    sidecar_mode = 0o444
    managed = list(validated.files) + [
        InstalledFile(LIFECYCLE_PATH, archive_mode, validated.size, validated.sha256, False),
        InstalledFile(SIDECAR_PATH, sidecar_mode, len(installed_sidecar_body), hashlib.sha256(installed_sidecar_body).hexdigest(), False),
    ]
    all_paths = tuple(item.path for item in managed) + (RECEIPT_PATH, JOURNAL_PATH)
    _preflight_absent(root, all_paths)
    created: list[str] = []
    transaction = uuid.uuid4().hex
    staged: list[tuple[Path, str, str, InstalledFile, tuple[int, int]]] = []
    published: list[tuple[InstalledFile, tuple[int, int]]] = []
    control_published: list[tuple[Path, InstalledFile, tuple[int, int]]] = []
    try:
        archive_descriptor = os.open(validated.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(archive_descriptor, "rb") as archive_source:
            before = os.fstat(archive_source.fileno())
            archive_digest, archive_size = _sha256_stream(archive_source)
            if archive_digest != validated.sha256 or archive_size != before.st_size:
                raise ValueError("distribution archive changed before installation")
            archive_source.seek(0)
            with zipfile.ZipFile(archive_source) as archive:
                for item in validated.files:
                    parent = _ensure_directory(root, str(PurePosixPath(item.path).parent), created)
                    name = PurePosixPath(item.path).name
                    def archive_writer(destination: BinaryIO, archive_name: str = "payload/" + item.path) -> None:
                        with archive.open(archive_name) as source:
                            while chunk := source.read(1 << 20):
                                destination.write(chunk)
                    temporary = _stage_file(parent, name, item.mode, archive_writer, transaction, _is_production(root))
                    staged.append((parent, temporary, name, item, _file_identity(parent / temporary)))
            lifecycle_item, lifecycle_sidecar_item = managed[-2:]
            parent = _ensure_directory(root, str(PurePosixPath(lifecycle_item.path).parent), created)
            name = PurePosixPath(lifecycle_item.path).name
            archive_source.seek(0)
            def lifecycle_writer(destination: BinaryIO) -> None:
                while chunk := archive_source.read(1 << 20):
                    destination.write(chunk)
            temporary = _stage_file(parent, name, lifecycle_item.mode, lifecycle_writer, transaction, _is_production(root))
            staged.append((parent, temporary, name, lifecycle_item, _file_identity(parent / temporary)))
            after = os.fstat(archive_source.fileno())
            stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            if any(getattr(before, key) != getattr(after, key) for key in stable):
                raise ValueError("distribution archive changed during installation")
        parent = _ensure_directory(root, str(PurePosixPath(lifecycle_sidecar_item.path).parent), created)
        name = PurePosixPath(lifecycle_sidecar_item.path).name
        temporary = _stage_file(parent, name, lifecycle_sidecar_item.mode, _write_bytes(installed_sidecar_body), transaction, _is_production(root))
        staged.append((parent, temporary, name, lifecycle_sidecar_item, _file_identity(parent / temporary)))
        for item, (parent, temporary, _, staged_item, _) in zip(managed, staged, strict=True):
            if item != staged_item:
                raise ValueError("staged file inventory is inconsistent")
            _validate_staged_file(parent, temporary, item)
        for item, (parent, temporary, name, staged_item, _) in zip(managed, staged, strict=True):
            if item != staged_item:
                raise ValueError("staged file inventory is inconsistent")
            identity = _publish_staged(parent, temporary, name)
            published.append((item, identity))
            _fsync_directory(parent)
        control_parent = _ensure_directory(root, str(PurePosixPath(RECEIPT_PATH).parent), created)
        created_directories = sorted(
            set(created), key=lambda value: (value.count("/"), value)
        )
        manifest_digest = hashlib.sha256(_canonical_json(validated.manifest)).hexdigest()
        receipt = {
            "archive_sha256": validated.sha256,
            "created_directories": created_directories,
            "files": [_receipt_file(item) for item in sorted(managed, key=lambda value: value.path)],
            "manifest_sha256": manifest_digest,
            "schema_version": SCHEMA_VERSION,
            "target": TARGET,
            "transaction": transaction,
            "version": validated.manifest["version"],
        }
        receipt_body = _canonical_json(receipt)
        journal = {
            "action": "install",
            "archive_sha256": validated.sha256,
            "receipt_sha256": hashlib.sha256(receipt_body).hexdigest(),
            "schema_version": SCHEMA_VERSION,
            "transaction": transaction,
        }
        if created_directories != sorted(
            set(created), key=lambda value: (value.count("/"), value)
        ):
            raise ValueError("installation directory inventory changed after receipt snapshot")
        receipt_temp = _stage_file(control_parent, PurePosixPath(RECEIPT_PATH).name, 0o444, _write_bytes(receipt_body), transaction, _is_production(root))
        receipt_item = InstalledFile(RECEIPT_PATH, 0o444, len(receipt_body), hashlib.sha256(receipt_body).hexdigest(), False)
        staged.append((control_parent, receipt_temp, PurePosixPath(RECEIPT_PATH).name, receipt_item, _file_identity(control_parent / receipt_temp)))
        receipt_identity = _publish_staged(control_parent, receipt_temp, PurePosixPath(RECEIPT_PATH).name)
        receipt_path = root / RECEIPT_PATH
        control_published.append((receipt_path, receipt_item, receipt_identity))
        _fsync_directory(control_parent)
        journal_body = _canonical_json(journal)
        journal_temp = _stage_file(control_parent, PurePosixPath(JOURNAL_PATH).name, 0o444, _write_bytes(journal_body), transaction, _is_production(root))
        journal_item = InstalledFile(JOURNAL_PATH, 0o444, len(journal_body), hashlib.sha256(journal_body).hexdigest(), False)
        staged.append((control_parent, journal_temp, PurePosixPath(JOURNAL_PATH).name, journal_item, _file_identity(control_parent / journal_temp)))
        journal_identity = _publish_staged(control_parent, journal_temp, PurePosixPath(JOURNAL_PATH).name)
        journal_path = root / JOURNAL_PATH
        control_published.append((journal_path, journal_item, journal_identity))
        _fsync_directory(control_parent)
    except BaseException:
        for parent, temporary, _, item, identity in staged:
            _unlink_owned_file(parent / temporary, item, identity)
        for path, item, identity in reversed(control_published):
            _unlink_owned_file(path, item, identity)
        for item, identity in reversed(published):
            _unlink_owned_file(root / item.path, item, identity)
        _remove_created_directories(root, created)
        raise


def _read_control_file(root: Path, relative: str) -> bytes:
    path = root / relative
    try:
        status = os.lstat(path)
    except OSError as error:
        raise ValueError("installation receipt or journal is unavailable") from error
    if not stat.S_ISREG(status.st_mode) or stat.S_ISLNK(status.st_mode) or stat.S_IMODE(status.st_mode) != 0o444:
        raise ValueError("installation receipt or journal is not protected")
    if _is_production(root) and (status.st_uid != 0 or status.st_gid != 0):
        raise ValueError("installation receipt or journal is not root-owned")
    _validate_directory_chain(root, str(PurePosixPath(relative).parent))
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as source:
            before = os.fstat(source.fileno())
            body = source.read((1 << 20) + 1)
            after = os.fstat(source.fileno())
    except OSError as error:
        raise ValueError("installation receipt or journal could not be read") from error
    stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if (before.st_dev, before.st_ino) != (status.st_dev, status.st_ino) or len(body) > (1 << 20) or len(body) != before.st_size or any(getattr(before, key) != getattr(after, key) for key in stable):
        raise ValueError("installation receipt or journal changed while read")
    return body


def _load_control(root: Path) -> tuple[dict[str, object], dict[str, object], tuple[InstalledFile, ...]]:
    receipt_raw = _read_control_file(root, RECEIPT_PATH)
    journal_raw = _read_control_file(root, JOURNAL_PATH)
    receipt = _json_loads(receipt_raw, "receipt")
    journal = _json_loads(journal_raw, "journal")
    if not isinstance(receipt, dict) or set(receipt) != {"archive_sha256", "created_directories", "files", "manifest_sha256", "schema_version", "target", "transaction", "version"}:
        raise ValueError("installation receipt fields are invalid")
    if not isinstance(journal, dict) or set(journal) != {"action", "archive_sha256", "receipt_sha256", "schema_version", "transaction"}:
        raise ValueError("installation journal fields are invalid")
    if receipt["schema_version"] != SCHEMA_VERSION or receipt["target"] != TARGET or journal["schema_version"] != SCHEMA_VERSION or journal["action"] != "install":
        raise ValueError("installation control identity is invalid")
    digest_fields = (receipt["archive_sha256"], receipt["manifest_sha256"], journal["archive_sha256"], journal["receipt_sha256"])
    if any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) for value in digest_fields):
        raise ValueError("installation control digest is invalid")
    if not isinstance(receipt["transaction"], str) or not re.fullmatch(r"[0-9a-f]{32}", receipt["transaction"]):
        raise ValueError("installation transaction is invalid")
    if not isinstance(receipt["version"], str) or not re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", receipt["version"]):
        raise ValueError("installation version is invalid")
    if journal["transaction"] != receipt["transaction"] or journal["archive_sha256"] != receipt["archive_sha256"] or journal["receipt_sha256"] != hashlib.sha256(receipt_raw).hexdigest():
        raise ValueError("installation journal does not bind the receipt")
    raw_files = receipt["files"]
    if not isinstance(raw_files, list) or not raw_files:
        raise ValueError("installation receipt inventory is invalid")
    files: list[InstalledFile] = []
    for raw in raw_files:
        if not isinstance(raw, dict) or set(raw) != {"elf", "mode", "path", "sha256", "size"}:
            raise ValueError("installation receipt file is invalid")
        path = _safe_relative_path(raw["path"])
        if raw["mode"] not in {0o444, 0o555} or not isinstance(raw["size"], int) or raw["size"] <= 0 or not isinstance(raw["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", raw["sha256"]) or not isinstance(raw["elf"], bool):
            raise ValueError("installation receipt file metadata is invalid")
        files.append(InstalledFile(path, raw["mode"], raw["size"], raw["sha256"], raw["elf"]))
    if [item.path for item in files] != sorted(item.path for item in files) or len({item.path for item in files}) != len(files):
        raise ValueError("installation receipt inventory is invalid")
    if {item.path for item in files if item.elf} != EXECUTABLE_PATHS or LIFECYCLE_PATH not in {item.path for item in files} or SIDECAR_PATH not in {item.path for item in files}:
        raise ValueError("installation receipt inventory is incomplete")
    created = receipt["created_directories"]
    if not isinstance(created, list) or len(set(created)) != len(created) or any(not isinstance(value, str) or value == "." or _safe_relative_path(value) != value for value in created):
        raise ValueError("installation directory inventory is invalid")
    allowed_directories: set[str] = set()
    for owned_path in [item.path for item in files] + [RECEIPT_PATH, JOURNAL_PATH]:
        parent = PurePosixPath(owned_path).parent
        while str(parent) != ".":
            allowed_directories.add(str(parent))
            parent = parent.parent
    if not set(created) <= allowed_directories:
        raise ValueError("installation directory inventory is out of scope")
    return receipt, journal, tuple(files)




def _validate_directory_chain(root: Path, relative: str) -> None:
    current = root
    for part in PurePosixPath(relative).parts:
        current = current / part
        try:
            status = os.lstat(current)
        except OSError as error:
            raise ValueError("installed file ancestor is unavailable") from error
        if not stat.S_ISDIR(status.st_mode) or stat.S_ISLNK(status.st_mode) or status.st_mode & 0o022:
            raise ValueError("installed file ancestor is not trusted")
        if _is_production(root) and (status.st_uid != 0 or status.st_gid != 0):
            raise ValueError("installed file ancestor is not root-owned")

def _validate_installed_file(root: Path, item: InstalledFile) -> os.stat_result:
    path = root / item.path
    try:
        status = os.lstat(path)
    except OSError as error:
        raise ValueError(f"installed file is unavailable: {item.path}") from error
    if not stat.S_ISREG(status.st_mode) or stat.S_ISLNK(status.st_mode) or stat.S_IMODE(status.st_mode) != item.mode or status.st_size != item.size:
        raise ValueError(f"installed file metadata does not match receipt: {item.path}")
    if _is_production(root) and (status.st_uid != 0 or status.st_gid != 0):
        raise ValueError(f"installed file is not root-owned: {item.path}")
    digest, size = _sha256_path(path)
    if digest != item.sha256 or size != item.size:
        raise ValueError(f"installed file digest does not match receipt: {item.path}")
    if item.elf:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as source:
            _validate_elf(source.read(item.size + 1), item.path)
    _validate_directory_chain(root, str(PurePosixPath(item.path).parent))
    return status


def verify_installed(archive_path: Path, destdir: Path | None = None) -> dict[str, object]:
    root = _installation_root(destdir)
    validated = validate_archive(archive_path)
    receipt, _, files = _load_control(root)
    if receipt["archive_sha256"] != validated.sha256:
        raise ValueError("installed receipt belongs to a different archive")
    manifest_digest = hashlib.sha256(_canonical_json(validated.manifest)).hexdigest()
    if receipt["manifest_sha256"] != manifest_digest:
        raise ValueError("installed receipt does not match the manifest")
    installed_sidecar_body = f"{validated.sha256}  {PurePosixPath(LIFECYCLE_PATH).name}\n".encode("ascii")
    expected_files = tuple(sorted(
        (*validated.files,
         InstalledFile(LIFECYCLE_PATH, 0o555, validated.size, validated.sha256, False),
         InstalledFile(SIDECAR_PATH, 0o444, len(installed_sidecar_body), hashlib.sha256(installed_sidecar_body).hexdigest(), False)),
        key=lambda item: item.path,
    ))
    if files != expected_files:
        raise ValueError("installed receipt inventory does not match the archive")
    for item in files:
        _validate_installed_file(root, item)
    return receipt


def _remove_created_directories(root: Path, directories: list[str] | tuple[str, ...]) -> None:
    for relative in sorted(set(directories), key=lambda value: (value.count("/"), value), reverse=True):
        if relative == ".":
            continue
        try:
            (root / relative).rmdir()
        except (FileNotFoundError, OSError):
            pass


def _remove_installation(archive_path: Path, destdir: Path | None, action: str) -> None:
    root = _installation_root(destdir)
    receipt = verify_installed(archive_path, destdir)
    _, _, files = _load_control(root)
    owned: list[tuple[Path, InstalledFile, tuple[int, int]]] = []
    for item in files:
        status = _validate_installed_file(root, item)
        owned.append((root / item.path, item, (status.st_dev, status.st_ino)))
    controls: list[tuple[Path, InstalledFile, tuple[int, int]]] = []
    for relative in (JOURNAL_PATH, RECEIPT_PATH):
        body = _read_control_file(root, relative)
        path = root / relative
        status = os.lstat(path)
        item = InstalledFile(relative, 0o444, len(body), hashlib.sha256(body).hexdigest(), False)
        controls.append((path, item, (status.st_dev, status.st_ino)))
    for path, item, identity in [*owned, *controls]:
        if not _matches_owned_file(path, item, identity):
            raise ValueError(f"owned file changed before {action}: {item.path}")
    for path, item, identity in sorted(owned, key=lambda value: value[1].path, reverse=True):
        if not _unlink_owned_file(path, item, identity):
            raise ValueError(f"owned file changed during {action}: {item.path}")
    for path, item, identity in controls:
        if not _unlink_owned_file(path, item, identity):
            raise ValueError(f"control file changed during {action}: {item.path}")
    created = receipt["created_directories"]
    assert isinstance(created, list)
    _remove_created_directories(root, created)


def rollback(archive_path: Path, destdir: Path | None = None) -> None:
    _remove_installation(archive_path, destdir, "rollback")


def uninstall(archive_path: Path, destdir: Path | None = None) -> None:
    _remove_installation(archive_path, destdir, "uninstall")


def smoke(archive_path: Path, destdir: Path | None = None, output: Path | None = None) -> dict[str, object]:
    root = _installation_root(destdir)
    receipt = verify_installed(archive_path, destdir)
    executable = root / "usr/local/bin/trestle"
    completed = subprocess.run(
        [str(executable)],
        cwd=root,
        env={"HOME": "/nonexistent", "LANG": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )
    if completed.returncode != 2 or completed.stdout or not completed.stderr.startswith(b"usage: trestle ") or len(completed.stderr) > 65536:
        raise ValueError("trestle command-boundary smoke probe failed")
    document = {
        "archive_sha256": receipt["archive_sha256"],
        "command": "trestle",
        "expected_exit_code": 2,
        "scanner": "integrity_verified_not_executed_in_destdir" if root != Path("/") else "integrity_verified_not_executed",
        "schema_version": SCHEMA_VERSION,
        "status": "passed_expected_usage",
        "target": TARGET,
        "version": receipt["version"],
    }
    body = _canonical_json(document)
    if output is None:
        sys.stdout.buffer.write(body)
    else:
        output = Path(output)
        if not output.is_absolute() or output.exists():
            raise ValueError("smoke output must be a new absolute path")
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o444)
        try:
            os.fchmod(descriptor, 0o444)
            view = memoryview(body)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("smoke evidence write made no progress")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _fsync_directory(output.parent)
    return document


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify and manage the unsigned Open Trestle Linux amd64 candidate.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify_parser = subparsers.add_parser("verify-archive", aliases=["verify"])
    verify_parser.add_argument("--checksum", type=Path)
    for command in ("install", "verify-installed", "rollback", "uninstall"):
        child = subparsers.add_parser(command)
        child.add_argument("--destdir", type=Path)
    smoke_parser = subparsers.add_parser("smoke")
    smoke_parser.add_argument("--destdir", type=Path)
    smoke_parser.add_argument("--output", type=Path)
    return parser


def main(arguments: list[str] | None = None) -> int:
    parser = _parser()
    options = parser.parse_args(arguments)
    archive_path = Path(os.path.abspath(sys.argv[0]))
    try:
        if options.command in {"verify", "verify-archive"}:
            validate_archive(archive_path, options.checksum)
            print("Open Trestle candidate archive verified.")
        elif options.command == "install":
            install(archive_path, options.destdir)
            print("Open Trestle candidate installed.")
        elif options.command == "verify-installed":
            verify_installed(archive_path, options.destdir)
            print("Open Trestle candidate installation verified.")
        elif options.command == "smoke":
            smoke(archive_path, options.destdir, options.output)
        elif options.command == "rollback":
            rollback(archive_path, options.destdir)
            print("Open Trestle candidate installation rolled back.")
        elif options.command == "uninstall":
            uninstall(archive_path, options.destdir)
            print("Open Trestle candidate uninstalled.")
    except (OSError, ValueError, PermissionError, zipfile.BadZipFile) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
