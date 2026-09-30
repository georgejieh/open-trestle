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
CONTROL_SCHEMA_VERSION = 3
TRANSACTION_SCHEMA_VERSION = 1
TARGET = "linux-amd64"
BOOTSTRAP_ANCHOR = ".open-trestle-linux-amd64.transaction.bootstrap.json"
PENDING_ANCHOR = ".open-trestle-linux-amd64.transaction.pending.json"
COMMITTED_ANCHOR = ".open-trestle-linux-amd64.transaction.committed.json"
TRANSACTION_ANCHORS = (BOOTSTRAP_ANCHOR, PENDING_ANCHOR, COMMITTED_ANCHOR)
GENERATION_DOMAIN = b"open-trestle-linux-generation-v1\0"
TRANSACTION_DOMAIN = b"open-trestle-linux-transaction-plan-v1\0"
MAX_TRANSACTION_SIZE = 1 << 20
SHEBANG = b"#!/usr/bin/env python3\n"
MAX_ARCHIVE_SIZE = 256 * 1024 * 1024
MAX_MEMBER_SIZE = 128 * 1024 * 1024
MAX_FILES = 512
LIFECYCLE_PATH = "usr/local/libexec/open-trestle/open-trestle-distribution.pyz"
SIDECAR_PATH = LIFECYCLE_PATH + ".sha256"
RECEIPT_PATH = "usr/local/share/open-trestle/distribution/receipt.json"
JOURNAL_PATH = "usr/local/share/open-trestle/distribution/journal.json"
PREVIOUS_ARCHIVE_PATH = "usr/local/share/open-trestle/distribution/previous.pyz"
PREVIOUS_SIDECAR_PATH = PREVIOUS_ARCHIVE_PATH + ".sha256"
PREVIOUS_RECEIPT_PATH = "usr/local/share/open-trestle/distribution/previous-receipt.json"
PREVIOUS_JOURNAL_PATH = "usr/local/share/open-trestle/distribution/previous-journal.json"
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


def _generation_core(
    archive_sha256: str,
    manifest_sha256: str,
    version: str,
    files: tuple[InstalledFile, ...] | list[InstalledFile],
) -> dict[str, object]:
    ordered = sorted(files, key=lambda item: item.path)
    if len({item.path for item in ordered}) != len(ordered):
        raise ValueError("generation inventory is not unique")
    return {
        "archive_sha256": archive_sha256,
        "files": [_receipt_file(item) for item in ordered],
        "manifest_sha256": manifest_sha256,
        "schema_version": 1,
        "target": TARGET,
        "version": version,
    }


def _validate_generation_core(value: object) -> dict[str, object]:
    fields = {"archive_sha256", "files", "manifest_sha256", "schema_version", "target", "version"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("transaction generation fields are invalid")
    if value["schema_version"] != 1 or value["target"] != TARGET:
        raise ValueError("transaction generation identity is invalid")
    for key in ("archive_sha256", "manifest_sha256"):
        if not isinstance(value[key], str) or not re.fullmatch(r"[0-9a-f]{64}", value[key]):
            raise ValueError("transaction generation digest is invalid")
    _version_precedence(value["version"])
    raw_files = value["files"]
    if not isinstance(raw_files, list) or len(raw_files) > MAX_FILES:
        raise ValueError("transaction generation inventory is invalid")
    paths: list[str] = []
    for raw in raw_files:
        if not isinstance(raw, dict) or set(raw) != {"elf", "mode", "path", "sha256", "size"}:
            raise ValueError("transaction generation file is invalid")
        path = _safe_relative_path(raw["path"])
        if raw["mode"] not in {0o444, 0o555} or not isinstance(raw["size"], int) or isinstance(raw["size"], bool) or raw["size"] <= 0:
            raise ValueError("transaction generation file metadata is invalid")
        if not isinstance(raw["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", raw["sha256"]) or not isinstance(raw["elf"], bool):
            raise ValueError("transaction generation file metadata is invalid")
        paths.append(path)
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise ValueError("transaction generation inventory is not canonical")
    return value


def _generation_identity(core: dict[str, object]) -> str:
    _validate_generation_core(core)
    return hashlib.sha256(GENERATION_DOMAIN + _canonical_json(core)).hexdigest()


def _owner_matches(status: os.stat_result, uid: int | None, gid: int | None) -> bool:
    return (uid is None or status.st_uid == uid) and (gid is None or status.st_gid == gid)


def _descriptor(item: InstalledFile, root: Path) -> dict[str, object]:
    owner = 0 if _is_production(root) else None
    return {
        "elf": item.elf,
        "gid": owner,
        "mode": item.mode,
        "sha256": item.sha256,
        "size": item.size,
        "uid": owner,
    }


def _parse_descriptor(value: object) -> dict[str, object]:
    fields = {"elf", "gid", "mode", "sha256", "size", "uid"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("transaction file descriptor fields are invalid")
    if value["mode"] not in {0o444, 0o555}:
        raise ValueError("transaction file mode is invalid")
    if not isinstance(value["size"], int) or isinstance(value["size"], bool) or value["size"] <= 0 or value["size"] > MAX_ARCHIVE_SIZE:
        raise ValueError("transaction file size is invalid")
    if not isinstance(value["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["sha256"]):
        raise ValueError("transaction file digest is invalid")
    if not isinstance(value["elf"], bool):
        raise ValueError("transaction file ELF flag is invalid")
    for key in ("uid", "gid"):
        if value[key] is not None and (not isinstance(value[key], int) or isinstance(value[key], bool) or value[key] < 0):
            raise ValueError("transaction file owner is invalid")
    if (value["uid"] is None) != (value["gid"] is None):
        raise ValueError("transaction file owner policy is incomplete")
    return value


def _transaction_names(relative: str, transaction: str) -> tuple[str, str]:
    path = PurePosixPath(relative)
    staged = str(path.parent / f".{path.name}.open-trestle-{transaction}")
    quarantine = str(path.parent / f".{path.name}.open-trestle-old-{transaction}")
    return staged, quarantine


def _transaction_plan(
    *,
    action: str,
    transaction: str,
    old_generation: dict[str, object] | None,
    new_generation: dict[str, object],
    old_receipt_sha256: str | None,
    old_journal_sha256: str | None,
    new_receipt_sha256: str,
    new_journal_sha256: str,
    created_directories: list[str],
    obsolete_directories: list[str],
    paths: list[dict[str, object]],
) -> dict[str, object]:
    return {
        "action": action,
        "created_directories": sorted(created_directories, key=lambda value: (value.count("/"), value)),
        "new_generation": new_generation,
        "new_generation_id": _generation_identity(new_generation),
        "new_journal_sha256": new_journal_sha256,
        "new_receipt_sha256": new_receipt_sha256,
        "obsolete_directories": sorted(obsolete_directories, key=lambda value: (value.count("/"), value), reverse=True),
        "old_generation": old_generation,
        "old_generation_id": None if old_generation is None else _generation_identity(old_generation),
        "old_journal_sha256": old_journal_sha256,
        "old_receipt_sha256": old_receipt_sha256,
        "paths": sorted(paths, key=lambda value: value["final"]),
        "target": TARGET,
        "transaction": transaction,
    }


def _transaction_envelope(plan: dict[str, object]) -> bytes:
    _validate_transaction_plan(plan)
    return _canonical_json({
        "plan": plan,
        "plan_sha256": hashlib.sha256(TRANSACTION_DOMAIN + _canonical_json(plan)).hexdigest(),
        "schema_version": TRANSACTION_SCHEMA_VERSION,
    })


def _validate_transaction_plan(plan: object) -> dict[str, object]:
    fields = {
        "action", "created_directories", "new_generation", "new_generation_id", "new_journal_sha256",
        "new_receipt_sha256", "obsolete_directories", "old_generation", "old_generation_id",
        "old_journal_sha256", "old_receipt_sha256", "paths", "target", "transaction",
    }
    if not isinstance(plan, dict) or set(plan) != fields:
        raise ValueError("transaction plan fields are invalid")
    if plan["target"] != TARGET or plan["action"] not in {"install", "upgrade", "rollback-version"}:
        raise ValueError("transaction plan identity is invalid")
    transaction = plan["transaction"]
    if not isinstance(transaction, str) or not re.fullmatch(r"[0-9a-f]{32}", transaction):
        raise ValueError("transaction identifier is invalid")
    new_generation = _validate_generation_core(plan["new_generation"])
    old_generation = plan["old_generation"]
    if old_generation is not None:
        _validate_generation_core(old_generation)
    if plan["new_generation_id"] != _generation_identity(new_generation):
        raise ValueError("transaction new generation identity does not match")
    expected_old_generation_id = None if old_generation is None else _generation_identity(old_generation)
    if plan["old_generation_id"] != expected_old_generation_id:
        raise ValueError("transaction old generation identity does not match")
    if plan["action"] == "install" and old_generation is not None:
        raise ValueError("install transaction has an old generation")
    if plan["action"] != "install" and old_generation is None:
        raise ValueError("transition transaction has no old generation")
    for key in ("new_receipt_sha256", "new_journal_sha256"):
        if not isinstance(plan[key], str) or not re.fullmatch(r"[0-9a-f]{64}", plan[key]):
            raise ValueError("transaction control digest is invalid")
    for key in ("old_receipt_sha256", "old_journal_sha256"):
        value = plan[key]
        if plan["action"] == "install":
            if value is not None:
                raise ValueError("install transaction has old controls")
        elif not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("transaction old control digest is invalid")
    for key in ("created_directories", "obsolete_directories"):
        values = plan[key]
        if not isinstance(values, list) or len(values) != len(set(values)):
            raise ValueError("transaction directory inventory is invalid")
        expected = sorted(values, key=lambda value: (value.count("/"), value), reverse=(key == "obsolete_directories"))
        if values != expected:
            raise ValueError("transaction directory inventory is not sorted")
        for value in values:
            if not isinstance(value, str) or value == "." or _safe_relative_path(value) != value:
                raise ValueError("transaction directory path is invalid")
    entries = plan["paths"]
    if not isinstance(entries, list) or len(entries) > MAX_FILES * 3:
        raise ValueError("transaction path inventory is invalid")
    finals: list[str] = []
    for entry in entries:
        entry_fields = {"final", "new", "old", "quarantine", "staged"}
        if not isinstance(entry, dict) or set(entry) != entry_fields:
            raise ValueError("transaction path fields are invalid")
        final = _safe_relative_path(entry["final"])
        staged, quarantine = _transaction_names(final, transaction)
        if entry["staged"] != staged or entry["quarantine"] != quarantine:
            raise ValueError("transaction derived path does not match")
        if entry["old"] is None and entry["new"] is None:
            raise ValueError("transaction path has no generation")
        if entry["old"] is not None:
            _parse_descriptor(entry["old"])
        if entry["new"] is not None:
            _parse_descriptor(entry["new"])
        finals.append(final)
    if finals != sorted(finals) or len(finals) != len(set(finals)):
        raise ValueError("transaction path inventory is not unique and sorted")
    allowed_directories: set[str] = set()
    for final in finals:
        parent = PurePosixPath(final).parent
        while str(parent) != ".":
            allowed_directories.add(str(parent))
            parent = parent.parent
    if not set(plan["created_directories"]) <= allowed_directories or not set(plan["obsolete_directories"]) <= allowed_directories:
        raise ValueError("transaction directory inventory is outside lifecycle scope")
    generation_paths = {item["path"] for item in new_generation["files"]}
    if isinstance(old_generation, dict):
        generation_paths |= {item["path"] for item in old_generation["files"]}
    allowed = generation_paths | {
        RECEIPT_PATH, JOURNAL_PATH, PREVIOUS_ARCHIVE_PATH, PREVIOUS_SIDECAR_PATH,
        PREVIOUS_RECEIPT_PATH, PREVIOUS_JOURNAL_PATH,
    }
    if not set(finals) <= allowed:
        raise ValueError("transaction path is outside lifecycle scope")
    entry_by_final = {entry["final"]: entry for entry in entries}
    control_paths = {RECEIPT_PATH, JOURNAL_PATH}
    previous_paths = {
        PREVIOUS_ARCHIVE_PATH, PREVIOUS_SIDECAR_PATH,
        PREVIOUS_RECEIPT_PATH, PREVIOUS_JOURNAL_PATH,
    }
    new_generation_paths = {item["path"] for item in new_generation["files"]}
    old_generation_paths = set()
    if isinstance(old_generation, dict):
        old_generation_paths = {item["path"] for item in old_generation["files"]}
    expected_paths = new_generation_paths | old_generation_paths | control_paths
    if plan["action"] != "install":
        expected_paths |= previous_paths
    if set(finals) != expected_paths:
        raise ValueError("transaction path inventory does not close over its generations")
    for side, generation in (("new", new_generation), ("old", old_generation)):
        if not isinstance(generation, dict):
            continue
        for item in generation["files"]:
            descriptor = entry_by_final[item["path"]][side]
            if descriptor is None or any(descriptor[key] != item[key] for key in ("elf", "mode", "sha256", "size")):
                raise ValueError("transaction descriptor does not match its generation")
    for side, receipt_key, journal_key in (
        ("new", "new_receipt_sha256", "new_journal_sha256"),
        ("old", "old_receipt_sha256", "old_journal_sha256"),
    ):
        expected_receipt = plan[receipt_key]
        expected_journal = plan[journal_key]
        receipt_descriptor = entry_by_final[RECEIPT_PATH][side]
        journal_descriptor = entry_by_final[JOURNAL_PATH][side]
        if expected_receipt is None:
            if receipt_descriptor is not None or journal_descriptor is not None:
                raise ValueError("transaction old controls are inconsistent")
        elif receipt_descriptor is None or journal_descriptor is None or receipt_descriptor["sha256"] != expected_receipt or journal_descriptor["sha256"] != expected_journal:
            raise ValueError("transaction control descriptors do not match")
    if plan["action"] == "upgrade":
        if any(entry_by_final[path]["old"] is not None or entry_by_final[path]["new"] is None for path in previous_paths):
            raise ValueError("upgrade predecessor-slot descriptors are invalid")
    if plan["action"] == "rollback-version":
        if any(entry_by_final[path]["old"] is None or entry_by_final[path]["new"] is not None for path in previous_paths):
            raise ValueError("rollback predecessor-slot descriptors are invalid")
    return plan


def _parse_transaction_envelope(raw: bytes) -> dict[str, object]:
    if len(raw) > MAX_TRANSACTION_SIZE:
        raise ValueError("transaction record is too large")
    document = _json_loads(raw, "transaction record")
    if _canonical_json(document) != raw:
        raise ValueError("transaction record is not canonical")
    if not isinstance(document, dict) or set(document) != {"plan", "plan_sha256", "schema_version"}:
        raise ValueError("transaction record fields are invalid")
    if document["schema_version"] != TRANSACTION_SCHEMA_VERSION:
        raise ValueError("transaction record schema is invalid")
    plan = _validate_transaction_plan(document["plan"])
    expected = hashlib.sha256(TRANSACTION_DOMAIN + _canonical_json(plan)).hexdigest()
    if document["plan_sha256"] != expected:
        raise ValueError("transaction plan digest does not match")
    return plan


def _version_precedence(version: str) -> tuple[int, int, int, tuple[tuple[int, object], ...]]:
    if not isinstance(version, str) or len(version) > 255:
        raise ValueError("version is not valid SemVer")
    match = re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?", version)
    if match is None:
        raise ValueError("version is not valid SemVer")
    prerelease = match.group(4)
    build = match.group(5)
    for identifiers, numeric_restriction in ((prerelease, True), (build, False)):
        if identifiers is None:
            continue
        for identifier in identifiers.split("."):
            if not identifier or not re.fullmatch(r"[0-9A-Za-z-]+", identifier):
                raise ValueError("version is not valid SemVer")
            if numeric_restriction and identifier.isdigit() and len(identifier) > 1 and identifier.startswith("0"):
                raise ValueError("version is not valid SemVer")
    major, minor, patch = (int(match.group(index)) for index in (1, 2, 3))
    if prerelease is None:
        return major, minor, patch, ((2, 0),)
    precedence: list[tuple[int, object]] = []
    for identifier in prerelease.split("."):
        precedence.append((0, int(identifier)) if identifier.isdigit() else (1, identifier))
    return major, minor, patch, tuple(precedence)


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
    try:
        _version_precedence(document["version"])
    except ValueError as error:
        raise ValueError("manifest version is invalid") from error
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
            parent = current.parent
            os.mkdir(current, 0o755)
            if _is_production(root):
                os.chown(current, 0, 0)
            _fsync_directory(parent)
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
        os.fchmod(handle.fileno(), mode)
        if production:
            os.fchown(handle.fileno(), 0, 0)
        os.fsync(handle.fileno())
        if os.fstat(handle.fileno()).st_mode & 0o777 != mode:
            raise ValueError("staged file mode is invalid")
    except BaseException:
        handle.close()
        try:
            os.unlink(parent / temporary)
            _fsync_directory(parent)
        except FileNotFoundError:
            pass
        raise
    handle.close()
    _fsync_directory(parent)
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


def _anchor_path(root: Path, name: str) -> Path:
    return root / name


def _read_transaction_anchor(root: Path, name: str) -> tuple[bytes, dict[str, object]]:
    path = _anchor_path(root, name)
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o444:
                raise ValueError("transaction anchor is not a protected regular file")
            expected_owner = 0 if _is_production(root) else None
            if not _owner_matches(before, expected_owner, expected_owner):
                raise ValueError("transaction anchor owner is invalid")
            raw = source.read(MAX_TRANSACTION_SIZE + 1)
            after = os.fstat(source.fileno())
    except OSError as error:
        raise ValueError("transaction anchor could not be read") from error
    stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if len(raw) != before.st_size or any(getattr(before, key) != getattr(after, key) for key in stable):
        raise ValueError("transaction anchor changed while read")
    plan = _parse_transaction_envelope(raw)
    expected_owner = 0 if _is_production(root) else None
    for entry in plan["paths"]:
        for side in ("old", "new"):
            file_descriptor = entry[side]
            if file_descriptor is not None and (file_descriptor["uid"] != expected_owner or file_descriptor["gid"] != expected_owner):
                raise ValueError("transaction descriptor owner policy is invalid")
    return raw, plan


def _active_transaction(root: Path) -> tuple[str, bytes, dict[str, object]] | None:
    present: list[str] = []
    for name in TRANSACTION_ANCHORS:
        try:
            os.lstat(root / name)
        except FileNotFoundError:
            continue
        present.append(name)
    if len(present) > 1:
        raise ValueError("multiple transaction anchors are present")
    if not present:
        return None
    name = present[0]
    raw, plan = _read_transaction_anchor(root, name)
    return name, raw, plan


def _preflight_no_transaction_debris(root: Path, finals: list[str] | tuple[str, ...] | set[str]) -> None:
    parents = {"."} | {str(PurePosixPath(relative).parent) for relative in finals}
    for relative in parents:
        parent = root / relative
        try:
            children = list(os.scandir(parent))
        except FileNotFoundError:
            continue
        for child in children:
            if ".open-trestle-" in child.name:
                raise ValueError("unexpected transaction-looking object is present")


def _validate_optional_parent_chain(root: Path, relative: str) -> None:
    current = root
    for part in PurePosixPath(relative).parent.parts:
        current = current / part
        try:
            status = os.lstat(current)
        except FileNotFoundError:
            return
        if not stat.S_ISDIR(status.st_mode) or stat.S_ISLNK(status.st_mode) or status.st_mode & 0o022:
            raise ValueError("transaction path ancestor is not trusted")
        if _is_production(root) and (status.st_uid != 0 or status.st_gid != 0):
            raise ValueError("transaction path ancestor is not root-owned")


def _descriptor_status(path: Path, descriptor: dict[str, object]) -> os.stat_result | None:
    try:
        status = os.lstat(path)
    except FileNotFoundError:
        return None
    if (
        not stat.S_ISREG(status.st_mode)
        or stat.S_ISLNK(status.st_mode)
        or stat.S_IMODE(status.st_mode) != descriptor["mode"]
        or status.st_size != descriptor["size"]
        or not _owner_matches(status, descriptor["uid"], descriptor["gid"])
    ):
        raise ValueError(f"transaction object metadata is invalid: {path}")
    digest, size = _sha256_path(path)
    if digest != descriptor["sha256"] or size != descriptor["size"]:
        raise ValueError(f"transaction object digest is invalid: {path}")
    return status


def _existing_status(path: Path) -> os.stat_result | None:
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None


def _matches_descriptor(path: Path, descriptor: dict[str, object] | None) -> bool:
    if descriptor is None:
        return False
    try:
        return _descriptor_status(path, descriptor) is not None
    except ValueError:
        return False


def _classify_transaction_paths(root: Path, plan: dict[str, object], state: str) -> list[dict[str, object]]:
    entries = plan["paths"]
    assert isinstance(entries, list)
    allowed_by_parent: dict[str, set[str]] = {".": set(TRANSACTION_ANCHORS)}
    for raw_entry in entries:
        assert isinstance(raw_entry, dict)
        for key in ("staged", "quarantine"):
            path = PurePosixPath(raw_entry[key])
            allowed_by_parent.setdefault(str(path.parent), set()).add(path.name)
        for key in ("final", "staged", "quarantine"):
            _validate_optional_parent_chain(root, raw_entry[key])
    for relative, allowed_names in allowed_by_parent.items():
        parent = root / relative
        try:
            children = list(os.scandir(parent))
        except FileNotFoundError:
            continue
        for child in children:
            if ".open-trestle-" in child.name and child.name not in allowed_names:
                raise ValueError("unexpected transaction-looking object is present")
    classified: list[dict[str, object]] = []
    for raw_entry in entries:
        entry = dict(raw_entry)
        final = root / entry["final"]
        staged = root / entry["staged"]
        quarantine = root / entry["quarantine"]
        old = entry["old"]
        new = entry["new"]
        final_status = _existing_status(final)
        staged_status = _existing_status(staged)
        quarantine_status = _existing_status(quarantine)
        final_old = final_status is not None and _matches_descriptor(final, old)
        final_new = final_status is not None and _matches_descriptor(final, new)
        staged_new = staged_status is not None and _matches_descriptor(staged, new)
        quarantine_old = quarantine_status is not None and _matches_descriptor(quarantine, old)
        if final_status is not None and not (final_old or final_new):
            raise ValueError(f"transaction final is ambiguous: {entry['final']}")
        if staged_status is not None and not staged_new:
            raise ValueError(f"transaction staged object is ambiguous: {entry['staged']}")
        if quarantine_status is not None and not quarantine_old:
            raise ValueError(f"transaction quarantine is ambiguous: {entry['quarantine']}")
        if state == BOOTSTRAP_ANCHOR:
            if old is None:
                valid = final_status is None and staged_status is None and quarantine_status is None
            else:
                valid = final_old and staged_status is None and quarantine_status is None
        elif state == PENDING_ANCHOR:
            if old is None:
                valid = quarantine_status is None and not (final_status is not None and staged_status is not None)
            elif new is None:
                valid = staged_status is None and ((final_old and quarantine_status is None) or (final_status is None and quarantine_old))
            else:
                valid = (
                    (final_old and quarantine_status is None)
                    or (final_status is None and quarantine_old)
                    or (final_new and quarantine_old and staged_status is None)
                )
        else:
            if new is None:
                valid = final_status is None and staged_status is None and (quarantine_status is None or quarantine_old)
            else:
                valid = final_new and (staged_status is None or staged_new) and (quarantine_status is None or quarantine_old)
        if not valid:
            raise ValueError(f"transaction path state is impossible: {entry['final']}")
        entry.update({
            "final_exists": final_status is not None,
            "final_old": final_old,
            "final_new": final_new,
            "quarantine_exists": quarantine_status is not None,
            "staged_exists": staged_status is not None,
        })
        classified.append(entry)
    return classified


def _unlink_verified(path: Path, descriptor: dict[str, object]) -> None:
    before = _descriptor_status(path, descriptor)
    if before is None:
        return
    current = os.lstat(path)
    if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
        raise ValueError(f"transaction object changed before removal: {path}")
    os.unlink(path)
    _fsync_directory(path.parent)


def _remove_transaction_directories(root: Path, directories: list[str]) -> None:
    for relative in sorted(set(directories), key=lambda value: (value.count("/"), value), reverse=True):
        path = root / relative
        try:
            path.rmdir()
        except FileNotFoundError:
            continue
        except OSError as error:
            if error.errno in {errno.ENOTEMPTY, errno.EEXIST}:
                continue
            raise
        _fsync_directory(path.parent)


def _unlink_anchor(root: Path, name: str, raw: bytes) -> None:
    current, _ = _read_transaction_anchor(root, name)
    if current != raw:
        raise ValueError("transaction anchor changed before removal")
    os.unlink(root / name)
    _fsync_directory(root)


def _recover_pending(root: Path, raw: bytes, plan: dict[str, object]) -> None:
    entries = _classify_transaction_paths(root, plan, PENDING_ANCHOR)
    controls = {RECEIPT_PATH, JOURNAL_PATH}
    ordered = sorted(entries, key=lambda entry: (entry["final"] in controls, entry["final"]))
    for entry in ordered:
        final = root / entry["final"]
        staged = root / entry["staged"]
        quarantine = root / entry["quarantine"]
        old = entry["old"]
        new = entry["new"]
        if old is None:
            if entry["final_exists"]:
                _unlink_verified(final, new)
            if entry["staged_exists"]:
                _unlink_verified(staged, new)
            continue
        if entry["quarantine_exists"]:
            if entry["final_exists"]:
                _unlink_verified(final, new)
            _rename_noreplace(quarantine.parent, quarantine.name, final.name)
            _fsync_directory(final.parent)
        if entry["staged_exists"]:
            _unlink_verified(staged, new)
    _remove_transaction_directories(root, plan["created_directories"])
    _unlink_anchor(root, PENDING_ANCHOR, raw)


def _recover_committed(root: Path, raw: bytes, plan: dict[str, object]) -> None:
    entries = _classify_transaction_paths(root, plan, COMMITTED_ANCHOR)
    for entry in entries:
        if entry["staged_exists"]:
            _unlink_verified(root / entry["staged"], entry["new"])
        if entry["quarantine_exists"]:
            _unlink_verified(root / entry["quarantine"], entry["old"])
    _remove_transaction_directories(root, plan["obsolete_directories"])
    _unlink_anchor(root, COMMITTED_ANCHOR, raw)


def recover(destdir: Path | None = None) -> None:
    root = _installation_root(destdir)
    active = _active_transaction(root)
    if active is None:
        return
    name, raw, plan = active
    if name == BOOTSTRAP_ANCHOR:
        _classify_transaction_paths(root, plan, BOOTSTRAP_ANCHOR)
        _unlink_anchor(root, name, raw)
    elif name == PENDING_ANCHOR:
        _recover_pending(root, raw, plan)
    else:
        _recover_committed(root, raw, plan)


def _require_no_recovery(root: Path) -> None:
    if _active_transaction(root) is not None:
        raise ValueError("lifecycle recovery is required; run recover")


def _start_transaction(root: Path, plan: dict[str, object]) -> bytes:
    if _active_transaction(root) is not None:
        raise ValueError("lifecycle recovery is required; run recover")
    body = _transaction_envelope(plan)
    _preflight_no_transaction_debris(
        root, {entry["final"] for entry in plan["paths"]}
    )
    handle: BinaryIO | None = None
    owned_anchor: str | None = None
    owned_identity: tuple[int, int] | None = None
    try:
        handle = _open_new_file(root, BOOTSTRAP_ANCHOR, 0o444)
        owned_anchor = BOOTSTRAP_ANCHOR
        opened_status = os.fstat(handle.fileno())
        owned_identity = (opened_status.st_dev, opened_status.st_ino)
        handle.write(body)
        handle.flush()
        os.fchmod(handle.fileno(), 0o444)
        if _is_production(root):
            os.fchown(handle.fileno(), 0, 0)
        os.fsync(handle.fileno())
        handle.close()
        handle = None
        _fsync_directory(root)
        _rename_noreplace(root, BOOTSTRAP_ANCHOR, PENDING_ANCHOR)
        owned_anchor = PENDING_ANCHOR
        _fsync_directory(root)
    except BaseException:
        if handle is not None:
            handle.close()
        if owned_anchor is not None and owned_identity is not None:
            try:
                current_status = os.lstat(root / owned_anchor)
                if (current_status.st_dev, current_status.st_ino) == owned_identity:
                    os.unlink(root / owned_anchor)
            except FileNotFoundError:
                pass
            try:
                _fsync_directory(root)
            except OSError:
                pass
        raise
    return body


def _commit_transaction(root: Path, plan: dict[str, object]) -> None:
    _classify_transaction_paths(root, plan, COMMITTED_ANCHOR)
    _rename_noreplace(root, PENDING_ANCHOR, COMMITTED_ANCHOR)
    _fsync_directory(root)


def _abandon_transaction(root: Path, plan: dict[str, object]) -> None:
    active = _active_transaction(root)
    if active is None:
        return
    name, raw, active_plan = active
    if active_plan != plan or name not in {BOOTSTRAP_ANCHOR, PENDING_ANCHOR}:
        raise ValueError("failed transaction anchor is ambiguous")
    _unlink_anchor(root, name, raw)


def _install_documents(
    validated: ValidatedArchive,
    managed: tuple[InstalledFile, ...],
    created_directories: list[str],
    transaction: str,
) -> tuple[bytes, bytes, dict[str, object]]:
    manifest_digest = hashlib.sha256(_canonical_json(validated.manifest)).hexdigest()
    version = validated.manifest["version"]
    generation = _generation_core(validated.sha256, manifest_digest, version, managed)
    generation_id = _generation_identity(generation)
    receipt = {
        "action": "install",
        "archive_sha256": validated.sha256,
        "created_directories": created_directories,
        "files": [_receipt_file(item) for item in managed],
        "generation_id": generation_id,
        "manifest_sha256": manifest_digest,
        "new_archive_sha256": validated.sha256,
        "new_generation_id": generation_id,
        "new_manifest_sha256": manifest_digest,
        "new_version": version,
        "old_archive_sha256": None,
        "old_generation_id": None,
        "old_manifest_sha256": None,
        "old_version": None,
        "previous": None,
        "schema_version": CONTROL_SCHEMA_VERSION,
        "target": TARGET,
        "transaction": transaction,
        "version": version,
    }
    receipt_body = _canonical_json(receipt)
    journal = {
        "action": "install",
        "new_archive_sha256": validated.sha256,
        "new_generation_id": generation_id,
        "new_manifest_sha256": manifest_digest,
        "new_version": version,
        "old_archive_sha256": None,
        "old_generation_id": None,
        "old_manifest_sha256": None,
        "old_version": None,
        "receipt_sha256": hashlib.sha256(receipt_body).hexdigest(),
        "schema_version": CONTROL_SCHEMA_VERSION,
        "target": TARGET,
        "transaction": transaction,
    }
    return receipt_body, _canonical_json(journal), generation


def _plan_entry(
    root: Path,
    transaction: str,
    relative: str,
    old: InstalledFile | None,
    new: InstalledFile | None,
) -> dict[str, object]:
    staged, quarantine = _transaction_names(relative, transaction)
    return {
        "final": relative,
        "new": None if new is None else _descriptor(new, root),
        "old": None if old is None else _descriptor(old, root),
        "quarantine": quarantine,
        "staged": staged,
    }


def _unlink_live_owned_file(path: Path, item: InstalledFile, identity: tuple[int, int]) -> bool:
    if not _matches_owned_file(path, item, identity):
        return False
    status = os.lstat(path)
    if (status.st_dev, status.st_ino) != identity:
        return False
    os.unlink(path)
    _fsync_directory(path.parent)
    return True


def install(archive_path: Path, destdir: Path | None = None) -> None:
    root = _installation_root(destdir)
    recover(destdir)
    validated = validate_archive(archive_path)
    managed = _managed_generation(validated)
    all_paths = {item.path for item in managed} | {RECEIPT_PATH, JOURNAL_PATH}
    _preflight_absent(root, tuple(sorted(all_paths)))
    transaction = uuid.uuid4().hex
    created_directories = _planned_directories(root, all_paths)
    receipt_body, journal_body, generation = _install_documents(
        validated, managed, created_directories, transaction
    )
    controls = (
        _control_item(RECEIPT_PATH, receipt_body),
        _control_item(JOURNAL_PATH, journal_body),
    )
    new_items = {item.path: item for item in (*managed, *controls)}
    paths = [
        _plan_entry(root, transaction, relative, None, new_items[relative])
        for relative in sorted(new_items)
    ]
    plan = _transaction_plan(
        action="install",
        transaction=transaction,
        old_generation=None,
        new_generation=generation,
        old_receipt_sha256=None,
        old_journal_sha256=None,
        new_receipt_sha256=controls[0].sha256,
        new_journal_sha256=controls[1].sha256,
        created_directories=created_directories,
        obsolete_directories=[],
        paths=paths,
    )
    generated_paths = tuple(
        value for entry in paths for value in (entry["staged"], entry["quarantine"])
    )
    _preflight_absent(root, generated_paths)
    _start_transaction(root, plan)
    created: list[str] = []
    staged: list[tuple[Path, str, str, InstalledFile, tuple[int, int]]] = []
    published: list[tuple[Path, InstalledFile, tuple[int, int]]] = []
    try:
        _stage_generation(root, validated, transaction, created, staged)
        control_parent = _ensure_directory(root, str(PurePosixPath(RECEIPT_PATH).parent), created)
        for relative, body, item in (
            (RECEIPT_PATH, receipt_body, controls[0]),
            (JOURNAL_PATH, journal_body, controls[1]),
        ):
            name = PurePosixPath(relative).name
            temporary = _stage_file(
                control_parent, name, item.mode, _write_bytes(body), transaction, _is_production(root)
            )
            staged.append((control_parent, temporary, name, item, _file_identity(control_parent / temporary)))
        if sorted(created, key=lambda value: (value.count("/"), value)) != created_directories:
            raise ValueError("installation directory inventory changed after preflight")
        staged_by_path = {entry[3].path: entry for entry in staged}
        if set(staged_by_path) != set(new_items):
            raise ValueError("installation staged inventory is inconsistent")
        order = sorted(set(new_items) - {RECEIPT_PATH, JOURNAL_PATH}) + [RECEIPT_PATH, JOURNAL_PATH]
        for relative in order:
            parent, temporary, name, item, staged_identity = staged_by_path[relative]
            if not _matches_owned_file(parent / temporary, item, staged_identity):
                raise ValueError(f"staged file changed before installation: {relative}")
            identity = _publish_staged(parent, temporary, name)
            published.append((parent / name, item, identity))
            if identity != staged_identity or not _matches_owned_file(parent / name, item, identity):
                raise ValueError(f"staged file changed during installation: {relative}")
            _fsync_directory(parent)
        _commit_transaction(root, plan)
    except BaseException:
        try:
            recover(destdir)
        except (OSError, ValueError):
            for path, item, identity in reversed(published):
                _unlink_live_owned_file(path, item, identity)
            for parent, temporary, _, item, identity in staged:
                _unlink_live_owned_file(parent / temporary, item, identity)
            _remove_created_directories(root, created)
            _abandon_transaction(root, plan)
        raise
    recover(destdir)


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


def _parse_receipt_files(raw_files: object) -> tuple[InstalledFile, ...]:
    if not isinstance(raw_files, list) or not raw_files:
        raise ValueError("installation receipt inventory is invalid")
    files: list[InstalledFile] = []
    for raw in raw_files:
        if not isinstance(raw, dict) or set(raw) != {"elf", "mode", "path", "sha256", "size"}:
            raise ValueError("installation receipt file is invalid")
        path = _safe_relative_path(raw["path"])
        if raw["mode"] not in {0o444, 0o555} or not isinstance(raw["size"], int) or isinstance(raw["size"], bool) or raw["size"] <= 0 or not isinstance(raw["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", raw["sha256"]) or not isinstance(raw["elf"], bool):
            raise ValueError("installation receipt file metadata is invalid")
        files.append(InstalledFile(path, raw["mode"], raw["size"], raw["sha256"], raw["elf"]))
    if [item.path for item in files] != sorted(item.path for item in files) or len({item.path for item in files}) != len(files):
        raise ValueError("installation receipt inventory is invalid")
    if {item.path for item in files if item.elf} != EXECUTABLE_PATHS or LIFECYCLE_PATH not in {item.path for item in files} or SIDECAR_PATH not in {item.path for item in files}:
        raise ValueError("installation receipt inventory is incomplete")
    return tuple(files)


def _validate_created_directories(raw: object, files: tuple[InstalledFile, ...]) -> list[str]:
    if not isinstance(raw, list) or len(set(raw)) != len(raw) or any(not isinstance(value, str) or value == "." or _safe_relative_path(value) != value for value in raw):
        raise ValueError("installation directory inventory is invalid")
    allowed_directories: set[str] = set()
    for owned_path in [item.path for item in files] + [
        RECEIPT_PATH, JOURNAL_PATH, PREVIOUS_ARCHIVE_PATH, PREVIOUS_SIDECAR_PATH,
        PREVIOUS_RECEIPT_PATH, PREVIOUS_JOURNAL_PATH,
    ]:
        parent = PurePosixPath(owned_path).parent
        while str(parent) != ".":
            allowed_directories.add(str(parent))
            parent = parent.parent
    if not set(raw) <= allowed_directories:
        raise ValueError("installation directory inventory is out of scope")
    return raw


def _load_control(root: Path) -> tuple[dict[str, object], dict[str, object], tuple[InstalledFile, ...]]:
    receipt_raw = _read_control_file(root, RECEIPT_PATH)
    journal_raw = _read_control_file(root, JOURNAL_PATH)
    receipt = _json_loads(receipt_raw, "receipt")
    journal = _json_loads(journal_raw, "journal")
    if _canonical_json(receipt) != receipt_raw or _canonical_json(journal) != journal_raw:
        raise ValueError("installation receipt or journal is not canonical")
    legacy_receipt_fields = {
        "archive_sha256", "created_directories", "files", "manifest_sha256",
        "schema_version", "target", "transaction", "version",
    }
    legacy_journal_fields = {
        "action", "archive_sha256", "receipt_sha256", "schema_version", "transaction",
    }
    if isinstance(receipt, dict) and isinstance(journal, dict) and set(receipt) == legacy_receipt_fields and set(journal) == legacy_journal_fields:
        if receipt["schema_version"] != SCHEMA_VERSION or receipt["target"] != TARGET or journal["schema_version"] != SCHEMA_VERSION or journal["action"] != "install":
            raise ValueError("legacy installation control identity is invalid")
        digest_values = (
            receipt["archive_sha256"], receipt["manifest_sha256"],
            journal["archive_sha256"], journal["receipt_sha256"],
        )
        if any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) for value in digest_values):
            raise ValueError("legacy installation control digest is invalid")
        try:
            _version_precedence(receipt["version"])
        except ValueError as error:
            raise ValueError("legacy installation version is invalid") from error
        if not isinstance(receipt["transaction"], str) or not re.fullmatch(r"[0-9a-f]{32}", receipt["transaction"]):
            raise ValueError("legacy installation transaction is invalid")
        if journal["transaction"] != receipt["transaction"] or journal["archive_sha256"] != receipt["archive_sha256"] or journal["receipt_sha256"] != hashlib.sha256(receipt_raw).hexdigest():
            raise ValueError("legacy installation journal does not bind the receipt")
        files = _parse_receipt_files(receipt["files"])
        _validate_created_directories(receipt["created_directories"], files)
        normalized = dict(receipt)
        legacy_generation = _generation_core(receipt["archive_sha256"], receipt["manifest_sha256"], receipt["version"], files)
        legacy_generation_id = _generation_identity(legacy_generation)
        normalized.update({
            "action": "install",
            "generation_id": legacy_generation_id,
            "new_generation_id": legacy_generation_id,
            "old_generation_id": None,
            "new_archive_sha256": receipt["archive_sha256"],
            "new_manifest_sha256": receipt["manifest_sha256"],
            "new_version": receipt["version"],
            "old_archive_sha256": None,
            "old_manifest_sha256": None,
            "old_version": None,
            "previous": None,
        })
        return normalized, journal, files
    receipt_fields = {
        "action", "archive_sha256", "created_directories", "files", "manifest_sha256",
        "new_archive_sha256", "new_manifest_sha256", "new_version",
        "old_archive_sha256", "old_manifest_sha256", "old_version", "previous",
        "schema_version", "target", "transaction", "version",
    }
    journal_fields = {
        "action", "new_archive_sha256", "new_manifest_sha256", "new_version",
        "old_archive_sha256", "old_manifest_sha256", "old_version", "receipt_sha256",
        "schema_version", "target", "transaction",
    }
    receipt_identity_fields = {"generation_id", "new_generation_id", "old_generation_id"}
    journal_identity_fields = {"new_generation_id", "old_generation_id"}
    if not isinstance(receipt, dict) or set(receipt) not in {frozenset(receipt_fields), frozenset(receipt_fields | receipt_identity_fields)}:
        raise ValueError("installation receipt fields are invalid")
    if not isinstance(journal, dict) or set(journal) not in {frozenset(journal_fields), frozenset(journal_fields | journal_identity_fields)}:
        raise ValueError("installation journal fields are invalid")
    has_generation_id = "generation_id" in receipt
    if has_generation_id != ("new_generation_id" in journal):
        raise ValueError("installation generation identity fields are inconsistent")
    action = receipt["action"]
    if action not in {"install", "upgrade", "rollback-version"} or journal["action"] != action:
        raise ValueError("installation control action is invalid")
    expected_schema = CONTROL_SCHEMA_VERSION if has_generation_id else 2
    if receipt["schema_version"] != expected_schema or receipt["target"] != TARGET or journal["schema_version"] != expected_schema or journal["target"] != TARGET:
        raise ValueError("installation control identity is invalid")
    digests = (receipt["archive_sha256"], receipt["manifest_sha256"], receipt["new_archive_sha256"], receipt["new_manifest_sha256"], journal["new_archive_sha256"], journal["new_manifest_sha256"], journal["receipt_sha256"])
    if any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) for value in digests):
        raise ValueError("installation control digest is invalid")
    old_values = (receipt["old_archive_sha256"], receipt["old_manifest_sha256"], journal["old_archive_sha256"], journal["old_manifest_sha256"])
    if action == "install":
        if any(value is not None for value in (*old_values, receipt["old_version"], journal["old_version"])) or receipt["previous"] is not None:
            raise ValueError("installation control predecessor is invalid")
    else:
        if any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) for value in old_values):
            raise ValueError("installation control predecessor digest is invalid")
        if any(not isinstance(value, str) for value in (receipt["old_version"], journal["old_version"])):
            raise ValueError("installation control predecessor version is invalid")
    versions = [receipt["version"], receipt["new_version"], journal["new_version"]]
    if action != "install":
        versions.extend((receipt["old_version"], journal["old_version"]))
    try:
        for value in versions:
            _version_precedence(value)
    except ValueError as error:
        raise ValueError("installation version is invalid") from error
    if action == "upgrade" and _version_precedence(receipt["new_version"]) <= _version_precedence(receipt["old_version"]):
        raise ValueError("installation upgrade version transition is invalid")
    if action == "rollback-version" and _version_precedence(receipt["new_version"]) >= _version_precedence(receipt["old_version"]):
        raise ValueError("installation rollback version transition is invalid")
    if not isinstance(receipt["transaction"], str) or not re.fullmatch(r"[0-9a-f]{32}", receipt["transaction"]):
        raise ValueError("installation transaction is invalid")
    bound = ("action", "new_archive_sha256", "new_manifest_sha256", "new_version", "old_archive_sha256", "old_manifest_sha256", "old_version", "schema_version", "target", "transaction")
    if has_generation_id:
        bound += ("new_generation_id", "old_generation_id")
    if any(journal[key] != receipt[key] for key in bound) or journal["receipt_sha256"] != hashlib.sha256(receipt_raw).hexdigest():
        raise ValueError("installation journal does not bind the receipt")
    if receipt["archive_sha256"] != receipt["new_archive_sha256"] or receipt["manifest_sha256"] != receipt["new_manifest_sha256"] or receipt["version"] != receipt["new_version"]:
        raise ValueError("installation current generation binding is invalid")
    files = _parse_receipt_files(receipt["files"])
    _validate_created_directories(receipt["created_directories"], files)
    generation = _generation_core(receipt["archive_sha256"], receipt["manifest_sha256"], receipt["version"], files)
    generation_id = _generation_identity(generation)
    if has_generation_id:
        if receipt["generation_id"] != generation_id or receipt["new_generation_id"] != generation_id:
            raise ValueError("installation generation identity does not match")
        if action == "install" and receipt["old_generation_id"] is not None:
            raise ValueError("installation old generation identity is invalid")
        if action != "install" and (not isinstance(receipt["old_generation_id"], str) or not re.fullmatch(r"[0-9a-f]{64}", receipt["old_generation_id"])):
            raise ValueError("installation old generation identity is invalid")
    else:
        receipt = dict(receipt)
        receipt.update({"generation_id": generation_id, "new_generation_id": generation_id})
        receipt["old_generation_id"] = None
    previous = receipt["previous"]
    if action == "upgrade":
        previous_fields = {
            "archive_sha256", "created_directories", "files", "journal_sha256",
            "manifest_sha256", "receipt_sha256", "version",
        }
        allowed_previous_fields = {frozenset(previous_fields), frozenset(previous_fields | {"generation_id"})}
        if not isinstance(previous, dict) or set(previous) not in allowed_previous_fields:
            raise ValueError("installation predecessor receipt is invalid")
        previous_files = _parse_receipt_files(previous["files"])
        _validate_created_directories(previous["created_directories"], previous_files)
        previous_generation = _generation_core(previous["archive_sha256"], previous["manifest_sha256"], previous["version"], previous_files)
        previous_generation_id = _generation_identity(previous_generation)
        if "generation_id" in previous and previous["generation_id"] != previous_generation_id:
            raise ValueError("installation predecessor generation identity is invalid")
        if has_generation_id and receipt["old_generation_id"] != previous_generation_id:
            raise ValueError("installation predecessor generation identity does not match")
        if previous["archive_sha256"] != receipt["old_archive_sha256"] or previous["manifest_sha256"] != receipt["old_manifest_sha256"] or previous["version"] != receipt["old_version"]:
            raise ValueError("installation predecessor binding is invalid")
        if any(not isinstance(previous[key], str) or not re.fullmatch(r"[0-9a-f]{64}", previous[key]) for key in ("receipt_sha256", "journal_sha256")):
            raise ValueError("installation predecessor control digest is invalid")
    elif previous is not None:
        raise ValueError("installation predecessor receipt is invalid")
    return receipt, journal, files


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
    _require_no_recovery(root)
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
    if receipt["action"] == "upgrade":
        _validate_previous_generation(root, receipt)
    return receipt


def _managed_generation(validated: ValidatedArchive) -> tuple[InstalledFile, ...]:
    sidecar_body = f"{validated.sha256}  {PurePosixPath(LIFECYCLE_PATH).name}\n".encode("ascii")
    return tuple(sorted(
        (*validated.files,
         InstalledFile(LIFECYCLE_PATH, 0o555, validated.size, validated.sha256, False),
         InstalledFile(SIDECAR_PATH, 0o444, len(sidecar_body), hashlib.sha256(sidecar_body).hexdigest(), False)),
        key=lambda item: item.path,
    ))


def _verified_installed_generation(root: Path) -> tuple[ValidatedArchive, dict[str, object], tuple[InstalledFile, ...]]:
    archive = validate_archive(root / LIFECYCLE_PATH, root / SIDECAR_PATH)
    receipt = verify_installed(archive.path, root)
    _, _, files = _load_control(root)
    return archive, receipt, files


def _planned_directories(root: Path, paths: set[str]) -> list[str]:
    planned: set[str] = set()
    for relative in sorted(paths):
        current = root
        for part in PurePosixPath(relative).parent.parts:
            current = current / part
            if str(current.relative_to(root)) in planned:
                continue
            try:
                status = os.lstat(current)
            except FileNotFoundError:
                planned.add(str(current.relative_to(root)))
                continue
            if not stat.S_ISDIR(status.st_mode) or stat.S_ISLNK(status.st_mode) or status.st_mode & 0o022:
                raise ValueError("destination path contains an untrusted directory")
            if _is_production(root) and (status.st_uid != 0 or status.st_gid != 0):
                raise ValueError("production destination directory is not root-owned")
    return sorted(planned, key=lambda value: (value.count("/"), value))


def _stage_generation(
    root: Path,
    validated: ValidatedArchive,
    transaction: str,
    created: list[str],
    staged: list[tuple[Path, str, str, InstalledFile, tuple[int, int]]] | None = None,
) -> list[tuple[Path, str, str, InstalledFile, tuple[int, int]]]:
    if staged is None:
        staged = []
    archive_descriptor = os.open(validated.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(archive_descriptor, "rb") as archive_source:
        before = os.fstat(archive_source.fileno())
        digest, size = _sha256_stream(archive_source)
        if digest != validated.sha256 or size != validated.size:
            raise ValueError("distribution archive changed before transition")
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
        lifecycle = InstalledFile(LIFECYCLE_PATH, 0o555, validated.size, validated.sha256, False)
        parent = _ensure_directory(root, str(PurePosixPath(LIFECYCLE_PATH).parent), created)
        archive_source.seek(0)

        def lifecycle_writer(destination: BinaryIO) -> None:
            while chunk := archive_source.read(1 << 20):
                destination.write(chunk)

        temporary = _stage_file(parent, PurePosixPath(LIFECYCLE_PATH).name, 0o555, lifecycle_writer, transaction, _is_production(root))
        staged.append((parent, temporary, PurePosixPath(LIFECYCLE_PATH).name, lifecycle, _file_identity(parent / temporary)))
        after = os.fstat(archive_source.fileno())
        stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, key) != getattr(after, key) for key in stable):
            raise ValueError("distribution archive changed during transition")
    sidecar_body = f"{validated.sha256}  {PurePosixPath(LIFECYCLE_PATH).name}\n".encode("ascii")
    sidecar = InstalledFile(SIDECAR_PATH, 0o444, len(sidecar_body), hashlib.sha256(sidecar_body).hexdigest(), False)
    parent = _ensure_directory(root, str(PurePosixPath(SIDECAR_PATH).parent), created)
    temporary = _stage_file(parent, PurePosixPath(SIDECAR_PATH).name, 0o444, _write_bytes(sidecar_body), transaction, _is_production(root))
    staged.append((parent, temporary, PurePosixPath(SIDECAR_PATH).name, sidecar, _file_identity(parent / temporary)))
    for parent, temporary, _, item, _ in staged:
        _validate_staged_file(parent, temporary, item)
    return staged


def _control_item(path: str, body: bytes) -> InstalledFile:
    return InstalledFile(path, 0o444, len(body), hashlib.sha256(body).hexdigest(), False)


def _previous_slot_items(
    validated: ValidatedArchive,
    receipt_body: bytes,
    journal_body: bytes,
) -> tuple[InstalledFile, ...]:
    sidecar_body = f"{validated.sha256}  {PurePosixPath(PREVIOUS_ARCHIVE_PATH).name}\n".encode("ascii")
    return (
        InstalledFile(PREVIOUS_ARCHIVE_PATH, 0o555, validated.size, validated.sha256, False),
        InstalledFile(PREVIOUS_SIDECAR_PATH, 0o444, len(sidecar_body), hashlib.sha256(sidecar_body).hexdigest(), False),
        _control_item(PREVIOUS_RECEIPT_PATH, receipt_body),
        _control_item(PREVIOUS_JOURNAL_PATH, journal_body),
    )


def _stage_previous_slot(
    root: Path,
    validated: ValidatedArchive,
    receipt_body: bytes,
    journal_body: bytes,
    transaction: str,
    created: list[str],
    staged: list[tuple[Path, str, str, InstalledFile, tuple[int, int]]] | None = None,
) -> list[tuple[Path, str, str, InstalledFile, tuple[int, int]]]:
    if staged is None:
        staged = []
    archive_item, sidecar_item, receipt_item, journal_item = _previous_slot_items(
        validated, receipt_body, journal_body
    )
    parent = _ensure_directory(root, str(PurePosixPath(PREVIOUS_ARCHIVE_PATH).parent), created)
    descriptor = os.open(validated.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())

        def writer(destination: BinaryIO) -> None:
            while chunk := source.read(1 << 20):
                destination.write(chunk)

        temporary = _stage_file(parent, PurePosixPath(PREVIOUS_ARCHIVE_PATH).name, 0o555, writer, transaction, _is_production(root))
        staged.append((parent, temporary, PurePosixPath(PREVIOUS_ARCHIVE_PATH).name, archive_item, _file_identity(parent / temporary)))
        after = os.fstat(source.fileno())
    stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, key) != getattr(after, key) for key in stable):
        raise ValueError("installed archive changed while staged as predecessor")
    bodies = (
        (PREVIOUS_SIDECAR_PATH, f"{validated.sha256}  {PurePosixPath(PREVIOUS_ARCHIVE_PATH).name}\n".encode("ascii"), sidecar_item),
        (PREVIOUS_RECEIPT_PATH, receipt_body, receipt_item),
        (PREVIOUS_JOURNAL_PATH, journal_body, journal_item),
    )
    for relative, body, item in bodies:
        name = PurePosixPath(relative).name
        temporary = _stage_file(parent, name, item.mode, _write_bytes(body), transaction, _is_production(root))
        staged.append((parent, temporary, name, item, _file_identity(parent / temporary)))
    for staged_parent, staged_name, _, item, _ in staged:
        _validate_staged_file(staged_parent, staged_name, item)
    return staged


def _validate_previous_generation(
    root: Path,
    receipt: dict[str, object],
) -> tuple[ValidatedArchive, tuple[InstalledFile, ...], bytes, bytes, tuple[InstalledFile, ...]]:
    if receipt["action"] != "upgrade" or not isinstance(receipt["previous"], dict):
        raise ValueError("no exact immediate predecessor is available")
    previous = receipt["previous"]
    validated = validate_archive(root / PREVIOUS_ARCHIVE_PATH, root / PREVIOUS_SIDECAR_PATH)
    manifest_digest = hashlib.sha256(_canonical_json(validated.manifest)).hexdigest()
    if validated.sha256 != previous["archive_sha256"] or manifest_digest != previous["manifest_sha256"] or validated.manifest["version"] != previous["version"]:
        raise ValueError("immediate predecessor archive does not match the receipt")
    files = _parse_receipt_files(previous["files"])
    if files != _managed_generation(validated):
        raise ValueError("immediate predecessor inventory does not match its archive")
    receipt_body = _read_control_file(root, PREVIOUS_RECEIPT_PATH)
    journal_body = _read_control_file(root, PREVIOUS_JOURNAL_PATH)
    if hashlib.sha256(receipt_body).hexdigest() != previous["receipt_sha256"] or hashlib.sha256(journal_body).hexdigest() != previous["journal_sha256"]:
        raise ValueError("immediate predecessor controls do not match the receipt")
    slot_items = _previous_slot_items(validated, receipt_body, journal_body)
    for item in slot_items:
        _validate_installed_file(root, item)
    return validated, files, receipt_body, journal_body, slot_items


def _transition_documents(
    *,
    action: str,
    old_receipt: dict[str, object],
    new_archive: ValidatedArchive,
    new_files: tuple[InstalledFile, ...],
    created_directories: list[str],
    transaction: str,
    previous: dict[str, object] | None,
) -> tuple[bytes, bytes]:
    old_archive_sha256 = old_receipt["archive_sha256"]
    old_manifest_sha256 = old_receipt["manifest_sha256"]
    old_version = old_receipt["version"]
    new_manifest_sha256 = hashlib.sha256(_canonical_json(new_archive.manifest)).hexdigest()
    new_version = new_archive.manifest["version"]
    old_generation_id = old_receipt["generation_id"]
    new_generation = _generation_core(new_archive.sha256, new_manifest_sha256, new_version, new_files)
    new_generation_id = _generation_identity(new_generation)
    receipt = {
        "action": action,
        "archive_sha256": new_archive.sha256,
        "created_directories": created_directories,
        "files": [_receipt_file(item) for item in new_files],
        "generation_id": new_generation_id,
        "manifest_sha256": new_manifest_sha256,
        "new_archive_sha256": new_archive.sha256,
        "new_generation_id": new_generation_id,
        "new_manifest_sha256": new_manifest_sha256,
        "new_version": new_version,
        "old_archive_sha256": old_archive_sha256,
        "old_generation_id": old_generation_id,
        "old_manifest_sha256": old_manifest_sha256,
        "old_version": old_version,
        "previous": previous,
        "schema_version": CONTROL_SCHEMA_VERSION,
        "target": TARGET,
        "transaction": transaction,
        "version": new_version,
    }
    receipt_body = _canonical_json(receipt)
    journal = {
        "action": action,
        "new_archive_sha256": new_archive.sha256,
        "new_generation_id": new_generation_id,
        "new_manifest_sha256": new_manifest_sha256,
        "new_version": new_version,
        "old_archive_sha256": old_archive_sha256,
        "old_generation_id": old_generation_id,
        "old_manifest_sha256": old_manifest_sha256,
        "old_version": old_version,
        "receipt_sha256": hashlib.sha256(receipt_body).hexdigest(),
        "schema_version": CONTROL_SCHEMA_VERSION,
        "target": TARGET,
        "transaction": transaction,
    }
    return receipt_body, _canonical_json(journal)


def _apply_transition(
    root: Path,
    staged: list[tuple[Path, str, str, InstalledFile, tuple[int, int]]],
    old_items: dict[str, tuple[InstalledFile, tuple[int, int]]],
    transaction: str,
) -> None:
    staged_by_path = {entry[3].path: entry for entry in staged}
    if len(staged_by_path) != len(staged):
        raise ValueError("transition staged duplicate destinations")
    old_paths = set(old_items)
    new_paths = set(staged_by_path)
    for relative in sorted(new_paths - old_paths):
        try:
            os.lstat(root / relative)
        except FileNotFoundError:
            continue
        raise FileExistsError(f"destination already exists: {relative}")
    for relative, (item, identity) in old_items.items():
        if not _matches_owned_file(root / relative, item, identity):
            raise ValueError(f"owned file changed before transition: {relative}")

    def publish(relative: str) -> None:
        parent, temporary, name, item, staged_identity = staged_by_path[relative]
        if not _matches_owned_file(parent / temporary, item, staged_identity):
            raise ValueError(f"staged file changed before transition: {relative}")
        if relative in old_items:
            old_item, old_identity = old_items[relative]
            quarantine = f".{name}.open-trestle-old-{transaction}"
            captured = _rename_noreplace(parent, name, quarantine)
            if captured != old_identity or not _matches_owned_file(parent / quarantine, old_item, old_identity):
                restored = _rename_noreplace(parent, quarantine, name)
                _fsync_directory(parent)
                if restored != captured:
                    raise ValueError(f"could not restore changed transition file: {relative}")
                raise ValueError(f"owned file changed during transition: {relative}")
            _fsync_directory(parent)
        identity = _publish_staged(parent, temporary, name)
        if identity != staged_identity or not _matches_owned_file(parent / name, item, staged_identity):
            raise ValueError(f"staged file changed during transition: {relative}")
        _fsync_directory(parent)

    controls = {RECEIPT_PATH, JOURNAL_PATH}
    for relative in sorted(new_paths - controls):
        publish(relative)
    for relative in sorted(old_paths - new_paths):
        item, identity = old_items[relative]
        path = root / relative
        quarantine = f".{path.name}.open-trestle-old-{transaction}"
        captured = _rename_noreplace(path.parent, path.name, quarantine)
        if captured != identity or not _matches_owned_file(path.parent / quarantine, item, identity):
            restored = _rename_noreplace(path.parent, quarantine, path.name)
            _fsync_directory(path.parent)
            if restored != captured:
                raise ValueError(f"could not restore changed transition file: {relative}")
            raise ValueError(f"owned file changed during transition: {relative}")
        _fsync_directory(path.parent)
    publish(RECEIPT_PATH)
    publish(JOURNAL_PATH)


def _transition(archive_path: Path, destdir: Path | None, *, rollback_to_previous: bool) -> None:
    root = _installation_root(destdir)
    recover(destdir)
    current_archive, current_receipt, current_files = _verified_installed_generation(root)
    old_items: dict[str, tuple[InstalledFile, tuple[int, int]]] = {}
    for item in current_files:
        status = _validate_installed_file(root, item)
        old_items[item.path] = (item, (status.st_dev, status.st_ino))
    control_bodies: dict[str, bytes] = {}
    for relative in (RECEIPT_PATH, JOURNAL_PATH):
        body = _read_control_file(root, relative)
        control_bodies[relative] = body
        item = _control_item(relative, body)
        old_items[relative] = (item, _file_identity(root / relative))
    previous_receipt_body: bytes | None = None
    previous_journal_body: bytes | None = None
    if current_receipt["action"] == "upgrade":
        verified_previous = _validate_previous_generation(root, current_receipt)
        _, _, previous_receipt_body, previous_journal_body, old_previous_items = verified_previous
        for item in old_previous_items:
            status = _validate_installed_file(root, item)
            old_items[item.path] = (item, (status.st_dev, status.st_ino))
    transaction = uuid.uuid4().hex
    if rollback_to_previous:
        action = "rollback-version"
        candidate, candidate_files, previous_receipt_body, previous_journal_body, _ = _validate_previous_generation(root, current_receipt)
        previous_receipt = current_receipt["previous"]
        assert isinstance(previous_receipt, dict)
        created_directories = list(previous_receipt["created_directories"])
        obsolete_directories = [
            value for value in current_receipt["created_directories"]
            if value not in created_directories
        ]
        assert previous_receipt_body is not None and previous_journal_body is not None
        receipt_body, journal_body = previous_receipt_body, previous_journal_body
        slot_items: tuple[InstalledFile, ...] = ()
    else:
        action = "upgrade"
        if current_receipt["action"] == "upgrade":
            raise ValueError("upgrade rollback slot must be consumed before another upgrade")
        candidate = validate_archive(archive_path)
        if _version_precedence(candidate.manifest["version"]) <= _version_precedence(current_archive.manifest["version"]):
            raise ValueError("upgrade candidate must be strictly newer than the installed version")
        candidate_files = _managed_generation(candidate)
        previous = {
            "archive_sha256": current_receipt["archive_sha256"],
            "created_directories": current_receipt["created_directories"],
            "files": current_receipt["files"],
            "generation_id": current_receipt["generation_id"],
            "journal_sha256": hashlib.sha256(control_bodies[JOURNAL_PATH]).hexdigest(),
            "manifest_sha256": current_receipt["manifest_sha256"],
            "receipt_sha256": hashlib.sha256(control_bodies[RECEIPT_PATH]).hexdigest(),
            "version": current_receipt["version"],
        }
        destination_for_directories = {item.path for item in candidate_files} | {
            PREVIOUS_ARCHIVE_PATH, PREVIOUS_SIDECAR_PATH,
            PREVIOUS_RECEIPT_PATH, PREVIOUS_JOURNAL_PATH,
        }
        planned = _planned_directories(root, destination_for_directories)
        created_directories = sorted(
            set(current_receipt["created_directories"]) | set(planned),
            key=lambda value: (value.count("/"), value),
        )
        obsolete_directories = []
        receipt_body, journal_body = _transition_documents(
            action=action,
            old_receipt=current_receipt,
            new_archive=candidate,
            new_files=candidate_files,
            created_directories=created_directories,
            transaction=transaction,
            previous=previous,
        )
        slot_items = _previous_slot_items(
            current_archive, control_bodies[RECEIPT_PATH], control_bodies[JOURNAL_PATH]
        )
    controls = (
        _control_item(RECEIPT_PATH, receipt_body),
        _control_item(JOURNAL_PATH, journal_body),
    )
    new_items = {item.path: item for item in (*candidate_files, *slot_items, *controls)}
    destination_paths = set(new_items)
    transaction_created = _planned_directories(root, destination_paths)
    for relative in destination_paths - set(old_items):
        try:
            os.lstat(root / relative)
        except FileNotFoundError:
            continue
        raise FileExistsError(f"destination already exists: {relative}")
    old_generation = _generation_core(
        current_archive.sha256,
        current_receipt["manifest_sha256"],
        current_receipt["version"],
        current_files,
    )
    new_manifest_sha256 = hashlib.sha256(_canonical_json(candidate.manifest)).hexdigest()
    new_generation = _generation_core(
        candidate.sha256, new_manifest_sha256, candidate.manifest["version"], candidate_files
    )
    paths = [
        _plan_entry(
            root,
            transaction,
            relative,
            old_items.get(relative, (None, (0, 0)))[0],
            new_items.get(relative),
        )
        for relative in sorted(set(old_items) | set(new_items))
    ]
    plan = _transaction_plan(
        action=action,
        transaction=transaction,
        old_generation=old_generation,
        new_generation=new_generation,
        old_receipt_sha256=hashlib.sha256(control_bodies[RECEIPT_PATH]).hexdigest(),
        old_journal_sha256=hashlib.sha256(control_bodies[JOURNAL_PATH]).hexdigest(),
        new_receipt_sha256=controls[0].sha256,
        new_journal_sha256=controls[1].sha256,
        created_directories=transaction_created,
        obsolete_directories=obsolete_directories,
        paths=paths,
    )
    generated_paths = tuple(
        value for entry in paths for value in (entry["staged"], entry["quarantine"])
    )
    _preflight_absent(root, generated_paths)
    _start_transaction(root, plan)
    created: list[str] = []
    staged: list[tuple[Path, str, str, InstalledFile, tuple[int, int]]] = []
    try:
        _stage_generation(root, candidate, transaction, created, staged)
        if not rollback_to_previous:
            _stage_previous_slot(
                root, current_archive, control_bodies[RECEIPT_PATH],
                control_bodies[JOURNAL_PATH], transaction, created, staged,
            )
        control_parent = _ensure_directory(root, str(PurePosixPath(RECEIPT_PATH).parent), created)
        for relative, body, item in (
            (RECEIPT_PATH, receipt_body, controls[0]),
            (JOURNAL_PATH, journal_body, controls[1]),
        ):
            name = PurePosixPath(relative).name
            temporary = _stage_file(
                control_parent, name, 0o444, _write_bytes(body), transaction, _is_production(root)
            )
            staged.append((control_parent, temporary, name, item, _file_identity(control_parent / temporary)))
        if sorted(created, key=lambda value: (value.count("/"), value)) != transaction_created:
            raise ValueError("transition directory inventory changed after preflight")
        _apply_transition(root, staged, old_items, transaction)
        _commit_transaction(root, plan)
    except BaseException:
        try:
            recover(destdir)
        except (OSError, ValueError):
            for parent, temporary, _, item, identity in staged:
                _unlink_live_owned_file(parent / temporary, item, identity)
            _remove_created_directories(root, created)
            _abandon_transaction(root, plan)
        raise
    recover(destdir)


def upgrade(archive_path: Path, destdir: Path | None = None) -> None:
    _transition(archive_path, destdir, rollback_to_previous=False)


def rollback_version(archive_path: Path, destdir: Path | None = None) -> None:
    root = _installation_root(destdir)
    recover(destdir)
    executing = validate_archive(archive_path)
    current, _, _ = _verified_installed_generation(root)
    if executing.sha256 != current.sha256:
        raise ValueError("rollback-version must run from the exact installed generation archive")
    _transition(archive_path, destdir, rollback_to_previous=True)


def _remove_created_directories(root: Path, directories: list[str] | tuple[str, ...]) -> None:
    for relative in sorted(set(directories), key=lambda value: (value.count("/"), value), reverse=True):
        if relative == ".":
            continue
        path = root / relative
        try:
            path.rmdir()
        except (FileNotFoundError, OSError):
            continue
        _fsync_directory(path.parent)


def _remove_installation(archive_path: Path, destdir: Path | None, action: str) -> None:
    root = _installation_root(destdir)
    recover(destdir)
    receipt = verify_installed(archive_path, destdir)
    _, _, files = _load_control(root)
    owned: list[tuple[Path, InstalledFile, tuple[int, int]]] = []
    for item in files:
        status = _validate_installed_file(root, item)
        owned.append((root / item.path, item, (status.st_dev, status.st_ino)))
    if receipt["action"] == "upgrade":
        _, _, _, _, previous_items = _validate_previous_generation(root, receipt)
        for item in previous_items:
            status = _validate_installed_file(root, item)
            owned.append((root / item.path, item, (status.st_dev, status.st_ino)))
    controls: list[tuple[Path, InstalledFile, tuple[int, int]]] = []
    for relative in (JOURNAL_PATH, RECEIPT_PATH):
        body = _read_control_file(root, relative)
        path = root / relative
        status = os.lstat(path)
        item = InstalledFile(relative, 0o444, len(body), hashlib.sha256(body).hexdigest(), False)
        controls.append((path, item, (status.st_dev, status.st_ino)))
    _preflight_no_transaction_debris(
        root, {item.path for _, item, _ in [*owned, *controls]}
    )
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
    for command in ("install", "upgrade", "verify-installed", "rollback", "rollback-version", "uninstall", "recover"):
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
        elif options.command == "upgrade":
            upgrade(archive_path, options.destdir)
            print("Open Trestle candidate upgraded.")
        elif options.command == "verify-installed":
            verify_installed(archive_path, options.destdir)
            print("Open Trestle candidate installation verified.")
        elif options.command == "recover":
            recover(options.destdir)
            print("Open Trestle candidate lifecycle recovered.")
        elif options.command == "smoke":
            smoke(archive_path, options.destdir, options.output)
        elif options.command == "rollback":
            rollback(archive_path, options.destdir)
            print("Open Trestle candidate installation rolled back.")
        elif options.command == "rollback-version":
            rollback_version(archive_path, options.destdir)
            print("Open Trestle candidate version rolled back.")
        elif options.command == "uninstall":
            uninstall(archive_path, options.destdir)
            print("Open Trestle candidate uninstalled.")
    except (OSError, ValueError, PermissionError, zipfile.BadZipFile) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
