"""Build and verify the isolated secret-scanner release package."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import uuid
from pathlib import Path, PurePosixPath
from urllib.parse import quote

SCANNER_NAME = "betterleaks"
SCANNER_VERSION = "v1.8.1"
SCANNER_COMMIT = "5eab48332cc48565864514e3bc6de89df091a7c4"
RULESET_IDENTITY = "27ded783c81940d13c22cc46556a3f8184baf397bff08a69fcfae87991925f42"
RULESET_RULE_COUNT = 417
BUILD_PROFILE = "public_detect_run_re2_purego_go1.26.10_linux_amd64_v1"
ROOT_GO = "go1.26.10"
WORKER_GO = "go1.26.10"
LAUNCHER_TOOLCHAIN_MANIFEST = "workers/secret-scanner/launcher/toolchain-v1.json"
LAUNCHER_TOOLCHAIN_CACHE = ".tmp/toolchains/zig-x86_64-linux-0.14.1.tar.xz"
LAUNCHER_ZIG_VERSION = "0.14.1"
LAUNCHER_ZIG_TARGET = "x86_64-linux-musl"
LAUNCHER_CPPFLAGS = ("-DOPEN_TRESTLE_PRODUCTION_BUILD=1",)
LAUNCHER_CFLAGS = (
    "-std=c17", "-O2", "-pipe", "-fPIE", "-fstack-protector-strong",
    "-D_FORTIFY_SOURCE=3", "-Wall", "-Wextra", "-Werror", "-Wformat=2",
    "-Wconversion", "-Wshadow", "-Wstrict-prototypes",
)
LAUNCHER_LDFLAGS = (
    "-static", "-pie", "-s",
    "-Wl,-z,relro,-z,now,-z,noexecstack,--build-id=none",
)
LAUNCHER_BUILD_ENVIRONMENT = {
    "base_environment": "empty",
    "LC_ALL": "C",
    "SOURCE_DATE_EPOCH": "0",
    "cache_policy": "fresh isolated global and local caches for each build",
}
WORKER_BUILD_FLAGS = (
    "-trimpath", "-buildvcs=false", "-ldflags=-s -w -buildid=",
)
RELEASE_SOURCE_PATHS = {"scripts/model_catalog.py": "tools/model_catalog.py"}
EXECUTABLE_PATHS = frozenset({
    "trestle",
    "trestled",
    "libexec/open-trestle/open-trestle-secret-scanner",
    "libexec/open-trestle/open-trestle-secret-scanner-worker",
})


def _file_checksums(path: Path) -> tuple[str, str]:
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1 << 20):
            sha1.update(chunk)
            sha256.update(chunk)
    return sha1.hexdigest(), sha256.hexdigest()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def _tree_digest(root: Path) -> tuple[str, int, int]:
    digest = hashlib.sha256()
    count = 0
    total = 0
    files = sorted(
        (path for path in root.rglob("*") if path.is_file()),
        key=lambda path: path.relative_to(root).as_posix(),
    )
    for path in files:
        relative = path.relative_to(root).as_posix().encode("utf-8")
        size = path.stat().st_size
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(size.to_bytes(8, "big"))
        digest.update(bytes.fromhex(_sha256(path)))
        count += 1
        total += size
    return digest.hexdigest(), count, total


def _launcher_toolchain_manifest(repository: Path) -> tuple[dict[str, object], str]:
    path = repository / LAUNCHER_TOOLCHAIN_MANIFEST
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("launcher toolchain manifest is invalid") from error
    archive = document.get("archive")
    tree = document.get("extracted_tree")
    critical_files = document.get("critical_files")
    runtime_components = document.get("runtime_components")
    if (
        document.get("schema_version") != 1
        or document.get("builder") != "zig"
        or document.get("builder_version") != LAUNCHER_ZIG_VERSION
        or document.get("target") != LAUNCHER_ZIG_TARGET
        or not isinstance(archive, dict)
        or archive.get("sha256") != "24aeeec8af16c381934a6cd7d95c807a8cb2cf7df9fa40d359aa884195c4716c"
        or archive.get("size") != 49086504
        or archive.get("url") != "https://ziglang.org/download/0.14.1/zig-x86_64-linux-0.14.1.tar.xz"
        or archive.get("root") != "zig-x86_64-linux-0.14.1"
        or tree != {
            "sha256": "58e5c7d8fd7b4c2940613201bdae6685fb1f70f879669db913c118cb20bb537a",
            "regular_files": 14673,
            "bytes": 311138938,
        }
        or not isinstance(critical_files, list)
        or not isinstance(runtime_components, list)
        or not isinstance(document.get("input_closure"), dict)
    ):
        raise ValueError("launcher toolchain manifest does not match the frozen pin")
    return document, _sha256(path)


def _verify_toolchain_archive(path: Path, archive: dict[str, object]) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError("launcher toolchain archive is unavailable")
    if path.stat().st_size != archive["size"] or _sha256(path) != archive["sha256"]:
        raise ValueError("launcher toolchain archive identity mismatch")


def _download_toolchain_archive(path: Path, archive: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        _verify_toolchain_archive(path, archive)
        return
    temporary = path.with_suffix(path.suffix + ".partial")
    temporary.unlink(missing_ok=True)
    try:
        with urllib.request.urlopen(str(archive["url"]), timeout=120) as response:
            if response.geturl() != archive["url"] or getattr(response, "status", 200) != 200:
                raise ValueError("launcher toolchain download was redirected or rejected")
            with temporary.open("xb") as destination:
                copied = 0
                while chunk := response.read(1 << 20):
                    copied += len(chunk)
                    if copied > archive["size"]:
                        raise ValueError("launcher toolchain download exceeds pinned size")
                    destination.write(chunk)
        _verify_toolchain_archive(temporary, archive)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _extract_toolchain(archive_path: Path, destination: Path, manifest: dict[str, object]) -> Path:
    archive = manifest["archive"]
    expected_root = str(archive["root"])
    destination.mkdir(parents=True)
    with tarfile.open(archive_path, mode="r:xz") as source:
        members = source.getmembers()
        file_bytes = sum(member.size for member in members if member.isfile())
        if file_bytes != manifest["extracted_tree"]["bytes"]:
            raise ValueError("launcher toolchain archive payload size mismatch")
        for member in members:
            relative = PurePosixPath(member.name)
            if (
                relative.is_absolute()
                or not relative.parts
                or relative.parts[0] != expected_root
                or any(part in {"", ".", ".."} for part in relative.parts)
                or not (member.isdir() or member.isfile())
            ):
                raise ValueError("launcher toolchain archive member is unsafe")
            target = destination.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                target.chmod(member.mode & 0o777)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            extracted = source.extractfile(member)
            if extracted is None:
                raise ValueError("launcher toolchain archive member is unreadable")
            with extracted, target.open("xb") as output:
                shutil.copyfileobj(extracted, output, 1 << 20)
            target.chmod(member.mode & 0o777)
    root = destination / expected_root
    tree = manifest["extracted_tree"]
    if _tree_digest(root) != (tree["sha256"], tree["regular_files"], tree["bytes"]):
        raise ValueError("launcher toolchain extracted-tree identity mismatch")
    for entry in manifest["critical_files"]:
        relative = PurePosixPath(entry["path"])
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
            raise ValueError("launcher toolchain critical path is invalid")
        path = root.joinpath(*relative.parts)
        if path.stat().st_size != entry["size"] or _sha256(path) != entry["sha256"]:
            raise ValueError("launcher toolchain critical file mismatch")
    version = _run([str(root / "zig"), "version"], cwd=destination, environment={"LC_ALL": "C"}).strip()
    if version != LAUNCHER_ZIG_VERSION:
        raise ValueError("launcher Zig version mismatch")
    return root


def provision_launcher_toolchain(
    repository: Path, temporary: Path
) -> tuple[Path, dict[str, object], str]:
    """Provision the complete pinned compiler, linker, sysroot, and static runtime closure."""
    manifest, manifest_sha256 = _launcher_toolchain_manifest(repository)
    archive_path = repository / LAUNCHER_TOOLCHAIN_CACHE
    _download_toolchain_archive(archive_path, manifest["archive"])
    private_archive = temporary / "launcher-toolchain.tar.xz"
    shutil.copyfile(archive_path, private_archive)
    private_archive.chmod(0o400)
    _verify_toolchain_archive(private_archive, manifest["archive"])
    toolchain = _extract_toolchain(private_archive, temporary / "launcher-toolchain", manifest)
    return toolchain, manifest, manifest_sha256


def _run(arguments: list[str], *, cwd: Path, environment: dict[str, str] | None = None) -> str:
    try:
        result = subprocess.run(
            arguments,
            cwd=cwd,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise ValueError(f"release command failed: {arguments[0]}") from error
    return result.stdout


def _parse_build_modules(build_info: str) -> dict[tuple[str, str], str]:
    modules: dict[tuple[str, str], str] = {}
    for line in build_info.splitlines():
        fields = line.strip().split("\t")
        if fields and fields[0] == "=>":
            raise ValueError("replaced linked modules are unsupported")
        if not fields or fields[0] != "dep":
            continue
        if len(fields) != 4 or not fields[1] or not fields[2] or not fields[3].startswith("h1:"):
            raise ValueError("linked module metadata is incomplete")
        identity = (fields[1], fields[2])
        if identity in modules:
            raise ValueError("duplicate linked module metadata")
        modules[identity] = fields[3]
    if not modules:
        raise ValueError("linked module inventory is empty")
    return modules


def verify_root_build_info(build_info: str) -> None:
    """Require the pinned root Go toolchain in package metadata."""
    lines = build_info.splitlines()
    if not lines or not lines[0].endswith(f": {ROOT_GO}"):
        raise ValueError("root Go toolchain metadata mismatch")


def verify_worker_build_info(build_info: str) -> None:
    """Require the frozen Go toolchain and target settings in the linked worker."""
    lines = build_info.splitlines()
    if not lines or not lines[0].endswith(": " + WORKER_GO):
        raise ValueError("worker Go toolchain metadata mismatch")
    required = {
        "build\t-trimpath=true",
        "build\tCGO_ENABLED=0",
        "build\tGOARCH=amd64",
        "build\tGOOS=linux",
    }
    normalized = {line.strip() for line in lines}
    if not required.issubset(normalized):
        raise ValueError("worker target metadata mismatch")

def verify_linked_licenses(
    build_info: str, manifest: dict[str, object], license_root: Path
) -> list[dict[str, str]]:
    """Match reviewed license material to the exact binary module closure."""
    if manifest.get("schema_version") != 1 or not isinstance(manifest.get("modules"), list):
        raise ValueError("license manifest is invalid")
    linked = _parse_build_modules(build_info)
    reviewed: dict[tuple[str, str], dict[str, object]] = {}
    for entry in manifest["modules"]:
        if not isinstance(entry, dict):
            raise ValueError("license manifest entry is invalid")
        module = entry.get("module")
        version = entry.get("version")
        license_name = entry.get("license")
        files = entry.get("files")
        if (
            not isinstance(module, str)
            or not isinstance(version, str)
            or not isinstance(license_name, str)
            or license_name in {"", "NOASSERTION", "UNKNOWN"}
            or not isinstance(files, list)
            or not files
        ):
            raise ValueError("license manifest entry is incomplete")
        identity = (module, version)
        if identity in reviewed:
            raise ValueError("duplicate license manifest entry")
        for file_entry in files:
            if not isinstance(file_entry, dict):
                raise ValueError("license file entry is invalid")
            relative = file_entry.get("file")
            expected_digest = file_entry.get("sha256")
            relative_path = PurePosixPath(relative) if isinstance(relative, str) else None
            if (
                relative_path is None
                or not re.fullmatch(r"[A-Za-z0-9._/-]+", relative)
                or relative_path.is_absolute()
                or any(part in {"", ".", ".."} for part in relative_path.parts)
            ):
                raise ValueError("license file path is invalid")
            path = license_root / relative
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"license file is missing: {relative}")
            if _sha256(path) != expected_digest:
                raise ValueError(f"license digest mismatch: {relative}")
        reviewed[identity] = entry
    if set(linked) != set(reviewed):
        raise ValueError("linked module inventory mismatch")
    return [
        {
            "module": module,
            "version": version,
            "module_sum": linked[(module, version)],
            "license": str(reviewed[(module, version)]["license"]),
        }
        for module, version in sorted(linked)
    ]


def verify_launcher_licenses(
    repository: Path, toolchain_manifest: dict[str, object]
) -> list[dict[str, str]]:
    """Verify legal material for every non-project component linked into the launcher."""
    root = repository / "THIRD_PARTY_LICENSES/secret-scanner-launcher"
    try:
        inventory = json.loads((root / "COMPONENTS.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("launcher legal inventory is invalid") from error
    components = inventory.get("components")
    if (
        inventory.get("schema_version") != 1
        or inventory.get("toolchain_manifest") != LAUNCHER_TOOLCHAIN_MANIFEST
        or components != toolchain_manifest["runtime_components"]
    ):
        raise ValueError("launcher legal inventory does not match the toolchain closure")
    result: list[dict[str, str]] = []
    for component in components:
        license_file = component.get("license_file")
        if not isinstance(license_file, str) or PurePosixPath(license_file).name != license_file:
            raise ValueError("launcher license path is invalid")
        path = root / license_file
        if path.is_symlink() or not path.is_file() or _sha256(path) != component.get("license_sha256"):
            raise ValueError("launcher license identity mismatch")
        if component.get("license") != "MIT":
            raise ValueError("launcher runtime license is unknown or incompatible")
        result.append(dict(component))
    return result


def _go_sum_entries(path: Path) -> dict[tuple[str, str, bool], str]:
    entries: dict[tuple[str, str, bool], str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) != 3:
            raise ValueError("worker go.sum is invalid")
        module, version, checksum = fields
        is_go_mod = version.endswith("/go.mod")
        if is_go_mod:
            version = version.removesuffix("/go.mod")
        entries[(module, version, is_go_mod)] = checksum
    return entries


def add_go_mod_sums(modules: list[dict[str, str]], go_sum_path: Path) -> list[dict[str, str]]:
    sums = _go_sum_entries(go_sum_path)
    result: list[dict[str, str]] = []
    for module in modules:
        identity = (module["module"], module["version"])
        if sums.get((*identity, False)) != module["module_sum"]:
            raise ValueError("worker module sum does not match go.sum")
        go_mod_sum = sums.get((*identity, True))
        if not go_mod_sum:
            raise ValueError("worker go.mod sum is missing")
        result.append({**module, "go_mod_sum": go_mod_sum})
    return result


def _canonical_json(document: object) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def encode_release_evidence(
    *,
    launcher_sha1: str,
    launcher_sha256: str,
    worker_sha1: str,
    worker_sha256: str,
    launcher_source_sha256: str,
    launcher_build_contract_sha256: str,
    launcher_toolchain_manifest_sha256: str,
    launcher_toolchain_manifest: dict[str, object],
    launcher_runtime_components: list[dict[str, str]],
    modules: list[dict[str, str]],
) -> tuple[bytes, bytes]:
    """Encode deterministic scanner build evidence and SPDX 2.3 JSON."""
    for digest in (launcher_sha1, worker_sha1):
        if not re.fullmatch(r"[0-9a-f]{40}", digest):
            raise ValueError("release digest is invalid")
    for digest in (
        launcher_sha256,
        worker_sha256,
        launcher_source_sha256,
        launcher_build_contract_sha256,
        launcher_toolchain_manifest_sha256,
    ):
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("release digest is invalid")
    combined = hashlib.sha256(
        f"{launcher_sha256}\n{worker_sha256}\n".encode("ascii")
    ).hexdigest()
    builder_identity = hashlib.sha256(_canonical_json({
        "archive_sha256": launcher_toolchain_manifest["archive"]["sha256"],
        "build_contract_sha256": launcher_build_contract_sha256,
        "cflags": list(LAUNCHER_CFLAGS),
        "cppflags": list(LAUNCHER_CPPFLAGS),
        "extracted_tree_sha256": launcher_toolchain_manifest["extracted_tree"]["sha256"],
        "ldflags": list(LAUNCHER_LDFLAGS),
        "build_environment": LAUNCHER_BUILD_ENVIRONMENT,
        "source_sha256": launcher_source_sha256,
        "target": LAUNCHER_ZIG_TARGET,
        "toolchain_manifest_sha256": launcher_toolchain_manifest_sha256,
    })).hexdigest()
    evidence = {
        "schema_version": 1,
        "scanner": SCANNER_NAME,
        "scanner_version": SCANNER_VERSION,
        "scanner_commit": SCANNER_COMMIT,
        "ruleset_identity": RULESET_IDENTITY,
        "ruleset_rule_count": RULESET_RULE_COUNT,
        "regexp_engine": "re2",
        "build_profile": BUILD_PROFILE,
        "sandbox_profile": "single_threaded_landlock_exec_then_worker_seccomp_tsync_v1",
        "launcher": {
            "sha256": launcher_sha256,
            "source_sha256": launcher_source_sha256,
            "builder": "zig",
            "builder_version": LAUNCHER_ZIG_VERSION,
            "target": LAUNCHER_ZIG_TARGET,
            "toolchain_archive": launcher_toolchain_manifest["archive"],
            "toolchain_extracted_tree": launcher_toolchain_manifest["extracted_tree"],
            "toolchain_input_closure": launcher_toolchain_manifest["input_closure"],
            "toolchain_manifest_sha256": launcher_toolchain_manifest_sha256,
            "build_contract_sha256": launcher_build_contract_sha256,
            "builder_identity": builder_identity,
            "cppflags": list(LAUNCHER_CPPFLAGS),
            "cflags": list(LAUNCHER_CFLAGS),
            "ldflags": list(LAUNCHER_LDFLAGS),
            "build_environment": LAUNCHER_BUILD_ENVIRONMENT,
            "runtime_components": launcher_runtime_components,
        },
        "worker": {
            "sha256": worker_sha256,
            "go_toolchain": WORKER_GO,
            "goos": "linux",
            "goarch": "amd64",
            "cgo_enabled": False,
            "build_flags": list(WORKER_BUILD_FLAGS),
            "modules": modules,
        },
        "root_client": {
            "go_toolchain": ROOT_GO,
            "launcher_sha256": launcher_sha256,
            "worker_sha256": worker_sha256,
        },
        "combined_release_identity": combined,
    }
    root_id = "SPDXRef-Package-Secret-Scanner"
    worker_file_id = "SPDXRef-File-Worker"
    launcher_file_id = "SPDXRef-File-Launcher"
    packages = [{
        "SPDXID": root_id,
        "name": "Open Trestle secret scanner",
        "versionInfo": BUILD_PROFILE,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "Apache-2.0",
        "licenseDeclared": "Apache-2.0",
        "primaryPackagePurpose": "APPLICATION",
    }]
    relationships = [
        {"spdxElementId": root_id, "relationshipType": "DISTRIBUTION_ARTIFACT", "relatedSpdxElement": launcher_file_id},
        {"spdxElementId": root_id, "relationshipType": "DISTRIBUTION_ARTIFACT", "relatedSpdxElement": worker_file_id},
    ]
    builder_package_id = "SPDXRef-Package-Launcher-Builder-Zig"
    packages.append({
        "SPDXID": builder_package_id,
        "name": "Zig launcher toolchain",
        "versionInfo": LAUNCHER_ZIG_VERSION,
        "downloadLocation": launcher_toolchain_manifest["archive"]["url"],
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "checksums": [{
            "algorithm": "SHA256",
            "checksumValue": launcher_toolchain_manifest["archive"]["sha256"],
        }],
        "sourceInfo": "Complete compiler, linker, headers, sysroot, and static-library closure is bound by the archive and extracted-tree SHA-256 values in the scanner release evidence.",
    })
    relationships.append({
        "spdxElementId": builder_package_id,
        "relationshipType": "BUILD_TOOL_OF",
        "relatedSpdxElement": launcher_file_id,
    })
    for component in launcher_runtime_components:
        component_identity = f"launcher-runtime\n{component['name']}\n{component['version']}".encode("utf-8")
        component_id = "SPDXRef-Package-" + hashlib.sha256(component_identity).hexdigest()
        packages.append({
            "SPDXID": component_id,
            "name": component["name"],
            "versionInfo": component["version"],
            "downloadLocation": launcher_toolchain_manifest["archive"]["url"],
            "filesAnalyzed": False,
            "licenseConcluded": component["license"],
            "licenseDeclared": component["license"],
            "primaryPackagePurpose": "LIBRARY",
            "sourceInfo": f"Runtime code linked from the verified Zig {LAUNCHER_ZIG_VERSION} toolchain archive.",
        })
        relationships.append({
            "spdxElementId": launcher_file_id,
            "relationshipType": "STATIC_LINK",
            "relatedSpdxElement": component_id,
        })
    linux_headers_id = "SPDXRef-Package-Linux-UAPI-Headers"
    packages.append({
        "SPDXID": linux_headers_id,
        "name": "Linux UAPI headers bundled in Zig 0.14.1",
        "versionInfo": "zig-0.14.1-bundle",
        "downloadLocation": launcher_toolchain_manifest["archive"]["url"],
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "GPL-2.0 WITH Linux-syscall-note",
        "primaryPackagePurpose": "SOURCE",
        "sourceInfo": "Compile-time headers only; no Linux kernel code is linked into the launcher.",
    })
    relationships.append({
        "spdxElementId": linux_headers_id,
        "relationshipType": "BUILD_DEPENDENCY_OF",
        "relatedSpdxElement": launcher_file_id,
    })
    for module in modules:
        identity = f"{module['module']}\n{module['version']}".encode("utf-8")
        package_id = "SPDXRef-Package-" + hashlib.sha256(identity).hexdigest()
        packages.append({
            "SPDXID": package_id,
            "name": module["module"],
            "versionInfo": module["version"],
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": module["license"],
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": f"pkg:golang/{quote(module['module'], safe='/')}@{quote(module['version'], safe='._-~')}",
            }],
        })
        relationships.append({
            "spdxElementId": root_id,
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": package_id,
        })
    namespace_identity = hashlib.sha256(_canonical_json(evidence)).hexdigest()
    spdx = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"Open Trestle secret scanner {BUILD_PROFILE}",
        "documentNamespace": "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, namespace_identity)),
        "creationInfo": {
            "created": "2026-09-29T00:00:00Z",
            "creators": ["Tool: open-trestle-secret-scanner-packager-1"],
        },
        "documentDescribes": [root_id],
        "files": [
            {
                "SPDXID": launcher_file_id,
                "fileName": "./libexec/open-trestle/open-trestle-secret-scanner",
                "checksums": [
                    {"algorithm": "SHA1", "checksumValue": launcher_sha1},
                    {"algorithm": "SHA256", "checksumValue": launcher_sha256},
                ],
                "licenseConcluded": "Apache-2.0 AND MIT",
                "licenseInfoInFiles": ["NOASSERTION"],
                "copyrightText": "NOASSERTION",
            },
            {
                "SPDXID": worker_file_id,
                "fileName": "./libexec/open-trestle/open-trestle-secret-scanner-worker",
                "checksums": [
                    {"algorithm": "SHA1", "checksumValue": worker_sha1},
                    {"algorithm": "SHA256", "checksumValue": worker_sha256},
                ],
                "licenseConcluded": "NOASSERTION",
                "licenseInfoInFiles": ["NOASSERTION"],
                "copyrightText": "NOASSERTION",
            },
        ],
        "packages": packages,
        "relationships": relationships,
    }
    return _canonical_json(evidence), _canonical_json(spdx)


def _staging_files(root: Path) -> set[str]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("staging directory is unavailable or symlinked")
    files: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("staging entries must not be symlinks")
        if path.is_file():
            files.add(PurePosixPath(path.relative_to(root).as_posix()).as_posix())
    return files


def release_input_digests(repository: Path) -> dict[str, str]:
    """Bind staged scripts to the maintained repository release inputs."""
    digests: dict[str, str] = {}
    for target, source in RELEASE_SOURCE_PATHS.items():
        path = repository / source
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"release input is unavailable: {source}")
        digests[target] = _sha256(path)
    return digests


def validate_staging(
    root: Path,
    expected_files: set[str],
    expected_source_digests: dict[str, str] | None = None,
) -> tuple[str, ...]:
    """Verify an exact runtime-only staging tree against reviewed source inputs."""
    if expected_source_digests is None:
        expected_source_digests = release_input_digests(Path(__file__).resolve().parent.parent)
    actual = _staging_files(root)
    if actual != expected_files:
        raise ValueError("staging inventory mismatch")
    forbidden_segments = {"references", "source", "sources", "test", "tests", "tools", "workers"}
    forbidden_suffixes = {".c", ".go", ".h", ".o", ".py", ".sh"}
    for relative in actual:
        path = PurePosixPath(relative)
        if forbidden_segments.intersection(part.lower() for part in path.parts):
            raise ValueError("source, test, private reference, or build tool in staging")
        if relative == "scripts/model_catalog.py":
            if stat.S_IMODE((root / relative).stat().st_mode) != 0o444:
                raise ValueError("catalog script mode is not read-only")
            if _sha256(root / relative) != expected_source_digests.get(relative):
                raise ValueError("catalog script digest mismatch")
        elif path.suffix.lower() in forbidden_suffixes or path.name in {"go", "gcc", "make", "ld", "zig", "clang", "lld", "musl-gcc"}:
            raise ValueError("source, test, private reference, or build tool in staging")
    for relative in EXECUTABLE_PATHS:
        path = root / relative
        if relative not in actual or stat.S_IMODE(path.stat().st_mode) != 0o555:
            raise ValueError("scanner executable mode is not read-only")
    data = root / "data"
    if data.is_symlink() or not data.is_dir() or any(data.iterdir()):
        raise ValueError("runtime data staging must be an empty directory")
    return tuple(sorted(actual))


def _environment(toolchain: str, go_tmp: Path | None = None) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update({
        "GOWORK": "off",
        "GOTOOLCHAIN": toolchain,
        "GOOS": "linux",
        "GOARCH": "amd64",
        "CGO_ENABLED": "0",
    })
    if go_tmp is not None:
        go_tmp.mkdir(parents=True, exist_ok=True)
        environment["GOTMPDIR"] = str(go_tmp)
    return environment


def _build_worker(repository: Path, output: Path, go_tmp: Path) -> None:
    _run(
        [
            "go", "build", "-trimpath", "-buildvcs=false",
            "-ldflags=-s -w -buildid=", "-o", str(output),
            "./cmd/open-trestle-secret-scanner",
        ],
        cwd=repository / "workers/secret-scanner",
        environment=_environment(WORKER_GO, go_tmp),
    )



def verify_launcher_build_contract(repository: Path) -> None:
    """Require the reviewed makefile to match the hermetic production command."""
    makefile = (repository / "workers/secret-scanner/launcher/build.mk").read_text(encoding="utf-8")
    required = (
        f"EXPECTED_ZIG_VERSION := {LAUNCHER_ZIG_VERSION}",
        f"ZIG_TARGET := {LAUNCHER_ZIG_TARGET}",
        "CPPFLAGS := " + " ".join(LAUNCHER_CPPFLAGS),
        "CFLAGS := " + " ".join(LAUNCHER_CFLAGS),
        "LDFLAGS := " + " ".join(LAUNCHER_LDFLAGS),
    )
    if any(line not in makefile.splitlines() for line in required):
        raise ValueError("launcher build contract mismatch")


def launcher_build_command(zig: Path, output: Path) -> list[str]:
    """Return the complete fixed launcher compiler invocation."""
    return [
        str(zig), "cc", "-target", LAUNCHER_ZIG_TARGET,
        *LAUNCHER_CPPFLAGS, *LAUNCHER_CFLAGS, *LAUNCHER_LDFLAGS,
        "-o", str(output), "launcher.c",
    ]


def _build_launcher(
    repository: Path, output: Path, toolchain: Path, cache: Path
) -> None:
    environment = {
        "LC_ALL": "C",
        "SOURCE_DATE_EPOCH": "0",
        "ZIG_GLOBAL_CACHE_DIR": str(cache / "global"),
        "ZIG_LOCAL_CACHE_DIR": str(cache / "local"),
    }
    _run(
        launcher_build_command(toolchain / "zig", output),
        cwd=repository / "workers/secret-scanner/launcher",
        environment=environment,
    )


def verify_static_pie_launcher(path: Path) -> None:
    """Require a static x86-64 PIE with no interpreter or dynamic dependency."""
    data = path.read_bytes()
    header_format = "<16sHHIQQQIHHHHHH"
    header_size = struct.calcsize(header_format)
    if len(data) < header_size:
        raise ValueError("launcher ELF header is truncated")
    header = struct.unpack_from(header_format, data)
    identity, elf_type, machine = header[0], header[1], header[2]
    program_offset, program_entry_size, program_count = header[5], header[9], header[10]
    if (
        identity[:7] != b"\x7fELF\x02\x01\x01"
        or elf_type != 3
        or machine != 62
        or program_entry_size != struct.calcsize("<IIQQQQQQ")
    ):
        raise ValueError("launcher is not an x86-64 static PIE")
    dynamic: tuple[int, int] | None = None
    has_nonexec_stack = False
    for index in range(program_count):
        offset = program_offset + index * program_entry_size
        if offset + program_entry_size > len(data):
            raise ValueError("launcher program header is truncated")
        program_type, flags, file_offset, _, _, file_size, _, _ = struct.unpack_from(
            "<IIQQQQQQ", data, offset
        )
        if program_type == 3:
            raise ValueError("launcher has a dynamic interpreter")
        if program_type == 2:
            dynamic = (file_offset, file_size)
        if program_type == 0x6474E551:
            has_nonexec_stack = flags & 1 == 0
    if dynamic is None or not has_nonexec_stack:
        raise ValueError("launcher hardening metadata is incomplete")
    dynamic_offset, dynamic_size = dynamic
    has_pie = False
    has_bind_now = False
    for offset in range(dynamic_offset, dynamic_offset + dynamic_size, 16):
        if offset + 16 > len(data):
            raise ValueError("launcher dynamic section is truncated")
        tag, value = struct.unpack_from("<qQ", data, offset)
        if tag == 0:
            break
        if tag == 1:
            raise ValueError("launcher has a dynamic dependency")
        if tag == 24 or tag == 30 and value & 8:
            has_bind_now = True
        if tag == 0x6FFFFFFB and value & 0x08000000:
            has_pie = True
    if not has_pie or not has_bind_now:
        raise ValueError("launcher PIE or BIND_NOW flag is missing")
    if b"GLIBC_" in data or b"GNU C Library" in data:
        raise ValueError("launcher contains a glibc runtime reference")


def _copy_file(source: Path, destination: Path, mode: int = 0o444) -> None:
    if source.is_symlink() or not source.is_file():
        raise ValueError(f"release input is unavailable: {source.name}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(mode)


def _expected_staging_files(repository: Path) -> set[str]:
    files = {
        "ca-certificates.crt", "LICENSE", "NOTICE", "trestle", "trestled",
        *RELEASE_SOURCE_PATHS,
        "libexec/open-trestle/open-trestle-secret-scanner",
        "libexec/open-trestle/open-trestle-secret-scanner-worker",
        "release/secret-scanner-release.json",
        "release/secret-scanner.spdx.json",
    }
    for source_root in (repository / "THIRD_PARTY_LICENSES",):
        for path in source_root.rglob("*"):
            if path.is_file():
                files.add("licenses/" + path.relative_to(source_root).as_posix())
    return files


def package(repository: Path, output: Path) -> None:
    """Build deterministic scanner binaries and create the runtime staging tree."""
    repository = repository.resolve()
    expected_source_digests = release_input_digests(repository)
    output = output.resolve()
    if output == repository or repository not in output.parents:
        raise ValueError("staging output must be a repository subdirectory")
    root_mod = (repository / "go.mod").read_text(encoding="utf-8")
    if "\ngo 1.25.0\n" not in root_mod or "\ntoolchain go1.26.10\n" not in root_mod:
        raise ValueError("root toolchain pin changed")
    worker_mod = (repository / "workers/secret-scanner/go.mod").read_text(encoding="utf-8")
    if "\ngo 1.25.0\n" not in worker_mod or "\ntoolchain go1.26.10\n" not in worker_mod:
        raise ValueError("worker toolchain pin changed")
    temporary_root = repository / ".tmp"
    temporary_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="open-trestle-secret-scanner-", dir=temporary_root) as directory:
        temporary = Path(directory)
        go_tmp = temporary / "go-tmp"
        verify_launcher_build_contract(repository)
        toolchain, toolchain_manifest, toolchain_manifest_sha256 = provision_launcher_toolchain(
            repository, temporary
        )
        launcher_runtime_components = verify_launcher_licenses(repository, toolchain_manifest)
        launcher_a = temporary / "launcher-a"
        launcher_b = temporary / "launcher-b"
        worker_a = temporary / "worker-a"
        worker_b = temporary / "worker-b"
        _build_launcher(repository, launcher_a, toolchain, temporary / "zig-cache-a")
        _build_launcher(repository, launcher_b, toolchain, temporary / "zig-cache-b")
        _build_worker(repository, worker_a, go_tmp)
        _build_worker(repository, worker_b, go_tmp)
        if launcher_a.read_bytes() != launcher_b.read_bytes():
            raise ValueError("launcher builds are not deterministic")
        verify_static_pie_launcher(launcher_a)
        verify_static_pie_launcher(launcher_b)
        if worker_a.read_bytes() != worker_b.read_bytes():
            raise ValueError("worker builds are not deterministic")
        launcher_sha1, launcher_digest = _file_checksums(launcher_a)
        worker_sha1, worker_digest = _file_checksums(worker_a)
        build_info = _run(["go", "version", "-m", str(worker_a)], cwd=repository)
        verify_worker_build_info(build_info)
        license_root = repository / "THIRD_PARTY_LICENSES/secret-scanner"
        manifest = json.loads((license_root / "MODULES.json").read_text(encoding="utf-8"))
        modules = verify_linked_licenses(build_info, manifest, license_root)
        modules = add_go_mod_sums(modules, repository / "workers/secret-scanner/go.sum")
        evidence, spdx = encode_release_evidence(
            launcher_sha1=launcher_sha1,
            launcher_sha256=launcher_digest,
            worker_sha1=worker_sha1,
            worker_sha256=worker_digest,
            launcher_source_sha256=_sha256(repository / "workers/secret-scanner/launcher/launcher.c"),
            launcher_build_contract_sha256=_sha256(repository / "workers/secret-scanner/launcher/build.mk"),
            launcher_toolchain_manifest_sha256=toolchain_manifest_sha256,
            launcher_toolchain_manifest=toolchain_manifest,
            launcher_runtime_components=launcher_runtime_components,
            modules=modules,
        )
        if output.exists():
            if output.is_symlink():
                raise ValueError("staging output must not be symlinked")
            shutil.rmtree(output)
        output.mkdir(parents=True)
        (output / "data").mkdir()
        _copy_file(Path("/etc/ssl/certs/ca-certificates.crt").resolve(), output / "ca-certificates.crt")
        _copy_file(repository / "LICENSE", output / "LICENSE")
        _copy_file(repository / "NOTICE", output / "NOTICE")
        for target, source in RELEASE_SOURCE_PATHS.items():
            _copy_file(repository / source, output / target)
        shutil.copytree(repository / "THIRD_PARTY_LICENSES", output / "licenses")
        for path in (output / "licenses").rglob("*"):
            if path.is_file():
                path.chmod(0o444)
        _copy_file(
            launcher_a,
            output / "libexec/open-trestle/open-trestle-secret-scanner",
            0o555,
        )
        _copy_file(
            worker_a,
            output / "libexec/open-trestle/open-trestle-secret-scanner-worker",
            0o555,
        )
        staged_launcher = output / "libexec/open-trestle/open-trestle-secret-scanner"
        staged_worker = output / "libexec/open-trestle/open-trestle-secret-scanner-worker"
        if _sha256(staged_launcher) != launcher_digest or _sha256(staged_worker) != worker_digest:
            raise ValueError("staged scanner digest mismatch")
        release_dir = output / "release"
        release_dir.mkdir()
        (release_dir / "secret-scanner-release.json").write_bytes(evidence)
        (release_dir / "secret-scanner.spdx.json").write_bytes(spdx)
        for path in release_dir.iterdir():
            path.chmod(0o444)
        root_environment = _environment(ROOT_GO, go_tmp)
        root_flags = (
            "-s -w -buildid= "
            f"-X github.com/georgejieh/open-trestle/internal/secretscan.expectedSecretScannerLauncherSHA256={launcher_digest} "
            f"-X github.com/georgejieh/open-trestle/internal/secretscan.expectedSecretScannerWorkerSHA256={worker_digest}"
        )
        for command, name in (("./cmd/trestle", "trestle"), ("./cmd/trestled", "trestled")):
            _run(
                ["go", "build", "-trimpath", "-buildvcs=false", f"-ldflags={root_flags}", "-o", str(output / name), command],
                cwd=repository,
                environment=root_environment,
            )
            (output / name).chmod(0o555)
            root_build_info = _run(["go", "version", "-m", str(output / name)], cwd=repository)
            verify_root_build_info(root_build_info)
            binary = (output / name).read_bytes()
            if launcher_digest.encode("ascii") not in binary or worker_digest.encode("ascii") not in binary:
                raise ValueError(f"{name} does not contain both scanner digests")
    validate_staging(output, _expected_staging_files(repository), expected_source_digests)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", metavar="DIRECTORY")
    parser.add_argument("--output", default=".container", metavar="DIRECTORY")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    repository = Path(__file__).resolve().parent.parent
    try:
        if arguments.verify:
            validate_staging(
                repository / arguments.verify,
                _expected_staging_files(repository),
                release_input_digests(repository),
            )
        else:
            package(repository, repository / arguments.output)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
