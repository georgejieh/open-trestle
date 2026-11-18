"""Build and verify the secret-scanner release package, or a development build."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path, PurePosixPath
from urllib.parse import quote

from local_alpha_system import capture_source_state

SCANNER_NAME = "betterleaks"
SCANNER_VERSION = "v1.8.1"
SCANNER_COMMIT = "5eab48332cc48565864514e3bc6de89df091a7c4"
RULESET_IDENTITY = "27ded783c81940d13c22cc46556a3f8184baf397bff08a69fcfae87991925f42"
RULESET_RULE_COUNT = 417
BUILD_PROFILE = "public_detect_run_re2_host_go1.26.11_wasip1_wasm_v1"
GO_TOOLCHAIN = "go1.26.11"
RELEASE_TARGET = ("linux", "amd64")
SCANNER_DIRECTORY = "workers/secret-scanner"
GUEST_DIRECTORY = "workers/secret-scanner/guest"
SCANNER_MODULE = "github.com/georgejieh/open-trestle/workers/secret-scanner"
HELPER_PACKAGE = SCANNER_MODULE + "/cmd/open-trestle-scan-helper"
GUEST_PACKAGE = SCANNER_MODULE + "/guest"
HELPER_NAME = "open-trestle-scan-helper"
GUEST_NAME = "open-trestle-scan-guest.wasm"
HELPER_PATH = "libexec/open-trestle/" + HELPER_NAME
HELPER_PIN = "github.com/georgejieh/open-trestle/internal/secretscan.expectedHelperSHA256"
BUILDINFO_PACKAGE = "github.com/georgejieh/open-trestle/internal/buildinfo"
GUEST_BUILD_FLAGS = ("-trimpath", "-buildvcs=false", "-ldflags=-s -w -buildid=")
RELEASE_SOURCE_PATHS = {"scripts/model_catalog.py": "tools/model_catalog.py"}
EXECUTABLE_PATHS = frozenset({"trestle", "trestled", HELPER_PATH})
# The linker embeds a program's module information between these markers.
MODINFO_START = bytes.fromhex("3077af0c9274080241e1c107e6d618e6")
MODINFO_END = bytes.fromhex("f932433186182072008242104116d8f2")


def _file_checksums(path: Path) -> tuple[str, str]:
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1 << 20):
            sha1.update(chunk)
            sha256.update(chunk)
    return sha1.hexdigest(), sha256.hexdigest()


def _sha256(path: Path) -> str:
    return _file_checksums(path)[1]


def _run(arguments: list[str], *, cwd: Path, environment: dict[str, str] | None = None) -> str:
    try:
        result = subprocess.run(
            arguments, cwd=cwd, env=environment, check=True, capture_output=True, text=True,
        )
    except OSError as error:
        raise ValueError(f"release command failed: {arguments[0]}") from error
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or "").strip()[-2000:]
        raise ValueError(f"release command failed: {' '.join(arguments[:3])}: {detail}") from error
    return result.stdout


def _go_environment(go_tmp: Path, target: tuple[str, str] | None = None) -> dict[str, str]:
    fixed = {"GOOS", "GOARCH", "CGO_ENABLED", "GOWORK", "GOTOOLCHAIN", "GOFLAGS", "GOENV", "GOEXPERIMENT"}
    environment = {key: value for key, value in os.environ.items() if key.upper() not in fixed}
    environment.update({
        "CGO_ENABLED": "0", "GOWORK": "off", "GOTOOLCHAIN": GO_TOOLCHAIN,
        "GOFLAGS": "", "GOENV": "off", "GOEXPERIMENT": "", "GOTMPDIR": str(go_tmp),
    })
    go_tmp.mkdir(parents=True, exist_ok=True)
    if target is not None:
        environment["GOOS"], environment["GOARCH"] = target
    return environment


def _executable_name(name: str, goos: str) -> str:
    return name + ".exe" if goos == "windows" else name


def parse_target(value: str) -> tuple[str, str]:
    match = re.fullmatch(r"([a-z0-9]+)/([a-z0-9]+)", value)
    if match is None:
        raise ValueError("target must be GOOS/GOARCH")
    return match.group(1), match.group(2)


def _host_target(repository: Path, go_tmp: Path) -> tuple[str, str]:
    fields = _run(["go", "env", "GOOS", "GOARCH"], cwd=repository, environment=_go_environment(go_tmp)).split()
    if len(fields) != 2:
        raise ValueError("host Go target is unavailable")
    return parse_target("/".join(fields))


def build_helper(repository: Path, output: Path, target: tuple[str, str], go_tmp: Path) -> tuple[Path, Path]:
    """Build the guest and a helper for target that embeds it, and return both paths."""
    printed = _run(
        ["go", "run", "./internal/cmd/build-scan-helper", "-o", str(output), "-goos", target[0], "-goarch", target[1]],
        cwd=repository / SCANNER_DIRECTORY,
        environment=_go_environment(go_tmp),
    ).strip()
    helper = output / _executable_name(HELPER_NAME, target[0])
    guest = output / GUEST_NAME
    if Path(printed).resolve() != helper.resolve() or not helper.is_file() or not guest.is_file():
        raise ValueError("scan helper build did not produce the expected files")
    return helper, guest


def embedded_build_info(program: bytes) -> str:
    """Return the module information the Go linker embeds, which go version -m cannot read from wasm."""
    start = program.find(MODINFO_START)
    end = program.find(MODINFO_END, start + len(MODINFO_START))
    if start < 0 or end < 0 or program.find(MODINFO_START, start + 1) >= 0:
        raise ValueError("guest build metadata is missing or ambiguous")
    try:
        return program[start + len(MODINFO_START):end].decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("guest build metadata is invalid") from error


def verify_go_toolchain(build_info: str, name: str) -> None:
    """Require the pinned Go toolchain in go version -m output."""
    lines = build_info.splitlines()
    if not lines or not lines[0].endswith(": " + GO_TOOLCHAIN):
        raise ValueError(f"{name} Go toolchain metadata mismatch")


def verify_build_settings(build_info: str, package: str, target: tuple[str, str]) -> None:
    """Require the main package and the fixed build settings for target."""
    lines = {line.strip() for line in build_info.splitlines()}
    required = {
        f"path\t{package}",
        "build\t-trimpath=true",
        "build\tCGO_ENABLED=0",
        f"build\tGOOS={target[0]}",
        f"build\tGOARCH={target[1]}",
    }
    if not required <= lines:
        raise ValueError(f"{package} build metadata mismatch")


def parse_build_modules(build_info: str) -> dict[tuple[str, str], dict[str, str]]:
    """Read linked modules; a local replacement is returned as its replacement path."""
    modules: dict[tuple[str, str], dict[str, str]] = {}
    previous: tuple[str, str] | None = None
    for line in build_info.splitlines():
        fields = line.strip().split("\t")
        if fields[0] == "dep":
            if len(fields) == 4 and fields[1] and fields[2] and fields[3].startswith("h1:"):
                metadata = {"module_sum": fields[3]}
            elif len(fields) == 3 and fields[1] and fields[2]:
                metadata = {}
            else:
                raise ValueError("linked module metadata is incomplete")
            identity = (fields[1], fields[2])
            if identity in modules:
                raise ValueError("duplicate linked module metadata")
            modules[identity] = metadata
            previous = identity
            continue
        if fields[0] == "=>":
            if previous is None or modules[previous] or len(fields) != 3 or fields[2] != "(devel)" or not fields[1]:
                raise ValueError("only local module replacements are supported")
            modules[previous] = {"replacement": fields[1]}
        previous = None
    if not modules or any(not metadata for metadata in modules.values()):
        raise ValueError("linked module inventory is empty or incomplete")
    return modules


def _safe_relative(value: object, label: str) -> str:
    path = PurePosixPath(value) if isinstance(value, str) else None
    if (
        path is None
        or not re.fullmatch(r"[A-Za-z0-9._/-]+", value)
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError(f"{label} path is invalid")
    return value


def reviewed_licenses(manifest: dict[str, object], license_root: Path) -> dict[tuple[str, str], dict[str, object]]:
    """Verify every reviewed license file and that no other file is present."""
    if manifest.get("schema_version") != 1 or not isinstance(manifest.get("modules"), list):
        raise ValueError("license manifest is invalid")
    reviewed: dict[tuple[str, str], dict[str, object]] = {}
    listed: set[str] = set()
    for entry in manifest["modules"]:
        if not isinstance(entry, dict):
            raise ValueError("license manifest entry is invalid")
        module, version = entry.get("module"), entry.get("version")
        license_name, files = entry.get("license"), entry.get("files")
        if (
            not isinstance(module, str)
            or not isinstance(version, str)
            or not isinstance(license_name, str)
            or license_name in {"", "NOASSERTION", "UNKNOWN"}
            or not isinstance(files, list)
            or not files
        ):
            raise ValueError("license manifest entry is incomplete")
        if (module, version) in reviewed:
            raise ValueError("duplicate license manifest entry")
        for file_entry in files:
            if not isinstance(file_entry, dict):
                raise ValueError("license file entry is invalid")
            relative = _safe_relative(file_entry.get("file"), "license file")
            path = license_root / relative
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"license file is missing: {relative}")
            if _sha256(path) != file_entry.get("sha256"):
                raise ValueError(f"license digest mismatch: {relative}")
            listed.add(relative)
        reviewed[(module, version)] = entry
    present = {
        path.relative_to(license_root).as_posix()
        for path in license_root.rglob("*")
        if not path.is_dir()
    } - {"MODULES.json"}
    if present != listed:
        raise ValueError("license directory contains unreviewed files")
    return reviewed


def go_sums(paths: list[Path]) -> dict[tuple[str, str, bool], str]:
    """Merge go.sum files keyed by module, version and whether the sum is for go.mod."""
    sums: dict[tuple[str, str, bool], str] = {}
    for path in paths:
        for line in path.read_text(encoding="utf-8").splitlines():
            fields = line.split()
            if len(fields) != 3:
                raise ValueError(f"go.sum is invalid: {path.name}")
            module, version, checksum = fields
            key = (module, version.removesuffix("/go.mod"), version.endswith("/go.mod"))
            if sums.setdefault(key, checksum) != checksum:
                raise ValueError("go.sum files disagree")
    return sums


def _patched_copy(
    repository: Path, linker_directory: str, replacement: str, entry: dict[str, object]
) -> dict[str, str]:
    path = posixpath.normpath(posixpath.join(linker_directory, replacement))
    copies = [
        item for item in entry.get("patched_copies", [])
        if isinstance(item, dict) and item.get("path") == path and item.get("linked_by") == linker_directory
    ]
    if len(copies) != 1:
        raise ValueError(f"replaced module is not a reviewed patched copy: {entry['module']}")
    patch = _safe_relative(copies[0].get("patch"), "patch")
    patch_file = repository / patch
    if patch_file.is_symlink() or not patch_file.is_file() or _sha256(patch_file) != copies[0].get("patch_sha256"):
        raise ValueError(f"patch digest mismatch: {patch}")
    return {"path": path, "patch": patch, "patch_sha256": str(copies[0]["patch_sha256"])}


def linked_modules(
    repository: Path,
    linked: dict[str, str],
    manifest: dict[str, object],
    license_root: Path,
) -> list[dict[str, object]]:
    """Match reviewed licenses and module sums to the modules linked into each component.

    linked maps a component directory, such as the guest module, to its build
    metadata. The scanner module itself is first-party and is not listed.
    """
    reviewed = reviewed_licenses(manifest, license_root)
    sums = go_sums([repository / directory / "go.sum" for directory in sorted(linked)])
    found: dict[tuple[str, str], tuple[dict[str, str], list[str]]] = {}
    for directory, build_info in sorted(linked.items()):
        for identity, metadata in parse_build_modules(build_info).items():
            if identity[0] == SCANNER_MODULE:
                if posixpath.normpath(posixpath.join(directory, metadata.get("replacement", ""))) != SCANNER_DIRECTORY:
                    raise ValueError("scanner module is not linked from the source tree")
                continue
            previous, components = found.setdefault(identity, (metadata, []))
            if previous != metadata or "replacement" in metadata and components:
                raise ValueError(f"components link different copies of {identity[0]}")
            components.append(directory)
    if set(found) != set(reviewed):
        missing = sorted(f"{module}@{version}" for module, version in set(found) - set(reviewed))
        extra = sorted(f"{module}@{version}" for module, version in set(reviewed) - set(found))
        raise ValueError(f"linked module inventory mismatch: unreviewed {missing}, unlinked {extra}")
    result: list[dict[str, object]] = []
    for (module, version), (metadata, components) in sorted(found.items()):
        entry = reviewed[(module, version)]
        record: dict[str, object] = {
            "module": module,
            "version": version,
            "license": str(entry["license"]),
            "linked_by": components,
        }
        if "replacement" in metadata:
            record["patched_copy"] = _patched_copy(repository, components[0], metadata["replacement"], entry)
            upstream = sums.get((module, version, False))
            if not upstream:
                raise ValueError(f"upstream module sum is missing: {module}")
            record["upstream_module_sum"] = upstream
        else:
            if entry.get("patched_copies"):
                raise ValueError(f"reviewed patched copy is not linked: {module}")
            if sums.get((module, version, False)) != metadata["module_sum"]:
                raise ValueError(f"module sum does not match go.sum: {module}")
            record["module_sum"] = metadata["module_sum"]
        go_mod_sum = sums.get((module, version, True))
        if not go_mod_sum:
            raise ValueError(f"go.mod sum is missing: {module}")
        record["go_mod_sum"] = go_mod_sum
        result.append(record)
    return result


def _canonical_json(document: object) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _package_id(*parts: str) -> str:
    return "SPDXRef-Package-" + hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


def encode_release_evidence(
    *, helper_sha1: str, helper_sha256: str, guest_sha256: str, modules: list[dict[str, object]],
) -> tuple[bytes, bytes]:
    """Encode deterministic scanner build evidence and SPDX 2.3 JSON."""
    if not re.fullmatch(r"[0-9a-f]{40}", helper_sha1):
        raise ValueError("release digest is invalid")
    for digest in (helper_sha256, guest_sha256):
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("release digest is invalid")
    goos, goarch = RELEASE_TARGET
    evidence = {
        "schema_version": 1,
        "scanner": SCANNER_NAME,
        "scanner_version": SCANNER_VERSION,
        "scanner_commit": SCANNER_COMMIT,
        "ruleset_identity": RULESET_IDENTITY,
        "ruleset_rule_count": RULESET_RULE_COUNT,
        "regexp_engine": "re2",
        "build_profile": BUILD_PROFILE,
        "helper": {
            "path": HELPER_PATH,
            "sha256": helper_sha256,
            "go_toolchain": GO_TOOLCHAIN,
            "goos": goos,
            "goarch": goarch,
            "cgo_enabled": False,
            "build_flags": [
                "-trimpath", "-buildvcs=false",
                f"-ldflags=-s -w -buildid= -X main.expectedGuestSHA256={guest_sha256}",
            ],
        },
        "guest": {
            "sha256": guest_sha256,
            "go_toolchain": GO_TOOLCHAIN,
            "goos": "wasip1",
            "goarch": "wasm",
            "cgo_enabled": False,
            "build_flags": list(GUEST_BUILD_FLAGS),
        },
        "modules": modules,
        "root_client": {
            "go_toolchain": GO_TOOLCHAIN,
            "helper_sha256": helper_sha256,
            "helper_pin": HELPER_PIN,
        },
    }
    root_id = "SPDXRef-Package-Secret-Scanner"
    helper_id = "SPDXRef-File-Scan-Helper"
    guest_id = "SPDXRef-Package-Scan-Guest"
    linkers = {SCANNER_DIRECTORY: helper_id, GUEST_DIRECTORY: guest_id}
    packages = [
        {
            "SPDXID": root_id,
            "name": "Open Trestle secret scanner",
            "versionInfo": BUILD_PROFILE,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "Apache-2.0",
            "licenseDeclared": "Apache-2.0",
            "primaryPackagePurpose": "APPLICATION",
        },
        {
            "SPDXID": guest_id,
            "name": "Open Trestle scan guest",
            "versionInfo": BUILD_PROFILE,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "checksums": [{"algorithm": "SHA256", "checksumValue": guest_sha256}],
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "Apache-2.0",
            "primaryPackagePurpose": "LIBRARY",
            "sourceInfo": "WebAssembly module for wasip1/wasm embedded in the scan helper.",
        },
    ]
    relationships = [
        {"spdxElementId": root_id, "relationshipType": "DISTRIBUTION_ARTIFACT", "relatedSpdxElement": helper_id},
        {"spdxElementId": helper_id, "relationshipType": "CONTAINS", "relatedSpdxElement": guest_id},
    ]
    for module in modules:
        package_id = _package_id(str(module["module"]), str(module["version"]))
        package = {
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
                "referenceLocator": f"pkg:golang/{quote(str(module['module']), safe='/')}@{quote(str(module['version']), safe='._-~')}",
            }],
        }
        if "patched_copy" in module:
            copy = module["patched_copy"]
            package["sourceInfo"] = (
                f"Patched copy at {copy['path']}: the upstream release plus {copy['patch']} "
                f"(SHA-256 {copy['patch_sha256']})."
            )
        packages.append(package)
        for directory in module["linked_by"]:
            relationships.append({
                "spdxElementId": linkers[directory],
                "relationshipType": "STATIC_LINK",
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
        "files": [{
            "SPDXID": helper_id,
            "fileName": "./" + HELPER_PATH,
            "checksums": [
                {"algorithm": "SHA1", "checksumValue": helper_sha1},
                {"algorithm": "SHA256", "checksumValue": helper_sha256},
            ],
            "licenseConcluded": "NOASSERTION",
            "licenseInfoInFiles": ["NOASSERTION"],
            "copyrightText": "NOASSERTION",
        }],
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
    forbidden_suffixes = {".c", ".go", ".h", ".o", ".py", ".sh", ".wasm"}
    for relative in actual:
        path = PurePosixPath(relative)
        if forbidden_segments.intersection(part.lower() for part in path.parts):
            raise ValueError("source, test, private reference, or build tool in staging")
        if relative == "scripts/model_catalog.py":
            if stat.S_IMODE((root / relative).stat().st_mode) != 0o444:
                raise ValueError("catalog script mode is not read-only")
            if _sha256(root / relative) != expected_source_digests.get(relative):
                raise ValueError("catalog script digest mismatch")
        elif path.suffix.lower() in forbidden_suffixes or path.name in {"go", "gcc", "make", "ld", "clang"}:
            raise ValueError("source, test, private reference, or build tool in staging")
    for relative in EXECUTABLE_PATHS:
        path = root / relative
        if relative not in actual or stat.S_IMODE(path.stat().st_mode) != 0o555:
            raise ValueError("scanner executable mode is not read-only")
    data = root / "data"
    if data.is_symlink() or not data.is_dir() or any(data.iterdir()):
        raise ValueError("runtime data staging must be an empty directory")
    return tuple(sorted(actual))


def _copy_file(source: Path, destination: Path, mode: int = 0o444) -> None:
    if source.is_symlink() or not source.is_file():
        raise ValueError(f"release input is unavailable: {source.name}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(mode)


def _expected_staging_files(repository: Path) -> set[str]:
    files = {
        "ca-certificates.crt", "LICENSE", "NOTICE", "trestle", "trestled", HELPER_PATH,
        *RELEASE_SOURCE_PATHS,
        "release/secret-scanner-release.json",
        "release/secret-scanner.spdx.json",
    }
    source_root = repository / "THIRD_PARTY_LICENSES"
    for path in source_root.rglob("*"):
        if path.is_file():
            files.add("licenses/" + path.relative_to(source_root).as_posix())
    return files


def source_binding(repository: Path) -> dict[str, str]:
    """Bind clean committed, indexed, and live tracked source using the existing verifier."""
    try:
        state = capture_source_state(repository)
    except (OSError, RuntimeError) as error:
        raise ValueError("protected packaging requires verified clean source") from error
    if not state.clean:
        raise ValueError("protected packaging requires verified clean source")
    # Ignored staging and build directories change during the build, not tracked inputs.
    fields = (
        state.git_authority_sha256, state.committed_tree_sha256,
        state.live_tracked_tree_sha256, state.index_sha256,
        state.index_flags_sha256, state.status_sha256,
    )
    return {
        "source_revision": state.revision,
        "source_tree": state.tree_identity,
        "verified_source": hashlib.sha256(_canonical_json(fields)).hexdigest(),
    }


def verify_root_provenance(payload: str, program: str, binding: dict[str, str]) -> None:
    """Require the built executable to report the exact protected source inputs."""
    try:
        document = json.loads(payload)
    except json.JSONDecodeError as error:
        raise ValueError(f"{program} source provenance mismatch") from error
    expected = {
        "contract": "open-trestle/build-info", "schema_version": 1,
        "program": program, "source_bound": True,
        "source_revision": binding["source_revision"],
        "source_tree": binding["source_tree"],
    }
    if (
        not isinstance(document, dict)
        or type(document.get("schema_version")) is not int
        or type(document.get("source_bound")) is not bool
        or document != expected
    ):
        raise ValueError(f"{program} source provenance mismatch")


def verify_packaged_provenance(repository: Path, staging: Path, binding: dict[str, str]) -> None:
    """Inspect both product entry points without loading daemon runtime configuration."""
    for name in ("trestle", "trestled"):
        payload = _run(
            [str(staging / name), "build-info"], cwd=repository,
            environment={"HOME": "/nonexistent", "LANG": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC"},
        )
        verify_root_provenance(payload, name, binding)


def build_root_binaries(
    repository: Path,
    output: Path,
    target: tuple[str, str],
    helper_sha256: str,
    go_tmp: Path,
    binding: dict[str, str] | None = None,
) -> dict[str, Path]:
    """Build trestle and trestled for target with the helper digest pinned."""
    flags = f"-s -w -buildid= -X {HELPER_PIN}={helper_sha256}"
    if binding is not None:
        flags += (
            f" -X {BUILDINFO_PACKAGE}.sourceRevision={binding['source_revision']}"
            f" -X {BUILDINFO_PACKAGE}.sourceTree={binding['source_tree']}"
        )
    binaries: dict[str, Path] = {}
    for name in ("trestle", "trestled"):
        binary = output / _executable_name(name, target[0])
        _run(
            ["go", "build", "-trimpath", "-buildvcs=false", f"-ldflags={flags}", "-o", str(binary), f"./cmd/{name}"],
            cwd=repository,
            environment=_go_environment(go_tmp, target),
        )
        build_info = _run(["go", "version", "-m", str(binary)], cwd=repository, environment=_go_environment(go_tmp))
        verify_go_toolchain(build_info, name)
        if helper_sha256.encode("ascii") not in binary.read_bytes():
            raise ValueError(f"{name} does not contain the scan helper digest")
        binaries[name] = binary
    return binaries


def _verify_go_mod_pins(repository: Path) -> None:
    for directory in (".", SCANNER_DIRECTORY, GUEST_DIRECTORY):
        go_mod = (repository / directory / "go.mod").read_text(encoding="utf-8")
        if "\ngo 1.25.0\n" not in go_mod or f"\ntoolchain {GO_TOOLCHAIN}\n" not in go_mod:
            raise ValueError(f"Go toolchain pin changed: {directory}/go.mod")


def package(repository: Path, output: Path) -> None:
    """Build the deterministic scan helper and root binaries into the runtime staging tree."""
    repository = repository.resolve()
    binding = source_binding(repository)
    expected_source_digests = release_input_digests(repository)
    output = output.resolve()
    if output == repository or repository not in output.parents:
        raise ValueError("staging output must be a repository subdirectory")
    _verify_go_mod_pins(repository)
    temporary_root = repository / ".tmp"
    temporary_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="open-trestle-secret-scanner-", dir=temporary_root) as directory:
        temporary = Path(directory)
        go_tmp = temporary / "go-tmp"
        helper_a, guest_a = build_helper(repository, temporary / "build-a", RELEASE_TARGET, go_tmp)
        helper_b, guest_b = build_helper(repository, temporary / "build-b", RELEASE_TARGET, go_tmp)
        helper_bytes = helper_a.read_bytes()
        guest_bytes = guest_a.read_bytes()
        if helper_bytes != helper_b.read_bytes() or guest_bytes != guest_b.read_bytes():
            raise ValueError("scan helper builds are not deterministic")
        helper_sha1, helper_sha256 = _file_checksums(helper_a)
        guest_sha256 = _sha256(guest_a)
        if guest_sha256.encode("ascii") not in helper_bytes or guest_bytes not in helper_bytes:
            raise ValueError("scan helper does not embed and pin the built guest")
        helper_info = _run(["go", "version", "-m", str(helper_a)], cwd=repository, environment=_go_environment(go_tmp))
        verify_go_toolchain(helper_info, "scan helper")
        verify_build_settings(helper_info, HELPER_PACKAGE, RELEASE_TARGET)
        guest_info = embedded_build_info(guest_bytes)
        verify_build_settings(guest_info, GUEST_PACKAGE, ("wasip1", "wasm"))
        license_root = repository / "THIRD_PARTY_LICENSES/secret-scanner"
        manifest = json.loads((license_root / "MODULES.json").read_text(encoding="utf-8"))
        modules = linked_modules(
            repository, {SCANNER_DIRECTORY: helper_info, GUEST_DIRECTORY: guest_info}, manifest, license_root,
        )
        evidence, spdx = encode_release_evidence(
            helper_sha1=helper_sha1, helper_sha256=helper_sha256, guest_sha256=guest_sha256, modules=modules,
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
        _copy_file(helper_a, output / HELPER_PATH, 0o555)
        if _sha256(output / HELPER_PATH) != helper_sha256:
            raise ValueError("staged scan helper digest mismatch")
        release_dir = output / "release"
        release_dir.mkdir()
        (release_dir / "secret-scanner-release.json").write_bytes(evidence)
        (release_dir / "secret-scanner.spdx.json").write_bytes(spdx)
        for path in release_dir.iterdir():
            path.chmod(0o444)
        for binary in build_root_binaries(repository, output, RELEASE_TARGET, helper_sha256, go_tmp, binding).values():
            binary.chmod(0o555)
    verify_packaged_provenance(repository, output, binding)
    if source_binding(repository) != binding:
        raise ValueError("source changed during packaging")
    validate_staging(output, _expected_staging_files(repository), expected_source_digests)


def build_development(repository: Path, output: Path, target: tuple[str, str] | None) -> None:
    """Build trestle, trestled and the scan helper for target from the working tree.

    The outputs are output/bin/trestle, output/bin/trestled and
    output/libexec/open-trestle/open-trestle-scan-helper (with .exe for
    Windows). They are not bound to committed source.
    """
    repository = repository.resolve()
    output = output.resolve()
    if output.is_symlink() or output.exists() and not output.is_dir():
        raise ValueError("development output must be a directory")
    _verify_go_mod_pins(repository)
    with tempfile.TemporaryDirectory(prefix="open-trestle-development-") as directory:
        temporary = Path(directory)
        go_tmp = temporary / "go-tmp"
        target = target or _host_target(repository, go_tmp)
        helper, guest = build_helper(repository, temporary / "helper", target, go_tmp)
        helper_bytes = helper.read_bytes()
        helper_sha256 = _sha256(helper)
        if _sha256(guest).encode("ascii") not in helper_bytes:
            raise ValueError("scan helper does not pin the built guest")
        helper_info = _run(["go", "version", "-m", str(helper)], cwd=repository, environment=_go_environment(go_tmp))
        verify_go_toolchain(helper_info, "scan helper")
        verify_build_settings(helper_info, HELPER_PACKAGE, target)
        binaries = build_root_binaries(repository, temporary, target, helper_sha256, go_tmp)
        placements = [(helper, output / "libexec/open-trestle" / helper.name)]
        placements += [(binary, output / "bin" / binary.name) for binary in binaries.values()]
        for source, destination in placements:
            destination.parent.mkdir(parents=True, exist_ok=True)
            if os.name != "nt":
                source.chmod(0o555)
            os.replace(source, destination)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--output", default=".container", metavar="DIRECTORY",
                       help="release staging directory below the repository")
    modes.add_argument("--verify", metavar="DIRECTORY", help="verify a release staging directory")
    modes.add_argument("--development", metavar="DIRECTORY",
                       help="build pinned development binaries from the working tree")
    parser.add_argument("--target", metavar="GOOS/GOARCH",
                        help="development target; the host target by default")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)
    if arguments.target and not arguments.development:
        parser.error("--target requires --development")
    repository = Path(__file__).resolve().parent.parent
    try:
        if arguments.development:
            target = parse_target(arguments.target) if arguments.target else None
            build_development(repository, Path(arguments.development), target)
        elif arguments.verify:
            binding = source_binding(repository)
            validate_staging(
                repository / arguments.verify,
                _expected_staging_files(repository),
                release_input_digests(repository),
            )
            verify_packaged_provenance(repository, repository / arguments.verify, binding)
            if source_binding(repository) != binding:
                raise ValueError("source changed during package verification")
        else:
            package(repository, repository / arguments.output)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
