"""Generate deterministic, unsigned local release evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass
from urllib.parse import quote
from datetime import datetime
from pathlib import Path, PurePosixPath


@dataclass(frozen=True)
class Artifact:
    """A content-addressed release artifact."""

    name: str
    sha256: str
    size: int


@dataclass(frozen=True)
class Component:
    """A versioned runtime component represented in the SBOM."""

    ecosystem: str
    name: str
    version: str
    license: str = "NOASSERTION"


def _validate_name(name: str) -> None:
    segments = name.split("/")
    if (
        not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}", name)
        or any(segment in {"", ".", ".."} for segment in segments)
    ):
        raise ValueError(f"invalid artifact name: {name}")


def _has_symlink_component(path: Path) -> bool:
    current = path
    while True:
        if current.is_symlink():
            return True
        parent = current.parent
        if parent == current:
            return False
        current = parent


def _reject_sensitive_path(
    path: Path, name: str, scoped_parts: tuple[str, ...] | None = None
) -> None:
    basename = path.name.lower()
    if scoped_parts is None:
        scoped_parts = PurePosixPath(name).parts
    lower_parts = {part.lower() for part in scoped_parts}
    if (
        basename == ".env"
        or basename.startswith(".env.")
        or basename in {
            ".git-credentials",
            ".netrc",
            ".npmrc",
            ".pypirc",
            "id_dsa",
            "id_ecdsa",
            "id_ed25519",
            "id_rsa",
        }
        or path.suffix.lower() in {".key", ".p12", ".pfx", ".pem"}
        or lower_parts
        & {".aws", ".git", ".prime", ".remember", ".ssh", "references"}
    ):
        raise ValueError(f"sensitive artifact path is forbidden: {name}")


def _artifact(name: str, path: Path) -> Artifact:
    _reject_sensitive_path(path, name)
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ValueError(f"artifact is not a regular file: {name}")
            while chunk := source.read(1 << 20):
                digest.update(chunk)
                size += len(chunk)
            after = os.fstat(source.fileno())
    except OSError as error:
        raise ValueError(f"artifact could not be read: {name}") from error
    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if size != before.st_size or any(
        getattr(before, field) != getattr(after, field) for field in stable_fields
    ):
        raise ValueError(f"artifact changed while read: {name}")
    if size == 0:
        raise ValueError(f"artifact must not be empty: {name}")
    return Artifact(name=name, sha256=digest.hexdigest(), size=size)


def _input_path(root: Path, source: str, label: str) -> tuple[Path, tuple[str, ...]]:
    root_absolute = Path(os.path.abspath(root))
    path = Path(os.path.abspath(root / source))
    try:
        parts = path.relative_to(root_absolute).parts
    except ValueError as error:
        raise ValueError(f"{label} escapes root") from error
    return path, parts


def collect_artifacts(
    entries: tuple[str, ...], root: Path = Path(".")
) -> tuple[Artifact, ...]:
    """Collect explicitly named files and directory members in stable order."""
    collected: dict[str, Artifact] = {}

    def add(name: str, path: Path) -> None:
        if name in collected:
            raise ValueError(f"duplicate artifact name: {name}")
        collected[name] = _artifact(name, path)

    for entry in entries:
        name, separator, source = entry.partition("=")
        if not separator or not name or not source:
            raise ValueError("artifact must use NAME=PATH")
        _validate_name(name)
        path, source_parts = _input_path(root, source, f"artifact path: {name}")
        _reject_sensitive_path(path, name, source_parts)
        if _has_symlink_component(path):
            raise ValueError(f"artifact path must not be a symlink: {name}")
        if path.is_file():
            add(name, path)
            continue
        if not path.is_dir():
            raise ValueError(f"artifact path is unavailable: {name}")
        count_before_directory = len(collected)
        try:
            for directory, directory_names, file_names in os.walk(path):
                directory_names.sort()
                for directory_name in directory_names:
                    if (Path(directory) / directory_name).is_symlink():
                        raise ValueError(
                            f"artifact path must not be a symlink: {name}"
                        )
                for file_name in sorted(file_names):
                    member = Path(directory) / file_name
                    if member.is_symlink():
                        raise ValueError(
                            f"artifact path must not be a symlink: {name}"
                        )
                    relative = member.relative_to(path)
                    logical_name = str(
                        PurePosixPath(name) / PurePosixPath(relative.as_posix())
                    )
                    add(logical_name, member)
        except OSError as error:
            raise ValueError(
                f"artifact directory could not be read: {name}"
            ) from error
        if len(collected) == count_before_directory:
            raise ValueError(f"artifact must not be empty: {name}")
    return tuple(collected[name] for name in sorted(collected))


def parse_go_components(build_info: str) -> tuple[Component, ...]:
    """Read runtime modules from `go version -m` output."""
    components: set[Component] = set()
    for line in build_info.splitlines():
        fields = line.strip().split("\t")
        if fields and fields[0] == "=>":
            raise ValueError("replaced Go modules are unsupported")
        if not fields or fields[0] != "dep":
            continue
        if len(fields) < 3 or not fields[1] or not fields[2]:
            raise ValueError("Go build dependency is invalid")
        components.add(Component("gomod", fields[1], fields[2]))
    return tuple(
        sorted(components, key=lambda item: (item.ecosystem, item.name, item.version))
    )


def read_npm_components(path: Path) -> tuple[Component, ...]:
    """Read production components from an npm lockfile version 3."""
    if _has_symlink_component(path):
        raise ValueError("npm lockfile must not be symlinked")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("npm lockfile is unavailable or invalid") from error
    packages = document.get("packages")
    if document.get("lockfileVersion") != 3 or not isinstance(packages, dict):
        raise ValueError("npm lockfile version 3 is required")
    components: set[Component] = set()
    for package_path, package in packages.items():
        if (
            not package_path
            or not isinstance(package, dict)
            or package.get("dev") is True
        ):
            continue
        marker = "node_modules/"
        if marker not in package_path:
            raise ValueError("npm package path is invalid")
        name = package_path.rsplit(marker, 1)[1]
        version = package.get("version")
        license_name = package.get("license", "NOASSERTION")
        if not name or not isinstance(version, str) or not version:
            raise ValueError("npm package name or version is invalid")
        if not isinstance(license_name, str) or not license_name:
            license_name = "NOASSERTION"
        components.add(Component("npm", name, version, license_name))
    return tuple(
        sorted(components, key=lambda item: (item.ecosystem, item.name, item.version))
    )


def merge_components(*groups: tuple[Component, ...]) -> tuple[Component, ...]:
    """Merge component inventories while rejecting conflicting metadata."""
    merged: dict[tuple[str, str, str], Component] = {}
    for group in groups:
        for component in group:
            key = (component.ecosystem, component.name, component.version)
            existing = merged.get(key)
            if existing is not None and existing != component:
                raise ValueError("conflicting component metadata")
            merged[key] = component
    result = tuple(
        sorted(
            merged.values(), key=lambda item: (item.ecosystem, item.name, item.version)
        )
    )
    _validate_components(result)
    return result


def _validate_artifacts(artifacts: tuple[Artifact, ...]) -> None:
    if not artifacts:
        raise ValueError("at least one artifact is required")
    names: set[str] = set()
    for artifact in artifacts:
        _validate_name(artifact.name)
        if artifact.name in names:
            raise ValueError(f"duplicate artifact name: {artifact.name}")
        if not re.fullmatch(r"[0-9a-f]{64}", artifact.sha256):
            raise ValueError(f"invalid artifact digest: {artifact.name}")
        if artifact.size <= 0:
            raise ValueError(f"artifact must not be empty: {artifact.name}")
        names.add(artifact.name)


def encode_checksums(artifacts: tuple[Artifact, ...]) -> bytes:
    """Encode sorted SHA-256 checksums using sha256sum's text format."""
    _validate_artifacts(artifacts)
    lines: list[str] = []
    for artifact in sorted(artifacts, key=lambda item: item.name):
        lines.append(f"{artifact.sha256}  {artifact.name}\n")
    return "".join(lines).encode("utf-8")


def _validate_components(components: tuple[Component, ...]) -> None:
    identities: set[tuple[str, str, str]] = set()
    for component in components:
        identity = (component.ecosystem, component.name, component.version)
        if identity in identities:
            raise ValueError("duplicate runtime component")
        if component.ecosystem not in {"gomod", "npm"}:
            raise ValueError("unsupported component ecosystem")
        if not re.fullmatch(r"[A-Za-z0-9@][A-Za-z0-9@._/+~-]{0,255}", component.name):
            raise ValueError("invalid component name")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+~-]{0,127}", component.version):
            raise ValueError("invalid component version")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 .()+-]{0,127}", component.license):
            raise ValueError("invalid component license")
        identities.add(identity)


def _validate_release_metadata(version: str, revision: str, created: str) -> None:
    if not re.fullmatch(
        r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
        r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?",
        version,
    ):
        raise ValueError("version must be semantic version text")
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", revision):
        raise ValueError("revision must be a lowercase Git object ID")
    try:
        parsed = datetime.strptime(created, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise ValueError("created must be a UTC RFC 3339 timestamp") from error
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != created:
        raise ValueError("created must be a UTC RFC 3339 timestamp")


def encode_spdx(
    artifacts: tuple[Artifact, ...],
    *,
    components: tuple[Component, ...] = (),
    version: str,
    revision: str,
    created: str,
) -> bytes:
    """Encode a deterministic SPDX 2.3 inventory for release artifacts."""
    _validate_artifacts(artifacts)
    _validate_components(components)
    _validate_release_metadata(version, revision, created)
    ordered = tuple(sorted(artifacts, key=lambda item: item.name))
    ordered_components = tuple(
        sorted(components, key=lambda item: (item.ecosystem, item.name, item.version))
    )
    files: list[dict[str, object]] = []
    file_ids: list[str] = []
    for artifact in ordered:
        _validate_name(artifact.name)
        spdx_id = "SPDXRef-File-" + hashlib.sha256(
            artifact.name.encode("utf-8")
        ).hexdigest()
        file_ids.append(spdx_id)
        files.append(
            {
                "SPDXID": spdx_id,
                "checksums": [
                    {"algorithm": "SHA256", "checksumValue": artifact.sha256}
                ],
                "fileName": "./" + artifact.name,
            }
        )
    identity_preimage = json.dumps(
        {
            "artifacts": [artifact.__dict__ for artifact in ordered],
            "components": [component.__dict__ for component in ordered_components],
            "created": created,
            "revision": revision,
            "version": version,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    identity = hashlib.sha256(identity_preimage).hexdigest()
    root_package_id = "SPDXRef-Package-Open-Trestle"
    packages: list[dict[str, object]] = [
        {
            "SPDXID": root_package_id,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "Apache-2.0",
            "licenseDeclared": "Apache-2.0",
            "name": "Open Trestle",
            "primaryPackagePurpose": "APPLICATION",
            "sourceInfo": f"Declared Git revision {revision}",
            "versionInfo": version,
        }
    ]
    component_ids: list[str] = []
    for component in ordered_components:
        component_preimage = (
            f"{component.ecosystem}\n{component.name}\n{component.version}"
        ).encode("utf-8")
        component_id = "SPDXRef-Package-" + hashlib.sha256(
            component_preimage
        ).hexdigest()
        component_ids.append(component_id)
        purl_type = "golang" if component.ecosystem == "gomod" else "npm"
        purl = (
            f"pkg:{purl_type}/{quote(component.name, safe='/')}@"
            f"{quote(component.version, safe='._-~')}"
        )
        packages.append(
            {
                "SPDXID": component_id,
                "downloadLocation": "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceLocator": purl,
                        "referenceType": "purl",
                    }
                ],
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": component.license,
                "name": component.name,
                "versionInfo": component.version,
            }
        )
    relationships = [
        {
            "relatedSpdxElement": file_id,
            "relationshipType": "CONTAINS",
            "spdxElementId": root_package_id,
        }
        for file_id in file_ids
    ] + [
        {
            "relatedSpdxElement": component_id,
            "relationshipType": "DEPENDS_ON",
            "spdxElementId": root_package_id,
        }
        for component_id in component_ids
    ]
    namespace_uuid = uuid.uuid5(
        uuid.NAMESPACE_URL, "open-trestle-release-evidence:" + identity
    )
    document = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "comment": (
            "Unsigned local inventory only. It does not establish build provenance, "
            "signature authority, vulnerability status, or production readiness."
        ),
        "creationInfo": {
            "created": created,
            "creators": ["Tool: open-trestle-release-evidence-1"],
        },
        "dataLicense": "CC0-1.0",
        "documentDescribes": [root_package_id],
        "documentNamespace": "urn:uuid:" + str(namespace_uuid),
        "files": files,
        "name": f"Open Trestle {version} release artifact inventory",
        "packages": packages,
        "relationships": relationships,
        "spdxVersion": "SPDX-2.3",
    }
    return (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def write_release_evidence(
    output: Path,
    artifacts: tuple[Artifact, ...],
    components: tuple[Component, ...],
    *,
    version: str,
    revision: str,
    created: str,
) -> None:
    """Write a complete evidence directory without replacing prior evidence."""
    checksums = encode_checksums(artifacts)
    spdx = encode_spdx(
        artifacts,
        components=components,
        version=version,
        revision=revision,
        created=created,
    )
    if output.is_symlink() or _has_symlink_component(output.parent):
        raise ValueError("output path must not be symlinked")
    if output.exists():
        raise ValueError("output path already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".release-evidence-", dir=output.parent))
    try:
        (temporary / "SHA256SUMS").write_bytes(checksums)
        (temporary / "sbom.spdx.json").write_bytes(spdx)
        os.rename(temporary, output)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def read_go_binary_components(path: Path) -> tuple[Component, ...]:
    """Read the embedded runtime module graph from a Go binary."""
    if _has_symlink_component(path) or not path.is_file():
        raise ValueError("Go binary is unavailable or symlinked")
    try:
        result = subprocess.run(
            ["go", "version", "-m", str(path)],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise ValueError("Go binary metadata could not be read") from error
    return parse_go_components(result.stdout)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate deterministic unsigned local release evidence."
    )
    parser.add_argument(
        "--artifact", action="append", required=True, metavar="NAME=PATH"
    )
    parser.add_argument("--go-binary", action="append", default=[], metavar="PATH")
    parser.add_argument("--npm-lock", action="append", default=[], metavar="PATH")
    parser.add_argument("--version", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--created", required=True)
    parser.add_argument("--output", required=True, metavar="DIRECTORY")
    return parser


def main(argv: list[str] | None = None, *, root: Path = Path(".")) -> int:
    """Generate release evidence from explicit local inputs."""
    arguments = _parser().parse_args(argv)
    try:
        artifacts = collect_artifacts(tuple(arguments.artifact), root)
        component_groups = [
            read_go_binary_components(_input_path(root, path, "Go binary path")[0])
            for path in arguments.go_binary
        ]
        component_groups.extend(
            read_npm_components(_input_path(root, path, "npm lockfile path")[0])
            for path in arguments.npm_lock
        )
        components = merge_components(*component_groups)
        output = Path(arguments.output)
        if not output.is_absolute():
            output = root / output
        write_release_evidence(
            output,
            artifacts,
            components,
            version=arguments.version,
            revision=arguments.revision,
            created=arguments.created,
        )
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
