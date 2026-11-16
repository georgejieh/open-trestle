"""Loads, verifies and materializes the pending model-review evaluation corpus.

The corpus lives under ``evaluation/testdata/model-corpus-v1``. Its labels are
fixture-author labels awaiting independent human review; nothing here treats
them as adjudicated truth.
"""

from __future__ import annotations

import argparse
import dataclasses
import difflib
import hashlib
import json
import os
import re
import sys
import zlib
from pathlib import Path
from typing import Any, Sequence

MANIFEST_CONTRACT = "open-trestle/model-corpus-manifest"
LABELS_CONTRACT = "open-trestle/model-corpus-labels"
ADJUDICATION_CONTRACT = "open-trestle/model-corpus-adjudication"
LABELS_SCHEMA = "urn:open-trestle:schema:evaluation:model-corpus-labels:v1"
FIXTURE_AUTHOR = "open-trestle-maintainers"
LABEL_STATUS = "labels_pending_human_review"

KIND_OUTCOMES = {
    "defect": "findings",
    "deletion_defect": "findings",
    "near_miss": "no_finding",
    "clean": "no_finding",
    "abstention": "abstention",
}
CATEGORIES = (
    "correctness",
    "security",
    "concurrency",
    "performance",
    "reliability",
    "maintainability",
    "style",
    "documentation",
    "testing",
)
SEVERITIES = ("low", "medium", "high", "critical")
SIDES = ("head", "base")
BUILD_STATES = ("builds", "external_module_source_absent")
BOUNDS = {
    "maximum_cases": 32,
    "maximum_files_per_case": 16,
    "maximum_file_bytes": 64 * 1024,
    "maximum_total_bytes": 1024 * 1024,
}
MAX_DOCUMENT_BYTES = 1024 * 1024

_CASE_ID = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_PATH = re.compile(r"^[A-Za-z0-9_-][A-Za-z0-9._-]*(/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_GO_VERSION = re.compile(r"^1\.[0-9]{1,3}$")
_GO_DIRECTIVE = re.compile(rb"^go (1\.[0-9]{1,3})(?:\.[0-9]+)?$", re.MULTILINE)

# Fixed commit metadata keeps materialized revisions reproducible and carries
# nothing about the case under review.
_COMMIT_IDENTITY = b"Open Trestle Corpus <corpus@example.test> 1704067200 +0000"


class CorpusError(ValueError):
    """Reports an invalid corpus without echoing its content."""


@dataclasses.dataclass(frozen=True)
class Location:
    path: str
    side: str
    start_line: int
    end_line: int

    def overlaps(self, path: str, side: str, start_line: int, end_line: int) -> bool:
        return (
            self.path == path
            and self.side == side
            and start_line <= self.end_line
            and self.start_line <= end_line
        )


@dataclasses.dataclass(frozen=True)
class ExpectedFinding:
    id: str
    locations: tuple[Location, ...]
    categories: tuple[str, ...]
    severity_hint: str


@dataclasses.dataclass(frozen=True)
class Trap:
    id: str
    locations: tuple[Location, ...]


@dataclasses.dataclass(frozen=True)
class CorpusCase:
    id: str
    kind: str
    go_versions: tuple[str, str]
    build: str
    base: dict[str, bytes]
    head: dict[str, bytes]
    labels_sha256: str
    expected_outcome: str
    expected_findings: tuple[ExpectedFinding, ...]
    traps: tuple[Trap, ...]

    def changed_paths(self) -> tuple[str, ...]:
        paths = sorted(set(self.base) | set(self.head))
        return tuple(path for path in paths if self.base.get(path) != self.head.get(path))


@dataclasses.dataclass(frozen=True)
class Corpus:
    root: Path
    identity: str
    manifest_sha256: str
    cases: tuple[CorpusCase, ...]

    def case(self, case_id: str) -> CorpusCase:
        for item in self.cases:
            if item.id == case_id:
                return item
        raise CorpusError("unknown corpus case")


@dataclasses.dataclass(frozen=True)
class MaterializedRepository:
    git_dir: Path
    objects_root: Path
    base_revision: str
    head_revision: str


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CorpusError("duplicate JSON key")
        value[key] = item
    return value


def _reject_constant(_: str) -> None:
    raise CorpusError("non-finite JSON number")


def decode_json(encoded: bytes, limit: int = MAX_DOCUMENT_BYTES) -> Any:
    """Decodes one bounded JSON document, refusing duplicate keys and NaN."""
    if len(encoded) > limit:
        raise CorpusError("JSON document exceeds its bound")
    try:
        return json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise CorpusError("invalid JSON document") from error


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _same(left: Any, right: Any) -> bool:
    """Compares JSON values without Python's bool-is-int equality."""
    return json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True)


def canonical_identity(manifest: dict[str, Any]) -> str:
    """Hashes the manifest with an empty identity, sorted keys and no spaces."""
    value = dict(manifest)
    value["corpus_identity"] = ""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return sha256(encoded.encode("utf-8"))


def encode_document(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode("ascii")


def line_count(data: bytes) -> int:
    if not data:
        return 0
    return data.count(b"\n") + (0 if data.endswith(b"\n") else 1)


def _lines(data: bytes) -> list[bytes]:
    parts = data.split(b"\n")
    return parts[:-1] if data.endswith(b"\n") else parts


def removed_base_lines(base: bytes, head: bytes | None) -> frozenset[int]:
    """Returns the 1-based base lines that the head deletes or replaces."""
    base_lines = _lines(base)
    if head is None:
        return frozenset(range(1, len(base_lines) + 1))
    matcher = difflib.SequenceMatcher(None, base_lines, _lines(head), autojunk=False)
    removed: set[int] = set()
    for tag, first, last, _, _ in matcher.get_opcodes():
        if tag in ("delete", "replace"):
            removed.update(range(first + 1, last + 1))
    return frozenset(removed)


def go_directive(go_mod: bytes) -> str:
    matches = _GO_DIRECTIVE.findall(go_mod)
    if len(matches) != 1:
        raise CorpusError("go.mod must declare exactly one go directive")
    return matches[0].decode("ascii")


def _exact_keys(value: Any, keys: Sequence[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(keys):
        raise CorpusError("object fields do not match the contract")
    return value


def _text(value: Any) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 1024:
        raise CorpusError("text field is empty or too long")
    return value


def _line(value: Any) -> int:
    if type(value) is not int or not 1 <= value <= 100000:
        raise CorpusError("line number out of range")
    return value


def _location(value: Any, case: dict[str, dict[str, bytes]], removed: dict[str, frozenset[int]]) -> Location:
    fields = _exact_keys(value, ("path", "side", "start_line", "end_line"))
    path, side = fields["path"], fields["side"]
    if not isinstance(path, str) or len(path) > 512 or not _PATH.match(path) or side not in SIDES:
        raise CorpusError("invalid label location")
    start, end = _line(fields["start_line"]), _line(fields["end_line"])
    tree = case[side]
    if path not in tree or end < start or end > line_count(tree[path]):
        raise CorpusError("label location is outside its file")
    if side == "base" and not set(range(start, end + 1)) <= removed.get(path, frozenset()):
        raise CorpusError("base label location is not on removed lines")
    return Location(path, side, start, end)


_LABEL_FIELDS = (
    "contract",
    "schema_version",
    "case_id",
    "case_kind",
    "review_state",
    "reviewer_identifier",
    "review_date",
    "fixture_author_identifier",
    "go_version",
    "go_semantics",
    "expected_outcome",
    "expected_findings",
    "false_positive_traps",
    "abstention_reason",
)
_FINDING_FIELDS = (
    "id",
    "path",
    "side",
    "start_line",
    "end_line",
    "also_accept_locations",
    "category",
    "also_compatible_categories",
    "severity_hint",
    "defect",
    "rationale",
)
_TRAP_FIELDS = (
    "id",
    "path",
    "side",
    "start_line",
    "end_line",
    "also_match_locations",
    "wrong_finding",
    "why_wrong",
)


def _locations(item: dict[str, Any], extra_key: str, case: dict[str, dict[str, bytes]], removed: dict[str, frozenset[int]]) -> tuple[Location, ...]:
    primary = {key: item[key] for key in ("path", "side", "start_line", "end_line")}
    extra = item[extra_key]
    if not isinstance(extra, list) or len(extra) > 4:
        raise CorpusError("invalid alternative locations")
    locations = tuple(_location(value, case, removed) for value in [primary, *extra])
    if len(set(locations)) != len(locations):
        raise CorpusError("duplicate label location")
    return locations


def validate_labels(
    value: Any,
    *,
    case_id: str,
    kind: str,
    head_go: str,
    trees: dict[str, dict[str, bytes]],
) -> tuple[str, tuple[ExpectedFinding, ...], tuple[Trap, ...]]:
    """Checks one label set against the v1 contract and the exact case trees."""
    labels = _exact_keys(value, _LABEL_FIELDS)
    fixed = {
        "contract": LABELS_CONTRACT,
        "schema_version": 1,
        "case_id": case_id,
        "case_kind": kind,
        "review_state": "pending",
        "reviewer_identifier": None,
        "review_date": None,
        "fixture_author_identifier": FIXTURE_AUTHOR,
        "go_version": head_go,
    }
    for key, expected in fixed.items():
        if type(labels[key]) is not type(expected) or labels[key] != expected:
            raise CorpusError("label set is not the pending v1 contract for its case")
    _text(labels["go_semantics"])
    outcome = labels["expected_outcome"]
    if outcome != KIND_OUTCOMES[kind]:
        raise CorpusError("expected outcome does not fit the case kind")
    removed = {
        path: removed_base_lines(data, trees["head"].get(path))
        for path, data in trees["base"].items()
    }
    raw_findings, raw_traps = labels["expected_findings"], labels["false_positive_traps"]
    if not isinstance(raw_findings, list) or not isinstance(raw_traps, list) or len(raw_findings) > 8 or len(raw_traps) > 8:
        raise CorpusError("invalid label lists")
    findings = []
    for index, raw in enumerate(raw_findings, start=1):
        item = _exact_keys(raw, _FINDING_FIELDS)
        if item["id"] != f"f{index}":
            raise CorpusError("expected finding identifiers are not sequential")
        also = item["also_compatible_categories"]
        if (
            item["category"] not in CATEGORIES
            or not isinstance(also, list)
            or any(category not in CATEGORIES for category in also)
            or len(set(also)) != len(also)
            or item["category"] in also
            or item["severity_hint"] not in SEVERITIES
        ):
            raise CorpusError("invalid expected finding classification")
        _text(item["defect"])
        _text(item["rationale"])
        findings.append(
            ExpectedFinding(
                id=item["id"],
                locations=_locations(item, "also_accept_locations", trees, removed),
                categories=(item["category"], *also),
                severity_hint=item["severity_hint"],
            )
        )
    traps = []
    for index, raw in enumerate(raw_traps, start=1):
        item = _exact_keys(raw, _TRAP_FIELDS)
        if item["id"] != f"t{index}":
            raise CorpusError("trap identifiers are not sequential")
        _text(item["wrong_finding"])
        _text(item["why_wrong"])
        traps.append(Trap(id=item["id"], locations=_locations(item, "also_match_locations", trees, removed)))
    reason = labels["abstention_reason"]
    if (outcome == "findings") != bool(findings):
        raise CorpusError("expected findings do not fit the expected outcome")
    if (outcome == "abstention") != (reason is not None):
        raise CorpusError("abstention reason does not fit the expected outcome")
    if reason is not None:
        _text(reason)
    if kind == "near_miss" and not traps:
        raise CorpusError("a near miss needs at least one false-positive trap")
    if kind == "deletion_defect" and not any(
        location.side == "base" for finding in findings for location in finding.locations[:1]
    ):
        raise CorpusError("a deletion defect needs a base-side primary location")
    return outcome, tuple(findings), tuple(traps)


def _descriptor(value: Any) -> tuple[str, str, int]:
    fields = _exact_keys(value, ("path", "sha256", "bytes"))
    if not isinstance(fields["path"], str) or not _DIGEST.match(str(fields["sha256"])) or type(fields["bytes"]) is not int:
        raise CorpusError("invalid file descriptor")
    return fields["path"], fields["sha256"], fields["bytes"]


def _read_exact(root: Path, relative: str, digest: str, size: int, limit: int) -> bytes:
    path = root / relative
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise CorpusError("corpus file is missing, oversized or not a regular file")
    data = path.read_bytes()
    if len(data) != size or size > limit or sha256(data) != digest:
        raise CorpusError("corpus file does not match its descriptor")
    return data


def _read_document(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_DOCUMENT_BYTES:
        raise CorpusError("corpus document is missing, oversized or not a regular file")
    return path.read_bytes()


def _inventory(root: Path) -> set[str]:
    found = set()
    for directory, names, files in os.walk(root, followlinks=False):
        for name in names:
            if (Path(directory) / name).is_symlink():
                raise CorpusError("corpus contains a symbolic link")
        for name in files:
            path = Path(directory) / name
            if path.is_symlink() or not path.is_file():
                raise CorpusError("corpus contains a non-regular file")
            found.add(path.relative_to(root).as_posix())
    return found


def load_corpus(root: Path) -> Corpus:
    """Loads the corpus and verifies every pin, bound, label and file."""
    root = Path(root)
    manifest_bytes = _read_document(root / "manifest.json")
    manifest = _exact_keys(
        decode_json(manifest_bytes),
        ("contract", "schema_version", "corpus_identity", "corpus_version", "license", "review_state", "labels_contract", "bounds", "origin", "cases"),
    )
    fixed = {
        "contract": MANIFEST_CONTRACT,
        "schema_version": 1,
        "corpus_version": 1,
        "license": "Apache-2.0",
        "review_state": "pending",
        "labels_contract": LABELS_SCHEMA,
        "bounds": BOUNDS,
    }
    if not all(_same(manifest[key], value) for key, value in fixed.items()):
        raise CorpusError("manifest is not the pending v1 contract")
    identity = manifest["corpus_identity"]
    if not isinstance(identity, str) or identity != canonical_identity(manifest):
        raise CorpusError("corpus identity does not match the manifest")
    expected_paths = {"manifest.json", "adjudication.json"}
    origin_path, origin_digest, origin_size = _descriptor(manifest["origin"])
    if origin_path != "ORIGIN.md":
        raise CorpusError("invalid origin descriptor")
    _read_exact(root, origin_path, origin_digest, origin_size, BOUNDS["maximum_file_bytes"])
    expected_paths.add(origin_path)
    adjudication = _exact_keys(
        decode_json(_read_document(root / "adjudication.json")),
        ("contract", "schema_version", "corpus_identity", "review_state", "method", "decision", "case_decisions"),
    )
    if not _same(adjudication, {
        "contract": ADJUDICATION_CONTRACT,
        "schema_version": 1,
        "corpus_identity": identity,
        "review_state": "pending",
        "method": "independent_human_review",
        "decision": "pending",
        "case_decisions": [],
    }):
        raise CorpusError("corpus adjudication is not pending for this identity")
    raw_cases = manifest["cases"]
    if not isinstance(raw_cases, list) or not 1 <= len(raw_cases) <= BOUNDS["maximum_cases"]:
        raise CorpusError("invalid case list")
    total = origin_size
    cases = []
    previous_id = ""
    for raw in raw_cases:
        item = _exact_keys(raw, ("id", "kind", "go_versions", "build", "files", "readme", "labels"))
        case_id, kind = item["id"], item["kind"]
        if (
            not isinstance(case_id, str)
            or not _CASE_ID.match(case_id)
            or case_id <= previous_id
            or not isinstance(kind, str)
            or kind not in KIND_OUTCOMES
            or item["build"] not in BUILD_STATES
        ):
            raise CorpusError("invalid case entry")
        previous_id = case_id
        versions = _exact_keys(item["go_versions"], ("base", "head"))
        if not all(isinstance(value, str) and _GO_VERSION.match(value) for value in versions.values()):
            raise CorpusError("invalid Go version")
        files = item["files"]
        if not isinstance(files, list) or not 2 <= len(files) <= BOUNDS["maximum_files_per_case"]:
            raise CorpusError("invalid case file list")
        trees: dict[str, dict[str, bytes]] = {"base": {}, "head": {}}
        previous_key: tuple[str, str] = ("", "")
        for descriptor in files:
            entry = _exact_keys(descriptor, ("side", "path", "sha256", "bytes"))
            side = entry["side"]
            path, digest, size = _descriptor({key: entry[key] for key in ("path", "sha256", "bytes")})
            key = (side, path)
            if side not in ("base", "head") or len(path) > 512 or not _PATH.match(path) or key <= previous_key:
                raise CorpusError("invalid or unordered case file")
            previous_key = key
            relative = f"cases/{case_id}/{side}/{path}"
            trees[side][path] = _read_exact(root, relative, digest, size, BOUNDS["maximum_file_bytes"])
            expected_paths.add(relative)
            total += size
        for side in ("base", "head"):
            if "go.mod" not in trees[side] or go_directive(trees[side]["go.mod"]) != versions[side]:
                raise CorpusError("go.mod does not declare the manifest Go version")
        if trees["base"] == trees["head"]:
            raise CorpusError("case has no change")
        readme_path, readme_digest, readme_size = _descriptor(item["readme"])
        labels_path, labels_digest, labels_size = _descriptor(item["labels"])
        if readme_path != f"cases/{case_id}/README.md" or labels_path != f"cases/{case_id}/labels.json":
            raise CorpusError("invalid case document path")
        _read_exact(root, readme_path, readme_digest, readme_size, BOUNDS["maximum_file_bytes"])
        labels_bytes = _read_exact(root, labels_path, labels_digest, labels_size, BOUNDS["maximum_file_bytes"])
        expected_paths.update((readme_path, labels_path))
        total += readme_size + labels_size
        outcome, findings, traps = validate_labels(
            decode_json(labels_bytes),
            case_id=case_id,
            kind=kind,
            head_go=versions["head"],
            trees=trees,
        )
        cases.append(
            CorpusCase(
                id=case_id,
                kind=kind,
                go_versions=(versions["base"], versions["head"]),
                build=item["build"],
                base=trees["base"],
                head=trees["head"],
                labels_sha256=labels_digest,
                expected_outcome=outcome,
                expected_findings=findings,
                traps=traps,
            )
        )
    total += len(manifest_bytes)
    if total > BOUNDS["maximum_total_bytes"]:
        raise CorpusError("corpus exceeds its total byte bound")
    if _inventory(root) != expected_paths:
        raise CorpusError("corpus directory holds unlisted or missing files")
    return Corpus(root=root, identity=identity, manifest_sha256=sha256(manifest_bytes), cases=tuple(cases))


def refresh_manifest(root: Path) -> tuple[bytes, bytes]:
    """Recomputes file pins and the identity after a maintainer edits a case.

    Case identifiers, kinds and build states come from the existing manifest;
    Go versions come from each tree's go.mod. Returns manifest and adjudication
    bytes without writing them.
    """
    root = Path(root)
    manifest = decode_json((root / "manifest.json").read_bytes())
    cases = []
    for item in manifest["cases"]:
        case_dir = root / "cases" / item["id"]
        files = []
        versions = {}
        for side in ("base", "head"):
            side_dir = case_dir / side
            for path in sorted(p for p in side_dir.rglob("*") if p.is_file()):
                data = path.read_bytes()
                files.append({"side": side, "path": path.relative_to(side_dir).as_posix(), "sha256": sha256(data), "bytes": len(data)})
            versions[side] = go_directive((side_dir / "go.mod").read_bytes())
        documents = {}
        for key, name in (("readme", "README.md"), ("labels", "labels.json")):
            data = (case_dir / name).read_bytes()
            documents[key] = {"path": f"cases/{item['id']}/{name}", "sha256": sha256(data), "bytes": len(data)}
        cases.append({"id": item["id"], "kind": item["kind"], "go_versions": versions, "build": item["build"], "files": files, **documents})
    origin = (root / "ORIGIN.md").read_bytes()
    refreshed = {
        "contract": MANIFEST_CONTRACT,
        "schema_version": 1,
        "corpus_identity": "",
        "corpus_version": 1,
        "license": "Apache-2.0",
        "review_state": "pending",
        "labels_contract": LABELS_SCHEMA,
        "bounds": dict(BOUNDS),
        "origin": {"path": "ORIGIN.md", "sha256": sha256(origin), "bytes": len(origin)},
        "cases": cases,
    }
    refreshed["corpus_identity"] = canonical_identity(refreshed)
    adjudication = {
        "contract": ADJUDICATION_CONTRACT,
        "schema_version": 1,
        "corpus_identity": refreshed["corpus_identity"],
        "review_state": "pending",
        "method": "independent_human_review",
        "decision": "pending",
        "case_decisions": [],
    }
    return encode_document(refreshed), encode_document(adjudication)


def _object(kind: bytes, payload: bytes) -> tuple[str, bytes]:
    framed = kind + b" " + str(len(payload)).encode("ascii") + b"\0" + payload
    return hashlib.sha1(framed).hexdigest(), framed


def _tree(files: dict[str, bytes], objects: dict[str, bytes]) -> str:
    children: dict[str, Any] = {}
    for path, data in files.items():
        node = children
        parts = path.split("/")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = data

    def build(node: dict[str, Any]) -> str:
        entries = []
        for name, child in node.items():
            if isinstance(child, dict):
                oid = build(child)
                entries.append((name.encode() + b"/", b"40000 " + name.encode() + b"\0" + bytes.fromhex(oid)))
            else:
                oid, framed = _object(b"blob", child)
                objects[oid] = framed
                entries.append((name.encode(), b"100644 " + name.encode() + b"\0" + bytes.fromhex(oid)))
        oid, framed = _object(b"tree", b"".join(entry for _, entry in sorted(entries)))
        objects[oid] = framed
        return oid

    return build(children)


def plan_revisions(case: CorpusCase) -> tuple[str, str, dict[str, bytes]]:
    """Returns the base and head commit digests and every framed SHA-1 object."""
    objects: dict[str, bytes] = {}
    revisions = []
    parent = b""
    for side, tree in (("base", case.base), ("head", case.head)):
        tree_oid = _tree(tree, objects)
        payload = (
            b"tree " + tree_oid.encode() + b"\n" + parent
            + b"author " + _COMMIT_IDENTITY + b"\n"
            + b"committer " + _COMMIT_IDENTITY + b"\n\n"
            + side.encode() + b"\n"
        )
        oid, framed = _object(b"commit", payload)
        objects[oid] = framed
        revisions.append(oid)
        parent = b"parent " + oid.encode() + b"\n"
    return revisions[0], revisions[1], objects


def _write_new(path: Path, data: bytes, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)


def materialize_case(case: CorpusCase, git_dir: Path) -> MaterializedRepository:
    """Writes the case as a new bare Git repository of loose SHA-1 objects.

    ``refs/heads/base`` names the base commit and ``refs/heads/main`` the head
    commit, whose parent is the base. ``git_dir`` must not exist yet.
    """
    git_dir = Path(git_dir)
    base, head, objects = plan_revisions(case)
    os.mkdir(git_dir, 0o700)
    for directory in ("objects", "refs", "refs/heads", "refs/tags"):
        os.mkdir(git_dir / directory, 0o700)
    for oid in sorted(objects):
        directory = git_dir / "objects" / oid[:2]
        if not directory.exists():
            os.mkdir(directory, 0o700)
        _write_new(directory / oid[2:], zlib.compress(objects[oid]), 0o444)
    _write_new(git_dir / "HEAD", b"ref: refs/heads/main\n", 0o600)
    _write_new(git_dir / "config", b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = true\n", 0o600)
    _write_new(git_dir / "refs" / "heads" / "base", base.encode() + b"\n", 0o600)
    _write_new(git_dir / "refs" / "heads" / "main", head.encode() + b"\n", 0o600)
    return MaterializedRepository(git_dir=git_dir, objects_root=git_dir / "objects", base_revision=base, head_revision=head)


def default_corpus_root() -> Path:
    return Path(__file__).resolve().parents[4] / "evaluation" / "testdata" / "model-corpus-v1"


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify or materialize the pending model-review corpus.")
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify", help="check every pin, bound and label")
    verify.add_argument("--corpus", type=Path, default=None)
    manifest = commands.add_parser("manifest", help="recompute pins after editing a case")
    manifest.add_argument("--corpus", type=Path, default=None)
    mode = manifest.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    materialize = commands.add_parser("materialize", help="write one case as a new bare Git repository")
    materialize.add_argument("--corpus", type=Path, default=None)
    materialize.add_argument("--case", required=True)
    materialize.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(arguments)
    root = args.corpus or default_corpus_root()
    try:
        if args.command == "manifest":
            manifest_bytes, adjudication_bytes = refresh_manifest(root)
            if args.write:
                (root / "manifest.json").write_bytes(manifest_bytes)
                (root / "adjudication.json").write_bytes(adjudication_bytes)
            elif (root / "manifest.json").read_bytes() != manifest_bytes or (root / "adjudication.json").read_bytes() != adjudication_bytes:
                print("manifest is stale; rerun with --write and review the diff", file=sys.stderr)
                return 1
            load_corpus(root)
            print(f"corpus {decode_json(manifest_bytes)['corpus_identity']} pending")
            return 0
        corpus = load_corpus(root)
        if args.command == "verify":
            print(f"corpus {corpus.identity} cases={len(corpus.cases)} review_state=pending label_status={LABEL_STATUS}")
            return 0
        repository = materialize_case(corpus.case(args.case), args.output)
    except (OSError, CorpusError) as error:
        print(f"model corpus: {error}", file=sys.stderr)
        return 1
    print(f"git_dir={repository.git_dir}")
    print(f"objects_root={repository.objects_root}")
    print(f"base_revision={repository.base_revision}")
    print(f"head_revision={repository.head_revision}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
