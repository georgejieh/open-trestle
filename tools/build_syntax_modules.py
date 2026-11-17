"""Build and verify the WebAssembly syntax-analysis modules.

Every input is pinned in internal/syntaxwasm/modules/manifest.json: the
wasi-sdk release archive by URL, size and SHA-256, and the tree-sitter
runtime, each grammar and the wasi-libc license sources by Git commit plus a
SHA-256 digest of the checked-out tree. The script builds every language
family module twice, in separate directories from separate copies of the
sources, and requires the two builds to be byte-identical.

Without options it verifies: the rebuilt modules must match the digests in
the manifest and the committed compressed modules, and the committed license
texts must match the pinned sources. With --update it writes the modules,
the output digests, the source tree digests and the license texts.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path, PurePosixPath

MANIFEST = "internal/syntaxwasm/modules/manifest.json"
MODULE_DIRECTORY = "internal/syntaxwasm/modules"
SHIM = "internal/syntaxwasm/shim/analyze.c"
LICENSE_DIRECTORY = "THIRD_PARTY_LICENSES/syntax-analysis"
WORK_DIRECTORY = ".tmp/syntax-modules"
SCHEMA_VERSION = 1
GZIP_LEVEL = 9
# Archives the modules may link from. Anything else, such as compiler-rt,
# would bring code whose license texts are not shipped.
ALLOWED_LINK_INPUTS = ("libc.a", "crt1-reactor.o")
COMPILE_FLAGS = (
    "--target=wasm32-wasip1", "-O2", "-std=c11", "-fno-common",
    "-D_POSIX_C_SOURCE=200112L", "-D_DEFAULT_SOURCE",
    "-DTREE_SITTER_REUSE_ALLOCATOR",
    "-Wno-unused-parameter", "-Wno-unused-but-set-variable",
)
LINK_FLAGS = (
    "--target=wasm32-wasip1", "-mexec-model=reactor",
    "-Wl,--stack-first", "-Wl,-z,stack-size=1048576", "-Wl,--strip-all",
)
BUILD_ENVIRONMENT = {"LC_ALL": "C", "SOURCE_DATE_EPOCH": "0", "TZ": "UTC"}
HEX64 = re.compile(r"[0-9a-f]{64}")
HEX40 = re.compile(r"[0-9a-f]{40}")
NAME = re.compile(r"[a-z][a-z0-9_-]{0,63}")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def tree_digest(root: Path) -> dict[str, object]:
    """Digest every regular file and symbolic link under root except .git."""
    digest = hashlib.sha256()
    count = 0
    total = 0
    entries = []
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if relative.parts[0] == ".git":
            continue
        if path.is_symlink() or path.is_file():
            entries.append((relative.as_posix(), path))
    for relative, path in sorted(entries):
        encoded = relative.encode("utf-8")
        if path.is_symlink():
            payload = os.readlink(path).encode("utf-8")
            kind = b"l"
        else:
            payload = bytes.fromhex(sha256_file(path))
            kind = b"f"
            total += path.stat().st_size
        digest.update(kind + len(encoded).to_bytes(4, "big") + encoded)
        digest.update(len(payload).to_bytes(4, "big") + payload)
        count += 1
    return {"sha256": digest.hexdigest(), "files": count, "bytes": total}


def canonical_json(document: object) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")


def deterministic_gzip(data: bytes) -> bytes:
    """Compress with a fixed header: no file name and a zero timestamp."""
    buffer = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", compresslevel=GZIP_LEVEL, fileobj=buffer, mtime=0) as output:
        output.write(data)
    return buffer.getvalue()


def load_manifest(repository: Path) -> dict[str, object]:
    try:
        document = json.loads((repository / MANIFEST).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("syntax module manifest is unreadable") from error
    validate_manifest(document)
    return document


def _safe_relative(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and all(part not in ("", ".", "..") for part in path.parts)


def _valid_lines(value: object) -> bool:
    if value is None:
        return True
    return (
        isinstance(value, list) and len(value) == 2
        and all(type(number) is int for number in value)
        and 1 <= value[0] <= value[1]
    )


def license_text(path: Path, lines: list[int] | None) -> bytes:
    """Read a license file, or an inclusive 1-based line range of a source file."""
    text = path.read_bytes()
    if lines is None:
        return text
    selected = text.splitlines(keepends=True)[lines[0] - 1:lines[1]]
    if len(selected) != lines[1] - lines[0] + 1:
        raise ValueError(f"license notice lines are out of range: {path.name}")
    return b"".join(selected)


def validate_manifest(document: object) -> None:
    """Check the manifest's structure and the cross-references between entries."""
    if not isinstance(document, dict) or document.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("syntax module manifest schema is invalid")
    toolchain = document.get("toolchain")
    if (
        not isinstance(toolchain, dict)
        or not isinstance(toolchain.get("url"), str)
        or not toolchain["url"].startswith("https://github.com/WebAssembly/wasi-sdk/releases/download/")
        or not isinstance(toolchain.get("sha256"), str)
        or not HEX64.fullmatch(toolchain["sha256"])
        or type(toolchain.get("size")) is not int
        or not _safe_relative(toolchain.get("root"))
        or len(PurePosixPath(toolchain["root"]).parts) != 1
        or not isinstance(toolchain.get("version_file"), str)
    ):
        raise ValueError("syntax module toolchain pin is invalid")
    sources = document.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ValueError("syntax module sources are invalid")
    names = set()
    for source in sources:
        if (
            not isinstance(source, dict)
            or not isinstance(source.get("name"), str)
            or not NAME.fullmatch(source["name"])
            or source["name"] in names
            or not isinstance(source.get("repository"), str)
            or not source["repository"].startswith("https://github.com/")
            or not isinstance(source.get("commit"), str)
            or not HEX40.fullmatch(source["commit"])
            or not isinstance(source.get("tree"), dict)
        ):
            raise ValueError("syntax module source pin is invalid")
        names.add(source["name"])
    grammars = document.get("grammars")
    languages = set()
    if not isinstance(grammars, list) or not grammars:
        raise ValueError("syntax module grammars are invalid")
    for grammar in grammars:
        if (
            not isinstance(grammar, dict)
            or not isinstance(grammar.get("language"), str)
            or not NAME.fullmatch(grammar["language"])
            or grammar["language"] in languages
            or grammar.get("source") not in names
            or not isinstance(grammar.get("symbol"), str)
            or not re.fullmatch(r"tree_sitter_[a-z_]+", grammar["symbol"])
            or not isinstance(grammar.get("include"), str)
            or not _safe_relative(grammar["include"])
            or not isinstance(grammar.get("files"), list)
            or not grammar["files"]
            or not all(_safe_relative(path) and path.endswith(".c") for path in grammar["files"])
        ):
            raise ValueError("syntax module grammar entry is invalid")
        languages.add(grammar["language"])
    runtime = document.get("runtime")
    if not isinstance(runtime, dict) or runtime.get("source") not in names:
        raise ValueError("syntax module runtime entry is invalid")
    families = document.get("families")
    if not isinstance(families, list) or not families:
        raise ValueError("syntax module families are invalid")
    family_names = set()
    assigned = set()
    for family in families:
        if (
            not isinstance(family, dict)
            or not isinstance(family.get("name"), str)
            or not NAME.fullmatch(family["name"])
            or family["name"] in family_names
            or not isinstance(family.get("languages"), list)
            or not family["languages"]
            or any(language not in languages or language in assigned for language in family["languages"])
        ):
            raise ValueError("syntax module family entry is invalid")
        family_names.add(family["name"])
        assigned.update(family["languages"])
    if assigned != languages:
        raise ValueError("every grammar must belong to one family")
    licenses = document.get("licenses")
    if not isinstance(licenses, list) or not licenses:
        raise ValueError("syntax module licenses are invalid")
    files = set()
    for entry in licenses:
        if (
            not isinstance(entry, dict)
            or entry.get("source") not in names
            or not _safe_relative(entry.get("path"))
            or not isinstance(entry.get("file"), str)
            or not re.fullmatch(r"[A-Za-z0-9._-]+\.txt", entry["file"])
            or entry["file"] in files
            or not isinstance(entry.get("license"), str)
            or not _valid_lines(entry.get("lines"))
        ):
            raise ValueError("syntax module license entry is invalid")
        files.add(entry["file"])
    covered = {entry["source"] for entry in licenses}
    used = {grammar["source"] for grammar in grammars} | {runtime["source"]}
    if not used.issubset(covered):
        raise ValueError("every linked source needs a license entry")


# Toolchain provisioning.

def download(url: str, size: int, digest: str, destination: Path) -> None:
    """Download once into the cache and verify size and SHA-256 every time."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not destination.exists():
        partial = destination.with_name(destination.name + ".partial")
        partial.unlink(missing_ok=True)
        try:
            with urllib.request.urlopen(url, timeout=300) as response:
                if getattr(response, "status", 200) != 200:
                    raise ValueError("toolchain download was rejected")
                with partial.open("xb") as output:
                    copied = 0
                    while chunk := response.read(1 << 20):
                        copied += len(chunk)
                        if copied > size:
                            raise ValueError("toolchain download exceeds the pinned size")
                        output.write(chunk)
            os.replace(partial, destination)
        except BaseException:
            partial.unlink(missing_ok=True)
            raise
    if destination.is_symlink() or destination.stat().st_size != size or sha256_file(destination) != digest:
        raise ValueError("toolchain archive identity mismatch")


def safe_extract(archive: Path, destination: Path, root: str) -> Path:
    """Extract a gzip tar whose members all stay under one root directory.

    Symbolic links are allowed only when their target resolves inside the
    root; device files, hard links and absolute or parent paths are refused.
    """
    destination.mkdir(parents=True)
    with tarfile.open(archive, mode="r:gz") as source:
        for member in source.getmembers():
            relative = PurePosixPath(member.name)
            if (
                relative.is_absolute()
                or not relative.parts
                or relative.parts[0] != root
                or any(part in ("", ".", "..") for part in relative.parts)
                or not (member.isdir() or member.isfile() or member.issym())
            ):
                raise ValueError(f"toolchain archive member is unsafe: {member.name}")
            target = destination.joinpath(*relative.parts)
            if member.issym():
                link = PurePosixPath(member.linkname)
                resolved = PurePosixPath(*relative.parts[:-1]) / link
                parts: list[str] = []
                for part in resolved.parts:
                    if part == "..":
                        if not parts:
                            raise ValueError(f"toolchain archive link escapes: {member.name}")
                        parts.pop()
                    elif part not in ("", "."):
                        parts.append(part)
                if link.is_absolute() or not parts or parts[0] != root:
                    raise ValueError(f"toolchain archive link escapes: {member.name}")
                target.parent.mkdir(parents=True, exist_ok=True)
                os.symlink(member.linkname, target)
                continue
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            extracted = source.extractfile(member)
            if extracted is None:
                raise ValueError("toolchain archive member is unreadable")
            with extracted, target.open("xb") as output:
                shutil.copyfileobj(extracted, output, 1 << 20)
            target.chmod(0o755 if member.mode & 0o111 else 0o644)
    return destination / root


def provision_toolchain(repository: Path, manifest: dict[str, object], work: Path) -> Path:
    toolchain = manifest["toolchain"]
    archive = repository / WORK_DIRECTORY / "downloads" / PurePosixPath(toolchain["url"]).name
    download(toolchain["url"], toolchain["size"], toolchain["sha256"], archive)
    root = safe_extract(archive, work / "toolchain", toolchain["root"])
    version = (root / "VERSION").read_text(encoding="utf-8")
    if version != toolchain["version_file"]:
        raise ValueError("toolchain VERSION file does not match the pin")
    return root


# Sources.

def run(arguments: list[str], *, cwd: Path, environment: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(arguments, cwd=cwd, env=environment, check=True, capture_output=True, text=True)
    except (OSError, subprocess.CalledProcessError) as error:
        detail = getattr(error, "stderr", "") or ""
        raise ValueError(f"command failed: {Path(arguments[0]).name}: {detail.strip()[-2000:]}") from error


def git_environment() -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": "/nonexistent",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
    }


def fetch_source(source: dict[str, object], cache: Path) -> Path:
    """Check out the pinned commit, reusing a cached checkout of it."""
    directory = cache / f"{source['name']}-{source['commit']}"
    environment = git_environment()
    if not (directory / ".git").is_dir():
        if directory.exists():
            shutil.rmtree(directory)
        directory.mkdir(parents=True)
        config = ["-c", "core.autocrlf=false", "-c", "core.symlinks=true", "-c", "advice.detachedHead=false"]
        run(["git", "init", "-q"], cwd=directory, environment=environment)
        run(["git", *config, "fetch", "-q", "--depth", "1", str(source["repository"]), str(source["commit"])], cwd=directory, environment=environment)
        run(["git", *config, "checkout", "-q", "FETCH_HEAD"], cwd=directory, environment=environment)
    head = run(["git", "rev-parse", "HEAD"], cwd=directory, environment=environment).stdout.strip()
    status = run(["git", "status", "--porcelain", "--ignored"], cwd=directory, environment=environment).stdout
    if head != source["commit"] or status:
        raise ValueError(f"source checkout is not the pinned commit: {source['name']}")
    return directory


def fetch_sources(repository: Path, manifest: dict[str, object], update: bool) -> dict[str, Path]:
    cache = repository / WORK_DIRECTORY / "sources"
    checkouts = {}
    for source in manifest["sources"]:
        directory = fetch_source(source, cache)
        digest = tree_digest(directory)
        if update:
            source["tree"] = digest
        elif source["tree"] != digest:
            raise ValueError(f"source tree digest mismatch: {source['name']}")
        checkouts[source["name"]] = directory
    return checkouts


# Licenses.

def sync_licenses(repository: Path, manifest: dict[str, object], checkouts: dict[str, Path], update: bool) -> None:
    """Keep the committed license texts identical to the pinned sources."""
    directory = repository / LICENSE_DIRECTORY
    if update:
        directory.mkdir(parents=True, exist_ok=True)
    expected = set()
    for entry in manifest["licenses"]:
        text = license_text(checkouts[entry["source"]] / entry["path"], entry.get("lines"))
        if update:
            (directory / entry["file"]).write_bytes(text)
            entry["sha256"] = sha256_bytes(text)
        if entry.get("sha256") != sha256_bytes(text):
            raise ValueError(f"license text changed upstream: {entry['file']}")
        committed = directory / entry["file"]
        if committed.is_symlink() or not committed.is_file() or committed.read_bytes() != text:
            raise ValueError(f"committed license text differs: {entry['file']}")
        expected.add(entry["file"])
    present = {path.name for path in directory.iterdir()}
    if present != expected:
        raise ValueError("license directory holds files outside the manifest")


# Build.

def languages_header(family: dict[str, object], grammars: dict[str, dict[str, object]]) -> str:
    """The X-macro list the shim expands into its language table."""
    lines = []
    for language in family["languages"]:
        lines.append(f'OT_LANGUAGE("{language}", {grammars[language]["symbol"]})')
    return "\n".join(lines) + "\n"


def compile_jobs(manifest: dict[str, object], sources: dict[str, Path], build: Path) -> list[tuple[str, list[str]]]:
    """Return (object name, compiler arguments) for the runtime and grammars."""
    runtime = sources[manifest["runtime"]["source"]]
    jobs = [("runtime.o", ["-I", str(runtime / "lib/include"), "-I", str(runtime / "lib/src"), "-c", str(runtime / "lib/src/lib.c")])]
    for grammar in manifest["grammars"]:
        root = sources[grammar["source"]]
        for file in grammar["files"]:
            name = f"{grammar['language']}-{PurePosixPath(file).stem}.o"
            jobs.append((name, ["-I", str(root / grammar["include"]), "-c", str(root / file)]))
    return jobs


def link_inputs(trace: str) -> list[str]:
    """Return the archive members and startup files the linker loaded."""
    members = []
    for line in trace.splitlines():
        line = line.strip()
        match = re.fullmatch(r"(.*/)?(lib[a-z_.-]+\.a)\(([^()]+)\)", line)
        if match:
            members.append(f"{match.group(2)}({match.group(3)})")
        elif line.endswith("crt1-reactor.o"):
            members.append("crt1-reactor.o")
        elif line and not line.endswith(".o"):
            members.append(line.rsplit("/", 1)[-1])
    return sorted(set(members))


def check_link_inputs(members: list[str]) -> None:
    for member in members:
        if not any(member == allowed or member.startswith(allowed + "(") for allowed in ALLOWED_LINK_INPUTS):
            raise ValueError(f"module links an input without shipped license texts: {member}")


def build_modules(repository: Path, manifest: dict[str, object], toolchain: Path, sources: dict[str, Path], build: Path) -> dict[str, tuple[bytes, list[str]]]:
    """Compile and link every family module in build, returning bytes and link inputs."""
    build.mkdir(parents=True)
    clang = str(toolchain / "bin/clang")
    sysroot = toolchain / "share/wasi-sysroot"
    prefix_maps = [f"-ffile-prefix-map={build}=/build", f"-ffile-prefix-map={toolchain}=/wasi-sdk", f"-ffile-prefix-map={repository}=/repository"]
    for name, path in sources.items():
        prefix_maps.append(f"-ffile-prefix-map={path}=/src/{name}")
    base = [clang, *COMPILE_FLAGS, f"--sysroot={sysroot}", *prefix_maps]
    environment = {**BUILD_ENVIRONMENT, "PATH": "/usr/bin:/bin", "HOME": str(build), "TMPDIR": str(build)}
    grammars = {grammar["language"]: grammar for grammar in manifest["grammars"]}
    jobs = compile_jobs(manifest, sources, build)
    shim = repository / SHIM
    for family in manifest["families"]:
        family_dir = build / family["name"]
        family_dir.mkdir()
        (family_dir / "ot_languages.h").write_text(languages_header(family, grammars), encoding="ascii")
        runtime = sources[manifest["runtime"]["source"]]
        jobs.append((f"{family['name']}/shim.o", ["-I", str(runtime / "lib/include"), "-I", str(family_dir), "-c", str(shim)]))
    with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 2) as pool:
        futures = [pool.submit(run, [*base, *arguments, "-o", str(build / name)], cwd=build, environment=environment) for name, arguments in jobs]
        for future in futures:
            future.result()
    outputs = {}
    for family in manifest["families"]:
        objects = [f"{family['name']}/shim.o", "runtime.o"]
        for language in family["languages"]:
            grammar = grammars[language]
            objects.extend(f"{language}-{PurePosixPath(file).stem}.o" for file in grammar["files"])
        output = build / f"{family['name']}.wasm"
        result = run(
            [clang, *LINK_FLAGS, f"--sysroot={sysroot}", "-Wl,--trace", *objects, "-o", str(output)],
            cwd=build, environment=environment,
        )
        members = link_inputs(result.stdout + result.stderr)
        check_link_inputs(members)
        outputs[family["name"]] = (output.read_bytes(), members)
    return outputs


def copy_sources(sources: dict[str, Path], destination: Path) -> dict[str, Path]:
    """Copy the checkouts without .git so a second build sees other paths."""
    copies = {}
    for name, path in sources.items():
        target = destination / name
        shutil.copytree(path, target, symlinks=True, ignore=shutil.ignore_patterns(".git"))
        copies[name] = target
    return copies


def reproducible_build(repository: Path, manifest: dict[str, object], sources: dict[str, Path], work: Path) -> dict[str, tuple[bytes, list[str]]]:
    toolchain = provision_toolchain(repository, manifest, work)
    first = build_modules(repository, manifest, toolchain, sources, work / "build-a")
    second_sources = copy_sources(sources, work / "sources-b")
    second = build_modules(repository, manifest, toolchain, second_sources, work / "build-b")
    for name, (data, members) in first.items():
        if second[name][0] != data:
            raise ValueError(f"two clean builds of the {name} module differ")
        if second[name][1] != members:
            raise ValueError(f"two clean builds of the {name} module linked different inputs")
    return first


def record_outputs(manifest: dict[str, object], outputs: dict[str, tuple[bytes, list[str]]], repository: Path, update: bool) -> None:
    directory = repository / MODULE_DIRECTORY
    for family in manifest["families"]:
        data, members = outputs[family["name"]]
        compressed = deterministic_gzip(data)
        module = directory / f"{family['name']}.wasm.gz"
        if update:
            module.write_bytes(compressed)
            family.update({
                "module": module.name,
                "wasm_sha256": sha256_bytes(data),
                "wasm_size": len(data),
                "gzip_sha256": sha256_bytes(compressed),
                "gzip_size": len(compressed),
                "link_inputs": members,
            })
        if family.get("wasm_sha256") != sha256_bytes(data) or family.get("wasm_size") != len(data):
            raise ValueError(f"rebuilt {family['name']} module differs from the manifest")
        if family.get("link_inputs") != members:
            raise ValueError(f"rebuilt {family['name']} module links different inputs")
        verify_committed_module(directory, family)


def verify_committed_module(directory: Path, family: dict[str, object]) -> None:
    """Check one committed compressed module against the manifest."""
    module = directory / str(family.get("module"))
    if module.is_symlink() or not module.is_file():
        raise ValueError(f"committed {family['name']} module is missing")
    compressed = module.read_bytes()
    if sha256_bytes(compressed) != family.get("gzip_sha256") or len(compressed) != family.get("gzip_size"):
        raise ValueError(f"committed {family['name']} module differs from the manifest")
    data = gzip.decompress(compressed)
    if sha256_bytes(data) != family.get("wasm_sha256") or len(data) != family.get("wasm_size"):
        raise ValueError(f"committed {family['name']} module does not decompress to the manifest digest")


def record_build(manifest: dict[str, object], repository: Path, update: bool) -> None:
    build = {
        "compile_flags": list(COMPILE_FLAGS),
        "link_flags": list(LINK_FLAGS),
        "environment": BUILD_ENVIRONMENT,
        "shim": SHIM,
        "shim_sha256": sha256_file(repository / SHIM),
        "gzip_level": GZIP_LEVEL,
    }
    if update:
        manifest["build"] = build
    elif manifest.get("build") != build:
        raise ValueError("build flags or shim differ from the manifest")


def verify_committed(repository: Path) -> None:
    """Check the committed modules against the manifest without rebuilding."""
    manifest = load_manifest(repository)
    record_build(manifest, repository, update=False)
    directory = repository / MODULE_DIRECTORY
    expected = {"manifest.json"} | {str(family.get("module")) for family in manifest["families"]}
    if {path.name for path in directory.iterdir()} != expected:
        raise ValueError("module directory holds files outside the manifest")
    for family in manifest["families"]:
        verify_committed_module(directory, family)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--update", action="store_true", help="rebuild and write the modules, digests and license texts")
    mode.add_argument("--committed", action="store_true", help="check the committed modules against the manifest only")
    arguments = parser.parse_args(argv)
    repository = Path(__file__).resolve().parent.parent
    try:
        if arguments.committed:
            verify_committed(repository)
            print("committed syntax modules match the manifest")
            return 0
        manifest = load_manifest(repository)
        record_build(manifest, repository, arguments.update)
        sources = fetch_sources(repository, manifest, arguments.update)
        sync_licenses(repository, manifest, sources, arguments.update)
        (repository / WORK_DIRECTORY).mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="build-", dir=repository / WORK_DIRECTORY) as directory:
            outputs = reproducible_build(repository, manifest, sources, Path(directory))
        record_outputs(manifest, outputs, repository, arguments.update)
        if arguments.update:
            validate_manifest(manifest)
            (repository / MANIFEST).write_bytes(canonical_json(manifest))
        print("syntax modules rebuilt twice, identical, and matching the manifest")
    except (OSError, ValueError, json.JSONDecodeError, tarfile.TarError, gzip.BadGzipFile) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
