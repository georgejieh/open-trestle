"""Build the per-platform release archives and SHA256SUMS that the install scripts download."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import sys
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path

from package_secret_scanner import (
    RELEASE_VERSION, _run, build_development, parse_target,
)

TARGETS = (("linux", "amd64"), ("windows", "amd64"))
SUMS_NAME = "SHA256SUMS"
README = """Open Trestle {version} for {goos}/{goarch}

This archive is an unsigned pre-release. Its SHA-256 in SHA256SUMS shows only
that a download matches the release; it does not say who built it.

  bin/trestle{exe}       the command-line program
  bin/trestled{exe}      the local daemon
  libexec/open-trestle/open-trestle-scan-helper{exe}
                         the secret scan helper; keep it at this path next
                         to bin, or every review is refused

The install scripts in the repository place this folder and put bin on PATH:
https://github.com/georgejieh/open-trestle/blob/main/docs/install.md

Check the copy with: bin/trestle{exe} build-info
Then, inside a Git repository: trestle init
"""


def archive_name(version: str, target: tuple[str, str]) -> str:
    suffix = ".zip" if target[0] == "windows" else ".tar.gz"
    return f"open-trestle-{version}-{target[0]}-{target[1]}{suffix}"


def archive_entries(repository: Path, build: Path, version: str, target: tuple[str, str]) -> list[tuple[str, bytes, int]]:
    """Return (path, content, mode) for every file, below one top folder, sorted."""
    exe = ".exe" if target[0] == "windows" else ""
    top = archive_name(version, target).removesuffix(".zip").removesuffix(".tar.gz")
    files = {
        f"bin/trestle{exe}": (build / f"bin/trestle{exe}", 0o555),
        f"bin/trestled{exe}": (build / f"bin/trestled{exe}", 0o555),
        f"libexec/open-trestle/open-trestle-scan-helper{exe}": (
            build / f"libexec/open-trestle/open-trestle-scan-helper{exe}", 0o555,
        ),
        "LICENSE": (repository / "LICENSE", 0o444),
        "NOTICE": (repository / "NOTICE", 0o444),
    }
    licenses = repository / "THIRD_PARTY_LICENSES"
    for path in licenses.rglob("*"):
        if path.is_file():
            files["licenses/" + path.relative_to(licenses).as_posix()] = (path, 0o444)
    entries = []
    for relative, (source, mode) in files.items():
        if source.is_symlink() or not source.is_file():
            raise ValueError(f"release input is unavailable: {relative}")
        entries.append((f"{top}/{relative}", source.read_bytes(), mode))
    readme = README.format(version=version, goos=target[0], goarch=target[1], exe=exe)
    entries.append((f"{top}/README.txt", readme.encode("utf-8"), 0o444))
    return sorted(entries)


def _directories(entries: list[tuple[str, bytes, int]]) -> list[str]:
    folders = set()
    for name, _, _ in entries:
        parts = name.split("/")[:-1]
        folders.update("/".join(parts[:index]) for index in range(1, len(parts) + 1))
    return sorted(folders)


def write_tar_gz(destination: Path, entries: list[tuple[str, bytes, int]], mtime: int) -> None:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        def add(name: str, kind: bytes, mode: int, content: bytes = b"") -> None:
            info = tarfile.TarInfo(name)
            info.type, info.mode, info.mtime, info.size = kind, mode, mtime, len(content)
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(content) if kind == tarfile.REGTYPE else None)
        for folder in _directories(entries):
            add(folder, tarfile.DIRTYPE, 0o755)
        for name, content, mode in entries:
            add(name, tarfile.REGTYPE, mode, content)
    with destination.open("xb") as output, gzip.GzipFile(fileobj=output, mode="wb", mtime=mtime, filename="") as stream:
        stream.write(buffer.getvalue())


def write_zip(destination: Path, entries: list[tuple[str, bytes, int]], mtime: int) -> None:
    stamp = time.gmtime(max(mtime, 315532800))[:6]
    with destination.open("xb") as output, zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for folder in _directories(entries):
            info = zipfile.ZipInfo(folder + "/", stamp)
            info.external_attr = (0o40755 << 16) | 0x10
            archive.writestr(info, b"")
        for name, content, mode in entries:
            info = zipfile.ZipInfo(name, stamp)
            info.external_attr = (0o100000 | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, content)


def write_sums(output: Path) -> None:
    """List every file in output except SHA256SUMS, in the format sha256sum -c reads."""
    lines = []
    for path in sorted(output.iterdir()):
        if path.name == SUMS_NAME:
            continue
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"output holds something other than release files: {path.name}")
        lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n")
    (output / SUMS_NAME).write_text("".join(lines), encoding="ascii", newline="\n")


def build(repository: Path, version: str, output: Path, targets: list[tuple[str, str]]) -> None:
    if not RELEASE_VERSION.fullmatch(version):
        raise ValueError("version must be SemVer without a leading v")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    mtime = int(_run(["git", "show", "-s", "--format=%ct", "HEAD"], cwd=repository).strip())
    with tempfile.TemporaryDirectory(prefix=".open-trestle-release-", dir=output) as directory:
        for target in targets:
            work = Path(directory) / f"{target[0]}-{target[1]}"
            build_development(repository, work, target, version)
            entries = archive_entries(repository, work, version, target)
            destination = output / archive_name(version, target)
            (write_zip if target[0] == "windows" else write_tar_gz)(destination, entries, mtime)
    write_sums(output)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="release version without the leading v")
    parser.add_argument("--output", required=True, metavar="DIRECTORY", help="folder for the archives and SHA256SUMS")
    parser.add_argument("--target", action="append", metavar="GOOS/GOARCH",
                        help="build only this target; repeatable (default: linux/amd64 and windows/amd64)")
    arguments = parser.parse_args(argv)
    repository = Path(__file__).resolve().parent.parent
    try:
        targets = [parse_target(value) for value in arguments.target] if arguments.target else list(TARGETS)
        build(repository, arguments.version, Path(arguments.output), targets)
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
