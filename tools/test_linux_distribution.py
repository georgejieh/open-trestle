"""Tests for the deterministic Linux amd64 distribution."""

import hashlib
import json
import os
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest.mock import patch

import linux_distribution
import linux_distribution_runtime


REVISION = "1" * 40
CREATED = "2026-09-30T00:00:00Z"


def _elf(payload: bytes = b"runtime", elf_type: int = 2) -> bytes:
    header = bytearray(64)
    header[:16] = b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 8)
    struct.pack_into("<HHI", header, 16, elf_type, 62, 1)
    return bytes(header) + payload


def _write(path: Path, body: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    path.chmod(mode)


def _staging(root: Path, marker: bytes = b"one") -> Path:
    staging = root / "staging"
    _write(staging / "trestle", _elf(b"trestle-" + marker), 0o555)
    _write(staging / "trestled", _elf(b"trestled-" + marker), 0o555)
    _write(
        staging / "libexec/open-trestle/open-trestle-secret-scanner",
        _elf(b"launcher-" + marker, 3),
        0o555,
    )
    _write(
        staging / "libexec/open-trestle/open-trestle-secret-scanner-worker",
        _elf(b"worker-" + marker),
        0o555,
    )
    _write(staging / "LICENSE", b"project license\n", 0o444)
    _write(staging / "NOTICE", b"project notice\n", 0o444)
    _write(staging / "scripts/model_catalog.py", Path(linux_distribution.__file__).with_name("model_catalog.py").read_bytes(), 0o444)
    _write(staging / "licenses/dependency/LICENSE", b"dependency license\n", 0o444)
    _write(staging / "release/secret-scanner-release.json", b"{}\n", 0o444)
    _write(staging / "release/secret-scanner.spdx.json", b"{}\n", 0o444)
    _write(staging / "release/vulnerability-scan.json", b"{}\n", 0o444)
    _write(staging / "ca-certificates.crt", b"excluded\n", 0o444)
    (staging / "data").mkdir()
    return staging


def _build(
    root: Path,
    marker: bytes = b"one",
    version: str = "0.1.0-dev",
) -> tuple[Path, Path]:
    staging = _staging(root, marker)
    output = root / "open-trestle-linux-amd64.pyz"
    linux_distribution.build_distribution(
        staging=staging,
        runtime=Path(linux_distribution_runtime.__file__),
        output=output,
        version=version,
        revision=REVISION,
        created=CREATED,
    )
    return output, Path(str(output) + ".sha256")




def _rewrite_controls_as_legacy(destdir: Path) -> tuple[bytes, bytes]:
    receipt_path = destdir / linux_distribution_runtime.RECEIPT_PATH
    journal_path = destdir / linux_distribution_runtime.JOURNAL_PATH
    current = json.loads(receipt_path.read_bytes())
    receipt = {
        key: current[key]
        for key in (
            "archive_sha256",
            "created_directories",
            "files",
            "manifest_sha256",
            "schema_version",
            "target",
            "transaction",
            "version",
        )
    }
    receipt["schema_version"] = linux_distribution_runtime.SCHEMA_VERSION
    receipt_body = linux_distribution_runtime._canonical_json(receipt)
    journal = {
        "action": "install",
        "archive_sha256": receipt["archive_sha256"],
        "receipt_sha256": hashlib.sha256(receipt_body).hexdigest(),
        "schema_version": linux_distribution_runtime.SCHEMA_VERSION,
        "transaction": receipt["transaction"],
    }
    journal_body = linux_distribution_runtime._canonical_json(journal)
    receipt_path.chmod(0o644)
    journal_path.chmod(0o644)
    receipt_path.write_bytes(receipt_body)
    journal_path.write_bytes(journal_body)
    receipt_path.chmod(0o444)
    journal_path.chmod(0o444)
    return receipt_body, journal_body


def _rewrite_controls_as_schema_2(destdir: Path) -> tuple[bytes, bytes]:
    """Rewrite the live controls in the schema-2 form, which predates generation identities."""
    receipt_path = destdir / linux_distribution_runtime.RECEIPT_PATH
    journal_path = destdir / linux_distribution_runtime.JOURNAL_PATH
    receipt = json.loads(receipt_path.read_bytes())
    journal = json.loads(journal_path.read_bytes())
    for key in ("generation_id", "new_generation_id", "old_generation_id"):
        del receipt[key]
    for key in ("new_generation_id", "old_generation_id"):
        del journal[key]
    if isinstance(receipt["previous"], dict):
        del receipt["previous"]["generation_id"]
    receipt["schema_version"] = journal["schema_version"] = 2
    receipt_body = linux_distribution_runtime._canonical_json(receipt)
    journal["receipt_sha256"] = hashlib.sha256(receipt_body).hexdigest()
    journal_body = linux_distribution_runtime._canonical_json(journal)
    for path, body in ((receipt_path, receipt_body), (journal_path, journal_body)):
        path.chmod(0o644)
        path.write_bytes(body)
        path.chmod(0o444)
    return receipt_body, journal_body


def _tree(destdir: Path) -> dict[str, object]:
    """Every path below destdir with its mode and bytes, or its symlink target."""
    return {
        str(path.relative_to(destdir)): (
            os.readlink(path) if path.is_symlink()
            else (stat.S_IMODE(path.lstat().st_mode), path.read_bytes() if path.is_file() else None)
        )
        for path in destdir.rglob("*")
    }


def _run(archive: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(archive), *arguments],
        text=True,
        capture_output=True,
        check=False,
    )


class StagedTemporaryOwnershipTest(unittest.TestCase):
    def test_failed_writer_preserves_replacement_at_temporary_name(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            replacement = b"operator replacement\n"
            temporary = parent / ".payload.open-trestle-owned-transaction"

            def writer(handle):
                handle.write(b"partial staged bytes")
                temporary.unlink()
                temporary.write_bytes(replacement)
                raise OSError("synthetic writer failure")

            with self.assertRaisesRegex(OSError, "synthetic writer failure"):
                linux_distribution_runtime._stage_file(parent, "payload", 0o444, writer, "owned-transaction")
            self.assertEqual(temporary.read_bytes(), replacement)

    def test_failed_writer_removes_only_its_own_temporary(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            def writer(handle):
                handle.write(b"partial")
                raise OSError("synthetic writer failure")
            with self.assertRaisesRegex(OSError, "synthetic writer failure"):
                linux_distribution_runtime._stage_file(parent, "payload", 0o444, writer, "owned-transaction")
            self.assertEqual(list(parent.iterdir()), [])

    def test_successful_writer_refuses_replacement_name(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            temporary = parent / ".payload.open-trestle-owned-transaction"
            replacement = b"operator replacement\n"
            def writer(handle):
                handle.write(b"staged bytes")
                temporary.unlink()
                temporary.write_bytes(replacement)
            with self.assertRaisesRegex(ValueError, "ownership changed"):
                linux_distribution_runtime._stage_file(parent, "payload", 0o444, writer, "owned-transaction")
            self.assertEqual(temporary.read_bytes(), replacement)

    def test_cleanup_preserves_replacement_swapped_at_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            temporary = parent / ".payload.open-trestle-owned-transaction"
            replacement = b"operator replacement at capture\n"
            rename = linux_distribution_runtime._rename_noreplace
            swapped = False
            def capture(parent, source, destination):
                nonlocal swapped
                if not swapped and source == temporary.name:
                    swapped = True
                    temporary.unlink()
                    temporary.write_bytes(replacement)
                return rename(parent, source, destination)
            def writer(handle):
                handle.write(b"partial")
                raise OSError("synthetic writer failure")
            with patch.object(linux_distribution_runtime, "_rename_noreplace", capture):
                with self.assertRaisesRegex(OSError, "synthetic writer failure"):
                    linux_distribution_runtime._stage_file(parent, "payload", 0o444, writer, "owned-transaction")
            self.assertTrue(swapped)
            self.assertEqual(temporary.read_bytes(), replacement)
            self.assertEqual(list(parent.iterdir()), [temporary])

    def test_cleanup_error_preserves_writer_error(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            failure = OSError("writer failure")
            cleanup_failure = OSError("capture failure")
            def writer(handle):
                raise failure
            with patch.object(linux_distribution_runtime, "_unlink_owned_file", side_effect=cleanup_failure):
                with self.assertRaises(OSError) as caught:
                    linux_distribution_runtime._stage_file(parent, "payload", 0o444, writer, "owned-transaction")
            self.assertIs(caught.exception, failure)
            self.assertIs(caught.exception.__cause__, cleanup_failure)


class BuilderTest(unittest.TestCase):
    def test_build_rejects_mode_correct_altered_or_stale_catalog_wrapper(self) -> None:
        source = Path(linux_distribution.__file__).with_name("model_catalog.py").read_bytes()
        stale = source.replace(b'            command.add_argument("--expected-current", required=True)\n', b"")
        self.assertNotEqual(stale, source)
        for name, body in (("altered", source + b"# altered fixture\n"), ("stale", stale)):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                staging = _staging(root)
                script = staging / "scripts/model_catalog.py"
                script.chmod(0o644)
                _write(script, body, 0o444)
                output = root / "out.pyz"

                with self.assertRaisesRegex(ValueError, "catalog script digest mismatch"):
                    linux_distribution.build_distribution(
                        staging, Path(linux_distribution_runtime.__file__), output,
                        "0.1.0-dev", REVISION, CREATED,
                    )

                self.assertFalse(output.exists())
                self.assertFalse(Path(str(output) + ".sha256").exists())
                self.assertEqual(list(root.glob(".*.tmp")), [])

    def test_build_rejects_unknown_script_beside_model_catalog(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staging = _staging(root)
            _write(staging / "scripts/unknown.py", b"raise SystemExit(0)\n", 0o444)
            output = root / "out.pyz"

            with self.assertRaises(ValueError):
                linux_distribution.build_distribution(
                    staging, Path(linux_distribution_runtime.__file__), output,
                    "0.1.0-dev", REVISION, CREATED,
                )

            self.assertFalse(output.exists())
            self.assertFalse(Path(str(output) + ".sha256").exists())

    def test_build_is_byte_deterministic_stored_and_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, first_sidecar = _build(root / "first")
            second, second_sidecar = _build(root / "second")

            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(first_sidecar.read_bytes(), second_sidecar.read_bytes())
            self.assertTrue(first.read_bytes().startswith(b"#!/usr/bin/env python3\n"))
            with zipfile.ZipFile(first) as archive:
                names = archive.namelist()
                self.assertEqual(names, sorted(names))
                self.assertEqual(names[0], "__main__.py")
                self.assertIn("manifest.json", names)
                self.assertNotIn("payload/etc/ssl/certs/ca-certificates.crt", names)
                self.assertFalse(any("data" in name for name in names))
                self.assertTrue(all(item.compress_type == zipfile.ZIP_STORED for item in archive.infolist()))
                self.assertTrue(all(item.date_time == (1980, 1, 1, 0, 0, 0) for item in archive.infolist()))
                self.assertEqual(archive.comment, b"")
                manifest = json.loads(archive.read("manifest.json"))
                self.assertEqual(manifest["target"], "linux-amd64")
                self.assertEqual([item["path"] for item in manifest["files"]], sorted(item["path"] for item in manifest["files"]))
                self.assertEqual(len(manifest["files"]), len(names) - 2)
            expected = hashlib.sha256(first.read_bytes()).hexdigest()
            self.assertEqual(first_sidecar.read_text(), f"{expected}  {first.name}\n")

    def test_build_refuses_existing_output_or_sidecar_without_changing_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staging = _staging(root)
            output = root / "candidate.pyz"
            output.write_bytes(b"owned")
            with self.assertRaisesRegex(ValueError, "already exists"):
                linux_distribution.build_distribution(staging, Path(linux_distribution_runtime.__file__), output, "0.1.0-dev", REVISION, CREATED)
            self.assertEqual(output.read_bytes(), b"owned")

            output.unlink()
            sidecar = Path(str(output) + ".sha256")
            sidecar.write_bytes(b"owned-sidecar")
            with self.assertRaisesRegex(ValueError, "already exists"):
                linux_distribution.build_distribution(staging, Path(linux_distribution_runtime.__file__), output, "0.1.0-dev", REVISION, CREATED)
            self.assertFalse(output.exists())
            self.assertEqual(sidecar.read_bytes(), b"owned-sidecar")


    def test_build_publish_failure_removes_both_output_names(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staging = _staging(root)
            output = root / "candidate.pyz"
            real_link = os.link
            calls = 0

            def fail_second(source, destination, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError(5, "injected link failure")
                return real_link(source, destination, **kwargs)

            with patch("linux_distribution.os.link", side_effect=fail_second):
                with self.assertRaises(OSError):
                    linux_distribution.build_distribution(staging, Path(linux_distribution_runtime.__file__), output, "0.1.0-dev", REVISION, CREATED)
            self.assertFalse(output.exists())
            self.assertFalse(Path(str(output) + ".sha256").exists())

    def test_build_rejects_wrong_modes_symlinks_elf_target_and_unexpected_inventory(self):
        cases = ("mode", "symlink", "elf", "unexpected", "release")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                staging = _staging(root)
                if case == "mode":
                    (staging / "trestle").chmod(0o755)
                elif case == "symlink":
                    (staging / "licenses/dependency/LICENSE").unlink()
                    (staging / "licenses/dependency/LICENSE").symlink_to(staging / "NOTICE")
                elif case == "elf":
                    path = staging / "trestle"
                    body = bytearray(path.read_bytes())
                    struct.pack_into("<H", body, 18, 183)
                    path.chmod(0o644)
                    _write(path, bytes(body), 0o555)
                elif case == "unexpected":
                    _write(staging / "source.go", b"private source\n", 0o444)
                else:
                    (staging / "release/vulnerability-scan.json").unlink()
                with self.assertRaises(ValueError):
                    linux_distribution.build_distribution(staging, Path(linux_distribution_runtime.__file__), root / "out.pyz", "0.1.0-dev", REVISION, CREATED)
                self.assertFalse((root / "out.pyz").exists())

    def test_build_rejects_bad_metadata_and_non_linux_host(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staging = _staging(root)
            for version, revision, created in (
                ("latest", REVISION, CREATED),
                ("1.0.0-01", REVISION, CREATED),
                ("1.0.0-a..b", REVISION, CREATED),
                (("1" * 256) + ".0.0", REVISION, CREATED),
                ("0.1.0", "HEAD", CREATED),
                ("0.1.0", REVISION, "today"),
            ):
                with self.subTest(version=version, revision=revision, created=created):
                    with self.assertRaises(ValueError):
                        linux_distribution.build_distribution(staging, Path(linux_distribution_runtime.__file__), root / f"{version}.pyz", version, revision, created)
            with patch("linux_distribution.sys.platform", "darwin"):
                with self.assertRaisesRegex(ValueError, "Linux"):
                    linux_distribution.build_distribution(staging, Path(linux_distribution_runtime.__file__), root / "darwin.pyz", "0.1.0", REVISION, CREATED)


class ArchiveVerificationTest(unittest.TestCase):
    def test_verify_accepts_archive_and_rejects_sidecar_tamper(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, sidecar = _build(Path(directory))
            valid = _run(archive, "verify")
            self.assertEqual(valid.returncode, 0, valid.stderr)
            self.assertIn("verified", valid.stdout)
            sidecar.chmod(0o644)
            sidecar.write_text(("0" * 64) + f"  {archive.name}\n")
            invalid = _run(archive, "verify")
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn("checksum", invalid.stderr.lower())

    def test_verify_rejects_archive_tampering_duplicate_extra_compressed_and_unsafe_names(self):
        mutations = ("body", "duplicate", "extra", "compressed", "unsafe")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                archive, sidecar = _build(root)
                archive.chmod(0o755)
                if mutation == "body":
                    body = bytearray(archive.read_bytes())
                    body[-30] ^= 1
                    archive.write_bytes(body)
                else:
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", UserWarning)
                        with zipfile.ZipFile(archive, "a", compression=zipfile.ZIP_STORED) as target:
                            if mutation == "duplicate":
                                target.writestr("manifest.json", b"{}")
                            elif mutation == "extra":
                                target.writestr("extra", b"x")
                            elif mutation == "compressed":
                                info = zipfile.ZipInfo("extra-compressed")
                                info.compress_type = zipfile.ZIP_DEFLATED
                                target.writestr(info, b"x")
                            else:
                                target.writestr("../escape", b"x")
                    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
                    sidecar.chmod(0o644)
                    sidecar.write_text(f"{digest}  {archive.name}\n")
                result = _run(archive, "verify")
                self.assertNotEqual(result.returncode, 0)

    def test_verify_rejects_bytes_between_shebang_and_first_local_header(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, sidecar = _build(Path(directory))
            body = archive.read_bytes()
            archive.chmod(0o755)
            archive.write_bytes(linux_distribution.SHEBANG + b"JUNK" + body[len(linux_distribution.SHEBANG):])
            archive.chmod(0o555)
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            sidecar.chmod(0o644)
            sidecar.write_text(f"{digest}  {archive.name}\n")
            sidecar.chmod(0o444)

            self.assertNotEqual(_run(archive, "verify-archive").returncode, 0)

    def test_verify_rejects_noncanonical_external_attributes(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, sidecar = _build(Path(directory))
            body = bytearray(archive.read_bytes())
            with zipfile.ZipFile(archive) as source:
                central_offset = source.start_dir
            external_offset = central_offset + 38
            current = struct.unpack_from("<I", body, external_offset)[0]
            struct.pack_into("<I", body, external_offset, current | 1)
            archive.chmod(0o755)
            archive.write_bytes(body)
            archive.chmod(0o555)
            digest = hashlib.sha256(body).hexdigest()
            sidecar.chmod(0o644)
            sidecar.write_text(f"{digest}  {archive.name}\n")
            sidecar.chmod(0o444)

            self.assertNotEqual(_run(archive, "verify-archive").returncode, 0)

    def test_verify_rejects_manifest_target_outside_fixed_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, sidecar = _build(Path(directory))
            with zipfile.ZipFile(archive) as source:
                members = {item.filename: source.read(item) for item in source.infolist()}
            manifest = json.loads(members["manifest.json"])
            body = b"x"
            manifest["files"].append({
                "elf": False,
                "mode": 0o444,
                "path": "payload/etc/cron.d/open-trestle",
                "sha256": hashlib.sha256(body).hexdigest(),
                "size": len(body),
                "source": "licenses/dependency/LICENSE",
            })
            manifest["files"].sort(key=lambda item: item["path"])
            members["manifest.json"] = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
            members["payload/etc/cron.d/open-trestle"] = body
            archive.chmod(0o755)
            with archive.open("wb") as destination:
                destination.write(linux_distribution.SHEBANG)
                with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_STORED) as target:
                    for name in sorted(members):
                        mode = 0o555 if name == "__main__.py" or name.startswith("payload/usr/local/bin/") or name.startswith("payload/usr/local/libexec/") and not name.endswith(".sha256") else 0o444
                        target.writestr(linux_distribution._zip_info(name, mode), members[name])
            archive.chmod(0o555)
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            sidecar.chmod(0o644)
            sidecar.write_text(f"{digest}  {archive.name}\n")
            sidecar.chmod(0o444)

            result = _run(archive, "verify-archive")
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((Path(directory) / "root/etc/cron.d/open-trestle").exists())

    def test_verify_rejects_missing_sidecar_and_noncanonical_sidecar(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, sidecar = _build(Path(directory))
            sidecar.unlink()
            self.assertNotEqual(_run(archive, "verify").returncode, 0)
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            for body in (f"{digest} *{archive.name}\n", f"{digest}  wrong.pyz\n", f"{digest.upper()}  {archive.name}\n"):
                sidecar.write_text(body)
                self.assertNotEqual(_run(archive, "verify").returncode, 0)


class LifecycleTest(unittest.TestCase):
    def test_installed_model_catalog_script_has_exact_bytes_help_and_owned_removal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staging = _staging(root / "build")
            wrapper = Path(linux_distribution.__file__).with_name("model_catalog.py").read_bytes()
            archive = root / "candidate.pyz"
            relative = "usr/local/share/open-trestle/scripts/model_catalog.py"
            linux_distribution.build_distribution(
                staging, Path(linux_distribution_runtime.__file__), archive,
                "0.1.0-dev", REVISION, CREATED,
            )
            with zipfile.ZipFile(archive) as package:
                manifest = json.loads(package.read("manifest.json"))
                entry = next(item for item in manifest["files"] if item["source"] == "scripts/model_catalog.py")
                self.assertEqual(entry, {
                    "path": "payload/" + relative,
                    "source": "scripts/model_catalog.py",
                    "mode": 0o444,
                    "size": len(wrapper),
                    "sha256": hashlib.sha256(wrapper).hexdigest(),
                    "elf": False,
                })
                self.assertEqual(package.read(entry["path"]), wrapper)

            destdir = root / "root"
            sentinel = destdir / "etc/open-trestle/config.json"
            _write(sentinel, b"operator config\n", 0o600)
            installed = _run(archive, "install", "--destdir", str(destdir))
            self.assertEqual(installed.returncode, 0, installed.stderr)
            script = destdir / relative
            self.assertEqual(script.read_bytes(), wrapper)
            self.assertEqual(stat.S_IMODE(script.stat().st_mode), 0o444)
            verified = _run(archive, "verify-installed", "--destdir", str(destdir))
            self.assertEqual(verified.returncode, 0, verified.stderr)

            working = root / "without-source"
            working.mkdir()
            help_result = subprocess.run(
                [sys.executable, "-I", str(script), "--help"],
                cwd=working,
                env={"HOME": str(working), "LANG": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC"},
                stdin=subprocess.DEVNULL,
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(help_result.returncode, 0, help_result.stderr)
            self.assertIn("--trestle", help_result.stdout)
            self.assertIn("refresh", help_result.stdout)
            self.assertIn("apply", help_result.stdout)
            self.assertEqual(help_result.stderr, "")

            removed = _run(archive, "uninstall", "--destdir", str(destdir))
            self.assertEqual(removed.returncode, 0, removed.stderr)
            self.assertFalse(script.exists())
            self.assertEqual(sentinel.read_bytes(), b"operator config\n")
            self.assertEqual(stat.S_IMODE(sentinel.stat().st_mode), 0o600)
            self.assertEqual(
                {str(path.relative_to(destdir)) for path in destdir.rglob("*") if path.is_file()},
                {"etc/open-trestle/config.json"},
            )

    def test_empty_destdir_install_uninstall_removes_every_package_created_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive, _ = _build(root / "build")
            destdir = root / "root"
            destdir.mkdir()

            linux_distribution_runtime.install(Path(archive), destdir)
            linux_distribution_runtime.uninstall(Path(archive), destdir)

            self.assertEqual(list(destdir.iterdir()), [])

    def test_interrupted_install_rollback_removes_created_paths_and_preserves_sentinels(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive, _ = _build(root / "build")
            destdir = root / "root"
            sentinels = {
                "etc/open-trestle/config.json": "operator config\n",
                "var/lib/open-trestle/state": "operator state\n",
                "usr/local/share/open-trestle/operator-note": "operator note\n",
            }
            for relative, body in sentinels.items():
                path = destdir / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body)
            expected_directories = {
                str(path.relative_to(destdir))
                for path in destdir.rglob("*")
                if path.is_dir()
            }
            original_publish = linux_distribution_runtime._publish_staged

            def interrupt_before_journal(parent, temporary, final_name):
                if final_name == "journal.json":
                    raise KeyboardInterrupt("injected interruption")
                return original_publish(parent, temporary, final_name)

            with patch.object(
                linux_distribution_runtime,
                "_publish_staged",
                side_effect=interrupt_before_journal,
            ):
                with self.assertRaisesRegex(KeyboardInterrupt, "injected interruption"):
                    linux_distribution_runtime.install(Path(archive), destdir)

            self.assertEqual(
                {
                    str(path.relative_to(destdir)): path.read_text()
                    for path in destdir.rglob("*")
                    if path.is_file()
                },
                sentinels,
            )
            self.assertEqual(
                {
                    str(path.relative_to(destdir))
                    for path in destdir.rglob("*")
                    if path.is_dir()
                },
                expected_directories,
            )

    def test_install_verify_rollback_and_uninstall_preserve_unowned_config_and_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive, _ = _build(root / "build")
            destdir = root / "root"
            (destdir / "etc/open-trestle").mkdir(parents=True)
            (destdir / "var/lib/open-trestle").mkdir(parents=True)
            (destdir / "etc/open-trestle/config.json").write_text("operator config\n")
            (destdir / "var/lib/open-trestle/state").write_text("operator state\n")

            installed = _run(archive, "install", "--destdir", str(destdir))
            self.assertEqual(installed.returncode, 0, installed.stderr)
            self.assertTrue((destdir / "usr/local/bin/trestle").exists())
            self.assertTrue((destdir / "usr/local/libexec/open-trestle/open-trestle-distribution.pyz").exists())
            self.assertTrue((destdir / "usr/local/share/open-trestle/distribution/receipt.json").exists())
            self.assertTrue((destdir / "usr/local/share/open-trestle/distribution/journal.json").exists())
            verified = _run(archive, "verify-installed", "--destdir", str(destdir))
            self.assertEqual(verified.returncode, 0, verified.stderr)

            rolled_back = _run(archive, "rollback", "--destdir", str(destdir))
            self.assertEqual(rolled_back.returncode, 0, rolled_back.stderr)
            self.assertFalse((destdir / "usr/local/bin/trestle").exists())
            self.assertEqual((destdir / "etc/open-trestle/config.json").read_text(), "operator config\n")
            self.assertEqual((destdir / "var/lib/open-trestle/state").read_text(), "operator state\n")

            self.assertEqual(_run(archive, "install", "--destdir", str(destdir)).returncode, 0)
            unowned = destdir / "usr/local/share/open-trestle/operator-note"
            unowned.write_text("keep\n")
            removed = _run(archive, "uninstall", "--destdir", str(destdir))
            self.assertEqual(removed.returncode, 0, removed.stderr)
            self.assertTrue(unowned.exists())
            self.assertTrue((destdir / "etc/open-trestle/config.json").exists())
            self.assertTrue((destdir / "var/lib/open-trestle/state").exists())

    def test_install_refuses_relative_destdir_existing_unowned_file_and_symlink_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive, _ = _build(root / "build")
            self.assertNotEqual(_run(archive, "install", "--destdir", "relative").returncode, 0)

            destdir = root / "collision"
            target = destdir / "usr/local/bin/trestle"
            _write(target, b"operator owned\n", 0o555)
            result = _run(archive, "install", "--destdir", str(destdir))
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(target.read_bytes(), b"operator owned\n")
            self.assertFalse((destdir / "usr/local/bin/trestled").exists())

            destdir = root / "symlink"
            outside = root / "outside"
            outside.mkdir()
            (destdir / "usr/local").mkdir(parents=True)
            (destdir / "usr/local/bin").symlink_to(outside)
            result = _run(archive, "install", "--destdir", str(destdir))
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(list(outside.iterdir()), [])

    def test_verify_uninstall_and_rollback_refuse_tampered_or_replaced_owned_file(self):
        for command in ("verify-installed", "rollback", "uninstall"):
            with self.subTest(command=command), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                archive, _ = _build(root / "build")
                destdir = root / "root"
                destdir.mkdir()
                result = _run(archive, "install", "--destdir", str(destdir))
                self.assertEqual(result.returncode, 0, result.stderr)
                installed = destdir / "usr/local/bin/trestle"
                installed.chmod(0o755)
                installed.write_bytes(installed.read_bytes() + b"tamper")
                result = _run(archive, command, "--destdir", str(destdir))
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(installed.exists())

    def test_second_install_is_refused_without_force_and_preserves_first(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive, _ = _build(root / "first", b"first")
            second, _ = _build(root / "second", b"second")
            destdir = root / "root"
            destdir.mkdir()
            self.assertEqual(_run(archive, "install", "--destdir", str(destdir)).returncode, 0)
            before = (destdir / "usr/local/bin/trestle").read_bytes()
            result = _run(second, "install", "--destdir", str(destdir))
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((destdir / "usr/local/bin/trestle").read_bytes(), before)

    def test_failed_receipt_publish_leaves_no_transaction_temporary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive, _ = _build(root / "build")
            destdir = root / "root"
            destdir.mkdir()
            original = linux_distribution_runtime._publish_staged

            def fail_receipt(parent, temporary, final_name):
                if final_name == "receipt.json":
                    raise OSError("injected receipt failure")
                return original(parent, temporary, final_name)

            with patch.object(linux_distribution_runtime, "_publish_staged", side_effect=fail_receipt):
                with self.assertRaises(OSError):
                    linux_distribution_runtime.install(Path(archive), destdir)
            leftovers = [path for path in destdir.rglob("*") if ".open-trestle-" in path.name]
            self.assertEqual(leftovers, [])
            self.assertFalse((destdir / "usr/local/bin/trestle").exists())

    def test_install_copies_lifecycle_from_verified_open_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive, _ = _build(root / "build")
            original_body = archive.read_bytes()
            secret = root / "secret"
            secret.write_bytes(b"root-only secret\n")
            secret.chmod(0o600)
            destdir = root / "root"
            destdir.mkdir()
            original_stage = linux_distribution_runtime._stage_file
            swapped = False
            staged_body = None

            def swap_before_lifecycle(parent, final_name, mode, writer, transaction, production=False):
                nonlocal swapped, staged_body
                if final_name == "open-trestle-distribution.pyz" and not swapped:
                    swapped = True
                    archive.unlink()
                    archive.symlink_to(secret)
                temporary = original_stage(parent, final_name, mode, writer, transaction, production)
                if final_name == "open-trestle-distribution.pyz":
                    staged_body = (parent / temporary).read_bytes()
                return temporary

            with patch.object(linux_distribution_runtime, "_stage_file", side_effect=swap_before_lifecycle):
                with self.assertRaisesRegex(ValueError, "archive changed"):
                    linux_distribution_runtime.install(Path(archive), destdir)
            self.assertTrue(swapped)
            self.assertEqual(staged_body, original_body)
            self.assertNotEqual(staged_body, secret.read_bytes())
            self.assertFalse((destdir / "usr/local/libexec/open-trestle/open-trestle-distribution.pyz").exists())

    def test_install_failure_preserves_replacement_of_published_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive, _ = _build(root / "build")
            destdir = root / "root"
            destdir.mkdir()
            replacement = b"operator replacement\n"
            calls = 0
            original_fsync = linux_distribution_runtime._fsync_directory

            def replace_after_first_publish(parent):
                nonlocal calls
                target = destdir / "usr/local/bin/trestle"
                if target.exists():
                    calls += 1
                    if calls == 1:
                        target.unlink()
                        _write(target, replacement, 0o555)
                        raise OSError("injected fsync failure")
                return original_fsync(parent)

            with patch.object(linux_distribution_runtime, "_fsync_directory", side_effect=replace_after_first_publish):
                with self.assertRaises(OSError):
                    linux_distribution_runtime.install(Path(archive), destdir)
            self.assertEqual((destdir / "usr/local/bin/trestle").read_bytes(), replacement)

    def test_uninstall_preserves_replacement_before_first_delete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive, _ = _build(root / "build")
            destdir = root / "root"
            destdir.mkdir()
            linux_distribution_runtime.install(Path(archive), destdir)
            replacement = b"operator replacement\n"
            original_unlink = linux_distribution_runtime._unlink_owned_file
            replaced_path = None

            def replace_first(path, item, identity):
                nonlocal replaced_path
                if replaced_path is None:
                    replaced_path = path
                    path.unlink()
                    _write(path, replacement, item.mode)
                return original_unlink(path, item, identity)

            with patch.object(linux_distribution_runtime, "_unlink_owned_file", side_effect=replace_first):
                with self.assertRaisesRegex(ValueError, "changed during uninstall"):
                    linux_distribution_runtime.uninstall(Path(archive), destdir)
            self.assertIsNotNone(replaced_path)
            self.assertEqual(replaced_path.read_bytes(), replacement)

    def test_failed_publish_rolls_back_created_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive, _ = _build(root / "build")
            destdir = root / "root"
            destdir.mkdir()
            original = linux_distribution_runtime._publish_staged
            calls = 0

            def fail_second(*args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("injected failure")
                return original(*args, **kwargs)

            with patch.object(linux_distribution_runtime, "_publish_staged", side_effect=fail_second):
                with self.assertRaises(OSError):
                    linux_distribution_runtime.install(Path(archive), destdir)
            self.assertFalse((destdir / "usr/local/bin/trestle").exists())
            self.assertFalse((destdir / "usr/local/bin/trestled").exists())


    def test_semver_precedence_is_strict_for_upgrade_admission(self):
        precedence = linux_distribution_runtime._version_precedence
        self.assertLess(precedence("1.0.0-rc.2"), precedence("1.0.0-rc.10"))
        self.assertLess(precedence("1.0.0-rc.10"), precedence("1.0.0"))
        self.assertEqual(precedence("1.0.0+one"), precedence("1.0.0+two"))
        for version in ("1.0.0-01", "1.0.0-a..b", "01.0.0", ("1" * 256) + ".0.0"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                precedence(version)

    def test_upgrade_from_scriptless_manifest_restores_exact_predecessor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, _ = _build(root / "old", b"old", "0.1.0-dev")
            with zipfile.ZipFile(first) as source:
                manifest = json.loads(source.read("manifest.json"))
                payload = tuple(
                    linux_distribution.Payload(
                        item["source"], item["path"].removeprefix("payload/"), item["mode"],
                        item["size"], item["sha256"], item["elf"], source.read(item["path"]),
                    ) for item in manifest["files"] if item["source"] != "scripts/model_catalog.py"
                )
                runtime = source.read("__main__.py")
            manifest["schema_version"] = 1
            manifest["files"] = [item for item in manifest["files"] if item["source"] != "scripts/model_catalog.py"]
            first.chmod(0o644)
            with first.open("w+b") as output:
                linux_distribution._write_archive(output, runtime, linux_distribution._canonical_json(manifest), payload)
            first.chmod(0o555)
            sidecar = Path(str(first) + ".sha256")
            sidecar.chmod(0o644)
            sidecar.write_text(f"{hashlib.sha256(first.read_bytes()).hexdigest()}  {first.name}\n")
            sidecar.chmod(0o444)
            second, _ = _build(root / "new", b"new", "0.2.0-dev")
            destdir = root / "installed"
            destdir.mkdir()
            linux_distribution_runtime.install(first, destdir)
            script = destdir / "usr/local/share/open-trestle/scripts/model_catalog.py"
            self.assertFalse(script.exists())
            linux_distribution_runtime.upgrade(second, destdir)
            self.assertEqual(script.read_bytes(), Path(linux_distribution.__file__).with_name("model_catalog.py").read_bytes())
            linux_distribution_runtime.rollback_version(second, destdir)
            self.assertFalse(script.exists())
            self.assertEqual((destdir / "usr/local/bin/trestle").read_bytes(), _elf(b"trestle-old"))

    def test_embedded_upgrade_rollback_version_and_upgraded_uninstall_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, _ = _build(root / "first", b"first", "1.0.0")
            second, _ = _build(root / "second", b"second", "1.1.0")
            destdir = root / "root"
            destdir.mkdir()

            for archive, arguments in (
                (first, ("install", "--destdir", str(destdir))),
                (second, ("upgrade", "--destdir", str(destdir))),
                (destdir / linux_distribution_runtime.LIFECYCLE_PATH, ("verify-installed", "--destdir", str(destdir))),
                (destdir / linux_distribution_runtime.LIFECYCLE_PATH, ("rollback-version", "--destdir", str(destdir))),
                (destdir / linux_distribution_runtime.LIFECYCLE_PATH, ("verify-installed", "--destdir", str(destdir))),
                (second, ("upgrade", "--destdir", str(destdir))),
                (destdir / linux_distribution_runtime.LIFECYCLE_PATH, ("uninstall", "--destdir", str(destdir))),
            ):
                result = _run(archive, *arguments)
                self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(list(destdir.iterdir()), [])

    def test_repeated_upgrade_replaces_the_rollback_slot_with_the_superseded_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, _ = _build(root / "first", b"first", "1.0.0")
            second, _ = _build(root / "second", b"second", "1.1.0")
            third, _ = _build(root / "third", b"third", "1.2.0")
            destdir = root / "root"
            sentinels = {
                "etc/open-trestle/config.json": b"operator config\n",
                "var/lib/open-trestle/state": b"operator state\n",
                "usr/local/share/open-trestle/operator-note": b"operator note\n",
            }
            for relative, body in sentinels.items():
                _write(destdir / relative, body, 0o600)
            installed = destdir / linux_distribution_runtime.LIFECYCLE_PATH
            distribution = destdir / "usr/local/share/open-trestle/distribution"

            def run(archive: Path, *arguments: str) -> None:
                result = _run(archive, *arguments, "--destdir", str(destdir))
                self.assertEqual(result.returncode, 0, f"{arguments}: {result.stderr}")

            def assert_slot_holds(archive: Path, receipt_body: bytes, journal_body: bytes) -> None:
                self.assertEqual(
                    sorted(path.name for path in distribution.iterdir()),
                    sorted([
                        "journal.json", "previous-journal.json", "previous-receipt.json",
                        "previous.pyz", "previous.pyz.sha256", "receipt.json",
                    ]),
                )
                self.assertEqual((destdir / linux_distribution_runtime.PREVIOUS_ARCHIVE_PATH).read_bytes(), archive.read_bytes())
                self.assertEqual((destdir / linux_distribution_runtime.PREVIOUS_RECEIPT_PATH).read_bytes(), receipt_body)
                self.assertEqual((destdir / linux_distribution_runtime.PREVIOUS_JOURNAL_PATH).read_bytes(), journal_body)

            run(first, "install")
            run(second, "upgrade")
            second_receipt = (destdir / linux_distribution_runtime.RECEIPT_PATH).read_bytes()
            second_journal = (destdir / linux_distribution_runtime.JOURNAL_PATH).read_bytes()
            run(third, "upgrade")
            run(installed, "verify-installed")
            self.assertEqual(installed.read_bytes(), third.read_bytes())
            assert_slot_holds(second, second_receipt, second_journal)
            receipt = json.loads((destdir / linux_distribution_runtime.RECEIPT_PATH).read_bytes())
            self.assertEqual((receipt["action"], receipt["old_version"], receipt["version"]), ("upgrade", "1.1.0", "1.2.0"))
            self.assertEqual(receipt["previous"]["version"], "1.1.0")
            self.assertEqual(receipt["previous"]["receipt_sha256"], hashlib.sha256(second_receipt).hexdigest())
            first_digest = hashlib.sha256(first.read_bytes()).hexdigest()
            self.assertFalse(any(
                hashlib.sha256(path.read_bytes()).hexdigest() == first_digest
                for path in destdir.rglob("*") if path.is_file()
            ))

            run(installed, "rollback-version")
            run(installed, "verify-installed")
            self.assertEqual(installed.read_bytes(), second.read_bytes())
            self.assertEqual((destdir / "usr/local/bin/trestle").read_bytes(), _elf(b"trestle-second"))
            self.assertEqual(
                sorted(path.name for path in distribution.iterdir()),
                ["journal.json", "receipt.json"],
            )
            restored = json.loads((destdir / linux_distribution_runtime.RECEIPT_PATH).read_bytes())
            self.assertEqual(
                (restored["action"], restored["old_version"], restored["version"], restored["previous"]),
                ("rollback-version", "1.2.0", "1.1.0", None),
            )
            refused = _run(installed, "rollback-version", "--destdir", str(destdir))
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn("immediate predecessor", refused.stderr)

            run(third, "upgrade")
            run(installed, "verify-installed")
            self.assertEqual(
                json.loads((destdir / linux_distribution_runtime.PREVIOUS_RECEIPT_PATH).read_bytes())["action"],
                "rollback-version",
            )
            run(installed, "uninstall")
            self.assertEqual(
                {str(path.relative_to(destdir)): path.read_bytes() for path in destdir.rglob("*") if path.is_file()},
                sentinels,
            )
            self.assertEqual([path for path in destdir.rglob("*") if ".open-trestle-" in path.name], [])

    def test_upgrade_accepts_legacy_controls_and_rollback_restores_them_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, _ = _build(root / "first", b"first", "1.0.0")
            second, _ = _build(root / "second", b"second", "1.1.0")
            destdir = root / "root"
            destdir.mkdir()
            linux_distribution_runtime.install(first, destdir)
            legacy_receipt, legacy_journal = _rewrite_controls_as_legacy(destdir)
            linux_distribution_runtime.verify_installed(first, destdir)

            linux_distribution_runtime.upgrade(second, destdir)
            linux_distribution_runtime.rollback_version(second, destdir)

            self.assertEqual(
                (destdir / linux_distribution_runtime.RECEIPT_PATH).read_bytes(),
                legacy_receipt,
            )
            self.assertEqual(
                (destdir / linux_distribution_runtime.JOURNAL_PATH).read_bytes(),
                legacy_journal,
            )
            linux_distribution_runtime.verify_installed(first, destdir)
            self.assertFalse(
                (destdir / linux_distribution_runtime.PREVIOUS_ARCHIVE_PATH).exists()
            )
            self.assertFalse(
                (destdir / linux_distribution_runtime.PREVIOUS_RECEIPT_PATH).exists()
            )

    def test_repeated_upgrade_and_rollback_accept_legacy_controls_in_and_out_of_the_slot(self):
        # schema-1: the discarded predecessor's controls are pre-upgrade legacy.
        # schema-2: the retained predecessor's controls predate generation identities,
        # so its rollback receipt must stay in the schema its own lifecycle reads.
        for form, rollback_schema in (("schema-1", 3), ("schema-2", 2)):
            with self.subTest(form=form), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                first, _ = _build(root / "first", b"first", "1.0.0")
                second, _ = _build(root / "second", b"second", "1.1.0")
                third, _ = _build(root / "third", b"third", "1.2.0")
                destdir = root / "root"
                destdir.mkdir()
                linux_distribution_runtime.install(first, destdir)
                if form == "schema-1":
                    legacy_receipt, _ = _rewrite_controls_as_legacy(destdir)
                    linux_distribution_runtime.upgrade(second, destdir)
                    self.assertEqual(
                        (destdir / linux_distribution_runtime.PREVIOUS_RECEIPT_PATH).read_bytes(),
                        legacy_receipt,
                    )
                else:
                    linux_distribution_runtime.upgrade(second, destdir)
                    _rewrite_controls_as_schema_2(destdir)
                linux_distribution_runtime.verify_installed(second, destdir)
                retained_receipt = (destdir / linux_distribution_runtime.RECEIPT_PATH).read_bytes()

                linux_distribution_runtime.upgrade(third, destdir)
                linux_distribution_runtime.verify_installed(third, destdir)
                self.assertEqual(
                    (destdir / linux_distribution_runtime.PREVIOUS_ARCHIVE_PATH).read_bytes(),
                    second.read_bytes(),
                )
                self.assertEqual(
                    (destdir / linux_distribution_runtime.PREVIOUS_RECEIPT_PATH).read_bytes(),
                    retained_receipt,
                )

                linux_distribution_runtime.rollback_version(third, destdir)
                self.assertEqual(linux_distribution_runtime.verify_installed(second, destdir)["version"], "1.1.0")
                receipt = json.loads((destdir / linux_distribution_runtime.RECEIPT_PATH).read_bytes())
                journal = json.loads((destdir / linux_distribution_runtime.JOURNAL_PATH).read_bytes())
                for document in (receipt, journal):
                    self.assertEqual(document["schema_version"], rollback_schema)
                    self.assertEqual(document["action"], "rollback-version")
                    self.assertEqual((document["old_version"], document["new_version"]), ("1.2.0", "1.1.0"))
                    self.assertEqual("old_generation_id" in document, rollback_schema == 3)
                self.assertIsNone(receipt["previous"])
                self.assertFalse((destdir / linux_distribution_runtime.PREVIOUS_ARCHIVE_PATH).exists())
                with self.assertRaisesRegex(ValueError, "immediate predecessor"):
                    linux_distribution_runtime.rollback_version(second, destdir)

                linux_distribution_runtime.upgrade(third, destdir)
                linux_distribution_runtime.verify_installed(third, destdir)
                linux_distribution_runtime.uninstall(third, destdir)
                self.assertEqual(list(destdir.iterdir()), [])

    def test_upgrade_refuses_a_tampered_or_unsafe_rollback_slot_without_mutation(self):
        slot = {
            "archive": linux_distribution_runtime.PREVIOUS_ARCHIVE_PATH,
            "sidecar": linux_distribution_runtime.PREVIOUS_SIDECAR_PATH,
            "receipt": linux_distribution_runtime.PREVIOUS_RECEIPT_PATH,
            "journal": linux_distribution_runtime.PREVIOUS_JOURNAL_PATH,
        }
        faults = (
            ("archive", "bytes", "checksum sidecar does not match"),
            ("archive", "substituted", "predecessor archive does not match the receipt"),
            ("sidecar", "bytes", "checksum sidecar does not match"),
            ("receipt", "bytes", "predecessor controls do not match the receipt"),
            ("journal", "bytes", "predecessor controls do not match the receipt"),
            ("receipt", "mode", "receipt or journal is not protected"),
            ("archive", "mode", "archive is not a protected regular file"),
            ("journal", "symlink", "receipt or journal is not protected"),
            ("sidecar", "missing", "checksum sidecar is unavailable"),
            ("journal", "ancestor", "ancestor is not trusted"),
        )
        for name, fault, message in faults:
            with self.subTest(name=name, fault=fault), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                first, _ = _build(root / "first", b"first", "1.0.0")
                second, _ = _build(root / "second", b"second", "1.1.0")
                third, _ = _build(root / "third", b"third", "1.2.0")
                destdir = root / "root"
                _write(destdir / "etc/open-trestle/config.json", b"operator config\n", 0o600)
                linux_distribution_runtime.install(first, destdir)
                linux_distribution_runtime.upgrade(second, destdir)
                path = destdir / slot[name]
                mode = stat.S_IMODE(path.stat().st_mode)
                if fault == "bytes":
                    body = path.read_bytes()
                    path.chmod(0o644)
                    path.write_bytes(body[:-1] + bytes([body[-1] ^ 1]))
                    path.chmod(mode)
                elif fault == "substituted":
                    # A valid archive, sealed by its own sidecar, that is not the bound predecessor.
                    sidecar = destdir / linux_distribution_runtime.PREVIOUS_SIDECAR_PATH
                    path.chmod(0o755)
                    path.write_bytes(third.read_bytes())
                    path.chmod(mode)
                    sidecar.chmod(0o644)
                    sidecar.write_text(f"{hashlib.sha256(third.read_bytes()).hexdigest()}  {path.name}\n")
                    sidecar.chmod(0o444)
                elif fault == "mode":
                    path.chmod(0o755 if mode == 0o555 else 0o644)
                elif fault == "symlink":
                    copy = root / "outside-copy"
                    copy.write_bytes(path.read_bytes())
                    copy.chmod(0o444)
                    path.unlink()
                    path.symlink_to(copy)
                elif fault == "missing":
                    path.unlink()
                else:
                    path.parent.chmod(0o775)
                before = _tree(destdir)
                with self.assertRaisesRegex(ValueError, message):
                    linux_distribution_runtime.upgrade(third, destdir)
                self.assertEqual(_tree(destdir), before)
                self.assertIsNone(linux_distribution_runtime._active_transaction(destdir))
                if fault == "ancestor":
                    path.parent.chmod(0o755)

    def test_upgrade_and_immediate_version_rollback_are_exact_and_one_use(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, _ = _build(root / "first", b"first", "1.0.0")
            second, _ = _build(root / "second", b"second", "1.1.0")
            destdir = root / "root"
            (destdir / "etc/open-trestle").mkdir(parents=True)
            (destdir / "var/lib/open-trestle").mkdir(parents=True)
            config = destdir / "etc/open-trestle/config.json"
            state = destdir / "var/lib/open-trestle/state"
            config.write_text("operator config\n")
            state.write_text("operator state\n")
            linux_distribution_runtime.install(first, destdir)
            unowned = destdir / "usr/local/share/open-trestle/operator-note"
            unowned.write_text("operator owned\n")
            first_body = (destdir / "usr/local/bin/trestle").read_bytes()

            linux_distribution_runtime.upgrade(second, destdir)
            self.assertEqual(linux_distribution_runtime.verify_installed(second, destdir)["version"], "1.1.0")
            self.assertNotEqual((destdir / "usr/local/bin/trestle").read_bytes(), first_body)
            receipt = json.loads((destdir / linux_distribution_runtime.RECEIPT_PATH).read_bytes())
            journal = json.loads((destdir / linux_distribution_runtime.JOURNAL_PATH).read_bytes())
            for document in (receipt, journal):
                self.assertEqual(document["action"], "upgrade")
                self.assertEqual(document["old_version"], "1.0.0")
                self.assertEqual(document["new_version"], "1.1.0")
                self.assertRegex(document["old_archive_sha256"], r"^[0-9a-f]{64}$")
                self.assertRegex(document["new_archive_sha256"], r"^[0-9a-f]{64}$")
                self.assertRegex(document["old_manifest_sha256"], r"^[0-9a-f]{64}$")
                self.assertRegex(document["new_manifest_sha256"], r"^[0-9a-f]{64}$")
                self.assertRegex(document["transaction"], r"^[0-9a-f]{32}$")

            linux_distribution_runtime.rollback_version(second, destdir)
            self.assertEqual(linux_distribution_runtime.verify_installed(first, destdir)["version"], "1.0.0")
            self.assertEqual((destdir / "usr/local/bin/trestle").read_bytes(), first_body)
            self.assertEqual(config.read_text(), "operator config\n")
            self.assertEqual(state.read_text(), "operator state\n")
            self.assertEqual(unowned.read_text(), "operator owned\n")
            with self.assertRaisesRegex(ValueError, "immediate predecessor"):
                linux_distribution_runtime.rollback_version(first, destdir)

    def test_production_lifecycle_resolves_the_root_once_without_reparsing_it_as_destdir(self):
        # A production command runs as root with no --destdir and resolves "/".
        # The --destdir parser refuses "/", so feeding the resolved root back
        # into a destdir-taking function broke every production upgrade and
        # rollback-version. Map "no --destdir" onto a sandbox and fail on any
        # internal re-entry with a resolved root.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, _ = _build(root / "first", b"first", "1.0.0")
            second, _ = _build(root / "second", b"second", "1.1.0")
            sandbox = root / "root"
            sandbox.mkdir()

            def production_root(destdir):
                if destdir is not None:
                    raise AssertionError(f"resolved root {destdir} re-entered the --destdir parser")
                return sandbox

            installed = sandbox / linux_distribution_runtime.LIFECYCLE_PATH
            with patch.object(linux_distribution_runtime, "_installation_root", production_root):
                linux_distribution_runtime.install(first, None)
                linux_distribution_runtime.upgrade(second, None)
                self.assertEqual(linux_distribution_runtime.verify_installed(second, None)["version"], "1.1.0")
                linux_distribution_runtime.rollback_version(installed, None)
                self.assertEqual(linux_distribution_runtime.verify_installed(first, None)["version"], "1.0.0")
                linux_distribution_runtime.upgrade(second, None)
                linux_distribution_runtime.uninstall(installed, None)
            self.assertEqual(list(sandbox.iterdir()), [])

    def test_production_repeated_upgrade_replaces_the_slot_without_reparsing_the_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, _ = _build(root / "first", b"first", "1.0.0")
            second, _ = _build(root / "second", b"second", "1.1.0")
            third, _ = _build(root / "third", b"third", "1.2.0")
            sandbox = root / "root"
            sandbox.mkdir()

            def production_root(destdir):
                if destdir is not None:
                    raise AssertionError(f"resolved root {destdir} re-entered the --destdir parser")
                return sandbox

            installed = sandbox / linux_distribution_runtime.LIFECYCLE_PATH
            previous = sandbox / linux_distribution_runtime.PREVIOUS_ARCHIVE_PATH
            with patch.object(linux_distribution_runtime, "_installation_root", production_root):
                linux_distribution_runtime.install(first, None)
                linux_distribution_runtime.upgrade(second, None)
                linux_distribution_runtime.upgrade(third, None)
                self.assertEqual(linux_distribution_runtime.verify_installed(third, None)["version"], "1.2.0")
                self.assertEqual(previous.read_bytes(), second.read_bytes())
                linux_distribution_runtime.rollback_version(installed, None)
                self.assertEqual(linux_distribution_runtime.verify_installed(second, None)["version"], "1.1.0")
                self.assertFalse(previous.exists())
                linux_distribution_runtime.upgrade(third, None)
                self.assertEqual(previous.read_bytes(), second.read_bytes())
                linux_distribution_runtime.uninstall(installed, None)
            self.assertEqual(list(sandbox.iterdir()), [])

    def test_upgrade_preflight_refuses_non_newer_collision_and_untrusted_control_without_mutation(self):
        cases = ("1.0.0", "0.9.0")
        for candidate_version in cases:
            with self.subTest(candidate_version=candidate_version), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                first, _ = _build(root / "first", b"first", "1.0.0")
                candidate, _ = _build(root / "candidate", b"candidate", candidate_version)
                destdir = root / "root"
                destdir.mkdir()
                linux_distribution_runtime.install(first, destdir)
                before = {str(path.relative_to(destdir)): path.read_bytes() for path in destdir.rglob("*") if path.is_file()}
                with self.assertRaisesRegex(ValueError, "strictly newer"):
                    linux_distribution_runtime.upgrade(candidate, destdir)
                after = {str(path.relative_to(destdir)): path.read_bytes() for path in destdir.rglob("*") if path.is_file()}
                self.assertEqual(after, before)

        for fault in ("collision", "symlink", "mode"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                first, _ = _build(root / "first", b"first", "1.0.0")
                second, _ = _build(root / "second", b"second", "1.1.0")
                destdir = root / "root"
                destdir.mkdir()
                linux_distribution_runtime.install(first, destdir)
                if fault == "mode":
                    (destdir / linux_distribution_runtime.JOURNAL_PATH).chmod(0o644)
                else:
                    collision = destdir / linux_distribution_runtime.PREVIOUS_ARCHIVE_PATH
                    collision.parent.mkdir(parents=True, exist_ok=True)
                    if fault == "collision":
                        collision.write_bytes(b"unowned")
                    else:
                        collision.symlink_to(root / "outside")
                before = {str(path.relative_to(destdir)): (path.read_bytes() if not path.is_symlink() else os.readlink(path)) for path in destdir.rglob("*") if path.is_file() or path.is_symlink()}
                with self.assertRaises((ValueError, FileExistsError)):
                    linux_distribution_runtime.upgrade(second, destdir)
                after = {str(path.relative_to(destdir)): (path.read_bytes() if not path.is_symlink() else os.readlink(path)) for path in destdir.rglob("*") if path.is_file() or path.is_symlink()}
                self.assertEqual(after, before)

    def test_rollback_version_refuses_missing_or_tampered_predecessor_without_mutation(self):
        for fault in ("missing", "tamper", "sidecar"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                first, _ = _build(root / "first", b"first", "1.0.0")
                second, _ = _build(root / "second", b"second", "1.1.0")
                destdir = root / "root"
                destdir.mkdir()
                linux_distribution_runtime.install(first, destdir)
                linux_distribution_runtime.upgrade(second, destdir)
                path = destdir / (linux_distribution_runtime.PREVIOUS_SIDECAR_PATH if fault == "sidecar" else linux_distribution_runtime.PREVIOUS_ARCHIVE_PATH)
                path.chmod(0o644 if fault == "tamper" else stat.S_IMODE(path.stat().st_mode))
                if fault == "missing":
                    path.unlink()
                elif fault == "tamper":
                    path.write_bytes(path.read_bytes() + b"tamper")
                else:
                    path.chmod(0o644)
                before = {str(item.relative_to(destdir)): item.read_bytes() for item in destdir.rglob("*") if item.is_file()}
                with self.assertRaises(ValueError):
                    linux_distribution_runtime.rollback_version(second, destdir)
                after = {str(item.relative_to(destdir)): item.read_bytes() for item in destdir.rglob("*") if item.is_file()}
                self.assertEqual(after, before)

    def test_upgrade_faults_restore_old_generation_without_transaction_debris(self):
        for fault in ("staging", "replacement", "receipt", "journal", "fsync"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                first, _ = _build(root / "first", b"first", "1.0.0")
                second, _ = _build(root / "second", b"second", "1.1.0")
                destdir = root / "root"
                destdir.mkdir()
                linux_distribution_runtime.install(first, destdir)
                before = {str(path.relative_to(destdir)): path.read_bytes() for path in destdir.rglob("*") if path.is_file()}
                original_stage = linux_distribution_runtime._stage_file
                original_publish = linux_distribution_runtime._publish_staged
                original_fsync = linux_distribution_runtime._fsync_directory
                calls = 0

                def fail_stage(parent, final_name, mode, writer, transaction, production=False):
                    if final_name == "trestled":
                        raise OSError("injected staging failure")
                    return original_stage(parent, final_name, mode, writer, transaction, production)

                def fail_publish(parent, temporary, final_name):
                    target = {"replacement": "trestled", "receipt": "receipt.json", "journal": "journal.json"}.get(fault)
                    if final_name == target:
                        raise OSError(f"injected {fault} failure")
                    return original_publish(parent, temporary, final_name)

                def fail_fsync(parent):
                    nonlocal calls
                    calls += 1
                    if calls == 1:
                        raise OSError("injected fsync failure")
                    return original_fsync(parent)

                stage_effect = fail_stage if fault == "staging" else original_stage
                fsync_effect = fail_fsync if fault == "fsync" else original_fsync
                with patch.object(linux_distribution_runtime, "_stage_file", side_effect=stage_effect), patch.object(linux_distribution_runtime, "_publish_staged", side_effect=fail_publish), patch.object(linux_distribution_runtime, "_fsync_directory", side_effect=fsync_effect):
                    with self.assertRaises(OSError):
                        linux_distribution_runtime.upgrade(second, destdir)
                after = {str(path.relative_to(destdir)): path.read_bytes() for path in destdir.rglob("*") if path.is_file()}
                self.assertEqual(after, before)
                self.assertEqual([path for path in destdir.rglob("*") if ".open-trestle-" in path.name], [])
                linux_distribution_runtime.verify_installed(first, destdir)

    def test_upgrade_race_preserves_replacement_and_leaves_no_transaction_names(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, _ = _build(root / "first", b"first", "1.0.0")
            second, _ = _build(root / "second", b"second", "1.1.0")
            destdir = root / "root"
            destdir.mkdir()
            linux_distribution_runtime.install(first, destdir)
            target = destdir / "usr/local/bin/trestle"
            replacement = b"operator replacement\n"
            original_rename = linux_distribution_runtime._rename_noreplace
            replaced = False

            def replace_before_quarantine(parent, source_name, destination_name):
                nonlocal replaced
                if source_name == "trestle" and ".open-trestle-old-" in destination_name and not replaced:
                    replaced = True
                    target.unlink()
                    _write(target, replacement, 0o555)
                return original_rename(parent, source_name, destination_name)

            with patch.object(
                linux_distribution_runtime,
                "_rename_noreplace",
                side_effect=replace_before_quarantine,
            ):
                with self.assertRaisesRegex(ValueError, "changed during transition"):
                    linux_distribution_runtime.upgrade(second, destdir)
            self.assertTrue(replaced)
            self.assertEqual(target.read_bytes(), replacement)
            self.assertEqual(
                [path for path in destdir.rglob("*") if ".open-trestle-" in path.name],
                [],
            )

    def test_rollback_version_faults_restore_new_generation_and_rollback_slot(self):
        for fault in ("staging", "replacement", "receipt", "journal", "fsync"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                first, _ = _build(root / "first", b"first", "1.0.0")
                second, _ = _build(root / "second", b"second", "1.1.0")
                destdir = root / "root"
                destdir.mkdir()
                linux_distribution_runtime.install(first, destdir)
                linux_distribution_runtime.upgrade(second, destdir)
                before = {
                    str(path.relative_to(destdir)): path.read_bytes()
                    for path in destdir.rglob("*")
                    if path.is_file()
                }
                original_stage = linux_distribution_runtime._stage_file
                original_publish = linux_distribution_runtime._publish_staged
                original_fsync = linux_distribution_runtime._fsync_directory
                calls = 0

                def fail_stage(parent, final_name, mode, writer, transaction, production=False):
                    if final_name == "trestled":
                        raise OSError("injected staging failure")
                    return original_stage(parent, final_name, mode, writer, transaction, production)

                def fail_publish(parent, temporary, final_name):
                    target = {
                        "replacement": "trestled",
                        "receipt": "receipt.json",
                        "journal": "journal.json",
                    }.get(fault)
                    if final_name == target:
                        raise OSError(f"injected {fault} failure")
                    return original_publish(parent, temporary, final_name)

                def fail_fsync(parent):
                    nonlocal calls
                    calls += 1
                    if calls == 1:
                        raise OSError("injected fsync failure")
                    return original_fsync(parent)

                with patch.object(
                    linux_distribution_runtime,
                    "_stage_file",
                    side_effect=fail_stage if fault == "staging" else original_stage,
                ), patch.object(
                    linux_distribution_runtime,
                    "_publish_staged",
                    side_effect=fail_publish,
                ), patch.object(
                    linux_distribution_runtime,
                    "_fsync_directory",
                    side_effect=fail_fsync if fault == "fsync" else original_fsync,
                ):
                    with self.assertRaises(OSError):
                        linux_distribution_runtime.rollback_version(second, destdir)
                after = {
                    str(path.relative_to(destdir)): path.read_bytes()
                    for path in destdir.rglob("*")
                    if path.is_file()
                }
                self.assertEqual(after, before)
                self.assertEqual(
                    [path for path in destdir.rglob("*") if ".open-trestle-" in path.name],
                    [],
                )
                linux_distribution_runtime.verify_installed(second, destdir)

    def test_destdir_root_and_production_privilege_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, _ = _build(Path(directory) / "build")
            self.assertNotEqual(_run(archive, "install", "--destdir", "/").returncode, 0)
            with patch("linux_distribution_runtime.os.geteuid", return_value=1000):
                with self.assertRaisesRegex(PermissionError, "root"):
                    linux_distribution_runtime._installation_root(None)


if __name__ == "__main__":
    unittest.main()
