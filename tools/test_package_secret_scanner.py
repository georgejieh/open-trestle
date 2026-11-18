"""Tests for the secret-scanner release package and development build."""

import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import package_secret_scanner

REPOSITORY = Path(__file__).resolve().parent.parent
SCANNER = package_secret_scanner.SCANNER_DIRECTORY
GUEST = package_secret_scanner.GUEST_DIRECTORY
PATCHED_PATH = "workers/secret-scanner/third_party/example"
PATCH_FILE = "workers/secret-scanner/third_party/example-v1.0.0.patch"
HELPER_INFO = (
    "helper: go1.26.11\n"
    f"\tpath\t{package_secret_scanner.HELPER_PACKAGE}\n"
    f"\tmod\t{package_secret_scanner.SCANNER_MODULE}\t(devel)\t\n"
    "\tdep\texample.org/runtime\tv1.2.3\th1:runtime\n"
    "\tbuild\t-trimpath=true\n\tbuild\tCGO_ENABLED=0\n"
    "\tbuild\tGOARCH=amd64\n\tbuild\tGOOS=linux\n"
)
GUEST_INFO = (
    f"path\t{package_secret_scanner.GUEST_PACKAGE}\n"
    f"mod\t{package_secret_scanner.GUEST_PACKAGE}\t(devel)\t\n"
    "dep\texample.org/patched\tv1.0.0\n"
    "=>\t../third_party/example\t(devel)\t\n"
    f"dep\t{package_secret_scanner.SCANNER_MODULE}\tv0.0.0\n"
    "=>\t../\t(devel)\t\n"
    "dep\texample.org/shared\tv0.1.0\th1:shared\n"
    "build\t-trimpath=true\nbuild\tCGO_ENABLED=0\n"
    "build\tGOARCH=wasm\nbuild\tGOOS=wasip1\n"
)


def _write(root: Path, relative: str, content: bytes) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def _license_fixture(root: Path) -> tuple[dict, Path]:
    """Create a repository with go.sum files, one patch and reviewed licenses."""
    _write(root, f"{SCANNER}/go.sum", (
        "example.org/patched v1.0.0 h1:upstream\n"
        "example.org/patched v1.0.0/go.mod h1:patched-mod\n"
        "example.org/runtime v1.2.3 h1:runtime\n"
        "example.org/runtime v1.2.3/go.mod h1:runtime-mod\n"
    ).encode())
    _write(root, f"{GUEST}/go.sum", (
        "example.org/shared v0.1.0 h1:shared\n"
        "example.org/shared v0.1.0/go.mod h1:shared-mod\n"
    ).encode())
    _write(root, PATCH_FILE, b"patch")
    license_root = root / "licenses"
    modules = []
    for module, version in (("example.org/patched", "v1.0.0"), ("example.org/runtime", "v1.2.3"), ("example.org/shared", "v0.1.0")):
        name = module.replace("/", "_") + "_" + version + "/LICENSE"
        _write(license_root, name, module.encode())
        entry = {
            "module": module, "version": version, "license": "MIT",
            "files": [{"file": name, "sha256": hashlib.sha256(module.encode()).hexdigest(), "upstream_path": "LICENSE"}],
        }
        if module == "example.org/patched":
            entry["patched_copies"] = [{
                "linked_by": GUEST, "path": PATCHED_PATH, "patch": PATCH_FILE,
                "patch_sha256": hashlib.sha256(b"patch").hexdigest(),
            }]
        modules.append(entry)
    _write(license_root, "MODULES.json", b"{}")
    return {"schema_version": 1, "modules": modules}, license_root


def _linked(root: Path, manifest: dict, license_root: Path, guest_info: str = GUEST_INFO) -> list[dict]:
    return package_secret_scanner.linked_modules(
        root, {SCANNER: HELPER_INFO, GUEST: guest_info}, manifest, license_root,
    )


class LinkedModulesTest(unittest.TestCase):
    def test_helper_and_guest_closure_records_sums_and_patched_copies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, license_root = _license_fixture(root)

            modules = _linked(root, manifest, license_root)

            self.assertEqual(modules, [
                {
                    "module": "example.org/patched", "version": "v1.0.0", "license": "MIT",
                    "linked_by": [GUEST],
                    "patched_copy": {
                        "path": PATCHED_PATH, "patch": PATCH_FILE,
                        "patch_sha256": hashlib.sha256(b"patch").hexdigest(),
                    },
                    "upstream_module_sum": "h1:upstream", "go_mod_sum": "h1:patched-mod",
                },
                {
                    "module": "example.org/runtime", "version": "v1.2.3", "license": "MIT",
                    "linked_by": [SCANNER], "module_sum": "h1:runtime", "go_mod_sum": "h1:runtime-mod",
                },
                {
                    "module": "example.org/shared", "version": "v0.1.0", "license": "MIT",
                    "linked_by": [GUEST], "module_sum": "h1:shared", "go_mod_sum": "h1:shared-mod",
                },
            ])

    def test_inventory_must_match_the_reviewed_licenses_exactly(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, license_root = _license_fixture(root)
            with self.assertRaisesRegex(ValueError, r"unreviewed \['example.org/missing@v1.0.0'\]"):
                _linked(root, manifest, license_root, GUEST_INFO + "dep\texample.org/missing\tv1.0.0\th1:x\n")
            without_shared = GUEST_INFO.replace("dep\texample.org/shared\tv0.1.0\th1:shared\n", "")
            with self.assertRaisesRegex(ValueError, r"unlinked \['example.org/shared@v0.1.0'\]"):
                _linked(root, manifest, license_root, without_shared)

    def test_replacements_must_be_reviewed_patched_copies(self):
        cases = {
            "other path": GUEST_INFO.replace("../third_party/example", "../third_party/other"),
            "versioned": GUEST_INFO.replace("=>\t../third_party/example\t(devel)", "=>\texample.org/fork\tv1.0.0\th1:fork"),
            "scanner elsewhere": GUEST_INFO.replace("=>\t../\t(devel)", "=>\t../../other\t(devel)"),
            "upstream release": GUEST_INFO.replace(
                "dep\texample.org/patched\tv1.0.0\n=>\t../third_party/example\t(devel)\t\n",
                "dep\texample.org/patched\tv1.0.0\th1:upstream\n",
            ),
        }
        for name, guest_info in cases.items():
            with self.subTest(case=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest, license_root = _license_fixture(root)
                with self.assertRaises(ValueError):
                    _linked(root, manifest, license_root, guest_info)

    def test_changed_patch_or_module_sum_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, license_root = _license_fixture(root)
            _write(root, PATCH_FILE, b"changed patch")
            with self.assertRaisesRegex(ValueError, "patch digest mismatch"):
                _linked(root, manifest, license_root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, license_root = _license_fixture(root)
            with self.assertRaisesRegex(ValueError, "module sum does not match go.sum"):
                _linked(root, manifest, license_root, GUEST_INFO.replace("h1:shared", "h1:other"))

    def test_license_files_are_verified_and_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, license_root = _license_fixture(root)
            _write(license_root, "unreviewed/LICENSE", b"extra")
            with self.assertRaisesRegex(ValueError, "unreviewed files"):
                package_secret_scanner.reviewed_licenses(manifest, license_root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, license_root = _license_fixture(root)
            (license_root / manifest["modules"][0]["files"][0]["file"]).write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "license digest mismatch"):
                package_secret_scanner.reviewed_licenses(manifest, license_root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, license_root = _license_fixture(root)
            manifest["modules"][0]["files"][0]["file"] = "../outside"
            with self.assertRaisesRegex(ValueError, "license file path is invalid"):
                package_secret_scanner.reviewed_licenses(manifest, license_root)

    def test_repository_license_inventory_and_patches_are_consistent(self):
        license_root = REPOSITORY / "THIRD_PARTY_LICENSES/secret-scanner"
        manifest = json.loads((license_root / "MODULES.json").read_text())
        reviewed = package_secret_scanner.reviewed_licenses(manifest, license_root)
        patched = {module for (module, _), entry in reviewed.items() if entry.get("patched_copies")}
        self.assertEqual(patched, {"github.com/betterleaks/betterleaks", "github.com/pkoukk/tiktoken-go"})
        for entry in reviewed.values():
            for copy in entry.get("patched_copies", []):
                with self.subTest(module=entry["module"]):
                    replacement = "../" + copy["path"].removeprefix("workers/secret-scanner/")
                    self.assertEqual(
                        package_secret_scanner._patched_copy(REPOSITORY, GUEST, replacement, entry)["patch"],
                        copy["patch"],
                    )


class BuildInfoTest(unittest.TestCase):
    def test_embedded_build_info_is_read_between_the_linker_markers(self):
        start, end = package_secret_scanner.MODINFO_START, package_secret_scanner.MODINFO_END
        program = b"\x00asm" + start + GUEST_INFO.encode() + end + b"data"
        self.assertEqual(package_secret_scanner.embedded_build_info(program), GUEST_INFO)
        for broken in (b"\x00asm", program + start + b"again" + end, b"\x00asm" + start + b"open"):
            with self.subTest(program=broken[:12]):
                with self.assertRaisesRegex(ValueError, "guest build metadata"):
                    package_secret_scanner.embedded_build_info(broken)

    def test_build_settings_and_toolchain_are_required(self):
        package_secret_scanner.verify_go_toolchain(HELPER_INFO, "scan helper")
        package_secret_scanner.verify_build_settings(HELPER_INFO, package_secret_scanner.HELPER_PACKAGE, ("linux", "amd64"))
        package_secret_scanner.verify_build_settings(GUEST_INFO, package_secret_scanner.GUEST_PACKAGE, ("wasip1", "wasm"))
        with self.assertRaisesRegex(ValueError, "scan helper Go toolchain metadata mismatch"):
            package_secret_scanner.verify_go_toolchain(HELPER_INFO.replace("go1.26.11", "go1.26.10"), "scan helper")
        for changed in (
            HELPER_INFO.replace("CGO_ENABLED=0", "CGO_ENABLED=1"),
            HELPER_INFO.replace("-trimpath=true", "-trimpath=false"),
            HELPER_INFO.replace("GOARCH=amd64", "GOARCH=arm64"),
            HELPER_INFO.replace("cmd/open-trestle-scan-helper", "cmd/other"),
        ):
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, "build metadata mismatch"):
                package_secret_scanner.verify_build_settings(changed, package_secret_scanner.HELPER_PACKAGE, ("linux", "amd64"))

    def test_target_parsing(self):
        self.assertEqual(package_secret_scanner.parse_target("windows/amd64"), ("windows", "amd64"))
        for value in ("windows", "windows/amd64/v2", "../amd64", "Windows/AMD64"):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "GOOS/GOARCH"):
                package_secret_scanner.parse_target(value)
        with patch("sys.stderr"), self.assertRaises(SystemExit):
            package_secret_scanner.main(["--target", "linux/amd64"])


class _FakeGo:
    """Stand in for go builds: binaries contain their link flags."""

    def __init__(self, test, *, missing_pin=None, wrong_toolchain=None, wrong_provenance=None, binding=None):
        self.test = test
        self.missing_pin = missing_pin
        self.wrong_toolchain = wrong_toolchain
        self.wrong_provenance = wrong_provenance
        self.binding = binding or {}
        self.builds = {}

    def run(self, arguments, **kwargs):
        if arguments[-1:] == ["build-info"]:
            name = Path(arguments[0]).name
            return json.dumps({
                "contract": "open-trestle/build-info", "schema_version": 1,
                "program": name, "source_bound": True, **self.binding,
                **({"source_revision": "c" * 40} if name == self.wrong_provenance else {}),
            })
        if arguments[:2] == ["go", "build"]:
            output = Path(arguments[arguments.index("-o") + 1])
            self.builds[output.name] = (arguments, kwargs["environment"])
            flags = next(item for item in arguments if item.startswith("-ldflags="))
            if output.stem == self.missing_pin:
                flags = flags.split(package_secret_scanner.HELPER_PIN)[0]
            output.write_bytes(flags.encode("ascii"))
            return ""
        self.test.assertEqual(arguments[:3], ["go", "version", "-m"])
        name = Path(arguments[-1]).name
        if name.startswith(package_secret_scanner.HELPER_NAME):
            return HELPER_INFO.replace("GOARCH=amd64\n\tbuild\tGOOS=linux", self.helper_target)
        version = "go1.26.10" if name == self.wrong_toolchain else "go1.26.11"
        return f"{name}: {version}\n"

    helper_target = "GOARCH=amd64\n\tbuild\tGOOS=linux"

    @staticmethod
    def build_helper(nondeterministic=False, unpinned=False):
        guest = (
            b"\x00asm" + package_secret_scanner.MODINFO_START + GUEST_INFO.encode()
            + package_secret_scanner.MODINFO_END
        )
        calls = []

        def build(_repository, output, target, _go_tmp):
            calls.append(target)
            output.mkdir(parents=True)
            guest_path = output / package_secret_scanner.GUEST_NAME
            guest_path.write_bytes(guest)
            pin = b"" if unpinned else hashlib.sha256(guest).hexdigest().encode()
            name = package_secret_scanner._executable_name(package_secret_scanner.HELPER_NAME, target[0])
            helper = output / name
            helper.write_bytes(b"helper" + pin + guest + (str(len(calls)).encode() if nondeterministic else b""))
            return helper, guest_path

        return build, calls


class ReleasePackageTest(unittest.TestCase):
    binding = {"source_revision": "a" * 40, "source_tree": "b" * 40}

    def _package(self, root, *, changed_source=False, nondeterministic=False, unpinned=False, **fake):
        go = _FakeGo(self, binding=self.binding, **fake)
        build_helper, calls = _FakeGo.build_helper(nondeterministic, unpinned)
        source_calls = []

        def capture(_root):
            source_calls.append(True)
            changed = changed_source and len(source_calls) > 1
            return {**self.binding, "verified_source": "changed" if changed else "stable"}

        go_mod = b"module example.org/test\n\ngo 1.25.0\ntoolchain go1.26.11\n"
        for relative in ("go.mod", f"{SCANNER}/go.mod", f"{GUEST}/go.mod"):
            _write(root, relative, go_mod)
        for relative in ("THIRD_PARTY_LICENSES/secret-scanner/MODULES.json", "tools/model_catalog.py", "LICENSE", "NOTICE"):
            _write(root, relative, b"{}")
        with patch.multiple(
            package_secret_scanner,
            release_input_digests=lambda _root: {},
            source_binding=capture,
            build_helper=build_helper,
            linked_modules=lambda *_args: [],
            validate_staging=lambda *_args: None,
            _run=go.run,
        ):
            package_secret_scanner.package(root, root / "staging")
        return go, calls

    def test_root_binaries_pin_the_helper_and_bind_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            go, calls = self._package(root)
            staging = root / "staging"
            helper = staging / package_secret_scanner.HELPER_PATH
            digest = hashlib.sha256(helper.read_bytes()).hexdigest()
            self.assertEqual(calls, [("linux", "amd64"), ("linux", "amd64")])
            self.assertEqual(stat.S_IMODE(helper.stat().st_mode), 0o555)
            self.assertEqual(set(go.builds), {"trestle", "trestled"})
            for name, (arguments, environment) in go.builds.items():
                with self.subTest(binary=name):
                    flags = next(item for item in arguments if item.startswith("-ldflags="))
                    self.assertEqual(
                        flags,
                        f"-ldflags=-s -w -buildid= -X {package_secret_scanner.HELPER_PIN}={digest}"
                        f" -X {package_secret_scanner.BUILDINFO_PACKAGE}.sourceRevision={'a' * 40}"
                        f" -X {package_secret_scanner.BUILDINFO_PACKAGE}.sourceTree={'b' * 40}",
                    )
                    self.assertEqual(arguments[:4], ["go", "build", "-trimpath", "-buildvcs=false"])
                    self.assertEqual(arguments[-1], f"./cmd/{name}")
                    self.assertEqual((environment["GOOS"], environment["GOARCH"], environment["CGO_ENABLED"]), ("linux", "amd64", "0"))
                    self.assertEqual(stat.S_IMODE((staging / name).stat().st_mode), 0o555)
            evidence = json.loads((staging / "release/secret-scanner-release.json").read_text())
            self.assertEqual(evidence["helper"]["sha256"], digest)
            self.assertEqual(evidence["root_client"]["helper_sha256"], digest)

    def test_helper_failures_are_refused(self):
        for options, message in (
            ({"nondeterministic": True}, "not deterministic"),
            ({"unpinned": True}, "does not embed and pin the built guest"),
            ({"changed_source": True}, "source changed during packaging"),
        ):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(ValueError, message):
                    self._package(Path(directory), **options)

    def test_each_root_binary_is_checked(self):
        for name in ("trestle", "trestled"):
            for options, message in (
                ({"missing_pin": name}, f"{name} does not contain the scan helper digest"),
                ({"wrong_toolchain": name}, f"{name} Go toolchain metadata mismatch"),
                ({"wrong_provenance": name}, "provenance mismatch"),
            ):
                with self.subTest(binary=name, options=options), tempfile.TemporaryDirectory() as directory:
                    with self.assertRaisesRegex(ValueError, message):
                        self._package(Path(directory), **options)


class DevelopmentBuildTest(unittest.TestCase):
    def test_development_build_pins_the_helper_for_another_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            go_mod = b"module example.org/test\n\ngo 1.25.0\ntoolchain go1.26.11\n"
            for relative in ("go.mod", f"{SCANNER}/go.mod", f"{GUEST}/go.mod"):
                _write(root, relative, go_mod)
            go = _FakeGo(self)
            go.helper_target = "GOARCH=amd64\n\tbuild\tGOOS=windows"
            build_helper, calls = _FakeGo.build_helper()
            output = root / "dev"
            moves = []
            replace = os.replace

            def recording_replace(source, destination):
                moves.append(Path(source))
                replace(source, destination)

            with patch.multiple(package_secret_scanner, build_helper=build_helper, _run=go.run), \
                    patch.object(package_secret_scanner.os, "replace", recording_replace):
                package_secret_scanner.build_development(root, output, ("windows", "amd64"))
            self.assertEqual(len(moves), 3)
            for source in moves:
                self.assertTrue(source.relative_to(root).parts[0].startswith(".open-trestle-development-"))
            self.assertFalse([path for path in root.iterdir() if path.name.startswith(".open-trestle-development-")])
            helper = output / "libexec/open-trestle/open-trestle-scan-helper.exe"
            digest = hashlib.sha256(helper.read_bytes()).hexdigest()
            self.assertEqual(calls, [("windows", "amd64")])
            self.assertEqual(
                {path.relative_to(output).as_posix() for path in output.rglob("*") if path.is_file()},
                {"bin/trestle.exe", "bin/trestled.exe", "libexec/open-trestle/open-trestle-scan-helper.exe"},
            )
            for name in ("trestle.exe", "trestled.exe"):
                with self.subTest(binary=name):
                    arguments, environment = go.builds[name]
                    flags = next(item for item in arguments if item.startswith("-ldflags="))
                    self.assertEqual(flags, f"-ldflags=-s -w -buildid= -X {package_secret_scanner.HELPER_PIN}={digest}")
                    self.assertEqual((environment["GOOS"], environment["GOARCH"]), ("windows", "amd64"))
                    if os.name != "nt":
                        self.assertEqual(stat.S_IMODE((output / "bin" / name).stat().st_mode), 0o555)

    def test_development_build_rejects_a_helper_for_another_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            go_mod = b"module example.org/test\n\ngo 1.25.0\ntoolchain go1.26.11\n"
            for relative in ("go.mod", f"{SCANNER}/go.mod", f"{GUEST}/go.mod"):
                _write(root, relative, go_mod)
            build_helper, _ = _FakeGo.build_helper()
            with patch.multiple(package_secret_scanner, build_helper=build_helper, _run=_FakeGo(self).run):
                with self.assertRaisesRegex(ValueError, "build metadata mismatch"):
                    package_secret_scanner.build_development(root, root / "dev", ("darwin", "arm64"))
            self.assertFalse((root / "dev").exists())


class PackageInventoryTest(unittest.TestCase):
    def _make_staging(self, root: Path) -> set[str]:
        files = {
            "ca-certificates.crt",
            "LICENSE",
            "NOTICE",
            "trestle",
            "trestled",
            package_secret_scanner.HELPER_PATH,
            "licenses/secret-scanner/MODULES.json",
            "licenses/secret-scanner/example-LICENSE",
            "release/secret-scanner-release.json",
            "release/secret-scanner.spdx.json",
        }
        for relative in files:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("artifact")
        (root / "data").mkdir()
        for relative in package_secret_scanner.EXECUTABLE_PATHS:
            (root / relative).chmod(0o555)
        return files

    def test_clean_staging_inventory_contains_only_runtime_material(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = self._make_staging(root)

            inventory = package_secret_scanner.validate_staging(root, expected)

            self.assertEqual(set(inventory), expected)

    def test_catalog_wrapper_is_the_only_admitted_script(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = self._make_staging(root)
            script = root / "scripts/model_catalog.py"
            script.parent.mkdir()
            script.write_bytes(Path(package_secret_scanner.__file__).with_name("model_catalog.py").read_bytes())
            script.chmod(0o444)
            expected.add("scripts/model_catalog.py")
            self.assertIn("scripts/model_catalog.py", package_secret_scanner.validate_staging(root, expected))
            script.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "script mode"):
                package_secret_scanner.validate_staging(root, expected)
            script.chmod(0o444)
            other = root / "scripts/other.py"
            other.write_text("private script")
            with self.assertRaises(ValueError):
                package_secret_scanner.validate_staging(root, expected | {"scripts/other.py"})

    def test_mode_correct_altered_or_stale_catalog_wrapper_is_rejected(self) -> None:
        source = Path(package_secret_scanner.__file__).with_name("model_catalog.py").read_bytes()
        stale = source.replace(b'            command.add_argument("--expected-current", required=True)\n', b"")
        self.assertNotEqual(stale, source)
        for name, body in (("altered", source + b"# altered fixture\n"), ("stale", stale)):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                expected = self._make_staging(root)
                script = root / "scripts/model_catalog.py"
                script.parent.mkdir()
                script.write_bytes(body)
                script.chmod(0o444)
                expected.add("scripts/model_catalog.py")

                with self.assertRaisesRegex(ValueError, "catalog script digest mismatch"):
                    package_secret_scanner.validate_staging(root, expected)

    def test_source_tests_private_references_and_build_tools_are_rejected(self):
        forbidden = (
            "libexec/open-trestle/open-trestle-scan-guest.wasm",
            "internal/adapter/adapter_test.go",
            "references/private-corpus.json",
            "tools/package_secret_scanner.py",
            "usr/bin/go",
        )
        for relative in forbidden:
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                expected = self._make_staging(root)
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("must not ship")
                with self.assertRaisesRegex(ValueError, "staging inventory mismatch"):
                    package_secret_scanner.validate_staging(root, expected)
                with self.assertRaisesRegex(ValueError, "source, test, private reference, or build tool"):
                    package_secret_scanner.validate_staging(root, expected | {relative})

    def test_scan_helper_must_be_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = self._make_staging(root)
            (root / package_secret_scanner.HELPER_PATH).chmod(0o755)

            with self.assertRaisesRegex(ValueError, "scanner executable mode"):
                package_secret_scanner.validate_staging(root, expected)


class ReleaseEvidenceTest(unittest.TestCase):
    @patch.object(Path, "read_bytes", side_effect=AssertionError("whole-file read"))
    def test_file_checksums_stream_sha1_and_sha256(self, _read):
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "artifact"
            artifact.write_bytes(b"scanner")

            sha1, sha256 = package_secret_scanner._file_checksums(artifact)

            self.assertEqual(sha1, hashlib.sha1(b"scanner").hexdigest())
            self.assertEqual(sha256, hashlib.sha256(b"scanner").hexdigest())

    def test_release_evidence_binds_helper_guest_modules_and_profile(self):
        helper = hashlib.sha256(b"helper").hexdigest()
        guest = hashlib.sha256(b"guest").hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, license_root = _license_fixture(root)
            modules = _linked(root, manifest, license_root)
        evidence, spdx = package_secret_scanner.encode_release_evidence(
            helper_sha1=hashlib.sha1(b"helper").hexdigest(), helper_sha256=helper,
            guest_sha256=guest, modules=modules,
        )
        document = json.loads(evidence)
        sbom = json.loads(spdx)

        self.assertEqual(document["build_profile"], "public_detect_run_re2_host_go1.26.11_wasip1_wasm_v1")
        self.assertEqual(document["helper"]["sha256"], helper)
        self.assertEqual(document["helper"]["path"], "libexec/open-trestle/open-trestle-scan-helper")
        self.assertEqual((document["helper"]["goos"], document["helper"]["goarch"]), ("linux", "amd64"))
        self.assertIn(f"-X main.expectedGuestSHA256={guest}", document["helper"]["build_flags"][-1])
        self.assertEqual(document["guest"]["sha256"], guest)
        self.assertEqual((document["guest"]["goos"], document["guest"]["goarch"]), ("wasip1", "wasm"))
        self.assertEqual(document["root_client"], {
            "go_toolchain": "go1.26.11", "helper_sha256": helper,
            "helper_pin": "github.com/georgejieh/open-trestle/internal/secretscan.expectedHelperSHA256",
        })
        self.assertEqual(document["modules"], modules)
        self.assertEqual(evidence, package_secret_scanner.encode_release_evidence(
            helper_sha1=hashlib.sha1(b"helper").hexdigest(), helper_sha256=helper,
            guest_sha256=guest, modules=modules,
        )[0])

        helper_file, = sbom["files"]
        self.assertEqual(helper_file["fileName"], "./libexec/open-trestle/open-trestle-scan-helper")
        self.assertEqual(helper_file["checksums"], [
            {"algorithm": "SHA1", "checksumValue": hashlib.sha1(b"helper").hexdigest()},
            {"algorithm": "SHA256", "checksumValue": helper},
        ])
        packages = {item["name"]: item for item in sbom["packages"]}
        self.assertEqual(set(packages), {
            "Open Trestle secret scanner", "Open Trestle scan guest",
            "example.org/patched", "example.org/runtime", "example.org/shared",
        })
        self.assertEqual(packages["Open Trestle scan guest"]["checksums"], [{"algorithm": "SHA256", "checksumValue": guest}])
        self.assertIn(hashlib.sha256(b"patch").hexdigest(), packages["example.org/patched"]["sourceInfo"])
        relationships = {
            (item["spdxElementId"], item["relationshipType"], item["relatedSpdxElement"])
            for item in sbom["relationships"]
        }
        guest_id = packages["Open Trestle scan guest"]["SPDXID"]
        self.assertEqual(relationships, {
            ("SPDXRef-Package-Secret-Scanner", "DISTRIBUTION_ARTIFACT", "SPDXRef-File-Scan-Helper"),
            ("SPDXRef-File-Scan-Helper", "CONTAINS", guest_id),
            ("SPDXRef-File-Scan-Helper", "STATIC_LINK", packages["example.org/runtime"]["SPDXID"]),
            (guest_id, "STATIC_LINK", packages["example.org/patched"]["SPDXID"]),
            (guest_id, "STATIC_LINK", packages["example.org/shared"]["SPDXID"]),
        })

    def test_invalid_digests_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "release digest is invalid"):
            package_secret_scanner.encode_release_evidence(
                helper_sha1="0" * 40, helper_sha256="0" * 64, guest_sha256="G" * 64, modules=[],
            )


class ReleaseContractTest(unittest.TestCase):
    def test_root_go_dependency_and_legal_closure_is_pinned(self):
        go_mod = (REPOSITORY / "go.mod").read_text()
        self.assertIn("\ngo 1.25.0\n", go_mod)
        self.assertIn("\ntoolchain go1.26.11\n", go_mod)
        for dependency in (
            "github.com/jackc/pgx/v5 v5.9.2",
            "golang.org/x/sync v0.22.0",
            "golang.org/x/text v0.41.0",
        ):
            self.assertIn(dependency, go_mod)
        self.assertNotIn("golang.org/x/crypto", go_mod)

        expected_licenses = {
            "aws-sdk-go-v2-1.45.1-Apache-2.0.txt",
            "aws-smithy-go-1.28.1-Apache-2.0.txt",
            "golang-x-sync-v0.22.0-BSD-3-Clause.txt",
            "golang-x-sys-v0.44.0-BSD-3-Clause.txt",
            "golang-x-text-v0.41.0-BSD-3-Clause.txt",
            "lucide-react-1.39.0-ISC.txt",
            "pgpassfile-v1.0.0-MIT.txt",
            "pgservicefile-MIT.txt",
            "pgx-v5.9.2-MIT.txt",
            "puddle-v2.2.2-MIT.txt",
            "react-family-19.2.8-MIT.txt",
            "wazero-v1.12.0-Apache-2.0.txt",
        }
        license_root = REPOSITORY / "THIRD_PARTY_LICENSES"
        self.assertEqual({path.name for path in license_root.iterdir() if path.is_file()}, expected_licenses)
        self.assertEqual(
            {path.name for path in license_root.iterdir() if path.is_dir()},
            {"secret-scanner", "syntax-analysis"},
        )
        expected_license_sha256 = {
            "golang-x-sync-v0.22.0-BSD-3-Clause.txt": "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad",
            "golang-x-text-v0.41.0-BSD-3-Clause.txt": "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad",
            "pgx-v5.9.2-MIT.txt": "467f95e074fe23079a5623ed652619682692041b8551da27e3c2ddb9659a1507",
        }
        for filename, expected in expected_license_sha256.items():
            self.assertEqual(hashlib.sha256((license_root / filename).read_bytes()).hexdigest(), expected)

        notice = (REPOSITORY / "NOTICE").read_text()
        self.assertIn("golang.org/x/sync and golang.org/x/text", notice)
        self.assertNotIn("golang.org/x/crypto", notice)
        self.assertNotIn("launcher", notice)

    def test_dockerfile_copies_the_root_owned_read_only_scan_helper(self):
        dockerfile = (REPOSITORY / "Dockerfile").read_text()
        self.assertIn(
            "COPY --chown=0:0 --chmod=0555 .container/libexec/open-trestle/open-trestle-scan-helper"
            " /usr/local/libexec/open-trestle/open-trestle-scan-helper\n",
            dockerfile,
        )
        self.assertEqual(dockerfile.count("libexec/open-trestle/"), 2)
        self.assertTrue(dockerfile.startswith("FROM scratch\n"))
        self.assertEqual([line for line in dockerfile.splitlines() if line.startswith("EXPOSE ")], ["EXPOSE 8741"])
        self.assertIn("USER 65532:65532", dockerfile)
        self.assertNotIn("RUN ", dockerfile)
        self.assertNotIn("ADD ", dockerfile)
        self.assertNotIn("/bin/sh", dockerfile)

    def test_ci_builds_and_runs_the_packaged_scan_helper(self):
        workflow = (REPOSITORY / ".github/workflows/verify-runtime.yml").read_text()
        self.assertIn("go-version-file: go.mod", workflow)
        self.assertIn("go-version-file: workers/secret-scanner/go.mod", workflow)
        for command in (
            "GOWORK=off GOTOOLCHAIN=go1.26.11 go mod verify",
            "GOWORK=off GOTOOLCHAIN=go1.26.11 go test -p=1 -timeout=30m ./...",
            "GOWORK=off GOTOOLCHAIN=go1.26.11 go test -race -p=1 -timeout=30m ./...",
            "GOWORK=off GOTOOLCHAIN=go1.26.11 go vet ./...",
            "GOWORK=off GOTOOLCHAIN=go1.26.11 CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -run='^$' -exec=true ./...",
            "GOWORK=off GOTOOLCHAIN=go1.26.11 CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go test -run='^$' -exec=true ./...",
            "GOWORK=off GOTOOLCHAIN=go1.26.11 CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go test -run='^$' -exec=true ./...",
            "python3 tools/package_secret_scanner.py --output .container",
            "python3 tools/package_secret_scanner.py --verify .container",
            "umask 022",
            "python3 tools/local_alpha_system.py",
            "--skip-browser",
            "--browser-script web/scripts/daemon-visual-check.mjs",
            'receipt["browser"]["status"]=="passed"',
            "docker run --rm --network=none --read-only --cap-drop=ALL",
            "--security-opt=no-new-privileges=true",
            "--tmpfs /scan-cache:rw,nosuid,nodev,size=256m,mode=0700,uid=65532,gid=65532",
            "--workdir /scan-cache",
            "--entrypoint /usr/local/libexec/open-trestle/open-trestle-scan-helper",
            'test ! -s "$RUNNER_TEMP/scanner-stderr"',
            'doc["build_profile"]=="public_detect_run_re2_host_go1.26.11_wasip1_wasm_v1"',
            "-run='^(TestScanHelper|TestRemoteReviewScansThroughTheScanHelper)' ./internal/secretscan/ ./cmd/trestle/",
        ):
            with self.subTest(command=command):
                self.assertIn(command, workflow)
        for retired in ("zig", "Zig", "open-trestle-secret-scanner"):
            self.assertNotIn(retired, workflow)


class SourceProvenanceTest(unittest.TestCase):
    def test_source_binding_uses_verified_state_not_caller_revision(self):
        state = SimpleNamespace(
            revision="a" * 40, tree_identity="b" * 40, clean=True,
            git_authority_sha256="authority", committed_tree_sha256="committed",
            live_tracked_tree_sha256="live", index_sha256="index",
            index_flags_sha256="flags", status_sha256="status",
        )
        with patch.object(package_secret_scanner, "capture_source_state", return_value=state):
            binding = package_secret_scanner.source_binding(Path("checkout"))
        self.assertEqual(binding["source_revision"], "a" * 40)
        self.assertEqual(binding["source_tree"], "b" * 40)
        state.clean = False
        with patch.object(package_secret_scanner, "capture_source_state", return_value=state):
            with self.assertRaisesRegex(ValueError, "clean source"):
                package_secret_scanner.source_binding(Path("checkout"))

    def test_source_capture_failure_is_not_accepted(self):
        with patch.object(package_secret_scanner, "capture_source_state", side_effect=RuntimeError("dirty")):
            with self.assertRaisesRegex(ValueError, "clean source"):
                package_secret_scanner.source_binding(Path("checkout"))

    def test_root_binary_document_matches_both_program_and_source(self):
        binding = {"source_revision": "a" * 40, "source_tree": "b" * 40}
        valid = {
            "contract": "open-trestle/build-info", "schema_version": 1,
            "program": "trestle", "source_bound": True, **binding,
        }
        package_secret_scanner.verify_root_provenance(json.dumps(valid), "trestle", binding)
        for changed in (
            {**valid, "program": "trestled"},
            {**valid, "source_revision": "c" * 40},
            {**valid, "source_tree": "d" * 40},
            {**valid, "source_bound": False},
            {**valid, "schema_version": True},
            {**valid, "extra": "unexpected"},
        ):
            with self.subTest(changed=changed):
                with self.assertRaisesRegex(ValueError, "provenance mismatch"):
                    package_secret_scanner.verify_root_provenance(json.dumps(changed), "trestle", binding)
        with self.assertRaisesRegex(ValueError, "provenance mismatch"):
            package_secret_scanner.verify_root_provenance("not-json", "trestle", binding)


if __name__ == "__main__":
    unittest.main()
