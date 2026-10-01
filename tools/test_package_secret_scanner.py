"""Tests for the isolated secret-scanner release package."""

import hashlib
import json
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import package_secret_scanner


class LinkedLicenseTest(unittest.TestCase):
    def test_exact_binary_module_closure_is_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            license_file = root / "example-LICENSE"
            license_file.write_text("license text")
            manifest = {
                "schema_version": 1,
                "modules": [{
                    "module": "example.org/runtime",
                    "version": "v1.2.3",
                    "license": "MIT",
                    "files": [{
                        "file": license_file.name,
                        "sha256": hashlib.sha256(b"license text").hexdigest(),
                        "upstream_path": "LICENSE",
                    }],
                }],
            }
            build_info = "\tdep\texample.org/runtime\tv1.2.3\th1:sum\n"

            modules = package_secret_scanner.verify_linked_licenses(
                build_info, manifest, root
            )

            self.assertEqual(modules[0]["module_sum"], "h1:sum")
            with self.assertRaisesRegex(ValueError, "linked module inventory mismatch"):
                package_secret_scanner.verify_linked_licenses(
                    build_info + "\tdep\texample.org/missing\tv1.0.0\th1:other\n",
                    manifest,
                    root,
                )

    def test_license_paths_cannot_escape_the_reviewed_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root.parent / "outside-license"
            outside.write_text("private")
            manifest = {
                "schema_version": 1,
                "modules": [{
                    "module": "example.org/runtime",
                    "version": "v1.2.3",
                    "license": "MIT",
                    "files": [{
                        "file": "../outside-license",
                        "sha256": hashlib.sha256(b"private").hexdigest(),
                        "upstream_path": "LICENSE",
                    }],
                }],
            }
            try:
                with self.assertRaisesRegex(ValueError, "license file path is invalid"):
                    package_secret_scanner.verify_linked_licenses(
                        "\tdep\texample.org/runtime\tv1.2.3\th1:sum\n",
                        manifest,
                        root,
                    )
            finally:
                outside.unlink(missing_ok=True)

    def test_root_build_metadata_uses_the_pinned_toolchain(self):
        package_secret_scanner.verify_root_build_info("trestled: go1.26.8\n")

        with self.assertRaisesRegex(ValueError, "root Go toolchain metadata mismatch"):
            package_secret_scanner.verify_root_build_info("trestled: go1.26.7\n")

    def test_worker_build_metadata_is_closed(self):
        valid = """worker: go1.26.8
\tbuild\t-trimpath=true
\tbuild\tCGO_ENABLED=0
\tbuild\tGOARCH=amd64
\tbuild\tGOOS=linux
"""
        package_secret_scanner.verify_worker_build_info(valid)
        for changed in (
            valid.replace("go1.26.8", "go1.26.7"),
            valid.replace("CGO_ENABLED=0", "CGO_ENABLED=1"),
            valid.replace("GOARCH=amd64", "GOARCH=arm64"),
        ):
            with self.assertRaisesRegex(ValueError, "worker .* metadata mismatch"):
                package_secret_scanner.verify_worker_build_info(changed)

    def test_missing_or_changed_license_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "LICENSE").write_text("changed")
            manifest = {
                "schema_version": 1,
                "modules": [{
                    "module": "example.org/runtime",
                    "version": "v1.2.3",
                    "license": "MIT",
                    "files": [{
                        "file": "LICENSE",
                        "sha256": "0" * 64,
                        "upstream_path": "LICENSE",
                    }],
                }],
            }

            with self.assertRaisesRegex(ValueError, "license digest mismatch"):
                package_secret_scanner.verify_linked_licenses(
                    "\tdep\texample.org/runtime\tv1.2.3\th1:sum\n",
                    manifest,
                    root,
                )


class PackageInventoryTest(unittest.TestCase):
    def _make_staging(self, root: Path) -> set[str]:
        files = {
            "ca-certificates.crt",
            "LICENSE",
            "NOTICE",
            "trestle",
            "trestled",
            "libexec/open-trestle/open-trestle-secret-scanner",
            "libexec/open-trestle/open-trestle-secret-scanner-worker",
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
            self.assertTrue(all(not path.endswith((".go", ".c", ".py")) for path in inventory))

    def test_source_tests_private_references_and_build_tools_are_rejected(self):
        forbidden = (
            "workers/secret-scanner/launcher/launcher.c",
            "internal/adapter/adapter_test.go",
            "references/private-corpus.json",
            "tools/package_secret_scanner.py",
            "usr/bin/go",
            "usr/bin/zig",
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

    def test_scanner_executables_must_be_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = self._make_staging(root)
            scanner = root / "libexec/open-trestle/open-trestle-secret-scanner"
            scanner.chmod(0o755)

            with self.assertRaisesRegex(ValueError, "scanner executable mode"):
                package_secret_scanner.validate_staging(root, expected)


class LauncherToolchainTest(unittest.TestCase):
    def test_launcher_invocation_uses_only_the_pinned_zig_musl_toolchain(self):
        command = package_secret_scanner.launcher_build_command(
            Path("/verified-toolchain/zig"), Path("/output/launcher")
        )

        self.assertEqual(
            command,
            [
                "/verified-toolchain/zig",
                "cc",
                "-target",
                "x86_64-linux-musl",
                "-DOPEN_TRESTLE_PRODUCTION_BUILD=1",
                "-std=c17",
                "-O2",
                "-pipe",
                "-fPIE",
                "-fstack-protector-strong",
                "-D_FORTIFY_SOURCE=3",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-Wformat=2",
                "-Wconversion",
                "-Wshadow",
                "-Wstrict-prototypes",
                "-static",
                "-pie",
                "-s",
                "-Wl,-z,relro,-z,now,-z,noexecstack,--build-id=none",
                "-o",
                "/output/launcher",
                "launcher.c",
            ],
        )
        self.assertNotIn("gcc", " ".join(command).lower())
        self.assertNotIn("glibc", " ".join(command).lower())

    @patch("package_secret_scanner._run")
    def test_launcher_build_environment_has_no_host_path_or_compiler(self, run):
        repository = Path("/repository")
        output = Path("/output/launcher")
        toolchain = Path("/verified-toolchain")
        cache = Path("/isolated-cache")

        package_secret_scanner._build_launcher(
            repository, output, toolchain, cache
        )

        arguments, = run.call_args.args
        self.assertEqual(arguments[0], "/verified-toolchain/zig")
        self.assertNotIn("gcc", " ".join(arguments).lower())
        self.assertEqual(
            run.call_args.kwargs["environment"],
            {
                "LC_ALL": "C",
                "SOURCE_DATE_EPOCH": "0",
                "ZIG_GLOBAL_CACHE_DIR": "/isolated-cache/global",
                "ZIG_LOCAL_CACHE_DIR": "/isolated-cache/local",
            },
        )
        self.assertNotIn("PATH", run.call_args.kwargs["environment"])

    def test_toolchain_manifest_binds_the_complete_archive_and_extracted_tree(self):
        repository = Path(__file__).resolve().parent.parent

        manifest, manifest_sha256 = package_secret_scanner._launcher_toolchain_manifest(
            repository
        )
        components = package_secret_scanner.verify_launcher_licenses(
            repository, manifest
        )

        self.assertRegex(manifest_sha256, r"^[0-9a-f]{64}$")
        self.assertEqual(manifest["builder_version"], "0.14.1")
        self.assertEqual(manifest["target"], "x86_64-linux-musl")
        self.assertEqual(
            manifest["archive"],
            {
                "root": "zig-x86_64-linux-0.14.1",
                "sha256": "24aeeec8af16c381934a6cd7d95c807a8cb2cf7df9fa40d359aa884195c4716c",
                "size": 49086504,
                "url": "https://ziglang.org/download/0.14.1/zig-x86_64-linux-0.14.1.tar.xz",
            },
        )
        self.assertEqual(
            manifest["extracted_tree"],
            {
                "bytes": 311138938,
                "regular_files": 14673,
                "sha256": "58e5c7d8fd7b4c2940613201bdae6685fb1f70f879669db913c118cb20bb537a",
            },
        )
        self.assertEqual(
            [(item["name"], item["version"], item["license"]) for item in components],
            [("Zig compiler-rt", "0.14.1", "MIT"), ("musl", "1.2.5", "MIT")],
        )
        self.assertEqual(
            manifest["input_closure"]["build_headers"][0]["license"],
            "GPL-2.0 WITH Linux-syscall-note",
        )

    def test_launcher_elf_verifier_rejects_truncated_or_dynamic_binaries(self):
        with tempfile.TemporaryDirectory() as directory:
            truncated = Path(directory) / "launcher"
            truncated.write_bytes(b"\x7fELF")
            with self.assertRaisesRegex(ValueError, "ELF header is truncated"):
                package_secret_scanner.verify_static_pie_launcher(truncated)
        if Path("/bin/true").is_file():
            with self.assertRaisesRegex(ValueError, "dynamic interpreter"):
                package_secret_scanner.verify_static_pie_launcher(Path("/bin/true"))

    def test_bad_cached_toolchain_is_rejected_without_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "zig.tar.xz"
            archive.write_bytes(b"not the pinned toolchain")
            expected = {
                "size": 49086504,
                "sha256": "24aeeec8af16c381934a6cd7d95c807a8cb2cf7df9fa40d359aa884195c4716c",
            }

            with self.assertRaisesRegex(ValueError, "toolchain archive identity mismatch"):
                package_secret_scanner._verify_toolchain_archive(archive, expected)


class ReleaseEvidenceTest(unittest.TestCase):
    @patch.object(Path, "read_bytes", side_effect=AssertionError("whole-file read"))
    def test_file_checksums_stream_sha1_and_sha256(self, _read):
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "artifact"
            artifact.write_bytes(b"scanner")

            sha1, sha256 = package_secret_scanner._file_checksums(artifact)

            self.assertEqual(sha1, hashlib.sha1(b"scanner").hexdigest())
            self.assertEqual(sha256, hashlib.sha256(b"scanner").hexdigest())

    def test_release_evidence_binds_both_binaries_and_profile(self):
        launcher = hashlib.sha256(b"launcher").hexdigest()
        worker = hashlib.sha256(b"worker").hexdigest()
        modules = [{
            "module": "example.org/runtime",
            "version": "v1.2.3",
            "module_sum": "h1:module",
            "go_mod_sum": "h1:gomod",
            "license": "MIT",
        }]

        repository = Path(__file__).resolve().parent.parent
        toolchain = json.loads(
            (repository / "workers/secret-scanner/launcher/toolchain-v1.json").read_text()
        )
        runtime_components = package_secret_scanner.verify_launcher_licenses(
            repository, toolchain
        )
        evidence, spdx = package_secret_scanner.encode_release_evidence(
            launcher_sha1=hashlib.sha1(b"launcher").hexdigest(),
            launcher_sha256=launcher,
            worker_sha1=hashlib.sha1(b"worker").hexdigest(),
            worker_sha256=worker,
            launcher_source_sha256="c" * 64,
            launcher_build_contract_sha256="e" * 64,
            launcher_toolchain_manifest_sha256="f" * 64,
            launcher_toolchain_manifest=toolchain,
            launcher_runtime_components=runtime_components,
            modules=modules,
        )
        document = json.loads(evidence)
        sbom = json.loads(spdx)

        self.assertEqual(document["launcher"]["sha256"], launcher)
        self.assertEqual(document["worker"]["sha256"], worker)
        self.assertEqual(document["worker"]["go_toolchain"], "go1.26.8")
        self.assertEqual(document["root_client"]["go_toolchain"], "go1.26.8")
        self.assertEqual(
            document["build_profile"],
            "public_detect_run_re2_purego_go1.26.8_linux_amd64_v1",
        )
        self.assertEqual(
            {item["name"] for item in sbom["packages"]},
            {
                "Open Trestle secret scanner",
                "Zig launcher toolchain",
                "Zig compiler-rt",
                "musl",
                "Linux UAPI headers bundled in Zig 0.14.1",
                "example.org/runtime",
            },
        )
        self.assertEqual(document["launcher"]["builder"], "zig")
        self.assertEqual(document["launcher"]["builder_version"], "0.14.1")
        self.assertEqual(document["launcher"]["target"], "x86_64-linux-musl")
        self.assertEqual(
            document["launcher"]["build_environment"],
            {
                "base_environment": "empty",
                "LC_ALL": "C",
                "SOURCE_DATE_EPOCH": "0",
                "cache_policy": "fresh isolated global and local caches for each build",
            },
        )
        self.assertEqual(
            document["launcher"]["toolchain_archive"]["sha256"],
            "24aeeec8af16c381934a6cd7d95c807a8cb2cf7df9fa40d359aa884195c4716c",
        )
        self.assertEqual(
            document["launcher"]["toolchain_extracted_tree"]["sha256"],
            "58e5c7d8fd7b4c2940613201bdae6685fb1f70f879669db913c118cb20bb537a",
        )
        self.assertNotIn("gcc", evidence.decode().lower())
        self.assertNotIn("glibc", evidence.decode().lower())
        launcher_file = next(
            item for item in sbom["files"]
            if item["SPDXID"] == "SPDXRef-File-Launcher"
        )
        self.assertEqual(launcher_file["licenseConcluded"], "Apache-2.0 AND MIT")
        self.assertEqual(launcher_file["licenseInfoInFiles"], ["NOASSERTION"])
        worker_file = next(
            item for item in sbom["files"]
            if item["SPDXID"] == "SPDXRef-File-Worker"
        )
        self.assertEqual(worker_file["licenseConcluded"], "NOASSERTION")
        self.assertEqual(worker_file["licenseInfoInFiles"], ["NOASSERTION"])
        self.assertEqual(
            launcher_file["checksums"],
            [
                {
                    "algorithm": "SHA1",
                    "checksumValue": hashlib.sha1(b"launcher").hexdigest(),
                },
                {"algorithm": "SHA256", "checksumValue": launcher},
            ],
        )
        self.assertEqual(
            worker_file["checksums"],
            [
                {
                    "algorithm": "SHA1",
                    "checksumValue": hashlib.sha1(b"worker").hexdigest(),
                },
                {"algorithm": "SHA256", "checksumValue": worker},
            ],
        )
        root_artifacts = [
            item for item in sbom["relationships"]
            if item["spdxElementId"] == "SPDXRef-Package-Secret-Scanner"
            and item["relationshipType"] == "DISTRIBUTION_ARTIFACT"
        ]
        self.assertEqual(len(root_artifacts), 2)
        self.assertFalse(
            any(
                item["spdxElementId"] == "SPDXRef-Package-Secret-Scanner"
                and item["relationshipType"] == "CONTAINS"
                for item in sbom["relationships"]
            )
        )
        static_links = [
            item for item in sbom["relationships"]
            if item["spdxElementId"] == "SPDXRef-File-Launcher"
            and item["relationshipType"] == "STATIC_LINK"
        ]
        self.assertEqual(len(static_links), 2)
        self.assertIn(launcher, spdx.decode())
        self.assertIn(worker, spdx.decode())


class ReleaseContractTest(unittest.TestCase):
    def test_root_go_dependency_and_legal_closure_is_pinned(self):
        repository_root = Path(__file__).resolve().parent.parent
        go_mod = (repository_root / "go.mod").read_text()
        self.assertIn("\ngo 1.25.0\n", go_mod)
        self.assertIn("\ntoolchain go1.26.8\n", go_mod)
        for dependency in (
            "github.com/jackc/pgx/v5 v5.9.2",
            "golang.org/x/sync v0.21.0",
            "golang.org/x/text v0.39.0",
        ):
            self.assertIn(dependency, go_mod)
        self.assertNotIn("golang.org/x/crypto", go_mod)

        expected_licenses = {
            "aws-sdk-go-v2-1.45.1-Apache-2.0.txt",
            "aws-smithy-go-1.28.1-Apache-2.0.txt",
            "golang-x-sync-v0.21.0-BSD-3-Clause.txt",
            "golang-x-text-v0.39.0-BSD-3-Clause.txt",
            "lucide-react-1.39.0-ISC.txt",
            "pgpassfile-v1.0.0-MIT.txt",
            "pgservicefile-MIT.txt",
            "pgx-v5.9.2-MIT.txt",
            "puddle-v2.2.2-MIT.txt",
            "react-family-19.2.8-MIT.txt",
        }
        license_root = repository_root / "THIRD_PARTY_LICENSES"
        self.assertEqual(
            {path.name for path in license_root.iterdir() if path.is_file()},
            expected_licenses,
        )
        expected_license_sha256 = {
            "golang-x-sync-v0.21.0-BSD-3-Clause.txt": "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad",
            "golang-x-text-v0.39.0-BSD-3-Clause.txt": "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad",
            "pgx-v5.9.2-MIT.txt": "467f95e074fe23079a5623ed652619682692041b8551da27e3c2ddb9659a1507",
        }
        for filename, expected in expected_license_sha256.items():
            self.assertEqual(
                hashlib.sha256((license_root / filename).read_bytes()).hexdigest(),
                expected,
            )

        notice = (repository_root / "NOTICE").read_text()
        self.assertIn("golang.org/x/sync and golang.org/x/text", notice)
        self.assertNotIn("golang.org/x/crypto", notice)

    def test_dockerfile_copies_root_owned_read_only_libexec_binaries(self):
        dockerfile = (Path(__file__).resolve().parent.parent / "Dockerfile").read_text()
        for binary in (
            "open-trestle-secret-scanner",
            "open-trestle-secret-scanner-worker",
        ):
            self.assertIn(
                "COPY --chown=0:0 --chmod=0555 .container/libexec/open-trestle/"
                + binary,
                dockerfile,
            )
        self.assertTrue(dockerfile.startswith("FROM scratch\n"))
        self.assertEqual(
            [line for line in dockerfile.splitlines() if line.startswith("EXPOSE ")],
            ["EXPOSE 8080"],
        )
        self.assertIn("USER 65532:65532", dockerfile)
        self.assertNotIn("RUN ", dockerfile)
        self.assertNotIn("ADD ", dockerfile)
        self.assertNotIn("/bin/sh", dockerfile)

    def test_ci_uses_both_pinned_go_modules_and_package_verifier(self):
        repository_root = Path(__file__).resolve().parent.parent
        workflow = (
            repository_root / ".github/workflows/verify-runtime.yml"
        ).read_text()
        self.assertIn("go-version-file: go.mod", workflow)
        self.assertIn("go-version-file: workers/secret-scanner/go.mod", workflow)
        for command in (
            "GOWORK=off GOTOOLCHAIN=go1.26.8 go mod verify",
            "GOWORK=off GOTOOLCHAIN=go1.26.8 go test -p=1 -timeout=30m ./...",
            "GOWORK=off GOTOOLCHAIN=go1.26.8 go test -race -p=1 -timeout=30m ./...",
            "GOWORK=off GOTOOLCHAIN=go1.26.8 go vet ./...",
            "GOWORK=off GOTOOLCHAIN=go1.26.8 CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -run='^$' -exec=true ./...",
            "GOWORK=off GOTOOLCHAIN=go1.26.8 CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go test -run='^$' -exec=true ./...",
            "GOWORK=off GOTOOLCHAIN=go1.26.8 CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go test -run='^$' -exec=true ./...",
        ):
            self.assertIn(command, workflow)
        self.assertIn("GOWORK=off GOTOOLCHAIN=go1.26.8 go test -timeout=15m ./...", workflow)
        self.assertIn("GOWORK=off GOTOOLCHAIN=go1.26.8 go test -race", workflow)
        self.assertIn("python3 tools/package_secret_scanner.py", workflow)
        self.assertIn("python3 tools/package_secret_scanner.py --verify .container", workflow)
        self.assertIn("umask 022", workflow)
        self.assertIn("python3 tools/local_alpha_system.py", workflow)
        self.assertIn("--skip-browser", workflow)
        self.assertIn("open-trestle-local-alpha-system/receipt.json", workflow)
        self.assertIn(
            "name: Provision pinned Zig musl builder and build deterministic release staging",
            workflow,
        )
        packager = (repository_root / "tools/package_secret_scanner.py").read_text()
        build_contract = (
            repository_root / "workers/secret-scanner/launcher/build.mk"
        ).read_text()
        self.assertIn(
            "24aeeec8af16c381934a6cd7d95c807a8cb2cf7df9fa40d359aa884195c4716c",
            packager,
        )
        self.assertIn('"x86_64-linux-musl"', packager)
        self.assertNotIn("/usr/bin/gcc", packager)
        self.assertNotIn("/usr/bin/gcc", build_contract)
        for required in (
            "docker run --rm --network=none --read-only --cap-drop=ALL",
            "--security-opt=no-new-privileges=true",
            "--entrypoint /usr/local/libexec/open-trestle/open-trestle-secret-scanner",
            'test ! -s "$RUNNER_TEMP/scanner-stderr"',
        ):
            self.assertIn(required, workflow)


if __name__ == "__main__":
    unittest.main()
