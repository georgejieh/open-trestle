"""Tests for deterministic local release evidence."""

import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

import release_evidence

class ArtifactCollectionTest(unittest.TestCase):
    def test_files_and_directory_members_are_sorted_and_content_addressed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "trestle").write_bytes(b"binary")
            (root / "dist" / "assets").mkdir(parents=True)
            (root / "dist" / "index.html").write_text("<main>Open Trestle</main>\n")
            (root / "dist" / "assets" / "app.js").write_text("export {};\n")

            artifacts = release_evidence.collect_artifacts(
                ("web=dist", "trestle=trestle"), root
            )

            self.assertEqual(
                [artifact.name for artifact in artifacts],
                ["trestle", "web/assets/app.js", "web/index.html"],
            )
            self.assertEqual(
                artifacts[0].sha256, hashlib.sha256(b"binary").hexdigest()
            )
            self.assertEqual(artifacts[0].size, 6)
            self.assertEqual(artifacts[1].size, len(b"export {};\n"))

    def test_symlinked_artifact_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.write_bytes(b"secret")
            (root / "release").symlink_to(target)

            with self.assertRaisesRegex(
                ValueError, "artifact path must not be a symlink"
            ):
                release_evidence.collect_artifacts(("trestle=release",), root)

    def test_artifact_source_must_remain_inside_root(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / "project"
            root.mkdir()
            (parent / "outside").write_bytes(b"private")

            with self.assertRaisesRegex(ValueError, "artifact path.*escapes root"):
                release_evidence.collect_artifacts(("trestle=../outside",), root)

    def test_duplicate_logical_name_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "first").write_bytes(b"first")
            (root / "second").write_bytes(b"second")

            with self.assertRaisesRegex(ValueError, "duplicate artifact name: trestle"):
                release_evidence.collect_artifacts(
                    ("trestle=first", "trestle=second"), root
                )

    def test_logical_names_are_relative_portable_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "artifact").write_bytes(b"release")
            for name in ("../escape", "/absolute", "windows\\path", "two//parts"):
                with self.subTest(name=name):
                    with self.assertRaisesRegex(ValueError, "invalid artifact name"):
                        release_evidence.collect_artifacts(
                            (f"{name}=artifact",), root
                        )

    def test_directory_member_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "dist").mkdir()
            target = root / "private"
            target.write_bytes(b"private")
            (root / "dist" / "linked").symlink_to(target)

            with self.assertRaisesRegex(
                ValueError, "artifact path must not be a symlink"
            ):
                release_evidence.collect_artifacts(("web=dist",), root)

    def test_symlinked_parent_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "private"
            target.mkdir()
            (target / "artifact").write_bytes(b"private")
            (root / "linked").symlink_to(target, target_is_directory=True)

            with self.assertRaisesRegex(
                ValueError, "artifact path must not be a symlink"
            ):
                release_evidence.collect_artifacts(("trestle=linked/artifact",), root)

    def test_empty_file_and_directory_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "empty-file").touch()
            (root / "empty-directory").mkdir()
            for entry in ("file=empty-file", "directory=empty-directory"):
                with self.subTest(entry=entry):
                    with self.assertRaisesRegex(
                        ValueError, "artifact must not be empty"
                    ):
                        release_evidence.collect_artifacts((entry,), root)

    def test_credential_file_patterns_are_rejected(self):
        for relative in (
            ".env.production",
            ".npmrc",
            ".netrc",
            ".pypirc",
            "id_rsa",
            ".aws/credentials",
            ".ssh/id_ed25519",
            "References/plan.md",
        ):
            with (
                self.subTest(relative=relative),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                path = root / "dist" / relative
                path.parent.mkdir(parents=True)
                path.write_text("TOKEN=secret\n")

                with self.assertRaisesRegex(
                    ValueError, "sensitive artifact path is forbidden"
                ):
                    release_evidence.collect_artifacts(("web=dist",), root)

    def test_repository_parent_named_references_is_not_treated_as_an_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "References" / "project"
            root.mkdir(parents=True)
            (root / "artifact").write_bytes(b"release")

            artifacts = release_evidence.collect_artifacts(("trestle=artifact",), root)

            self.assertEqual([artifact.name for artifact in artifacts], ["trestle"])

    @patch.object(Path, "read_bytes", side_effect=AssertionError("whole-file read"))
    def test_artifacts_are_hashed_without_loading_whole_file(self, _read):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "artifact").write_bytes(b"release")

            artifacts = release_evidence.collect_artifacts(("trestle=artifact",), root)

            self.assertEqual(artifacts[0].size, 7)

    def test_artifact_read_failure_reports_only_logical_name(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "artifact").write_bytes(b"release")

            with patch.object(
                Path, "open", side_effect=PermissionError("/private/path")
            ):
                with self.assertRaisesRegex(
                    ValueError, "artifact could not be read: trestle"
                ) as raised:
                    release_evidence.collect_artifacts(("trestle=artifact",), root)
            self.assertNotIn("/private/path", str(raised.exception))

    def test_artifact_change_during_hashing_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "artifact"
            path.write_bytes(b"release")
            original_open = Path.open

            class ChangingReader:
                def __init__(self, handle):
                    self.handle = handle
                    self.changed = False

                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    return self.handle.__exit__(*args)

                def fileno(self):
                    return self.handle.fileno()

                def read(self, size):
                    chunk = self.handle.read(size)
                    if not self.changed:
                        self.changed = True
                        with original_open(path, "ab") as writer:
                            writer.write(b"!")
                    return chunk

            def changing_open(candidate, *args, **kwargs):
                handle = original_open(candidate, *args, **kwargs)
                if candidate == path and args and args[0] == "rb":
                    return ChangingReader(handle)
                return handle

            with patch.object(Path, "open", new=changing_open):
                with self.assertRaisesRegex(ValueError, "artifact changed while read"):
                    release_evidence.collect_artifacts(("trestle=artifact",), root)

    @patch("release_evidence.os.walk", side_effect=PermissionError("/private/path"))
    def test_directory_walk_failure_reports_only_logical_name(self, _walk):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "dist").mkdir()

            with self.assertRaisesRegex(
                ValueError, "artifact directory could not be read: web"
            ) as raised:
                release_evidence.collect_artifacts(("web=dist",), root)
            self.assertNotIn("/private/path", str(raised.exception))

    def test_checksum_output_is_stable_and_sha256sum_compatible(self):
        artifacts = (
            release_evidence.Artifact("b/file", "b" * 64, 2),
            release_evidence.Artifact("a", "a" * 64, 1),
        )

        encoded = release_evidence.encode_checksums(artifacts)

        self.assertEqual(
            encoded,
            (("a" * 64) + "  a\n" + ("b" * 64) + "  b/file\n").encode(),
        )

    def test_spdx_inventory_is_deterministic_and_exact(self):
        artifacts = (
            release_evidence.Artifact("trestle", "a" * 64, 100),
            release_evidence.Artifact("web/index.html", "b" * 64, 25),
        )

        components = (
            release_evidence.Component("npm", "react", "19.2.8", "MIT"),
            release_evidence.Component("gomod", "example.org/module", "v1.0.0"),
        )
        first = release_evidence.encode_spdx(
            artifacts,
            components=components,
            version="0.1.0",
            revision="1" * 40,
            created="2026-09-15T00:00:00Z",
        )
        second = release_evidence.encode_spdx(
            tuple(reversed(artifacts)),
            components=tuple(reversed(components)),
            version="0.1.0",
            revision="1" * 40,
            created="2026-09-15T00:00:00Z",
        )
        document = json.loads(first)

        self.assertEqual(first, second)
        self.assertTrue(first.endswith(b"\n"))
        self.assertEqual(document["spdxVersion"], "SPDX-2.3")
        self.assertEqual(document["dataLicense"], "CC0-1.0")
        self.assertTrue(document["documentNamespace"].startswith("urn:uuid:"))
        self.assertNotIn("github.com", document["documentNamespace"])
        self.assertEqual(document["creationInfo"]["created"], "2026-09-15T00:00:00Z")
        self.assertEqual(
            [item["fileName"] for item in document["files"]],
            ["./trestle", "./web/index.html"],
        )
        self.assertTrue(
            all(
                item["SPDXID"].startswith("SPDXRef-File-")
                for item in document["files"]
            )
        )
        self.assertEqual(
            document["files"][0]["checksums"],
            [{"algorithm": "SHA256", "checksumValue": "a" * 64}],
        )
        self.assertEqual(
            document["documentDescribes"], ["SPDXRef-Package-Open-Trestle"]
        )
        self.assertEqual(
            [(item["name"], item["versionInfo"]) for item in document["packages"]],
            [
                ("Open Trestle", "0.1.0"),
                ("example.org/module", "v1.0.0"),
                ("react", "19.2.8"),
            ],
        )
        self.assertEqual(
            document["packages"][0]["sourceInfo"],
            "Declared Git revision " + ("1" * 40),
        )
        self.assertEqual(
            document["packages"][1]["externalRefs"][0]["referenceLocator"],
            "pkg:golang/example.org/module@v1.0.0",
        )
        self.assertEqual(
            document["packages"][2]["externalRefs"][0]["referenceLocator"],
            "pkg:npm/react@19.2.8",
        )
        relationship_types = [
            item["relationshipType"] for item in document["relationships"]
        ]
        self.assertEqual(relationship_types.count("CONTAINS"), 2)
        self.assertEqual(relationship_types.count("DEPENDS_ON"), 2)
        self.assertIn("unsigned local inventory", document["comment"].lower())

    def test_spdx_inventory_rejects_invalid_metadata_and_artifacts(self):
        valid = release_evidence.Artifact("trestle", "a" * 64, 1)
        cases = (
            ((), "0.1.0", "1" * 40, "2026-09-15T00:00:00Z"),
            ((valid,), "latest", "1" * 40, "2026-09-15T00:00:00Z"),
            ((valid,), "0.1.0", "ABC", "2026-09-15T00:00:00Z"),
            ((valid,), "0.1.0", "1" * 40, "2026-09-15 00:00:00"),
            (
                (release_evidence.Artifact("trestle", "A" * 64, 1),),
                "0.1.0",
                "1" * 40,
                "2026-09-15T00:00:00Z",
            ),
            (
                (release_evidence.Artifact("trestle", "a" * 64, 0),),
                "0.1.0",
                "1" * 40,
                "2026-09-15T00:00:00Z",
            ),
        )
        for artifacts, version, revision, created in cases:
            with self.subTest(version=version, revision=revision, created=created):
                with self.assertRaises(ValueError):
                    release_evidence.encode_spdx(
                        artifacts,
                        version=version,
                        revision=revision,
                        created=created,
                    )

    def test_spdx_inventory_rejects_duplicate_or_unsafe_components(self):
        artifact = (release_evidence.Artifact("trestle", "a" * 64, 1),)
        valid = release_evidence.Component("npm", "react", "19.2.8", "MIT")
        cases = (
            (valid, valid),
            (release_evidence.Component("unknown", "react", "19.2.8"),),
            (release_evidence.Component("npm", "bad\nname", "1.0.0"),),
            (release_evidence.Component("npm", "react", ""),),
        )
        for components in cases:
            with self.subTest(components=components):
                with self.assertRaises(ValueError):
                    release_evidence.encode_spdx(
                        artifact,
                        components=components,
                        version="0.1.0",
                        revision="1" * 40,
                        created="2026-09-15T00:00:00Z",
                    )

    def test_release_evidence_directory_is_complete_and_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "evidence"
            artifacts = (release_evidence.Artifact("trestle", "a" * 64, 1),)

            release_evidence.write_release_evidence(
                output,
                artifacts,
                (),
                version="0.1.0",
                revision="1" * 40,
                created="2026-09-15T00:00:00Z",
            )

            self.assertEqual(
                sorted(path.name for path in output.iterdir()),
                ["SHA256SUMS", "sbom.spdx.json"],
            )
            self.assertEqual(
                (output / "SHA256SUMS").read_text(), ("a" * 64) + "  trestle\n"
            )
            before = (output / "sbom.spdx.json").read_bytes()
            with self.assertRaisesRegex(ValueError, "output path already exists"):
                release_evidence.write_release_evidence(
                    output,
                    artifacts,
                    (),
                    version="0.1.0",
                    revision="1" * 40,
                    created="2026-09-15T00:00:00Z",
                )
            self.assertEqual((output / "sbom.spdx.json").read_bytes(), before)

    def test_release_evidence_rejects_symlinked_output_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            (root / "linked").symlink_to(target, target_is_directory=True)
            artifact = (release_evidence.Artifact("trestle", "a" * 64, 1),)

            with self.assertRaisesRegex(
                ValueError, "output path must not be symlinked"
            ):
                release_evidence.write_release_evidence(
                    root / "linked" / "evidence",
                    artifact,
                    (),
                    version="0.1.0",
                    revision="1" * 40,
                    created="2026-09-15T00:00:00Z",
                )
            self.assertFalse((target / "evidence").exists())

    @patch.object(Path, "write_bytes", side_effect=OSError("disk failure"))
    def test_output_write_failure_leaves_no_partial_directory(self, _write):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "evidence"
            artifact = (release_evidence.Artifact("trestle", "a" * 64, 1),)

            with self.assertRaises(OSError):
                release_evidence.write_release_evidence(
                    output,
                    artifact,
                    (),
                    version="0.1.0",
                    revision="1" * 40,
                    created="2026-09-15T00:00:00Z",
                )
            self.assertFalse(output.exists())
            self.assertEqual(list(root.iterdir()), [])

    def test_cli_rejects_component_input_outside_root(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / "project"
            root.mkdir()
            (root / "trestle").write_bytes(b"binary")
            (parent / "outside-lock.json").write_text(
                json.dumps({"lockfileVersion": 3, "packages": {}})
            )

            errors = io.StringIO()
            with redirect_stderr(errors):
                code = release_evidence.main(
                    [
                        "--artifact",
                        "trestle=trestle",
                        "--npm-lock",
                        "../outside-lock.json",
                        "--version",
                        "0.1.0",
                        "--revision",
                        "1" * 40,
                        "--created",
                        "2026-09-15T00:00:00Z",
                        "--output",
                        "evidence",
                    ],
                    root=root,
                )

            self.assertEqual(code, 1)
            self.assertEqual(
                errors.getvalue(), "error: npm lockfile path escapes root\n"
            )
            self.assertFalse((root / "evidence").exists())

    def test_cli_writes_local_artifact_and_runtime_component_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "trestle").write_bytes(b"binary")
            (root / "package-lock.json").write_text(
                json.dumps(
                    {
                        "lockfileVersion": 3,
                        "packages": {
                            "": {"dependencies": {"runtime": "1.0.0"}},
                            "node_modules/runtime": {
                                "version": "1.0.0",
                                "license": "MIT",
                            },
                        },
                    }
                )
            )

            code = release_evidence.main(
                [
                    "--artifact",
                    "trestle=trestle",
                    "--npm-lock",
                    "package-lock.json",
                    "--version",
                    "0.1.0",
                    "--revision",
                    "1" * 40,
                    "--created",
                    "2026-09-15T00:00:00Z",
                    "--output",
                    "evidence",
                ],
                root=root,
            )

            self.assertEqual(code, 0)
            document = json.loads((root / "evidence" / "sbom.spdx.json").read_bytes())
            self.assertEqual(
                [(item["name"], item["versionInfo"]) for item in document["packages"]],
                [("Open Trestle", "0.1.0"), ("runtime", "1.0.0")],
            )

class ComponentInventoryTest(unittest.TestCase):
    def test_npm_lock_inventory_includes_only_production_packages(self):
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / "package-lock.json"
            lock.write_text(
                json.dumps(
                    {
                        "lockfileVersion": 3,
                        "packages": {
                            "": {"dependencies": {"runtime": "1.0.0"}},
                            "node_modules/runtime": {
                                "version": "1.0.0",
                                "license": "MIT",
                            },
                            "node_modules/runtime/node_modules/transitive": {
                                "version": "2.0.0",
                                "license": "Apache-2.0",
                            },
                            "node_modules/test-only": {
                                "version": "3.0.0",
                                "dev": True,
                                "license": "ISC",
                            },
                        },
                    }
                )
            )

            components = release_evidence.read_npm_components(lock)

            self.assertEqual(
                [(item.name, item.version, item.license) for item in components],
                [
                    ("runtime", "1.0.0", "MIT"),
                    ("transitive", "2.0.0", "Apache-2.0"),
                ],
            )

    def test_go_build_info_inventory_uses_embedded_runtime_dependencies(self):
        components = release_evidence.parse_go_components(
            """binary: go1.24.0
	path	github.com/example/tool
	mod	github.com/example/project	(devel)	
	dep	github.com/example/runtime	v1.2.3	h1:sum
	dep	golang.org/x/text	v0.24.0	h1:sum
	build	CGO_ENABLED=0
"""
        )

        self.assertEqual(
            [(item.ecosystem, item.name, item.version) for item in components],
            [
                ("gomod", "github.com/example/runtime", "v1.2.3"),
                ("gomod", "golang.org/x/text", "v0.24.0"),
            ],
        )

    def test_component_merge_deduplicates_exact_inventory(self):
        react = release_evidence.Component("npm", "react", "19.2.8", "MIT")
        scheduler = release_evidence.Component("npm", "scheduler", "0.27.0", "MIT")

        merged = release_evidence.merge_components((react,), (scheduler, react))

        self.assertEqual(merged, (react, scheduler))
        with self.assertRaisesRegex(ValueError, "conflicting component metadata"):
            release_evidence.merge_components(
                (react,),
                (release_evidence.Component("npm", "react", "19.2.8", "ISC"),),
            )


    @patch("release_evidence.subprocess.run")
    def test_go_binary_inventory_reads_embedded_build_info(self, run):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "trestle"
            binary.write_bytes(b"binary")
            run.return_value.stdout = (
                "trestle: go1.24.0\n"
                "\tdep\texample.org/runtime\tv1.2.3\th1:sum\n"
            )

            components = release_evidence.read_go_binary_components(binary)

            self.assertEqual(
                components,
                (release_evidence.Component("gomod", "example.org/runtime", "v1.2.3"),),
            )
            run.assert_called_once_with(
                ["go", "version", "-m", str(binary)],
                check=True,
                capture_output=True,
                text=True,
            )

    def test_component_inputs_reject_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target-lock.json"
            target.write_text(json.dumps({"lockfileVersion": 3, "packages": {}}))
            linked = root / "package-lock.json"
            linked.symlink_to(target)

            with self.assertRaisesRegex(
                ValueError, "npm lockfile must not be symlinked"
            ):
                release_evidence.read_npm_components(linked)

    def test_go_build_info_replacements_fail_closed(self):
        build_info = (
            "trestle: go1.24.0\n"
            "\tdep\texample.org/runtime\tv1.2.3\th1:sum\n"
            "\t=>\t../local-runtime\t(devel)\t\n"
        )

        with self.assertRaisesRegex(
            ValueError, "replaced Go modules are unsupported"
        ):
            release_evidence.parse_go_components(build_info)


class ReleaseWorkflowTest(unittest.TestCase):
    def test_ci_generates_release_evidence_twice_and_compares_bytes(self):
        repository_root = Path(__file__).resolve().parent.parent
        workflow = (
            repository_root / ".github/workflows/verify-runtime.yml"
        ).read_text()

        self.assertEqual(workflow.count("python3 tools/release_evidence.py"), 2)
        for required in (
            "--artifact container=.container",
            "--artifact web=web/dist",
            "--artifact vscode=extensions/vscode/dist/open-trestle.vsix",
            "--go-binary .container/trestle",
            "--go-binary .container/trestled",
            "--npm-lock web/package-lock.json",
            "--npm-lock extensions/vscode/package-lock.json",
            "diff -r",
        ):
            self.assertIn(required, workflow)

    def test_ci_allows_race_instrumented_package_runtime(self):
        repository_root = Path(__file__).resolve().parent.parent
        workflow = (
            repository_root / ".github/workflows/verify-runtime.yml"
        ).read_text()

        self.assertIn("go test -race -p=1 -timeout=30m ./...", workflow)


if __name__ == "__main__":
    unittest.main()
