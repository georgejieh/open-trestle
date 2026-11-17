"""Tests for the WebAssembly syntax-analysis module build."""

import copy
import gzip
import hashlib
import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path

import build_syntax_modules as build

REPOSITORY = Path(__file__).resolve().parent.parent


def committed_manifest() -> dict:
    return json.loads((REPOSITORY / build.MANIFEST).read_text(encoding="utf-8"))


class ManifestTest(unittest.TestCase):
    def test_committed_manifest_is_valid(self):
        manifest = committed_manifest()
        build.validate_manifest(manifest)
        families = {family["name"]: family["languages"] for family in manifest["families"]}
        self.assertEqual(families["web"], ["javascript", "typescript", "tsx", "html"])
        self.assertEqual(families["jvm"], ["java"])
        self.assertEqual(families["python"], ["python"])
        self.assertEqual(manifest["build"]["shim"], build.SHIM)
        for family in manifest["families"]:
            self.assertRegex(family["wasm_sha256"], "^[0-9a-f]{64}$")
            build.check_link_inputs(family["link_inputs"])

    def test_every_source_is_pinned_by_commit_and_tree_digest(self):
        for source in committed_manifest()["sources"]:
            self.assertRegex(source["commit"], "^[0-9a-f]{40}$")
            self.assertRegex(source["tree"]["sha256"], "^[0-9a-f]{64}$")
            self.assertGreater(source["tree"]["files"], 0)

    def test_invalid_manifests_are_refused(self):
        base = committed_manifest()
        mutations = []

        def mutate(change):
            document = copy.deepcopy(base)
            change(document)
            mutations.append(document)

        mutate(lambda d: d.update(schema_version=2))
        mutate(lambda d: d["sources"][0].update(commit="v0.27.2"))
        mutate(lambda d: d["sources"][1].update(name=d["sources"][0]["name"]))
        mutate(lambda d: d["sources"][0].update(repository="http://example.com/x"))
        mutate(lambda d: d["toolchain"].update(url="https://example.com/wasi-sdk.tar.gz"))
        mutate(lambda d: d["toolchain"].update(root="../escape"))
        mutate(lambda d: d["grammars"][0].update(files=["../../etc/passwd.c"]))
        mutate(lambda d: d["grammars"][0].update(include="/abs"))
        mutate(lambda d: d["grammars"][1].update(language=d["grammars"][0]["language"]))
        mutate(lambda d: d["families"][0]["languages"].append("python"))
        mutate(lambda d: d["families"].pop())
        mutate(lambda d: d.update(licenses=[entry for entry in d["licenses"] if entry["source"] != "tree-sitter-java"]))
        mutate(lambda d: d["licenses"][0].update(file="../NOTICE"))
        mutate(lambda d: d["licenses"][0].update(lines=[3, 1]))
        for document in mutations:
            with self.assertRaises(ValueError):
                build.validate_manifest(document)


class DigestTest(unittest.TestCase):
    def test_tree_digest_covers_paths_contents_and_links_but_not_git(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "src/parser.c").write_text("int x;\n")
            (root / ".git").mkdir()
            (root / ".git/HEAD").write_text("ref\n")
            os.symlink("parser.c", root / "src/link.c")
            first = build.tree_digest(root)
            self.assertEqual(first["files"], 2)
            (root / ".git/HEAD").write_text("other\n")
            self.assertEqual(build.tree_digest(root), first)
            (root / "src/parser.c").write_text("int y;\n")
            changed = build.tree_digest(root)
            self.assertNotEqual(changed["sha256"], first["sha256"])
            (root / "src/link.c").unlink()
            os.symlink("other.c", root / "src/link.c")
            self.assertNotEqual(build.tree_digest(root)["sha256"], changed["sha256"])

    def test_gzip_is_deterministic_without_name_or_time(self):
        data = b"\0asm" + bytes(range(256)) * 64
        first = build.deterministic_gzip(data)
        self.assertEqual(first, build.deterministic_gzip(data))
        self.assertEqual(first[4:8], b"\0\0\0\0")
        self.assertEqual(first[3] & 0x08, 0)
        self.assertEqual(gzip.decompress(first), data)

    def test_license_line_ranges(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "malloc.c"
            path.write_bytes(b"/*\n notice\n*/\nint x;\n")
            self.assertEqual(build.license_text(path, [1, 3]), b"/*\n notice\n*/\n")
            self.assertEqual(build.license_text(path, None), path.read_bytes())
            with self.assertRaises(ValueError):
                build.license_text(path, [3, 9])


def make_tar(members):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for info, data in members:
            archive.addfile(info, io.BytesIO(data) if data is not None else None)
    return buffer.getvalue()


def file_member(name, data=b"x", mode=0o644):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    return info, data


def link_member(name, target, kind=tarfile.SYMTYPE):
    info = tarfile.TarInfo(name)
    info.type = kind
    info.linkname = target
    return info, None


class ExtractTest(unittest.TestCase):
    def extract(self, members):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        archive = Path(directory.name) / "sdk.tar.gz"
        archive.write_bytes(make_tar(members))
        return build.safe_extract(archive, Path(directory.name) / "out", "sdk")

    def test_extracts_files_and_internal_links(self):
        root = self.extract([
            file_member("sdk/bin/clang-23", b"#!", 0o755),
            link_member("sdk/bin/clang", "clang-23"),
            link_member("sdk/lib/libLLVM.so", "../lib/libLLVM.so.23"),
            file_member("sdk/lib/libLLVM.so.23"),
        ])
        self.assertEqual(os.readlink(root / "bin/clang"), "clang-23")
        self.assertTrue(os.access(root / "bin/clang-23", os.X_OK))

    def test_refuses_unsafe_members(self):
        for members in (
            [file_member("other/file")],
            [file_member("sdk/../escape")],
            [file_member("/sdk/abs")],
            [link_member("sdk/bin/x", "/usr/bin/x")],
            [link_member("sdk/bin/x", "../../outside")],
            [link_member("sdk/bin/x", "sdk/bin/y", tarfile.LNKTYPE)],
        ):
            with self.assertRaises(ValueError):
                self.extract(members)


class LinkTest(unittest.TestCase):
    def test_link_inputs_are_parsed_and_restricted(self):
        trace = "\n".join([
            "/build/web/shim.o",
            "/build/runtime.o",
            "/sdk/share/wasi-sysroot/lib/wasm32-wasip1/crt1-reactor.o",
            "/sdk/share/wasi-sysroot/lib/wasm32-wasip1/libc.a(dlmalloc.c.obj)",
            "/sdk/share/wasi-sysroot/lib/wasm32-wasip1/libc.a(strlen.c.obj)",
        ])
        members = build.link_inputs(trace)
        self.assertEqual(members, ["crt1-reactor.o", "libc.a(dlmalloc.c.obj)", "libc.a(strlen.c.obj)"])
        build.check_link_inputs(members)
        with self.assertRaises(ValueError):
            build.check_link_inputs(build.link_inputs("/sdk/lib/clang/23/lib/libclang_rt.builtins.a(multi3.c.o)"))

    def test_languages_header_follows_family_order(self):
        manifest = committed_manifest()
        grammars = {grammar["language"]: grammar for grammar in manifest["grammars"]}
        web = next(family for family in manifest["families"] if family["name"] == "web")
        self.assertEqual(
            build.languages_header(web, grammars).splitlines(),
            [
                'OT_LANGUAGE("javascript", tree_sitter_javascript)',
                'OT_LANGUAGE("typescript", tree_sitter_typescript)',
                'OT_LANGUAGE("tsx", tree_sitter_tsx)',
                'OT_LANGUAGE("html", tree_sitter_html)',
            ],
        )


class CommittedModuleTest(unittest.TestCase):
    def test_committed_module_check_detects_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = b"\0asm\1\0\0\0"
            compressed = build.deterministic_gzip(data)
            (root / "web.wasm.gz").write_bytes(compressed)
            family = {
                "name": "web", "module": "web.wasm.gz",
                "wasm_sha256": hashlib.sha256(data).hexdigest(), "wasm_size": len(data),
                "gzip_sha256": hashlib.sha256(compressed).hexdigest(), "gzip_size": len(compressed),
            }
            build.verify_committed_module(root, family)
            for change in (
                {"wasm_sha256": "0" * 64},
                {"gzip_sha256": "0" * 64},
                {"wasm_size": len(data) + 1},
            ):
                with self.assertRaises(ValueError):
                    build.verify_committed_module(root, {**family, **change})
            (root / "web.wasm.gz").write_bytes(build.deterministic_gzip(b"\0asm\1\0\0\1"))
            with self.assertRaises(ValueError):
                build.verify_committed_module(root, family)

    def test_build_record_binds_the_shim(self):
        manifest = committed_manifest()
        build.record_build(manifest, REPOSITORY, update=False)
        changed = copy.deepcopy(manifest)
        changed["build"]["shim_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            build.record_build(changed, REPOSITORY, update=False)
        changed = copy.deepcopy(manifest)
        changed["build"]["compile_flags"] = changed["build"]["compile_flags"] + ["-O0"]
        with self.assertRaises(ValueError):
            build.record_build(changed, REPOSITORY, update=False)


if __name__ == "__main__":
    unittest.main()
