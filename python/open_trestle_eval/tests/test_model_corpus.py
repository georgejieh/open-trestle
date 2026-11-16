import collections
import contextlib
import hashlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
import zlib
from pathlib import Path

from open_trestle_eval.model_corpus import (
    CorpusError,
    canonical_identity,
    default_corpus_root,
    load_corpus,
    main,
    materialize_case,
    plan_revisions,
    refresh_manifest,
    removed_base_lines,
)

CORPUS = default_corpus_root()


def read_object(objects: Path, oid: str) -> tuple[bytes, bytes]:
    framed = zlib.decompress((objects / oid[:2] / oid[2:]).read_bytes())
    if hashlib.sha1(framed).hexdigest() != oid:
        raise AssertionError("object name does not match its content")
    header, payload = framed.split(b"\0", 1)
    kind, size = header.split(b" ")
    if int(size) != len(payload):
        raise AssertionError("object size header is wrong")
    return kind, payload


def read_tree(objects: Path, oid: str, prefix: str = "") -> dict[str, bytes]:
    kind, payload = read_object(objects, oid)
    assert kind == b"tree"
    files = {}
    names = []
    while payload:
        header, rest = payload.split(b"\0", 1)
        mode, name = header.split(b" ", 1)
        child, payload = rest[:20].hex(), rest[20:]
        names.append(name + (b"/" if mode == b"40000" else b""))
        path = prefix + name.decode()
        if mode == b"40000":
            files.update(read_tree(objects, child, path + "/"))
        else:
            assert mode == b"100644"
            child_kind, data = read_object(objects, child)
            assert child_kind == b"blob"
            files[path] = data
    assert names == sorted(names), "tree entries are not in Git order"
    return files


def commit_fields(objects: Path, oid: str) -> dict[str, str]:
    kind, payload = read_object(objects, oid)
    assert kind == b"commit"
    header, message = payload.split(b"\n\n", 1)
    fields = dict(line.split(" ", 1) for line in header.decode().split("\n"))
    fields["message"] = message.decode()
    return fields


class CommittedCorpusTest(unittest.TestCase):
    def test_committed_corpus_verifies_and_stays_pending(self) -> None:
        corpus = load_corpus(CORPUS)
        manifest = json.loads((CORPUS / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(corpus.identity, manifest["corpus_identity"])
        self.assertEqual(corpus.identity, canonical_identity(manifest))
        self.assertEqual(
            collections.Counter(case.kind for case in corpus.cases),
            {"defect": 12, "deletion_defect": 3, "near_miss": 3, "clean": 3, "abstention": 2},
        )
        for case in corpus.cases:
            labels = json.loads((CORPUS / "cases" / case.id / "labels.json").read_text(encoding="utf-8"))
            self.assertEqual(
                (labels["review_state"], labels["reviewer_identifier"], labels["review_date"], labels["fixture_author_identifier"]),
                ("pending", None, None, "open-trestle-maintainers"),
            )
            self.assertTrue(case.changed_paths(), case.id)
            if case.kind == "deletion_defect":
                self.assertEqual(case.expected_findings[0].locations[0].side, "base", case.id)

    def test_manifest_pins_are_current(self) -> None:
        manifest_bytes, adjudication_bytes = refresh_manifest(CORPUS)
        self.assertEqual(manifest_bytes, (CORPUS / "manifest.json").read_bytes())
        self.assertEqual(adjudication_bytes, (CORPUS / "adjudication.json").read_bytes())

    def test_version_dependent_near_misses_raise_the_go_directive_in_the_diff(self) -> None:
        corpus = load_corpus(CORPUS)
        self.assertEqual(corpus.case("near_miss_loop_variable_go122").go_versions, ("1.21", "1.22"))
        self.assertEqual(corpus.case("near_miss_time_after_go123").go_versions, ("1.22", "1.23"))
        for case_id in ("near_miss_loop_variable_go122", "near_miss_time_after_go123"):
            self.assertIn("go.mod", corpus.case(case_id).changed_paths())
        external = [case.id for case in corpus.cases if case.build != "builds"]
        self.assertEqual(external, ["abstention_argument_order", "abstention_unit_unknown"])


class CorpusTamperTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name) / "corpus"
        shutil.copytree(CORPUS, self.root)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def edit_labels(self, case_id: str, edit) -> None:
        path = self.root / "cases" / case_id / "labels.json"
        labels = json.loads(path.read_text(encoding="utf-8"))
        edit(labels)
        path.write_text(json.dumps(labels, indent=2) + "\n", encoding="utf-8")
        manifest, adjudication = refresh_manifest(self.root)
        (self.root / "manifest.json").write_bytes(manifest)
        (self.root / "adjudication.json").write_bytes(adjudication)

    def assert_refused(self, reason: str) -> None:
        with self.assertRaisesRegex(CorpusError, reason):
            load_corpus(self.root)

    def test_refreshed_copy_loads(self) -> None:
        self.edit_labels("clean_rename", lambda labels: None)
        self.assertEqual(load_corpus(self.root).identity, load_corpus(CORPUS).identity)

    def test_refuses_changed_source_bytes(self) -> None:
        path = self.root / "cases" / "defect_off_by_one" / "head" / "tail.go"
        path.write_bytes(path.read_bytes().replace(b"i <= len(lines)", b"i < len(lines)"))
        self.assert_refused('does not match its descriptor')

    def test_refuses_unlisted_file(self) -> None:
        (self.root / "cases" / "clean_rename" / "head" / "extra.go").write_text("package kv\n", encoding="utf-8")
        self.assert_refused('unlisted or missing files')

    def test_refuses_symbolic_link(self) -> None:
        os.symlink("parse.go", self.root / "cases" / "clean_rename" / "head" / "link.go")
        self.assert_refused('non-regular file')

    def test_refuses_a_recorded_reviewer(self) -> None:
        self.edit_labels("clean_rename", lambda labels: labels.update(reviewer_identifier="someone", review_state="adjudicated"))
        self.assert_refused('pending v1 contract')

    def test_refuses_a_base_location_on_unchanged_lines(self) -> None:
        def edit(labels):
            labels["expected_findings"][0]["start_line"] = 1
            labels["expected_findings"][0]["end_line"] = 2

        self.edit_labels("deletion_bounds_check", edit)
        self.assert_refused('not on removed lines')

    def test_refuses_a_location_past_the_end_of_its_file(self) -> None:
        self.edit_labels("defect_off_by_one", lambda labels: labels["expected_findings"][0].update(end_line=999))
        self.assert_refused('outside its file')

    def test_refuses_a_location_in_a_missing_file(self) -> None:
        self.edit_labels("defect_off_by_one", lambda labels: labels["expected_findings"][0].update(path="other.go"))
        self.assert_refused('outside its file')

    def test_refuses_an_outcome_that_does_not_fit_the_kind(self) -> None:
        self.edit_labels("clean_rename", lambda labels: labels.update(expected_outcome="abstention", abstention_reason="x"))
        self.assert_refused('does not fit the case kind')

    def test_refuses_a_near_miss_without_traps(self) -> None:
        self.edit_labels("near_miss_nil_map_read", lambda labels: labels.update(false_positive_traps=[]))
        self.assert_refused('near miss needs')

    def test_refuses_a_go_version_other_than_the_head_directive(self) -> None:
        self.edit_labels("near_miss_time_after_go123", lambda labels: labels.update(go_version="1.22"))
        self.assert_refused('pending v1 contract')

    def test_refuses_a_stale_identity(self) -> None:
        manifest = json.loads((self.root / "manifest.json").read_text(encoding="utf-8"))
        manifest["cases"][0]["build"] = "builds"
        (self.root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        self.assert_refused('corpus identity')

    def test_refuses_a_decided_adjudication(self) -> None:
        path = self.root / "adjudication.json"
        path.write_text(path.read_text(encoding="utf-8").replace('"decision": "pending"', '"decision": "accepted"'), encoding="utf-8")
        self.assert_refused('adjudication is not pending')

    def test_refuses_duplicate_json_keys(self) -> None:
        path = self.root / "adjudication.json"
        path.write_text(path.read_text(encoding="utf-8").replace('"review_state": "pending",', '"review_state": "pending",\n  "review_state": "pending",'), encoding="utf-8")
        self.assert_refused('duplicate JSON key')

    def test_refuses_a_boolean_schema_version(self) -> None:
        path = self.root / "adjudication.json"
        path.write_text(path.read_text(encoding="utf-8").replace('"schema_version": 1', '"schema_version": true'), encoding="utf-8")
        self.assert_refused('adjudication is not pending')


class MaterializationTest(unittest.TestCase):
    def test_removed_base_lines_cover_deleted_and_replaced_lines(self) -> None:
        self.assertEqual(removed_base_lines(b"a\nb\nc\nd\n", b"a\nd\n"), frozenset({2, 3}))
        self.assertEqual(removed_base_lines(b"a\nb\n", b"a\nB\n"), frozenset({2}))
        self.assertEqual(removed_base_lines(b"a\nb\n", None), frozenset({1, 2}))
        self.assertEqual(removed_base_lines(b"a\n", b"a\nb\n"), frozenset())

    def test_revisions_are_reproducible_and_bind_the_exact_trees(self) -> None:
        corpus = load_corpus(CORPUS)
        seen = set()
        with tempfile.TemporaryDirectory() as value:
            for case in corpus.cases:
                base, head, _ = plan_revisions(case)
                self.assertEqual((base, head), plan_revisions(case)[:2])
                self.assertNotEqual(base, head)
                seen.add(head)
                repository = materialize_case(case, Path(value) / f"{case.id}.git")
                self.assertEqual((repository.base_revision, repository.head_revision), (base, head))
                objects = repository.objects_root
                base_commit = commit_fields(objects, base)
                head_commit = commit_fields(objects, head)
                self.assertNotIn("parent", base_commit)
                self.assertEqual(head_commit["parent"], base)
                self.assertEqual((base_commit["message"], head_commit["message"]), ("base\n", "head\n"))
                for fields in (base_commit, head_commit):
                    self.assertNotIn(case.id, json.dumps(fields))
                self.assertEqual(read_tree(objects, base_commit["tree"]), case.base)
                self.assertEqual(read_tree(objects, head_commit["tree"]), case.head)
                self.assertEqual((repository.git_dir / "refs/heads/main").read_text(encoding="ascii"), head + "\n")
                self.assertEqual((repository.git_dir / "refs/heads/base").read_text(encoding="ascii"), base + "\n")
                self.assertEqual((repository.git_dir / "HEAD").read_text(encoding="ascii"), "ref: refs/heads/main\n")
        self.assertEqual(len(seen), len(corpus.cases))

    def test_refuses_an_existing_destination(self) -> None:
        corpus = load_corpus(CORPUS)
        with tempfile.TemporaryDirectory() as value:
            target = Path(value) / "repository.git"
            target.mkdir()
            with self.assertRaises(FileExistsError):
                materialize_case(corpus.cases[0], target)
            self.assertEqual(list(target.iterdir()), [])

    @unittest.skipIf(shutil.which("git") is None, "git is not installed")
    def test_git_accepts_every_materialized_repository(self) -> None:
        corpus = load_corpus(CORPUS)
        with tempfile.TemporaryDirectory() as value:
            environment = {
                "PATH": os.environ.get("PATH", ""),
                "HOME": value,
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "LC_ALL": "C",
            }
            for case in corpus.cases:
                repository = materialize_case(case, Path(value) / f"{case.id}.git")

                def git(*arguments: str) -> bytes:
                    return subprocess.run(
                        ["git", "--git-dir", str(repository.git_dir), *arguments],
                        check=True,
                        capture_output=True,
                        env=environment,
                    ).stdout

                git("fsck", "--strict", "--no-dangling", "--no-progress")
                changed = git("diff", "--no-renames", "--name-only", "base", "main").decode().split()
                self.assertEqual(tuple(changed), case.changed_paths(), case.id)
                for path, data in case.head.items():
                    self.assertEqual(git("cat-file", "blob", f"main:{path}"), data)

    def test_command_line_verifies_and_materializes(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["verify"]), 0)
        self.assertIn("review_state=pending", output.getvalue())
        with tempfile.TemporaryDirectory() as value:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["materialize", "--case", "clean_rename", "--output", str(Path(value) / "r.git")]), 0)
            fields = dict(line.split("=", 1) for line in output.getvalue().splitlines())
            base, head, _ = plan_revisions(load_corpus(CORPUS).case("clean_rename"))
            self.assertEqual((fields["base_revision"], fields["head_revision"]), (base, head))
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["materialize", "--case", "missing_case", "--output", str(Path(value) / "x.git")]), 1)


if __name__ == "__main__":
    unittest.main()
