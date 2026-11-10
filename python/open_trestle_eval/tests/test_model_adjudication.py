import contextlib
import hashlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from jsonschema_subset import SchemaError, validate
from open_trestle_eval.model_adjudication import AdjudicationError, import_adjudication, main, read_record
from open_trestle_eval.model_corpus import default_corpus_root, load_corpus

SCHEMAS = Path(__file__).resolve().parents[3] / "schemas/evaluation"
RECORD_SCHEMA = json.loads((SCHEMAS / "model-corpus-human-adjudication-v1.schema.json").read_text(encoding="utf-8"))
CORPUS = load_corpus(default_corpus_root())
# Every record in these tests is synthetic test data: no person reviewed the
# corpus to produce it, and none is shipped as a filled human record.
SYNTHETIC_REVIEWER = "synthetic-test-reviewer"
SYNTHETIC_REASON = "Synthetic test reason; no review took place."


def synthetic_record(corpus=CORPUS, excluded: dict[str, str] | None = None) -> dict:
    """Returns a synthetic record confirming every case except ``excluded``."""
    excluded = excluded or {}
    cases = []
    for case in corpus.cases:
        row = {"case_id": case.id, "labels_sha256": case.labels_sha256, "decision": excluded.get(case.id, "confirmed")}
        if case.id in excluded:
            row["reason"] = SYNTHETIC_REASON
        cases.append(row)
    return {
        "contract": "open-trestle/model-corpus-human-adjudication",
        "schema_version": 1,
        "corpus_identity": corpus.identity,
        "manifest_sha256": corpus.manifest_sha256,
        "reviewer_identifier": SYNTHETIC_REVIEWER,
        "fixture_author_identifier": "open-trestle-maintainers",
        "review_date": "2026-11-09",
        "method": "independent_human_review",
        "source_first": True,
        "prior_run_output_exposure": "none_declared",
        "cases": cases,
    }


def encode(value) -> bytes:
    return (json.dumps(value, indent=2) + "\n").encode("utf-8")


def pin(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class RecordSchemaTest(unittest.TestCase):
    def test_admits_full_confirmation_and_reasoned_exclusions(self) -> None:
        validate(RECORD_SCHEMA, synthetic_record())
        validate(RECORD_SCHEMA, synthetic_record(excluded={"clean_rename": "revised", "defect_off_by_one": "rejected"}))
        self.assertEqual(RECORD_SCHEMA["$id"], "urn:open-trestle:schema:evaluation:model-corpus-human-adjudication:v1")

    def test_refuses_records_outside_the_closed_contract(self) -> None:
        def row(value: dict, index: int = 0) -> dict:
            return value["cases"][index]

        mutations = {
            "unknown field": lambda value: value.update(notes="x"),
            "missing reviewer": lambda value: value.pop("reviewer_identifier"),
            "reviewer is the fixture author": lambda value: value.update(reviewer_identifier="open-trestle-maintainers"),
            "other fixture author": lambda value: value.update(fixture_author_identifier="someone-else"),
            "invalid reviewer": lambda value: value.update(reviewer_identifier="Synthetic Reviewer"),
            "null reviewer": lambda value: value.update(reviewer_identifier=None),
            "not source first": lambda value: value.update(source_first=False),
            "source first as integer": lambda value: value.update(source_first=1),
            "exposure declared": lambda value: value.update(prior_run_output_exposure="exposed"),
            "other method": lambda value: value.update(method="model_review"),
            "unpadded date": lambda value: value.update(review_date="2026-11-9"),
            "month thirteen": lambda value: value.update(review_date="2026-13-01"),
            "short corpus identity": lambda value: value.update(corpus_identity="a" * 63),
            "zero manifest digest": lambda value: value.update(manifest_sha256="0" * 64),
            "version as float": lambda value: value.update(schema_version=1.5),
            "no cases": lambda value: value.update(cases=[]),
            "unknown decision": lambda value: row(value).update(decision="pending"),
            "confirmed with a reason": lambda value: row(value).update(reason=SYNTHETIC_REASON),
            "revised without a reason": lambda value: row(value).update(decision="revised"),
            "rejected with an empty reason": lambda value: row(value).update(decision="rejected", reason=""),
            "reason too long": lambda value: row(value).update(decision="rejected", reason="x" * 1025),
            "unknown case field": lambda value: row(value).update(kind="defect"),
            "upper-case digest": lambda value: row(value).update(labels_sha256=row(value)["labels_sha256"].upper()),
            "invalid case identifier": lambda value: row(value).update(case_id="Clean-Rename"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                value = synthetic_record()
                mutate(value)
                with self.assertRaises(SchemaError):
                    validate(RECORD_SCHEMA, value)


class ImportTest(unittest.TestCase):
    def test_imports_a_full_confirmation(self) -> None:
        data = encode(synthetic_record())
        adjudication = import_adjudication(CORPUS, data, pin(data))
        self.assertEqual(
            (adjudication.record_sha256, adjudication.corpus_identity, adjudication.manifest_sha256),
            (pin(data), CORPUS.identity, CORPUS.manifest_sha256),
        )
        self.assertEqual([item.case_id for item in adjudication.decisions], [case.id for case in CORPUS.cases])
        self.assertEqual([item.labels_sha256 for item in adjudication.decisions], [case.labels_sha256 for case in CORPUS.cases])
        self.assertTrue(adjudication.every_case_confirmed)
        self.assertEqual(adjudication.excluded, ())
        self.assertEqual(adjudication.for_case("clean_rename").decision, "confirmed")
        # Whitespace is the author's; the pin covers the exact bytes.
        compact = json.dumps(synthetic_record(), separators=(",", ":")).encode()
        self.assertEqual(import_adjudication(CORPUS, compact, pin(compact)).record_sha256, pin(compact))

    def test_imports_revised_and_rejected_cases_as_excluded(self) -> None:
        data = encode(synthetic_record(excluded={"clean_rename": "revised", "defect_off_by_one": "rejected"}))
        adjudication = import_adjudication(CORPUS, data, pin(data))
        self.assertFalse(adjudication.every_case_confirmed)
        self.assertEqual(
            [(item.case_id, item.decision, item.reason) for item in adjudication.excluded],
            [("clean_rename", "revised", SYNTHETIC_REASON), ("defect_off_by_one", "rejected", SYNTHETIC_REASON)],
        )
        self.assertIsNone(adjudication.for_case("defect_data_race").reason)
        with self.assertRaisesRegex(AdjudicationError, "no decision"):
            adjudication.for_case("missing_case")

    def test_refuses_a_record_that_does_not_match_its_pin(self) -> None:
        data = encode(synthetic_record())
        reformatted = data.replace(b"\n", b"\r\n")
        for name, record, pinned in (
            ("other bytes", data, pin(data + b" ")),
            ("reformatted after pinning", reformatted, pin(data)),
            ("upper-case pin", data, pin(data).upper()),
            ("short pin", data, pin(data)[:63]),
            ("pin with newline", data, pin(data) + "\n"),
            ("zero pin", data, "0" * 64),
        ):
            with self.subTest(name=name):
                with self.assertRaisesRegex(AdjudicationError, "pinned SHA-256"):
                    import_adjudication(CORPUS, record, pinned)

    def test_refuses_each_invalid_record(self) -> None:
        def row(index: int, **fields):
            return lambda value: value["cases"][index].update(fields)

        def swap(value: dict) -> None:
            value["cases"][0], value["cases"][1] = value["cases"][1], value["cases"][0]

        def repeat(value: dict) -> None:
            value["cases"][1] = dict(value["cases"][0])

        other_digest = CORPUS.cases[1].labels_sha256
        mutations = {
            "unknown field": (lambda value: value.update(notes="x"), "fields"),
            "missing field": (lambda value: value.pop("review_date"), "fields"),
            "unknown case field": (row(0, kind="defect"), "case decision fields"),
            "confirmed with a reason": (row(0, reason=SYNTHETIC_REASON), "case decision fields"),
            "revised without a reason": (row(0, decision="revised"), "case decision fields"),
            "unknown decision": (row(0, decision="pending"), "not confirmed, revised or rejected"),
            "empty reason": (row(0, decision="rejected", reason=""), "reason"),
            "long reason": (row(0, decision="rejected", reason="x" * 1025), "reason"),
            "missing case": (lambda value: value["cases"].pop(), "omits"),
            "wrong order": (swap, "order"),
            "repeated case": (repeat, "repeats"),
            "unknown case": (row(0, case_id="missing_case"), "unknown case"),
            "wrong label digest": (row(0, labels_sha256=other_digest), "label digest"),
            "malformed label digest": (row(0, labels_sha256="z" * 64), "label digest"),
            "other corpus": (lambda value: value.update(corpus_identity="b" * 64), "different corpus"),
            "other manifest": (lambda value: value.update(manifest_sha256="c" * 64), "different corpus"),
            "reviewer is the fixture author": (lambda value: value.update(reviewer_identifier="open-trestle-maintainers"), "reviewer is the declared fixture author"),
            "invalid reviewer": (lambda value: value.update(reviewer_identifier="Synthetic Reviewer"), "reviewer identifier"),
            "null reviewer": (lambda value: value.update(reviewer_identifier=None), "reviewer identifier"),
            "other fixture author": (lambda value: value.update(fixture_author_identifier="someone-else"), "does not name the corpus's declared fixture author"),
            "exposure declared": (lambda value: value.update(prior_run_output_exposure="exposed"), "exposure"),
            "exposure as boolean": (lambda value: value.update(prior_run_output_exposure=False), "exposure"),
            "not source first": (lambda value: value.update(source_first=False), "source-first"),
            "source first as integer": (lambda value: value.update(source_first=1), "source-first"),
            "other method": (lambda value: value.update(method="model_review"), "method"),
            "impossible date": (lambda value: value.update(review_date="2026-02-30"), "review date"),
            "compact date": (lambda value: value.update(review_date="20261109"), "review date"),
            "other contract": (lambda value: value.update(contract="open-trestle/model-corpus-adjudication"), "contract"),
            "version as boolean": (lambda value: value.update(schema_version=True), "contract"),
            "no cases": (lambda value: value.update(cases=[]), "omits"),
            "cases not a list": (lambda value: value.update(cases={}), "case list"),
        }
        for name, (mutate, reason) in mutations.items():
            with self.subTest(name=name):
                value = synthetic_record()
                mutate(value)
                data = encode(value)
                with self.assertRaisesRegex(AdjudicationError, reason):
                    import_adjudication(CORPUS, data, pin(data))

    def test_refuses_records_that_are_not_strict_json(self) -> None:
        good = encode(synthetic_record())
        duplicate = good.replace(b'"schema_version": 1,', b'"schema_version": 1,\n  "schema_version": 1,', 1)
        self.assertNotEqual(duplicate, good)
        for name, data, reason in (
            ("duplicate field", duplicate, "strict JSON"),
            ("not JSON", b"{\n", "strict JSON"),
            ("not UTF-8", b"\xff" + good, "strict JSON"),
            ("not an object", b"[]\n", "fields"),
            ("non-finite number", good.replace(b'"schema_version": 1', b'"schema_version": NaN', 1), "strict JSON"),
            ("empty", b"", "empty"),
            ("oversized", good + b" " * (1024 * 1024), "bound"),
        ):
            with self.subTest(name=name):
                with self.assertRaisesRegex(AdjudicationError, reason):
                    import_adjudication(CORPUS, data, pin(data))

    def test_every_imported_record_satisfies_the_schema(self) -> None:
        for excluded in ({}, {"clean_rename": "revised"}):
            value = synthetic_record(excluded=excluded)
            data = encode(value)
            import_adjudication(CORPUS, data, pin(data))
            validate(RECORD_SCHEMA, value)


class ReadRecordTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_reads_a_bounded_regular_file_only(self) -> None:
        record = self.root / "record.json"
        record.write_bytes(encode(synthetic_record()))
        self.assertEqual(read_record(record), record.read_bytes())
        link = self.root / "link.json"
        link.symlink_to(record)
        large = self.root / "large.json"
        large.write_bytes(b" " * (1024 * 1024 + 1))
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        for path, reason in (
            (link, "regular file"),
            (self.root, "regular file"),
            (fifo, "regular file"),
            (self.root / "absent.json", "regular file"),
            (large, "bound"),
        ):
            with self.subTest(path=path.name):
                with self.assertRaisesRegex(AdjudicationError, reason):
                    read_record(path)

    def test_check_command_reports_decisions_without_reasons(self) -> None:
        record = self.root / "record.json"
        data = encode(synthetic_record(excluded={"clean_rename": "rejected"}))
        record.write_bytes(data)
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(main(["check", "--adjudication", str(record), "--adjudication-sha256", pin(data)]), 0)
            self.assertEqual(main(["check", "--adjudication", str(record), "--adjudication-sha256", pin(data + b" ")]), 1)
        output = stdout.getvalue()
        self.assertIn(f"record_sha256={pin(data)}", output)
        self.assertIn(f"corpus={CORPUS.identity}", output)
        self.assertIn("cases=23 confirmed=22 excluded=1", output)
        self.assertIn("provenance_status=externally_asserted", output)
        self.assertIn("excluded clean_rename rejected", output)
        self.assertNotIn(SYNTHETIC_REASON, output)
        self.assertIn("pinned SHA-256", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
