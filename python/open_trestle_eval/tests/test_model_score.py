import contextlib
import dataclasses
import hashlib
import io
import json
import math
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema_subset import SchemaError, validate
from open_trestle_eval.model_adjudication import import_adjudication
from open_trestle_eval.model_corpus import LABEL_STATUS, default_corpus_root, load_corpus, plan_revisions, refresh_manifest
from open_trestle_eval.model_runs import run_corpus, summarize_result
from open_trestle_eval.model_score import ScoreError, main, read_review, score_bundle
from test_model_adjudication import SYNTHETIC_REASON, encode, pin, synthetic_record
from test_model_runs import FAKE_TRESTLE, KNOWN_TOKENS, UNKNOWN_TOKENS, operator_flags

SCHEMAS = Path(__file__).resolve().parents[3] / "schemas/evaluation"
SCORE_SCHEMA = json.loads((SCHEMAS / "model-corpus-score-v1.schema.json").read_text(encoding="utf-8"))
ADJUDICATED_SCHEMA = json.loads((SCHEMAS / "model-corpus-adjudicated-score-v1.schema.json").read_text(encoding="utf-8"))
BUNDLE_SCHEMA = json.loads((SCHEMAS / "model-corpus-run-bundle-v1.schema.json").read_text(encoding="utf-8"))
CORPUS = load_corpus(default_corpus_root())
ADJUDICATED = "adjudicated_externally_asserted"


def finding(path: str, start: int, end: int, *, side: str = "head", category: str | None = "correctness", severity: str = "error", salt: str = "") -> dict:
    identity = hashlib.sha256(f"{path}:{side}:{start}:{end}:{salt}".encode()).hexdigest()
    value = {
        "identity": identity,
        "source_identity": hashlib.sha256(b"source:" + identity.encode()).hexdigest(),
        "fingerprint": hashlib.sha256(b"fingerprint:" + identity.encode()).hexdigest(),
        "title": "Synthetic title",
        "message": "Synthetic claim.",
        "severity": severity,
        "path": path,
        "start_line": start,
        "end_line": end,
        "evidence_ids": ["source-1"],
        "_category": category,
    }
    if side == "base":
        value["side"] = "base"
    return value


def tokens(input_tokens: int, output_tokens: int, cached: int) -> dict:
    """Returns known token usage split as generation 2/3 and verification 1/3."""
    def count(attempts: int, values: tuple[int, int, int]) -> dict:
        return {"known": True, "route_attempts": attempts, "input_tokens": values[0], "output_tokens": values[1], "cached_input_tokens": values[2]}
    generation = (input_tokens * 2 // 3, output_tokens * 2 // 3, cached)
    verification = (input_tokens - generation[0], output_tokens - generation[1], 0)
    return {**count(2, (input_tokens, output_tokens, cached)), "generation": count(1, generation), "verification": count(1, verification)}


def result(*findings: dict, status: str | None = None, inconclusive: int = 0, rejected: int = 0, version: int = 4, usage_known: bool = True, cost: int = 100, diagnostics: bool = True, token_usage: dict | None = None) -> bytes:
    clean = [{key: item for key, item in value.items() if key != "_category"} for value in findings]
    guidance = [{"finding_identity": value["source_identity"], "category": value["_category"]} for value in findings if value["_category"]]
    status = status or ("findings" if findings else ("incomplete" if inconclusive or rejected else "no_candidates"))
    document = {
        "contract": "open-trestle/local-git-model-review-result",
        "schema_version": version,
        "status": status,
        "ci_disposition": "blocked" if findings else "inconclusive",
        "run_status": "succeeded",
        "usage_known": usage_known,
        "actual_cost_micro_usd": cost,
        "diagnostics": {
            "contract": "open-trestle/review-diagnostic-set",
            "schema_version": 8 if any(value.get("side") == "base" for value in clean) else 5,
            "coverage": {
                "candidate_count": len(clean) + inconclusive + rejected,
                "verified_count": len(clean),
                "rejected_count": rejected,
                "inconclusive_count": inconclusive,
            },
            "findings": clean,
        } if diagnostics else None,
    }
    if guidance and version >= 4:
        document["finding_guidance"] = guidance
    if token_usage is not None:
        document["token_usage"] = token_usage
    return (json.dumps(document, separators=(",", ":")) + "\n").encode()


def refused() -> bytes:
    return result(status="refused", diagnostics=False, usage_known=False, cost=0)


def write_bundle(root: Path, runs: dict[str, list[tuple[bytes, int]]], completion: str = "complete") -> Path:
    bundle_dir = root / "bundle"
    (bundle_dir / "runs").mkdir(parents=True)
    cases = []
    for case_id, items in runs.items():
        case = CORPUS.case(case_id)
        base, head = plan_revisions(case)[:2]
        (bundle_dir / "runs" / case_id).mkdir()
        records = []
        for index, (stdout, latency) in enumerate(items, start=1):
            files = {}
            for stream, data in (("stdout", stdout), ("stderr", b"")):
                relative = f"runs/{case_id}/run-{index}.{stream}"
                (bundle_dir / relative).write_bytes(data)
                files[stream] = {"path": relative, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
            records.append({
                "run_index": index, "started_at": "2026-11-09T00:00:00Z", "termination": "exited", "exit_code": 4,
                "signal": None, "latency_ns": latency, **files, "result": summarize_result(stdout),
            })
        cases.append({
            "case_id": case_id, "labels_sha256": case.labels_sha256, "repository_name": f"case-{CORPUS.cases.index(case) + 1:02d}",
            "base_revision": base, "head_revision": head, "runs": records,
        })
    bundle = {
        "contract": "open-trestle/model-corpus-run-bundle", "schema_version": 1, "review_state": "pending",
        "release_evidence_eligible": False, "label_status": LABEL_STATUS, "completion": completion,
        "corpus_identity": CORPUS.identity, "manifest_sha256": CORPUS.manifest_sha256, "driver": "open_trestle_eval.model_runs/1",
        "trestle_path": "/synthetic/trestle", "trestle_sha256": "a" * 64, "runs_per_case": 3,
        "operator_arguments": ["--tenant", "t", "--repository", "r", "--route-inventory", "/i", "--runtime-policy", "/p", "--egress", "local-only", "--timeout", "1m"],
        "repository_authority": "corpus.invalid", "repository_namespace": "model-corpus-v1", "revision_algorithm": "sha1",
        "process_timeout_seconds": 120, "environment": {"os": "Linux", "release": "synthetic", "architecture": "x86_64", "python": "3"},
        "started_at": "2026-11-09T00:00:00Z", "finished_at": "2026-11-09T00:01:00Z", "cases": cases,
    }
    validate(BUNDLE_SCHEMA, bundle)
    (bundle_dir / "bundle.json").write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
    return bundle_dir


def every_number_is_labelled(test: unittest.TestCase, metrics: dict, label_status: str = LABEL_STATUS) -> None:
    for key, value in metrics.items():
        test.assertIsInstance(value, dict, key)
        test.assertEqual(value["label_status"], label_status, key)
        for inner in value.values():
            if isinstance(inner, dict):
                test.assertEqual(inner["label_status"], label_status, key)


def relabelled(metrics: dict) -> dict:
    """Returns pending metrics with every number relabelled as adjudicated."""
    return json.loads(json.dumps(metrics).replace(f'"{LABEL_STATUS}"', f'"{ADJUDICATED}"'))


def adjudication(corpus=CORPUS, excluded: dict[str, str] | None = None):
    """Imports a synthetic record; no person reviewed the corpus for it."""
    data = encode(synthetic_record(corpus, excluded))
    return import_adjudication(corpus, data, pin(data))


class ReadReviewTest(unittest.TestCase):
    def test_classifies_outcomes_and_reads_categories_and_sides(self) -> None:
        review = read_review(result(finding("page.go", 33, 35, side="base"), finding("page.go", 33, 33, category=None)))
        self.assertEqual((review.completion, review.outcome), ("completed", "findings"))
        self.assertEqual([(item.side, item.category) for item in review.findings], [("base", "correctness"), ("head", None)])
        self.assertEqual(read_review(result(inconclusive=1)).outcome, "abstention")
        self.assertEqual(read_review(result(rejected=2)).outcome, "no_finding")
        self.assertEqual(read_review(result()).outcome, "no_finding")
        self.assertEqual(read_review(refused()).completion, "not_completed")
        self.assertEqual(read_review(result(status="incomplete", diagnostics=False)).completion, "not_completed")

    def test_unreadable_results_are_not_scored(self) -> None:
        good = result(finding("a.go", 1, 1))
        document = json.loads(good)
        variants = [
            b"not json\n",
            good[:-1],
            good + good,
            json.dumps({**document, "schema_version": 2}).encode() + b"\n",
            json.dumps({**document, "schema_version": True}).encode() + b"\n",
            json.dumps({**document, "contract": "other"}).encode() + b"\n",
            json.dumps({**document, "status": "no_candidates"}).encode() + b"\n",
            json.dumps({**document, "diagnostics": {**document["diagnostics"], "schema_version": 4}}).encode() + b"\n",
            json.dumps({**document, "finding_guidance": [{"finding_identity": "x", "category": "naming"}]}).encode() + b"\n",
            json.dumps({**document, "schema_version": 6}).encode() + b"\n",
            json.dumps({**document, "token_usage": KNOWN_TOKENS}).encode() + b"\n",
            json.dumps({**document, "schema_version": 6, "token_usage": {**KNOWN_TOKENS, "known": False}}).encode() + b"\n",
            json.dumps({**document, "schema_version": 6, "token_usage": {**UNKNOWN_TOKENS, "input_tokens": 0}}).encode() + b"\n",
        ]
        broken = json.loads(good)
        broken["diagnostics"]["findings"][0]["end_line"] = 0
        variants.append(json.dumps(broken).encode() + b"\n")
        for raw in variants:
            with self.subTest(raw=raw[:60]):
                self.assertEqual(read_review(raw).completion, "unreadable")


class ScoreBundleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def score(self, runs: dict, completion: str = "complete") -> dict:
        report = score_bundle(CORPUS, write_bundle(self.root, runs, completion))
        validate(SCORE_SCHEMA, report)
        self.assertEqual((report["review_state"], report["label_status"], report["release_evidence_eligible"], report["golden_status"]),
                         ("pending", LABEL_STATUS, False, "prohibited_pending_human_review"))
        every_number_is_labelled(self, report["aggregate"])
        for case in report["cases"]:
            every_number_is_labelled(self, case["metrics"])
        return report

    def test_matches_on_path_side_lines_and_category(self) -> None:
        report = self.score({
            "defect_off_by_one": [
                (result(finding("tail.go", 25, 26)), 1000),
                (result(finding("tail.go", 5, 5)), 2000),
                (result(), 3000),
            ],
            "deletion_bounds_check": [
                (result(finding("page.go", 33, 35, side="base")), 10),
                (result(finding("page.go", 33, 33, category="reliability")), 20),
                (result(finding("page.go", 34, 34)), 30),
            ],
        })
        off_by_one, bounds = report["cases"]
        self.assertEqual([len(run["matches"]) for run in off_by_one["runs"]], [1, 0, 0])
        self.assertEqual(off_by_one["runs"][1]["false_positives"][0]["class"], "other")
        self.assertEqual([run["false_negatives"] for run in off_by_one["runs"]], [[], ["f1"], ["f1"]])
        self.assertEqual(off_by_one["metrics"]["counts"]["true_positive"], 1)
        self.assertEqual(off_by_one["metrics"]["recall"], {"label_status": LABEL_STATUS, "numerator": 1, "denominator": 3})
        self.assertEqual(off_by_one["metrics"]["precision"], {"label_status": LABEL_STATUS, "numerator": 1, "denominator": 2})
        self.assertEqual(off_by_one["metrics"]["outcome_agreement"]["numerator"], 2)
        # Base-side removed lines and the head-side deletion point both count;
        # head line 34 is a different line in a different coordinate space.
        self.assertEqual([len(run["matches"]) for run in bounds["runs"]], [1, 1, 0])
        self.assertEqual(bounds["runs"][2]["false_positives"][0]["side"], "head")
        aggregate = report["aggregate"]
        self.assertEqual((aggregate["counts"]["true_positive"], aggregate["counts"]["false_positive"], aggregate["counts"]["false_negative"]), (3, 2, 3))
        self.assertEqual(aggregate["latency_ns"]["sample_count"], 6)
        self.assertEqual((aggregate["latency_ns"]["minimum"], aggregate["latency_ns"]["maximum"]), (10, 3000))
        values = [1000, 2000, 3000]
        spread = off_by_one["metrics"]["latency_ns"]
        self.assertEqual(spread["mean"], 2000)
        self.assertEqual(spread["sample_standard_deviation"], round(math.sqrt(sum((v - 2000) ** 2 for v in values) / 2), 3))

    def test_classifies_false_positives(self) -> None:
        report = self.score({
            "defect_data_race": [
                (result(finding("fetch.go", 29, 29, category="concurrency"), finding("fetch.go", 29, 29, category="correctness", salt="2")), 1),
                (result(finding("fetch.go", 29, 29, category="style")), 1),
                (result(finding("fetch.go", 28, 28, category="concurrency"), finding("fetch.go", 29, 29, category=None, salt="3")), 1),
            ],
        })
        runs = report["cases"][0]["runs"]
        self.assertEqual([item["class"] for item in runs[0]["false_positives"]], ["duplicate"])
        self.assertEqual([item["class"] for item in runs[1]["false_positives"]], ["category_mismatch"])
        self.assertEqual(runs[1]["false_negatives"], ["f1"])
        self.assertEqual([(item["class"], item["trap_id"]) for item in runs[2]["false_positives"]], [("near_miss", "t1")])
        self.assertEqual(runs[2]["matches"][0]["category_checked"], False)
        counts = report["aggregate"]["counts"]
        self.assertEqual(
            (counts["duplicate_false_positive"], counts["category_mismatch_false_positive"], counts["near_miss_false_positive"], counts["category_unchecked_true_positive"]),
            (1, 1, 1, 1),
        )

    def test_near_misses_clean_changes_abstentions_and_incomplete_runs(self) -> None:
        report = self.score({
            "abstention_unit_unknown": [
                (result(inconclusive=1), 5),
                (result(finding("session.go", 29, 29, category="correctness")), 5),
                (result(), 5),
            ],
            "clean_rename": [(refused(), 1), (b"garbage\n", 1), (result(rejected=1), 7)],
            "near_miss_loop_variable_go122": [
                (result(finding("notify.go", 19, 19, category="concurrency")), 3),
                (result(finding("notify.go", 17, 17, side="base", category="concurrency")), 3),
                (result(), 3),
            ],
        })
        aggregate = report["aggregate"]
        self.assertEqual(aggregate["runs"], {"label_status": LABEL_STATUS, "total": 9, "completed": 7, "not_completed": 1, "unreadable": 1})
        self.assertEqual(aggregate["abstention"]["correctness"], {"label_status": LABEL_STATUS, "numerator": 1, "denominator": 3})
        self.assertEqual((aggregate["abstention"]["overclaimed"], aggregate["abstention"]["silent"]), (1, 1))
        self.assertEqual(aggregate["false_positive_rate"], {"label_status": LABEL_STATUS, "numerator": 2, "denominator": 4})
        self.assertEqual(aggregate["near_miss_false_positive_rate"], {"label_status": LABEL_STATUS, "numerator": 2, "denominator": 3})
        self.assertEqual(aggregate["counts"]["near_miss_false_positive"], 3)
        self.assertEqual(aggregate["precision"], {"label_status": LABEL_STATUS, "numerator": 0, "denominator": 3})
        self.assertEqual(aggregate["recall"], {"label_status": LABEL_STATUS, "numerator": 0, "denominator": 0})
        clean = report["cases"][1]
        self.assertEqual([run["completion"] for run in clean["runs"]], ["not_completed", "unreadable", "completed"])
        self.assertEqual(clean["metrics"]["latency_ns"]["sample_count"], 1)
        self.assertEqual(clean["runs"][0]["outcome_matches_expected"], None)
        # No result here reports token usage, so every completed run is unknown.
        for key in ("input_tokens", "output_tokens", "cached_input_tokens"):
            self.assertEqual((aggregate["tokens"][key]["sample_count"], aggregate["tokens"][key]["unknown_count"], aggregate["tokens"][key]["mean"]), (0, 7, None))
        self.assertEqual([run["token_usage"] for run in clean["runs"]], [None, None, None])

    def test_token_spread_counts_unknown_and_earlier_results(self) -> None:
        report = self.score({
            "clean_rename": [
                (result(version=6, token_usage=tokens(900, 300, 120)), 1),
                (result(version=6, token_usage=tokens(1500, 600, 0)), 1),
                (result(version=6, usage_known=False, cost=0, token_usage=UNKNOWN_TOKENS), 1),
            ],
            "clean_extract_function": [
                (result(version=4), 1),
                (result(version=6, token_usage=tokens(1200, 450, 60)), 1),
                (result(status="failed", diagnostics=False, usage_known=False, cost=0, version=6, token_usage=tokens(600, 200, 0)), 1),
            ],
        })
        spread = report["aggregate"]["tokens"]
        self.assertEqual(spread["label_status"], LABEL_STATUS)
        for key, values in (("input_tokens", [900, 1500, 1200]), ("output_tokens", [300, 600, 450]), ("cached_input_tokens", [120, 0, 60])):
            mean = sum(values) / 3
            self.assertEqual(
                (spread[key]["sample_count"], spread[key]["unknown_count"], spread[key]["mean"], spread[key]["minimum"], spread[key]["maximum"]),
                (3, 2, round(mean, 3), min(values), max(values)),
            )
            self.assertEqual(spread[key]["sample_standard_deviation"], round(math.sqrt(sum((value - mean) ** 2 for value in values) / 2), 3))
        rename, extract = report["cases"]
        self.assertEqual([run["token_usage"] for run in rename["runs"]], [tokens(900, 300, 120), tokens(1500, 600, 0), UNKNOWN_TOKENS])
        self.assertEqual([run["token_usage"] for run in extract["runs"]], [None, tokens(1200, 450, 60), tokens(600, 200, 0)])
        self.assertEqual(rename["metrics"]["tokens"]["input_tokens"]["mean"], 1200)
        for mutate in (
            lambda value: value["aggregate"]["tokens"]["input_tokens"].update(unknown_count=None),
            lambda value: value["cases"][0]["runs"][2]["token_usage"].update(input_tokens=0),
            lambda value: value["cases"][0]["runs"][0]["token_usage"].update(known=False),
        ):
            altered = json.loads(json.dumps(report))
            mutate(altered)
            with self.assertRaises(SchemaError):
                validate(SCORE_SCHEMA, altered)

    def test_refuses_a_bundle_whose_token_usage_disagrees_with_its_result(self) -> None:
        bundle_dir = write_bundle(self.root, {"clean_rename": [(result(version=6, token_usage=tokens(900, 300, 120)), 1)]})
        index = json.loads((bundle_dir / "bundle.json").read_text(encoding="utf-8"))
        for name, recorded in (("changed", tokens(901, 300, 120)), ("absent", None)):
            with self.subTest(name=name):
                altered = json.loads(json.dumps(index))
                altered["cases"][0]["runs"][0]["result"]["token_usage"] = recorded
                (bundle_dir / "bundle.json").write_text(json.dumps(altered), encoding="utf-8")
                with self.assertRaisesRegex(ScoreError, "token usage"):
                    score_bundle(CORPUS, bundle_dir)

    def test_an_unreadable_result_with_token_usage_is_one_unscored_run(self) -> None:
        # A result no build writes, version 5 with token usage, is one
        # unreadable run, not a refused bundle, though the driver copied it.
        report = self.score({"clean_rename": [(result(version=5, token_usage=tokens(900, 300, 120)), 1), (result(version=6, token_usage=tokens(900, 300, 120)), 1)]})
        self.assertEqual([run["completion"] for run in report["cases"][0]["runs"]], ["unreadable", "completed"])
        self.assertEqual(report["aggregate"]["tokens"]["input_tokens"]["sample_count"], 1)

    def test_cost_spread_counts_unknown_usage(self) -> None:
        report = self.score({
            "clean_rename": [(result(cost=100), 1), (result(cost=300), 1), (result(usage_known=False, cost=0), 1)],
        })
        cost = report["aggregate"]["cost_micro_usd"]
        self.assertEqual((cost["sample_count"], cost["unknown_count"], cost["mean"], cost["minimum"], cost["maximum"]), (2, 1, 200, 100, 300))
        self.assertEqual(cost["sample_standard_deviation"], round(math.sqrt(20000), 3))
        single = self.score_empty_spread()
        self.assertIsNone(single["sample_standard_deviation"])

    def score_empty_spread(self) -> dict:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        report = score_bundle(CORPUS, write_bundle(Path(directory.name), {"clean_rename": [(result(), 9)]}))
        return report["aggregate"]["latency_ns"]

    def test_score_schema_refuses_an_adjudicated_report(self) -> None:
        report = self.score({"clean_rename": [(result(), 1)]})
        for mutate in (
            lambda value: value.update(release_evidence_eligible=True),
            lambda value: value.update(label_status="adjudicated"),
            lambda value: value["aggregate"]["precision"].update(label_status="adjudicated"),
            lambda value: value["aggregate"]["counts"].update(extra=1),
        ):
            altered = json.loads(json.dumps(report))
            mutate(altered)
            with self.assertRaises(SchemaError):
                validate(SCORE_SCHEMA, altered)

    def test_refuses_a_bundle_that_does_not_bind_this_corpus(self) -> None:
        bundle_dir = write_bundle(self.root, {"clean_rename": [(result(), 1)]})
        index = json.loads((bundle_dir / "bundle.json").read_text(encoding="utf-8"))
        edits = {
            "corpus": lambda value: value.update(corpus_identity="b" * 64),
            "labels": lambda value: value["cases"][0].update(labels_sha256="c" * 64),
            "revision": lambda value: value["cases"][0].update(head_revision="d" * 40),
            "unknown case": lambda value: value["cases"][0].update(case_id="missing_case"),
            "repeated case": lambda value: value["cases"].append(value["cases"][0]),
            "run order": lambda value: value["cases"][0]["runs"][0].update(run_index=2),
            "escape": lambda value: value["cases"][0]["runs"][0]["stdout"].update(path="../bundle.json"),
            "contract": lambda value: value.update(contract="other"),
        }
        for name, edit in edits.items():
            with self.subTest(name=name):
                altered = json.loads(json.dumps(index))
                edit(altered)
                (bundle_dir / "bundle.json").write_text(json.dumps(altered), encoding="utf-8")
                with self.assertRaises(ScoreError):
                    score_bundle(CORPUS, bundle_dir)
        (bundle_dir / "bundle.json").write_text(json.dumps(index), encoding="utf-8")
        stdout = bundle_dir / "runs/clean_rename/run-1.stdout"
        stdout.write_bytes(stdout.read_bytes().replace(b"no_candidates", b"no_candidatez"))
        with self.assertRaisesRegex(ScoreError, "does not match its pin"):
            score_bundle(CORPUS, bundle_dir)

    def test_scores_a_bundle_the_driver_wrote(self) -> None:
        trestle = self.root / "trestle"
        trestle.write_text(FAKE_TRESTLE, encoding="utf-8")
        trestle.chmod(0o700)
        case = CORPUS.case("deletion_authz_check")
        canned = result(finding("service.go", 49, 51, side="base", category="security")).decode()
        config = self.root / "fake.json"
        config.write_text(json.dumps({"log": str(self.root / "log"), "results": {}, "default": {"stdout": canned, "exit": 4}}), encoding="utf-8")
        (self.root / "routes.json").write_text("{}", encoding="utf-8")
        (self.root / "policy.json").write_text("{}", encoding="utf-8")
        with patch.dict(os.environ, {"FAKE_TRESTLE_CONFIG": str(config)}):
            run_corpus(
                corpus=CORPUS, cases=[case], trestle=trestle.resolve(), runs=2,
                operator_arguments=operator_flags(self.root), output=self.root / "driven",
                repository_authority="corpus.invalid", repository_namespace="model-corpus-v1",
            )
        report = score_bundle(CORPUS, self.root / "driven")
        validate(SCORE_SCHEMA, report)
        self.assertEqual(report["aggregate"]["recall"], {"label_status": LABEL_STATUS, "numerator": 2, "denominator": 2})
        self.assertEqual(report["aggregate"]["latency_ns"]["sample_count"], 2)

    def test_command_line_writes_a_new_pending_report(self) -> None:
        bundle_dir = write_bundle(self.root, {"clean_rename": [(result(), 1)]}, completion="interrupted")
        output = self.root / "score.json"
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(main(["--bundle", str(bundle_dir), "--output", str(output)]), 4)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["bundle_completion"], "interrupted")
            self.assertEqual(report["bundle_sha256"], hashlib.sha256((bundle_dir / "bundle.json").read_bytes()).hexdigest())
            self.assertEqual(main(["--bundle", str(bundle_dir), "--output", str(output)]), 1)
        self.assertIn("not release evidence", stderr.getvalue())


class AdjudicatedScoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def bundle(self, runs: dict, completion: str = "complete", name: str = "bundle") -> Path:
        parent = self.root / name
        parent.mkdir()
        return write_bundle(parent, runs, completion)

    @staticmethod
    def every_case_runs() -> dict:
        runs = {case.id: [(result(), 5)] for case in CORPUS.cases}
        runs["defect_off_by_one"] = [(result(finding("tail.go", 25, 26)), 1000), (result(), 2000)]
        return runs

    def adjudicated(self, bundle_dir: Path, record) -> dict:
        report = score_bundle(CORPUS, bundle_dir, record)
        validate(ADJUDICATED_SCHEMA, report)
        self.assertEqual(
            (report["contract"], report["label_status"], report["provenance_status"], report["acceptance_status"]),
            ("open-trestle/model-corpus-adjudicated-score", ADJUDICATED, "externally_asserted", "not_decided"),
        )
        self.assertNotIn(LABEL_STATUS, json.dumps(report))
        every_number_is_labelled(self, report["aggregate"], ADJUDICATED)
        for case in report["cases"]:
            every_number_is_labelled(self, case["metrics"], ADJUDICATED)
        return report

    def test_a_full_confirmation_scores_every_case_as_adjudicated(self) -> None:
        bundle_dir = self.bundle(self.every_case_runs())
        record = adjudication()
        report = self.adjudicated(bundle_dir, record)
        pending = score_bundle(CORPUS, bundle_dir)
        validate(SCORE_SCHEMA, pending)
        # The same matching produces the same numbers; only their status differs.
        self.assertEqual(report["aggregate"], relabelled(pending["aggregate"]))
        self.assertEqual(report["cases"], relabelled(pending["cases"]))
        for key in ("scorer", "corpus_identity", "manifest_sha256", "bundle_sha256", "bundle_completion", "matching"):
            self.assertEqual(report[key], pending[key], key)
        self.assertEqual(report["aggregate"]["counts"]["true_positive"], 1)
        self.assertEqual((report["release_evidence_eligible"], report["release_evidence_blockers"], report["excluded_cases"]), (True, [], []))
        self.assertEqual(report["adjudication"], {
            "contract": "open-trestle/model-corpus-human-adjudication", "schema_version": 1, "record_sha256": record.record_sha256,
            "case_count": 23, "confirmed_count": 23, "excluded_count": 0,
        })
        self.assertNotIn("synthetic-test-reviewer", json.dumps(report))

    def test_a_revised_case_is_excluded_and_reported_with_its_reason(self) -> None:
        runs = self.every_case_runs()
        bundle_dir = self.bundle(runs)
        record = adjudication(excluded={"defect_off_by_one": "revised"})
        report = self.adjudicated(bundle_dir, record)
        self.assertEqual([case["case_id"] for case in report["cases"]], [case.id for case in CORPUS.cases if case.id != "defect_off_by_one"])
        self.assertEqual(report["excluded_cases"], [{
            "case_id": "defect_off_by_one", "case_kind": "defect", "labels_sha256": CORPUS.case("defect_off_by_one").labels_sha256,
            "decision": "revised", "reason": SYNTHETIC_REASON, "runs_not_scored": 2,
        }])
        self.assertEqual((report["release_evidence_eligible"], report["release_evidence_blockers"]), (False, ["cases_excluded_by_review"]))
        self.assertEqual((report["adjudication"]["confirmed_count"], report["adjudication"]["excluded_count"]), (22, 1))
        # The excluded case's runs leave every number.
        self.assertEqual((report["aggregate"]["counts"]["true_positive"], report["aggregate"]["runs"]["total"]), (0, 22))
        without = {key: value for key, value in runs.items() if key != "defect_off_by_one"}
        self.assertEqual(report["aggregate"], relabelled(score_bundle(CORPUS, self.bundle(without, name="without"))["aggregate"]))
        # An excluded case's runs are still checked against their pins.
        stdout = bundle_dir / "runs/defect_off_by_one/run-1.stdout"
        stdout.write_bytes(stdout.read_bytes().replace(b"tail.go", b"tail.gx"))
        with self.assertRaisesRegex(ScoreError, "does not match its pin"):
            score_bundle(CORPUS, bundle_dir, record)

    def test_a_partial_or_unfinished_bundle_is_not_release_evidence(self) -> None:
        record = adjudication()
        partial = self.adjudicated(self.bundle({"clean_rename": [(result(), 1)]}, name="partial"), record)
        self.assertEqual((partial["release_evidence_eligible"], partial["release_evidence_blockers"]), (False, ["bundle_omits_cases"]))
        interrupted = self.adjudicated(self.bundle(self.every_case_runs(), completion="interrupted", name="interrupted"), record)
        self.assertEqual((interrupted["release_evidence_eligible"], interrupted["release_evidence_blockers"]), (False, ["bundle_not_complete"]))
        excluded = adjudication(excluded={"clean_rename": "rejected", "defect_off_by_one": "revised"})
        everything = self.adjudicated(self.bundle({"clean_rename": [(result(), 1)]}, completion="in_progress", name="everything"), excluded)
        self.assertEqual(everything["release_evidence_blockers"], ["cases_excluded_by_review", "bundle_omits_cases", "bundle_not_complete"])
        self.assertEqual((everything["cases"], everything["aggregate"]["runs"]["total"]), ([], 0))
        self.assertEqual([(case["case_id"], case["runs_not_scored"]) for case in everything["excluded_cases"]], [("clean_rename", 1), ("defect_off_by_one", 0)])

    def test_refuses_a_record_or_bundle_whose_digests_differ(self) -> None:
        bundle_dir = self.bundle({"clean_rename": [(result(), 1)]})
        other_root = self.root / "corpus"
        shutil.copytree(default_corpus_root(), other_root)
        labels_path = other_root / "cases/clean_rename/labels.json"
        labels = json.loads(labels_path.read_text(encoding="utf-8"))
        labels["go_semantics"] += " Synthetic revision."
        labels_path.write_text(json.dumps(labels, indent=2) + "\n", encoding="utf-8")
        manifest, pending = refresh_manifest(other_root)
        (other_root / "manifest.json").write_bytes(manifest)
        (other_root / "adjudication.json").write_bytes(pending)
        other = load_corpus(other_root)
        self.assertNotEqual(other.case("clean_rename").labels_sha256, CORPUS.case("clean_rename").labels_sha256)
        # A record of another corpus version does not bind these labels.
        with self.assertRaisesRegex(ScoreError, "adjudication record does not bind this corpus"):
            score_bundle(CORPUS, bundle_dir, adjudication(other))
        record = adjudication()
        first = record.decisions[0]
        for name, tampered in (
            ("label digest", dataclasses.replace(record, decisions=(dataclasses.replace(first, labels_sha256="e" * 64), *record.decisions[1:]))),
            ("case order", dataclasses.replace(record, decisions=(record.decisions[1], first, *record.decisions[2:]))),
            ("missing case", dataclasses.replace(record, decisions=record.decisions[1:])),
            ("manifest", dataclasses.replace(record, manifest_sha256="f" * 64)),
        ):
            with self.subTest(name=name):
                with self.assertRaisesRegex(ScoreError, "adjudication record does not bind this corpus"):
                    score_bundle(CORPUS, bundle_dir, tampered)
        # A bundle captured from other labels is refused before any score.
        with self.assertRaisesRegex(ScoreError, "different corpus"):
            score_bundle(other, bundle_dir, adjudication(other))
        index = json.loads((bundle_dir / "bundle.json").read_text(encoding="utf-8"))
        index["cases"][0]["labels_sha256"] = other.case("clean_rename").labels_sha256
        (bundle_dir / "bundle.json").write_text(json.dumps(index), encoding="utf-8")
        with self.assertRaisesRegex(ScoreError, "does not match the corpus labels"):
            score_bundle(CORPUS, bundle_dir, record)

    def test_adjudicated_schema_refuses_inconsistent_reports(self) -> None:
        report = self.adjudicated(self.bundle(self.every_case_runs()), adjudication())
        excluded_row = {
            "case_id": "clean_rename", "case_kind": "clean", "labels_sha256": CORPUS.case("clean_rename").labels_sha256,
            "decision": "rejected", "reason": SYNTHETIC_REASON, "runs_not_scored": 1,
        }
        for name, mutate in {
            "eligible with a blocker": lambda value: value.update(release_evidence_blockers=["bundle_not_complete"]),
            "ineligible without a blocker": lambda value: value.update(release_evidence_eligible=False),
            "eligible with an excluded case": lambda value: value["excluded_cases"].append(excluded_row),
            "pending status": lambda value: value.update(label_status=LABEL_STATUS),
            "pending number": lambda value: value["aggregate"]["precision"].update(label_status=LABEL_STATUS),
            "verified provenance": lambda value: value.update(provenance_status="verified"),
            "decided acceptance": lambda value: value.update(acceptance_status="accepted"),
            "reviewer echoed": lambda value: value["adjudication"].update(reviewer_identifier="synthetic-test-reviewer"),
            "unknown blocker": lambda value: value.update(release_evidence_eligible=False, release_evidence_blockers=["threshold_unmet"]),
            "golden status": lambda value: value.update(golden_status="prohibited_pending_human_review"),
        }.items():
            with self.subTest(name=name):
                altered = json.loads(json.dumps(report))
                mutate(altered)
                with self.assertRaises(SchemaError):
                    validate(ADJUDICATED_SCHEMA, altered)
        altered = json.loads(json.dumps(report))
        altered.update(release_evidence_eligible=False, release_evidence_blockers=["cases_excluded_by_review"])
        altered["excluded_cases"].append(excluded_row)
        validate(ADJUDICATED_SCHEMA, altered)

    def test_adjudicated_schema_keeps_the_pending_score_definitions(self) -> None:
        definitions = dict(ADJUDICATED_SCHEMA["$defs"])
        excluded_case = definitions.pop("excluded_case")
        self.assertEqual(definitions, relabelled(SCORE_SCHEMA["$defs"]))
        self.assertEqual(excluded_case["properties"]["case_kind"], SCORE_SCHEMA["$defs"]["case"]["properties"]["case_kind"])
        for key in ("scorer", "corpus_identity", "manifest_sha256", "bundle_sha256", "bundle_completion", "matching"):
            self.assertEqual(ADJUDICATED_SCHEMA["properties"][key], SCORE_SCHEMA["properties"][key], key)

    def test_command_line_imports_the_pinned_record(self) -> None:
        bundle_dir = self.bundle(self.every_case_runs())
        data = encode(synthetic_record())
        record = self.root / "record.json"
        record.write_bytes(data)
        output = self.root / "score.json"
        arguments = ["--bundle", str(bundle_dir), "--adjudication", str(record), "--output", str(output)]
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(main([*arguments, "--adjudication-sha256", pin(data + b" ")]), 1)
            self.assertFalse(output.exists())
            self.assertEqual(main([*arguments, "--adjudication-sha256", pin(data)]), 4)
            for partial in (["--bundle", str(bundle_dir), "--adjudication", str(record)], ["--bundle", str(bundle_dir), "--adjudication-sha256", pin(data)]):
                with self.assertRaises(SystemExit) as raised:
                    main(partial)
                self.assertEqual(raised.exception.code, 2)
        report = json.loads(output.read_text(encoding="utf-8"))
        validate(ADJUDICATED_SCHEMA, report)
        self.assertEqual((report["release_evidence_eligible"], report["adjudication"]["record_sha256"]), (True, pin(data)))
        self.assertIn("pinned SHA-256", stderr.getvalue())
        self.assertIn("adjudicated score written", stderr.getvalue())
        self.assertIn("release_evidence_eligible=true", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
