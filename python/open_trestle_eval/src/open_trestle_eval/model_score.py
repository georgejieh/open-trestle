"""Scores a model-review corpus run bundle against the pending labels.

Every number is labelled ``labels_pending_human_review`` and the report is
never release evidence: the labels are fixture-author labels that no
independent reviewer has adjudicated.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import math
import os
import re
import sys
from pathlib import Path
from typing import Any, Sequence

from .model_corpus import (
    CATEGORIES,
    LABEL_STATUS,
    Corpus,
    CorpusCase,
    CorpusError,
    decode_json,
    default_corpus_root,
    load_corpus,
    plan_revisions,
)
from .model_runs import BUNDLE_CONTRACT, MAX_STDOUT_BYTES

SCORER = "open_trestle_eval.model_score/1"
SCORE_CONTRACT = "open-trestle/model-corpus-score"
RESULT_CONTRACT = "open-trestle/local-git-model-review-result"
DIAGNOSTIC_CONTRACT = "open-trestle/review-diagnostic-set"
RESULT_VERSIONS = (1, 3, 4, 5)
DIAGNOSTIC_VERSIONS = (5, 8)
COMPLETED_STATUSES = ("findings", "no_candidates", "incomplete")
STATUSES = (*COMPLETED_STATUSES, "refused", "canceled", "failed")
SEVERITIES = ("error", "warning", "information", "hint")
LIMITATIONS = (
    "labels_pending_human_review",
    "location_and_category_matching_not_claim_semantics",
    "not_completed_and_unreadable_runs_excluded_from_rates",
    "result_identities_not_reverified",
    "result_records_no_consumed_token_counts",
    "small_synthetic_corpus",
)
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_RUN_PATH = re.compile(r"^runs/[a-z][a-z0-9_]{0,63}/run-[0-9]{1,2}\.stdout$")


class ScoreError(ValueError):
    """Reports a bundle that cannot be scored without echoing its content."""


@dataclasses.dataclass(frozen=True)
class ObservedFinding:
    identity: str
    path: str
    side: str
    start_line: int
    end_line: int
    category: str | None
    severity: str


@dataclasses.dataclass(frozen=True)
class Review:
    completion: str
    status: str | None
    outcome: str | None
    coverage: dict[str, int] | None
    findings: tuple[ObservedFinding, ...]
    usage_known: bool | None
    actual_cost_micro_usd: int | None


_UNREADABLE = Review("unreadable", None, None, None, (), None, None)


def _int(value: Any, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ScoreError("invalid integer")
    return value


def read_review(stdout: bytes) -> Review:
    """Extracts the verified findings and coverage from one captured result.

    The result's sealed identities are not recomputed here; feed a capture to
    ``trestle evaluate model-result`` when byte-level provenance matters.
    """
    if len(stdout) > MAX_STDOUT_BYTES or not stdout.endswith(b"\n") or b"\n" in stdout[:-1]:
        return _UNREADABLE
    try:
        value = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return _UNREADABLE
    if not isinstance(value, dict) or value.get("contract") != RESULT_CONTRACT or value.get("schema_version") not in RESULT_VERSIONS or type(value.get("schema_version")) is not int:
        return _UNREADABLE
    status = value.get("status")
    if status not in STATUSES:
        return _UNREADABLE
    usage_known = value.get("usage_known") if type(value.get("usage_known")) is bool else None
    cost = value.get("actual_cost_micro_usd") if type(value.get("actual_cost_micro_usd")) is int and value["actual_cost_micro_usd"] >= 0 else None
    diagnostics = value.get("diagnostics")
    if status not in COMPLETED_STATUSES or diagnostics is None:
        return Review("not_completed", status, None, None, (), usage_known, cost)
    try:
        if not isinstance(diagnostics, dict) or diagnostics.get("contract") != DIAGNOSTIC_CONTRACT or diagnostics.get("schema_version") not in DIAGNOSTIC_VERSIONS:
            raise ScoreError("unsupported diagnostic set")
        raw_coverage = diagnostics["coverage"]
        coverage = {key: _int(raw_coverage[key]) for key in ("candidate_count", "verified_count", "rejected_count", "inconclusive_count")}
        categories: dict[str, str] = {}
        guidance = value.get("finding_guidance", [])
        if not isinstance(guidance, list):
            raise ScoreError("invalid finding guidance")
        for entry in guidance:
            if not isinstance(entry, dict) or entry.get("category") not in CATEGORIES or not isinstance(entry.get("finding_identity"), str):
                raise ScoreError("invalid finding guidance")
            categories[entry["finding_identity"]] = entry["category"]
        findings = []
        for raw in diagnostics["findings"]:
            side = raw.get("side", "head")
            path = raw["path"]
            start, end = _int(raw["start_line"], 1), _int(raw["end_line"], 1)
            if (
                side not in ("head", "base")
                or not isinstance(path, str)
                or not path
                or end < start
                or raw.get("severity") not in SEVERITIES
                or not isinstance(raw.get("identity"), str)
                or not _DIGEST.match(raw["identity"])
                or not isinstance(raw.get("source_identity"), str)
            ):
                raise ScoreError("invalid diagnostic finding")
            findings.append(
                ObservedFinding(raw["identity"], path, side, start, end, categories.get(raw["source_identity"]), raw["severity"])
            )
        if coverage["verified_count"] != len(findings) or (status == "findings") != bool(findings):
            raise ScoreError("result status and findings disagree")
        if coverage["verified_count"] + coverage["rejected_count"] + coverage["inconclusive_count"] != coverage["candidate_count"]:
            raise ScoreError("coverage counts disagree")
    except (ScoreError, KeyError, TypeError, AttributeError):
        return _UNREADABLE
    if findings:
        outcome = "findings"
    elif coverage["inconclusive_count"] > 0:
        outcome = "abstention"
    else:
        outcome = "no_finding"
    return Review("completed", status, outcome, coverage, tuple(findings), usage_known, cost)


def _maximum_matching(edges: list[list[int]]) -> dict[int, int]:
    """Returns expected -> observed for a maximum one-to-one assignment."""
    owner: dict[int, int] = {}

    def assign(expected: int, seen: set[int]) -> bool:
        for observed in edges[expected]:
            if observed in seen:
                continue
            seen.add(observed)
            if observed not in owner or assign(owner[observed], seen):
                owner[observed] = expected
                return True
        return False

    for expected in range(len(edges)):
        assign(expected, set())
    return {expected: observed for observed, expected in owner.items()}


def _located(finding: ObservedFinding, locations: Sequence[Any]) -> bool:
    return any(location.overlaps(finding.path, finding.side, finding.start_line, finding.end_line) for location in locations)


def match_run(case: CorpusCase, review: Review) -> dict[str, Any]:
    """Matches one completed run's verified findings to the case labels."""
    observed = review.findings
    edges = [
        [
            index
            for index, finding in enumerate(observed)
            if _located(finding, expected.locations) and (finding.category is None or finding.category in expected.categories)
        ]
        for expected in case.expected_findings
    ]
    assignment = _maximum_matching(edges)
    matched_observed = set(assignment.values())
    matches = []
    for expected_index, observed_index in sorted(assignment.items()):
        expected, finding = case.expected_findings[expected_index], observed[observed_index]
        matches.append({
            "expected_id": expected.id,
            "finding_identity": finding.identity,
            "category_checked": finding.category is not None,
            "severity_hint": expected.severity_hint,
            "observed_severity": finding.severity,
        })
    false_positives = []
    for index, finding in enumerate(observed):
        if index in matched_observed:
            continue
        trap = next((trap.id for trap in case.traps if _located(finding, trap.locations)), None)
        if any(index in edge for edge in edges):
            kind = "duplicate"
        elif trap is not None:
            kind = "near_miss"
        elif any(_located(finding, expected.locations) for expected in case.expected_findings):
            kind = "category_mismatch"
        else:
            kind = "other"
        false_positives.append({
            "finding_identity": finding.identity,
            "path": finding.path,
            "side": finding.side,
            "start_line": finding.start_line,
            "end_line": finding.end_line,
            "category": finding.category,
            "severity": finding.severity,
            "class": kind,
            "trap_id": trap,
        })
    false_negatives = [expected.id for index, expected in enumerate(case.expected_findings) if index not in assignment]
    return {"matches": matches, "false_positives": false_positives, "false_negatives": false_negatives}


def _ratio(numerator: int, denominator: int) -> dict[str, Any]:
    return {"label_status": LABEL_STATUS, "numerator": numerator, "denominator": denominator}


def _spread(values: Sequence[int], unknown: int | None = None) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "label_status": LABEL_STATUS,
        "sample_count": len(values),
        "mean": round(sum(values) / len(values), 3) if values else None,
        "minimum": min(values) if values else None,
        "maximum": max(values) if values else None,
        "sample_standard_deviation": None,
    }
    if len(values) >= 2:
        mean = sum(values) / len(values)
        summary["sample_standard_deviation"] = round(math.sqrt(sum((value - mean) ** 2 for value in values) / (len(values) - 1)), 3)
    if unknown is not None:
        summary["unknown_count"] = unknown
    return summary


class _Tally:
    def __init__(self) -> None:
        self.runs = {"total": 0, "completed": 0, "not_completed": 0, "unreadable": 0}
        self.counts = dict.fromkeys(
            ("true_positive", "false_positive", "false_negative", "near_miss_false_positive", "duplicate_false_positive", "category_mismatch_false_positive", "category_unchecked_true_positive"),
            0,
        )
        self.outcomes = {"findings": 0, "no_finding": 0, "abstention": 0}
        self.agreement = [0, 0]
        self.clean_runs = [0, 0]
        self.near_miss_runs = [0, 0]
        self.abstention = {"correct": 0, "overclaimed": 0, "silent": 0, "total": 0}
        self.latency: list[int] = []
        self.cost: list[int] = []
        self.cost_unknown = 0

    def add(self, case: CorpusCase, review: Review, matched: dict[str, Any] | None, latency_ns: int) -> None:
        self.runs["total"] += 1
        self.runs[review.completion] += 1
        if review.completion != "completed" or matched is None:
            return
        positives = matched["false_positives"]
        self.counts["true_positive"] += len(matched["matches"])
        self.counts["false_positive"] += len(positives)
        self.counts["false_negative"] += len(matched["false_negatives"])
        for key, kind in (("near_miss_false_positive", "near_miss"), ("duplicate_false_positive", "duplicate"), ("category_mismatch_false_positive", "category_mismatch")):
            self.counts[key] += sum(item["class"] == kind for item in positives)
        self.counts["category_unchecked_true_positive"] += sum(not item["category_checked"] for item in matched["matches"])
        self.outcomes[review.outcome] += 1
        self.agreement[0] += review.outcome == case.expected_outcome
        self.agreement[1] += 1
        if case.expected_outcome == "no_finding":
            self.clean_runs[0] += bool(positives)
            self.clean_runs[1] += 1
        if case.kind == "near_miss":
            self.near_miss_runs[0] += any(item["class"] == "near_miss" for item in positives)
            self.near_miss_runs[1] += 1
        if case.expected_outcome == "abstention":
            self.abstention["total"] += 1
            key = {"abstention": "correct", "findings": "overclaimed", "no_finding": "silent"}[review.outcome]
            self.abstention[key] += 1
        self.latency.append(latency_ns)
        if review.usage_known and review.actual_cost_micro_usd is not None:
            self.cost.append(review.actual_cost_micro_usd)
        else:
            self.cost_unknown += 1

    def report(self) -> dict[str, Any]:
        tp, fp, fn = self.counts["true_positive"], self.counts["false_positive"], self.counts["false_negative"]
        return {
            "runs": {"label_status": LABEL_STATUS, **self.runs},
            "counts": {"label_status": LABEL_STATUS, **self.counts},
            "observed_outcomes": {"label_status": LABEL_STATUS, **self.outcomes},
            "precision": _ratio(tp, tp + fp),
            "recall": _ratio(tp, tp + fn),
            "false_positive_rate": _ratio(*self.clean_runs),
            "near_miss_false_positive_rate": _ratio(*self.near_miss_runs),
            "outcome_agreement": _ratio(*self.agreement),
            "abstention": {
                "label_status": LABEL_STATUS,
                "correct": self.abstention["correct"],
                "overclaimed": self.abstention["overclaimed"],
                "silent": self.abstention["silent"],
                "correctness": _ratio(self.abstention["correct"], self.abstention["total"]),
            },
            "latency_ns": _spread(self.latency),
            "cost_micro_usd": _spread(self.cost, self.cost_unknown),
            "tokens": {"label_status": LABEL_STATUS, "known": False, "reason": "result_records_no_consumed_token_counts"},
        }


def _strict_file(bundle_dir: Path, relative: Any, digest: Any, size: Any) -> bytes:
    if not isinstance(relative, str) or not _RUN_PATH.match(relative) or not isinstance(digest, str) or not _DIGEST.match(digest) or type(size) is not int:
        raise ScoreError("invalid run file descriptor")
    path = bundle_dir / relative
    if path.is_symlink() or not path.is_file() or path.stat().st_size != size or size > MAX_STDOUT_BYTES:
        raise ScoreError("run output file is missing or changed")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ScoreError("run output file does not match its pin")
    return data


def score_bundle(corpus: Corpus, bundle_dir: Path) -> dict[str, Any]:
    """Scores every recorded run of a bundle captured from this exact corpus."""
    bundle_dir = Path(bundle_dir)
    index_path = bundle_dir / "bundle.json"
    if index_path.is_symlink() or not index_path.is_file():
        raise ScoreError("bundle.json is missing")
    index_bytes = index_path.read_bytes()
    try:
        bundle = decode_json(index_bytes, 4 * 1024 * 1024)
    except CorpusError as error:
        raise ScoreError("bundle.json is not valid JSON") from error
    if not isinstance(bundle, dict) or bundle.get("contract") != BUNDLE_CONTRACT or bundle.get("schema_version") != 1 or type(bundle.get("schema_version")) is not int:
        raise ScoreError("not a model corpus run bundle")
    if bundle.get("corpus_identity") != corpus.identity or bundle.get("manifest_sha256") != corpus.manifest_sha256:
        raise ScoreError("bundle was captured from a different corpus")
    if bundle.get("completion") not in ("in_progress", "complete", "interrupted", "failed") or not isinstance(bundle.get("cases"), list):
        raise ScoreError("invalid bundle completion or case list")
    by_id = {case.id: case for case in corpus.cases}
    aggregate = _Tally()
    cases = []
    seen = set()
    for item in bundle["cases"]:
        if not isinstance(item, dict) or item.get("case_id") not in by_id or item["case_id"] in seen:
            raise ScoreError("bundle names an unknown or repeated case")
        case = by_id[item["case_id"]]
        seen.add(case.id)
        base, head, _ = plan_revisions(case)
        if item.get("labels_sha256") != case.labels_sha256 or item.get("base_revision") != base or item.get("head_revision") != head:
            raise ScoreError("bundle case does not match the corpus labels or revisions")
        runs = item.get("runs")
        if not isinstance(runs, list):
            raise ScoreError("invalid run list")
        tally = _Tally()
        details = []
        for position, run in enumerate(runs, start=1):
            if not isinstance(run, dict) or run.get("run_index") != position or not isinstance(run.get("stdout"), dict):
                raise ScoreError("run indexes are not sequential")
            stdout = _strict_file(bundle_dir, run["stdout"].get("path"), run["stdout"].get("sha256"), run["stdout"].get("bytes"))
            latency_ns = _int(run.get("latency_ns"))
            review = read_review(stdout)
            matched = match_run(case, review) if review.completion == "completed" else None
            tally.add(case, review, matched, latency_ns)
            aggregate.add(case, review, matched, latency_ns)
            details.append({
                "run_index": position,
                "completion": review.completion,
                "status": review.status,
                "observed_outcome": review.outcome,
                "outcome_matches_expected": None if review.outcome is None else review.outcome == case.expected_outcome,
                "coverage": review.coverage,
                "latency_ns": latency_ns,
                "usage_known": review.usage_known,
                "actual_cost_micro_usd": review.actual_cost_micro_usd,
                "matches": matched["matches"] if matched else [],
                "false_positives": matched["false_positives"] if matched else [],
                "false_negatives": matched["false_negatives"] if matched else [],
            })
        cases.append({
            "case_id": case.id,
            "case_kind": case.kind,
            "expected_outcome": case.expected_outcome,
            "labels_sha256": case.labels_sha256,
            "metrics": tally.report(),
            "runs": details,
        })
    if not cases:
        raise ScoreError("bundle records no case")
    return {
        "contract": SCORE_CONTRACT,
        "schema_version": 1,
        "review_state": "pending",
        "label_status": LABEL_STATUS,
        "release_evidence_eligible": False,
        "golden_status": "prohibited_pending_human_review",
        "scorer": SCORER,
        "corpus_identity": corpus.identity,
        "manifest_sha256": corpus.manifest_sha256,
        "bundle_sha256": hashlib.sha256(index_bytes).hexdigest(),
        "bundle_completion": bundle["completion"],
        "matching": {
            "rule": "same_path_same_side_overlapping_lines_compatible_category",
            "uncategorized_findings": "matched_on_location_only",
            "assignment": "maximum_one_to_one",
        },
        "limitations": list(LIMITATIONS),
        "aggregate": aggregate.report(),
        "cases": cases,
    }


def encode_score(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode("ascii")


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score a model-review corpus run bundle against the pending labels.")
    parser.add_argument("--bundle", type=Path, required=True, help="bundle directory written by open_trestle_eval.model_runs")
    parser.add_argument("--corpus", type=Path, default=None)
    parser.add_argument("--output", type=Path, default=None, help="new file for the report; stdout when absent")
    args = parser.parse_args(arguments)
    try:
        corpus = load_corpus(args.corpus or default_corpus_root())
        encoded = encode_score(score_bundle(corpus, args.bundle))
        if args.output is None:
            sys.stdout.buffer.write(encoded)
        else:
            descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encoded)
    except (OSError, CorpusError, ScoreError) as error:
        print(f"model score: {error}", file=sys.stderr)
        return 1
    print(f"pending score written ({LABEL_STATUS}; not release evidence)", file=sys.stderr)
    return 4


if __name__ == "__main__":
    raise SystemExit(main())
