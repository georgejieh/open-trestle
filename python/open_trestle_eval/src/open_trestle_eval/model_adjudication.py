"""Imports a human-authored adjudication of the model-review corpus labels.

The operator pins the record by the SHA-256 of its exact bytes, taken from the
reviewer's handoff. A matching pin binds those bytes. It does not authenticate
the reviewer, establish independence or prove that a source-first review took
place, so everything the record declares stays externally asserted. Nothing
here writes, generates or fills in a record.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, Sequence

from .model_corpus import FIXTURE_AUTHOR, Corpus, CorpusError, decode_json, default_corpus_root, load_corpus, sha256

RECORD_CONTRACT = "open-trestle/model-corpus-human-adjudication"
RECORD_SCHEMA = "urn:open-trestle:schema:evaluation:model-corpus-human-adjudication:v1"
PROVENANCE_STATUS = "externally_asserted"
MAX_RECORD_BYTES = 1024 * 1024
CONFIRMED = "confirmed"
EXCLUDING_DECISIONS = ("revised", "rejected")

_RECORD_FIELDS = (
    "contract",
    "schema_version",
    "corpus_identity",
    "manifest_sha256",
    "reviewer_identifier",
    "fixture_author_identifier",
    "review_date",
    "method",
    "source_first",
    "prior_run_output_exposure",
    "cases",
)
_CASE_FIELDS = ("case_id", "labels_sha256", "decision")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_IDENTIFIER = re.compile(r"[a-z][a-z0-9._-]{0,63}")
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


class AdjudicationError(ValueError):
    """Reports a record that cannot be imported without echoing its content."""


@dataclasses.dataclass(frozen=True)
class CaseDecision:
    case_id: str
    labels_sha256: str
    decision: str
    reason: str | None

    @property
    def excluded(self) -> bool:
        return self.decision != CONFIRMED


@dataclasses.dataclass(frozen=True)
class HumanAdjudication:
    """One imported record: its exact-byte pin and a decision per corpus case."""

    record_sha256: str
    corpus_identity: str
    manifest_sha256: str
    decisions: tuple[CaseDecision, ...]

    @property
    def excluded(self) -> tuple[CaseDecision, ...]:
        return tuple(item for item in self.decisions if item.excluded)

    @property
    def every_case_confirmed(self) -> bool:
        return not self.excluded

    def for_case(self, case_id: str) -> CaseDecision:
        for item in self.decisions:
            if item.case_id == case_id:
                return item
        raise AdjudicationError("adjudication record has no decision for this case")


def _digest(value: Any) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None and value != "0" * 64


def _review_date(value: Any) -> bool:
    if not isinstance(value, str) or _DATE.fullmatch(value) is None:
        return False
    try:
        datetime.date.fromisoformat(value)
    except ValueError:
        return False
    return True


def _decision(value: Any) -> CaseDecision:
    if not isinstance(value, dict):
        raise AdjudicationError("case decision fields are not the closed set for its decision")
    decision = value.get("decision")
    if not isinstance(decision, str) or decision not in (CONFIRMED, *EXCLUDING_DECISIONS):
        raise AdjudicationError("case decision is not confirmed, revised or rejected")
    fields = _CASE_FIELDS if decision == CONFIRMED else (*_CASE_FIELDS, "reason")
    if set(value) != set(fields):
        raise AdjudicationError("case decision fields are not the closed set for its decision")
    case_id, digest, reason = value["case_id"], value["labels_sha256"], value.get("reason")
    if not isinstance(case_id, str):
        raise AdjudicationError("adjudication record names an unknown case")
    if not _digest(digest):
        raise AdjudicationError("case label digest is not a SHA-256 digest")
    if decision != CONFIRMED and (not isinstance(reason, str) or not 1 <= len(reason) <= 1024):
        raise AdjudicationError("an excluded case's reason is empty or too long")
    return CaseDecision(case_id, digest, decision, reason)


def import_adjudication(corpus: Corpus, record: bytes, pinned_sha256: str) -> HumanAdjudication:
    """Checks one record's exact bytes against its pin and the exact corpus.

    It refuses any mismatch rather than importing part of a record: an unknown,
    missing or duplicate field or case, cases out of corpus order, a label
    digest or corpus binding that differs, the fixture author as reviewer, or
    a review that is not declared source-first and free of prior exposure to
    run output.
    """
    if not isinstance(pinned_sha256, str) or not _digest(pinned_sha256):
        raise AdjudicationError("the pinned SHA-256 is not a lowercase SHA-256 digest")
    if not record:
        raise AdjudicationError("adjudication record is empty")
    if len(record) > MAX_RECORD_BYTES:
        raise AdjudicationError("adjudication record exceeds its bound")
    if sha256(record) != pinned_sha256:
        raise AdjudicationError("adjudication record does not match its pinned SHA-256")
    try:
        value = decode_json(record, MAX_RECORD_BYTES)
    except CorpusError as error:
        raise AdjudicationError("adjudication record is not strict JSON") from error
    if not isinstance(value, dict) or set(value) != set(_RECORD_FIELDS):
        raise AdjudicationError("adjudication record fields are not the closed set")
    if value["contract"] != RECORD_CONTRACT or type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise AdjudicationError("adjudication record is not the model-corpus human adjudication contract v1")
    if value["method"] != "independent_human_review":
        raise AdjudicationError("adjudication record method is not independent_human_review")
    if value["fixture_author_identifier"] != FIXTURE_AUTHOR:
        raise AdjudicationError("adjudication record does not name the corpus's declared fixture author")
    reviewer = value["reviewer_identifier"]
    if not isinstance(reviewer, str) or _IDENTIFIER.fullmatch(reviewer) is None:
        raise AdjudicationError("adjudication record reviewer identifier is invalid")
    if reviewer == FIXTURE_AUTHOR:
        raise AdjudicationError("adjudication record reviewer is the declared fixture author")
    if not _review_date(value["review_date"]):
        raise AdjudicationError("adjudication record review date is not a YYYY-MM-DD calendar date")
    if value["source_first"] is not True:
        raise AdjudicationError("adjudication record does not declare a source-first review")
    if value["prior_run_output_exposure"] != "none_declared" or not isinstance(value["prior_run_output_exposure"], str):
        raise AdjudicationError("adjudication record does not declare no prior exposure to run output")
    if value["corpus_identity"] != corpus.identity or value["manifest_sha256"] != corpus.manifest_sha256:
        raise AdjudicationError("adjudication record binds a different corpus")
    if not isinstance(value["cases"], list):
        raise AdjudicationError("adjudication record case list is not a list")
    decisions = tuple(_decision(item) for item in value["cases"])
    recorded = [item.case_id for item in decisions]
    expected = [case.id for case in corpus.cases]
    if any(case_id not in expected for case_id in recorded):
        raise AdjudicationError("adjudication record names an unknown case")
    if len(set(recorded)) != len(recorded):
        raise AdjudicationError("adjudication record repeats a case")
    if set(recorded) != set(expected):
        raise AdjudicationError("adjudication record omits a corpus case")
    if recorded != expected:
        raise AdjudicationError("adjudication record lists cases out of corpus order")
    for item, case in zip(decisions, corpus.cases):
        if item.labels_sha256 != case.labels_sha256:
            raise AdjudicationError("adjudication record label digest does not match the corpus case")
    return HumanAdjudication(pinned_sha256, corpus.identity, corpus.manifest_sha256, decisions)


def read_record(path: Path) -> bytes:
    """Reads one bounded regular file without following a final symlink."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as error:
        raise AdjudicationError("adjudication record is not a readable regular file") from error
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise AdjudicationError("adjudication record is not a readable regular file")
    with os.fdopen(descriptor, "rb") as stream:
        data = stream.read(MAX_RECORD_BYTES + 1)
    if len(data) > MAX_RECORD_BYTES:
        raise AdjudicationError("adjudication record exceeds its bound")
    return data


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check a human-authored model-corpus adjudication record against its pin and the corpus.")
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="import the record and report its decisions; writes nothing")
    check.add_argument("--adjudication", type=Path, required=True, help="the human-authored record")
    check.add_argument("--adjudication-sha256", required=True, help="SHA-256 of the record's exact bytes, from the reviewer's handoff")
    check.add_argument("--corpus", type=Path, default=None)
    args = parser.parse_args(arguments)
    try:
        corpus = load_corpus(args.corpus or default_corpus_root())
        adjudication = import_adjudication(corpus, read_record(args.adjudication), args.adjudication_sha256)
    except (OSError, CorpusError, AdjudicationError) as error:
        print(f"model adjudication: {error}", file=sys.stderr)
        return 1
    excluded = adjudication.excluded
    print(
        f"adjudication record_sha256={adjudication.record_sha256} corpus={adjudication.corpus_identity} "
        f"cases={len(adjudication.decisions)} confirmed={len(adjudication.decisions) - len(excluded)} "
        f"excluded={len(excluded)} provenance_status={PROVENANCE_STATUS}"
    )
    for item in excluded:
        print(f"excluded {item.case_id} {item.decision}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
