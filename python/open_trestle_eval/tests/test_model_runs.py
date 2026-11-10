import contextlib
import hashlib
import io
import json
import os
import signal
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema_subset import SchemaError, validate
from open_trestle_eval.model_corpus import default_corpus_root, load_corpus, plan_revisions
from open_trestle_eval.model_runs import (
    DRIVER_FLAGS,
    MAX_STDOUT_BYTES,
    UNSUPPORTED_FLAGS,
    DriverError,
    UsageError,
    main,
    parse_duration,
    parse_operator_arguments,
    repository_name,
    run_corpus,
    summarize_result,
)

SCHEMA = json.loads(
    (Path(__file__).resolve().parents[3] / "schemas/evaluation/model-corpus-run-bundle-v1.schema.json").read_text(encoding="utf-8")
)

# A stand-in for trestle. It checks that both commits exist in the objects root,
# logs its arguments and prints canned bytes; it never contacts a model.
FAKE_TRESTLE = r'''#!/usr/bin/env python3
import hashlib, json, os, sys, time, zlib
config = json.load(open(os.environ["FAKE_TRESTLE_CONFIG"]))
args = sys.argv[1:]
flags = dict(zip(args[2::2], args[3::2]))
ok = args[:2] == ["local-git", "model-review"] and len(args[2:]) == 2 * len(flags)
for key in ("--base-revision-digest", "--head-revision-digest"):
    oid = flags.get(key, "")
    try:
        with open(os.path.join(flags.get("--objects-root", ""), oid[:2], oid[2:]), "rb") as stream:
            framed = zlib.decompress(stream.read())
        ok = ok and hashlib.sha1(framed).hexdigest() == oid and framed.startswith(b"commit ")
    except (OSError, zlib.error):
        ok = False
with open(config["log"], "a") as log:
    log.write(json.dumps({"args": args, "objects_ok": ok, "cwd": os.getcwd()}) + "\n")
mode = config.get("mode", "normal")
if mode == "sleep":
    time.sleep(30)
if mode == "flood":
    sys.stdout.buffer.write(b"x" * (300 * 1024))
    sys.stdout.flush()
    time.sleep(30)
if mode == "mutate":
    with open(sys.argv[0], "ab") as own:
        own.write(b"\n# changed\n")
entry = config["results"].get(flags.get("--repository-name"), config["default"])
sys.stdout.buffer.write(entry["stdout"].encode("utf-8"))
sys.stderr.buffer.write(entry.get("stderr", "").encode("utf-8"))
sys.exit(entry["exit"])
'''

RESULT = {
    "contract": "open-trestle/local-git-model-review-result",
    "schema_version": 4,
    "status": "findings",
    "ci_disposition": "blocked",
    "run_status": "succeeded",
    "usage_known": True,
    "actual_cost_micro_usd": 125,
    "diagnostics": None,
}


def operator_flags(root: Path, egress: str = "policy-approved", timeout: str = "1s") -> list[str]:
    return [
        "--tenant", "tenant-eval",
        "--repository", "repository-eval",
        "--route-inventory", str(root / "routes.json"),
        "--runtime-policy", str(root / "policy.json"),
        "--egress", egress,
        "--timeout", timeout,
    ]


class OperatorArgumentTest(unittest.TestCase):
    def test_parses_go_durations_within_trestle_bounds(self) -> None:
        for value, seconds in (("5m", 300.0), ("1m30s", 90.0), ("90s", 90.0), ("1500ms", 1.5), ("15m", 900.0)):
            self.assertEqual(parse_duration(value), seconds)
        for value in ("", "5", "5x", "0s", "999ms", "16m", "-1s", "1h"):
            with self.subTest(value=value), self.assertRaises(UsageError):
                parse_duration(value)

    def test_refuses_flags_the_driver_owns_or_cannot_score(self) -> None:
        base = operator_flags(Path("/protected"))
        self.assertEqual(parse_operator_arguments(base)["--egress"], "policy-approved")
        self.assertEqual(parse_operator_arguments([*base, "--profile", "bug_hunter"])["--profile"], "bug_hunter")
        refused = {
            **{flag: [*base, flag, "value"] for flag in (*DRIVER_FLAGS, *UNSUPPORTED_FLAGS)},
            "unknown": [*base, "--publish", "true"],
            "equals form": [*base[:-2], "--timeout=1s", "x"],
            "repeated": [*base, "--tenant", "other"],
            "odd count": [*base, "--profile"],
            "missing": base[:-2],
            "egress": [*base[:-4], "--egress", "unrestricted", "--timeout", "1s"],
            "timeout": [*base[:-2], "--timeout", "forever"],
            "newline": [*base[:-12], "--tenant", "a\nb", *base[2:]],
        }
        for name, arguments in refused.items():
            with self.subTest(name=name), self.assertRaises(UsageError):
                parse_operator_arguments(arguments)

    def test_summarizes_only_well_typed_result_fields(self) -> None:
        line = (json.dumps({**RESULT, "context_shortfall": {"required_tokens": 9, "estimated_input_tokens": 5, "max_output_tokens": 4, "declared_context_tokens": 8}}) + "\n").encode()
        summary = summarize_result(line)
        self.assertTrue(summary["parsed"])
        self.assertEqual((summary["status"], summary["usage_known"], summary["actual_cost_micro_usd"], summary["schema_version"]), ("findings", True, 125, 4))
        self.assertEqual(summary["context_shortfall"]["required_tokens"], 9)
        for raw in (line[:-1], line + line, b"not json\n", b"[1]\n", b"\xff\n"):
            self.assertFalse(summarize_result(raw)["parsed"])
        odd = summarize_result((json.dumps({**RESULT, "usage_known": 1, "actual_cost_micro_usd": True, "status": 7}) + "\n").encode())
        self.assertEqual((odd["usage_known"], odd["actual_cost_micro_usd"], odd["status"]), (None, None, None))


class DriverTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.corpus = load_corpus(default_corpus_root())
        (self.root / "routes.json").write_text(json.dumps({"schema_version": 1, "routes": [
            {"zone": "private_remote", "provider_id": "fake", "model_id": "fake-generator", "content_logging": False},
            {"zone": "private_remote", "provider_id": "fake", "model_id": "fake-verifier", "content_logging": False},
        ]}), encoding="utf-8")
        (self.root / "policy.json").write_text(json.dumps({"schema_version": 6, "connections": [{"endpoint": "https://provider.example.invalid/v1"}]}), encoding="utf-8")
        self.trestle = self.root / "bin" / "trestle"
        self.trestle.parent.mkdir()
        self.trestle.write_text(FAKE_TRESTLE, encoding="utf-8")
        self.trestle.chmod(self.trestle.stat().st_mode | stat.S_IXUSR)
        self.log = self.root / "calls.jsonl"
        self.config = self.root / "fake.json"
        self.configure()
        patcher = patch.dict(os.environ, {"FAKE_TRESTLE_CONFIG": str(self.config)})
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def configure(self, mode: str = "normal", results: dict | None = None) -> None:
        default = {"stdout": json.dumps(RESULT) + "\n", "stderr": "", "exit": 4}
        self.config.write_text(json.dumps({"log": str(self.log), "mode": mode, "results": results or {}, "default": default}), encoding="utf-8")

    def calls(self) -> list[dict]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]

    def run_main(self, *arguments: str) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(list(arguments))
        return code, stdout.getvalue(), stderr.getvalue()

    def test_prints_the_plan_and_makes_no_call_without_confirmation(self) -> None:
        output = self.root / "bundle"
        code, stdout, stderr = self.run_main("--trestle", str(self.trestle), "--output", str(output), "--", *operator_flags(self.root))
        self.assertEqual(code, 2)
        self.assertEqual(self.calls(), [])
        self.assertFalse(output.exists())
        self.assertIn("No model call has been made yet.", stdout)
        self.assertIn(f"cases: {len(self.corpus.cases)}; runs per case: 3; invocations: {3 * len(self.corpus.cases)}", stdout)
        self.assertIn("egress policy-approved: sanitized, secret-scanned source selected from each case may leave this machine", stdout)
        self.assertIn("route zone=private_remote provider_id=fake model_id=fake-generator content_logging=false", stdout)
        self.assertIn("endpoint https://provider.example.invalid/v1", stdout)
        self.assertIn(f"sha256 {hashlib.sha256(self.trestle.read_bytes()).hexdigest()}", stdout)
        self.assertIn("case-01 abstention_argument_order: changed push.go", stdout)
        self.assertIn("--confirm-model-calls", stderr)

    def test_usage_errors_make_no_call(self) -> None:
        cases = {
            "driver flag": ("--", *operator_flags(self.root), "--format", "text"),
            "unknown case": ("--case", "missing_case", "--confirm-model-calls", "--", *operator_flags(self.root)),
            "runs": ("--runs", "0", "--confirm-model-calls", "--", *operator_flags(self.root)),
        }
        for name, extra in cases.items():
            with self.subTest(name=name):
                code, _, stderr = self.run_main("--trestle", str(self.trestle), "--output", str(self.root / name), *extra)
                self.assertEqual(code, 2)
                self.assertIn("model runs:", stderr)
        existing = self.root / "existing"
        existing.mkdir()
        code, _, _ = self.run_main("--trestle", str(self.trestle), "--output", str(existing), "--confirm-model-calls", "--", *operator_flags(self.root))
        self.assertEqual(code, 2)
        code, _, _ = self.run_main("--trestle", str(self.root / "missing"), "--output", str(self.root / "new"), "--confirm-model-calls", "--", *operator_flags(self.root))
        self.assertEqual(code, 2)
        self.assertEqual(self.calls(), [])

    def test_runs_round_robin_and_keeps_exact_bytes(self) -> None:
        first, second = self.corpus.case("clean_rename"), self.corpus.case("defect_off_by_one")
        first_name, second_name = repository_name(self.corpus, first), repository_name(self.corpus, second)
        exact = json.dumps(RESULT, separators=(",", ":")) + "\n"
        self.configure(results={
            first_name: {"stdout": exact, "stderr": "note\n", "exit": 4},
            second_name: {"stdout": "not a result", "exit": 1},
        })
        output = self.root / "bundle"
        flags = [*operator_flags(self.root), "--profile", "bug_hunter"]
        code, stdout, _ = self.run_main(
            "--trestle", str(self.trestle), "--output", str(output), "--case", "defect_off_by_one", "--case", "clean_rename",
            "--confirm-model-calls", "--", *flags,
        )
        self.assertEqual(code, 0)
        self.assertIn("No model call has been made yet.", stdout)
        self.assertIn("recorded 6 runs", stdout)
        bundle = json.loads((output / "bundle.json").read_text(encoding="utf-8"))
        validate(SCHEMA, bundle)
        for mutate in (
            lambda value: value.update(release_evidence_eligible=True),
            lambda value: value.update(unexpected=1),
            lambda value: value["cases"][0]["runs"][0]["result"].update(usage_known=1),
        ):
            altered = json.loads(json.dumps(bundle))
            mutate(altered)
            with self.assertRaises(SchemaError):
                validate(SCHEMA, altered)
        self.assertEqual((bundle["completion"], bundle["runs_per_case"], bundle["review_state"], bundle["release_evidence_eligible"]), ("complete", 3, "pending", False))
        self.assertEqual(bundle["corpus_identity"], self.corpus.identity)
        self.assertEqual(bundle["operator_arguments"], flags)
        self.assertEqual([item["case_id"] for item in bundle["cases"]], ["clean_rename", "defect_off_by_one"])
        calls = self.calls()
        self.assertEqual(len(calls), 6)
        names = [dict(zip(call["args"][2::2], call["args"][3::2]))["--repository-name"] for call in calls]
        self.assertEqual(names, [first_name, second_name] * 3)
        for call, case in zip(calls, [first, second] * 3):
            self.assertTrue(call["objects_ok"])
            base, head, _ = plan_revisions(case)
            self.assertEqual(call["args"][:2], ["local-git", "model-review"])
            self.assertEqual(call["args"][-2:], ["--format", "json"])
            self.assertEqual(call["args"][-2 - len(flags):-2], flags)
            values = dict(zip(call["args"][2::2], call["args"][3::2]))
            self.assertEqual((values["--base-revision-digest"], values["--head-revision-digest"], values["--revision-algorithm"]), (base, head, "sha1"))
            self.assertEqual((values["--repository-authority"], values["--repository-namespace"]), ("corpus.invalid", "model-corpus-v1"))
            self.assertNotIn(case.id, " ".join(call["args"]))
            self.assertFalse(Path(call["cwd"]).exists(), "throwaway repositories were not removed")
        for item, stdout_bytes, exit_code, parsed in ((bundle["cases"][0], exact.encode(), 4, True), (bundle["cases"][1], b"not a result", 1, False)):
            self.assertEqual([run["run_index"] for run in item["runs"]], [1, 2, 3])
            for run in item["runs"]:
                self.assertEqual((run["termination"], run["exit_code"], run["signal"]), ("exited", exit_code, None))
                self.assertGreater(run["latency_ns"], 0)
                self.assertEqual((output / run["stdout"]["path"]).read_bytes(), stdout_bytes)
                self.assertEqual(run["stdout"]["sha256"], hashlib.sha256(stdout_bytes).hexdigest())
                self.assertEqual(run["result"]["parsed"], parsed)
        self.assertEqual(bundle["cases"][0]["runs"][0]["result"]["actual_cost_micro_usd"], 125)
        self.assertEqual((output / bundle["cases"][0]["runs"][0]["stderr"]["path"]).read_bytes(), b"note\n")
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)

    def bounded_run(self, mode: str) -> dict:
        self.configure(mode=mode)
        output = self.root / f"bundle-{mode}"
        started = time.monotonic()
        bundle = run_corpus(
            corpus=self.corpus, cases=[self.corpus.case("clean_rename")], trestle=self.trestle.resolve(), runs=1,
            operator_arguments=operator_flags(self.root, timeout="1s"), output=output,
            repository_authority="corpus.invalid", repository_namespace="model-corpus-v1", grace_seconds=0.5,
        )
        self.assertLess(time.monotonic() - started, 15)
        validate(SCHEMA, bundle)
        return bundle["cases"][0]["runs"][0]

    @unittest.skipUnless(sys.platform.startswith("linux"), "process groups are exercised on Linux")
    def test_records_a_timed_out_run(self) -> None:
        run = self.bounded_run("sleep")
        self.assertEqual(run["termination"], "timed_out")
        self.assertIsNone(run["exit_code"])
        self.assertIn(run["signal"], (signal.SIGTERM, signal.SIGKILL))
        self.assertFalse(run["result"]["parsed"])

    @unittest.skipUnless(sys.platform.startswith("linux"), "process groups are exercised on Linux")
    def test_records_an_output_limit_run(self) -> None:
        run = self.bounded_run("flood")
        self.assertEqual(run["termination"], "output_limit")
        self.assertEqual(run["stdout"]["bytes"], MAX_STDOUT_BYTES)

    def test_stops_when_the_executable_changes(self) -> None:
        self.configure(mode="mutate")
        output = self.root / "bundle"
        with self.assertRaisesRegex(DriverError, "executable changed"):
            run_corpus(
                corpus=self.corpus, cases=list(self.corpus.cases[:2]), trestle=self.trestle.resolve(), runs=2,
                operator_arguments=operator_flags(self.root), output=output,
                repository_authority="corpus.invalid", repository_namespace="model-corpus-v1",
            )
        bundle = json.loads((output / "bundle.json").read_text(encoding="utf-8"))
        validate(SCHEMA, bundle)
        self.assertEqual(bundle["completion"], "failed")
        self.assertEqual(sum(len(item["runs"]) for item in bundle["cases"]), 1)
        self.assertEqual(len(self.calls()), 1)


if __name__ == "__main__":
    unittest.main()
