import json
import os
import stat
import sys
import time
import tempfile
import unittest
from pathlib import Path

from open_trestle_eval.performance import (
    PerformanceMeasurementError,
    measure_candidate,
    nearest_rank_percentile,
)


def candidate(identity: str = "a" * 64) -> str:
    return json.dumps(
        {
            "contract": "open-trestle/deterministic-corpus-candidate-result",
            "schema_version": 1,
            "identity": identity,
            "corpus_identity": "b" * 64,
            "review_state": "pending",
            "release_evidence_eligible": False,
            "golden_status": "prohibited_pending_human_review",
        },
        separators=(",", ":"),
    )


@unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux wait4")
class PerformanceMeasurementTest(unittest.TestCase):
    def write_program(self, directory: Path, body: str) -> Path:
        path = directory / "candidate"
        path.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path

    def test_measures_pending_candidate_without_promoting_it(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            command = self.write_program(
                Path(value),
                f"import sys\nprint({candidate()!r})\nsys.exit(3)\n",
            )
            result = measure_candidate([str(command)], warmup_count=1, sample_count=10)
        self.assertEqual(result["contract"], "open-trestle/deterministic-corpus-performance-observation")
        self.assertFalse(result["release_evidence_eligible"])
        self.assertEqual(result["sample_count"], 10)
        self.assertEqual(len(result["samples"]), 10)
        self.assertEqual(result["report_identity"], "a" * 64)
        self.assertEqual(result["corpus_identity"], "b" * 64)
        self.assertTrue(all(sample["max_rss_kib"] > 0 for sample in result["samples"]))
        schema_path = (
            Path(__file__).resolve().parents[3]
            / "schemas/evaluation/deterministic-corpus-performance-observation-v1.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(set(result), set(schema["required"]))
        sample_schema = schema["properties"]["samples"]["items"]
        self.assertEqual(set(result["samples"][0]), set(sample_schema["required"]))
        for sample in result["samples"]:
            for key, number in sample.items():
                self.assertLessEqual(number, sample_schema["properties"][key]["maximum"])

    def test_rejects_output_drift(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            counter = root / "counter"
            command = self.write_program(
                root,
                "import json,pathlib,sys\n"
                f"p=pathlib.Path({str(counter)!r}); n=int(p.read_text())+1 if p.exists() else 1; p.write_text(str(n))\n"
                "print(json.dumps({'contract':'open-trestle/deterministic-corpus-candidate-result','schema_version':1,'identity':format(n,'064x'),'corpus_identity':'b'*64,'review_state':'pending','release_evidence_eligible':False,'golden_status':'prohibited_pending_human_review'},separators=(',',':')))\n"
                "sys.exit(3)\n",
            )
            with self.assertRaises(PerformanceMeasurementError):
                measure_candidate([str(command)], warmup_count=1, sample_count=10)

    def test_rejects_excessive_warmups(self) -> None:
        with self.assertRaisesRegex(ValueError, "measurement bounds"):
            measure_candidate(["/does/not/exist"], warmup_count=101, sample_count=10)

    def test_rejects_timeout_and_oversized_output(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            timeout = self.write_program(root, "import time\ntime.sleep(10)\n")
            with self.assertRaises(PerformanceMeasurementError):
                measure_candidate([str(timeout)], warmup_count=1, sample_count=10, timeout_seconds=0.05)
            oversized = self.write_program(root, "print('x'*70000)\n")
            with self.assertRaises(PerformanceMeasurementError):
                measure_candidate([str(oversized)], warmup_count=1, sample_count=10)

    def test_timeout_kills_descendant_holding_output_pipe(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            command = self.write_program(
                root,
                "import os,sys,time\n"
                "if os.fork() == 0:\n"
                "    time.sleep(30)\n"
                "    os._exit(0)\n"
                f"print({candidate()!r})\n"
                "sys.exit(3)\n",
            )
            started = time.monotonic()
            with self.assertRaises(PerformanceMeasurementError):
                measure_candidate(
                    [str(command)],
                    warmup_count=1,
                    sample_count=10,
                    timeout_seconds=0.1,
                )
            self.assertLess(time.monotonic() - started, 2.0)

    def test_rejects_wrong_exit_and_nonpending_report(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            wrong_exit = self.write_program(root, f"print({candidate()!r})\n")
            with self.assertRaises(PerformanceMeasurementError):
                measure_candidate([str(wrong_exit)], warmup_count=1, sample_count=10)
            accepted = candidate().replace('"review_state":"pending"', '"review_state":"accepted"')
            nonpending = self.write_program(root, f"import sys\nprint({accepted!r})\nsys.exit(3)\n")
            with self.assertRaises(PerformanceMeasurementError):
                measure_candidate([str(nonpending)], warmup_count=1, sample_count=10)


class PercentileTest(unittest.TestCase):
    def test_nearest_rank(self) -> None:
        self.assertEqual(nearest_rank_percentile([9, 1, 5], 50), 5)
        self.assertEqual(nearest_rank_percentile(list(range(1, 21)), 95), 19)


if __name__ == "__main__":
    unittest.main()
