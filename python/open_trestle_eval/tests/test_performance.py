import hashlib
import json
import os
import signal
import subprocess
import stat
import sys
import time
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from open_trestle_eval.performance import (
    PerformanceMeasurementError,
    _run_once,
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

    def test_hashes_the_executable_selected_from_path(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            work = root / "work"
            commands = root / "bin"
            work.mkdir()
            commands.mkdir()
            self.write_program(work, "raise SystemExit('wrong executable')\n")
            selected = self.write_program(
                commands,
                f"import sys\nprint({candidate()!r})\nsys.exit(3)\n",
            )
            previous = Path.cwd()
            try:
                os.chdir(work)
                with patch.dict(os.environ, {"PATH": str(commands) + os.pathsep + os.environ["PATH"]}):
                    result = measure_candidate(["candidate"], warmup_count=1, sample_count=10)
            finally:
                os.chdir(previous)
            self.assertEqual(result["binary_sha256"], hashlib.sha256(selected.read_bytes()).hexdigest())

    def test_resolves_path_only_command_and_preserves_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            command = self.write_program(
                root,
                "import sys\n"
                "assert sys.argv[1:] == ['argument with spaces', '--flag']\n"
                f"print({candidate()!r})\nsys.exit(3)\n",
            )
            with patch.dict(os.environ, {"PATH": str(root) + os.pathsep + os.environ["PATH"]}):
                result = measure_candidate([command.name, "argument with spaces", "--flag"])
            self.assertEqual(result["binary_sha256"], hashlib.sha256(command.read_bytes()).hexdigest())

    def test_rejects_missing_path_command_before_process_start(self) -> None:
        with patch.dict(os.environ, {"PATH": ""}):
            with patch("open_trestle_eval.performance._run_once") as run_once:
                with self.assertRaisesRegex(PerformanceMeasurementError, "candidate process did not start"):
                    measure_candidate(["missing-candidate-command"])
                run_once.assert_not_called()

    def test_pins_the_resolved_launch_path(self) -> None:
        observation = {
            "stdout_sha256": "a" * 64,
            "report_identity": "b" * 64,
            "corpus_identity": "c" * 64,
            "elapsed_ns": 1,
            "user_cpu_ns": 1,
            "system_cpu_ns": 0,
            "max_rss_kib": 1,
        }
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            command = self.write_program(root, "raise SystemExit(3)\n")
            with patch.dict(os.environ, {"PATH": str(root)}):
                with patch("open_trestle_eval.performance._run_once", return_value=observation) as run_once:
                    measure_candidate([command.name, "argument"])
            self.assertEqual(run_once.call_count, 11)
            for call in run_once.call_args_list:
                self.assertEqual(call.args[0], [str(command.resolve()), "argument"])

    def test_executes_and_hashes_the_symlink_target(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            target = root / "target"
            program = self.write_program(
                root,
                "import sys\n"
                f"assert sys.argv[0] == {str(target)!r}\n"
                f"print({candidate()!r})\nsys.exit(3)\n",
            )
            program.rename(target)
            program.symlink_to(target)
            result = measure_candidate([str(program)])
            self.assertEqual(result["binary_sha256"], hashlib.sha256(target.read_bytes()).hexdigest())

    def test_rejects_executable_changes_during_measurement(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            counter = root / "counter"
            command = self.write_program(
                root,
                "import pathlib,sys\n"
                f"counter=pathlib.Path({str(counter)!r})\n"
                "count=int(counter.read_text())+1 if counter.exists() else 1\n"
                "counter.write_text(str(count))\n"
                "p=pathlib.Path(__file__)\n"
                "p.write_text(p.read_text()+'# changed\\n')\n"
                f"print({candidate()!r})\n"
                "sys.exit(3)\n",
            )
            with self.assertRaisesRegex(
                PerformanceMeasurementError, "candidate executable changed"
            ):
                measure_candidate([str(command)], warmup_count=1, sample_count=10)
            self.assertEqual(counter.read_text(), "1")

    def test_rejects_missing_executable_without_exposing_path(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            command = self.write_program(
                Path(value),
                "import pathlib,sys\n"
                "pathlib.Path(__file__).unlink()\n"
                f"print({candidate()!r})\n"
                "sys.exit(3)\n",
            )
            with self.assertRaises(PerformanceMeasurementError) as raised:
                measure_candidate([str(command)], warmup_count=1, sample_count=10)
            self.assertEqual(str(raised.exception), "candidate executable changed")
            self.assertIsNone(raised.exception.__cause__)
            self.assertTrue(raised.exception.__suppress_context__)

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

    def test_rejects_nonfinite_timeout_before_process_start(self) -> None:
        observation = {
            "stdout_sha256": "a" * 64,
            "report_identity": "b" * 64,
            "corpus_identity": "c" * 64,
            "elapsed_ns": 1,
            "user_cpu_ns": 1,
            "system_cpu_ns": 0,
            "max_rss_kib": 1,
        }
        for timeout in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(timeout=timeout):
                with patch(
                    "open_trestle_eval.performance._run_once",
                    return_value=observation,
                ) as run_once:
                    with self.assertRaisesRegex(ValueError, "invalid timeout"):
                        measure_candidate([sys.executable], timeout_seconds=timeout)
                    run_once.assert_not_called()

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

    def test_capture_failures_kill_and_reap_candidate(self) -> None:
        for target, failure in (
            ("_drain_ready", KeyboardInterrupt()),
            ("os.set_blocking", OSError("capture setup failed")),
        ):
            with self.subTest(target=target):
                processes: list[subprocess.Popen] = []
                popen = subprocess.Popen

                def launch(*args, **kwargs):
                    process = popen(*args, **kwargs)
                    processes.append(process)
                    return process

                try:
                    with patch("open_trestle_eval.performance.subprocess.Popen", side_effect=launch):
                        with patch("open_trestle_eval.performance." + target, side_effect=failure):
                            with self.assertRaises(type(failure)) as raised:
                                _run_once([sys.executable, "-c", "import time; time.sleep(30)"], 1.0)
                    self.assertIs(raised.exception, failure)
                    self.assertEqual(len(processes), 1)
                    process = processes[0]
                    self.assertEqual(process.returncode, -signal.SIGKILL)
                    with self.assertRaises(ChildProcessError):
                        os.waitpid(process.pid, os.WNOHANG)
                    self.assertTrue(process.stdout.closed)
                    self.assertTrue(process.stderr.closed)
                finally:
                    for process in processes:
                        if process.poll() is None:
                            os.killpg(process.pid, signal.SIGKILL)
                        process.wait()

    def test_interruption_after_reaping_preserves_status(self) -> None:
        processes: list[subprocess.Popen] = []
        popen = subprocess.Popen
        wait4 = os.wait4
        reaped = False
        interruption = KeyboardInterrupt()

        def launch(*args, **kwargs):
            process = popen(*args, **kwargs)
            processes.append(process)
            return process

        def reap(*args):
            nonlocal reaped
            result = wait4(*args)
            if result[0] != 0:
                reaped = True
            return result

        def interrupt_after_reap(*args):
            if reaped:
                raise interruption

        try:
            with patch("open_trestle_eval.performance.subprocess.Popen", side_effect=launch):
                with patch("open_trestle_eval.performance.os.wait4", side_effect=reap):
                    with patch("open_trestle_eval.performance._drain_ready", side_effect=interrupt_after_reap):
                        with self.assertRaises(KeyboardInterrupt) as raised:
                            _run_once([sys.executable, "-c", "raise SystemExit(3)"], 1.0)
            self.assertIs(raised.exception, interruption)
            self.assertEqual(processes[0].returncode, 3)
            with self.assertRaises(ChildProcessError):
                os.waitpid(processes[0].pid, os.WNOHANG)
            self.assertTrue(processes[0].stdout.closed)
            self.assertTrue(processes[0].stderr.closed)
        finally:
            for process in processes:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait()

    def test_rejects_wrong_json_types_in_pending_envelope(self) -> None:
        for field, value in (
            ("schema_version", True),
            ("schema_version", 1.0),
            ("release_evidence_eligible", 0),
            ("release_evidence_eligible", 0.0),
        ):
            with self.subTest(field=field, value=value):
                report = json.loads(candidate())
                report[field] = value
                encoded = json.dumps(report, separators=(",", ":"))
                with tempfile.TemporaryDirectory() as directory:
                    command = self.write_program(
                        Path(directory),
                        f"import sys\nprint({encoded!r})\nsys.exit(3)\n",
                    )
                    with self.assertRaisesRegex(
                        PerformanceMeasurementError, "candidate report is not pending"
                    ):
                        measure_candidate([str(command)])

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
