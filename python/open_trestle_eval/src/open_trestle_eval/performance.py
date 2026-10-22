"""Linux wall-time and peak-RSS observation for pending corpus candidates."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import selectors
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Sequence

from .candidate_response import CandidateResponseDecodeError, decode_candidate_response

_MAX_CAPTURE_BYTES = 64 * 1024
_MAX_WARMUP_COUNT = 100


class PerformanceMeasurementError(RuntimeError):
    """Reports a content-free performance measurement failure."""


def nearest_rank_percentile(values: Sequence[int], percentile: int) -> int:
    if not values or percentile < 1 or percentile > 100:
        raise ValueError("invalid percentile input")
    ordered = sorted(values)
    index = math.ceil(len(ordered) * percentile / 100) - 1
    return ordered[index]


class _Capture:
    def __init__(self) -> None:
        self.content = bytearray()
        self.oversized = False

    def append(self, chunk: bytes) -> None:
        remaining = _MAX_CAPTURE_BYTES - len(self.content)
        if remaining > 0:
            self.content.extend(chunk[:remaining])
        if len(chunk) > remaining:
            self.oversized = True


def _signal_group(process: subprocess.Popen[bytes], value: signal.Signals) -> None:
    try:
        os.killpg(process.pid, value)
    except ProcessLookupError:
        pass


def _drain_ready(
    selector: selectors.BaseSelector,
    captures: dict[int, _Capture],
    timeout: float,
) -> None:
    for key, _ in selector.select(timeout):
        descriptor = key.fd
        try:
            chunk = os.read(descriptor, 8192)
        except BlockingIOError:
            continue
        if chunk:
            captures[descriptor].append(chunk)
        else:
            selector.unregister(descriptor)


def _run_once(command: Sequence[str], timeout_seconds: float) -> dict[str, Any]:
    started = time.perf_counter_ns()
    try:
        process = subprocess.Popen(
            list(command),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except (OSError, ValueError) as error:
        raise PerformanceMeasurementError("candidate process did not start") from error
    assert process.stdout is not None and process.stderr is not None
    stdout = _Capture()
    stderr = _Capture()
    capture_by_descriptor = {
        process.stdout.fileno(): stdout,
        process.stderr.fileno(): stderr,
    }
    selector = selectors.DefaultSelector()
    for descriptor in capture_by_descriptor:
        os.set_blocking(descriptor, False)
        selector.register(descriptor, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout_seconds
    usage = None
    status = None
    failure: str | None = None
    term_sent_at: float | None = None
    try:
        while status is None or selector.get_map():
            now = time.monotonic()
            if failure is None and (stdout.oversized or stderr.oversized):
                failure = "candidate process output exceeded the limit"
                term_sent_at = now
                _signal_group(process, signal.SIGTERM)
            if failure is None and now >= deadline:
                failure = "candidate process timed out"
                term_sent_at = now
                _signal_group(process, signal.SIGTERM)
            if term_sent_at is not None and now - term_sent_at >= 0.1:
                _signal_group(process, signal.SIGKILL)
            _drain_ready(selector, capture_by_descriptor, 0.005)
            if status is None:
                try:
                    waited_pid, waited_status, waited_usage = os.wait4(
                        process.pid, os.WNOHANG
                    )
                except ChildProcessError as error:
                    raise PerformanceMeasurementError(
                        "candidate process could not be reaped"
                    ) from error
                if waited_pid == process.pid:
                    status, usage = waited_status, waited_usage
            if failure is not None and status is not None and not selector.get_map():
                break
            if failure is not None and term_sent_at is not None and now - term_sent_at >= 0.5:
                break
        if status is None:
            _signal_group(process, signal.SIGKILL)
            _, status, usage = os.wait4(process.pid, 0)
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    process.returncode = os.waitstatus_to_exitcode(status)
    if failure is not None:
        raise PerformanceMeasurementError(failure)
    elapsed_ns = time.perf_counter_ns() - started
    if process.returncode not in (3, 4):
        raise PerformanceMeasurementError("candidate process returned an invalid status")
    try:
        decoded = decode_candidate_response(bytes(stdout.content))
    except CandidateResponseDecodeError as error:
        raise PerformanceMeasurementError("candidate process returned invalid JSON") from error
    if not isinstance(decoded, dict):
        raise PerformanceMeasurementError("candidate process returned an invalid report")
    required = {
        "contract": "open-trestle/deterministic-corpus-candidate-result",
        "schema_version": 1,
        "review_state": "pending",
        "release_evidence_eligible": False,
        "golden_status": "prohibited_pending_human_review",
    }
    if any(
        type(decoded.get(key)) is not type(value) or decoded.get(key) != value
        for key, value in required.items()
    ):
        raise PerformanceMeasurementError("candidate report is not pending")
    report_identity = decoded.get("identity")
    corpus_identity = decoded.get("corpus_identity")
    if not _is_digest(report_identity) or not _is_digest(corpus_identity):
        raise PerformanceMeasurementError("candidate report identity is invalid")
    assert usage is not None
    return {
        "stdout_sha256": hashlib.sha256(stdout.content).hexdigest(),
        "report_identity": report_identity,
        "corpus_identity": corpus_identity,
        "elapsed_ns": elapsed_ns,
        "user_cpu_ns": int(usage.ru_utime * 1_000_000_000),
        "system_cpu_ns": int(usage.ru_stime * 1_000_000_000),
        "max_rss_kib": int(usage.ru_maxrss),
    }

def _is_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
        and value != "0" * 64
    )


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _summary(values: Sequence[int]) -> dict[str, int]:
    return {
        "p50": nearest_rank_percentile(values, 50),
        "p95": nearest_rank_percentile(values, 95),
        "max": max(values),
    }


def measure_candidate(
    command: Sequence[str],
    *,
    warmup_count: int = 1,
    sample_count: int = 10,
    timeout_seconds: float = 30.0,
) -> dict[str, Any]:
    """Measures one pending candidate command without assigning a quality gate."""
    if not sys.platform.startswith("linux") or not hasattr(os, "wait4"):
        raise PerformanceMeasurementError("Linux wait4 is required")
    if not command or warmup_count < 1 or warmup_count > _MAX_WARMUP_COUNT or sample_count < 10 or sample_count > 1000:
        raise ValueError("invalid measurement bounds")
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0 or timeout_seconds > 600:
        raise ValueError("invalid timeout")
    program = command[0]
    if os.path.dirname(program) == "":
        selected = shutil.which(program)
        if selected is None:
            raise PerformanceMeasurementError("candidate process did not start")
        program = selected
    executable = Path(program).resolve(strict=True)
    resolved_command = [str(executable), *command[1:]]
    binary_sha256 = _file_sha256(executable)
    observations = []
    for _ in range(warmup_count + sample_count):
        observations.append(_run_once(resolved_command, timeout_seconds))
        try:
            current_sha256 = _file_sha256(executable)
        except OSError:
            raise PerformanceMeasurementError("candidate executable changed") from None
        if current_sha256 != binary_sha256:
            raise PerformanceMeasurementError("candidate executable changed")
    baseline = observations[0]
    for observation in observations[1:]:
        if (
            observation["stdout_sha256"] != baseline["stdout_sha256"]
            or observation["report_identity"] != baseline["report_identity"]
            or observation["corpus_identity"] != baseline["corpus_identity"]
        ):
            raise PerformanceMeasurementError("candidate report changed between runs")
    measured = observations[warmup_count:]
    samples = [
        {
            "elapsed_ns": value["elapsed_ns"],
            "user_cpu_ns": value["user_cpu_ns"],
            "system_cpu_ns": value["system_cpu_ns"],
            "max_rss_kib": value["max_rss_kib"],
        }
        for value in measured
    ]
    return {
        "contract": "open-trestle/deterministic-corpus-performance-observation",
        "schema_version": 1,
        "release_evidence_eligible": False,
        "observation_scope": "environment_specific_not_a_golden_or_gate",
        "binary_sha256": binary_sha256,
        "stdout_sha256": baseline["stdout_sha256"],
        "report_identity": baseline["report_identity"],
        "corpus_identity": baseline["corpus_identity"],
        "environment": {
            "os": platform.system(),
            "release": platform.release(),
            "architecture": platform.machine(),
            "python": platform.python_version(),
        },
        "warmup_count": warmup_count,
        "sample_count": sample_count,
        "samples": samples,
        "elapsed_ns": _summary([value["elapsed_ns"] for value in samples]),
        "max_rss_kib": _summary([value["max_rss_kib"] for value in samples]),
    }


def encode_observation(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--samples", type=int, default=10)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--output", type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(arguments)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    try:
        observation = measure_candidate(
            command,
            warmup_count=args.warmups,
            sample_count=args.samples,
            timeout_seconds=args.timeout,
        )
    except (OSError, ValueError, PerformanceMeasurementError):
        print("performance observation failed", file=sys.stderr)
        return 1
    encoded = encode_observation(observation)
    if args.output is None:
        sys.stdout.buffer.write(encoded)
    else:
        args.output.write_bytes(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
