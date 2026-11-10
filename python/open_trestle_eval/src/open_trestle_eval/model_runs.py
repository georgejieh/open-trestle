"""Runs `trestle local-git model-review` over the pending model-review corpus.

Every run makes real model requests through the operator's routes, so the
driver prints what it will send where and refuses to start without
``--confirm-model-calls``. It records exact output bytes; it scores nothing.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import hashlib
import json
import os
import platform
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Sequence

from .model_corpus import (
    LABEL_STATUS,
    Corpus,
    CorpusCase,
    CorpusError,
    MaterializedRepository,
    default_corpus_root,
    load_corpus,
    materialize_case,
)

DRIVER = "open_trestle_eval.model_runs/1"
BUNDLE_CONTRACT = "open-trestle/model-corpus-run-bundle"
MAX_STDOUT_BYTES = 256 * 1024
MAX_STDERR_BYTES = 64 * 1024
MAX_RUNS = 10
DEFAULT_GRACE_SECONDS = 60.0
_KILL_DELAY_SECONDS = 2.0

REQUIRED_FLAGS = ("--tenant", "--repository", "--route-inventory", "--runtime-policy", "--egress", "--timeout")
OPTIONAL_FLAGS = ("--profile",)
DRIVER_FLAGS = (
    "--objects-root",
    "--repository-authority",
    "--repository-namespace",
    "--repository-name",
    "--revision-algorithm",
    "--base-revision-digest",
    "--head-revision-digest",
    "--format",
    "--checkout",
    "--base",
    "--head",
    "--object-store",
)
UNSUPPORTED_FLAGS = {
    "--specialists": "a review set is not the result contract this corpus scores",
    "--max-specialists": "a review set is not the result contract this corpus scores",
    "--investigation-policy": "investigation results are not scored by this corpus",
    "--retained-memory-input": "retained advisory memory could carry knowledge of these cases",
    "--exit-code-policy": "the driver records the default exit codes",
}
EGRESS_DESCRIPTIONS = {
    "local-only": "local-only: trestle admits only local routes on numeric loopback endpoints and refuses remote routes.",
    "policy-approved": (
        "policy-approved: sanitized, secret-scanned source selected from each case may leave this machine "
        "for the private_remote or brokered_remote routes the runtime policy approves."
    ),
}

_DURATION = re.compile(r"^(?:[0-9]+(?:\.[0-9]+)?(?:h|m|s|ms))+$")
_DURATION_PART = re.compile(r"([0-9]+(?:\.[0-9]+)?)(h|ms|m|s)")
_DURATION_UNITS = {"h": 3600.0, "m": 60.0, "s": 1.0, "ms": 0.001}


class DriverError(RuntimeError):
    """Reports a refused or failed batch without echoing run output."""


class UsageError(DriverError):
    """Reports invalid driver intent; no model call has been made."""


def parse_duration(value: str) -> float:
    """Parses the subset of Go duration syntax that trestle's --timeout uses."""
    if not _DURATION.match(value):
        raise UsageError("--timeout must be a Go duration such as 5m or 90s")
    seconds = sum(float(number) * _DURATION_UNITS[unit] for number, unit in _DURATION_PART.findall(value))
    if not 1.0 <= seconds <= 900.0:
        raise UsageError("--timeout must be between 1s and 15m")
    return seconds


def parse_operator_arguments(arguments: Sequence[str]) -> dict[str, str]:
    """Validates the operator's setup flags as ordered flag/value pairs."""
    if len(arguments) % 2:
        raise UsageError("operator flags must be flag/value pairs")
    values: dict[str, str] = {}
    for index in range(0, len(arguments), 2):
        flag, value = arguments[index], arguments[index + 1]
        if "=" in flag:
            raise UsageError(f"use separate flag and value, not {flag.split('=', 1)[0]}=...")
        if flag in DRIVER_FLAGS:
            raise UsageError(f"{flag} is set by the driver for each case")
        if flag in UNSUPPORTED_FLAGS:
            raise UsageError(f"{flag} is not supported: {UNSUPPORTED_FLAGS[flag]}")
        if flag not in REQUIRED_FLAGS and flag not in OPTIONAL_FLAGS:
            raise UsageError(f"unknown operator flag {flag}")
        if flag in values:
            raise UsageError(f"{flag} is repeated")
        if not value or len(value) > 4096 or "\0" in value or "\n" in value:
            raise UsageError(f"{flag} needs a nonempty single-line value")
        values[flag] = value
    missing = [flag for flag in REQUIRED_FLAGS if flag not in values]
    if missing:
        raise UsageError("missing operator flags: " + " ".join(missing))
    if values["--egress"] not in EGRESS_DESCRIPTIONS:
        raise UsageError("--egress must be local-only or policy-approved")
    parse_duration(values["--timeout"])
    return values


def resolve_executable(program: str) -> Path:
    if os.path.dirname(program) == "":
        selected = shutil.which(program)
        if selected is None:
            raise UsageError("the trestle executable was not found")
        program = selected
    try:
        path = Path(program).resolve(strict=True)
    except OSError as error:
        raise UsageError("the trestle executable was not found") from error
    if not path.is_file() or not os.access(path, os.X_OK):
        raise UsageError("the trestle path is not an executable file")
    return path


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def repository_name(corpus: Corpus, case: CorpusCase) -> str:
    """Names a case's throwaway repository by its manifest position only."""
    return f"case-{corpus.cases.index(case) + 1:02d}"


def _summarize_inventory(path: Path) -> list[str]:
    try:
        if path.stat().st_size > 8 * 1024 * 1024:
            return ["  (larger than 8 MiB; not summarized)"]
        value = json.loads(path.read_bytes())
        routes = value["routes"]
        if not isinstance(routes, list):
            raise TypeError
    except (OSError, ValueError, KeyError, TypeError):
        return ["  (could not be read as a route inventory; not summarized)"]
    lines = []
    for route in routes[:64]:
        if not isinstance(route, dict):
            continue
        fields = []
        for key in ("zone", "provider_id", "model_id", "content_logging"):
            item = route.get(key)
            if isinstance(item, (str, bool)):
                fields.append(f"{key}={str(item).lower() if isinstance(item, bool) else item}")
        lines.append("  route " + " ".join(fields))
    if len(routes) > 64:
        lines.append(f"  ... {len(routes) - 64} more routes")
    return lines or ["  (no routes declared)"]


def _endpoints(value: Any, found: list[str]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "endpoint" and isinstance(item, str) and item not in found:
                found.append(item)
            else:
                _endpoints(item, found)
    elif isinstance(value, list):
        for item in value:
            _endpoints(item, found)


def _summarize_policy(path: Path) -> list[str]:
    try:
        if path.stat().st_size > 1024 * 1024:
            return ["  (larger than 1 MiB; not summarized)"]
        value = json.loads(path.read_bytes())
    except (OSError, ValueError):
        return ["  (could not be read as JSON; not summarized)"]
    found: list[str] = []
    _endpoints(value, found)
    lines = [f"  endpoint {endpoint}" for endpoint in found[:32]]
    if len(found) > 32:
        lines.append(f"  ... {len(found) - 32} more endpoints")
    return lines or ["  (no endpoint field found)"]


def describe_plan(
    *,
    corpus: Corpus,
    cases: Sequence[CorpusCase],
    trestle: Path,
    trestle_sha256: str,
    runs: int,
    operator: dict[str, str],
    output: Path,
) -> str:
    """Returns the disclosure printed before any run starts."""
    lines = [
        "Open Trestle model-review evaluation plan",
        "No model call has been made yet.",
        "",
        f"trestle: {trestle}",
        f"  sha256 {trestle_sha256}",
        f"corpus: {corpus.root} identity {corpus.identity} ({LABEL_STATUS})",
        f"cases: {len(cases)}; runs per case: {runs}; invocations: {len(cases) * runs}",
        "Each invocation runs `trestle local-git model-review --format json` over one throwaway Git repository. It normally",
        "requests candidate generation and independent verification from the routes the runtime policy selects;",
        "a run refused before dispatch requests neither. Every repeated run repeats those requests and any provider spend.",
        "egress " + EGRESS_DESCRIPTIONS[operator["--egress"]],
        f"tenant: {operator['--tenant']}; repository scope: {operator['--repository']}; timeout: {operator['--timeout']}",
        f"specialist profile: {operator.get('--profile', 'none')}",
        f"route inventory: {operator['--route-inventory']}",
        *_summarize_inventory(Path(operator["--route-inventory"])),
        f"runtime policy: {operator['--runtime-policy']}",
        *_summarize_policy(Path(operator["--runtime-policy"])),
        "The runtime policy and trestle decide which of these routes each request uses; this list is a disclosure, not a check.",
        "Source that may be sent (trestle selects changed hunks, removed lines and nearby context from these trees):",
    ]
    for case in cases:
        size = sum(len(data) for data in case.base.values()) + sum(len(data) for data in case.head.values())
        lines.append(
            f"  {repository_name(corpus, case)} {case.id}: changed {', '.join(case.changed_paths())}; "
            f"{len(case.base)} base and {len(case.head)} head files, {size} bytes"
        )
    lines.append(f"results: {output} (exact stdout and stderr, exit status and latency of every run)")
    return "\n".join(lines) + "\n"


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _signal_group(process: subprocess.Popen[bytes], value: signal.Signals) -> None:
    try:
        os.killpg(process.pid, value)
    except (ProcessLookupError, PermissionError):
        pass


@dataclasses.dataclass
class _Capture:
    limit: int
    content: bytearray = dataclasses.field(default_factory=bytearray)
    oversized: bool = False

    def append(self, chunk: bytes) -> None:
        room = self.limit - len(self.content)
        self.content.extend(chunk[: max(room, 0)])
        if len(chunk) > room:
            self.oversized = True


def capture_run(command: Sequence[str], *, timeout_seconds: float, cwd: Path) -> dict[str, Any]:
    """Runs one command in its own process group with bounded capture."""
    started = time.perf_counter_ns()
    try:
        process = subprocess.Popen(
            list(command),
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except (OSError, ValueError) as error:
        raise DriverError("the trestle process did not start") from error
    assert process.stdout is not None and process.stderr is not None
    stdout, stderr = _Capture(MAX_STDOUT_BYTES), _Capture(MAX_STDERR_BYTES)
    captures = {process.stdout.fileno(): stdout, process.stderr.fileno(): stderr}
    selector = selectors.DefaultSelector()
    termination = "exited"
    signalled_at: float | None = None
    try:
        for descriptor in captures:
            os.set_blocking(descriptor, False)
            selector.register(descriptor, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout_seconds
        while selector.get_map() or process.poll() is None:
            now = time.monotonic()
            if signalled_at is None and (stdout.oversized or stderr.oversized or now >= deadline):
                termination = "timed_out" if now >= deadline and not (stdout.oversized or stderr.oversized) else "output_limit"
                signalled_at = now
                _signal_group(process, signal.SIGTERM)
            if signalled_at is not None and now - signalled_at >= _KILL_DELAY_SECONDS:
                _signal_group(process, signal.SIGKILL)
                if now - signalled_at >= 2 * _KILL_DELAY_SECONDS and process.poll() is not None:
                    break
            if not selector.get_map():
                time.sleep(0.005)
                continue
            for key, _ in selector.select(0.01):
                try:
                    chunk = os.read(key.fd, 65536)
                except BlockingIOError:
                    continue
                if chunk:
                    captures[key.fd].append(chunk)
                else:
                    selector.unregister(key.fd)
    except BaseException:
        _signal_group(process, signal.SIGKILL)
        process.wait()
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    returncode = process.wait()
    latency_ns = time.perf_counter_ns() - started
    if termination == "exited" and returncode < 0:
        termination = "signaled"
    return {
        "termination": termination,
        "exit_code": returncode if returncode >= 0 else None,
        "signal": -returncode if returncode < 0 else None,
        "latency_ns": latency_ns,
        "stdout": bytes(stdout.content),
        "stderr": bytes(stderr.content),
    }


_TOKEN_COUNTS = ("input_tokens", "output_tokens", "cached_input_tokens")


def _token_count(value: Any) -> dict[str, Any] | None:
    """Returns one well-formed token count: counts present exactly when known."""
    if not isinstance(value, dict) or type(value.get("known")) is not bool:
        return None
    attempts = value.get("route_attempts")
    if type(attempts) is not int or attempts < 0:
        return None
    if not value["known"]:
        return {"known": False, "route_attempts": attempts} if set(value) == {"known", "route_attempts"} else None
    if set(value) != {"known", "route_attempts", *_TOKEN_COUNTS}:
        return None
    if any(type(value[key]) is not int or value[key] < 0 for key in _TOKEN_COUNTS) or value["cached_input_tokens"] > value["input_tokens"]:
        return None
    return {key: value[key] for key in ("known", "route_attempts", *_TOKEN_COUNTS)}


def read_token_usage(value: Any) -> dict[str, Any] | None:
    """Returns a result's token_usage when it is well formed, otherwise None.

    A version 6 result reports the provider-reported input, output and
    cached-input tokens summed over the run's route attempts, with generation
    and verification shares; the counts are absent, never zero, when not every
    attempt reported usage. Earlier result versions carry none.
    """
    if not isinstance(value, dict) or not {"generation", "verification"} <= set(value):
        return None
    total = _token_count({key: item for key, item in value.items() if key not in ("generation", "verification")})
    stages = [_token_count(value[stage]) for stage in ("generation", "verification")]
    if total is None or None in stages or total["route_attempts"] < sum(stage["route_attempts"] for stage in stages):
        return None
    if total["known"] and all(stage["known"] for stage in stages) and any(total[key] != sum(stage[key] for stage in stages) for key in _TOKEN_COUNTS):
        return None
    return {**total, "generation": stages[0], "verification": stages[1]}


def summarize_result(stdout: bytes) -> dict[str, Any]:
    """Copies status, usage, cost and token fields from one LF-terminated JSON result."""
    summary: dict[str, Any] = {
        "parsed": False,
        "contract": None,
        "schema_version": None,
        "status": None,
        "ci_disposition": None,
        "run_status": None,
        "usage_known": None,
        "actual_cost_micro_usd": None,
        "context_shortfall": None,
        "token_usage": None,
    }
    if not stdout.endswith(b"\n") or b"\n" in stdout[:-1]:
        return summary
    try:
        value = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return summary
    if not isinstance(value, dict):
        return summary
    summary["parsed"] = True
    for key in ("contract", "status", "ci_disposition", "run_status"):
        if isinstance(value.get(key), str) and len(value[key]) <= 256:
            summary[key] = value[key]
    for key, upper in (("schema_version", 1000), ("actual_cost_micro_usd", 2**64 - 1)):
        item = value.get(key)
        if type(item) is int and 0 <= item <= upper:
            summary[key] = item
    if type(value.get("usage_known")) is bool:
        summary["usage_known"] = value["usage_known"]
    shortfall = value.get("context_shortfall")
    fields = ("required_tokens", "estimated_input_tokens", "max_output_tokens", "declared_context_tokens")
    if isinstance(shortfall, dict) and set(shortfall) == set(fields) and all(type(shortfall[key]) is int and shortfall[key] >= 0 for key in fields):
        summary["context_shortfall"] = {key: shortfall[key] for key in fields}
    summary["token_usage"] = read_token_usage(value.get("token_usage"))
    return summary


def _write_new(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)


def _write_index(output: Path, bundle: dict[str, Any]) -> None:
    temporary = output / ".bundle.json.partial"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write((json.dumps(bundle, indent=2, ensure_ascii=True) + "\n").encode("ascii"))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, output / "bundle.json")


def run_corpus(
    *,
    corpus: Corpus,
    cases: Sequence[CorpusCase],
    trestle: Path,
    runs: int,
    operator_arguments: Sequence[str],
    output: Path,
    repository_authority: str,
    repository_namespace: str,
    work_parent: Path | None = None,
    grace_seconds: float = DEFAULT_GRACE_SECONDS,
) -> dict[str, Any]:
    """Runs every selected case ``runs`` times, round-robin, into a new bundle."""
    operator = parse_operator_arguments(operator_arguments)
    if not 1 <= runs <= MAX_RUNS:
        raise UsageError(f"--runs must be between 1 and {MAX_RUNS}")
    if not cases:
        raise UsageError("no case selected")
    timeout_seconds = parse_duration(operator["--timeout"]) + grace_seconds
    trestle_sha256 = file_sha256(trestle)
    os.mkdir(output, 0o700)
    os.mkdir(output / "runs", 0o700)
    bundle: dict[str, Any] = {
        "contract": BUNDLE_CONTRACT,
        "schema_version": 1,
        "review_state": "pending",
        "release_evidence_eligible": False,
        "label_status": LABEL_STATUS,
        "completion": "in_progress",
        "corpus_identity": corpus.identity,
        "manifest_sha256": corpus.manifest_sha256,
        "driver": DRIVER,
        "trestle_path": str(trestle),
        "trestle_sha256": trestle_sha256,
        "runs_per_case": runs,
        "operator_arguments": list(operator_arguments),
        "repository_authority": repository_authority,
        "repository_namespace": repository_namespace,
        "revision_algorithm": "sha1",
        "process_timeout_seconds": timeout_seconds,
        "environment": {
            "os": platform.system() or "unknown",
            "release": platform.release() or "unknown",
            "architecture": platform.machine() or "unknown",
            "python": platform.python_version(),
        },
        "started_at": _utc_now(),
        "finished_at": None,
        "cases": [],
    }
    with tempfile.TemporaryDirectory(prefix="open-trestle-model-corpus-", dir=work_parent) as work:
        repositories: list[MaterializedRepository] = []
        for case in cases:
            name = repository_name(corpus, case)
            repository = materialize_case(case, Path(work) / f"{name}.git")
            repositories.append(repository)
            os.mkdir(output / "runs" / case.id, 0o700)
            bundle["cases"].append(
                {
                    "case_id": case.id,
                    "labels_sha256": case.labels_sha256,
                    "repository_name": name,
                    "base_revision": repository.base_revision,
                    "head_revision": repository.head_revision,
                    "runs": [],
                }
            )
        _write_index(output, bundle)
        try:
            for run_index in range(1, runs + 1):
                for position, case in enumerate(cases):
                    repository = repositories[position]
                    command = [
                        str(trestle), "local-git", "model-review",
                        "--objects-root", str(repository.objects_root),
                        "--repository-authority", repository_authority,
                        "--repository-namespace", repository_namespace,
                        "--repository-name", bundle["cases"][position]["repository_name"],
                        "--revision-algorithm", "sha1",
                        "--base-revision-digest", repository.base_revision,
                        "--head-revision-digest", repository.head_revision,
                        *operator_arguments,
                        "--format", "json",
                    ]
                    started_at = _utc_now()
                    captured = capture_run(command, timeout_seconds=timeout_seconds, cwd=Path(work))
                    record: dict[str, Any] = {
                        "run_index": run_index,
                        "started_at": started_at,
                        "termination": captured["termination"],
                        "exit_code": captured["exit_code"],
                        "signal": captured["signal"],
                        "latency_ns": captured["latency_ns"],
                    }
                    for stream in ("stdout", "stderr"):
                        relative = f"runs/{case.id}/run-{run_index}.{stream}"
                        _write_new(output / relative, captured[stream])
                        record[stream] = {"path": relative, "sha256": hashlib.sha256(captured[stream]).hexdigest(), "bytes": len(captured[stream])}
                    record["result"] = summarize_result(captured["stdout"])
                    bundle["cases"][position]["runs"].append(record)
                    _write_index(output, bundle)
                    try:
                        unchanged = file_sha256(trestle) == trestle_sha256
                    except OSError:
                        unchanged = False
                    if not unchanged:
                        raise DriverError("the trestle executable changed during the batch")
        except KeyboardInterrupt:
            bundle["completion"], bundle["finished_at"] = "interrupted", _utc_now()
            _write_index(output, bundle)
            raise
        except BaseException:
            bundle["completion"], bundle["finished_at"] = "failed", _utc_now()
            _write_index(output, bundle)
            raise
    bundle["completion"], bundle["finished_at"] = "complete", _utc_now()
    _write_index(output, bundle)
    return bundle


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run trestle local-git model-review over the pending model-review corpus.",
        epilog="Operator setup flags follow --: --tenant, --repository, --route-inventory, --runtime-policy, --egress, --timeout and optionally --profile.",
    )
    parser.add_argument("--trestle", required=True, help="trestle executable to run")
    parser.add_argument("--output", type=Path, required=True, help="new bundle directory; must not exist")
    parser.add_argument("--corpus", type=Path, default=None)
    parser.add_argument("--runs", type=int, default=3, help="runs per case (1 to 10, default 3)")
    parser.add_argument("--case", action="append", default=[], help="run only this case; repeatable")
    parser.add_argument("--repository-authority", default="corpus.invalid")
    parser.add_argument("--repository-namespace", default="model-corpus-v1")
    parser.add_argument("--work-dir", type=Path, default=None, help="parent for the throwaway repositories")
    parser.add_argument("--confirm-model-calls", action="store_true", help="make the model calls the plan describes")
    parser.add_argument("operator", nargs=argparse.REMAINDER)
    args = parser.parse_args(arguments)
    operator_arguments = args.operator[1:] if args.operator[:1] == ["--"] else args.operator
    try:
        operator = parse_operator_arguments(operator_arguments)
        if not 1 <= args.runs <= MAX_RUNS:
            raise UsageError(f"--runs must be between 1 and {MAX_RUNS}")
        corpus = load_corpus(args.corpus or default_corpus_root())
        unknown = sorted(set(args.case) - {case.id for case in corpus.cases})
        if unknown:
            raise UsageError("unknown case: " + " ".join(unknown))
        cases = [case for case in corpus.cases if not args.case or case.id in args.case]
        trestle = resolve_executable(args.trestle)
        output = args.output.absolute()
        if output.exists() or output.is_symlink():
            raise UsageError("--output must name a new directory")
        trestle_sha256 = file_sha256(trestle)
    except (UsageError, CorpusError, OSError) as error:
        print(f"model runs: {error}", file=sys.stderr)
        return 2
    sys.stdout.write(
        describe_plan(corpus=corpus, cases=cases, trestle=trestle, trestle_sha256=trestle_sha256, runs=args.runs, operator=operator, output=output)
    )
    sys.stdout.flush()
    if not args.confirm_model_calls:
        print("Refusing to run: no model call was made. Pass --confirm-model-calls to make these calls.", file=sys.stderr)
        return 2
    try:
        bundle = run_corpus(
            corpus=corpus,
            cases=cases,
            trestle=trestle,
            runs=args.runs,
            operator_arguments=operator_arguments,
            output=output,
            repository_authority=args.repository_authority,
            repository_namespace=args.repository_namespace,
            work_parent=args.work_dir,
        )
    except KeyboardInterrupt:
        print(f"model runs: interrupted; recorded runs are in {output}", file=sys.stderr)
        return 1
    except (DriverError, CorpusError, OSError) as error:
        print(f"model runs: {error}; recorded runs, if any, are in {output}", file=sys.stderr)
        return 1
    recorded = sum(len(item["runs"]) for item in bundle["cases"])
    print(f"recorded {recorded} runs in {output / 'bundle.json'} ({LABEL_STATUS}; not release evidence)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
