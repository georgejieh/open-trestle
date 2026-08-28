"""Validate the tracked public repository boundary."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REQUIRED_PATHS = (
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "GOVERNANCE.md",
    "LICENSE",
    "NOTICE",
    "README.md",
    "SECURITY.md",
    "SUPPORT.md",
    "docs/architecture.md",
    "docs/development.md",
    "docs/public-boundary.md",
    "docs/roadmap.md",
)
FORBIDDEN_PREFIXES = (
    ".agents/",
    ".claude/",
    ".codex/",
    ".hermes/",
    "references/",
)
FORBIDDEN_PATHS = (
    ".hermes.md",
    "AGENTS.md",
    "CLAUDE.md",
)


def tracked_paths() -> tuple[str, ...]:
    """Return Git-tracked paths for the current checkout."""
    result = subprocess.run(
        ["git", "ls-files"],
        check=True,
        capture_output=True,
        text=True,
    )
    return tuple(path for path in result.stdout.splitlines() if path)


def find_violations(paths: tuple[str, ...]) -> list[str]:
    """Return public-boundary violations in tracked paths."""
    violations: list[str] = []
    path_set = set(paths)
    for required in REQUIRED_PATHS:
        if required not in path_set:
            violations.append(f"missing required public file: {required}")
    for path in paths:
        if path in FORBIDDEN_PATHS or path.startswith(FORBIDDEN_PREFIXES):
            violations.append(f"tracked private artifact: {path}")
    return violations


def main() -> int:
    """Run the repository-boundary validation."""
    if not Path(".git").exists():
        print("error: run from the repository root", file=sys.stderr)
        return 2
    violations = find_violations(tracked_paths())
    if violations:
        print("public-tree validation failed:", file=sys.stderr)
        for violation in violations:
            print(f"- {violation}", file=sys.stderr)
        return 1
    print("public-tree validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
