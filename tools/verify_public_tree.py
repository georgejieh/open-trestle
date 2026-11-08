"""Validate tracked public paths, with an optional clean-checkout boundary."""

from __future__ import annotations

import argparse
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
    "docs/roadmap.md",
)
FORBIDDEN_PREFIXES = ("references/",)
# Local coding-agent guidance stays out of the published tree.
FORBIDDEN_PATHS = frozenset(("AGENTS.md", "CLAUDE.md"))


def tracked_paths(root: Path = Path(".")) -> tuple[str, ...]:
    """Return the index's public-boundary inventory without splitting filenames."""
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--cached", "--full-name", "-z"],
        check=True,
        capture_output=True,
        text=True,
    )
    return tuple(path for path in result.stdout.split("\0") if path)


def find_violations(paths: tuple[str, ...]) -> list[str]:
    """Return missing public files and tracked private-reference paths."""
    violations: list[str] = []
    path_set = set(paths)
    for required in REQUIRED_PATHS:
        if required not in path_set:
            violations.append(f"missing required public file: {required}")
    for path in paths:
        if path.startswith(FORBIDDEN_PREFIXES) or path in FORBIDDEN_PATHS:
            violations.append(f"tracked private artifact: {path}")
    return violations


def main(argv: list[str] | None = None, *, root: Path = Path(".")) -> int:
    """Validate tracked paths; clean-checkout mode also excludes local references."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        choices=("local", "clean-checkout"),
        default="local",
        help="local permits untracked references; clean-checkout requires them absent",
    )
    arguments = parser.parse_args(argv)
    if not (root / ".git").exists():
        print("error: run from the repository root", file=sys.stderr)
        return 2
    try:
        violations = find_violations(tracked_paths(root))
    except (OSError, subprocess.CalledProcessError):
        print("error: tracked public paths could not be read", file=sys.stderr)
        return 2
    if arguments.mode == "clean-checkout":
        for prefix in FORBIDDEN_PREFIXES:
            path = root / prefix.rstrip("/")
            if path.exists() or path.is_symlink():
                violations.append(f"private local material present: {prefix}")
    if violations:
        print("public tracked-path validation failed:", file=sys.stderr)
        for violation in violations:
            print(f"- {violation}", file=sys.stderr)
        return 1
    print(f"public tracked-path validation passed (mode={arguments.mode})")
    print("Scope: required tracked paths and private-reference paths only; "
          "not a secrets, history, content, link, or release-artifact audit.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
