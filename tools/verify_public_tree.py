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

# Repository AI-tool configuration stays out of the published tree. These are
# the conventions the harness recognizes when reading a repository under review
# (see internal/review.agentConfigurationPath and
# docs/prompt-injection-boundary.md); shipping them here would couple the
# published tree to one vendor's local tooling.
AGENT_CONFIGURATION_FILE_NAMES = frozenset(
    ("agents.md", "claude.md", "gemini.md", ".cursorrules", "skill.md")
)
AGENT_CONFIGURATION_DIRECTORIES = frozenset(
    (".cursor", ".claude", ".codex", ".trestle", "prompts")
)
# The harness ships its own specialist profiles under agentprofile/skills.
# Those are product assets, not repository AI-tool configuration, so they stay
# tracked.
SHIPPED_PROFILE_PREFIXES = ("agentprofile/skills/",)


def tracked_paths(root: Path = Path(".")) -> tuple[str, ...]:
    """Return the index's public-boundary inventory without splitting filenames."""
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--cached", "--full-name", "-z"],
        check=True,
        capture_output=True,
        text=True,
    )
    return tuple(path for path in result.stdout.split("\0") if path)


def is_agent_configuration(path: str) -> bool:
    """Report whether a tracked path is repository AI-tool configuration.

    The rules mirror internal/review.agentConfigurationPath, except that the
    harness's own shipped specialist profiles are product assets and remain
    tracked.
    """
    normalized = path.replace("\\", "/")
    if normalized.startswith(SHIPPED_PROFILE_PREFIXES):
        return False
    segments = normalized.split("/")
    base = segments[-1].lower()
    if base in AGENT_CONFIGURATION_FILE_NAMES:
        return True
    if base.endswith(".prompt") or base.endswith(".prompt.md") or base.endswith(".prompty"):
        return True
    directories = segments[:-1]
    for index, directory in enumerate(directories):
        lowered = directory.lower()
        if lowered in AGENT_CONFIGURATION_DIRECTORIES:
            return True
        if lowered == "skills" and base.endswith(".md"):
            return True
        if lowered == ".github" and index == len(directories) - 1 and base == "copilot-instructions.md":
            return True
    return False


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
        elif is_agent_configuration(path):
            violations.append(f"tracked agent-tool configuration: {path}")
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
    print("Scope: required tracked paths, private-reference paths, and "
          "repository AI-tool configuration paths only; "
          "not a secrets, history, content, link, or release-artifact audit.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
