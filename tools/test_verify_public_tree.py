"""Tests for the tracked public repository boundary."""

from __future__ import annotations

import contextlib
import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import verify_public_tree as boundary


class TrackedBoundaryTest(unittest.TestCase):
    def test_required_public_files_are_accepted(self):
        self.assertEqual(boundary.find_violations(boundary.REQUIRED_PATHS), [])

    def test_missing_required_public_file_is_refused(self):
        paths = tuple(path for path in boundary.REQUIRED_PATHS if path != "README.md")
        self.assertEqual(
            boundary.find_violations(paths),
            ["missing required public file: README.md"],
        )

    def test_tracked_private_plan_is_refused(self):
        private = "references/agentic/plans/plans/local-plan.md"
        self.assertEqual(
            boundary.find_violations((*boundary.REQUIRED_PATHS, private)),
            [f"tracked private artifact: {private}"],
        )

    def test_tracked_local_agent_guidance_is_refused(self):
        self.assertEqual(
            boundary.find_violations((*boundary.REQUIRED_PATHS, "AGENTS.md", "CLAUDE.md", "docs/AGENTS.md")),
            [
                "tracked private artifact: AGENTS.md",
                "tracked private artifact: CLAUDE.md",
                "tracked agent-tool configuration: docs/AGENTS.md",
            ],
        )

    def test_nested_agent_tool_configuration_is_refused(self):
        forbidden = (
            "docs/CLAUDE.md",
            "pkg/CLAUDE.md",
            "GEMINI.md",
            ".cursorrules",
            ".claude/settings.json",
            ".claude/commands/review.md",
            ".cursor/rules/go.mdc",
            ".codex/config.toml",
            "prompts/review.prompt",
            ".github/prompts/review.prompt.md",
            ".github/copilot-instructions.md",
            "docs/review.prompt.md",
            "docs/review.prompty",
        )
        for path in forbidden:
            with self.subTest(path=path):
                self.assertEqual(
                    boundary.find_violations((*boundary.REQUIRED_PATHS, path)),
                    [f"tracked agent-tool configuration: {path}"],
                )

    def test_shipped_product_profiles_and_product_paths_are_accepted(self):
        accepted = (
            "agentprofile/skills/backend.md",
            "agentprofile/skills/security_probe.md",
            "cmd/trestle/mcp.go",
            "mcpserver/server.go",
            "adapters/providers/openai/adapter.go",
            "docs/mcp.md",
            "docs/remote-model-review.md",
        )
        self.assertEqual(
            boundary.find_violations((*boundary.REQUIRED_PATHS, *accepted)), []
        )

    def test_shipped_product_profiles_are_accepted(self):
        profiles = (
            "agentprofile/catalog.go",
            "agentprofile/skills/backend.md",
            "agentprofile/skills/bug_hunter.md",
            "agentprofile/skills/drift_auditor.md",
            "agentprofile/skills/frontend.md",
            "agentprofile/skills/knowledge_graph.md",
            "agentprofile/skills/orchestrator.md",
            "agentprofile/skills/security_probe.md",
            "agentprofile/skills/style_conformance.md",
            "agentprofile/skills/test_author.md",
        )
        self.assertEqual(
            boundary.find_violations((*boundary.REQUIRED_PATHS, *profiles)), []
        )

    def test_tracked_names_are_nul_delimited(self):
        result = subprocess.CompletedProcess([], 0, "README.md\0file\nname.md\0", "")
        with patch.object(boundary.subprocess, "run", return_value=result) as run:
            self.assertEqual(
                boundary.tracked_paths(Path("checkout")),
                ("README.md", "file\nname.md"),
            )
        self.assertEqual(run.call_args.args[0], [
            "git", "-C", "checkout", "ls-files", "--cached", "--full-name", "-z"
        ])


class CheckoutModeTest(unittest.TestCase):
    def invoke(self, root: Path, mode: str) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            patch.object(boundary, "tracked_paths", return_value=boundary.REQUIRED_PATHS),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            status = boundary.main(["--mode", mode], root=root)
        return status, stdout.getvalue(), stderr.getvalue()

    def test_clean_checkout_does_not_require_ignored_private_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".git").mkdir()
            (root / ".gitignore").write_text("references/\n", encoding="utf-8")
            status, stdout, stderr = self.invoke(root, "clean-checkout")
        self.assertEqual(status, 0, stderr)
        self.assertIn("tracked-path", stdout)
        self.assertIn("not a secrets", stdout)

    def test_local_checkout_allows_ignored_private_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".git").mkdir()
            (root / ".gitignore").write_text("references/\n", encoding="utf-8")
            plan = root / "references/agentic/plans/plans/local-plan.md"
            plan.parent.mkdir(parents=True)
            plan.write_text("local only\n", encoding="utf-8")
            status, _, stderr = self.invoke(root, "local")
        self.assertEqual(status, 0, stderr)

    def test_clean_checkout_refuses_present_private_references(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".git").mkdir()
            (root / "references").mkdir()
            status, _, stderr = self.invoke(root, "clean-checkout")
        self.assertEqual(status, 1)
        self.assertIn("private local material present: references/", stderr)

    def test_linked_worktree_git_file_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".git").write_text("gitdir: /private/worktrees/checkout\n", encoding="utf-8")
            status, _, stderr = self.invoke(root, "clean-checkout")
        self.assertEqual(status, 0, stderr)

    def test_non_root_directory_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            status, _, stderr = self.invoke(Path(directory), "local")
        self.assertEqual(status, 2)
        self.assertIn("repository root", stderr)

    def test_git_inventory_failure_does_not_report_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".git").mkdir()
            with (
                patch.object(boundary, "tracked_paths", side_effect=subprocess.CalledProcessError(128, "git")),
                contextlib.redirect_stdout(io.StringIO()) as stdout,
                contextlib.redirect_stderr(io.StringIO()),
            ):
                status = boundary.main([], root=root)
        self.assertEqual(status, 2)
        self.assertEqual(stdout.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
