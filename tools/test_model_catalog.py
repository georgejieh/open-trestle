"""Check that the manual wrapper delegates to the product CLI without provider I/O."""
from __future__ import annotations

import unittest
from unittest.mock import patch

import model_catalog


class ModelCatalogWrapperTests(unittest.TestCase):
    def test_refresh_executes_only_product_cli(self) -> None:
        with patch("model_catalog.os.execv") as execute:
            model_catalog.main([
                "--trestle", "/opt/trestle/bin/trestle", "refresh",
                "--sources", "/private/sources.json", "--current", "/private/models.json",
                "--proposal", "/private/proposal.json", "--allow-remote",
            ])
        execute.assert_called_once_with("/opt/trestle/bin/trestle", [
            "/opt/trestle/bin/trestle", "config", "models", "refresh",
            "--sources", "/private/sources.json", "--current", "/private/models.json",
            "--proposal", "/private/proposal.json", "--allow-remote",
        ])

    def test_apply_passes_review_digests(self) -> None:
        with patch("model_catalog.os.execv") as execute:
            model_catalog.main([
                "--trestle", "/opt/trestle/bin/trestle", "apply",
                "--sources", "sources", "--current", "models", "--proposal", "proposal",
                "--expected-proposal", "a" * 64, "--expected-current", "absent",
            ])
        self.assertEqual(execute.call_args.args[1][-4:], [
            "--expected-proposal", "a" * 64, "--expected-current", "absent",
        ])

    def test_rejects_auth_and_incomplete_apply(self) -> None:
        for args in [
            ["--trestle", "/opt/trestle", "refresh", "--api-key", "secret"],
            ["--trestle", "/opt/trestle", "apply", "--sources", "s", "--current", "c", "--proposal", "p"],
        ]:
            with patch("model_catalog.os.execv") as execute, self.assertRaises(SystemExit):
                model_catalog.main(args)
            execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
