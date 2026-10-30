#!/usr/bin/env python3
"""Run the product's manually invoked model metadata proposal or apply command."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
from collections.abc import Sequence


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trestle", required=True, type=Path, help="Installed product executable")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("refresh", "apply"):
        command = commands.add_parser(name)
        command.add_argument("--sources", required=True)
        command.add_argument("--current", required=True)
        command.add_argument("--proposal", required=True)
        if name == "refresh":
            command.add_argument("--allow-remote", action="store_true")
        else:
            command.add_argument("--expected-proposal", required=True)
            command.add_argument("--expected-current", required=True)
    args = parser.parse_args(argv)
    executable = str(args.trestle.absolute())
    command = [executable, "config", "models", args.command,
               "--sources", args.sources, "--current", args.current, "--proposal", args.proposal]
    if args.command == "refresh":
        if args.allow_remote:
            command.append("--allow-remote")
    else:
        command.extend(["--expected-proposal", args.expected_proposal,
                        "--expected-current", args.expected_current])
    os.execv(executable, command)


if __name__ == "__main__":
    main()
