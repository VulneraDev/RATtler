"""Command-line interface for explicit RATtler response actions."""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from .response import ResponseError, default_store, list_quarantine, quarantine_file, restore_file


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rattler response",
        description="Plan or apply explicit, reversible endpoint response actions.",
    )
    actions = parser.add_subparsers(dest="response_action", required=True)

    quarantine = actions.add_parser("quarantine", help="move one exact file into protected storage")
    quarantine.add_argument("path", help="regular file to inspect or quarantine")
    quarantine.add_argument("--reason", required=True, help="operator reason recorded in the audit log")
    quarantine.add_argument("--store", default=str(default_store()), help="quarantine store")
    quarantine.add_argument("--expected-sha256", help="hash returned by the dry run")
    quarantine.add_argument("--apply", action="store_true", help="apply the reviewed action")
    quarantine.add_argument("--pretty", action="store_true")

    restore = actions.add_parser("restore", help="restore one quarantined entry")
    restore.add_argument("id", help="quarantine entry ID")
    restore.add_argument("--store", default=str(default_store()), help="quarantine store")
    restore.add_argument("--apply", action="store_true", help="apply the reviewed restore")
    restore.add_argument("--pretty", action="store_true")

    listing = actions.add_parser("list", help="list quarantine manifests")
    listing.add_argument("--store", default=str(default_store()), help="quarantine store")
    listing.add_argument("--pretty", action="store_true")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.response_action == "quarantine":
            result = quarantine_file(
                Path(args.path),
                args.reason,
                Path(args.store),
                args.expected_sha256,
                args.apply,
            )
        elif args.response_action == "restore":
            result = restore_file(args.id, Path(args.store), args.apply)
        else:
            result = {"entries": list_quarantine(Path(args.store))}
    except (OSError, ResponseError, json.JSONDecodeError) as error:
        print(json.dumps({"error": "response action refused", "detail": str(error)}), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2 if args.pretty else None, sort_keys=True))
    return 0
