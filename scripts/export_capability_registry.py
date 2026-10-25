#!/usr/bin/env python3
"""Print the canonical capability registry as JSON or CSV (read-only)."""
from __future__ import annotations

import argparse
import json

from packages.capability_registry import csv_text, snapshot


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--format", choices=("json", "csv"), default="json")
    args = parser.parse_args()
    if args.format == "csv":
        print(csv_text(), end="")
    else:
        print(json.dumps(snapshot(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
