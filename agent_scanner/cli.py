#!/usr/bin/env python3
"""
Usage:
    python -m agent_scanner.cli agent_scanner/examples/risky_agent.json
    python -m agent_scanner.cli agent_scanner/examples/safe_agent.json

Exits non-zero if any HIGH/CRITICAL finding is present -- wire this into a
CI step to gate on agent tool definitions the same way you'd gate on any
other static analysis check.
"""
from __future__ import annotations

import json
import sys

from scanner import scan_file


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python -m agent_scanner.cli <manifest.json>")
        sys.exit(2)

    report = scan_file(sys.argv[1])
    print(json.dumps(report.as_dict(), indent=2))

    if not report.passed:
        print(f"\nFAILED: {report.agent_name} has HIGH/CRITICAL findings.", file=sys.stderr)
        sys.exit(1)

    print(f"\nPASSED: {report.agent_name} has no HIGH/CRITICAL findings.")


if __name__ == "__main__":
    main()
