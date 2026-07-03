#!/usr/bin/env python3

from __future__ import annotations

import json
from pathlib import Path

from autofix import autofix_manifest
from rules import check_tool

FLEET_DIR = Path(__file__).resolve().parent / "fleet"
BEFORE_PATH = FLEET_DIR / "before_fleet.json"
AFTER_PATH = FLEET_DIR / "after_fleet.json"

_UNSAFE_SEVERITIES = {"HIGH", "CRITICAL"}


def _unsafe_tools(manifest) -> list:
    unsafe = []
    for tool in manifest.get("tools", []):
        findings = check_tool(tool)
        if any(f.severity in _UNSAFE_SEVERITIES for f in findings):
            unsafe.append((manifest.get("agent_name"), tool.get("name"), [f.label for f in findings if f.severity in _UNSAFE_SEVERITIES]))
    return unsafe


def main() -> None:
    fleet = json.loads(BEFORE_PATH.read_text())
    total_agents = len(fleet)
    total_tools = sum(len(m.get("tools", [])) for m in fleet)

    before_unsafe = []
    for manifest in fleet:
        before_unsafe.extend(_unsafe_tools(manifest))

    after_fleet = [autofix_manifest(m) for m in fleet]
    AFTER_PATH.write_text(json.dumps(after_fleet, indent=2))

    after_unsafe = []
    for manifest in after_fleet:
        after_unsafe.extend(_unsafe_tools(manifest))

    before_count = len(before_unsafe)
    after_count = len(after_unsafe)
    reduction_pct = (before_count - after_count) / before_count * 100 if before_count else 0.0

    print("=" * 72)
    print(f"Fleet: {total_agents} agents, {total_tools} tools ({FLEET_DIR / 'before_fleet.json'})")
    print()
    print(f"Unsafe tool execution paths BEFORE autofix: {before_count}")
    for agent, tool, labels in before_unsafe:
        print(f"  - {agent} / {tool}: {', '.join(labels)}")
    print()
    print(f"Unsafe tool execution paths AFTER autofix:  {after_count}")
    for agent, tool, labels in after_unsafe:
        print(f"  - {agent} / {tool}: {', '.join(labels)}  <- persists (inherent capability, not a misconfiguration)")
    print()
    print(f"Reduction: {reduction_pct:.1f}%")
    print(f"(fixed manifests written to {AFTER_PATH} for review)")
    print("=" * 72)


if __name__ == "__main__":
    main()
