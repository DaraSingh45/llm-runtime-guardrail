import json
from pathlib import Path

from autofix import autofix_manifest
from benchmark import BEFORE_PATH, _unsafe_tools

FLEET = json.loads(Path(BEFORE_PATH).read_text())


def test_fleet_has_expected_shape():
    assert len(FLEET) == 15
    total_tools = sum(len(a["tools"]) for a in FLEET)
    assert total_tools == 22


def test_before_fleet_has_unsafe_tools():
    before = [t for agent in FLEET for t in _unsafe_tools(agent)]
    assert len(before) > 0


def test_autofix_meaningfully_reduces_unsafe_tool_count():
    before = [t for agent in FLEET for t in _unsafe_tools(agent)]
    after_fleet = [autofix_manifest(a) for a in FLEET]
    after = [t for agent in after_fleet for t in _unsafe_tools(agent)]

    assert len(after) < len(before)
    reduction_pct = (len(before) - len(after)) / len(before) * 100
    # Regression guard, not a target to tune toward: fails loudly if a
    # future change to the fleet or the rules silently guts autofix's
    # effectiveness, without hardcoding an exact percentage to chase.
    assert reduction_pct > 40


def test_every_remaining_unsafe_tool_after_autofix_is_a_shell_tool():
    # By design, autofix cannot remove the inherent SHELL_EXECUTION_
    # CAPABILITY finding -- so anything still flagged after autofix should
    # be a shell tool, not a leftover fixable misconfiguration.
    after_fleet = [autofix_manifest(a) for a in FLEET]
    for agent in after_fleet:
        for tool in agent["tools"]:
            from rules import check_tool

            findings = check_tool(tool)
            unsafe = [f for f in findings if f.severity in ("HIGH", "CRITICAL")]
            if unsafe:
                assert tool["type"] == "shell", f"{agent['agent_name']}/{tool['name']} still unsafe but not a shell tool: {unsafe}"
