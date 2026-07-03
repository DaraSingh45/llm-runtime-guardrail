from autofix import SENTINEL, apply_fixes, autofix_manifest
from rules import check_tool


def _refix(tool):
    """Helper: run check_tool -> apply_fixes in one step, like benchmark.py does."""
    return apply_fixes(tool, check_tool(tool))


def test_unrestricted_filesystem_gets_sentinel_path():
    tool = {"name": "t", "type": "filesystem", "allow_write": False}
    fixed = _refix(tool)
    assert fixed["allowed_paths"] == [SENTINEL]
    assert fixed["needs_review"] is True
    assert check_tool(fixed) == []  # no findings left


def test_unscoped_write_access_forced_to_read_only():
    tool = {"name": "t", "type": "filesystem", "allow_write": True}
    fixed = _refix(tool)
    assert fixed["allow_write"] is False
    assert check_tool(fixed) == []


def test_wildcard_network_scope_gets_sentinel_host():
    tool = {"name": "t", "type": "network", "allowed_hosts": ["*"], "rate_limit_per_minute": 10}
    fixed = _refix(tool)
    assert fixed["allowed_hosts"] == [SENTINEL]
    assert check_tool(fixed) == []


def test_shell_without_approval_gets_approval_flag_but_capability_finding_persists():
    tool = {"name": "t", "type": "shell", "requires_human_approval": False}
    fixed = _refix(tool)
    assert fixed["requires_human_approval"] is True

    remaining = check_tool(fixed)
    labels = {f.label for f in remaining}
    # The critical misconfiguration is fixed...
    assert "SHELL_WITHOUT_HUMAN_APPROVAL" not in labels
    # ...but the inherent capability finding is not, and should not be --
    # no config change makes a shell tool not a shell tool.
    assert "SHELL_EXECUTION_CAPABILITY" in labels


def test_overbroad_credential_scope_gets_sentinel():
    tool = {"name": "t", "type": "network", "allowed_hosts": ["example.com"], "rate_limit_per_minute": 10, "credential_scopes": ["admin"]}
    fixed = _refix(tool)
    assert fixed["credential_scopes"] == [SENTINEL]
    assert check_tool(fixed) == []


def test_missing_rate_limit_gets_conservative_default():
    tool = {"name": "t", "type": "network", "allowed_hosts": ["example.com"]}
    fixed = _refix(tool)
    assert fixed["rate_limit_per_minute"] == 10


def test_already_safe_tool_is_untouched():
    tool = {"name": "t", "type": "filesystem", "allowed_paths": ["/data/safe"], "allow_write": False}
    findings = check_tool(tool)
    assert findings == []
    fixed = apply_fixes(tool, findings)
    assert fixed == tool
    assert "needs_review" not in fixed


def test_autofix_manifest_does_not_mutate_input():
    manifest = {"agent_name": "a", "tools": [{"name": "t", "type": "filesystem", "allow_write": True}]}
    import copy

    original = copy.deepcopy(manifest)
    autofix_manifest(manifest)
    assert manifest == original


def test_autofix_manifest_fixes_every_tool_with_findings():
    manifest = {
        "agent_name": "a",
        "tools": [
            {"name": "fs", "type": "filesystem", "allow_write": True},
            {"name": "net", "type": "network", "allowed_hosts": ["example.com"], "rate_limit_per_minute": 5},
        ],
    }
    fixed = autofix_manifest(manifest)
    assert check_tool(fixed["tools"][0]) == []
    assert check_tool(fixed["tools"][1]) == []
