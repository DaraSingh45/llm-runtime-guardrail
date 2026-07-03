from scanner import scan_manifest


def test_filesystem_tool_with_no_paths_flags_unrestricted():
    manifest = {"agent_name": "a", "tools": [{"name": "fs", "type": "filesystem", "allow_write": True}]}
    report = scan_manifest(manifest)
    labels = {f.label for f in report.findings}
    assert "UNRESTRICTED_FILESYSTEM_ACCESS" in labels
    assert report.passed is False


def test_filesystem_tool_with_scoped_read_only_path_passes():
    manifest = {
        "agent_name": "a",
        "tools": [{"name": "fs", "type": "filesystem", "allowed_paths": ["/data/read-only"], "allow_write": False}],
    }
    report = scan_manifest(manifest)
    assert report.passed is True


def test_network_tool_wildcard_host_flagged():
    manifest = {"agent_name": "a", "tools": [{"name": "net", "type": "network", "allowed_hosts": ["*"]}]}
    report = scan_manifest(manifest)
    labels = {f.label for f in report.findings}
    assert "WILDCARD_NETWORK_SCOPE" in labels


def test_shell_tool_without_approval_is_critical():
    manifest = {"agent_name": "a", "tools": [{"name": "sh", "type": "shell", "requires_human_approval": False}]}
    report = scan_manifest(manifest)
    assert report.highest_severity == "CRITICAL"


def test_admin_credential_scope_flagged_regardless_of_tool_type():
    manifest = {
        "agent_name": "a",
        "tools": [{"name": "net", "type": "network", "allowed_hosts": ["example.com"], "credential_scopes": ["admin"]}],
    }
    report = scan_manifest(manifest)
    labels = {f.label for f in report.findings}
    assert "OVERBROAD_CREDENTIAL_SCOPE" in labels


def test_empty_manifest_passes_with_no_findings():
    report = scan_manifest({"agent_name": "empty", "tools": []})
    assert report.passed is True
    assert report.findings == []


def test_safe_example_manifest_passes(tmp_path):
    from scanner import scan_file
    import json
    from pathlib import Path

    example_path = Path(__file__).resolve().parent.parent / "agent_scanner" / "examples" / "safe_agent.json"
    report = scan_file(str(example_path))
    assert report.passed is True


def test_risky_example_manifest_fails():
    from scanner import scan_file
    from pathlib import Path

    example_path = Path(__file__).resolve().parent.parent / "agent_scanner" / "examples" / "risky_agent.json"
    report = scan_file(str(example_path))
    assert report.passed is False
    assert report.highest_severity == "CRITICAL"
