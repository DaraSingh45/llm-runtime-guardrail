
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class ScanFinding:
    tool_name: str
    label: str
    severity: str
    detail: str


def _check_filesystem_tool(tool: Dict[str, Any]) -> List[ScanFinding]:
    findings = []
    paths = tool.get("allowed_paths")
    name = tool.get("name", "<unnamed>")

    if not paths:
        findings.append(
            ScanFinding(name, "UNRESTRICTED_FILESYSTEM_ACCESS", "CRITICAL", "Filesystem tool declares no allowed_paths -- implies unrestricted read/write.")
        )
    elif any(p in ("/", "/*", "**", "C:\\") for p in paths):
        findings.append(
            ScanFinding(name, "OVERBROAD_FILESYSTEM_SCOPE", "CRITICAL", f"allowed_paths includes a root/wildcard path: {paths}")
        )

    if tool.get("allow_write") and not tool.get("allowed_paths"):
        findings.append(ScanFinding(name, "UNSCOPED_WRITE_ACCESS", "CRITICAL", "Write access enabled with no path scoping."))

    return findings


def _check_network_tool(tool: Dict[str, Any]) -> List[ScanFinding]:
    findings = []
    hosts = tool.get("allowed_hosts")
    name = tool.get("name", "<unnamed>")

    if not hosts:
        findings.append(
            ScanFinding(name, "UNRESTRICTED_NETWORK_ACCESS", "CRITICAL", "Network tool declares no allowed_hosts -- can reach any host, including internal/metadata endpoints.")
        )
    elif any(h in ("*", "0.0.0.0/0") for h in hosts):
        findings.append(ScanFinding(name, "WILDCARD_NETWORK_SCOPE", "CRITICAL", f"allowed_hosts includes a wildcard: {hosts}"))

    return findings


def _check_shell_tool(tool: Dict[str, Any]) -> List[ScanFinding]:
    name = tool.get("name", "<unnamed>")
    findings = [ScanFinding(name, "SHELL_EXECUTION_CAPABILITY", "HIGH", "Tool grants arbitrary shell/code execution -- highest-impact capability an agent can hold.")]
    if not tool.get("requires_human_approval"):
        findings.append(
            ScanFinding(name, "SHELL_WITHOUT_HUMAN_APPROVAL", "CRITICAL", "Shell execution tool has no human-approval gate configured.")
        )
    return findings


def _check_credential_scope(tool: Dict[str, Any]) -> List[ScanFinding]:
    name = tool.get("name", "<unnamed>")
    scopes = tool.get("credential_scopes", [])
    findings = []
    if any(s in ("admin", "*", "full_access") for s in scopes):
        findings.append(ScanFinding(name, "OVERBROAD_CREDENTIAL_SCOPE", "CRITICAL", f"Tool holds an admin/wildcard credential scope: {scopes}"))
    return findings


def _check_rate_limit(tool: Dict[str, Any]) -> List[ScanFinding]:
    name = tool.get("name", "<unnamed>")
    if tool.get("type") in ("network", "shell") and not tool.get("rate_limit_per_minute"):
        return [ScanFinding(name, "MISSING_RATE_LIMIT", "MEDIUM", "No rate_limit_per_minute set on a network/shell-capable tool -- no throttle on repeated/automated abuse.")]
    return []


_CHECKS_BY_TYPE = {
    "filesystem": _check_filesystem_tool,
    "network": _check_network_tool,
    "shell": _check_shell_tool,
}


def check_tool(tool: Dict[str, Any]) -> List[ScanFinding]:
    findings: List[ScanFinding] = []
    tool_type = tool.get("type")

    check_fn = _CHECKS_BY_TYPE.get(tool_type)
    if check_fn:
        findings.extend(check_fn(tool))

    findings.extend(_check_credential_scope(tool))
    findings.extend(_check_rate_limit(tool))

    return findings
