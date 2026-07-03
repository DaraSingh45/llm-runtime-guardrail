
from __future__ import annotations

import copy
from typing import Any, Dict, List

from rules import ScanFinding, check_tool

SENTINEL = "__NEEDS_REVIEW__"


def apply_fixes(tool: Dict[str, Any], findings: List[ScanFinding]) -> Dict[str, Any]:
    fixed = dict(tool)
    labels = {f.label for f in findings}
    changed = False

    if "UNRESTRICTED_FILESYSTEM_ACCESS" in labels or "OVERBROAD_FILESYSTEM_SCOPE" in labels:
        fixed["allowed_paths"] = [SENTINEL]
        changed = True

    if "UNSCOPED_WRITE_ACCESS" in labels:
        # Deny write by default until a human scopes allowed_paths for real.
        fixed["allow_write"] = False
        changed = True

    if "UNRESTRICTED_NETWORK_ACCESS" in labels or "WILDCARD_NETWORK_SCOPE" in labels:
        fixed["allowed_hosts"] = [SENTINEL]
        changed = True

    if "SHELL_WITHOUT_HUMAN_APPROVAL" in labels:
        fixed["requires_human_approval"] = True
        changed = True

    if "OVERBROAD_CREDENTIAL_SCOPE" in labels:
        fixed["credential_scopes"] = [SENTINEL]
        changed = True

    if "MISSING_RATE_LIMIT" in labels:
        fixed["rate_limit_per_minute"] = 10  # conservative default
        changed = True

    if changed:
        fixed["needs_review"] = True

    return fixed


def autofix_manifest(manifest: Dict[str, Any]) -> Dict[str, Any]:
    """Returns a new manifest with every tool's fixable findings resolved.
    Does not mutate the input."""
    fixed_manifest = copy.deepcopy(manifest)
    fixed_tools = []

    for tool in fixed_manifest.get("tools", []):
        findings = check_tool(tool)
        fixed_tools.append(apply_fixes(tool, findings) if findings else tool)

    fixed_manifest["tools"] = fixed_tools
    return fixed_manifest
