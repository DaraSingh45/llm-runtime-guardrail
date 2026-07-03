
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

from rules import ScanFinding, check_tool

_SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


@dataclass
class ScanReport:
    agent_name: str
    findings: List[ScanFinding]

    @property
    def highest_severity(self) -> str:
        if not self.findings:
            return "NONE"
        return max((f.severity for f in self.findings), key=lambda s: _SEVERITY_RANK[s])

    @property
    def passed(self) -> bool:
        return not any(f.severity in ("HIGH", "CRITICAL") for f in self.findings)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "agent_name": self.agent_name,
            "passed": self.passed,
            "highest_severity": self.highest_severity,
            "findings": [
                {"tool_name": f.tool_name, "label": f.label, "severity": f.severity, "detail": f.detail}
                for f in self.findings
            ],
        }


def scan_manifest(manifest: Dict[str, Any]) -> ScanReport:
    agent_name = manifest.get("agent_name", "<unnamed agent>")
    findings: List[ScanFinding] = []

    for tool in manifest.get("tools", []):
        findings.extend(check_tool(tool))

    return ScanReport(agent_name=agent_name, findings=findings)


def scan_file(path: str) -> ScanReport:
    manifest = json.loads(Path(path).read_text())
    return scan_manifest(manifest)
