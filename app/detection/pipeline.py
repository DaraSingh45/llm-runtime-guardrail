
from __future__ import annotations

from typing import List

from config import DLP_BLOCK_SEVERITIES, INJECTION_BLOCK_THRESHOLD
from detection import injection_rules, url_scanner
from detection.dlp_scanner import DlpScanner
from detection.injection_classifier import InjectionClassifier
from models import Finding, GuardrailDecision

_SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _combine_injection_score(rule_findings, classifier_score: float) -> float:
    if not rule_findings:
        return classifier_score * 0.6  # classifier alone is weighted down -- it's the noisier signal

    top_rule_confidence = max(f.confidence for f in rule_findings)
    # Two independent signals agreeing pushes the combined score up; either
    # one alone is more likely to be a false positive.
    return min(1.0, 0.75 * top_rule_confidence + 0.25 * classifier_score)


class GuardrailPipeline:
    def __init__(self, classifier: InjectionClassifier, dlp_scanner: DlpScanner) -> None:
        self._classifier = classifier
        self._dlp = dlp_scanner

    def evaluate(self, text: str) -> GuardrailDecision:
        findings: List[Finding] = []

        rule_findings = injection_rules.scan(text)
        classifier_score = self._classifier.score(text)
        combined_score = _combine_injection_score(rule_findings, classifier_score)

        for rf in rule_findings:
            findings.append(
                Finding(layer="RULES", label=rf.label, severity=rf.severity, confidence=rf.confidence, detail=rf.detail)
            )
        if classifier_score >= 0.5:
            findings.append(
                Finding(
                    layer="CLASSIFIER",
                    label="PROMPT_INJECTION_LIKELY",
                    severity="MEDIUM",
                    confidence=classifier_score,
                    detail=f"TF-IDF/LogReg classifier score {classifier_score:.2f}",
                )
            )

        dlp_findings = self._dlp.scan(text)
        for df in dlp_findings:
            findings.append(
                Finding(
                    layer="DLP",
                    label=df.label,
                    severity=df.severity,
                    confidence=df.confidence,
                    detail=df.detail,
                    redacted_span=df.redacted_span,
                )
            )

        url_findings = url_scanner.scan(text)
        for uf in url_findings:
            findings.append(
                Finding(layer="URL_SCAN", label=uf.label, severity=uf.severity, confidence=uf.confidence, detail=uf.detail)
            )

        blocking_dlp = [f for f in dlp_findings if f.severity in DLP_BLOCK_SEVERITIES]
        if blocking_dlp:
            labels = ", ".join(sorted({f.label for f in blocking_dlp}))
            return GuardrailDecision(allowed=False, findings=findings, blocked_reason=f"DLP: sensitive data detected ({labels})")

        if combined_score >= INJECTION_BLOCK_THRESHOLD:
            return GuardrailDecision(
                allowed=False,
                findings=findings,
                blocked_reason=f"Prompt injection suspected (combined score {combined_score:.2f})",
            )

        return GuardrailDecision(allowed=True, findings=findings)
