
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import List, Optional

log = logging.getLogger("dlp-scanner")


@dataclass
class DlpFinding:
    label: str
    severity: str
    confidence: float
    detail: str
    redacted_span: str


def _redact(match_text: str) -> str:
    if len(match_text) <= 6:
        return "*" * len(match_text)
    return f"{match_text[:3]}{'*' * (len(match_text) - 5)}{match_text[-2:]}"


def _luhn_valid(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, digit in enumerate(digits):
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


_STRUCTURED_PATTERNS = [
    ("EMAIL_ADDRESS", "MEDIUM", 0.7, re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")),
    ("AWS_ACCESS_KEY_ID", "CRITICAL", 0.95, re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("OPENAI_STYLE_API_KEY", "CRITICAL", 0.9, re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("ANTHROPIC_STYLE_API_KEY", "CRITICAL", 0.9, re.compile(r"\bsk-ant-[A-Za-z0-9\-]{20,}\b")),
    ("GITHUB_TOKEN", "CRITICAL", 0.9, re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,40}\b")),
    ("SLACK_TOKEN", "CRITICAL", 0.9, re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")),
    ("JWT", "HIGH", 0.75, re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")),
    ("PRIVATE_KEY_BLOCK", "CRITICAL", 0.97, re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("PHONE_NUMBER", "LOW", 0.5, re.compile(r"\b(\+?\d{1,3}[\s.-]?)?\(?\d{3,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}\b")),
]

_CREDIT_CARD_CANDIDATE = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def _scan_structured(text: str) -> List[DlpFinding]:
    findings: List[DlpFinding] = []

    for label, severity, confidence, pattern in _STRUCTURED_PATTERNS:
        for match in pattern.finditer(text):
            findings.append(
                DlpFinding(
                    label=label,
                    severity=severity,
                    confidence=confidence,
                    detail=f"Matched {label} pattern",
                    redacted_span=_redact(match.group(0)),
                )
            )

    for match in _CREDIT_CARD_CANDIDATE.finditer(text):
        candidate = match.group(0)
        if _luhn_valid(candidate):
            findings.append(
                DlpFinding(
                    label="CREDIT_CARD_NUMBER",
                    severity="CRITICAL",
                    confidence=0.9,
                    detail="Matched a Luhn-valid credit card number",
                    redacted_span=_redact(candidate),
                )
            )

    return findings


class DlpScanner:
    def __init__(self, enable_ner: bool = True) -> None:
        self._nlp = self._load_ner(enable_ner)

    @staticmethod
    def _load_ner(enable_ner: bool):
        if not enable_ner:
            return None
        try:
            import spacy

            return spacy.load("en_core_web_sm")
        except Exception as exc:  # model not installed, or spaCy not installed at all
            log.warning(
                "NER layer unavailable (%s) -- structured regex detection still fully active. "
                "Run `python -m spacy download en_core_web_sm` to enable it.",
                exc,
            )
            return None

    def scan(self, text: str) -> List[DlpFinding]:
        findings = _scan_structured(text)

        if self._nlp is not None:
            doc = self._nlp(text)
            for ent in doc.ents:
                if ent.label_ in {"PERSON", "ORG", "GPE"}:
                    findings.append(
                        DlpFinding(
                            label=f"NER_{ent.label_}",
                            severity="LOW",
                            confidence=0.4,
                            detail=f"Named entity ({ent.label_}) detected",
                            redacted_span=_redact(ent.text),
                        )
                    )

        return findings
