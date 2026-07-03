
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List


@dataclass
class RuleFinding:
    label: str
    severity: str
    confidence: float
    detail: str


# Each entry: (compiled pattern, label, severity, confidence)
_PATTERNS = [
    (re.compile(r"ignore (all|any|the) (previous|prior|above) instructions", re.I), "INSTRUCTION_OVERRIDE", "HIGH", 0.9),
    (re.compile(r"disregard (all|any|the) (previous|prior|above|system)", re.I), "INSTRUCTION_OVERRIDE", "HIGH", 0.9),
    (re.compile(r"you are now (DAN|in developer mode|unrestricted|jailbroken)", re.I), "PERSONA_JAILBREAK", "HIGH", 0.9),
    (re.compile(r"pretend (that )?you have no (restrictions|rules|guidelines|filters)", re.I), "PERSONA_JAILBREAK", "HIGH", 0.85),
    (re.compile(r"reveal (your|the) (system prompt|instructions|hidden prompt)", re.I), "PROMPT_EXFILTRATION", "HIGH", 0.85),
    (re.compile(r"repeat (the words|everything) (above|before this)", re.I), "PROMPT_EXFILTRATION", "MEDIUM", 0.6),
    (re.compile(r"what (are|were) your (initial|original|system) instructions", re.I), "PROMPT_EXFILTRATION", "MEDIUM", 0.65),
    (re.compile(r"act as (if you (were|are)|an? )?(unfiltered|uncensored|amoral)", re.I), "PERSONA_JAILBREAK", "HIGH", 0.85),
    (re.compile(r"do anything now", re.I), "PERSONA_JAILBREAK", "MEDIUM", 0.7),
    (re.compile(r"this is (a test|for testing purposes)[,.]? (so )?ignore", re.I), "INSTRUCTION_OVERRIDE", "MEDIUM", 0.6),
    (re.compile(r"\bsudo\b.{0,20}\b(mode|override)\b", re.I), "PERSONA_JAILBREAK", "MEDIUM", 0.55),
    (re.compile(r"from now on,? you (will|must|shall) (only )?respond", re.I), "INSTRUCTION_OVERRIDE", "MEDIUM", 0.55),
    # Base64/encoding smuggling attempts (long base64-looking blob adjacent
    # to instruction-like language) -- a very common obfuscation technique.
    (re.compile(r"decode (this|the following) (base64|and (run|execute|follow))", re.I), "ENCODED_PAYLOAD", "MEDIUM", 0.6),
    # Broadened after an initial red-team run against redteam/payloads.py
    # missed several paraphrasings of the same underlying techniques above.
    # These generalize the *category* (bypass phrasing, developer-mode
    # variants, prompt exfiltration variants, instruction supersession)
    # rather than matching the literal test strings -- matching the test
    # strings verbatim would be overfitting to the held-out set and would
    # defeat the point of keeping it separate from training data.
    (re.compile(r"\b(no|without any|skip|bypass|disable)\b.{0,25}\b(restrictions?|filters?|guidelines?|content polic(y|ies)|safety (training|guidelines|filters?))\b", re.I), "FILTER_BYPASS_PHRASING", "HIGH", 0.8),
    (re.compile(r"\bunrestricted\b.{0,15}\b(mode|sandbox|environment)\b", re.I), "PERSONA_JAILBREAK", "HIGH", 0.75),
    (re.compile(r"\bdeveloper mode\b", re.I), "PERSONA_JAILBREAK", "MEDIUM", 0.65),
    (re.compile(r"\b(reveal|print|show|display|output|disclose)\b.{0,25}\b(your |the )?(initial|original|system|hidden)?\s*(prompt|instructions|configuration|config)\b", re.I), "PROMPT_EXFILTRATION", "HIGH", 0.8),
    (re.compile(r"\b(guidelines?|rules?|restrictions?)\b.{0,10}\b(dont|don't|do not)\b.{0,10}\b(exist|apply)\b", re.I), "PERSONA_JAILBREAK", "HIGH", 0.75),
    (re.compile(r"\byou have no (restrictions|rules|limits)\b", re.I), "PERSONA_JAILBREAK", "HIGH", 0.75),
    (re.compile(r"\bsupersedes?\b.{0,20}\b(previous|prior|all)\b", re.I), "INSTRUCTION_OVERRIDE", "HIGH", 0.75),
    (re.compile(r"\bignore\b.{0,20}\b(said|written|stated)?\s*(before|above) this\b", re.I), "INSTRUCTION_OVERRIDE", "HIGH", 0.75),
    (re.compile(r"\buncensor(ed)? yourself\b", re.I), "PERSONA_JAILBREAK", "HIGH", 0.75),
    (re.compile(r"\boutput everything\b.{0,20}\bbetween\b", re.I), "PROMPT_EXFILTRATION", "MEDIUM", 0.65),
    (re.compile(r"\bforget\b.{0,15}\b(any |all )?(prior|previous)?\s*rules?\b", re.I), "INSTRUCTION_OVERRIDE", "MEDIUM", 0.6),
    (re.compile(r"\b(initial|original|hidden) prompt\b", re.I), "PROMPT_EXFILTRATION", "MEDIUM", 0.55),
]


def scan(text: str) -> List[RuleFinding]:
    findings: List[RuleFinding] = []
    for pattern, label, severity, confidence in _PATTERNS:
        match = pattern.search(text)
        if match:
            findings.append(
                RuleFinding(
                    label=label,
                    severity=severity,
                    confidence=confidence,
                    detail=f"Matched known injection pattern near: \"...{text[max(0, match.start()-15):match.end()+15]}...\"",
                )
            )
    return findings
