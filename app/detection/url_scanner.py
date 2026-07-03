
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List

_URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.I)
_IP_HOST_PATTERN = re.compile(r"https?://(\d{1,3}\.){3}\d{1,3}", re.I)
_SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly"}
_SUSPICIOUS_TLDS = {".xyz", ".top", ".zip", ".click", ".ru", ".tk"}
_USERINFO_PATTERN = re.compile(r"https?://[^/\s]+:[^/\s]+@", re.I)


@dataclass
class UrlFinding:
    label: str
    severity: str
    confidence: float
    detail: str


def _domain_of(url: str) -> str:
    match = re.match(r"https?://([^/]+)", url, re.I)
    return match.group(1).lower() if match else ""


def scan(text: str) -> List[UrlFinding]:
    findings: List[UrlFinding] = []

    for url in _URL_PATTERN.findall(text):
        domain = _domain_of(url)

        if _IP_HOST_PATTERN.match(url):
            findings.append(UrlFinding("RAW_IP_URL", "MEDIUM", 0.6, f"URL uses a raw IP instead of a domain: {url}"))

        if any(domain == d or domain.endswith("." + d) for d in _SHORTENER_DOMAINS):
            findings.append(UrlFinding("URL_SHORTENER", "MEDIUM", 0.55, f"URL uses a known shortener: {domain}"))

        if any(domain.endswith(tld) for tld in _SUSPICIOUS_TLDS):
            findings.append(UrlFinding("SUSPICIOUS_TLD", "LOW", 0.4, f"URL uses a commonly-abused TLD: {domain}"))

        if _USERINFO_PATTERN.match(url):
            findings.append(UrlFinding("CREDENTIAL_IN_URL", "HIGH", 0.75, "URL embeds credentials in userinfo syntax"))

    return findings
