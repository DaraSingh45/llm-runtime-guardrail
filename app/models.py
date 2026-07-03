"""Request/response contracts for the proxy's public API."""
from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    prompt: str
    system: Optional[str] = None
    max_tokens: int = 512


class Finding(BaseModel):
    layer: str          # RULES | CLASSIFIER | DLP | URL_SCAN
    label: str           # e.g. "PROMPT_INJECTION", "AWS_ACCESS_KEY", "SUSPICIOUS_URL"
    severity: str         # LOW | MEDIUM | HIGH | CRITICAL
    confidence: float
    detail: str
    redacted_span: Optional[str] = None  # never the raw sensitive text itself


class GuardrailDecision(BaseModel):
    allowed: bool
    findings: List[Finding] = Field(default_factory=list)
    blocked_reason: Optional[str] = None


class ChatResponse(BaseModel):
    request_decision: GuardrailDecision
    response_decision: Optional[GuardrailDecision] = None
    output: Optional[str] = None
    blocked: bool = False
