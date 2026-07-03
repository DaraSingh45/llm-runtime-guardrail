
from __future__ import annotations

import logging
import time

from fastapi import FastAPI
from prometheus_fastapi_instrumentator import Instrumentator

from config import CLASSIFIER_MODEL_PATH
from detection.dlp_scanner import DlpScanner
from detection.injection_classifier import InjectionClassifier
from detection.pipeline import GuardrailPipeline
from llm_backends import build_llm_backend
from metrics import FINDINGS_TOTAL, REQUESTS_BLOCKED_TOTAL, REQUESTS_TOTAL, SCAN_LATENCY
from models import ChatRequest, ChatResponse

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s guardrail: %(message)s")
log = logging.getLogger("guardrail")

app = FastAPI(
    title="LLM Runtime Guardrail",
    description="Inline proxy that scans requests/responses for prompt injection and sensitive-data leakage before they reach (or leave) an LLM",
)
Instrumentator().instrument(app).expose(app)

_classifier = InjectionClassifier(CLASSIFIER_MODEL_PATH)
_dlp = DlpScanner(enable_ner=True)
_pipeline = GuardrailPipeline(classifier=_classifier, dlp_scanner=_dlp)
_llm = build_llm_backend()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/v1/chat", response_model=ChatResponse)
def chat(request: ChatRequest):
    REQUESTS_TOTAL.inc()

    start = time.time()
    request_decision = _pipeline.evaluate(request.prompt)
    SCAN_LATENCY.observe(time.time() - start)
    for f in request_decision.findings:
        FINDINGS_TOTAL.labels(layer=f.layer, label=f.label).inc()

    if not request_decision.allowed:
        REQUESTS_BLOCKED_TOTAL.labels(direction="request").inc()
        log.warning("BLOCKED request: %s", request_decision.blocked_reason)
        return ChatResponse(request_decision=request_decision, blocked=True)

    output = _llm.complete(request.prompt, request.system, request.max_tokens)

    start = time.time()
    response_decision = _pipeline.evaluate(output)
    SCAN_LATENCY.observe(time.time() - start)
    for f in response_decision.findings:
        FINDINGS_TOTAL.labels(layer=f.layer, label=f.label).inc()

    if not response_decision.allowed:
        REQUESTS_BLOCKED_TOTAL.labels(direction="response").inc()
        log.warning("BLOCKED response: %s", response_decision.blocked_reason)
        return ChatResponse(request_decision=request_decision, response_decision=response_decision, blocked=True)

    return ChatResponse(request_decision=request_decision, response_decision=response_decision, output=output, blocked=False)
