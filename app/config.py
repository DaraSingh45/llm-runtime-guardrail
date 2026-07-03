from __future__ import annotations

import os

# Below this combined injection score, a request passes through untouched.
INJECTION_BLOCK_THRESHOLD = float(os.getenv("INJECTION_BLOCK_THRESHOLD", "0.6"))

# DLP findings at/above this severity block the request outright rather
# than merely redacting -- see detection/pipeline.py.
DLP_BLOCK_SEVERITIES = {"HIGH", "CRITICAL"}

LLM_BACKEND = os.getenv("LLM_BACKEND", "mock")  # mock | anthropic
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")

CLASSIFIER_MODEL_PATH = os.getenv("CLASSIFIER_MODEL_PATH", "models/injection_classifier.joblib")
