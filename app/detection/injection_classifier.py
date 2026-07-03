
from __future__ import annotations

import logging
import os

import joblib

log = logging.getLogger("injection-classifier")


class InjectionClassifier:
    def __init__(self, model_path: str) -> None:
        self.model_path = model_path
        self.model = self._load()

    def _load(self):
        if not os.path.exists(self.model_path):
            log.warning(
                "No injection classifier found at %s -- classifier score will be 0.0 until one is "
                "trained (see `make train-classifier`).",
                self.model_path,
            )
            return None
        log.info("Loaded injection classifier from %s", self.model_path)
        return joblib.load(self.model_path)

    def score(self, text: str) -> float:
        """Returns P(injection) in [0, 1]."""
        if self.model is None:
            return 0.0
        proba = self.model.predict_proba([text])[0]
        # classes_ ordering isn't guaranteed to be [0, 1] by sklearn, so
        # look up the injection (label=1) class index explicitly rather
        # than assuming proba[1].
        classes = list(self.model.classes_)
        injection_index = classes.index(1)
        return float(proba[injection_index])
