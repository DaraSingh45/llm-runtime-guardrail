#!/usr/bin/env python3
"""
Trains a TF-IDF + Logistic Regression classifier on dataset.py and saves it
via joblib. Run automatically at Docker build time (see the Dockerfile) so
the proxy works immediately; re-run manually any time dataset.py changes.

Why TF-IDF + Logistic Regression and not a pretrained sentence-embedding
model: this environment can't guarantee outbound access to a model hub at
build time, and a linear classifier over TF-IDF features is fully
explainable (you can inspect exactly which n-grams drove a decision) --
appropriate for a portfolio project. README documents swapping in
sentence-transformer embeddings as a natural upgrade if you want it.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

APP_DIR = Path(__file__).resolve().parent.parent  # app/
sys.path.insert(0, str(APP_DIR))
from train.dataset import load_training_data  # noqa: E402

DEFAULT_MODEL_OUT = str(APP_DIR / "models" / "injection_classifier.joblib")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-out", default=DEFAULT_MODEL_OUT)
    args = parser.parse_args()

    texts, labels = load_training_data()
    print(f"Training on {len(texts)} labeled examples ({sum(labels)} injection, {len(labels) - sum(labels)} benign)")

    pipeline = Pipeline(
        [
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True)),
            ("clf", LogisticRegression(max_iter=1000, class_weight="balanced")),
        ]
    )
    pipeline.fit(texts, labels)

    os.makedirs(os.path.dirname(args.model_out), exist_ok=True)
    joblib.dump(pipeline, args.model_out)
    print(f"Saved classifier to {args.model_out}")


if __name__ == "__main__":
    main()
