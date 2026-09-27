"""Loads Stage 9's trained artifacts once and exposes `analyze()` for the API pipeline.

If the models haven't been trained yet (`python -m app.ml.train` hasn't been run - e.g. a
fresh checkout before that step), `analyze()` returns `None` rather than crashing the
analyzer: the rule engine (Stage 6) must keep working standalone even if this stage is
disabled or unavailable (CLAUDE.md §12), and CLAUDE.md §7 already reserves `ai_analysis:
null` for exactly this case.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Optional

import joblib

from .features import extract_features

MODELS_DIR = Path(__file__).parent / "models"


@lru_cache(maxsize=1)
def _load_artifacts():
    try:
        encoder = joblib.load(MODELS_DIR / "encoder.joblib")
        anomaly_model = joblib.load(MODELS_DIR / "anomaly_model.joblib")
        risk_model = joblib.load(MODELS_DIR / "risk_model.joblib")
    except FileNotFoundError:
        return None
    return encoder, anomaly_model, risk_model


def analyze(session, tls_handshake: dict, certificate: dict, starttls: dict) -> Optional[dict]:
    artifacts = _load_artifacts()
    if artifacts is None:
        return None
    encoder, anomaly_model, risk_model = artifacts

    features = extract_features(session, tls_handshake, certificate, starttls)
    row = encoder.transform([features])

    anomaly = anomaly_model.score(row)
    risk = risk_model.predict(row)
    explanation = risk_model.explain(row)

    return {
        "risk_score": risk["risk_score"],
        "anomaly_flag": anomaly["anomaly_flag"],
        "anomaly_score": anomaly["anomaly_score"],
        "predicted_label": risk["predicted_label"],
        "top_contributing_features": explanation,
    }
