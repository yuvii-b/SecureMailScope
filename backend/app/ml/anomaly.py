"""Isolation Forest anomaly detection (Stage 9) over the encoded feature matrix.

Unsupervised on purpose - it never sees the safe/weak/anomalous labels (those are
reserved for the risk classifier in `risk_model.py`), so a session lands outside the
normal feature distribution regardless of whether the deterministic rule engine
(Stage 6) has a matching check for it. That matters because files `19`/`21`
(malformed handshake / unusual cipher, both manifest-labeled "anomalous") currently
produce almost no rule-engine findings at all - `client_hello_seen` is False and the
protocol comes back `UNKNOWN`, so Stage 6's checks have nothing to fire on and the
session scores a misleadingly clean posture - but their feature vectors (every TLS/cert
field unobserved, `protocol=UNKNOWN`) look nothing like the rest of the dataset, which is
exactly what this model is meant to catch instead.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest


@dataclass
class AnomalyModel:
    model: IsolationForest
    score_min: float
    score_max: float

    def score(self, row: pd.DataFrame) -> dict:
        raw = float(self.model.decision_function(row)[0])  # higher = more normal
        is_anomaly = bool(self.model.predict(row)[0] == -1)
        span = (self.score_max - self.score_min) or 1.0
        normalized = (self.score_max - raw) / span  # higher = more anomalous
        anomaly_score = float(np.clip(normalized, 0.0, 1.0))
        return {"anomaly_flag": is_anomaly, "anomaly_score": round(anomaly_score, 4)}


def train_anomaly_model(X: pd.DataFrame, random_state: int = 42) -> AnomalyModel:
    model = IsolationForest(n_estimators=200, contamination="auto", random_state=random_state)
    model.fit(X)
    raw_scores = model.decision_function(X)
    return AnomalyModel(
        model=model, score_min=float(raw_scores.min()), score_max=float(raw_scores.max())
    )
