"""Trains and persists Stage 9's models against `genny.py`'s dataset (CLAUDE.md §12:
"treat it as the ground-truth fixture source for every backend module").

Run as a script to (re)generate the artifacts `backend/app/ml/models/` loads at
inference time:

    cd backend && ../.venv/Scripts/python.exe -m app.ml.train

Safe to re-run whenever `genny.py`'s dataset or `ml/features.py`'s extraction changes -
the API gracefully serves `ai_analysis: null` (see `ml/inference.py`) if these artifacts
are ever missing, so this step is not required for the rest of the pipeline to work.
"""
from __future__ import annotations

import json
from pathlib import Path

import joblib

from .anomaly import train_anomaly_model
from .dataset import build_dataset
from .encoding import FeatureEncoder
from .risk_model import LABELS, train_risk_model

MODELS_DIR = Path(__file__).parent / "models"
DATASET_DIR = Path(__file__).resolve().parents[3] / "securemail_test_pcaps"


def train_and_save(dataset_dir: Path = DATASET_DIR, models_dir: Path = MODELS_DIR) -> dict:
    records = build_dataset(dataset_dir)
    feature_dicts = [r["features"] for r in records]
    labels = [r["label"] for r in records]

    encoder = FeatureEncoder().fit(feature_dicts)
    X = encoder.transform(feature_dicts)

    anomaly_model = train_anomaly_model(X)
    risk_model = train_risk_model(X, labels)

    models_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(encoder, models_dir / "encoder.joblib")
    joblib.dump(anomaly_model, models_dir / "anomaly_model.joblib")
    joblib.dump(risk_model, models_dir / "risk_model.joblib")

    predicted = [risk_model.predict(X.iloc[[i]])["predicted_label"] for i in range(len(X))]
    accuracy = sum(p == l for p, l in zip(predicted, labels)) / len(labels)
    anomalies_flagged = [
        records[i]["filename"]
        for i in range(len(X))
        if anomaly_model.score(X.iloc[[i]])["anomaly_flag"]
    ]

    summary = {
        "sessions_trained_on": len(records),
        "label_counts": {label: labels.count(label) for label in LABELS},
        "training_set_accuracy": round(accuracy, 4),
        "files_flagged_anomalous_by_isolation_forest": anomalies_flagged,
    }
    (models_dir / "training_summary.json").write_text(json.dumps(summary, indent=2))
    return summary


if __name__ == "__main__":
    print(json.dumps(train_and_save(), indent=2))
