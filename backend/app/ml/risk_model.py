"""XGBoost risk classification + SHAP explainability (Stage 9).

This is the "must-have novelty" from CLAUDE.md §10: "Explainable AI - SHAP evidence,
never a bare score." `predict()` gives the 0-100 `risk_score`; `explain()` backs it with
the ranked, signed features that drove it, so the UI never has to show a number with
nothing behind it.

Trained against the manifest's safe/weak/anomalous per-session labels (`ml/dataset.py`),
not the rule engine's own `risk_level` - the two stay decoupled by design (CLAUDE.md
§12), so this is a second, independently-derived opinion rather than a restatement of the
same deterministic checks. With ~26 labeled sessions total this cannot be a generalizable
classifier; it is fit and evaluated on the same small synthetic dataset by design (see
CLAUDE.md's own Stage 9 note: "under-trained on the small synthetic dataset") - a
demonstration of the explainability pipeline, not a claim of real-world accuracy.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd
import shap
from xgboost import XGBClassifier

LABELS = ["safe", "weak", "anomalous"]
_LABEL_INDEX = {label: i for i, label in enumerate(LABELS)}

# How much each predicted class contributes to the single 0-100 risk_score: "weak" (a
# known-bad security posture) and "anomalous" (traffic that doesn't fit any expected
# pattern) both push risk up; only "safe" pulls it down.
_CLASS_RISK_WEIGHT = np.array([0.0, 0.7, 1.0])


def _per_feature_per_class(raw_shap, n_classes: int) -> np.ndarray:
    """Normalizes SHAP's output (which varies by shap/xgboost version - a list of
    per-class arrays, or a single 3-D array in either class-major or sample-major order)
    into `(n_features, n_classes)` for a single-row input.
    """
    if isinstance(raw_shap, list):
        return np.stack([np.asarray(c)[0] for c in raw_shap], axis=-1)
    arr = np.asarray(raw_shap)
    if arr.ndim == 3:
        if arr.shape[-1] == n_classes:
            return arr[0]
        if arr.shape[0] == n_classes:
            return np.moveaxis(arr[:, 0, :], 0, -1)
    raise ValueError(f"unexpected SHAP output shape {arr.shape}")


@dataclass
class RiskModel:
    model: XGBClassifier
    feature_names: list

    def predict(self, row: pd.DataFrame) -> dict:
        proba = self.model.predict_proba(row)[0]
        risk_score = float(round(100 * np.dot(proba, _CLASS_RISK_WEIGHT), 1))
        predicted_label = LABELS[int(np.argmax(proba))]
        return {
            "risk_score": risk_score,
            "predicted_label": predicted_label,
            "class_probabilities": {label: round(float(p), 4) for label, p in zip(LABELS, proba)},
        }

    def explain(self, row: pd.DataFrame, top_n: int = 5) -> list:
        """Ranks the features that most influenced this session's risk score, signed by
        direction ("increases_risk" / "decreases_risk") and sized as each feature's share
        of the total SHAP explanation - a relative weight, not a claim about exact
        probability units, since XGBoost's multiclass SHAP output is in raw-margin space.
        """
        explainer = shap.TreeExplainer(self.model)
        raw_shap = explainer.shap_values(row)
        per_class = _per_feature_per_class(raw_shap, len(LABELS))  # (n_features, n_classes)
        weighted = per_class @ _CLASS_RISK_WEIGHT  # signed scalar per feature

        total_abs = np.abs(weighted).sum() or 1.0
        order = np.argsort(-np.abs(weighted))[:top_n]
        return [
            {
                "feature": self.feature_names[i],
                "direction": "increases_risk" if weighted[i] > 0 else "decreases_risk",
                "share_of_explanation": round(float(abs(weighted[i]) / total_abs), 4),
            }
            for i in order
            if weighted[i] != 0
        ]


def train_risk_model(X: pd.DataFrame, labels: list, random_state: int = 42) -> RiskModel:
    y = np.array([_LABEL_INDEX[label] for label in labels])
    model = XGBClassifier(
        n_estimators=100,
        max_depth=3,
        learning_rate=0.3,
        objective="multi:softprob",
        num_class=len(LABELS),
        random_state=random_state,
        eval_metric="mlogloss",
    )
    model.fit(X, y)
    return RiskModel(model=model, feature_names=list(X.columns))
