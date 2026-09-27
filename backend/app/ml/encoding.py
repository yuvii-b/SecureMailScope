"""Turns the 19-feature dict (`ml/features.py`) into a fixed-width numeric matrix for
scikit-learn/XGBoost.

Categorical string features are one-hot encoded against a vocabulary learned at fit time
(`FeatureEncoder.fit`), with an `=__unseen__` bucket for any value not seen during
training (a category from a real capture that never showed up in `genny.py`'s dataset) -
named that way rather than `=UNKNOWN` because `protocol`'s own observed values already
include the literal string `"UNKNOWN"` (Stage 3's honest answer for files `19`/`21`'s
unidentifiable traffic), which would otherwise collide with the catch-all bucket.
Booleans
and numerics get a paired `<name>_observed` column instead of silently mapping `None` to
a specific value (`False`/`0`) the model could confuse with a real observation - the same
"never guess a missing value" rule `features.py` already follows (CLAUDE.md §12).
"""
from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd

CATEGORICAL_FEATURES = [
    "protocol",
    "tls_version",
    "cipher_suite",
    "key_exchange",
    "public_key_algorithm",
    "signature_algorithm",
]
BOOLEAN_FEATURES = [
    "forward_secrecy",
    "certificate_valid",
    "chain_valid",
    "starttls_used",
    "handshake_success",
]
NUMERIC_FEATURES = [
    "certificate_age",
    "certificate_days_to_expiry",
    "public_key_length",
    "handshake_duration",
    "handshake_failure_count",
    "packet_count",
    "retransmission_count",
    "session_duration",
]


@dataclass
class FeatureEncoder:
    categories: dict = field(default_factory=dict)
    columns: list = field(default_factory=list)

    def fit(self, feature_dicts: list) -> "FeatureEncoder":
        self.categories = {
            col: sorted({str(f[col]) for f in feature_dicts if f.get(col) is not None})
            for col in CATEGORICAL_FEATURES
        }
        self.columns = self._build_columns()
        return self

    def _build_columns(self) -> list:
        columns = []
        for col in CATEGORICAL_FEATURES:
            columns.extend(f"{col}={value}" for value in self.categories.get(col, []))
            columns.append(f"{col}=__unseen__")
        for col in BOOLEAN_FEATURES:
            columns.append(col)
            columns.append(f"{col}_observed")
        for col in NUMERIC_FEATURES:
            columns.append(col)
            columns.append(f"{col}_observed")
        return columns

    def transform(self, feature_dicts: list) -> pd.DataFrame:
        rows = []
        for features in feature_dicts:
            row = {}
            for col in CATEGORICAL_FEATURES:
                value = features.get(col)
                known = self.categories.get(col, [])
                for candidate in known:
                    row[f"{col}={candidate}"] = 1.0 if str(value) == candidate else 0.0
                row[f"{col}=__unseen__"] = (
                    1.0 if (value is not None and str(value) not in known) else 0.0
                )
            for col in BOOLEAN_FEATURES:
                value = features.get(col)
                row[col] = 1.0 if value is True else 0.0
                row[f"{col}_observed"] = 0.0 if value is None else 1.0
            for col in NUMERIC_FEATURES:
                value = features.get(col)
                row[col] = float(value) if value is not None else 0.0
                row[f"{col}_observed"] = 0.0 if value is None else 1.0
            rows.append(row)
        return pd.DataFrame(rows, columns=self.columns)

    def fit_transform(self, feature_dicts: list) -> pd.DataFrame:
        return self.fit(feature_dicts).transform(feature_dicts)
