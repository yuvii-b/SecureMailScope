import pytest

from app.ml.anomaly import train_anomaly_model
from app.ml.dataset import build_dataset
from app.ml.encoding import FeatureEncoder
from app.ml.risk_model import LABELS, train_risk_model


@pytest.fixture(scope="module")
def trained(dataset_dir):
    records = build_dataset(dataset_dir)
    feature_dicts = [r["features"] for r in records]
    labels = [r["label"] for r in records]
    encoder = FeatureEncoder().fit(feature_dicts)
    X = encoder.transform(feature_dicts)
    anomaly_model = train_anomaly_model(X)
    risk_model = train_risk_model(X, labels)
    return records, X, labels, anomaly_model, risk_model


def test_isolation_forest_flags_the_manifest_anomalous_sessions(trained):
    records, X, _labels, anomaly_model, _risk_model = trained
    for i, record in enumerate(records):
        if record["filename"] in {"19_malformed_tls.pcap", "21_unusual_cipher.pcap"}:
            result = anomaly_model.score(X.iloc[[i]])
            assert result["anomaly_flag"] is True
            assert 0.0 <= result["anomaly_score"] <= 1.0


def test_risk_classifier_predicts_a_valid_label_for_every_session(trained):
    _records, X, _labels, _anomaly_model, risk_model = trained
    for i in range(len(X)):
        prediction = risk_model.predict(X.iloc[[i]])
        assert prediction["predicted_label"] in LABELS
        assert 0.0 <= prediction["risk_score"] <= 100.0
        assert set(prediction["class_probabilities"]) == set(LABELS)


def test_safe_sessions_score_lower_risk_than_anomalous_sessions_on_average(trained):
    _records, X, labels, _anomaly_model, risk_model = trained
    safe_scores = [
        risk_model.predict(X.iloc[[i]])["risk_score"] for i, label in enumerate(labels) if label == "safe"
    ]
    anomalous_scores = [
        risk_model.predict(X.iloc[[i]])["risk_score"]
        for i, label in enumerate(labels)
        if label == "anomalous"
    ]
    assert safe_scores and anomalous_scores
    assert sum(safe_scores) / len(safe_scores) < sum(anomalous_scores) / len(anomalous_scores)


def test_explain_returns_directional_ranked_features_backed_by_shap(trained):
    _records, X, _labels, _anomaly_model, risk_model = trained
    explanation = risk_model.explain(X.iloc[[0]], top_n=5)

    assert 1 <= len(explanation) <= 5
    for item in explanation:
        assert set(item) == {"feature", "direction", "share_of_explanation"}
        assert item["feature"] in risk_model.feature_names
        assert item["direction"] in {"increases_risk", "decreases_risk"}
        assert 0.0 <= item["share_of_explanation"] <= 1.0


@pytest.fixture
def clear_inference_cache():
    from app.ml.inference import _load_artifacts

    _load_artifacts.cache_clear()
    yield
    _load_artifacts.cache_clear()


def test_train_and_save_persists_artifacts_inference_can_load(
    dataset_dir, tmp_path, monkeypatch, clear_inference_cache
):
    from app.api.pipeline import analyze_session
    from app.ml import inference as inference_module
    from app.ml import train as train_module
    from app.reassembly.reassembler import reassemble_pcap

    models_dir = tmp_path / "models"
    summary = train_module.train_and_save(dataset_dir=dataset_dir, models_dir=models_dir)
    assert summary["sessions_trained_on"] == 26
    assert (models_dir / "encoder.joblib").exists()
    assert (models_dir / "anomaly_model.joblib").exists()
    assert (models_dir / "risk_model.joblib").exists()

    monkeypatch.setattr(inference_module, "MODELS_DIR", models_dir)
    inference_module._load_artifacts.cache_clear()

    sessions = reassemble_pcap(dataset_dir / "19_malformed_tls.pcap")
    analysis = analyze_session(sessions[0])

    assert analysis["ai_analysis"] is not None
    assert analysis["ai_analysis"]["anomaly_flag"] is True
    assert analysis["ai_analysis"]["predicted_label"] == "anomalous"
    assert analysis["ai_analysis"]["top_contributing_features"]


def test_inference_returns_none_gracefully_when_models_are_missing(
    tmp_path, monkeypatch, clear_inference_cache
):
    from app.ml import inference as inference_module

    monkeypatch.setattr(inference_module, "MODELS_DIR", tmp_path / "does_not_exist")
    inference_module._load_artifacts.cache_clear()

    result = inference_module.analyze(
        session=None, tls_handshake={}, certificate={}, starttls={}
    )
    assert result is None
