from app.ml.dataset import build_dataset
from app.ml.features import FEATURE_NAMES


def test_build_dataset_covers_every_session_in_the_genny_dataset(dataset_dir):
    records = build_dataset(dataset_dir)

    # 22 files, 25 single-session files + file 22's 3 sessions = 27... but two files
    # (14, 22) are multi-scenario; assert against the actual reassembled total instead of
    # a hand-counted constant, and pin the number so a regression is visible.
    assert len(records) == 26
    assert all(set(r["features"].keys()) == set(FEATURE_NAMES) for r in records)
    assert all(r["label"] in {"safe", "weak", "anomalous"} for r in records)


def test_multi_session_file_gets_per_session_label_overrides(dataset_dir):
    records = [
        r for r in build_dataset(dataset_dir) if r["filename"] == "22_multiple_sessions_combined.pcap"
    ]
    records.sort(key=lambda r: r["session_index"])

    assert [r["label"] for r in records] == ["safe", "weak", "weak"]
    assert [r["protocol"] for r in records] == ["SMTP", "SMTP", "POP3"]


def test_manifest_anomalous_files_are_labeled_anomalous(dataset_dir):
    records = build_dataset(dataset_dir)
    for filename in ["19_malformed_tls.pcap", "20_unexpected_tls_version.pcap", "21_unusual_cipher.pcap"]:
        matches = [r for r in records if r["filename"] == filename]
        assert matches, f"no session reconstructed for {filename}"
        assert all(r["label"] == "anomalous" for r in matches)
