"""Builds the labeled training dataset for Stage 9 from genny.py's fixtures.

Ground truth is the manifest's per-file safe/weak/anomalous label (CLAUDE.md §12:
"validate against the manifest's ... labels"), assigned to every reconstructed session in
that file. This is deliberately the manifest label, not the rule engine's own
`risk_level` - a diagnostic pass over the full dataset found the two diverge a lot (every
genny.py leaf cert is self-signed by construction, which drags even "safe" TLS configs up
to rule-engine HIGH; conversely files `19`/`21`'s malformed/UNKNOWN-protocol traffic
produces almost no parseable evidence, so no rule fires and they score a misleadingly
clean LOW). Training against the rule engine's own output would be circular and inherit
its blind spots instead of complementing them (CLAUDE.md §12: keep rules and ML decoupled).

The one file with more than one label, `22_multiple_sessions_combined.pcap` (manifest
label "mixed"), is built in `genny.py` from three named session-builders in a fixed
order - safe SMTP (ECDHE, valid cert), weak SMTP (TLS 1.0/3DES, expired cert), then an
always-plaintext POP3 session - so its three reconstructed sessions get per-session
overrides instead of one blanket label. `reassemble_pcap` sorts sessions by
`(client, server)` address tuple, and the three client IPs genny.py assigns
(`10.10.20.1/.2/.3`) already sort in that same build order, so the override list below
lines up positionally with the reassembled session list.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..api.pipeline import analyze_session
from ..reassembly.reassembler import reassemble_pcap
from .features import extract_features

SESSION_LABEL_OVERRIDES = {
    "22_multiple_sessions_combined.pcap": ["safe", "weak", "weak"],
}


def _label_by_file(dataset_dir: Path) -> dict:
    manifest = json.loads((dataset_dir / "test_manifest.json").read_text())
    return {case["filename"]: case["label"] for case in manifest["cases"]}


def build_dataset(dataset_dir: Path) -> list:
    """Returns one record per reconstructed session across every `genny.py` pcap file:
    `{filename, session_index, protocol, label, features}`.
    """
    labels_by_file = _label_by_file(dataset_dir)
    records = []

    for pcap_path in sorted(dataset_dir.glob("*.pcap")):
        override = SESSION_LABEL_OVERRIDES.get(pcap_path.name)
        file_label = labels_by_file.get(pcap_path.name)

        sessions = reassemble_pcap(pcap_path)
        if override is not None and len(override) != len(sessions):
            raise ValueError(
                f"{pcap_path.name}: expected {len(override)} sessions for its per-session "
                f"label override but reassembled {len(sessions)} - genny.py's construction "
                "may have changed"
            )

        for i, session in enumerate(sessions):
            label = override[i] if override is not None else file_label
            if label is None:
                raise ValueError(f"{pcap_path.name}: no manifest label found")

            analysis = analyze_session(session)
            features = extract_features(
                session, analysis["tls_handshake"], analysis["certificate"], analysis["starttls"]
            )
            records.append(
                {
                    "filename": pcap_path.name,
                    "session_index": i,
                    "protocol": session.protocol,
                    "label": label,
                    "features": features,
                }
            )

    return records
