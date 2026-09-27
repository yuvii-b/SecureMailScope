# SecureMailScope — Project Guide for Claude Code

AI-assisted passive network forensic framework that analyzes PCAP/PCAPNG captures of
SMTP/IMAP/POP3 traffic, reconstructs sessions, evaluates TLS/X.509 cryptographic posture,
and produces a scored, evidence-linked security report. Built for SIH 2026.

Source docs (already analyzed into this file, don't need to be re-read unless the plan
changes): `SecureMailScope_SIH2026_FINAL (1).pdf` (pitch deck) and
`SecureMailScope_SIH2026_Team_Knowledge_Share_REVISED.docx` (team knowledge base).

**This is a passive analyzer only.** It never sends live traffic to a mail server during
analysis. The one exception is the optional, separately-scoped "self-healing agent"
(see Non-goals) which is not part of the MVP.

## 1. Product in one line

`PCAP → TCP/session reconstruction → STARTTLS/TLS handshake parsing → X.509 extraction →
deterministic rule engine → ML risk/anomaly scoring → posture score + evidence-linked
findings → JSON/PDF/HTML report + dashboard`

## 2. Non-goals (explicitly out of scope for MVP)

- No active scanning, no contact with production mail servers.
- No decrypting TLS payloads — only handshake metadata and certificates are observable.
- The "Self-Healing Secure Transfer" agent (auto-retry over a fresh verified TLS session)
  is a differentiator, not MVP. Only build it after Stage 12 if time remains, and keep it
  as an opt-in component separate from the passive analyzer.
- Don't build config/certificate drift detection, what-if simulator, or baseline
  comparison until the core pipeline (Stages 0–8 below) is solid end-to-end.

## 3. Locked-in tech stack

Pick this stack and don't re-litigate it mid-build; the docs treat it as illustrative,
but for a team under deadline pressure, consistency beats optionality:

| Layer | Choice |
|---|---|
| PCAP/packet parsing | Python + Scapy (already used in `genny.py`); add `pyshark`/tshark only if Scapy can't expose a needed TLS/DPI field |
| Crypto / X.509 | `cryptography` (pyca) |
| Backend API | FastAPI |
| Job queue | Redis + Celery (analysis runs async, PCAPs can be large) |
| Database | PostgreSQL (sessions, findings, certs, reports) |
| ML | scikit-learn (Isolation Forest for anomaly), XGBoost + SHAP (risk classification + explainability) — added only in Stage 9, after rules work |
| Frontend | React + TypeScript + Tailwind, Recharts for charts |
| Reports | Jinja2 + WeasyPrint (HTML→PDF), plus raw JSON export |
| Packaging | Docker Compose (api, worker, redis, postgres, frontend) |

Do not introduce Spring Boot, Streamlit, or a different ML stack without discussing it
first — the docs list these as alternatives, but switching mid-project causes the
"incompatible team output" risk called out in the knowledge doc.

## 4. Repository layout (target — create as stages require it)

```
securemailscope/
  genny.py                     # synthetic PCAP + manifest generator (EXISTING — see §5)
  securemail_test_pcaps/       # output of genny.py: pcaps + certificates/ + test_manifest.json
  backend/
    app/
      ingestion/                # Stage 2: pcap upload, validation, packet/flow extraction
      reassembly/                # Stage 3: TCP stream reconstruction, protocol ID
      starttls/                  # Stage 4: STARTTLS/STLS state machine
      tls/                       # Stage 4-5: TLS handshake parsing (ClientHello/ServerHello/etc.)
      certificates/              # Stage 5: X.509 extraction + validation
      rules/                     # Stage 6: deterministic security rule engine
      ml/                        # Stage 9: feature extraction, Isolation Forest, XGBoost, SHAP
      api/                       # Stage 7: FastAPI routes, schemas (the JSON contract, §7)
      reports/                   # Stage 11: JSON/PDF/HTML report generation
      models/                    # SQLAlchemy models for sessions/findings/certs
    tests/
      fixtures/                  # symlink or copy of securemail_test_pcaps/ for test input
  frontend/
    src/
      pages/                     # Stage 8: dashboard, session explorer, findings, certs
  docker-compose.yml
  CLAUDE.md                     # this file
```

## 5. Dataset generator — `genny.py`

This is the team's existing synthetic PCAP generator. **Treat it as the ground-truth
fixture source for every backend module** — write parsers against its output before
trying anything on a real capture.

Run it to (re)generate the dataset:

```bash
pip install scapy cryptography
python genny.py
```

Output: `securemail_test_pcaps/*.pcap` (22 scenario files), `securemail_test_pcaps/certificates/`
(DER + PEM certs for each scenario), and `securemail_test_pcaps/test_manifest.json`
(per-file protocol/scenario/TLS version/cipher/label + an `ml_dataset` section pre-split
into `safe` / `weak` / `anomalous` / `mixed`).

Coverage already in the generator (map each backend module's tests to these files):

- TLS versions 1.0/1.1/1.2/1.3; weak ciphers (3DES, RC4, NULL, DH-anon); key exchange
  RSA/ECDHE/DHE (files `01`–`07`).
- Certificate scenarios: valid, expired, wrong hostname, self-signed, 1024-bit weak key,
  SHA-1 signature, incomplete chain (files `08`–`13`).
- STARTTLS failures: not used, rejected, plaintext-after-advertisement (file `14`, IMAP).
- Plaintext POP3 credentials (file `15`).
- TCP conditions: segmented records, retransmission, out-of-order (files `16`–`18`).
- Anomalous TLS: malformed handshake, unexpected version, unusual cipher (files `19`–`21`).
- Multiple sessions combined in one PCAP (file `22`).

When a new scenario is needed (e.g. a real captured lab PCAP, or a case the generator
doesn't cover), extend `genny.py` rather than hand-crafting one-off pcaps, so the
manifest/labels stay authoritative and reproducible.

## 6. Build stages (MVP first, novelty second)

Work stage by stage. Each stage should be demoable against `genny.py` output before
moving on — don't parallelize ahead into later stages with unstable interfaces below
them. Update the checkboxes in this file as stages complete so the state is visible to
every session.

- [x] **Stage 0 — Requirement freeze.** This file. Every SIH requirement mapped to a
      module (see §9 mapping table).
- [x] **Stage 1 — Test lab + PCAP dataset.** `genny.py` + manifest (done). Fixed three
      bugs found while first running it against the installed `cryptography` 50.x:
      `BasicConstraints` now requires `path_length`; SHA-1 cert signing is hard-blocked by
      modern `cryptography` for certificate creation (worked around with a manual
      asn1crypto-built TBSCertificate signed with SHA-1 directly, then loaded back via
      `cryptography` — see `make_sha1_signed_certificate()`); `malformed_tls()` and
      `unusual_cipher()` weren't passing `client_port` through to `make_session()`. Added
      `asn1crypto` as a dependency for the SHA-1 workaround.
      **How to test:** `python genny.py` from the project root should print 22
      `[+] Created ...pcap` lines with no traceback, then a manifest/certificate summary.
- [x] **Stage 2 — PCAP ingestion.** Upload endpoint, PCAP/PCAPNG validation (magic bytes,
      corrupt-file handling), packet/flow extraction via Scapy. Lives in
      `backend/app/ingestion/` (`validator.py`, `extractor.py`, `router.py`), mounted at
      `POST /api/pcap/upload`. Deliberately does not classify SMTP/IMAP/POP3 or reassemble
      TCP sequences yet — that's Stage 3; this stage only proves every packet is read and
      grouped into a direction-agnostic 5-tuple flow.
      **How to test:** `cd backend && python -m pytest -v` (14 tests: validator magic-byte
      cases, flow extraction against `genny.py` scenarios `03`/`16`/`18`/`22`, and live
      API upload/rejection cases). To sanity-check the running service by hand:
      `uvicorn app.main:app --reload --port 8000`, then
      `curl http://127.0.0.1:8000/health` and
      `curl -X POST http://127.0.0.1:8000/api/pcap/upload -F "file=@../securemail_test_pcaps/22_multiple_sessions_combined.pcap"`
      — expect `flow_count: 3` for that file (three independent sessions stitched
      together by the generator).
- [x] **Stage 3 — Session reconstruction.** TCP stream reassembly (per-direction sequence
      tracking, retransmission dedup, out-of-order reordering, gap detection) plus
      SMTP/IMAP/POP3 identification by banner (`220`, `* OK`, `+OK`) with port number only
      as a fallback. Lives in `backend/app/reassembly/` (`reassembler.py`, `protocol_id.py`,
      `router.py`), mounted at `POST /api/pcap/sessions`. Client vs. server is resolved from
      the initial SYN packet, not port number, since files `19`/`21` run SMTP-like traffic on
      non-standard ports 2525/2526 with no plaintext banner — those correctly come back as
      `protocol: "UNKNOWN"` rather than a guess.
      **How to test:** `cd backend && python -m pytest -v` (24 tests total; 8 new in
      `test_reassembler.py` covering files `03`, `14`, `15`, `16`–`19`, `22`, plus 2 new API
      tests in `test_api.py`). To sanity-check by hand:
      `uvicorn app.main:app --reload --port 8000`, then
      `curl -X POST http://127.0.0.1:8000/api/pcap/sessions -F "file=@../securemail_test_pcaps/22_multiple_sessions_combined.pcap"`
      — expect `session_count: 3` with two `SMTP` sessions (port 25) and one `POP3` session
      (port 110), each with `protocol_confidence: "banner_match"` and empty `gaps`. Also try
      `17_tcp_retransmission.pcap` (expect `retransmitted_segments > 0`, `gaps: []`) and
      `19_malformed_tls.pcap` (expect `protocol: "UNKNOWN"`, port `2525`).
- [x] **Stage 4 — STARTTLS/TLS analysis.** STARTTLS/STLS state machine classifying each
      session into `SUCCESS`, `REJECTED`, `NOT_USED`, `PLAINTEXT_AFTER_ADVERTISEMENT`,
      `NOT_APPLICABLE_IMPLICIT_TLS` (traffic that is TLS from the very first byte, e.g.
      SMTPS/993/995 or genny.py's non-standard-port anomalous scenarios — detected
      generically by checking for a TLS record header, not by hardcoding port numbers),
      or `NOT_OBSERVED` when there isn't enough evidence to call it either way. Lives in
      `backend/app/starttls/state_machine.py`. TLS handshake parsing
      (`backend/app/tls/records.py`, `handshake.py`, `cipher_suites.py`) extracts
      ClientHello/ServerHello version, cipher suite, key exchange, forward secrecy, SNI,
      and raw certificate DER bytes from the Certificate handshake message (full X.509
      validation is Stage 5) — all parsing stops cleanly on truncated/corrupt input
      instead of raising or guessing (file `19`'s deliberately malformed handshake length
      correctly comes back with `client_hello_seen: false` + an explanatory note, not a
      crash). Both are wired into `POST /api/pcap/sessions`'s response per session, next
      to the existing Stage 3 fields.
      **How to test:** `cd backend && python -m pytest -v` (55 tests total; 8 new in
      `test_starttls.py` covering file `14`'s three failure modes, file `07`'s implicit
      TLS 1.3, file `19`'s implicit-TLS-like anomalous traffic on a non-standard port,
      file `15`'s no-STARTTLS-attempted POP3 case, and the full STARTTLS-success matrix
      across files `01`/`02`/`04`/`05`/`06`/`20`; 11 new in `test_tls_handshake.py`
      covering the version/cipher/key-exchange/forward-secrecy matrix for files `01`–`06`,
      certificate DER extraction for files `08`–`13`, the unrecognized-version file `20`
      and unknown-cipher file `21` (both reported honestly rather than guessed), and file
      `19`'s malformed handshake not crashing the parser; 1 new API test in `test_api.py`.
      To sanity-check by hand: `uvicorn app.main:app --reload --port 8000`, then
      `curl -X POST http://127.0.0.1:8000/api/pcap/sessions -F "file=@../securemail_test_pcaps/03_tls12_ecdhe_rsa_safe.pcap"`
      — expect `starttls.status: "SUCCESS"`, `tls_handshake.version_negotiated: "TLS 1.2"`,
      `cipher_suite_selected: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"`,
      `forward_secrecy: true`, and one entry in `certificates_der_hex`. Also try
      `14_starttls_rejected.pcap` (expect `starttls.status: "REJECTED"` with evidence
      `"a002 NO STARTTLS unavailable"`) and `19_malformed_tls.pcap` (expect
      `starttls.status: "NOT_APPLICABLE_IMPLICIT_TLS"`, `tls_handshake.client_hello_seen:
      false`, and a fatal `handshake_failure` alert reported in `alerts`/`notes`).
- [ ] **Stage 5 — Certificate analysis.** X.509 extraction from the TLS Certificate
      handshake message; validity window vs. capture timestamp; key algorithm/length;
      signature algorithm; SAN/hostname match; chain completeness (report "chain not
      observable" vs. "chain invalid" — see file `13`); certificate fingerprint.
- [ ] **Stage 6 — Rule engine.** Deterministic checks producing findings with severity +
      evidence (see §8 rule matrix). This is the correctness backbone — get this right
      before touching ML.
- [ ] **Stage 7 — Backend/API.** FastAPI routes implementing the JSON contract (§7);
      Celery job queue for async analysis; PostgreSQL persistence.
- [ ] **Stage 8 — Dashboard (MVP demo milestone).** Upload → posture score → findings →
      session drill-down, built against mocked/real JSON from Stage 7. This is the MVP
      completion point per the docs: "MVP: complete PCAP → posture → report pipeline."
- [ ] **Stage 9 — ML.** Feature extraction (19 features, §7.1) → Isolation Forest anomaly
      detection → XGBoost risk classification → SHAP explainability. Only start once
      Stage 6 produces reliable features; validate against the manifest's
      safe/weak/anomalous/mixed labels.
- [ ] **Stage 10 — Novelty (post-MVP).** Cryptographic fingerprinting, config/certificate
      drift detection, what-if remediation simulator, baseline comparison. Pick 2–3, not
      all — see priority table in §10.
- [ ] **Stage 11 — Reports.** JSON (always), plus PDF and/or HTML (at minimum one
      human-readable format if time is tight) via Jinja2 + WeasyPrint.
- [ ] **Stage 12 — Integration + demo hardening.** Full run against every `genny.py`
      scenario, measure metrics (§11), fix edge cases, prepare backup demo assets/video.

## 7. JSON contract (freeze early, version it)

This is illustrative per the source doc — treat it as a starting point, lock the shape
once the frontend starts consuming it, and version the schema (`schema_version` field)
rather than breaking it silently.

```json
{
  "summary": {
    "capture_file": "capture.pcap",
    "total_sessions_analyzed": 1420,
    "overall_health_score": 42.5,
    "risk_level": "HIGH"
  },
  "sessions": [
    {
      "session_id": "SESS-SMTP-8921",
      "protocol": "SMTP",
      "client": {"ip": "192.168.1.20", "port": 52144},
      "server": {"ip": "10.0.0.15", "port": 25},
      "starttls_negotiation": {"command_detected": true, "status": "SUCCESS"},
      "tls_handshake": {
        "version_negotiated": "TLS 1.2",
        "cipher_suite": "ECDHE_RSA_AES_256_GCM_SHA384",
        "key_exchange": "ECDHE",
        "forward_secrecy": true
      },
      "certificate": {
        "subject": "mail.example.com",
        "issuer": "Example CA",
        "key_algorithm": "RSA",
        "key_length_bits": 2048,
        "signature_algorithm": "SHA256withRSA",
        "expired": false,
        "chain_status": "OBSERVED_VALID | NOT_OBSERVABLE | INVALID"
      },
      "ai_analysis": {"risk_score": 18.2, "anomaly_flag": false},
      "findings": [
        {
          "severity": "HIGH",
          "title": "Deprecated TLS version",
          "evidence": "ServerHello version 0x0301 (TLS 1.0)",
          "policy_reference": "RFC 8996",
          "recommendation": "Disable TLS < 1.2 on this endpoint"
        }
      ]
    }
  ]
}
```

### 7.1 ML feature set (19 features referenced in the docs)

`protocol, tls_version, cipher_suite, key_exchange, forward_secrecy, certificate_valid,
certificate_age, certificate_days_to_expiry, public_key_algorithm, public_key_length,
signature_algorithm, chain_valid, starttls_used, handshake_success, handshake_duration,
handshake_failure_count, packet_count, retransmission_count, session_duration`

Only engineer features that are actually observable from a passive capture — never
infer/guess a field that isn't present in the handshake evidence.

## 8. Reference security rule matrix (deterministic engine, Stage 6)

| Domain | Condition | Severity | Policy reference |
|---|---|---|---|
| Protocol | TLS 1.0 / 1.1 | High | RFC 8996 |
| Protocol | SSLv2 / SSLv3 | Critical | — |
| Cipher | RC4 / 3DES / EXPORT / NULL / ANON | Critical | BSI TR-02102-2 |
| Cipher | CBC-mode on TLS 1.2 | Medium | — |
| Key exchange | Static RSA / no PFS | High | NIST SP 800-52r2 |
| Key exchange | DH group below configured minimum | High | — |
| Certificate | Self-signed / untrusted chain | High | RFC 5280 |
| Certificate | Expired / not-yet-valid | High | RFC 5280 |
| Certificate | SHA-1 / MD5 signature | High | RFC 5280 |
| Certificate | Key length < 2048-bit RSA | High | NIST SP 800-52r2 |
| STARTTLS | Plaintext continues after advertised upgrade | Critical | RFC 3207, RFC 8314 |

Every finding needs: severity, evidence (the literal field/value observed), the policy
it violates, and a plain-language recommendation. Severity/weights should be
configurable, not hardcoded magic numbers — the docs explicitly call out "over-scoring"
(a single arbitrary score) as a named risk.

## 9. Requirement → module mapping (for coverage tracking)

| SIH requirement | Module |
|---|---|
| Passive PCAP analysis | `ingestion/` |
| SMTP/IMAP/POP3 identification | `reassembly/` |
| STARTTLS detection | `starttls/` |
| TCP stream reconstruction | `reassembly/` |
| TLS handshake reconstruction | `tls/` |
| Certificate extraction/validation | `certificates/` |
| TLS version/cipher/key-exchange/FS | `tls/`, `rules/` |
| Weakness detection | `rules/` |
| AI/ML risk + anomaly | `ml/` |
| Security posture scoring | `rules/` + `ml/` → `api/` |
| Reports/dashboard | `reports/`, `frontend/` |

## 10. Post-MVP novelty priority (only after Stage 8 works end-to-end)

1. **Must-have:** Explainable AI (SHAP evidence, never a bare score).
2. **Must-have:** Cryptographic config drift + certificate drift detection.
3. **Strong:** Cryptographic fingerprint (TLS version + key exchange + cipher + key size
   + cert hash → one comparable ID).
4. **Strong:** Evidence-linked findings (finding → session → handshake field → cert).
5. **Strong:** What-if remediation simulator.
6. **Nice-to-have:** Attack-surface map, synthetic PCAP generator (already have `genny.py`).

## 11. Definition of done for MVP (Stage 8 checkpoint)

- PCAP uploadable through the UI; backend returns a completed analysis.
- SMTP/IMAP/POP3 scenarios in `genny.py`'s dataset are correctly recognized.
- TCP sessions correctly grouped for segmented/retransmitted/out-of-order captures
  (files `16`–`18`).
- STARTTLS/STLS transitions identified, including all three failure modes (file `14`).
- TLS version + cipher extracted for supported captures.
- Certificate metadata extracted and displayed, chain-observability distinguished from
  chain-invalidity.
- At least 5 rule-engine checks working with evidence + recommendation text.
- Transparent posture score shown, with drill-down from finding → session.
- JSON export plus at least one human-readable report format.
- Full demo runs from upload to report with no manual DB editing.

Metrics to capture for the final demo: PCAP size/packet count, TCP streams
reconstructed, sessions detected per protocol, TLS sessions detected, certificates
extracted, findings by severity, anomalous sessions, analysis time, detection accuracy
against the manifest's labels.

## 12. Working conventions for this repo

- Validate every parser against `securemail_test_pcaps/test_manifest.json` labels before
  calling a module done — it's the ground truth.
- When a capture doesn't contain enough evidence for a check (partial chain, truncated
  stream), report "not observable," never assume/guess a value.
- Keep the rule engine and the ML engine decoupled: rules must work standalone even if
  the ML stage is disabled or under-trained on the small synthetic dataset.
- No live traffic to real mail servers from analyzer code — this is a passive-analysis
  codebase.
