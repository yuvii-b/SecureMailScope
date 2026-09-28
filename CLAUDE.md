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
| Frontend | React + JavaScript (JSX) + Tailwind, Recharts for charts |
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
- [x] **Stage 5 — Certificate analysis.** X.509 extraction from the DER bytes Stage 4
      pulled out of the Certificate handshake message: subject/issuer, validity window
      evaluated against the *capture's own timestamp* (earliest packet time in the
      session, not wall-clock "now" — a capture from last year must not be judged
      against today's date), key algorithm/length, signature algorithm, SAN/hostname
      match against the session's observed SNI, SHA-256 fingerprint, and chain
      completeness via real signature verification (`OBSERVED_VALID` / `NOT_OBSERVABLE`
      / `INVALID`) rather than name-matching alone. Lives in
      `backend/app/certificates/analyzer.py`, wired into `POST /api/pcap/sessions`'s
      per-session response as `certificate`. `ReassembledSession` (Stage 3) gained a
      `capture_time` field (min packet timestamp in the flow) to support this. Every
      leaf certificate in `genny.py`'s dataset except the incomplete-chain one turns out
      to be structurally self-signed (issuer == subject) — that's a property of the
      generator's cert-building shortcuts, not a bug in this module; `13`'s leaf is the
      only one genuinely signed by an absent intermediate, which is exactly the "chain
      not observable" case CLAUDE.md called out.
      **How to test:** `cd backend && python -m pytest -v` (72 tests total; 12 new in
      `test_certificates.py` covering the full `08`–`13` cert-scenario matrix, the
      no-certificate case (file `15`), fingerprint shape, and a hand-stitched two-cert
      mismatch exercising the `INVALID` branch that `genny.py`'s dataset doesn't
      otherwise produce; 2 new API tests in `test_api.py`. To sanity-check by hand:
      `uvicorn app.main:app --reload --port 8000`, then
      `curl -X POST http://127.0.0.1:8000/api/pcap/sessions -F "file=@../securemail_test_pcaps/13_cert_incomplete_chain.pcap"`
      — expect `certificate.chain_status: "NOT_OBSERVABLE"`, `certificate.self_signed:
      false`, `certificate.issuer: "SecureMailScope Intermediate CA"`. Also try
      `08_cert_expired.pcap` (expect `certificate.expired: true`,
      `certificate.chain_status: "OBSERVED_VALID"` since its leaf is self-signed) and
      `03_tls12_ecdhe_rsa_safe.pcap` (expect `certificate.hostname_match: true`,
      `certificate.key_length_bits: 2048`).
- [x] **Stage 6 — Rule engine.** Deterministic checks implementing the §8 matrix against
      the `tls_handshake`/`certificate`/`starttls` dicts Stages 4-5 already produce:
      deprecated TLS 1.0/1.1 and insecure SSLv2/SSLv3 (Protocol), critical ciphers
      (NULL/RC4/3DES/EXPORT/ANON, matched by name against the negotiated cipher suite)
      and CBC-mode on TLS 1.2 (Cipher), static RSA with no forward secrecy (Key exchange),
      self-signed/broken/not-fully-observable chains, expired/not-yet-valid, SHA-1/MD5
      signatures, and sub-2048-bit RSA keys (Certificate), and STARTTLS
      plaintext-after-advertisement (Critical). "DH group below configured minimum" is
      deliberately not implemented — Stage 4's parser only extracts the cipher suite name
      from ServerHello, not the actual DH parameters from ServerKeyExchange, so the group
      size isn't observable yet (CLAUDE.md §12: report not observable, never guess). Each
      `Finding` carries severity/title/evidence/policy_reference/recommendation/domain
      (`to_dict()` matches §7's JSON contract shape). Severity→score weights and
      score→risk-level bands are plain config dicts in `backend/app/rules/engine.py`, not
      inline magic numbers; `risk_level` is the score's band floored by the worst
      individual finding's severity, so one CRITICAL finding on an otherwise-clean session
      is never reported as merely "HIGH". Pure functions of the three input dicts — no
      dependency on the (not-yet-built) ML engine, so it works standalone per §12. Wired
      into `POST /api/pcap/sessions`'s per-session response as `findings`,
      `posture_score`, and `risk_level`.
      **How to test:** `cd backend && python -m pytest -v` (91 tests total; 18 new in
      `test_rules.py` covering the full matrix against `genny.py` scenarios `01`/`02`
      (deprecated TLS 1.0/1.1 + RC4/3DES), `05`/`06` (NULL/DH-anon ciphers), `03`/`07`
      (safe sessions produce no protocol/cipher/key-exchange findings), `08`/`10`–`13`
      (certificate findings, including the `NOT_OBSERVABLE`-is-informational-not-HIGH
      distinction), and `14` (STARTTLS stripping); plus synthetic-dict unit tests for the
      CBC-on-TLS-1.2 rule (no cipher in `genny.py`'s dataset exercises it) and score/
      risk-level boundary behavior; 2 new API tests in `test_api.py`. To sanity-check by
      hand: `uvicorn app.main:app --reload --port 8000`, then
      `curl -X POST http://127.0.0.1:8000/api/pcap/sessions -F "file=@../securemail_test_pcaps/01_tls10_3des_rsa.pcap"`
      — expect `risk_level: "CRITICAL"`, `posture_score: 0`, and findings for the
      deprecated TLS version, the 3DES cipher, static RSA key exchange, and the
      self-signed leaf. Also try `14_starttls_plaintext_after_advertisement.pcap` (expect
      a single CRITICAL STARTTLS finding whose `evidence` includes the leaked plaintext
      IMAP `LOGIN` command — this is a real passive-capture credential leak, not a
      contrived example).
- [x] **Stage 7 — Backend/API.** New `backend/app/api/` package freezes the §7 JSON
      contract: `POST /api/analyses` (upload, returns `{capture_id, status}`, 202),
      `GET /api/analyses/{capture_id}` (status, and once `COMPLETE` the full
      `schema_version` + `summary` + `sessions` body), `GET /api/analyses` (history list).
      `app/api/pipeline.py` is the one place that wires
      reassembly → STARTTLS → TLS handshake → certificate → rule engine (Stages 3-6) into
      a per-session contract dict and a capture-level `summary` (`overall_health_score` =
      mean posture score across sessions, `risk_level` = worst session's risk level —
      one badly configured endpoint is enough to compromise mail flow through it).
      `ai_analysis` is reported as `null` since ML is Stage 9 — never fabricate a score
      for a stage that doesn't exist yet (§12). The old `POST /api/pcap/sessions`
      (Stages 3-6) is left in place unchanged as a synchronous, no-persistence debug
      endpoint; the new routes are additive, not a replacement.

      Async job queue: `backend/app/worker.py` defines a Celery app and
      `analyze_pcap_task`. `CELERY_TASK_ALWAYS_EAGER` defaults to `true`, so the task runs
      synchronously in-process the moment `.delay()` is called — no Redis broker or
      separate worker process required to develop or test on a machine without them
      running (this sandbox's Docker Desktop engine wasn't up during this stage).
      `docker-compose.yml` sets it to `false` for real deployment, where the `worker`
      service actually consumes from the `redis` service asynchronously, matching the
      locked-in stack (§3). Uploaded pcaps are saved to `UPLOAD_DIR` (default
      `backend/uploads/`) keyed by `capture_id` so a real out-of-process worker can find
      them by path.

      Persistence: `backend/app/models/` has two SQLAlchemy models, `Capture` (one row per
      upload/job: filename, status, summary, timestamps) and `SessionRecord` (one row per
      reconstructed session, findings/tls_handshake/certificate stored as JSON columns
      rather than further normalized tables — there's no cross-capture query requirement
      yet, e.g. "all findings of severity X across every capture," to justify that extra
      schema complexity; revisit if Stage 9/11 need it). `app/db.py`'s `DATABASE_URL`
      defaults to a local SQLite file so `uvicorn`/`pytest` stay zero-dependency, matching
      every prior stage's "just run it" convention — PostgreSQL remains the locked
      production choice, wired via `docker-compose.yml`'s `DATABASE_URL` env var, not
      swapped out. No Alembic yet; `Base.metadata.create_all()` on startup is enough for a
      schema that hasn't shipped a single migration.
      **How to test:** `cd backend && python -m pytest -v` (96 tests total; 5 new in
      `test_analysis_api.py` covering upload→complete round-trip against `01`
      (expect `risk_level: "CRITICAL"`), corrupt-file rejection, 404 for an unknown
      `capture_id`, the history list, and stable `session_id`s across the multi-session
      file `22`). `backend/tests/conftest.py` points `DATABASE_URL`/`UPLOAD_DIR` at
      throwaway test-local paths before any app module is imported, so this suite still
      needs no Postgres/Redis/Docker. To sanity-check by hand:
      `uvicorn app.main:app --reload --port 8000`, then
      `curl -X POST http://127.0.0.1:8000/api/analyses -F "file=@../securemail_test_pcaps/14_starttls_plaintext_after_advertisement.pcap"`
      — returns `{"capture_id": "...", "status": "COMPLETE"}` immediately (eager mode);
      `curl http://127.0.0.1:8000/api/analyses/<capture_id>` then returns the full
      contract body with the STARTTLS-stripping finding. To exercise the real async path,
      start Docker Desktop and run `docker compose up --build` from the repo root, which
      brings up `redis` + `postgres` + `api` + `worker` with `CELERY_TASK_ALWAYS_EAGER=false`
      (not exercised in this sandbox — its Docker engine wasn't running during this stage).
- [x] **Stage 8 — Dashboard (MVP demo milestone).** React + JavaScript (JSX) + Tailwind v4
      + Recharts, in `frontend/`, consuming Stage 7's `/api/analyses` contract directly (no
      mocked JSON needed - the real backend was already up). Three pages in
      `frontend/src/pages/`: `CapturesListPage` (upload panel + list of every analyzed
      capture, polling every 4s so a running job flips to COMPLETE without a manual
      refresh), `CaptureDashboardPage` (posture-score gauge, a findings-by-severity bar
      chart, and a session table - polls the single capture every 1.5s while its status is
      PENDING/RUNNING), and `SessionDetailPage` (STARTTLS negotiation, TLS handshake,
      certificate, and the full evidence-linked findings list for one session, reached by
      clicking a session row - this is the "drill-down from finding to session" the MVP
      definition of done calls for). Deliberately plain JavaScript, not TypeScript - no
      build-time type checking, so `frontend/src/api/client.js` is trusted at runtime
      against the shapes `pipeline.py`/`models/analysis.py`/`rules/engine.py`/
      `state_machine.py` actually produce (kept in sync by re-reading those on every
      change) rather than enforced by a compiler; a backend schema drift shows up as
      `undefined` in the UI instead of a build error.
      **Visual direction (explicit user requirement, not the default AI-generated look):**
      the pitch deck (`SecureMailScope_SIH2026_FINAL (1).pdf`) turned out to have no actual
      dashboard screenshot - just an architecture diagram and a stat-card slide - so those
      were mined for a palette (dark navy panels, a category-colored top bar, a
      before/after posture circle) instead of being cloned pixel-for-pixel. The dashboard
      is a dark, dense, monospace-forward theme deliberately built to read like Wireshark
      or a SIEM/NOC console rather than a rounded-card SaaS template: near-black
      background (`--color-bg: #090c11`), 1px square-cornered borders instead of shadows,
      JetBrains Mono for every technical value (IPs, ports, cipher suite names, session
      IDs, hex fingerprints), and one fixed severity/risk color mapping used everywhere
      (`CRITICAL` red / `HIGH` orange / `MEDIUM` yellow / `LOW` blue / `INFO` gray, plus a
      green "ok" tone for COMPLETE/LOW) so a finding's color means the same thing on the
      captures list, the session table, and the findings panel.
      `docker-compose.yml` gained a `frontend` service (multi-stage Dockerfile, `serve`-d
      static build) with a `VITE_API_BASE_URL` build arg for the cross-origin-from-API
      case; local `npm run dev` instead proxies `/api` straight to the backend
      (`vite.config.js`), so no env var is needed for day-to-day development.
      **How to test:** `cd backend && uvicorn app.main:app --reload --port 8000` in one
      terminal, `cd frontend && npm install && npm run dev` in another, then open the
      printed localhost URL. Upload
      `securemail_test_pcaps/01_tls10_3des_rsa.pcap` and confirm it lands in the captures
      list as `CRITICAL` with score `0.0`; open
      `22_multiple_sessions_combined.pcap` and confirm the dashboard shows 3 sessions with
      a findings-by-severity bar chart (1 CRITICAL, several HIGH) and that clicking
      `SESS-SMTP-2` drills into a page showing `TLS_RSA_WITH_3DES_EDE_CBC_SHA`,
      `forward_secrecy: false`, and all 5 findings with evidence/policy/recommendation
      text; open `14_starttls_plaintext_after_advertisement.pcap` and confirm
      `SESS-IMAP-1`'s single CRITICAL finding's evidence still contains the leaked
      plaintext `LOGIN victim Password123!` command. `npm run build` (plain `vite build`,
      no type-checking step) must complete with no errors before calling this stage done.
- [x] **Stage 9 — ML.** Feature extraction (19 features, §7.1) → Isolation Forest anomaly
      detection → XGBoost risk classification → SHAP explainability, all in
      `backend/app/ml/`. `features.py` builds the 19-feature dict per session from the
      dicts Stages 3-5 already produce (no new packet parsing); per CLAUDE.md §12,
      unobservable values are `None`, never guessed (`chain_valid`/`certificate_valid`
      when the chain isn't fully captured; `handshake_duration` always, since the TLS
      record parser has no per-record timestamps to subtract - a Stage 4 change, not a
      feature-extraction one). `encoding.py`'s `FeatureEncoder` turns that dict into a
      fixed-width numeric matrix: one-hot columns per categorical value seen at fit time
      plus an `=__unseen__` catch-all bucket (deliberately not named `=UNKNOWN`, since
      `protocol` itself can legitimately *be* the string `"UNKNOWN"` for files `19`/`21`'s
      unidentifiable traffic - that must not collide with "a value the encoder has never
      seen"), and a paired `<col>_observed` flag for every boolean/numeric so a `None`
      is never silently conflated with a real `False`/`0`.

      `dataset.py` assembles the labeled training set across all 22 `genny.py` files (26
      sessions), labeled from `test_manifest.json`'s per-file safe/weak/anomalous field -
      deliberately *not* the rule engine's own `risk_level` (kept decoupled per §12): a
      diagnostic pass found the two disagree often, since every `genny.py` leaf cert is
      self-signed by construction (drags "safe" TLS configs up to rule-engine HIGH) while
      files `19`/`21`'s malformed/unidentifiable traffic trips no rule at all (scores a
      misleadingly clean LOW). Training against the rule engine's own output would be
      circular; the manifest label is the actual ground truth. File `22`
      (`multiple_sessions_combined`, manifest label "mixed") gets a
      `SESSION_LABEL_OVERRIDES` entry - `["safe", "weak", "weak"]` - derived by reading
      `genny.py`'s construction order for that file, since `reassemble_pcap` sorts
      sessions by client address and that happens to match the build order.

      `anomaly.py` wraps an unsupervised `IsolationForest` (never sees the labels) and
      normalizes its `decision_function` into a 0-1 `anomaly_score` + boolean
      `anomaly_flag` using training-time min/max. `risk_model.py` wraps an XGBoost
      multiclass classifier (`safe`/`weak`/`anomalous`) fit on the manifest labels, turns
      its class probabilities into a single 0-100 `risk_score` via a documented weighted
      formula (weak=0.7, anomalous=1.0, safe=0.0), and wires `shap.TreeExplainer` so
      every score comes with a ranked, directional feature list (`increases_risk` /
      `decreases_risk` + a normalized share of the explanation) - the §10 "must-have"
      explainability requirement: never a bare score. With ~26 labeled sessions this is a
      demonstration of the pipeline, not a claim of generalization (documented in the
      module docstrings and in CLAUDE.md's own original Stage 9 note).

      `train.py` (`python -m app.ml.train`) builds the dataset, fits the encoder and both
      models, and persists all three via `joblib` to `backend/app/ml/models/` (committed
      to the repo, matching Stage 7's SQLite "just run it" convention - no separate
      training step needed to demo). `inference.py` lazy-loads those artifacts once and
      exposes `analyze()`, wired into `backend/app/api/pipeline.py`'s `analyze_session()`
      as the real `ai_analysis` value; if the artifacts are ever missing, `analyze()`
      returns `None` rather than crashing, so the rule engine keeps working standalone
      (§12) - `ai_analysis: null` was always a documented valid contract value (§7), never
      a placeholder.
      **How to test:** `cd backend && python -m pytest -v` (120 tests total; 10 in
      `test_ml_features.py` from the feature-extraction phase; 14 new: 5 in
      `test_ml_encoding.py` covering the fit/transform round-trip, the unseen-category
      bucket, and the literal-`"UNKNOWN"`-value collision case; 3 in `test_ml_dataset.py`
      confirming all 26 sessions are covered, file `22`'s per-session label override, and
      files `19`/`20`/`21` all landing on `anomalous`; 6 in `test_ml_models.py` covering
      Isolation Forest flagging files `19`/`21`, the risk classifier producing a valid
      label + probabilities for every session, safe sessions scoring lower risk than
      anomalous ones on average, SHAP-backed `explain()` output shape, and
      `train.py`/`inference.py`'s persist-then-load round trip including the
      graceful-`None`-when-missing fallback; plus one new assertion in
      `test_analysis_api.py` confirming `ai_analysis` is populated end-to-end for a real
      upload. To sanity-check by hand:
      `cd backend && ../.venv/Scripts/python.exe -m app.ml.train` reprints a training
      summary (`sessions_trained_on: 26`, per-label counts, training-set accuracy); then
      `uvicorn app.main:app --reload --port 8000` and
      `curl -X POST http://127.0.0.1:8000/api/analyses -F "file=@../securemail_test_pcaps/19_malformed_tls.pcap"`
      followed by `curl http://127.0.0.1:8000/api/analyses/<capture_id>` - expect that
      session's `ai_analysis.anomaly_flag: true`, `predicted_label: "anomalous"`, and a
      non-empty `top_contributing_features` list.
- [x] **Stage 10 — Novelty (post-MVP).** All §10 items implemented (explicit user
      instruction: "implement all," overriding this section's own "pick 2-3" advice).
      Explainable AI was already satisfied by Stage 9's SHAP output; the four new items
      below are each a self-contained package under `backend/app/`, wired additively into
      `api/pipeline.py`/`models/analysis.py`/`worker.py` so none of them can break the
      Stage 0-9 pipeline if disabled.

      **Cryptographic fingerprint** (`backend/app/fingerprint/fingerprint.py`) — one
      comparable ID per session: SHA-256 (truncated to 16 hex chars) over a canonical
      sorted string of `tls_version`, `key_exchange`, `cipher_suite`,
      `certificate_key_algorithm`, `certificate_key_length_bits`, `certificate_sha256`.
      `observable: false`/`fingerprint_id: null` when no TLS version was negotiated at
      all, per §12's "report not observable, never guess." Wired into
      `pipeline.py::analyze_session()`'s return dict as `crypto_fingerprint`, persisted on
      `SessionRecord.crypto_fingerprint` (new nullable JSON column).

      **Config/certificate drift detection** (`backend/app/drift/detector.py`) —
      deliberately *not* in `pipeline.py`, since it needs to query other captures'
      `SessionRecord`s for the same endpoint and `pipeline.py` is kept DB-free by design
      (§12). Split into a pure `detect_drift(baseline_tls, baseline_cert,
      baseline_starttls, current_tls, current_cert, current_starttls)` (unit-testable with
      plain dicts) and `find_baseline_and_compare(db, capture_id, session_dict)`, which
      looks up the most recently completed prior capture at the same `server_ip` +
      `server_port` + `protocol` (SNI isn't always observed, so hostname can't be the key)
      and calls `detect_drift`. Called from `worker.py` — the one place with both freshly
      computed session data and DB access — right before each `SessionRecord` is inserted,
      so a capture never matches itself. Checks: TLS version downgrade (HIGH), forward
      secrecy lost (HIGH), cipher suite changed (INFO), certificate key length decreased
      (HIGH), certificate rotated (INFO), STARTTLS enforcement regressed (CRITICAL — e.g.
      `SUCCESS` → `PLAINTEXT_AFTER_ADVERTISEMENT`). An *improvement* (TLS upgrade, cert
      renewed to a longer key, STARTTLS newly enforced) is never flagged. Result stored as
      a new, separate `SessionRecord.drift` JSON column — `status` is `NO_BASELINE` (first
      time this endpoint has ever been captured), `NO_DRIFT`, or `DRIFT_DETECTED` — never
      merged into `posture_score`/`risk_level`, mirroring how Stage 9's `ai_analysis` stays
      additive. `genny.py`'s 22 scenario files each use a distinct synthetic server IP, so
      there's no natural same-endpoint pair in the fixture dataset to exercise this with;
      tested with hand-built dicts (`detect_drift`) and directly-inserted
      `Capture`/`SessionRecord` rows sharing an endpoint (`find_baseline_and_compare`),
      following the same "hand-stitched" pattern `test_certificates.py` already uses for
      the `INVALID`-chain case genny.py doesn't produce either.

      **What-if remediation simulator** (`backend/app/simulator/remediation.py` +
      `router.py`) — a catalog of 7 atomic pure patch functions (`upgrade_tls_version`,
      `remove_weak_cipher`, `enable_forward_secrecy`, `renew_certificate`,
      `reissue_certificate_strong_key`, `replace_self_signed_with_ca_issued`,
      `enforce_starttls`) that mutate deep-copied `tls_handshake`/`certificate`/`starttls`
      dicts. `simulate_remediation()` reruns the same `rules.engine.evaluate_session()`
      used for real analysis before and after applying the requested patches and diffs
      findings by title into `findings_resolved`/`findings_remaining`/
      `findings_newly_introduced`, plus `posture_score_delta`. Never contacts a real mail
      server and never mutates the stored session — purely "what would the deterministic
      rule engine say about a hypothetically-patched config" (§12). Mounted at a
      **separate** `/api/simulator` prefix rather than nested under `/api/analyses`,
      specifically to avoid a FastAPI route collision with the existing catch-all
      `GET /api/analyses/{capture_id}`.

      **Attack-surface map** — nested into the existing `summary` dict as
      `summary.attack_surface` (`backend/app/attack_surface/mapper.py`, called from
      `pipeline.py::analyze_pcap_file()`; no schema change needed, since `summary` was
      already a flexible JSON column). Pure aggregation of the capture's already-computed
      per-session dicts into: distinct endpoints (by `server_ip:server_port`), protocol
      counts, findings-by-severity across the whole capture, worst risk level per
      endpoint, and endpoints flagged for deprecated TLS or STARTTLS-stripped plaintext.

      **Evidence-linked findings (strengthened)** — `rules.engine.Finding` gained an
      `evidence_path: Optional[str]` field (e.g. `"tls_handshake.version_negotiated"`,
      `"certificate.key_length_bits"`), populated at all 11 finding-construction sites
      across the rule engine plus all 6 in the new drift detector, so a UI can link a
      finding straight to the exact contract field/session/handshake value it came from,
      not just a prose evidence string.

      Stage 10 work is backend-only — confirmed via grep that Stage 9's own
      `ai_analysis` field isn't rendered anywhere in `frontend/src/pages/`, establishing
      that new pipeline output fields don't require immediate frontend wiring in this
      project; the new fields are available over the API for whenever frontend work
      resumes.
      **How to test:** `cd backend && python -m pytest -v` (158 tests total; 5 new in
      `test_fingerprint.py`, 6 new in `test_attack_surface.py`, 11 new in `test_drift.py`
      (8 unit tests for `detect_drift` covering every check plus the "improvement is not
      flagged" cases, 3 DB-level tests for `find_baseline_and_compare`), 10 new in
      `test_simulator.py` (one per catalog remediation plus the unknown-id error path,
      combining remediations, and unrelated findings surviving), and 6 new assertions/
      tests added to `test_analysis_api.py` (crypto_fingerprint/drift/attack_surface
      populated end-to-end, a second upload of the same pcap producing `NO_DRIFT` against
      its own first upload as baseline, the simulator's `GET /api/simulator/remediations`
      catalog endpoint, and `POST /api/simulator/{capture_id}/sessions/{session_id}`
      against a real persisted session). To sanity-check by hand:
      `uvicorn app.main:app --reload --port 8000`, then
      `curl -X POST http://127.0.0.1:8000/api/analyses -F "file=@../securemail_test_pcaps/01_tls10_3des_rsa.pcap"`
      twice in a row (same file) — the second capture's session should come back with
      `drift.status: "NO_DRIFT"` (identical config to the first upload) and both should
      have identical `crypto_fingerprint.fingerprint_id`. Then
      `curl http://127.0.0.1:8000/api/simulator/remediations` lists all 7 remediations,
      and
      `curl -X POST http://127.0.0.1:8000/api/simulator/<capture_id>/sessions/<session_id> -H "Content-Type: application/json" -d "{\"remediations\": [\"upgrade_tls_version\", \"remove_weak_cipher\"]}"`
      against that session returns `after.posture_score` higher than `before.posture_score`
      with `findings_resolved` including "Deprecated TLS version negotiated". Also check
      `result["summary"]["attack_surface"]["distinct_endpoints"]` is populated on any
      `GET /api/analyses/<capture_id>`.
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
