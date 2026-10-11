# ScamShield × ScamSathi — Full-stack scam screening and incident response

This combined educational project preserves the original ScamShield dashboard layout and integrates ScamSathi's first-response investigation workflow into the same application.

## What is combined

### ScamShield core
- Original dark dashboard UI and scanner interaction flow
- URL and message scanning with explainable indicators and risk scores
- Persistent scan history and dashboard statistics in SQLite
- Scam DNA explanations and provisional attack-flow reconstruction
- Optional QR image decoding and scan follow-up
- PDF scan reports, JSON reports, CSV export
- Optional live VirusTotal and Google Safe Browsing URL lookups when API keys are configured

### ScamSathi first-response workflow
- Incident/case creation with the description screened by the shared rule engine
- Evidence upload tied to a selected incident
- SHA-256 evidence integrity recording and re-verification
- Incident timeline entries and automatically recorded evidence events
- Consolidated incident PDF report containing case details, evidence inventory/hashes, and timeline
- Protection guidance and a case-based workflow from screening to documentation

## Novelty direction

The main differentiator is a **screen → explain → reconstruct → investigate → preserve → verify → report** workflow. A scan can be used as the starting point for an incident; Scam DNA explains the rule signals; Attack Flow provides a cautious, inferred sequence; the incident workspace records evidence and a timeline; hash checks help detect changes to stored bytes; and the final PDF gathers the investigation record. These outputs are decision-support aids, not proof of fraud or legal chain of custody.

## Run locally (Windows / VS Code)

1. Extract the ZIP and open the project folder in VS Code.
2. In the terminal:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install -r requirements.txt
   python app.py
   ```

3. Visit `http://127.0.0.1:5000`.

The SQLite database and evidence files are created locally on first use. QR decoding needs OpenCV; PDF reports need ReportLab.

## Optional external reputation providers

Set `VIRUSTOTAL_API_KEY` and/or `GOOGLE_SAFE_BROWSING_API_KEY` in your local environment. Never commit real keys to GitHub. When configured, only the URL is sent to the provider; message text is not sent by these URL lookups. Third-party lookup availability and rate limits apply. If no key is configured, the local explainable rules still work.

## API endpoints

- `GET /api/health`
- `POST /api/scan` (also `/scan`, `/scan-url`, `/scan-message` for compatibility with the original UI)
- `GET /api/stats`, `GET /api/history`, `GET /api/scan/<id>`, `DELETE /api/scan/<id>`
- `POST /api/incidents`, `GET /api/incidents`, `GET /api/incidents/<id>`
- `POST /api/incidents/<id>/evidence`, `POST /api/incidents/<id>/events`
- `POST /api/incident-evidence/<id>/verify`, `GET /api/incident-evidence/<id>/download`
- `GET /api/incidents/<id>/report.pdf`
- `POST /api/evidence`, `GET /api/evidence`, `POST /api/evidence/<id>/verify`, `GET /api/evidence/<id>/download`
- `GET /api/timeline`, `POST /api/timeline`
- `GET /api/report/<id>.pdf`, `GET /api/report/<id>.json`, `GET /api/export.csv`
- `POST /api/qr/scan`, `GET /api/integrations/status`

## Tests

```powershell
python -m unittest discover -s tests -v
```

The included tests cover health, scan persistence, input validation, ScamSathi rule-pack integration, incident creation/timeline, and registration validation.

## Important limitations

- The detector is transparent rule-based screening, not a trained ML model or a definitive scam/malware verdict. False positives and false negatives are possible.
- Attack Flow is a provisional narrative inferred from text indicators; it does not establish that each stage occurred or attribute an attacker.
- A low score is not proof of safety.
- A matching SHA-256 digest means the current bytes match the recorded digest; it does not prove source, authenticity, trusted time, or legal chain of custody.
- This is a local development starter, not production-hardened. Before public deployment, add CSRF protection, rate limiting, authorization/isolation for every case and file, encrypted evidence storage, retention policy, HTTPS, secure secret management, and a production WSGI server.
- Keep secrets in environment variables. Do not commit `.env`, databases, uploads, real victim data, or API keys.

## Suggested future research extensions

- Multilingual Telugu/English scam-language packs
- URL lookalike/typosquatting and IDN similarity scoring
- Consent-based email/SMS import connectors
- Append-only signed audit log and trusted timestamping
- Optional ML classifier evaluated against a labeled dataset, with precision/recall and calibration
- Official reporting workflow links, user consent, and privacy-preserving data retention


## Advanced project edition — module map

### Core platform
- ScamShield URL/message risk triage with transparent heuristic indicators and a bounded 0–100 score.
- Scam DNA explanations and a provisional attack-flow hypothesis (not forensic attribution).
- QR image decoding and subsequent URL/message screening (requires OpenCV).
- ScamSathi-inspired incident workspace: case records, evidence uploads, SHA-256 integrity verification, event timeline, and incident PDF report.
- Dedicated Digital Forensics Laboratory: candidate IOC extraction from pasted text (URLs/domains, email addresses, IPv4, hash-shaped strings and phone-like strings) and text fingerprinting (SHA-256/SHA-1).
- Scan history, CSV export, per-scan JSON/PDF reports, account endpoints, optional URL-reputation integrations.

### API additions
- `POST /api/forensics/ioc-extract` — JSON body `{ "text": "..." }`; extracts candidate indicators.
- `POST /api/forensics/text-fingerprint` — JSON body `{ "text": "..." }`; returns SHA-256, SHA-1, UTF-8 byte count, and character count.

### Suggested research extensions
1. Add a proper append-only chain-of-custody ledger with actor, timestamp, action, previous-event hash, and event hash.
2. Add MIME-aware `.eml` parsing and RFC email-header analysis.
3. Add passive DNS / WHOIS / certificate transparency connectors with rate limits and caching.
4. Add Hindi/Telugu/Tanglish scam-language pattern packs with an evaluation dataset.
5. Add role-based case access, CSRF protection, rate limiting, and deployment secret management before exposing it beyond localhost.
6. Add unit/integration tests for uploads, path traversal, oversized payloads, hash verification, auth, and report generation.

### Important limitations
This is a defensive student project and a triage aid. It does not perform disk imaging, memory forensics, malware detonation, live packet capture, or court-grade chain-of-custody certification. Heuristic scores are not proof that a message is malicious; false positives and false negatives are possible. Never upload confidential evidence to external providers without authorization. Optional reputation integrations send URLs only, not message text. Keep the app bound to localhost unless you have hardened authentication, CSRF controls, rate limits, and deployment settings.

## Advanced dashboard behaviors

- The sidebar and workspace have independent scroll containers. Choosing a sidebar module hides the other workspaces; Dashboard returns to the scan overview.
- Dashboard statistics and recent activity refresh from SQLite. The notification bell opens recent scan and investigation activity; the profile button opens account controls.
- Detection includes contextual click-through reward rules, including examples such as `click link to get 50k`. Scores are explainable heuristic signals and must not be interpreted as proof that content is malicious or safe.
- Signed-in users have account-scoped scan, evidence, timeline, and incident access. Keep `SCAMSHIELD_SECRET_KEY` stable across restarts for reliable sessions and configure it explicitly for deployments.

## Validation note

Python syntax and the embedded frontend JavaScript syntax have been checked for this build. The test suite is included, but it must be run in an environment where the dependencies in `requirements.txt` are installed. This package has not been represented as production-certified or as a substitute for a professional forensic platform.
