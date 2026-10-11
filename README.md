# ScamShield Advanced — AI-Powered Scam Detection & Digital Forensics

ScamShield Advanced is a cybersecurity and digital forensics platform designed to analyze suspicious messages and URLs, explain potential scam indicators, support incident investigations, and help preserve digital evidence integrity. It brings scam screening, threat analysis, evidence management, and investigation reporting into one unified application.

## Key Features

### 1. Scam Detection & Threat Analysis

- Dark-themed dashboard with an intuitive scanning interface.
- URL and message scanning with explainable indicators and risk scores.
- Persistent scan history and dashboard statistics backed by SQLite.
- Scam DNA explanations showing the indicators behind a detection result.
- Provisional attack-flow reconstruction based on suspicious text indicators.
- Optional QR image decoding followed by URL or message screening.
- PDF and JSON scan reports with CSV export.
- Optional VirusTotal and Google Safe Browsing URL reputation lookups when API keys are configured.
- Contextual detection rules for suspicious rewards, giveaways, urgent requests, payment requests, and potentially impersonated identities.

### 2. Digital Forensics & Incident Response

- Investigation case creation and management.
- Evidence uploads associated with investigation cases.
- SHA-256 evidence hashing and integrity re-verification.
- Incident timeline entries and recorded evidence activity.
- Consolidated PDF investigation reports containing case details, evidence inventories, hashes, and timeline events.
- Incident response guidance and structured investigation workflows.
- Account-scoped access to scans, evidence, timelines, and investigation cases.

### 3. Digital Forensics Laboratory

- Candidate Indicator of Compromise (IOC) extraction from text.
- Extraction of URLs, domains, email addresses, IPv4 addresses, hash-shaped strings, and phone-like strings.
- Text fingerprinting using SHA-256 and SHA-1.
- UTF-8 byte count and character count calculation.
- Evidence integrity checks to identify changes between the current file and its recorded digest.

## Investigation Workflow

**Screen → Explain → Reconstruct → Investigate → Preserve → Verify → Report**

ScamShield Advanced supports a structured workflow from initial screening to investigation documentation.

1. **Screen:** Analyze a suspicious URL or message using transparent detection rules.
2. **Explain:** Review the indicators contributing to the risk score.
3. **Reconstruct:** Examine a provisional attack-flow hypothesis inferred from available text indicators.
4. **Investigate:** Create an incident case and record relevant details.
5. **Preserve:** Upload and organize digital evidence.
6. **Verify:** Compare the current evidence hash against the previously recorded digest.
7. **Report:** Generate a report containing case information, evidence details, hashes, and timeline entries.

These capabilities are decision-support aids. They do not independently prove fraud, establish attacker identity, or certify a legal chain of custody.

## Run Locally (Windows / VS Code)

### Prerequisites

- Python installed on your system.
- Visual Studio Code or another Python-compatible editor.
- Git, if you want to clone the repository.

### Installation

1. Clone the repository or download the project files.
2. Open the project folder in VS Code.
3. Open the integrated terminal.
4. Create and activate a virtual environment:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

5. Install the required dependencies:

   ```powershell
   python -m pip install -r requirements.txt
   ```

6. Start the Flask application:

   ```powershell
   python app.py
   ```

7. Open the following address in your browser:

   http://127.0.0.1:5000

The SQLite database and evidence files are stored locally and created as required by the application. QR decoding requires OpenCV, and PDF report generation requires ReportLab.

## Optional External Reputation Providers

ScamShield Advanced can use optional external URL reputation services when their API credentials are configured.

Supported integrations:

- VirusTotal
- Google Safe Browsing

Configure `VIRUSTOTAL_API_KEY` and/or `GOOGLE_SAFE_BROWSING_API_KEY` in your local environment.

Never commit real API keys or other secrets to GitHub.

The configured URL lookups send URLs to the selected provider; message text is not sent by these URL lookups. Provider availability, privacy terms, and rate limits apply. Local rule-based screening remains available without external API keys.

## API Endpoints

### Health, Scanning & History

- `GET /api/health` — Check application health.
- `POST /api/scan` — Analyze a URL or message.
- `GET /api/stats` — Retrieve dashboard statistics.
- `GET /api/history` — Retrieve scan history.
- `GET /api/scan/<id>` — Retrieve an individual scan.
- `DELETE /api/scan/<id>` — Delete a scan.

The application also supports the following scan routes for compatibility with the existing interface:

- `POST /scan`
- `POST /scan-url`
- `POST /scan-message`

### Incident & Evidence Management

- `POST /api/incidents` — Create an investigation case.
- `GET /api/incidents` — Retrieve investigation cases.
- `GET /api/incidents/<id>` — Retrieve an individual case.
- `POST /api/incidents/<id>/evidence` — Upload evidence associated with a case.
- `POST /api/incidents/<id>/events` — Add a case timeline event.
- `POST /api/incident-evidence/<id>/verify` — Verify incident evidence integrity.
- `GET /api/incident-evidence/<id>/download` — Download incident evidence.
- `GET /api/incidents/<id>/report.pdf` — Generate an incident report.

### General Evidence & Timeline

- `POST /api/evidence` — Add evidence.
- `GET /api/evidence` — Retrieve evidence records.
- `POST /api/evidence/<id>/verify` — Verify evidence integrity.
- `GET /api/evidence/<id>/download` — Download evidence.
- `GET /api/timeline` — Retrieve timeline entries.
- `POST /api/timeline` — Add a timeline entry.

### Reports & Exports

- `GET /api/report/<id>.pdf` — Generate a PDF report.
- `GET /api/report/<id>.json` — Generate a JSON report.
- `GET /api/export.csv` — Export scan records as CSV.

### QR Scanning & Integrations

- `POST /api/qr/scan` — Process a QR image for scanning.
- `GET /api/integrations/status` — Retrieve integration status.

### Digital Forensics Utilities

- `POST /api/forensics/ioc-extract` — Accepts JSON such as `{"text":"..."}` and extracts candidate indicators.
- `POST /api/forensics/text-fingerprint` — Accepts JSON such as `{"text":"..."}` and returns SHA-256, SHA-1, UTF-8 byte count, and character count.

Endpoint availability and behavior should be confirmed against the current application implementation.

## Testing

Run the included test suite after installing the dependencies:

```powershell
python -m unittest discover -s tests -v
```

The included tests cover health checks, scan persistence, input validation, detection rule integration, incident creation, timeline behavior, and registration validation.

Run the tests locally to confirm the current build's behavior. Additional integration and security testing is recommended before public deployment.

## Advanced Dashboard Behaviors

- The sidebar and main workspace use independent scrolling areas.
- Selecting a sidebar module switches the visible workspace; Dashboard returns to the scan overview.
- Dashboard statistics and recent activity are retrieved from SQLite.
- The notification panel displays recent scan and investigation activity.
- The profile menu provides account controls.
- Detection includes contextual reward and suspicious-link rules, including examples such as `click link to get 50k`.
- Signed-in users have account-scoped access to scans, evidence, timelines, and investigation cases.

Keep `SCAMSHIELD_SECRET_KEY` stable across restarts for reliable sessions, and configure it explicitly for deployments.

## Important Limitations & Security Notes

- The detector uses transparent rule-based screening. It is not a trained machine-learning model or a definitive scam or malware verdict.
- False positives and false negatives are possible.
- A low risk score does not prove that content is safe.
- Attack-flow reconstruction is a provisional narrative inferred from text indicators. It does not establish that every stage occurred or identify an attacker.
- A matching SHA-256 digest indicates that the current bytes match the recorded digest. It does not independently prove authenticity, source, trusted time, or legal chain of custody.
- This is a local development project, not a production-hardened service.
- Before public deployment, implement and test CSRF protection, rate limiting, authorization and isolation for every case and file, encrypted evidence storage, retention policies, HTTPS, secure secret management, and a production WSGI server.
- Keep secrets in environment variables. Do not commit `.env` files, databases, evidence uploads, real victim data, or API keys.
- Do not send confidential evidence to external services without appropriate authorization.
- The application does not perform disk imaging, memory forensics, malware detonation, or live packet capture.
- This project is not a certified forensic platform or a substitute for professional forensic examination.

## Suggested Future Research Extensions

1. **Multilingual scam detection:** Add Telugu, English, Hindi, and Tanglish language patterns and evaluate them against a labeled dataset.
2. **URL similarity analysis:** Detect lookalike domains, typosquatting, and internationalized domain name (IDN) similarities.
3. **Email analysis:** Add consent-based email import, MIME-aware `.eml` parsing, and RFC email-header analysis.
4. **Audit integrity:** Implement an append-only signed audit log containing the actor, timestamp, action, previous-event hash, and event hash, with trusted timestamping.
5. **Threat intelligence:** Integrate passive DNS, WHOIS, and certificate transparency sources with caching and rate limits.
6. **Machine-learning evaluation:** Add an optional classifier and measure precision, recall, and probability calibration against a labeled dataset.
7. **Incident reporting:** Add official reporting links, explicit user consent, and privacy-preserving data retention.
8. **Security testing:** Expand tests for file uploads, path traversal, oversized payloads, authentication, authorization, hash verification, and report generation.

## Validation Note

Python syntax and embedded frontend JavaScript syntax were checked for this build. The test suite is included, but it must be run in an environment with the dependencies installed.

Features and integrations should be verified locally before being described as fully functional. ScamShield Advanced is an educational cybersecurity and digital forensics project and is not represented as production-certified.
