import os
import re
import io
import csv
import json
import hmac
import hashlib
import sqlite3
import secrets
import time
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, request, jsonify, render_template, session, redirect, url_for, send_file, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("SCAMSHIELD_DB", BASE_DIR / "scamshield.db"))
UPLOAD_DIR = Path(os.getenv("SCAMSHIELD_UPLOAD_DIR", BASE_DIR / "evidence_uploads"))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.getenv("SCAMSHIELD_SECRET_KEY") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("SCAMSHIELD_HTTPS", "0") == "1"

ALLOWED_EVIDENCE_EXTENSIONS = {".txt", ".eml", ".msg", ".pdf", ".png", ".jpg", ".jpeg", ".webp", ".json", ".csv", ".log"}
URL_RE = re.compile(r'https?://[^\s<>"\']+', re.I)
IP_URL_RE = re.compile(r'^https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/|$)', re.I)

URL_KEYWORDS = {
    "login": 12, "verify": 12, "verification": 12, "secure": 6,
    "account": 6, "update": 6, "password": 12, "bank": 12,
    "banking": 12, "signin": 12, "sign-in": 12, "confirm": 8,
    "payment": 12, "wallet": 10, "claim": 8, "prize": 12,
    "winner": 12, "phishing": 20, "scam": 20, "fraud": 20, "free": 6,
}
MESSAGE_KEYWORDS = {
    "phishing": 25, "scam": 25, "fraud": 22, "fake": 14,
    "urgent": 12, "immediately": 12, "act now": 14, "limited time": 12,
    "within 24 hours": 14, "account will be blocked": 20,
    "account will be suspended": 20, "blocked": 10, "suspended": 10,
    "deactivated": 10, "verify your account": 18, "confirm your account": 18,
    "password": 15, "username": 8, "login": 10, "sign in": 10,
    "signin": 10, "otp": 18, "one time password": 18, "verification code": 18,
    "pin": 12, "credentials": 18, "bank": 10, "bank account": 15,
    "payment": 10, "pay now": 15, "credit card": 16, "debit card": 16,
    "upi": 10, "refund": 10, "transaction": 8, "money": 6,
    "winner": 15, "you won": 20, "prize": 15, "lottery": 18,
    "reward": 10, "free gift": 15, "click here": 12, "click the link": 16,
    "open this link": 12, "download": 6, "install": 6, "customer support": 8,
    "support team": 8, "government": 8, "sbi": 6, "bank of india": 8,
    "gift card": 12, "investment guaranteed": 20, "double your money": 20,
}
SENSITIVE_RE = re.compile(r'\b(send|share|enter|provide|give|reply with)\b.{0,60}\b(password|otp|pin|card|credentials|verification code)\b', re.I)
SUSPICIOUS_TLDS = {".zip", ".mov", ".click", ".top", ".xyz", ".work", ".support"}

def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            scan_type TEXT NOT NULL,
            url TEXT NOT NULL DEFAULT '',
            message TEXT NOT NULL DEFAULT '',
            score INTEGER NOT NULL,
            risk TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            indicators_json TEXT NOT NULL,
            explanation_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            mime_type TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            sha256 TEXT NOT NULL,
            notes TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS timeline_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
            event_time TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            severity TEXT NOT NULL DEFAULT 'info',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            title TEXT NOT NULL,
            incident_type TEXT NOT NULL,
            description TEXT NOT NULL,
            analysis_score INTEGER NOT NULL DEFAULT 0,
            analysis_level TEXT NOT NULL DEFAULT 'Unassessed',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS incident_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            mime_type TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            notes TEXT NOT NULL DEFAULT '',
            added_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS incident_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            event_text TEXT NOT NULL,
            event_time TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'info'
        );
        """)
init_db()

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    with db() as con:
        row = con.execute("SELECT id,name,email FROM users WHERE id=?", (uid,)).fetchone()
    return dict(row) if row else None

def owned_or_public_clause(user):
    # Anonymous demo scans remain usable locally; authenticated users see their own scans.
    return ("user_id IS NULL", ()) if not user else ("user_id = ?", (user["id"],))

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            return jsonify({"error": "Please sign in to use this feature."}), 401
        return fn(*args, **kwargs)
    return wrapper

def analyse(url="", message="", source_type="combined"):
    url = (url or "").strip()[:4096]
    message = (message or "").strip()[:12000]
    if not url and not message:
        raise ValueError("Enter a URL or message to scan.")
    score, indicators, explanations = 0, [], []
    def add(points, label, detail):
        nonlocal score
        score += points
        indicators.append(label)
        explanations.append({"indicator": label, "why": detail, "points": points})

    # Extract a URL from the message if the separate URL field is empty.
    extracted = URL_RE.findall(message)
    effective_urls = [url] if url else extracted[:5]
    for candidate in effective_urls:
        candidate = candidate.rstrip(".,);]")
        parsed = urlparse(candidate if "://" in candidate else "https://" + candidate)
        if parsed.scheme != "https":
            add(12, "URL does not use HTTPS", "Unencrypted transport can expose traffic; HTTPS alone does not prove a site is trustworthy.")
        if IP_URL_RE.search(candidate):
            add(22, "URL uses a raw IP address", "Credential-harvesting pages sometimes use IP addresses instead of recognizable domains.")
        if len(candidate) > 100:
            add(8, "Unusually long URL", "Long URLs can obscure the true destination or contain tracking/redirect parameters.")
        host = (parsed.hostname or "").lower()
        if host.startswith("xn--") or ".xn--" in host:
            add(15, "Internationalized/punycode domain to inspect", "Punycode can represent internationalized domain names; inspect for lookalike characters and verify the actual domain.")
        if host.count(".") >= 3:
            add(8, "Many subdomain levels", "Nested subdomains can make a misleading hostname harder to inspect.")
        if "@" in parsed.netloc:
            add(18, "URL contains an @ sign in its authority", "Some URLs use user-info syntax to disguise the destination host.")
        suffix = "." + host.rsplit(".", 1)[-1] if "." in host else ""
        if suffix in SUSPICIOUS_TLDS:
            add(8, f"Less-common domain ending: {suffix}", "This ending is not proof of fraud, but it deserves additional context checks.")
        for word, points in URL_KEYWORDS.items():
            if word in candidate.lower():
                add(points, f"Suspicious URL pattern: {word}", "The URL contains a term commonly used in account, payment, or prize lures.")

    text = (url + " " + message).lower()
    for word, points in MESSAGE_KEYWORDS.items():
        if word in text:
            add(points, f"Message pattern: {word}", "This phrase can be used to create urgency, impersonate an organization, or solicit money or credentials.")

    # ScamSathi rule pack: additional first-response patterns that complement the
    # original ScamShield keyword set without replacing its scoring/explanations.
    scamsathi_rules = [
        (r"\b(cvv|card number)\b", 16, "Requests or references to CVV/card-number data", "ScamSathi payment-data pattern"),
        (r"\b(giveaway|claim your reward)\b", 14, "Unexpected giveaway or reward claim", "ScamSathi prize-lure pattern"),
        (r"\b(send money|pay fee|processing fee|transfer funds|refund fee)\b", 16, "Explicit fee, transfer, or payment request", "ScamSathi payment-request pattern"),
        (r"\b(investment secret)\b", 16, "Unusual investment-secret promise", "ScamSathi investment-lure pattern"),
        (r"\b(download attachment)\b", 10, "Prompt to download an attachment", "ScamSathi attachment-lure pattern"),
        (r"\b(cryptocurrency|crypto|wallet seed|recovery phrase)\b", 10, "Cryptocurrency or wallet recovery terms", "ScamSathi crypto-wallet pattern"),
    ]
    for pattern, points, label, explanation in scamsathi_rules:
        if re.search(pattern, text, re.I):
            add(points, label, explanation + ". Verify the request independently and never share wallet recovery phrases.")

    # Context-aware lure rules: catch short informal reward messages such as
    # "click link to get 50k" that a plain keyword list can miss. These are
    # risk indicators, not a definitive verdict.
    contextual_rules = [
        (r"\b(click|tap|open)\b.{0,45}\b(link|here|below)\b.{0,45}\b(get|claim|win|receive)\b.{0,30}(?:₹|rs\.?\s*)?\d+(?:[,.]\d+)?\s*(?:k|thousand|lakh|lakhs)?", 38, "Click-through monetary reward lure", "A request to click a link to obtain a stated cash reward is a common lure pattern."),
        (r"\b(?:get|win|claim|receive)\b.{0,35}(?:₹|rs\.?\s*)?\d+(?:[,.]\d+)?\s*(?:k|thousand|lakh|lakhs)?\b", 24, "Unexpected money or prize promise", "Unexpected money or prize promises should be verified independently."),
        (r"\b(click|tap|open)\b.{0,35}\b(link|here|below)\b", 14, "Prompt to click a link", "The message prompts the recipient to follow a link; check the destination and sender before interacting."),
        (r"\b(only today|last chance|act fast|hurry|expires soon|limited offer)\b", 12, "Urgency or scarcity language", "Pressure to act quickly can discourage careful verification."),
        (r"\b(official|support|security|bank|government|police|courier)\b.{0,35}\b(verify|confirm|blocked|suspended|pay|fee)\b", 12, "Possible organization impersonation pattern", "The message combines organization-related language with a request or threat; verify through a known official channel."),
    ]
    for pattern, points, label, explanation in contextual_rules:
        if re.search(pattern, text, re.I):
            add(points, label, explanation)

    if extracted:
        add(8, "Message includes a clickable URL", "Links in unsolicited messages can lead to credential theft, malware, or fake payment pages.")
    if SENSITIVE_RE.search(text):
        add(22, "Requests sensitive information", "Legitimate services should not ask you to share an OTP, password, or PIN over a message.")
    if re.search(r'\b(guaranteed returns?|double your money|risk[- ]free profit)\b', text):
        add(18, "Promises guaranteed investment returns", "Unrealistic or guaranteed returns are a common investment-scam warning sign.")
    indicators = list(dict.fromkeys(indicators))
    score = min(score, 100)
    if score >= 70:
        risk = "HIGH RISK"
    elif score >= 40:
        risk = "SUSPICIOUS"
    else:
        risk = "LOW SIGNAL"
    if any(w in text for w in ("otp", "password", "pin", "credentials", "verification code", "login")):
        threat_type = "Credential Theft"
    elif any(w in text for w in ("bank", "payment", "upi", "credit card", "debit card", "refund", "transaction", "money")):
        threat_type = "Financial Scam"
    elif any(w in text for w in ("prize", "winner", "lottery", "reward", "free gift", "you won", "get 50k", "claim your reward")) or re.search(r"\b(click|tap|open)\b.{0,45}\b(link|here)\b.{0,45}\b(get|claim|win)\b", text):
        threat_type = "Prize / Reward Scam"
    elif any(w in text for w in ("investment", "guaranteed returns", "double your money")):
        threat_type = "Investment Scam"
    elif effective_urls:
        threat_type = "Suspicious URL"
    elif indicators:
        threat_type = "Social Engineering"
    else:
        threat_type = "No strong pattern detected"
    if not indicators:
        indicators = ["No strong scam indicators detected by these rules"]
        explanations = [{"indicator": indicators[0], "why": "The rule-based scanner did not find a listed pattern. This is not a guarantee of safety.", "points": 0}]
    return {
        "url": url, "message": message, "scan_type": source_type,
        "score": score, "risk": risk, "threat_type": threat_type,
        "indicators": indicators, "warnings": indicators,
        "explanations": explanations,
        "recommendations": (
            ["Do not open the link or send money.", "Never share OTPs, PINs, or passwords.", "Verify through the organization's official app or independently typed website.", "Preserve the original message and sender details as evidence."]
            if score >= 40 else
            ["Do not share sensitive information based on a message.", "Verify important requests through an independent official channel.", "A low score is not proof that a link or message is safe."]
        ),
        "scanned_at": utc_now(),
        "engine": "ScamShield explainable heuristic engine"
    }


def check_external_reputation(url):
    """Optional reputation lookups. Only URLs are sent; message text is never shared."""
    url = (url or "").strip()
    if not url or not re.match(r"^https?://", url, re.I):
        return {"virustotal": {"configured": bool(os.getenv("VIRUSTOTAL_API_KEY")), "checked": False},
                "google_safe_browsing": {"configured": bool(os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")), "checked": False}}
    output = {}
    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if vt_key:
        try:
            import requests
            encoded = __import__("base64").urlsafe_b64encode(url.encode()).decode().rstrip("=")
            response = requests.get(f"https://www.virustotal.com/api/v3/urls/{encoded}",
                                    headers={"x-apikey": vt_key}, timeout=8)
            if response.status_code == 200:
                stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = int(stats.get("malicious", 0))
                suspicious = int(stats.get("suspicious", 0))
                output["virustotal"] = {"configured": True, "checked": True, "malicious": malicious,
                                        "suspicious": suspicious, "stats": stats, "status": "found"}
            elif response.status_code == 404:
                output["virustotal"] = {"configured": True, "checked": False,
                                        "status": "URL not in existing report; submission is not automatic"}
            else:
                output["virustotal"] = {"configured": True, "checked": False,
                                        "status": f"Provider returned HTTP {response.status_code}"}
        except Exception:
            output["virustotal"] = {"configured": True, "checked": False, "status": "Lookup failed or timed out"}
    else:
        output["virustotal"] = {"configured": False, "checked": False, "status": "API key not configured"}

    gsb_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if gsb_key:
        try:
            import requests
            endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
            payload = {"client": {"clientId": "scamshield-local", "clientVersion": "1.0"},
                       "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                                       "POTENTIALLY_HARMFUL_APPLICATION"],
                                      "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                                      "threatEntries": [{"url": url}]}}
            response = requests.post(endpoint, params={"key": gsb_key}, json=payload, timeout=8)
            if response.status_code == 200:
                matches = response.json().get("matches", [])
                output["google_safe_browsing"] = {"configured": True, "checked": True,
                    "matches": [{"threatType": m.get("threatType"), "platformType": m.get("platformType")}
                                for m in matches], "threat_found": bool(matches), "status": "checked"}
            else:
                output["google_safe_browsing"] = {"configured": True, "checked": False,
                                                   "status": f"Provider returned HTTP {response.status_code}"}
        except Exception:
            output["google_safe_browsing"] = {"configured": True, "checked": False, "status": "Lookup failed or timed out"}
    else:
        output["google_safe_browsing"] = {"configured": False, "checked": False, "status": "API key not configured"}
    return output

def store_scan(result, user):
    with db() as con:
        cur = con.execute("""INSERT INTO scans
        (user_id,scan_type,url,message,score,risk,threat_type,indicators_json,explanation_json,created_at)
        VALUES(?,?,?,?,?,?,?,?,?,?)""",
        (user["id"] if user else None, result["scan_type"], result["url"], result["message"],
         result["score"], result["risk"], result["threat_type"], json.dumps(result["indicators"]),
         json.dumps(result["explanations"]), result["scanned_at"]))
        scan_id = cur.lastrowid
        con.execute("""INSERT INTO timeline_events(user_id,scan_id,event_time,title,description,severity,created_at)
        VALUES(?,?,?,?,?,?,?)""",
        (user["id"] if user else None, scan_id, result["scanned_at"], "Scan completed",
         f'{result["threat_type"]} classified as {result["risk"]} ({result["score"]}/100).',
         "high" if result["score"] >= 70 else "medium" if result["score"] >= 40 else "info", utc_now()))
    result["id"] = scan_id
    return result

def scan_to_dict(row):
    return {
        "id": row["id"], "scan_type": row["scan_type"], "url": row["url"], "message": row["message"],
        "score": row["score"], "risk": row["risk"], "threat_type": row["threat_type"],
        "indicators": json.loads(row["indicators_json"]), "explanations": json.loads(row["explanation_json"]),
        "created_at": row["created_at"]
    }

@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=()")
    return response

@app.get("/")
def home():
    return render_template("index.html")

@app.post("/api/forensics/ioc-extract")
def forensic_ioc_extract():
    """Extract candidate indicators from user-supplied text; results are leads, not attribution."""
    payload = request.get_json(silent=True) or {}
    source = str(payload.get("text", ""))[:30000]
    if not source.strip():
        return jsonify({"error": "Paste message, log, email headers, or text to inspect."}), 400
    patterns = {
        "URLs": r"https?://[^\s<>\"']+",
        "Email addresses": r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
        "IPv4 addresses": r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
        "MD5-like hashes": r"\b[a-fA-F0-9]{32}\b",
        "SHA-1-like hashes": r"\b[a-fA-F0-9]{40}\b",
        "SHA-256-like hashes": r"\b[a-fA-F0-9]{64}\b",
        "Phone-like strings": r"(?<!\w)(?:\+?\d[\d ()-]{7,}\d)(?!\w)",
    }
    result = {}
    for label, pattern in patterns.items():
        vals = list(dict.fromkeys(re.findall(pattern, source, re.I)))[:100]
        result[label] = vals
    # Domain extraction is derived only from URLs and intentionally not a reputation verdict.
    domains=[]
    for u in result["URLs"]:
        try:
            host=(urlparse(u).hostname or "").lower()
            if host and host not in domains: domains.append(host)
        except Exception: pass
    result["Domains from URLs"] = domains
    return jsonify({"indicators": result, "counts": {k:len(v) for k,v in result.items()}, "note":"Pattern-based extraction only. Indicators can be benign; validate with context and trusted sources."})


@app.post("/api/forensics/text-fingerprint")
def forensic_text_fingerprint():
    payload = request.get_json(silent=True) or {}
    source = str(payload.get("text", ""))[:30000]
    if not source:
        return jsonify({"error":"Enter text to fingerprint."}), 400
    raw=source.encode("utf-8")
    return jsonify({"sha256":hashlib.sha256(raw).hexdigest(),"sha1":hashlib.sha1(raw).hexdigest(),"bytes":len(raw),"characters":len(source),"note":"Fingerprints the exact UTF-8 text submitted, not an original file. Preserve originals separately for evidence handling."})


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "application": "ScamShield", "database": "sqlite", "time": utc_now()})

@app.get("/api/auth/me")
def auth_me():
    return jsonify({"user": current_user()})

@app.post("/api/auth/register")
def register():
    data = request.get_json(silent=True) or {}
    name, email, password = (str(data.get(k, "")).strip() for k in ("name", "email", "password"))
    if len(name) < 2 or len(email) > 254 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return jsonify({"error": "Enter a valid name and email address."}), 400
    if len(password) < 10:
        return jsonify({"error": "Use a password with at least 10 characters."}), 400
    try:
        with db() as con:
            cur = con.execute("INSERT INTO users(name,email,password_hash,created_at) VALUES(?,?,?,?)",
                              (name, email.lower(), generate_password_hash(password), utc_now()))
            session.clear()
            session["user_id"] = cur.lastrowid
        return jsonify({"message": "Account created.", "user": current_user()}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "An account with this email already exists."}), 409

@app.post("/api/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    email, password = str(data.get("email", "")).strip().lower(), str(data.get("password", ""))
    with db() as con:
        user = con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Incorrect email or password."}), 401
    session.clear()
    session["user_id"] = user["id"]
    return jsonify({"message": "Signed in.", "user": current_user()})

@app.post("/api/auth/logout")
def logout():
    session.clear()
    return jsonify({"message": "Signed out."})

@app.post("/api/scan")
@app.post("/scan")
@app.post("/scan-url")
@app.post("/scan-message")
def scan_api():
    data = request.get_json(silent=True) or {}
    try:
        result = analyse(data.get("url", ""), data.get("message", ""), data.get("scan_type", "combined"))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    # External URL reputation is opt-in through server-side API keys. Only URL data is sent;
    # message contents are deliberately not transmitted to third-party providers.
    result["external_reputation"] = check_external_reputation(result.get("url", ""))
    reputation = result["external_reputation"]
    vt = reputation.get("virustotal", {})
    gsb = reputation.get("google_safe_browsing", {})
    external_flags = []
    if vt.get("checked") and (vt.get("malicious", 0) > 0 or vt.get("suspicious", 0) > 0):
        external_flags.append(f'VirusTotal reports {vt.get("malicious", 0)} malicious and {vt.get("suspicious", 0)} suspicious detection(s)')
    if gsb.get("checked") and gsb.get("threat_found"):
        external_flags.append("Google Safe Browsing reports a known threat match")
    if external_flags:
        result["indicators"].extend(external_flags)
        result["warnings"] = result["indicators"]
        result["score"] = max(result["score"], 85)
        result["risk"] = "HIGH RISK"
        result["explanations"].extend([{"indicator": flag, "why": "A configured external reputation provider returned a threat signal.", "points": 0} for flag in external_flags])
    return jsonify(store_scan(result, current_user()))

@app.get("/api/notifications")
def notifications():
    user = current_user()
    clause, params = owned_or_public_clause(user)
    with db() as con:
        events = con.execute(f"SELECT id,title AS title,description AS detail,severity,created_at FROM timeline_events WHERE {clause} ORDER BY id DESC LIMIT 15", params).fetchall()
        recent = con.execute(f"SELECT id,threat_type AS title, (risk || ' · ' || score || '/100') AS detail, CASE WHEN score>=70 THEN 'high' WHEN score>=40 THEN 'medium' ELSE 'info' END AS severity, created_at FROM scans WHERE {clause} ORDER BY id DESC LIMIT 10", params).fetchall()
        incident_events = con.execute(f"SELECT ev.id, i.title AS title, ev.event_text AS detail, ev.severity, ev.event_time AS created_at FROM incident_events ev JOIN incidents i ON i.id=ev.incident_id WHERE i.{clause} ORDER BY ev.id DESC LIMIT 15", params).fetchall()
    items = [dict(x) for x in events] + [dict(x) for x in recent] + [dict(x) for x in incident_events]
    items.sort(key=lambda x: x.get('created_at',''), reverse=True)
    return jsonify({"items": items[:20], "unread_count": sum(1 for x in items if x.get('severity') in ('high','critical','medium'))})

@app.get("/api/stats")
def stats():
    user = current_user()
    clause, params = owned_or_public_clause(user)
    with db() as con:
        rows = con.execute(f"SELECT score,risk FROM scans WHERE {clause}", params).fetchall()
        evidence_count = con.execute(f"SELECT COUNT(*) FROM evidence WHERE {clause}", params).fetchone()[0]
    return jsonify({
        "total_scans": len(rows),
        "threats_detected": sum(1 for r in rows if r["score"] >= 40),
        "high_risk": sum(1 for r in rows if r["score"] >= 70),
        "evidence_count": evidence_count,
        "engine_status": "Operational"
    })

@app.get("/api/history")
def history():
    user = current_user()
    clause, params = owned_or_public_clause(user)
    limit = min(max(request.args.get("limit", default=50, type=int), 1), 200)
    with db() as con:
        rows = con.execute(f"SELECT * FROM scans WHERE {clause} ORDER BY id DESC LIMIT ?", (*params, limit)).fetchall()
    return jsonify({"items": [scan_to_dict(r) for r in rows]})

@app.get("/api/scan/<int:scan_id>")
def get_scan(scan_id):
    user = current_user()
    clause, params = owned_or_public_clause(user)
    with db() as con:
        row = con.execute(f"SELECT * FROM scans WHERE id=? AND {clause}", (scan_id, *params)).fetchone()
    if not row:
        return jsonify({"error": "Scan not found."}), 404
    return jsonify(scan_to_dict(row))

@app.delete("/api/scan/<int:scan_id>")
@login_required
def delete_scan(scan_id):
    with db() as con:
        cur = con.execute("DELETE FROM scans WHERE id=? AND user_id=?", (scan_id, current_user()["id"]))
    if not cur.rowcount:
        return jsonify({"error": "Scan not found."}), 404
    return jsonify({"message": "Scan deleted."})

@app.post("/api/evidence")
def upload_evidence():
    file = request.files.get("file")
    if not file or not file.filename:
        return jsonify({"error": "Choose an evidence file."}), 400
    original = secure_filename(file.filename)
    ext = Path(original).suffix.lower()
    if ext not in ALLOWED_EVIDENCE_EXTENSIONS:
        return jsonify({"error": "File type not allowed. Accepted: " + ", ".join(sorted(ALLOWED_EVIDENCE_EXTENSIONS))}), 400
    data = file.read(8 * 1024 * 1024 + 1)
    if not data or len(data) > 8 * 1024 * 1024:
        return jsonify({"error": "Evidence must be between 1 byte and 8 MB."}), 413
    digest = hashlib.sha256(data).hexdigest()
    stored_name = secrets.token_hex(16) + ext
    (UPLOAD_DIR / stored_name).write_bytes(data)
    notes = request.form.get("notes", "").strip()[:1000]
    scan_id = request.form.get("scan_id", type=int)
    user = current_user()
    try:
        with db() as con:
            if scan_id:
                if user:
                    row = con.execute("SELECT id FROM scans WHERE id=? AND user_id=?", (scan_id, user["id"])).fetchone()
                else:
                    row = con.execute("SELECT id FROM scans WHERE id=? AND user_id IS NULL", (scan_id,)).fetchone()
                if not row:
                    (UPLOAD_DIR / stored_name).unlink(missing_ok=True)
                    return jsonify({"error": "Linked scan does not exist in this account."}), 404
            cur = con.execute("""INSERT INTO evidence(user_id,scan_id,original_name,stored_name,mime_type,size_bytes,sha256,notes,created_at)
            VALUES(?,?,?,?,?,?,?,?,?)""",
            (user["id"] if user else None, scan_id, original, stored_name,
             file.mimetype or "application/octet-stream", len(data), digest, notes, utc_now()))
            evidence_id = cur.lastrowid
            con.execute("""INSERT INTO timeline_events(user_id,scan_id,event_time,title,description,severity,created_at)
            VALUES(?,?,?,?,?,?,?)""",
            (user["id"] if user else None, scan_id, utc_now(), "Evidence preserved",
             f"Stored {original}; SHA-256 {digest}.", "info", utc_now()))
    except Exception:
        (UPLOAD_DIR / stored_name).unlink(missing_ok=True)
        raise
    return jsonify({"id": evidence_id, "original_name": original, "size_bytes": len(data),
                    "sha256": digest, "created_at": utc_now(), "message": "Evidence stored and SHA-256 recorded."}), 201

@app.get("/api/evidence")
def list_evidence():
    user = current_user()
    clause, params = owned_or_public_clause(user)
    with db() as con:
        rows = con.execute(f"""SELECT id,scan_id,original_name,mime_type,size_bytes,sha256,notes,created_at
                               FROM evidence WHERE {clause} ORDER BY id DESC LIMIT 100""", params).fetchall()
    return jsonify({"items": [dict(r) for r in rows]})

@app.post("/api/evidence/<int:evidence_id>/verify")
def verify_evidence(evidence_id):
    user = current_user()
    clause, params = owned_or_public_clause(user)
    with db() as con:
        row = con.execute(f"SELECT * FROM evidence WHERE id=? AND {clause}", (evidence_id, *params)).fetchone()
    if not row:
        return jsonify({"error": "Evidence not found."}), 404
    path = UPLOAD_DIR / row["stored_name"]
    if not path.exists():
        return jsonify({"verified": False, "error": "Stored evidence file is missing."}), 404
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    return jsonify({"id": evidence_id, "verified": hmac.compare_digest(actual, row["sha256"]),
                    "recorded_sha256": row["sha256"], "current_sha256": actual})

@app.get("/api/evidence/<int:evidence_id>/download")
def download_evidence(evidence_id):
    user = current_user()
    clause, params = owned_or_public_clause(user)
    with db() as con:
        row = con.execute(f"SELECT * FROM evidence WHERE id=? AND {clause}", (evidence_id, *params)).fetchone()
    if not row:
        abort(404)
    path = UPLOAD_DIR / row["stored_name"]
    if not path.exists():
        abort(404)
    return send_file(path, as_attachment=True, download_name=row["original_name"], mimetype="application/octet-stream")

@app.get("/api/timeline")
def timeline():
    user = current_user()
    clause, params = owned_or_public_clause(user)
    with db() as con:
        rows = con.execute(f"SELECT * FROM timeline_events WHERE {clause} ORDER BY event_time DESC LIMIT 200", params).fetchall()
    return jsonify({"items": [dict(r) for r in rows]})

@app.post("/api/timeline")
@login_required
def add_timeline_event():
    data = request.get_json(silent=True) or {}
    title = str(data.get("title", "")).strip()[:160]
    description = str(data.get("description", "")).strip()[:2000]
    event_time = str(data.get("event_time", "")).strip() or utc_now()
    severity = str(data.get("severity", "info")).lower()
    if not title:
        return jsonify({"error": "Event title is required."}), 400
    if severity not in {"info", "low", "medium", "high", "critical"}:
        severity = "info"
    with db() as con:
        cur = con.execute("""INSERT INTO timeline_events(user_id,scan_id,event_time,title,description,severity,created_at)
        VALUES(?,NULL,?,?,?,?,?)""", (current_user()["id"], event_time, title, description, severity, utc_now()))
    return jsonify({"id": cur.lastrowid, "message": "Timeline event added."}), 201

@app.get("/api/reports")
def reports():
    user = current_user()
    clause, params = owned_or_public_clause(user)
    with db() as con:
        rows = con.execute(f"""SELECT s.id,s.scan_type,s.score,s.risk,s.threat_type,s.created_at
        FROM scans s WHERE s.{clause.replace('user_id', 'user_id')} ORDER BY s.id DESC LIMIT 100""", params).fetchall()
    return jsonify({"items": [dict(r) for r in rows]})

@app.get("/api/report/<int:scan_id>.json")
def report_json(scan_id):
    result = get_scan(scan_id)
    if isinstance(result, tuple):
        return result
    payload = result.get_json()
    payload["generated_at"] = utc_now()
    return jsonify(payload)

@app.get("/api/report/<int:scan_id>.pdf")
def report_pdf(scan_id):
    user = current_user()
    clause, params = owned_or_public_clause(user)
    with db() as con:
        row = con.execute(f"SELECT * FROM scans WHERE id=? AND {clause}", (scan_id, *params)).fetchone()
        if row:
            con.execute("INSERT INTO reports(user_id,scan_id,created_at) VALUES(?,?,?)",
                        (user["id"] if user else None, scan_id, utc_now()))
    if not row:
        return jsonify({"error": "Scan not found."}), 404
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import mm
    except ImportError:
        return jsonify({"error": "PDF export dependency missing. Run pip install -r requirements.txt."}), 501
    result = scan_to_dict(row)
    output = io.BytesIO()
    doc = SimpleDocTemplate(output, pagesize=A4, rightMargin=18*mm, leftMargin=18*mm, topMargin=18*mm, bottomMargin=18*mm)
    styles = getSampleStyleSheet()
    story = [Paragraph("ScamShield — Security Analysis Report", styles["Title"]),
             Paragraph("Generated: " + utc_now(), styles["Normal"]), Spacer(1, 10)]
    data = [["Scan ID", str(result["id"])], ["Risk", result["risk"]],
            ["Score", f'{result["score"]}/100'], ["Threat type", result["threat_type"]],
            ["Scan type", result["scan_type"]], ["URL", result["url"] or "(none)"],
            ["Message", (result["message"] or "(none)")[:1200]], ["Scanned at", result["created_at"]]]
    table = Table(data, colWidths=[35*mm, 135*mm])
    table.setStyle(TableStyle([("BACKGROUND",(0,0),(0,-1),colors.HexColor("#eaf1fb")),
                               ("GRID",(0,0),(-1,-1),0.4,colors.grey),("VALIGN",(0,0),(-1,-1),"TOP"),
                               ("LEFTPADDING",(0,0),(-1,-1),7),("RIGHTPADDING",(0,0),(-1,-1),7),
                               ("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6)]))
    story += [table, Spacer(1, 12), Paragraph("Indicators and explanations", styles["Heading2"])]
    for item in result["explanations"]:
        story.append(Paragraph(f'<b>{item["indicator"]}</b> (+{item["points"]}): {item["why"]}', styles["BodyText"]))
        story.append(Spacer(1, 5))
    story.append(Paragraph("Recommendations", styles["Heading2"]))
    for rec in analyse(result["url"], result["message"])["recommendations"]:
        story.append(Paragraph("• " + rec, styles["BodyText"]))
    story += [Spacer(1, 10), Paragraph("Disclaimer: This is a heuristic screening aid, not a definitive verdict. A low score does not guarantee safety.", styles["Italic"])]
    doc.build(story)
    output.seek(0)
    return send_file(output, mimetype="application/pdf", as_attachment=True, download_name=f"scamshield-report-{scan_id}.pdf")

@app.get("/api/export.csv")
def export_csv():
    user = current_user()
    clause, params = owned_or_public_clause(user)
    with db() as con:
        rows = con.execute(f"SELECT * FROM scans WHERE {clause} ORDER BY id DESC", params).fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id","scan_type","url","message","score","risk","threat_type","indicators","created_at"])
    for row in rows:
        writer.writerow([row["id"],row["scan_type"],row["url"],row["message"],row["score"],row["risk"],row["threat_type"],row["indicators_json"],row["created_at"]])
    return send_file(io.BytesIO(output.getvalue().encode("utf-8-sig")), mimetype="text/csv", as_attachment=True, download_name="scamshield-scans.csv")

@app.post("/api/qr/scan")
def qr_scan():
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "Upload a QR image."}), 400
    raw = file.read(5 * 1024 * 1024 + 1)
    if len(raw) > 5 * 1024 * 1024:
        return jsonify({"error": "QR image must be under 5 MB."}), 413
    try:
        import cv2
        import numpy as np
        image = cv2.imdecode(np.frombuffer(raw, dtype=np.uint8), cv2.IMREAD_COLOR)
        if image is None:
            return jsonify({"error": "The uploaded file is not a readable image."}), 400
        value, points, _ = cv2.QRCodeDetector().detectAndDecode(image)
    except ImportError:
        return jsonify({"error": "QR scanning dependency missing. Install opencv-python-headless and numpy."}), 501
    if not value:
        return jsonify({"error": "No readable QR code found in this image."}), 422
    result = analyse(value if value.lower().startswith(("http://","https://")) else "", value, "qr")
    result = store_scan(result, current_user())
    result["qr_content"] = value
    return jsonify(result)

@app.get("/api/integrations/status")
def integrations_status():
    return jsonify({
        "rule_engine": {"configured": True, "status": "active"},
        "virustotal": {"configured": bool(os.getenv("VIRUSTOTAL_API_KEY")), "status": "live lookup enabled" if os.getenv("VIRUSTOTAL_API_KEY") else "optional API key not set"},
        "google_safe_browsing": {"configured": bool(os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")), "status": "live lookup enabled" if os.getenv("GOOGLE_SAFE_BROWSING_API_KEY") else "optional API key not set"},
        "qr_decoder": {"configured": True, "status": "installed only if opencv-python-headless is available"},
        "pdf_reports": {"configured": True, "status": "available if reportlab is installed"}
    })


INCIDENT_ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".pdf", ".txt", ".eml", ".json", ".csv", ".log"}

def incident_level(score):
    return "High" if score >= 60 else "Elevated" if score >= 30 else "Lower indicator count"

@app.get("/api/incidents")
def list_incidents():
    user = current_user()
    clause, params = owned_or_public_clause(user)
    with db() as con:
        rows = con.execute(f"SELECT * FROM incidents WHERE {clause} ORDER BY id DESC LIMIT 100", params).fetchall()
    return jsonify({"items": [dict(r) for r in rows]})

@app.post("/api/incidents")
def create_incident():
    data = request.get_json(silent=True) or {}
    title = str(data.get("title", "")).strip()[:120]
    incident_type = str(data.get("incident_type", "Suspicious message")).strip()[:80]
    description = str(data.get("description", "")).strip()[:12000]
    if len(title) < 3 or len(description) < 3:
        return jsonify({"error": "Enter an incident title and description (at least 3 characters each)."}), 400
    analysis = analyse(message=description, source_type="incident")
    with db() as con:
        cur = con.execute("INSERT INTO incidents(user_id,title,incident_type,description,analysis_score,analysis_level,created_at) VALUES(?,?,?,?,?,?,?)",
                           (current_user()["id"] if current_user() else None, title, incident_type, description, analysis["score"], incident_level(analysis["score"]), utc_now()))
        incident_id = cur.lastrowid
        con.execute("INSERT INTO incident_events(incident_id,event_text,event_time,severity) VALUES(?,?,?,?)",
                    (incident_id, "Incident record created and description screened", utc_now(), "info"))
    return jsonify({"id": incident_id, "title": title, "incident_type": incident_type, "description": description,
                    "analysis_score": analysis["score"], "analysis_level": incident_level(analysis["score"]),
                    "indicators": analysis["indicators"], "created_at": utc_now()}), 201

@app.get("/api/incidents/<int:incident_id>")
def incident_detail_api(incident_id):
    user = current_user()
    owner_clause, owner_params = owned_or_public_clause(user)
    with db() as con:
        incident = con.execute(f"SELECT * FROM incidents WHERE id=? AND {owner_clause}", (incident_id, *owner_params)).fetchone()
        if not incident:
            return jsonify({"error": "Incident not found."}), 404
        evidence = con.execute("SELECT id,original_name,mime_type,sha256,size_bytes,notes,added_at FROM incident_evidence WHERE incident_id=? ORDER BY id DESC", (incident_id,)).fetchall()
        events = con.execute("SELECT * FROM incident_events WHERE incident_id=? ORDER BY event_time DESC", (incident_id,)).fetchall()
    return jsonify({"incident": dict(incident), "evidence": [dict(x) for x in evidence], "events": [dict(x) for x in events]})

@app.post("/api/incidents/<int:incident_id>/evidence")
def upload_incident_evidence(incident_id):
    upload = request.files.get("file")
    if not upload or not upload.filename:
        return jsonify({"error": "Choose a file to preserve."}), 400
    original = secure_filename(upload.filename) or "evidence_file"
    ext = Path(original).suffix.lower()
    if ext not in INCIDENT_ALLOWED_EXTENSIONS:
        return jsonify({"error": "Unsupported file type."}), 400
    data = upload.read(8 * 1024 * 1024 + 1)
    if not data or len(data) > 8 * 1024 * 1024:
        return jsonify({"error": "Evidence must be between 1 byte and 8 MB."}), 413
    user = current_user()
    owner_clause, owner_params = owned_or_public_clause(user)
    with db() as con:
        if not con.execute(f"SELECT id FROM incidents WHERE id=? AND {owner_clause}", (incident_id, *owner_params)).fetchone():
            return jsonify({"error": "Incident not found."}), 404
    stored = secrets.token_hex(16) + ext
    (UPLOAD_DIR / stored).write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    try:
        with db() as con:
            cur = con.execute("INSERT INTO incident_evidence(incident_id,original_name,stored_name,mime_type,sha256,size_bytes,notes,added_at) VALUES(?,?,?,?,?,?,?,?)",
                              (incident_id, original, stored, upload.mimetype or "application/octet-stream", digest, len(data), request.form.get("notes", "").strip()[:1000], utc_now()))
            evidence_id = cur.lastrowid
            con.execute("INSERT INTO incident_events(incident_id,event_text,event_time,severity) VALUES(?,?,?,?)",
                        (incident_id, f"Evidence preserved: {original}; SHA-256 recorded", utc_now(), "info"))
    except Exception:
        (UPLOAD_DIR / stored).unlink(missing_ok=True)
        raise
    return jsonify({"id": evidence_id, "incident_id": incident_id, "original_name": original, "sha256": digest,
                    "size_bytes": len(data), "message": "Evidence saved and SHA-256 recorded."}), 201

@app.post("/api/incidents/<int:incident_id>/events")
def add_incident_event(incident_id):
    data = request.get_json(silent=True) or {}
    event_text = str(data.get("event_text", "")).strip()[:1000]
    event_time = str(data.get("event_time", "")).strip() or utc_now()
    severity = str(data.get("severity", "info")).lower()
    if not event_text:
        return jsonify({"error": "Timeline event is required."}), 400
    if severity not in {"info", "low", "medium", "high", "critical"}:
        severity = "info"
    user = current_user()
    owner_clause, owner_params = owned_or_public_clause(user)
    with db() as con:
        if not con.execute(f"SELECT id FROM incidents WHERE id=? AND {owner_clause}", (incident_id, *owner_params)).fetchone():
            return jsonify({"error": "Incident not found."}), 404
        cur = con.execute("INSERT INTO incident_events(incident_id,event_text,event_time,severity) VALUES(?,?,?,?)",
                          (incident_id, event_text, event_time, severity))
    return jsonify({"id": cur.lastrowid, "message": "Timeline event added."}), 201

@app.post("/api/incident-evidence/<int:evidence_id>/verify")
def verify_incident_evidence(evidence_id):
    user = current_user()
    owner_clause, owner_params = owned_or_public_clause(user)
    with db() as con:
        row = con.execute(f"SELECT ie.* FROM incident_evidence ie JOIN incidents i ON i.id=ie.incident_id WHERE ie.id=? AND i.{owner_clause}", (evidence_id, *owner_params)).fetchone()
    if not row:
        return jsonify({"error": "Evidence not found."}), 404
    path = UPLOAD_DIR / row["stored_name"]
    if not path.exists():
        return jsonify({"verified": False, "error": "Evidence file is missing."}), 404
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    return jsonify({"verified": hmac.compare_digest(actual, row["sha256"]), "recorded_sha256": row["sha256"], "current_sha256": actual})

@app.get("/api/incident-evidence/<int:evidence_id>/download")
def download_incident_evidence(evidence_id):
    user = current_user()
    owner_clause, owner_params = owned_or_public_clause(user)
    with db() as con:
        row = con.execute(f"SELECT ie.* FROM incident_evidence ie JOIN incidents i ON i.id=ie.incident_id WHERE ie.id=? AND i.{owner_clause}", (evidence_id, *owner_params)).fetchone()
    if not row:
        abort(404)
    path = UPLOAD_DIR / row["stored_name"]
    if not path.exists():
        abort(404)
    return send_file(path, as_attachment=True, download_name=row["original_name"], mimetype="application/octet-stream")

@app.get("/api/incidents/<int:incident_id>/report.pdf")
def incident_report_pdf(incident_id):
    user = current_user()
    owner_clause, owner_params = owned_or_public_clause(user)
    with db() as con:
        incident = con.execute(f"SELECT * FROM incidents WHERE id=? AND {owner_clause}", (incident_id, *owner_params)).fetchone()
        if not incident:
            return jsonify({"error": "Incident not found."}), 404
        evidence = con.execute("SELECT * FROM incident_evidence WHERE incident_id=? ORDER BY id", (incident_id,)).fetchall()
        events = con.execute("SELECT * FROM incident_events WHERE incident_id=? ORDER BY event_time", (incident_id,)).fetchall()
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
    except ImportError:
        return jsonify({"error": "Install reportlab to generate PDFs."}), 501
    output = io.BytesIO(); styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="SmallScamShield", parent=styles["BodyText"], fontSize=8, leading=10, wordWrap="CJK"))
    story = [Paragraph("ScamShield + ScamSathi — Incident Report", styles["Title"]),
             Paragraph("Educational first-response summary; not a legal finding or definitive scam verdict.", styles["SmallScamShield"]), Spacer(1, 10),
             Paragraph(f"<b>Incident #{incident_id}: {secure_filename(incident['title'])}</b>", styles["Heading2"]),
             Paragraph(f"Type: {incident['incident_type']} | Created: {incident['created_at']}", styles["BodyText"]),
             Paragraph(f"Heuristic score: {incident['analysis_score']}/100 ({incident['analysis_level']})", styles["BodyText"]), Spacer(1, 8),
             Paragraph("Description", styles["Heading3"]), Paragraph(str(incident["description"]).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\n","<br/>"), styles["BodyText"]), Spacer(1, 8), Paragraph("Evidence inventory", styles["Heading3"])]
    if evidence:
        data = [["File", "Size", "SHA-256", "Added"]]
        for e in evidence:
            data.append([Paragraph(e["original_name"].replace("&","&amp;").replace("<","&lt;"), styles["SmallScamShield"]), str(e["size_bytes"]), Paragraph(e["sha256"], styles["SmallScamShield"]), e["added_at"]])
        table = Table(data, colWidths=[38*mm, 18*mm, 77*mm, 30*mm], repeatRows=1)
        table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#14213d")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),0.35,colors.grey),("VALIGN",(0,0),(-1,-1),"TOP"),("FONTSIZE",(0,0),(-1,-1),7)]))
        story.append(table)
    else: story.append(Paragraph("No evidence attached.", styles["BodyText"]))
    story += [Spacer(1, 8), Paragraph("Incident timeline", styles["Heading3"])]
    for event in events:
        story.append(Paragraph(f"{event['event_time']}: {event['event_text']}", styles["SmallScamShield"]))
    story += [Spacer(1, 10), Paragraph("Limitations", styles["Heading3"]), Paragraph("A heuristic score does not prove maliciousness or safety. SHA-256 matching detects byte changes relative to the recorded digest but does not establish source authenticity or legal chain of custody.", styles["SmallScamShield"])]
    SimpleDocTemplate(output, pagesize=A4, rightMargin=18*mm, leftMargin=18*mm, topMargin=16*mm, bottomMargin=16*mm).build(story)
    output.seek(0)
    return send_file(output, mimetype="application/pdf", as_attachment=True, download_name=f"scamshield-incident-{incident_id}.pdf")

@app.errorhandler(413)
def too_large(_):
    return jsonify({"error": "Upload exceeds the configured size limit."}), 413

@app.errorhandler(404)
def not_found(_):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Resource not found."}), 404
    return "Page not found", 404

if __name__ == "__main__":
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "5000")), debug=os.getenv("FLASK_DEBUG", "0") == "1")
