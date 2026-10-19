"""
Flask application for the Presidio anonymization microservice.
"""
import hmac
import os
import re
import secrets
import sys
from pathlib import Path

from flask import Flask, request, jsonify, render_template, session
from presidio_anonymizer.entities import OperatorConfig

try:
    from anonymize_data.core import get_analyzer, get_anonymizer
    from anonymize_data.openmed_tools import DEIDENTIFY_METHODS, deidentify, extract_pii
except ModuleNotFoundError:
    # Running from presidio_service/ without the package installed: the
    # repository root (one level up) holds anonymize_data/.
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from anonymize_data.core import get_analyzer, get_anonymizer
    from anonymize_data.openmed_tools import DEIDENTIFY_METHODS, deidentify, extract_pii

app = Flask(__name__)
# Sessions survive restarts only when SESSION_SECRET is set; the random
# fallback keeps the demo safe to expose without a hardcoded key.
app.secret_key = os.environ.get("SESSION_SECRET") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

# Simple demo credentials for local usage; override via environment.
VALID_USERS = {
    os.environ.get("ANONYMIZE_USERNAME", "admin"): os.environ.get(
        "ANONYMIZE_PASSWORD", "anonymize123"
    ),
}

# Warm the shared engines at import time so the first request doesn't pay the
# spaCy model load. Both the /anonymize and /pii/* routes use this same pair.
analyzer = get_analyzer()
anonymizer = get_anonymizer()


def _is_logged_in() -> bool:
    return bool(session.get("authenticated"))


def _get_json() -> dict | None:
    """Parse the request body as JSON, returning None when it is invalid."""
    data = request.get_json(force=True, silent=True)
    return data if isinstance(data, dict) else None


def _parse_int(value, default: int = 0) -> int | None:
    """Coerce a JSON value to int, returning None when it cannot be."""
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _adjust_numbers(text: str, delta: int) -> str:
    if delta == 0:
        return text

    def replace_number(match: re.Match) -> str:
        return str(int(match.group(0)) + delta)

    return re.sub(r"\d+", replace_number, text)


def _remove_unusual_words(text: str) -> str:
    words = text.split()
    filtered = []
    for word in words:
        normalized = re.sub(r"[^A-Za-z]", "", word)
        if normalized and len(normalized) > 14:
            continue
        if re.search(r"[^\w\s.,!?;:'\"()\-]", word):
            continue
        filtered.append(word)
    return " ".join(filtered)


@app.get("/")
def index():
    """Serve the web UI for text anonymization."""
    return render_template("index.html", logged_in=_is_logged_in())


@app.get("/health")
def health():
    """Health check endpoint."""
    return jsonify({"status": "ok"}), 200


@app.post("/login")
def login():
    data = _get_json() or {}
    username = str(data.get("username", ""))
    password = str(data.get("password", ""))
    expected = VALID_USERS.get(username)
    if expected is not None and hmac.compare_digest(expected, password):
        session["authenticated"] = True
        session["username"] = username
        return jsonify({"status": "ok", "username": username}), 200
    return jsonify({"error": "Invalid username or password."}), 401


@app.post("/logout")
def logout():
    session.clear()
    return jsonify({"status": "ok"}), 200


@app.get("/session")
def session_state():
    return jsonify({"authenticated": _is_logged_in(), "username": session.get("username")}), 200


@app.post("/anonymize")
def anonymize():
    """
    Anonymize PII in the provided text.
    Request JSON: {"text": "...", "adjust_data": bool, "adjust_numbers": bool, "number_delta": int, "remove_unusual_words": bool}
    Response JSON: {"text": "..."}
    """
    if not _is_logged_in():
        return jsonify({"error": "Login required."}), 401

    data = _get_json()
    if data is None or "text" not in data:
        return jsonify({"error": "Missing 'text' field in JSON body."}), 400

    text = data["text"]
    if not isinstance(text, str):
        return jsonify({"error": "'text' must be a string."}), 400

    delta = _parse_int(data.get("number_delta"))
    if delta is None:
        return jsonify({"error": "'number_delta' must be an integer."}), 400

    # Analyze text for PII
    results = analyzer.analyze(text=text, language="en")

    # Build operator configs for anonymization
    replacement = "<PII_ADJUSTED>" if data.get("adjust_data") else "<PII>"
    operators = {
        "DEFAULT": OperatorConfig(
            operator_name="replace",
            params={"new_value": replacement},
        )
    }
    anonymized = anonymizer.anonymize(
        text=text,
        analyzer_results=results,
        operators=operators,
    ).text

    if data.get("adjust_numbers"):
        anonymized = _adjust_numbers(anonymized, delta)

    if data.get("remove_unusual_words"):
        anonymized = _remove_unusual_words(anonymized)

    return jsonify({"text": anonymized}), 200


@app.post("/pii/extract")
def pii_extract():
    """OpenMed-style PII extraction.

    Request JSON:  {"text": "...", "lang": "en"}
    Response JSON: {"entities": [{"label", "text", "start", "end", "score"}, ...]}
    """
    if not _is_logged_in():
        return jsonify({"error": "Login required."}), 401

    data = _get_json()
    if data is None or "text" not in data:
        return jsonify({"error": "Missing 'text' field in JSON body."}), 400
    if not isinstance(data["text"], str):
        return jsonify({"error": "'text' must be a string."}), 400

    entities = extract_pii(data["text"], lang=data.get("lang", "en"))
    return jsonify({"entities": [e.to_dict() for e in entities]}), 200


@app.post("/pii/deidentify")
def pii_deidentify():
    """OpenMed-style de-identification.

    Request JSON:  {"text": "...", "method": "mask|replace|hash|shift_dates",
                    "lang": "en", "date_shift_days": int}
    Response JSON: {"text": "...", "method": "..."}
    """
    if not _is_logged_in():
        return jsonify({"error": "Login required."}), 401

    data = _get_json()
    if data is None or "text" not in data:
        return jsonify({"error": "Missing 'text' field in JSON body."}), 400
    if not isinstance(data["text"], str):
        return jsonify({"error": "'text' must be a string."}), 400

    method = data.get("method", "mask")
    if method not in DEIDENTIFY_METHODS:
        return jsonify({
            "error": f"Invalid method. Choose one of: {', '.join(DEIDENTIFY_METHODS)}"
        }), 400

    shift_days = _parse_int(data.get("date_shift_days"))
    if shift_days is None:
        return jsonify({"error": "'date_shift_days' must be an integer."}), 400

    result = deidentify(
        data["text"],
        method=method,
        lang=data.get("lang", "en"),
        date_shift_days=shift_days,
    )
    return jsonify({"text": result, "method": method}), 200


if __name__ == "__main__":
    # For local development/testing only; use Gunicorn in production
    app.run(host="0.0.0.0", port=5000)
