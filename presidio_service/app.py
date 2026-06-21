"""
Flask application for the Presidio anonymization microservice.
"""
import re
from flask import Flask, request, jsonify, render_template, session
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine, OperatorConfig

from anonymize_data.openmed_tools import DEIDENTIFY_METHODS, deidentify, extract_pii

app = Flask(__name__)
app.secret_key = "change-me-in-production"

# Simple demo credentials for local usage.
VALID_USERS = {
    "admin": "anonymize123",
}

# Initialize Presidio engines once at startup
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()


def _is_logged_in() -> bool:
    return bool(session.get("authenticated"))


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
    data = request.get_json(force=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    if VALID_USERS.get(username) == password:
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

    data = request.get_json(force=True)
    if not data or "text" not in data:
        return jsonify({"error": "Missing 'text' field in JSON body."}), 400

    text = data["text"]

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
        delta = int(data.get("number_delta", 0))
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

    data = request.get_json(force=True) or {}
    if "text" not in data:
        return jsonify({"error": "Missing 'text' field in JSON body."}), 400

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

    data = request.get_json(force=True) or {}
    if "text" not in data:
        return jsonify({"error": "Missing 'text' field in JSON body."}), 400

    method = data.get("method", "mask")
    if method not in DEIDENTIFY_METHODS:
        return jsonify({
            "error": f"Invalid method. Choose one of: {', '.join(DEIDENTIFY_METHODS)}"
        }), 400

    result = deidentify(
        data["text"],
        method=method,
        lang=data.get("lang", "en"),
        date_shift_days=int(data.get("date_shift_days", 0)),
    )
    return jsonify({"text": result, "method": method}), 200


if __name__ == "__main__":
    # For local development/testing only; use Gunicorn in production
    app.run(host="0.0.0.0", port=5000)
