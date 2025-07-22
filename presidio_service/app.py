"""
Flask application for the Presidio anonymization microservice.
"""
from flask import Flask, request, jsonify
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine, OperatorConfig

app = Flask(__name__)

# Initialize Presidio engines once at startup
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

@app.get("/health")
def health():
    """Health check endpoint."""
    return jsonify({"status": "ok"}), 200

@app.post("/anonymize")
def anonymize():
    """
    Anonymize PII in the provided text.
    Request JSON: {"text": "..."}
    Response JSON: {"text": "..."}
    """
    data = request.get_json(force=True)
    if not data or "text" not in data:
        return jsonify({"error": "Missing 'text' field in JSON body."}), 400

    text = data["text"]
    # Analyze text for PII
    results = analyzer.analyze(text=text, language="en")

    # Anonymize using default operator: replace all PII with '<PII>'
    # Build operator configs for anonymization
    operators = {
        "DEFAULT": OperatorConfig(
            operator_name="replace",
            params={"new_value": "<PII>"},
        )
    }
    anonymized = anonymizer.anonymize(
        text=text,
        analyzer_results=results,
        operators=operators,
    )

    return jsonify({"text": anonymized.text}), 200

if __name__ == "__main__":
    # For local development/testing only; use Gunicorn in production
    app.run(host="0.0.0.0", port=8001)