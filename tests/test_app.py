"""API tests for the Flask microservice.

Run with: ``pytest tests/test_app.py``
(requires presidio + the ``en_core_web_lg`` spaCy model).
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "presidio_service"))

from app import app  # noqa: E402

SAMPLE = "Patient John Smith, SSN 126-48-6789, phone 555-123-4567, born 01/02/1980."


@pytest.fixture()
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


@pytest.fixture()
def logged_in(client):
    res = client.post("/login", json={"username": "admin", "password": "anonymize123"})
    assert res.status_code == 200
    return client


def test_health(client):
    res = client.get("/health")
    assert res.status_code == 200
    assert res.get_json() == {"status": "ok"}


def test_index_serves_ui(client):
    res = client.get("/")
    assert res.status_code == 200
    assert b"Text Anonymizer" in res.data


def test_login_rejects_bad_credentials(client):
    res = client.post("/login", json={"username": "admin", "password": "wrong"})
    assert res.status_code == 401
    res = client.post("/login", json={"username": "ghost", "password": "anonymize123"})
    assert res.status_code == 401


def test_login_logout_roundtrip(client):
    assert client.get("/session").get_json()["authenticated"] is False
    client.post("/login", json={"username": "admin", "password": "anonymize123"})
    state = client.get("/session").get_json()
    assert state == {"authenticated": True, "username": "admin"}
    client.post("/logout")
    assert client.get("/session").get_json()["authenticated"] is False


@pytest.mark.parametrize("path", ["/anonymize", "/pii/extract", "/pii/deidentify"])
def test_endpoints_require_login(client, path):
    res = client.post(path, json={"text": SAMPLE})
    assert res.status_code == 401


def test_anonymize_masks_pii(logged_in):
    res = logged_in.post("/anonymize", json={"text": SAMPLE})
    assert res.status_code == 200
    out = res.get_json()["text"]
    assert "John Smith" not in out
    assert "126-48-6789" not in out
    assert "<PII>" in out


def test_anonymize_validates_body(logged_in):
    assert logged_in.post("/anonymize", json={}).status_code == 400
    assert logged_in.post(
        "/anonymize", data="not json", content_type="application/json"
    ).status_code == 400
    assert logged_in.post("/anonymize", json={"text": 42}).status_code == 400
    res = logged_in.post(
        "/anonymize", json={"text": SAMPLE, "adjust_numbers": True, "number_delta": "abc"}
    )
    assert res.status_code == 400


def test_anonymize_number_adjustment(logged_in):
    res = logged_in.post(
        "/anonymize",
        json={"text": "Dosage 10 mg", "adjust_numbers": True, "number_delta": 5},
    )
    assert res.status_code == 200
    assert "15" in res.get_json()["text"]


def test_pii_extract_returns_entities(logged_in):
    res = logged_in.post("/pii/extract", json={"text": SAMPLE})
    assert res.status_code == 200
    entities = res.get_json()["entities"]
    assert entities
    labels = {e["label"] for e in entities}
    assert "PERSON" in labels and "US_SSN" in labels
    for ent in entities:
        assert set(ent) == {"label", "text", "start", "end", "score"}


def test_pii_deidentify_mask(logged_in):
    res = logged_in.post("/pii/deidentify", json={"text": SAMPLE, "method": "mask"})
    assert res.status_code == 200
    body = res.get_json()
    assert body["method"] == "mask"
    assert "John Smith" not in body["text"]
    assert "[PERSON]" in body["text"]


def test_pii_deidentify_rejects_bad_input(logged_in):
    res = logged_in.post("/pii/deidentify", json={"text": SAMPLE, "method": "nope"})
    assert res.status_code == 400
    res = logged_in.post(
        "/pii/deidentify",
        json={"text": SAMPLE, "method": "shift_dates", "date_shift_days": "many"},
    )
    assert res.status_code == 400


def test_pii_deidentify_shift_dates(logged_in):
    res = logged_in.post(
        "/pii/deidentify",
        json={"text": "Born 01/02/1980, John Smith.", "method": "shift_dates", "date_shift_days": 10},
    )
    assert res.status_code == 200
    assert "01/12/1980" in res.get_json()["text"]
