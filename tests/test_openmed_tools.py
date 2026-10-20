"""Tests for the OpenMed-inspired PII toolkit.

Run with: ``pytest tests/test_openmed_tools.py``
(requires presidio + the ``en_core_web_lg`` spaCy model).
"""

import pytest
from presidio_analyzer import RecognizerResult

from anonymize_data import (
    BatchProcessor,
    PiiEntity,
    anonymize_medical_text,
    deidentify,
    extract_pii,
)

SAMPLE = "Patient John Smith, SSN 126-48-6789, phone 555-123-4567, born 01/02/1980."


def test_extract_pii_returns_structured_non_overlapping_entities():
    ents = extract_pii(SAMPLE)
    assert ents and all(isinstance(e, PiiEntity) for e in ents)
    # Sorted by start and disjoint.
    for a, b in zip(ents, ents[1:]):
        assert a.start <= b.start
        assert a.end <= b.start
    labels = {e.label for e in ents}
    assert {"PERSON", "US_SSN"} <= labels


def test_deidentify_mask_uses_label_placeholders():
    out = deidentify(SAMPLE, method="mask")
    assert "John Smith" not in out
    assert "[PERSON]" in out and "[US_SSN]" in out


def test_deidentify_replace_is_format_preserving_and_synthetic():
    out = deidentify(SAMPLE, method="replace", seed="t")
    assert "126-48-6789" not in out and "John Smith" not in out
    # SSN replaced with another SSN-shaped value, not a random word.
    import re

    assert re.search(r"\d{3}-\d{2}-\d{4}", out)


def test_deidentify_hash_is_deterministic_and_irreversible():
    a = deidentify(SAMPLE, method="hash")
    b = deidentify(SAMPLE, method="hash")
    assert a == b
    assert "John Smith" not in a and "126-48-6789" not in a


def test_deidentify_shift_dates_preserves_chronology():
    out = deidentify("Born 01/02/1980, John Smith.", method="shift_dates", date_shift_days=10)
    assert "01/12/1980" in out  # shifted by 10 days
    assert "John Smith" not in out  # non-date PII still removed


@pytest.mark.parametrize(
    ("text", "needle"),
    [
        ("Mailing ZIP 60614-3302 on file.", "60614"),
        ("A 93-year-old woman presented.", "93"),
        ("DOB 14.03.1957 per chart.", "14.03.1957"),
        ("Discharged on 3 March 2021.", "3 March 2021"),
    ],
)
def test_shift_dates_masks_unparseable_date_time(text, needle):
    out = deidentify(text, method="shift_dates", date_shift_days=30)
    assert needle not in out
    assert "[DATE_TIME]" in out


class _OrderedAnalyzer:
    def __init__(self, results):
        self._results = results

    def analyze(self, text, language):
        return list(self._results)


@pytest.mark.parametrize(
    "order",
    [("US_SSN", "DATE_TIME"), ("DATE_TIME", "US_SSN")],
)
def test_overlap_tie_prefers_pattern_recognizer(monkeypatch, order):
    text = "SSN 219-09-9931 verified."
    results = [
        RecognizerResult(entity_type=label, start=4, end=15, score=0.85) for label in order
    ]
    monkeypatch.setattr(
        "anonymize_data.openmed_tools.get_analyzer",
        lambda: _OrderedAnalyzer(results),
    )
    assert [e.label for e in extract_pii(text)] == ["US_SSN"]
    assert deidentify(text, method="mask") == "SSN [US_SSN] verified."


def test_batch_processor_preserves_order_and_count():
    texts = [SAMPLE, "Email jane.doe@example.com", "No PII here at all."]

    deid = BatchProcessor(operation="deidentify", method="mask", batch_size=2)
    masked = deid.process_texts(texts)
    assert len(masked) == 3
    assert "[PERSON]" in masked[0]
    assert masked[2] == texts[2]  # untouched

    extract = BatchProcessor(operation="extract_pii")
    found = extract.process_texts(texts)
    assert len(found) == 3 and all(isinstance(x, list) for x in found)


@pytest.mark.parametrize("operation", ["deidentify", "extract_pii"])
def test_batch_processor_rejects_bare_string(operation):
    processor = BatchProcessor(operation=operation)
    with pytest.raises(TypeError):
        processor.process_texts("Contact Zelda Quintrell today.")


def test_batch_processor_accepts_generators():
    masked = BatchProcessor(operation="deidentify", method="mask", batch_size=2).process_texts(
        t for t in [SAMPLE, "No PII here at all."]
    )
    assert len(masked) == 2 and "[PERSON]" in masked[0]


def test_anonymize_medical_text_uses_specific_ssn_operator():
    out = anonymize_medical_text(SAMPLE)
    assert "126-48-6789" not in out
    # US_SSN must hit its dedicated operator, not fall through to <REDACTED>.
    assert "XXX-XX-XXXX" in out
