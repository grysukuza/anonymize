"""Tests for the OpenMed-inspired PII toolkit.

Run with: ``pytest tests/test_openmed_tools.py``
(requires presidio + the ``en_core_web_lg`` spaCy model).
"""

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


def test_resolve_overlaps_keeps_union_of_regions():
    from anonymize_data.openmed_tools import _resolve_overlaps

    text = "Patient John Smith"
    ents = [
        PiiEntity("PERSON", "John Smith", 8, 18, 0.85),
        PiiEntity("OTHER", "John", 8, 12, 0.95),
    ]
    [merged] = _resolve_overlaps(ents, text)
    # The higher-scoring span names the label, but coverage must not shrink.
    assert (merged.start, merged.end, merged.text) == (8, 18, "John Smith")
    assert merged.label == "OTHER"


def test_shift_dates_masks_unparseable_dates():
    out = deidentify("Born on the 2nd of January 1980.", method="shift_dates", date_shift_days=10)
    assert "1980" not in out


def test_shift_dates_handles_month_name_formats():
    out = deidentify("Seen on 2 January 1980.", method="shift_dates", date_shift_days=10)
    assert "12 January 1980" in out


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


def test_hash_tokens_are_keyed_and_128_bit():
    from anonymize_data.openmed_tools import _hash_token

    # These two SSNs collided under the old 32-bit public-salt scheme.
    a = _hash_token("126-04-6628", "US_SSN", b"k")
    b = _hash_token("126-10-6161", "US_SSN", b"k")
    assert a != b
    assert len(a) == len("[US_SSN_]") + 32
    # A different key gives a different token, so tokens can't be precomputed.
    assert _hash_token("126-04-6628", "US_SSN", b"other") != a


def test_hash_key_argument_controls_tokens():
    one = deidentify(SAMPLE, method="hash", hash_key="alpha")
    assert one == deidentify(SAMPLE, method="hash", hash_key="alpha")
    assert one != deidentify(SAMPLE, method="hash", hash_key="beta")


def test_shift_dates_without_offset_masks_dates():
    out = deidentify("Born 01/02/1980, John Smith.", method="shift_dates")
    assert "01/02/1980" not in out
    assert "[DATE_TIME]" in out


def test_adjacent_dates_stay_independently_shiftable():
    out = deidentify("Visits:\n01/02/1980\n01/12/1980", method="shift_dates", date_shift_days=1)
    assert "01/03/1980" in out and "01/13/1980" in out


def test_shift_dates_masks_on_overflow():
    out = deidentify("Expires 12/31/9999.", method="shift_dates", date_shift_days=1)
    assert "9999" not in out


def test_replace_preserves_date_and_card_formats():
    import re

    out = deidentify("Seen 2024-03-15 by John Smith", method="replace")
    assert re.search(r"\d{4}-\d{2}-\d{2}", out) and "2024-03-15" not in out

    from anonymize_data.openmed_tools import _preserve_digit_layout

    assert _preserve_digit_layout("4111-1111-1111-1111", "5500005555555559") == "5500-0055-5555-5559"


def test_fake_value_is_deterministic_across_threads():
    from concurrent.futures import ThreadPoolExecutor

    expected = deidentify(SAMPLE, method="replace", seed="t")
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: deidentify(SAMPLE, method="replace", seed="t"), range(32)))
    assert all(r == expected for r in results)


def test_iter_texts_streams_results():
    processor = BatchProcessor(operation="deidentify", method="mask", batch_size=1)
    stream = processor.iter_texts(t for t in [SAMPLE, "No PII here at all."])
    assert "[PERSON]" in next(stream)
    assert next(stream) == "No PII here at all."
