"""Core functionality for HIPAA-oriented medical text anonymization."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import random
import re
from typing import Iterable

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig


# Heuristic pattern list for very rare/traceable conditions; remove from output.
RARE_DISEASE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bprogeria\b", re.IGNORECASE),
    re.compile(r"\bfatal familial insomnia\b", re.IGNORECASE),
    re.compile(r"\bkuru\b", re.IGNORECASE),
    re.compile(r"\bparaneoplastic pemphigus\b", re.IGNORECASE),
    re.compile(r"\bgerstmann[- ]str[aä]ussler[- ]scheinker\b", re.IGNORECASE),
    re.compile(r"\bcreutzfeldt[- ]jakob\b", re.IGNORECASE),
)


@dataclass(frozen=True)
class _DateShiftConfig:
    seed: str
    min_days: int = -30
    max_days: int = 30


class HospitalRecognizer(PatternRecognizer):
    def __init__(self) -> None:
        patterns = [
            Pattern(
                name="hospital_pattern",
                regex=r"\b(?:General Hospital|St\. Mary's Hospital|City Clinic|Northwestern Memorial Hospital|University of Chicago)\b",
                score=0.85,
            )
        ]
        super().__init__(supported_entity="HOSPITAL", patterns=patterns)


class MedicalRecordRecognizer(PatternRecognizer):
    def __init__(self) -> None:
        patterns = [
            Pattern(
                name="mrn_pattern",
                regex=r"\b(?:MRN|Medical Record Number)[:#\s-]*[A-Z0-9]{6,12}\b",
                score=0.9,
            )
        ]
        super().__init__(supported_entity="MEDICAL_RECORD_NUMBER", patterns=patterns)


def _remove_rare_disease_terms(text: str) -> str:
    cleaned = text
    for pattern in RARE_DISEASE_PATTERNS:
        cleaned = pattern.sub("[CONDITION_REDACTED]", cleaned)
    return cleaned


def _shift_dates(text: str, config: _DateShiftConfig) -> str:
    """Apply deterministic date shifting to reduce linkage risk while keeping chronology."""

    rng = random.Random(int(hashlib.sha256(config.seed.encode("utf-8")).hexdigest(), 16))
    shift_days = rng.randint(config.min_days, config.max_days)

    def _replace(match: re.Match[str]) -> str:
        raw = match.group(0)
        for fmt in ("%m/%d/%Y", "%m/%d/%y", "%Y-%m-%d"):
            try:
                parsed = datetime.strptime(raw, fmt)
                shifted = parsed + timedelta(days=shift_days)
                return shifted.strftime(fmt)
            except ValueError:
                continue
        return raw

    return re.sub(r"\b(?:\d{1,2}/\d{1,2}/\d{2,4}|\d{4}-\d{2}-\d{2})\b", _replace, text)


def _build_operators() -> dict[str, OperatorConfig]:
    return {
        "DEFAULT": OperatorConfig("replace", {"new_value": "<REDACTED>"}),
        "PHONE_NUMBER": OperatorConfig("mask", {"masking_char": "*", "chars_to_mask": 4, "from_end": True}),
        "EMAIL_ADDRESS": OperatorConfig("redact", {}),
        "PERSON": OperatorConfig("replace", {"new_value": "Patient"}),
        "DATE_TIME": OperatorConfig("replace", {"new_value": "[DATE_SHIFTED]"}),
        "LOCATION": OperatorConfig("replace", {"new_value": "[REGION_REDACTED]"}),
        "US_SOCIAL_SECURITY_NUMBER": OperatorConfig("replace", {"new_value": "XXX-XX-XXXX"}),
        "MEDICAL_RECORD_NUMBER": OperatorConfig("replace", {"new_value": "MRNXXXXXX"}),
        "HOSPITAL": OperatorConfig("replace", {"new_value": "[FACILITY_REDACTED]"}),
        "CREDIT_CARD": OperatorConfig("replace", {"new_value": "XXXX-XXXX-XXXX-XXXX"}),
        "BANK_ACCOUNT": OperatorConfig("replace", {"new_value": "XXXX-XXXX-XXXX-XXXX"}),
        "BANK_ROUTING": OperatorConfig("replace", {"new_value": "XXXXXXXXX"}),
        "LICENSE_PLATE": OperatorConfig("replace", {"new_value": "[LICENSE_REDACTED]"}),
        "URL": OperatorConfig("replace", {"new_value": "[URL_REDACTED]"}),
        "IP_ADDRESS": OperatorConfig("replace", {"new_value": "[IP_REDACTED]"}),
        "PASSPORT_NUMBER": OperatorConfig("replace", {"new_value": "[PASSPORT_REDACTED]"}),
    }


def _register_custom_recognizers(analyzer: AnalyzerEngine) -> None:
    for recognizer in (HospitalRecognizer(), MedicalRecordRecognizer()):
        analyzer.registry.add_recognizer(recognizer)


def build_analyzer() -> AnalyzerEngine:
    """Build an AnalyzerEngine with the project's custom medical recognizers registered."""
    analyzer = AnalyzerEngine()
    _register_custom_recognizers(analyzer)
    return analyzer


def anonymize_medical_text(text: str, *, patient_scope_seed: str = "default") -> str:
    """
    Apply layered anonymization strategies aligned with HIPAA safe-harbor goals.

    Techniques used:
    1. Presidio NER + pattern recognizers for direct identifiers.
    2. Deterministic date shifting (small data distortion preserving sequence utility).
    3. Rare disease redaction for quasi-identifier suppression.
    """
    analyzer = build_analyzer()
    anonymizer = AnonymizerEngine()

    preprocessed_text = _remove_rare_disease_terms(text)
    preprocessed_text = _shift_dates(preprocessed_text, _DateShiftConfig(seed=patient_scope_seed))

    analyzer_results = analyzer.analyze(text=preprocessed_text, language="en")
    result = anonymizer.anonymize(
        text=preprocessed_text,
        analyzer_results=analyzer_results,
        operators=_build_operators(),
    )
    return result.text
