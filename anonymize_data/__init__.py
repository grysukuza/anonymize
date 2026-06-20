"""
anonymize_data package for medical text anonymization.

Two complementary APIs are available:

- ``anonymize_medical_text`` (from ``core``): a one-shot, HIPAA-oriented
  pipeline (NER + date shifting + rare-disease suppression).
- An OpenMed-inspired toolkit (from ``openmed_tools``): structured
  ``extract_pii``, a method-based ``deidentify`` (mask/replace/hash/shift_dates),
  and a ``BatchProcessor`` for high-throughput processing.
"""

from .core import anonymize_medical_text, build_analyzer
from .openmed_tools import (
    BatchProcessor,
    PiiEntity,
    deidentify,
    extract_pii,
)

__all__ = [
    "anonymize_medical_text",
    "build_analyzer",
    "extract_pii",
    "deidentify",
    "BatchProcessor",
    "PiiEntity",
]

__version__ = "0.2.0"
