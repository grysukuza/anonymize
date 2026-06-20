"""
Console script for the anonymize_data package.

Demonstrates both the original one-shot pipeline and the OpenMed-inspired
method-based de-identification toolkit.
"""
from .core import anonymize_medical_text
from .openmed_tools import deidentify, extract_pii

DEFAULT_TEXT = (
    "Patient John Smith, born on 01/02/1980, resides at 123 Main St. "
    "Contact number: 555-123-4567. Email: john.smith@example.com. "
    "Medical record number: MRN123459."
    "Social Security Number: 126-48-6789. "
    "He was treated at St. Mary's Hospital and then at Northwestern Memorial Hospital for a severe headache. "
)


def main():
    print("Original Text:")
    print(DEFAULT_TEXT)

    print("\n=== anonymize_medical_text (layered HIPAA pipeline) ===")
    print(anonymize_medical_text(DEFAULT_TEXT))

    print("\n=== extract_pii (structured detections) ===")
    for ent in extract_pii(DEFAULT_TEXT):
        print(f"  {ent.label:<28} {ent.text!r:<30} {ent.score:.2f}")

    print("\n=== deidentify methods (OpenMed-style) ===")
    for method in ("mask", "replace", "hash", "shift_dates"):
        kwargs = {"date_shift_days": 180} if method == "shift_dates" else {}
        print(f"\n[{method}]")
        print(deidentify(DEFAULT_TEXT, method=method, **kwargs))


if __name__ == "__main__":
    main()
