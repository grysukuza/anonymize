"""
Console script for the anonymize_data package.
"""
from .core import anonymize_medical_text

DEFAULT_TEXT = (
    "Patient John Smith, born on 01/02/1980, resides at 123 Main St. "
    "Contact number: 555-123-4567. Email: john.smith@example.com. "
    "Medical record number: MRN123459."
    "Social Security Number: 126-48-6789. "
    "He was treated at St. Mary's Hospital and then at Northwestern Memorial Hospital for a severe headache. "
)

def main():
    anonymized = anonymize_medical_text(DEFAULT_TEXT)
    print("Original Text:")
    print(DEFAULT_TEXT)
    print("\nAnonymized Text:")
    print(anonymized)

if __name__ == "__main__":
    main()