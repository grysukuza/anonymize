from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from presidio_analyzer import PatternRecognizer, Pattern



class HospitalRecognizer(PatternRecognizer):
    def __init__(self):
        patterns = [
            Pattern(name="hospital_pattern", regex=r"\b(?:General Hospital|St\. Mary's Hospital|City Clinic|Northwestern Memorial Hospital|University of Chicago)\b", score=0.85),
            # Add more patterns as needed
        ]
        super().__init__(supported_entity="HOSPITAL", patterns=patterns)


# Initialize the Presidio Analyzer and Anonymizer engines
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

# Register the custom recognizer for hospital names
hospital_recognizer = HospitalRecognizer()
analyzer.registry.add_recognizer(hospital_recognizer)

# Define the text to be anonymized
text = (
    "Patient John Smith, born on 01/02/1980, resides at 123 Main St. "
    "Contact number: 555-123-4567. Email: john.smith@example.com. "
    "Medical record number: MRN123459."
    "Social Security Number: 126-48-6789. "
    "He was treated at St. Mary's Hospital and then at Northwestern Memorial Hospital for a severe headache. "
)

# Analyze the text to identify PII entities
analyzer_results = analyzer.analyze(text=text, language="en")

# Define anonymization operators for different PII entity types
operators = {
    "DEFAULT": OperatorConfig("replace", {"new_value": "<REDACTED>"}),
    "PHONE_NUMBER": OperatorConfig("mask", {"masking_char": "*", "chars_to_mask": 4, "from_end": True}),
    "EMAIL_ADDRESS": OperatorConfig("redact", {}),
    "PERSON": OperatorConfig("replace", {"new_value": "Patient"}),
    "DATE_TIME": OperatorConfig("replace", {"new_value": "01/01/1900"}),
    "LOCATION": OperatorConfig("replace", {"new_value": "Unknown"}),
    "US_SOCIAL_SECURITY_NUMBER": OperatorConfig("replace", {"new_value": "XXX-XX-XXXX"}),
    "MEDICAL_RECORD_NUMBER": OperatorConfig("replace", {"new_value": "MRNXXXXXX"}),
    "HOSPITAL": OperatorConfig("replace", {"new_value": "<REDACTED_HOSPITAL>"}),
}

# Anonymize the text based on the analyzer results and defined operators

def anonymize_medical_text(text):
    """
    Anonymizes the given text based on the analyzer results and specified operators.
    
    :param text: The original text to be anonymized.
    :param analyzer_results: The results from the analyzer containing identified PII entities.
    :param operators: A dictionary of operators for different PII entity types.
    :return: The anonymized text.
    """
    # Anonymize the text using the defined operators
    anonymized_result = anonymizer.anonymize(
        text=text,
        analyzer_results=analyzer_results,
        operators=operators
    )
    
    return anonymized_result

if __name__ == "__main__":
    # Anonymize the text
    anonymized_result = anonymize_medical_text(text)
    
    # Print the original and anonymized text
    print("Original Text:")
    print(text)
    print("\nAnonymized Text:")
    print(anonymized_result.text)