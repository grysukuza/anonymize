"""
Core functionality for the anonymize_data package.
"""
def anonymize_medical_text(text):
    """
    Anonymizes the given medical text by identifying and masking PII entities.

    :param text: The original text to be anonymized.
    :return: The anonymized text as a string.
    """
    from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
    from presidio_anonymizer import AnonymizerEngine
    from presidio_anonymizer.entities import OperatorConfig

    class HospitalRecognizer(PatternRecognizer):
        def __init__(self):
            patterns = [
                Pattern(
                    name="hospital_pattern",
                    regex=r"\b(?:General Hospital|St\. Mary's Hospital|City Clinic|Northwestern Memorial Hospital|University of Chicago)\b",
                    score=0.85,
                ),
            ]
            super().__init__(supported_entity="HOSPITAL", patterns=patterns)

    analyzer = AnalyzerEngine()
    anonymizer = AnonymizerEngine()
    hospital_recognizer = HospitalRecognizer()
    analyzer.registry.add_recognizer(hospital_recognizer)

    analyzer_results = analyzer.analyze(text=text, language="en")

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
        "CREDIT_CARD": OperatorConfig("replace", {"new_value": "XXXX-XXXX-XXXX-XXXX"}),
        "BANK_ACCOUNT": OperatorConfig("replace", {"new_value": "XXXX-XXXX-XXXX-XXXX"}),
        "BANK_ROUTING": OperatorConfig("replace", {"new_value": "XXXX-XXXX-XXXX-XXXX"}),
        "LICENSE_PLATE": OperatorConfig("replace", {"new_value": "XXXX-XXXX"}),
        "URL": OperatorConfig("replace", {"new_value": "<REDACTED_URL>"}),
        "IP_ADDRESS": OperatorConfig("replace", {"new_value": "<REDACTED_IP>"}),
        "CREDIT_CARD_NUMBER": OperatorConfig("replace", {"new_value": "<REDACTED_CREDIT_CARD>"}),
        "PASSPORT_NUMBER": OperatorConfig("replace", {"new_value": "<REDACTED_PASSPORT>"}),
        "EMAIL": OperatorConfig("replace", {"new_value": "<REDACTED_EMAIL>"}),    
    }

    result = anonymizer.anonymize(text=text, analyzer_results=analyzer_results, operators=operators)
    return result.text