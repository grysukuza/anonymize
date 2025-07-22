from setuptools import setup, find_packages

setup(
    name="anonymize_data",
    version="0.1.0",
    packages=find_packages(),
    extras_require={
        "anonymization": [
            "presidio-analyzer",
            "presidio-anonymizer",
        ],
    },
    entry_points={
        "console_scripts": [
            "anonymize-data=anonymize_data.__main__:main",
        ],
    },
)