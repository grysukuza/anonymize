# Anonymize Data — Presidio Microservice

## Overview

A Python project with two components:

1. **`presidio_service/`** — A Flask REST API microservice that anonymizes PII in text using Microsoft Presidio. Runs on port 8000.
2. **`anonymize_data/`** — A Python package for medical text anonymization with custom entity recognizers (hospitals, SSNs, etc.).

## Architecture

- **Runtime**: Python 3.11
- **Framework**: Flask
- **NLP backend**: spaCy (`en_core_web_lg` model) via Presidio Analyzer
- **Anonymization**: Microsoft Presidio Analyzer + Anonymizer

## API Endpoints

- `GET /health` — Health check, returns `{"status": "ok"}`
- `POST /anonymize` — Accepts `{"text": "..."}`, returns `{"text": "..."}` with PII replaced by `<PII>`

## Running the Service

The workflow runs: `cd presidio_service && python app.py` on port 8000.

## Key Files

- `presidio_service/app.py` — Flask application entry point
- `anonymize_data/core.py` — Medical text anonymization with custom operators
- `anonymize_data/__main__.py` — CLI demo script (`python -m anonymize_data`)
- `setup.py` — Package setup for `anonymize_data`
- `Pipfile` — Project dependencies

## Dependencies

Installed via pip: `flask`, `gunicorn`, `presidio-analyzer`, `presidio-anonymizer`, `openai`, `pydantic`, `instructor`, `spacy` + `en_core_web_lg` model.
