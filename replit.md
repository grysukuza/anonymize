# Anonymize Data — Presidio Microservice

## Overview

A Python project with two components:

1. **`presidio_service/`** — A Flask app that serves a web UI plus a REST API for anonymizing PII in text using Microsoft Presidio. Runs on port 5000.
2. **`anonymize_data/`** — A Python package for medical text anonymization with custom entity recognizers (hospitals, SSNs, etc.), plus an OpenMed-inspired PII toolkit (`openmed_tools.py`).

## Architecture

- **Runtime**: Python 3.11
- **Framework**: Flask
- **NLP backend**: spaCy (`en_core_web_lg` model) via Presidio Analyzer
- **Anonymization**: Microsoft Presidio Analyzer + Anonymizer

## Routes

- `GET /` — Web UI (HTML page with two-panel input/output for trying anonymization in the browser)
- `GET /health` — Health check, returns `{"status": "ok"}`
- `POST /anonymize` — Accepts `{"text": "..."}`, returns `{"text": "..."}` with PII replaced by `<PII>`
- `POST /pii/extract` — OpenMed-style PII detection; returns structured entities `{label, text, start, end, score}`
- `POST /pii/deidentify` — OpenMed-style de-identification via `mask` / `replace` / `hash` / `shift_dates`

## OpenMed-Inspired Toolkit (`anonymize_data/openmed_tools.py`)

Ports the ergonomic API of [`maziyarpanahi/openmed`](https://github.com/maziyarpanahi/openmed)
onto the Presidio backend (no heavy ML models required):

- `extract_pii(text, lang=, use_smart_merging=)` — returns a list of `PiiEntity`
  (`label`, `text`, `start`, `end`, `score`). Smart merging reassembles fragmented
  same-label spans and resolves cross-label overlaps.
- `deidentify(text, method=)` — four strategies: `mask` (`[LABEL]`),
  `replace` (Faker-backed, format-preserving synthetic data), `hash`
  (deterministic one-way tokens), `shift_dates` (offset dates by `date_shift_days`,
  mask the rest).
- `BatchProcessor(operation=, method=, batch_size=)` — runs extract/deidentify
  over many documents in memory-bounded chunks.

Run the demo: `python -m anonymize_data`.

## Running the Service

The workflow runs: `cd presidio_service && python app.py` on port 5000.
Production deployment uses Gunicorn on the same port.

## Key Files

- `presidio_service/app.py` — Flask application entry point (web UI + JSON API)
- `presidio_service/templates/index.html` — Web UI (vanilla HTML/CSS/JS)
- `anonymize_data/core.py` — Medical text anonymization with custom operators
- `anonymize_data/openmed_tools.py` — OpenMed-inspired `extract_pii` / `deidentify` / `BatchProcessor`
- `anonymize_data/__main__.py` — CLI demo script (`python -m anonymize_data`)
- `setup.py` — Package setup for `anonymize_data`
- `Pipfile` — Project dependencies

## Dependencies

Installed via pip: `flask`, `gunicorn`, `presidio-analyzer`, `presidio-anonymizer`, `openai`, `pydantic`, `instructor`, `faker`, `spacy` + `en_core_web_lg` model.
