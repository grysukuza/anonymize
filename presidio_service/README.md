# Presidio Anonymization Microservice

This microservice provides a REST API for anonymizing text using Microsoft Presidio.

## Setup

Requirements:
- Python 3.11+
- pip

```bash
git clone <your-repo-url>
cd <your-repo>/presidio_service
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python -m spacy download en_core_web_lg
```

## Running the Service

For development/testing:
```bash
python app.py
```

In production (with Gunicorn):
```bash
gunicorn -w 2 -b 0.0.0.0:5000 app:app
```

## Web UI

Open `http://localhost:5000/` in a browser to use the interactive web interface
for anonymizing text.

## API

### Health Check
GET /health

Response:
```json
{ "status": "ok" }
```

### Anonymize Text
POST /anonymize

Request JSON:
```json
{ "text": "Patient John Smith was seen at St. Mary's Hospital." }
```

Response JSON:
```json
{ "text": "<PII>" }
```

### OpenMed-style PII Endpoints

These endpoints mirror the API surface of
[`maziyarpanahi/openmed`](https://github.com/maziyarpanahi/openmed),
backed here by Presidio. Both require an authenticated session (`POST /login`).

#### Extract PII
POST /pii/extract

Request JSON:
```json
{ "text": "Patient John Smith, SSN 126-48-6789", "lang": "en" }
```

Response JSON:
```json
{ "entities": [
  { "label": "PERSON", "text": "John Smith", "start": 8, "end": 18, "score": 0.85 },
  { "label": "US_SSN", "text": "126-48-6789", "start": 24, "end": 35, "score": 0.85 }
] }
```

#### De-identify
POST /pii/deidentify

Request JSON (`method` is one of `mask`, `replace`, `hash`, `shift_dates`):
```json
{ "text": "John Smith born 01/02/1980", "method": "shift_dates", "date_shift_days": 180 }
```

Response JSON:
```json
{ "text": "[PERSON] born 06/30/1980", "method": "shift_dates" }
```

## Client Example

```python
import requests

def anonymize_via_api(text: str, url: str = "http://localhost:5000/anonymize") -> str:
    response = requests.post(url, json={"text": text}, timeout=5)
    response.raise_for_status()
    return response.json().get("text", "")

clean_text = anonymize_via_api("John Doe visited the clinic.")
print(clean_text)
```

## Docker

### Build Image
```bash
cd presidio_service
docker build -t presidio-service .
```

### Run Container
```bash
docker run -p 5000:5000 presidio-service
```