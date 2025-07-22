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
gunicorn -w 2 -b 0.0.0.0:8001 app:app
```

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

## Client Example

```python
import requests

def anonymize_via_api(text: str, url: str = "http://localhost:8001/anonymize") -> str:
    response = requests.post(url, json={"text": text}, timeout=5)
    response.raise_for_status()
    return response.json().get("text", "")

clean_text = anonymize_via_api("John Doe visited the clinic.")
print(clean_text)

## Docker

### Build Image
```bash
cd presidio_service
docker build -t presidio-service .
```

### Run Container
```bash
docker run -p 8001:8001 presidio-service
```
```