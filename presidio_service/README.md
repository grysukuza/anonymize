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

## Required security configuration

The service refuses to start without an explicit session secret, username, and
password hash. Generate them outside the repository so no deployable credential
is committed:

```bash
export PRESIDIO_SESSION_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export PRESIDIO_USERNAME="your-admin-username"
export PRESIDIO_PASSWORD_HASH="$(python -c 'from getpass import getpass; from werkzeug.security import generate_password_hash; print(generate_password_hash(getpass("Password: ")))')"
```

Use your platform's secret manager in production. Do not commit these values or
put them in a client-side bundle. `PRESIDIO_SESSION_SECRET` must be at least 32
characters; `PRESIDIO_PASSWORD_HASH` must be a Werkzeug scrypt or PBKDF2 hash.

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

## Client Example

```python
import getpass
import os
import requests

def anonymize_via_api(text: str, base_url: str = "http://localhost:5000") -> str:
    client = requests.Session()
    login = client.post(
        f"{base_url}/login",
        json={
            "username": os.environ["PRESIDIO_USERNAME"],
            "password": getpass.getpass("Presidio password: "),
        },
        timeout=5,
    )
    login.raise_for_status()
    response = client.post(f"{base_url}/anonymize", json={"text": text}, timeout=5)
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
docker run --env-file /secure/path/presidio.env -p 5000:5000 presidio-service
```

The env file must define the three variables above and remain outside the image
and source repository.
