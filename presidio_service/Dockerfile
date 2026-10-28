# Build from the repository root so the anonymize_data package is in context:
#   docker build -f presidio_service/Dockerfile -t presidio-service .
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY presidio_service/requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && python -m spacy download en_core_web_lg

# Copy application code (app.py imports the anonymize_data package)
COPY anonymize_data/ ./anonymize_data/
COPY presidio_service/app.py .
COPY presidio_service/templates/ ./templates/

# Expose port
EXPOSE 5000

# --preload imports the app once before forking, so workers share the spaCy
# model and the session signing key (otherwise cookies from one worker are
# rejected by the other unless SESSION_SECRET is set).
CMD ["gunicorn", "--preload", "-w", "2", "-b", "0.0.0.0:5000", "app:app"]
