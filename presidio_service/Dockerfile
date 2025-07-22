FROM python:3.11-slim

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && python -m spacy download en_core_web_lg

# Copy application code
COPY app.py .

# Expose port
EXPOSE 8001

# Run the Gunicorn server
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:8001", "app:app"]