FROM python:3.11-slim

# Install system dependencies including nmap
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY backend/ ./backend/

# Create directories
RUN mkdir -p logs backend/app/ml/models

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=backend/app/main.py

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--timeout", "120", "backend.app.main:app"]
