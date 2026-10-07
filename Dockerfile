# Honeypot Nexus - Production Dockerfile
FROM python:3.11-slim

# Prevent Python from writing .pyc and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ALLOW_NON_LOOPBACK=true \
    DASHBOARD_BIND_HOST=0.0.0.0 \
    HONEYPOT_BIND_HOST=0.0.0.0 \
    APP_TIMEZONE=Asia/Kolkata \
    DEMO_MODE=true

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application codebase
COPY . .

# Expose ports for local/container testing
EXPOSE 5000 8080

# Default entry point
CMD ["python", "run.py"]
