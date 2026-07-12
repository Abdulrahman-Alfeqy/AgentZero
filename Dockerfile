# Agent Zero — Docker Configuration
FROM python:3.11-slim

# Metadata
LABEL maintainer="Agent Zero"
LABEL description="AI-powered Slack compliance guardian"

# Set working directory
WORKDIR /app

# Install system dependencies (ReportLab needs some libs)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libfreetype6 \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY *.py ./

# Create directories for runtime files
RUN mkdir -p /app/reports

# Create non-root user for security
RUN useradd -m -u 1000 agentuser && chown -R agentuser:agentuser /app
USER agentuser

# Environment defaults (override via docker-compose or -e flags)
ENV STORAGE_PATH=/app/incidents.jsonl
ENV REPORTS_DIR=/app/reports
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Expose Dashboard and MCP server ports
EXPOSE 5000
EXPOSE 5001

ENV DASHBOARD_HOST=0.0.0.0
ENV PORT=5000

ENTRYPOINT ["python", "main.py"]
