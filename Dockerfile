FROM python:3.13-slim as base

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY agents/ agents/
COPY api/ api/
COPY dashboard/ dashboard/
COPY orchestrator/ orchestrator/
COPY rbac/ rbac/
COPY proxy/ proxy/
COPY configs/ configs/
COPY .env.example ./

# Create logs directory
RUN mkdir -p logs && touch logs/.gitkeep

# Expose ports
EXPOSE 8000 8501

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
