FROM python:3.13-slim AS base

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

# Bake Chroma's default ONNX embedding model (~83 MB) into the image. Otherwise the
# first query downloads it at runtime and the first pipeline calls time out.
RUN python -c "from chromadb.utils.embedding_functions import ONNXMiniLM_L6_V2 as E; E()(['warmup'])"

# Copy project files
COPY config.py storage.py ./
COPY agents/ agents/
COPY api/ api/
COPY audit/ audit/
COPY dashboard/ dashboard/
COPY orchestrator/ orchestrator/
COPY rbac/ rbac/
COPY proxy/ proxy/
COPY configs/ configs/
COPY tests/ tests/
COPY .coveragerc ./
COPY .env.example ./

# logs/ holds the shared audit log; data/ holds paused-run checkpoints (SQLite)
RUN mkdir -p logs data && chmod 700 data && touch logs/.gitkeep

# Expose ports
EXPOSE 8000 8501

# One worker: the rate limiter is per process (see api/rate_limit.py).
CMD ["uvicorn", "--factory", "api.main:create_app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
