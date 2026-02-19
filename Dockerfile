# ReportGC - FastAPI Edition
# Optimized for ASGI performance

# ==========================================
# Stage 1: Builder
# ==========================================
FROM python:3.11-slim as builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libcairo2-dev \
    libpango1.0-dev \
    libgdk-pixbuf2.0-dev \
    libffi-dev \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ==========================================
# Stage 2: Production (FastAPI + Uvicorn)
# ==========================================
FROM python:3.11-slim as production

RUN groupadd -r reportgc && useradd -r -g reportgc reportgc

RUN apt-get update && apt-get install -y --no-install-recommends \
    libcairo2 \
    libpango-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libffi8 \
    shared-mime-info \
    fonts-liberation \
    fonts-dejavu \
    && rm -rf /var/lib/apt/lists/* \
    && fc-cache -fv

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app

# Copy FastAPI app
COPY engine.py pptx_generator.py report_generator.py main.py api.py ./
COPY report.html templates/
RUN mkdir -p /app/static /app/reports

RUN chown -R reportgc:reportgc /app

USER reportgc

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    REPORTGC_TEMPLATE_DIR=/app/templates \
    REPORTGC_STATIC_DIR=/app/static \
    REPORTGC_OUTPUT_DIR=/app/reports \
    REPORTGC_LOG_LEVEL=INFO

# FastAPI health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

# Uvicorn ASGI server (production config)
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4", "--proxy-headers"]

# ==========================================
# Stage 3: Development
# ==========================================
FROM production as development

USER root
RUN pip install --no-cache-dir pytest pytest-asyncio httpx black flake8 mypy
COPY tests/ /app/tests/
RUN chown -R reportgc:reportgc /app
USER reportgc

# Auto-reload for development
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
