# ==========================================
# ReportGC - Render Production Dockerfile
# Optimized for MVP / Free Tier
# ==========================================

# -------- Builder Stage --------
FROM python:3.12-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    libcairo2 \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libgdk-pixbuf-xlib-2.0-0 \
    libffi8 \
    libexpat1 \
    shared-mime-info \
    fonts-liberation \
    fonts-dejavu \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && fc-cache -fv

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt


# -------- Production Stage --------
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libcairo2 \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libgdk-pixbuf-xlib-2.0-0 \
    libffi8 \
    libexpat1 \
    shared-mime-info \
    fonts-liberation \
    fonts-dejavu \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && fc-cache -fv

# Create non-root user
RUN groupadd -r reportgc && useradd -r -g reportgc reportgc

# Copy virtual environment
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app

# Copy application files
COPY engine.py pptx_generator.py report_generator.py main.py api.py ./
COPY template/report.html /app/templates/report.html

# Create reports directory (ephemeral)
RUN mkdir -p /app/reports && \
    chown -R reportgc:reportgc /app

USER reportgc

ENV PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    REPORTGC_TEMPLATE_DIR=/app/templates \
    REPORTGC_OUTPUT_DIR=/app/reports \
    REPORTGC_LOG_LEVEL=INFO

# Simple healthcheck (Render-compatible)
HEALTHCHECK CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=5)"

# Single worker for free tier
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]