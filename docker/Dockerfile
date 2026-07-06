# ── Vulntriage Docker image ──────────────────────────────────────────────
# Build:  docker build -f docker/Dockerfile -t vulntriage .
# Run:    docker run --network vuln-net -v ./output:/app/output vulntriage --help
# Webapp: docker compose -f docker/compose.yaml up

# ── Stage 1: nuclei binary ──────────────────────────────────────────────
FROM projectdiscovery/nuclei:v3 AS nuclei-src

# ── Stage 2: uv binary ──────────────────────────────────────────────────
FROM ghcr.io/astral-sh/uv:latest AS uv-bin

# ── Stage 3: runtime ────────────────────────────────────────────────────
FROM python:3.14-slim

# System deps for WeasyPrint (PDF rendering)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libcairo2 \
    libpangoft2-1.0-0 \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

# Copy nuclei binary and pre-download templates
COPY --from=nuclei-src /usr/local/bin/nuclei /usr/local/bin/nuclei
RUN nuclei -ut && \
    mkdir -p /root/.config/nuclei && \
    echo "disable-update-check: true" > /root/.config/nuclei/config.yaml

# Copy uv
COPY --from=uv-bin /uv /usr/local/bin/uv

WORKDIR /app

# Install Python dependencies (layer cache: pyproject + lock change less often than src)
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev

# Copy application code
COPY src/ ./src/
COPY main.py ./
COPY data/ ./data/

# Ensure output directory exists
RUN mkdir -p output/runs output/eval

EXPOSE 9000

ENTRYPOINT ["uv", "run", "python", "main.py"]
CMD ["--help"]
