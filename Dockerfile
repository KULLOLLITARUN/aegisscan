# AegisScan, hosted mode (for Render or any Docker host).
#   docker build -t aegisscan .
#   docker run -p 10000:10000 -e AEGISSCAN_ACCESS_TOKEN=<16+ random characters> aegisscan

# ---- stage 1: build the React UI into scanner/server/dist ----
FROM node:22-slim AS ui
WORKDIR /app/ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci
COPY ui/ ./
# vite.config.js writes to ../scanner/server/dist
RUN node node_modules/vite/bin/vite.js build

# ---- stage 2: the Python server ----
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    AEGISSCAN_MODE=hosted \
    PORT=10000

# git is needed for "scan a Git URL". The optional gitleaks binary is not installed; the scanner
# falls back to its built-in secret scanner.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml ./
COPY main.py ./
COPY scanner ./scanner
COPY --from=ui /app/scanner/server/dist ./scanner/server/dist
# "[static]" adds semgrep. Bandit and the other analysers are core dependencies.
RUN pip install ".[static]"

# Never run as root: uploaded and cloned code is untrusted input.
RUN useradd --create-home --uid 10001 aegis \
    && mkdir -p /tmp/aegisscan-workspaces \
    && chown -R aegis:aegis /app /tmp/aegisscan-workspaces
USER aegis

EXPOSE 10000
# AEGISSCAN_ACCESS_TOKEN must be provided at run time: hosted mode refuses to start without it.
CMD ["python", "main.py", "--server"]
