# Sentinel: one image with the demo target, the five agents and the web console.
# Everything talks over 127.0.0.1 inside the container; publish ONLY the console port.

# --- build the React console ---
FROM node:24-slim AS console
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-fund --no-audit
COPY frontend/ ./
RUN npm run build

# --- runtime ---
FROM python:3.11-slim
ENV PYTHONPATH=/app PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

# Test-only packages stay out of the image
COPY requirements.txt ./
RUN grep -vE '^(pytest|pytest-asyncio|respx)==' requirements.txt > runtime.txt \
    && pip install -r runtime.txt \
    && rm runtime.txt

COPY agents ./agents
COPY common ./common
COPY scripts ./scripts
COPY web ./web
COPY demo_target_app ./demo_target_app
COPY --from=console /build/dist ./frontend/dist

# uagents keeps each agent's state as <address>_data.json in the working directory
RUN useradd --uid 1000 --create-home sentinel && mkdir /data && chown sentinel:sentinel /data
USER sentinel
WORKDIR /data

ENV WEB_HOST=0.0.0.0
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s \
    CMD python -c "import os, urllib.request as u; u.urlopen('http://127.0.0.1:' + (os.environ.get('WEB_PORT') or os.environ.get('PORT') or '8080') + '/api/health', timeout=4)"

# Refuses to start without the required env vars; the console refuses to start without CONSOLE_PASSWORD
CMD ["python", "-m", "scripts.run_stack"]
