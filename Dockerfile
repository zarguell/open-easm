# ── Stage 1: Build the React UI ──
FROM node:24-slim AS ui-builder

WORKDIR /ui
COPY ui/package.json ui/package-lock.json* ./
RUN npm install
COPY ui/ .
RUN npm run build

# ── Stage 2: Python base (shared) ──
FROM python:3.14-slim AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml .
COPY src/ src/
RUN pip install --no-cache-dir hatchling && pip install --no-cache-dir -e .

COPY alembic/ alembic/
COPY alembic.ini .

COPY --from=ui-builder /ui/dist /app/ui/dist

# ── Stage 3: Web server (slim) ──
FROM base AS web

RUN useradd --create-home --shell /bin/bash easm && \
    mkdir -p /app/data && chown -R easm:easm /app/data

USER easm
EXPOSE 8000
ENV EASM_MODE=web
CMD ["python", "-m", "easm.main"]

# ── Stage 4: Worker (full tools) ──
FROM base AS worker

# Install nmap
RUN apt-get update && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

# Install subfinder
RUN SUBFINDER_VER="v2.14.0" && \
    curl -L "https://github.com/projectdiscovery/subfinder/releases/download/${SUBFINDER_VER}/subfinder_${SUBFINDER_VER#v}_linux_amd64.zip" \
    -o /tmp/subfinder.zip && \
    unzip /tmp/subfinder.zip -d /usr/local/bin/ subfinder && \
    chmod +x /usr/local/bin/subfinder && \
    rm /tmp/subfinder.zip

# Install asnmap
RUN ASNMAP_VER="v1.1.1" && \
    curl -L "https://github.com/projectdiscovery/asnmap/releases/download/${ASNMAP_VER}/asnmap_${ASNMAP_VER#v}_linux_amd64.zip" \
    -o /tmp/asnmap.zip && \
    unzip /tmp/asnmap.zip -d /usr/local/bin/ asnmap && \
    chmod +x /usr/local/bin/asnmap && \
    rm /tmp/asnmap.zip

# Install nuclei
RUN NUCLEI_VER="v3.4.2" && \
    curl -L "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VER}/nuclei_${NUCLEI_VER#v}_linux_amd64.zip" \
    -o /tmp/nuclei.zip && \
    unzip /tmp/nuclei.zip -d /usr/local/bin/ nuclei && \
    chmod +x /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip

# Install webanalyze
RUN WEBANALYZE_VER="v0.4.3" && \
    curl -L "https://github.com/rverton/webanalyze/releases/download/${WEBANALYZE_VER}/webanalyze_Linux_x86_64.tar.gz" \
    | tar xz -C /usr/local/bin/ webanalyze && \
    chmod +x /usr/local/bin/webanalyze && \
    cd /tmp && webanalyze -update && mv /tmp/technologies.json /usr/local/bin/

# Install gitleaks
RUN GITLEAKS_VER="v8.24.3" && \
    curl -L "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VER}/gitleaks_${GITLEAKS_VER#v}_linux_x64.tar.gz" \
    | tar xz -C /usr/local/bin/ gitleaks && \
    chmod +x /usr/local/bin/gitleaks

# Install dnstwist
RUN pip install --no-cache-dir dnstwist

# Download GeoLite2 database
RUN mkdir -p /app/data && \
    curl -fsSL "https://github.com/zarguell/TA-geoip/raw/refs/heads/master/bin/GeoLite2-City.mmdb" \
    -o /app/data/GeoLite2-City.mmdb || echo "GeoLite2 download failed, geo-IP disabled"

# Install Playwright for screenshot runner
RUN useradd --create-home --shell /bin/bash easm && \
    PLAYWRIGHT_BROWSERS_PATH=/opt/playwright-browsers playwright install chromium --with-deps && \
    chown -R easm:easm /opt/playwright-browsers && \
    mkdir -p /app/data/screenshots && chown -R easm:easm /app/data

USER easm
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/playwright-browsers
ENV EASM_MODE=worker
CMD ["python", "-m", "easm.worker"]

# ── Stage 5: All-in-one (backward compatible) ──
FROM worker AS all-in-one

ENV EASM_MODE=all
EXPOSE 8000
CMD ["python", "-m", "easm.main"]
