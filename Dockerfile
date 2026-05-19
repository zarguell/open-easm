# ── Stage 1: Build the React UI ──
FROM node:24-slim AS ui-builder

WORKDIR /ui
COPY ui/package.json ui/package-lock.json* ./
RUN npm install
COPY ui/ .
RUN npm run build

# ── Stage 2: Python app + built UI ──
FROM python:3.14-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates unzip \
    && rm -rf /var/lib/apt/lists/*

RUN SUBFINDER_VER="v2.14.0" && \
    curl -L "https://github.com/projectdiscovery/subfinder/releases/download/${SUBFINDER_VER}/subfinder_${SUBFINDER_VER#v}_linux_amd64.zip" \
    -o /tmp/subfinder.zip && \
    unzip /tmp/subfinder.zip -d /usr/local/bin/ subfinder && \
    chmod +x /usr/local/bin/subfinder && \
    rm /tmp/subfinder.zip

RUN ASNMAP_VER="v1.1.1" && \
    curl -L "https://github.com/projectdiscovery/asnmap/releases/download/${ASNMAP_VER}/asnmap_${ASNMAP_VER#v}_linux_amd64.zip" \
    -o /tmp/asnmap.zip && \
    unzip /tmp/asnmap.zip -d /usr/local/bin/ asnmap && \
    chmod +x /usr/local/bin/asnmap && \
    rm /tmp/asnmap.zip

RUN NUCLEI_VER="v3.4.2" && \
    curl -L "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VER}/nuclei_${NUCLEI_VER#v}_linux_amd64.zip" \
    -o /tmp/nuclei.zip && \
    unzip /tmp/nuclei.zip -d /usr/local/bin/ nuclei && \
    chmod +x /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip

RUN apt-get update && apt-get install -y --no-install-recommends nmap && \
    rm -rf /var/lib/apt/lists/*

# Download GeoLite2 database for geo-IP enrichment (non-fatal)
RUN mkdir -p /app/data && \
    curl -fsSL "https://github.com/zarguell/TA-geoip/raw/refs/heads/master/bin/GeoLite2-City.mmdb" \
    -o /app/data/GeoLite2-City.mmdb || echo "GeoLite2 download failed, geo-IP disabled"

WORKDIR /app

COPY pyproject.toml .
COPY src/ src/
RUN pip install --no-cache-dir hatchling && pip install --no-cache-dir -e .

COPY alembic/ alembic/
COPY alembic.ini .

# Copy the built UI from the first stage
COPY --from=ui-builder /ui/dist /app/ui/dist

RUN useradd --create-home --shell /bin/bash easm
USER easm
EXPOSE 8000

CMD ["python", "-m", "easm.main"]