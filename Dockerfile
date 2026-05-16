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

WORKDIR /app

COPY pyproject.toml .
COPY src/ src/
RUN pip install --no-cache-dir hatchling && pip install --no-cache-dir -e .

COPY alembic/ alembic/
COPY alembic.ini .

RUN useradd --create-home --shell /bin/bash easm
USER easm
EXPOSE 8000

CMD ["python", "-m", "easm.main"]