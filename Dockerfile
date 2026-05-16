FROM python:3.14-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates unzip \
    && rm -rf /var/lib/apt/lists/*

RUN curl -L https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_linux_amd64.zip \
    -o /tmp/subfinder.zip \
    && unzip /tmp/subfinder.zip -d /usr/local/bin/ subfinder \
    && chmod +x /usr/local/bin/subfinder \
    && rm /tmp/subfinder.zip

RUN curl -L https://github.com/projectdiscovery/asnmap/releases/latest/download/asnmap_linux_amd64.zip \
    -o /tmp/asnmap.zip \
    && unzip /tmp/asnmap.zip -d /usr/local/bin/ asnmap \
    && chmod +x /usr/local/bin/asnmap \
    && rm /tmp/asnmap.zip

RUN useradd --create-home --shell /bin/bash easm
WORKDIR /app

RUN pip install uv && uv export --no-dev --format=requirements-txt -o requirements.txt

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ src/
COPY alembic/ alembic/
COPY alembic.ini .

USER easm
EXPOSE 8000

CMD ["uvicorn", "easm.main:app", "--host", "0.0.0.0", "--port", "8000"]
