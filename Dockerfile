FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends swtpm tpm2-tools libtss2-tcti-swtpm0 curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml requirements.lock ./
COPY integrity ./integrity
RUN pip install --no-cache-dir -r requirements.lock && pip install --no-cache-dir --no-deps .
COPY tests ./tests
COPY scripts ./scripts
RUN useradd --create-home --uid 10001 monitor && mkdir -p /app/state && chown monitor:monitor /app/state
USER monitor
ENV PYTHONUNBUFFERED=1
CMD ["uvicorn", "integrity.verifier:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
