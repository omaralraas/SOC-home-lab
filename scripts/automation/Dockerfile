FROM python:3.13.15-slim-bookworm

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn==26.2.0

COPY soar_engine.py .
COPY config/soar_config.yml config/soar_config.yml

# Blocklist state and the audit trail live on volumes; run unprivileged.
RUN useradd --system --create-home --uid 10001 soar \
    && mkdir -p /app/data /var/log/soar \
    && chown soar /app/data /var/log/soar
USER soar

EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=3)"
# One worker: blocklist and de-duplication state are held in-process.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "4", "soar_engine:wsgi()"]
