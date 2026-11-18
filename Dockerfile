FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN useradd --create-home --uid 10001 dhcp \
    && mkdir -p /data \
    && chown -R dhcp:dhcp /data /app

USER dhcp
WORKDIR /app

ENV DHCP_DB_PATH=/data/dhcp.sqlite3 \
    DHCP_UDP_HOST=0.0.0.0 \
    DHCP_UDP_PORT=6767

EXPOSE 6767/udp 8080/tcp

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=4 \
    CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=2)"

# One process owns the pool: the UDP listener and the web server share state,
# and the SQLite process lock rejects a second instance on the same database.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1", "--no-access-log"]
