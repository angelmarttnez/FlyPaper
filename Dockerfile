# FlyPaper — imagen de producción (Flask + Gunicorn, usuario non-root).
# Estructura en contenedor:
#   /app/app.py + /app/wsgi.py   → entrypoint local / Gunicorn (wsgi:aplicacion)
#   /app/app/                   → paquete (database, core, ctf_sqli, templates, static)
#   /app/data/                  → SQLite unificadas (volumen ./data:/app/data)

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    FLYPAPER_DATA_DIR=/app/data \
    PYTHONPATH=/app

RUN groupadd -r flypaper \
    && useradd -r -g flypaper -d /app -s /usr/sbin/nologin flypaper

WORKDIR /app

COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir "gunicorn>=22.0.0"

COPY . .

RUN mkdir -p /app/data /app/data/ctf \
    && chown -R flypaper:flypaper /app

USER flypaper

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "4", "wsgi:aplicacion"]
