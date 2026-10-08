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

# UID fijo para que el volumen ./data sea predecible en el host.
RUN groupadd -r -g 10001 flypaper \
    && useradd -r -u 10001 -g flypaper -d /app -s /usr/sbin/nologin flypaper

WORKDIR /app

COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir "gunicorn>=22.0.0"

COPY . .

RUN mkdir -p /app/data /app/data/ctf \
    && chmod +x /app/docker-entrypoint.sh \
    && chown -R flypaper:flypaper /app

# Arranca como root solo para chown del volumen; el entrypoint baja a flypaper.
USER root

EXPOSE 5000

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "4", "wsgi:aplicacion"]
