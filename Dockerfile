# FlyPaper — imagen de producción (Flask + Gunicorn, usuario non-root).
# Bases SQLite persistidas en /app/data (montar volumen en despliegue).

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    FLYPAPER_DATA_DIR=/app/data

RUN groupadd -r flypaper \
    && useradd -r -g flypaper -d /app -s /usr/sbin/nologin flypaper

WORKDIR /app

COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir "gunicorn>=22.0.0"

COPY . .

RUN mkdir -p /app/data \
    && chown -R flypaper:flypaper /app

USER flypaper

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "4", "app:aplicacion"]
