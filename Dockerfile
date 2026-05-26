# Imagen de la aplicación FlyPaper (Flask).
# SQLite se crea en /app al arrancar (flypaper.db, flypaper_priv.db).
# Para persistir datos entre recreaciones del contenedor, monta un volumen
# en /app solo si aceptas mezclar código y BD; lo habitual en lab es
# copiar las .db fuera con `docker cp` o añadir una variable de ruta en código.

FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install -r requirements.txt \
    && pip install "gunicorn>=22.0.0"

COPY . .

EXPOSE 5000

# Un worker evita duplicar el hilo de fondo del módulo; threads sirven concurrencia I/O.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "4", "app:aplicacion"]
