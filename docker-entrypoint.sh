#!/bin/sh
# Arranque Docker: el volumen ./data del host suele ser de root/ubuntu
# y el proceso Gunicorn corre como flypaper (non-root). Aquí se corrige
# el dueño de /app/data y luego se baja de privilegios.
set -e

mkdir -p /app/data/ctf
chown -R flypaper:flypaper /app/data

exec runuser -u flypaper -- "$@"
