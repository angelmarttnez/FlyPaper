#!/usr/bin/env python3
"""
Reinicia usuarios (portal + SOC), eventos de ataques y progreso CTF para pruebas.

Uso (desde la raíz del repo, con el servidor Flask detenido):

    python scripts/reiniciar_lab.py --confirmar
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
if str(RAIZ) not in sys.path:
    sys.path.insert(0, str(RAIZ))

from dotenv import load_dotenv

load_dotenv(RAIZ / ".env")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Vacía ataques, usuarios portal/SOC y progreso CTF (lab FlyPaper)."
    )
    parser.add_argument(
        "--confirmar",
        action="store_true",
        help="Ejecutar el borrado (sin este flag solo muestra aviso).",
    )
    args = parser.parse_args()

    if not args.confirmar:
        print(
            "Este script borra eventos, registros, IPs bloqueadas, progreso CTF,\n"
            "cuentas /register, cuentas SOC (y recrea bootstrap) y claves Redis flypaper:*.\n"
            "Detén Flask antes. Ejecuta con:  python scripts/reiniciar_lab.py --confirmar"
        )
        return 1

    from app.database import reiniciar_entorno_pruebas_completo

    try:
        stats = reiniciar_entorno_pruebas_completo()
    except sqlite3.Error as exc:
        print(f"Error SQLite (¿servidor en marcha?): {exc}")
        return 2

    print("Reinicio de laboratorio completado:")
    for clave, valor in stats.items():
        print(f"  {clave}: {valor}")
    print("\nReinicia Flask y vuelve a registrarte en /register o entra al SOC con la cuenta bootstrap.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
