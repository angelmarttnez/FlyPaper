#!/usr/bin/env python3
"""
Crea (o actualiza) la cuenta portal para tests HTTP sin pasar por /register (evita rate limit).

Escribe FLYPAPER_TEST_USER y FLYPAPER_TEST_PASSWORD en .env del repo.

Uso: python scripts/preparar_cuenta_demo.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
if str(RAIZ) not in sys.path:
    sys.path.insert(0, str(RAIZ))

from dotenv import load_dotenv

load_dotenv(RAIZ / ".env")

# Credenciales fijas de laboratorio (solo entorno local / vídeo demo).
DEMO_USER = "demo_flypaper"
DEMO_PASS = "DemoFlyPaper2026!"


def _actualizar_linea_env(ruta: Path, clave: str, valor: str) -> None:
    texto = ruta.read_text(encoding="utf-8") if ruta.is_file() else ""
    lineas = texto.splitlines()
    patron = re.compile(rf"^{re.escape(clave)}=")
    sustituido = False
    nuevas: list[str] = []
    for linea in lineas:
        if patron.match(linea):
            nuevas.append(f"{clave}={valor}")
            sustituido = True
        else:
            nuevas.append(linea)
    if not sustituido:
        if nuevas and nuevas[-1].strip():
            nuevas.append("")
        nuevas.append(f"# Cuenta portal para tests solve_* (scripts/preparar_cuenta_demo.py)")
        nuevas.append(f"{clave}={valor}")
    ruta.write_text("\n".join(nuevas).rstrip() + "\n", encoding="utf-8")


def main() -> int:
    from app.database import registrar_usuario

    resultado = registrar_usuario(DEMO_USER, DEMO_PASS)
    if resultado["exito"]:
        print(f"[OK] Cuenta creada: {DEMO_USER}")
    elif "ya existe" in (resultado.get("mensaje") or "").lower():
        print(f"[OK] Cuenta ya existía: {DEMO_USER} (solo actualizo .env)")
    else:
        print(f"[WARN] Registro: {resultado.get('mensaje')}")

    env_path = RAIZ / ".env"
    _actualizar_linea_env(env_path, "FLYPAPER_TEST_USER", DEMO_USER)
    _actualizar_linea_env(env_path, "FLYPAPER_TEST_PASSWORD", DEMO_PASS)
    print(f"[OK] .env actualizado con FLYPAPER_TEST_* ({env_path})")
    print("     Reinicia Flask si ya estaba en marcha para recargar variables.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
