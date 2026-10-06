#!/usr/bin/env python3
"""
Genera y guarda un resumen diario con Groq (misma lógica que el panel SOC).

Útil en laboratorio sin esperar al job automático de las 23:59.

Uso:
  python scripts/forzar_resumen_ia.py
  python scripts/forzar_resumen_ia.py --fecha 2026-10-06 --regenerar
  python scripts/forzar_resumen_ia.py --telegram
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
if str(RAIZ) not in sys.path:
    sys.path.insert(0, str(RAIZ))

from dotenv import load_dotenv

load_dotenv(RAIZ / ".env")

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Forzar resumen diario IA (Groq)")
    parser.add_argument(
        "--fecha",
        help="YYYY-MM-DD (por defecto: hoy en Europe/Madrid)",
    )
    parser.add_argument(
        "--regenerar",
        action="store_true",
        help="Ignora resumen ya guardado y vuelve a llamar a Groq",
    )
    parser.add_argument(
        "--telegram",
        action="store_true",
        help="Envía el texto al topic TELEGRAM_TOPIC_RESUMEN si está configurado",
    )
    parser.add_argument(
        "--solo-preview",
        action="store_true",
        help="Solo genera texto; no guarda en resumenes_diarios_ia",
    )
    args = parser.parse_args()

    from app.core.timezone_fp import fecha_hoy
    from app.database import (
        contar_eventos_en_fecha,
        eliminar_resumen_diario_ia,
        guardar_resumen_diario_ia,
        obtener_resumen_diario_ia,
        registrar_resumen_log,
    )
    from ai_analyzer import _modelo_groq, generar_resumen_diario

    fecha = (args.fecha or fecha_hoy()).strip()
    total = contar_eventos_en_fecha(fecha)
    print(f"Fecha: {fecha} | eventos en BD: {total} | modelo Groq: {_modelo_groq()}")

    if total == 0:
        print("No hay eventos ese día; el panel mostraría «sin datos».")
        return 1

    if args.regenerar and not args.solo_preview:
        eliminar_resumen_diario_ia(fecha)
        print("Resumen anterior eliminado (--regenerar).")

    if not args.regenerar and not args.solo_preview:
        guardado = obtener_resumen_diario_ia(fecha)
        if guardado and guardado.get("resumen"):
            print("\n--- Ya existía (usa --regenerar para forzar Groq) ---\n")
            print(guardado["resumen"][:2000])
            if len(guardado["resumen"]) > 2000:
                print("\n… (truncado en consola)")
            return 0

    print("Llamando a Groq…")
    texto = generar_resumen_diario(fecha)
    if not texto or "El modelo no devolvió contenido" in texto:
        print("Groq devolvió respuesta vacía; reintentando una vez…")
        texto = generar_resumen_diario(fecha)
    if (
        not texto
        or texto.strip().startswith("No se pudo generar")
        or "Error de API Groq" in texto
        or "El modelo no devolvió contenido" in texto
    ):
        print("ERROR:", texto)
        registrar_resumen_log(fecha, "manual_script", total, 0, ok=False)
        return 2

    if not args.solo_preview:
        guardar_resumen_diario_ia(fecha, texto, total_eventos=total)
        registrar_resumen_log(fecha, "manual_script", total, len(texto), ok=True)
        print("Guardado en resumenes_diarios_ia.")

    if args.telegram:
        from app.core.telegram_notifier import notificar_resumen_diario

        ok = notificar_resumen_diario(fecha, texto, total)
        print("Telegram resumen:", "OK" if ok else "falló (revisa TELEGRAM_* en .env)")

    print("\n--- Resumen ---\n")
    print(texto)
    print(f"\n--- Fin ({len(texto)} caracteres) ---")
    print("Panel: /admin > Reportes > Resumenes, o GET /admin/api/resumenes-panel")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
