#!/usr/bin/env python3
"""
Ejecuta los scripts solve_* y verify_* del directorio tests/ (smoke del laboratorio).

Uso:
  python scripts/ejecutar_pruebas_lab.py
  python scripts/ejecutar_pruebas_lab.py --base http://127.0.0.1:5000
  python scripts/ejecutar_pruebas_lab.py --solo-unitarios   # sin HTTP (admin + search + sandbox)
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
TESTS = RAIZ / "tests"

# Orden: unitarios / aislados primero, integración HTTP después.
SCRIPTS_UNITARIOS = [
    "solve_admin_panel.py",
    "solve_admin_participantes.py",
    "solve_search.py",
    "verify_pt_sandbox.py",
    "solve_pathtraversal_01.py",  # incluye --solo-sandbox si no hay servidor
]

SCRIPTS_HTTP = [
    "solve_pathtraversal_01.py",
    "solve_pathtraversal_02.py",
    "solve_idor_01.py",
    "solve_xss_01.py",
    "solve_superlab.py",
]


def _run(script: str, extra: list[str] | None = None) -> tuple[bool, str]:
    ruta = TESTS / script
    if not ruta.is_file():
        return False, f"No existe {ruta}"
    cmd = [sys.executable, str(ruta)] + (extra or [])
    proc = subprocess.run(
        cmd,
        cwd=str(TESTS),
        capture_output=True,
        text=True,
        timeout=120,
    )
    salida = (proc.stdout or "") + (proc.stderr or "")
    ok = proc.returncode == 0
    return ok, salida.strip() or f"exit {proc.returncode}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Batería smoke FlyPaper")
    parser.add_argument("--base", default="http://127.0.0.1:5000")
    parser.add_argument(
        "--solo-unitarios",
        action="store_true",
        help="No exige servidor HTTP para CTF (solo admin, search, sandbox PT).",
    )
    args = parser.parse_args()

    resultados: list[tuple[str, bool, str]] = []

    for script in SCRIPTS_UNITARIOS:
        extra = []
        if script == "verify_pt_sandbox.py":
            extra = ["--sin-http"]
        if script == "solve_pathtraversal_01.py" and args.solo_unitarios:
            extra = ["--solo-sandbox"]
        ok, msg = _run(script, extra)
        resultados.append((script, ok, msg))

    if not args.solo_unitarios:
        import urllib.request

        base = args.base.rstrip("/")
        servidor_ok = False
        try:
            with urllib.request.urlopen(f"{base}/login", timeout=3) as resp:
                servidor_ok = resp.status == 200
        except Exception:
            servidor_ok = False

        if not servidor_ok:
            print(
                f"\n[WARN] Servidor no responde en {base} — "
                "omitiendo solve_* HTTP (levanta: python app.py o docker compose up).\n"
            )
        else:
            for script in SCRIPTS_HTTP:
                if script == "solve_pathtraversal_01.py":
                    continue  # ya corrido arriba sin --solo-sandbox si unitarios; re-run full
                extra = ["--base", base]
                ok, msg = _run(script, extra)
                resultados.append((f"{script} (HTTP)", ok, msg))
            ok, msg = _run(
                "solve_pathtraversal_01.py",
                ["--base", base],
            )
            resultados.append(("solve_pathtraversal_01.py (HTTP)", ok, msg))

    print("\n=== Resumen pruebas FlyPaper ===\n")
    fallos = 0
    for nombre, ok, msg in resultados:
        estado = "OK" if ok else "FAIL"
        if not ok:
            fallos += 1
        print(f"  [{estado}] {nombre}")
        if not ok or "--verbose" in sys.argv:
            for linea in msg.splitlines()[-8:]:
                print(f"         {linea}")
    print(f"\nTotal: {len(resultados) - fallos}/{len(resultados)} OK")
    if fallos:
        return 1
    print("\nOpcional: Redis NGWAF -> docker run -d -p 6379:6379 redis:7-alpine")
    print("Opcional: tests/test_soc_stres.py (carga WAF, requiere servidor + Redis)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
