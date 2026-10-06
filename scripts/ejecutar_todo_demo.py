#!/usr/bin/env python3
"""
Batería completa pre-grabación: cuenta demo, unitarios, CTF HTTP, WAF (test_soc_stres).

Uso:
  python scripts/ejecutar_todo_demo.py
  python scripts/ejecutar_todo_demo.py --sin-waf-stres
  python scripts/ejecutar_todo_demo.py --base http://127.0.0.1:5000

Requisitos: FlyPaper en marcha (python app.py). Redis opcional (NGWAF ONLINE).
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
TESTS = RAIZ / "tests"
SCRIPTS = RAIZ / "scripts"


def _servidor_vivo(base: str) -> bool:
    try:
        with urllib.request.urlopen(f"{base.rstrip('/')}/login", timeout=4) as r:
            return r.status == 200
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def _run(cmd: list[str], cwd: Path | None = None, timeout: int = 300) -> tuple[bool, str]:
    proc = subprocess.run(
        cmd,
        cwd=str(cwd or RAIZ),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    out = ((proc.stdout or "") + (proc.stderr or "")).strip()
    return proc.returncode == 0, out


def main() -> int:
    parser = argparse.ArgumentParser(description="Batería demo FlyPaper")
    parser.add_argument("--base", default="http://127.0.0.1:5000")
    parser.add_argument(
        "--sin-waf-stres",
        action="store_true",
        help="Omite tests/test_soc_stres.py --all",
    )
    args = parser.parse_args()
    base = args.base.rstrip("/")

    print("=== [1/4] Cuenta demo (BD + .env) ===")
    ok_prep, msg_prep = _run([sys.executable, str(SCRIPTS / "preparar_cuenta_demo.py")])
    print(msg_prep or ("OK" if ok_prep else "FAIL preparar"))
    if not ok_prep:
        return 2

    print("\n=== [2/4] Unitarios (SOC, search, sandbox) ===")
    ok_u, msg_u = _run([sys.executable, str(SCRIPTS / "ejecutar_pruebas_lab.py"), "--solo-unitarios"])
    print(msg_u[-2000:] if len(msg_u) > 2000 else msg_u)
    if not ok_u:
        print("[FAIL] Unitarios")
        return 1

    if not _servidor_vivo(base):
        print(f"\n[WARN] No hay servidor en {base}. Omite CTF HTTP y WAF.")
        print("       Levanta: python app.py")
        return 0 if ok_u else 1

    print(f"\n=== [3/4] CTF + portal HTTP ({base}) ===")
    ok_h, msg_h = _run(
        [sys.executable, str(SCRIPTS / "ejecutar_pruebas_lab.py"), "--base", base],
        timeout=600,
    )
    print(msg_h[-2500:] if len(msg_h) > 2500 else msg_h)

    resultados = [("unitarios", ok_u), ("http_ctf", ok_h)]

    if not args.sin_waf_stres:
        print("\n=== [4/4] WAF / rutas prohibidas (test_soc_stres --all) ===")
        ok_w, msg_w = _run(
            [sys.executable, str(TESTS / "test_soc_stres.py"), "--base", base, "--all"],
            cwd=TESTS,
            timeout=600,
        )
        print(msg_w[-3000:] if len(msg_w) > 3000 else msg_w)
        resultados.append(("waf_stres", ok_w))

    print("\n=== RESUMEN DEMO ===")
    fallos = 0
    for nombre, ok in resultados:
        print(f"  [{'OK' if ok else 'FAIL'}] {nombre}")
        if not ok:
            fallos += 1

    from dotenv import load_dotenv

    load_dotenv(RAIZ / ".env")
    try:
        from app.core.ip_reputation import redis_esta_disponible

        redis_ok = redis_esta_disponible(forzar=True)
        print(f"  [{'OK' if redis_ok else 'WARN'}] Redis NGWAF ({'ONLINE' if redis_ok else 'degradado — arranca Redis en 6379'})")
    except Exception:
        print("  [WARN] No se pudo comprobar Redis")

    print("\n  Portal demo: FLYPAPER_TEST_USER / FLYPAPER_TEST_PASSWORD en .env")
    print("  SOC bootstrap: Flypaper / Flypaper_123 (o INITIAL_SOC_*)\n")

    return 1 if fallos else 0


if __name__ == "__main__":
    raise SystemExit(main())
