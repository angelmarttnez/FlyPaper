#!/usr/bin/env python3
"""Comprueba el buscador /search (portal real, sin SQLi)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.buscador_portal import buscar_portal


def _cliente_http(base: str):
    """Sesión requests o None si el servidor no está levantado."""
    import requests

    try:
        requests.get(f"{base.rstrip('/')}/login", timeout=3)
    except requests.RequestException:
        return None
    from solve_ctf_auth import asegurar_sesion

    return asegurar_sesion(base)


def _cliente_flask():
    from tests.solve_admin_auth import cargar_aplicacion

    app = cargar_aplicacion()
    return app.test_client()


def _login_test_client(client) -> None:
    import secrets

    user = f"search_{secrets.token_hex(3)}"
    pwd = "SearchTest2026!"
    client.post(
        "/register",
        data={"usuario": user, "password": pwd, "confirmar_password": pwd},
        follow_redirects=True,
    )


def _get_busqueda(cliente, base: str, q: str):
    from urllib.parse import quote_plus

    if base.startswith("http"):
        return cliente.get(
            f"{base.rstrip('/')}/search",
            params={"q": q},
            timeout=20,
        )
    return cliente.get(f"/search?q={quote_plus(q)}")


def _assert_categorias(base: str, sesion) -> None:
    """Términos conocidos en blog, labs y documentación."""
    casos = [
        ("monitorización", "blog", "FlyPaper 2.0: nuevo panel"),
        ("Authentication Bypass", "labs", "objetivos/sqli"),
        ("Cheat sheet", "docs", "documentacion"),
    ]
    for termino, grupo, needle in casos:
        r = _get_busqueda(sesion, base, termino)
        assert r.status_code == 200, f"HTTP {r.status_code} para q={termino!r}"
        cuerpo = r.get_data(as_text=True) if hasattr(r, "get_data") else r.text
        assert needle in cuerpo, f"Falta {needle!r} en resultados de {termino!r}"


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--base", default="http://127.0.0.1:5000")
    args = p.parse_args()
    base = args.base.rstrip("/")

    # Unitario: payload SQLi como texto de búsqueda (sin excepción ni filas anómalas).
    payload = "' OR 1=1--"
    datos = buscar_portal(payload)
    assert isinstance(datos["total"], int)
    assert datos["q"] == payload

    sesion = _cliente_http(base)
    if sesion is None:
        sesion = _cliente_flask()
        _login_test_client(sesion)
        base = ""

    _assert_categorias(base, sesion)

    r_vacio = _get_busqueda(sesion, base, "xyz_sin_match_flypaper_999")
    assert r_vacio.status_code == 200
    cuerpo_vacio = (
        r_vacio.get_data(as_text=True)
        if hasattr(r_vacio, "get_data")
        else r_vacio.text
    )
    assert "No hay coincidencias" in cuerpo_vacio

    r_sqli = _get_busqueda(sesion, base, payload)
    texto_sqli = (
        r_sqli.get_data(as_text=True)
        if hasattr(r_sqli, "get_data")
        else r_sqli.text
    )
    assert r_sqli.status_code == 200
    assert "Error de base de datos" not in texto_sqli
    assert "SQLi_flag" not in texto_sqli
    assert "UNION SELECT" not in texto_sqli.upper()
    # Jinja autoescapa comillas; basta comprobar que el término aparece sin errores SQL.
    assert "OR 1=1" in texto_sqli
    assert "&#x27;" in texto_sqli or "'" in texto_sqli or "&#39;" in texto_sqli

    r_get = sesion.get(f"{base}/search" if base else "/search")
    assert r_get.status_code == 200

    print("[OK] solve_search — buscador portal seguro y resultados por categoría")
    return 0


if __name__ == "__main__":
    sys.exit(main())
