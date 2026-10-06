"""Helper: sesión autenticada en FlyPaper para scripts solve_*."""

from __future__ import annotations

import os
import secrets
from pathlib import Path

import requests

# Credenciales FLYPAPER_TEST_* desde .env del repo (tests no cargan app.py).
try:
    from dotenv import load_dotenv

    _raiz = Path(__file__).resolve().parent.parent
    load_dotenv(_raiz / ".env")
except ImportError:
    pass


def _login_portal(sesion: requests.Session, base: str, user: str, password: str) -> None:
    r = sesion.post(
        f"{base.rstrip('/')}/login",
        data={"username": user, "password": password},
        timeout=20,
        allow_redirects=True,
    )
    r.raise_for_status()


def asegurar_sesion(base: str) -> requests.Session:
    """
    Abre sesión en el portal público (requerido para /objetivos/*).

    Orden:
    1. Si existen FLYPAPER_TEST_USER y FLYPAPER_TEST_PASSWORD en el entorno, solo login.
    2. Si no, registro + login (puede fallar con HTTP 429 si el rate limit de /register está agotado).
    """
    sesion = requests.Session()
    base = base.rstrip("/")
    user_env = os.getenv("FLYPAPER_TEST_USER", "").strip()
    pass_env = os.getenv("FLYPAPER_TEST_PASSWORD", "").strip()

    if user_env and pass_env:
        _login_portal(sesion, base, user_env, pass_env)
        return sesion

    user = f"solve_{secrets.token_hex(4)}"
    password = "SolveTest2026!"
    reg = sesion.post(
        f"{base}/register",
        data={
            "usuario": user,
            "password": password,
            "confirmar_password": password,
        },
        timeout=20,
        allow_redirects=False,
    )
    if reg.status_code == 429:
        raise RuntimeError(
            "Rate limit en /register (3/hora). Reinicia Flask, espera 1 h o define "
            "FLYPAPER_TEST_USER y FLYPAPER_TEST_PASSWORD en .env con una cuenta ya registrada."
        )
    if reg.status_code not in (302, 303):
        reg.raise_for_status()

    _login_portal(sesion, base, user, password)
    return sesion
