#!/usr/bin/env python3
"""Helpers de autenticación SOC para tests (2FA + onboarding)."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

_PASSWORDS_TEST_SOC: dict[str, str] = {}
SOC_USER_BOOTSTRAP = "Flypaper"
SOC_PASS_BOOTSTRAP = "Flypaper_123"


def preparar_datos_aislados(
    password: str = SOC_PASS_BOOTSTRAP,
    username: str = SOC_USER_BOOTSTRAP,
) -> str:
    """BD temporal con bootstrap SOC único (Flypaper por defecto)."""
    tmp = tempfile.mkdtemp(prefix="flypaper_admin_test_")
    os.environ["FLYPAPER_DATA_DIR"] = tmp
    os.environ["INITIAL_SOC_USERNAME"] = username
    os.environ["INITIAL_SOC_PASSWORD"] = password
    _PASSWORDS_TEST_SOC["user"] = username
    _PASSWORDS_TEST_SOC["password"] = password
    return tmp


def cargar_aplicacion():
    import importlib.util

    ruta_app = ROOT / "app.py"
    spec = importlib.util.spec_from_file_location("flypaper_entry", ruta_app)
    modulo = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(modulo)
    _sincronizar_password_bootstrap_test()
    return modulo.aplicacion


def _sincronizar_password_bootstrap_test() -> None:
    from app.database import resetear_password_soc

    user = (_PASSWORDS_TEST_SOC.get("user") or SOC_USER_BOOTSTRAP).strip()
    pwd = (_PASSWORDS_TEST_SOC.get("password") or SOC_PASS_BOOTSTRAP).strip()
    if user and pwd and len(pwd) >= 12:
        resetear_password_soc(user, pwd)
    elif user and pwd:
        # Bootstrap permite contraseña corta; tests usan onboarding con clave ≥12.
        resetear_password_soc(user, pwd + "X" if len(pwd) < 12 else pwd)


def completar_login_soc(
    client,
    username: str,
    password: str,
    *,
    username_nuevo: str | None = None,
    nueva_password: str | None = None,
) -> None:
    """Login /admin/login → 2FA → onboarding opcional."""
    from app.database import generar_codigo_2fa, obtener_codigo_2fa_pendiente

    resp_login = client.post(
        "/admin/login",
        data={"username": username, "password": password},
        follow_redirects=False,
    )
    assert resp_login.status_code in (302, 303), resp_login.data[:300]
    codigo = obtener_codigo_2fa_pendiente(username) or generar_codigo_2fa(username)
    assert codigo, f"No hay OTP 2FA para {username}"
    resp = client.post(
        "/admin/verificar-2fa",
        data={"codigo": codigo},
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303), resp.data[:200]

    if username_nuevo and nueva_password:
        resp2 = client.post(
            "/admin/cambiar-password",
            data={
                "password_actual": password,
                "username_nuevo": username_nuevo,
                "password_nueva": nueva_password,
                "password_confirmacion": nueva_password,
            },
            follow_redirects=True,
        )
        assert resp2.status_code == 200
