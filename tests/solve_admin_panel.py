#!/usr/bin/env python3
"""Tests gestión cuentas SOC: onboarding obligatorio y CRUD."""

from __future__ import annotations

import secrets
import sys

from solve_admin_auth import (
    SOC_PASS_BOOTSTRAP,
    SOC_USER_BOOTSTRAP,
    cargar_aplicacion,
    completar_login_soc,
    preparar_datos_aislados,
)

ADMIN_NUEVA = "NewSecureAdmin99!"


def main() -> int:
    preparar_datos_aislados()
    app = cargar_aplicacion()
    client = app.test_client()

    admin_definitivo = f"soc.admin.{secrets.token_hex(2)}"

    completar_login_soc(client, SOC_USER_BOOTSTRAP, SOC_PASS_BOOTSTRAP)
    r = client.get("/admin", follow_redirects=False)
    assert r.status_code in (302, 303), f"/admin -> {r.status_code} {r.location!r}"
    assert "/admin/cambiar-password" in (r.location or "")

    r = client.post(
        "/admin/cambiar-password",
        data={
            "password_actual": SOC_PASS_BOOTSTRAP,
            "username_nuevo": admin_definitivo,
            "password_nueva": ADMIN_NUEVA,
            "password_confirmacion": ADMIN_NUEVA,
        },
        follow_redirects=True,
    )
    assert r.status_code == 200
    r = client.get("/admin/usuarios-soc")
    assert r.status_code == 200, "Admin debe acceder a usuarios-soc tras onboarding"

    temp_user = f"test.analyst.{secrets.token_hex(3)}"
    r = client.post(
        "/admin/usuarios-soc/crear",
        data={"username": temp_user, "rol": "monitor"},
        follow_redirects=True,
    )
    assert r.status_code == 200

    r = client.post(
        f"/admin/usuarios-soc/{admin_definitivo}/eliminar",
        data={"confirmacion": admin_definitivo},
        follow_redirects=True,
    )
    assert b"No puedes eliminar tu propia sesi" in r.data

    r = client.post(
        f"/admin/usuarios-soc/{temp_user}/reset",
        follow_redirects=True,
    )
    assert r.status_code == 200

    r = client.post(
        f"/admin/usuarios-soc/{temp_user}/eliminar",
        data={"confirmacion": temp_user},
        follow_redirects=True,
    )
    assert r.status_code == 200

    from app.database import contar_admins_soc, crear_cuenta_soc, eliminar_cuenta_soc

    assert contar_admins_soc() >= 1
    extra_admin = f"admin.extra.{secrets.token_hex(2)}"
    temp_pass = secrets.token_urlsafe(14)
    assert crear_cuenta_soc(extra_admin, "admin_panel", temp_pass)["exito"]
    assert eliminar_cuenta_soc(extra_admin)["exito"]

    print("[OK] solve_admin_panel — onboarding + gestión SOC")
    return 0


if __name__ == "__main__":
    sys.exit(main())
