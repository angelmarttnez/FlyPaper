#!/usr/bin/env python3
"""Tests admin participantes CTF: reset y eliminación en cascada."""

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
    admin_definitivo = "soc.participantes.test"
    from app.database import enviar_flag_por_usuario, obtener_puntos_usuario, registrar_usuario
    from app.gestion_participantes import (
        detalle_progreso_participante,
        eliminar_participante_completo,
        resetear_progreso_participante,
    )

    client = app.test_client()

    completar_login_soc(
        client,
        SOC_USER_BOOTSTRAP,
        SOC_PASS_BOOTSTRAP,
        username_nuevo=admin_definitivo,
        nueva_password=ADMIN_NUEVA,
    )

    alumno = f"ctf_alumno_{secrets.token_hex(4)}"
    pwd = "AlumnoTest123!"
    assert registrar_usuario(alumno, pwd)["exito"]

    # Simular una flag resuelta (usa catálogo flypaper.db).
    from app.database import obtener_conexion

    with obtener_conexion() as con:
        cur = con.cursor()
        cur.execute("SELECT flag_string FROM flags LIMIT 1;")
        fila = cur.fetchone()
    assert fila, "Se necesita al menos una flag en flypaper.db"
    flag = fila["flag_string"]
    enviar_flag_por_usuario(alumno, flag)
    assert obtener_puntos_usuario(alumno) > 0

    stats = resetear_progreso_participante(alumno)
    assert stats.get("objetivos_completados", 0) >= 1
    assert obtener_puntos_usuario(alumno) == 0

    enviar_flag_por_usuario(alumno, flag)
    det = detalle_progreso_participante(alumno)
    assert det and det["flags_capturadas"] >= 1

    with app.app_context():
        from app.database import obtener_conexion_users

        with obtener_conexion_users() as con:
            uid = con.execute(
                "SELECT id FROM usuarios_registrados WHERE username = ?;",
                (alumno,),
            ).fetchone()["id"]

    res = eliminar_participante_completo(uid)
    assert res["exito"]
    assert detalle_progreso_participante(alumno) is None

    r = client.get("/admin/participantes-ctf")
    assert r.status_code == 200
    assert alumno.encode() not in r.data

    print("[OK] solve_admin_participantes — reset + eliminar completo")
    return 0


if __name__ == "__main__":
    sys.exit(main())
