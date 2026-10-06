"""
Login staging vulnerable a SQLi (concatenación sobre superlab.db).

Patrón equivalente al buscador ``/search`` de FlyPaper, aislado en superlab.db.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Optional

import bcrypt

from app.superlab.superlab_db import obtener_conexion_superlab

logger = logging.getLogger(__name__)

_PATRON_SQLI_BYPASS = re.compile(r"'\s*OR\s+1\s*=\s*1\s*--", re.IGNORECASE)


def _parece_sqli(usuario: str) -> bool:
    """Heurística mínima para marcar bypass clásico en telemetría interna."""
    texto = (usuario or "").strip()
    if _PATRON_SQLI_BYPASS.search(texto):
        return True
    return "OR 1=1" in texto.upper().replace(" ", "")


def intentar_login_staging(
    usuario: str,
    password: str,
) -> tuple[Optional[dict[str, Any]], bool]:
    """
    Intenta autenticación contra ``superlab_empleados``.

    1) Consulta vulnerable por concatenación (SQLi posible).
    2) Si falla, login legítimo con bcrypt (usuario + contraseña en claro).

    Returns:
        (empleado, login_via_sqli) — empleado None si falla.
    """
    usuario_raw = usuario or ""
    password_raw = password or ""
    via_sqli = _parece_sqli(usuario_raw)

    sql_vulnerable = (
        "SELECT id, nombre, usuario, password_hash, estado "
        "FROM superlab_empleados "
        f"WHERE usuario = '{usuario_raw}' AND password_hash = '{password_raw}' "
        "LIMIT 1"
    )
    try:
        with obtener_conexion_superlab() as conexion:
            cursor = conexion.cursor()
            cursor.execute(sql_vulnerable)
            fila = cursor.fetchone()
            if fila is not None:
                return dict(fila), via_sqli
    except Exception as exc:
        logger.debug("SuperLab staging SQLi: consulta vulnerable falló — %s", exc)

    usuario_limpio = usuario_raw.strip()
    if not usuario_limpio:
        return None, False

    try:
        with obtener_conexion_superlab() as conexion:
            cursor = conexion.execute(
                """
                SELECT id, nombre, usuario, password_hash, estado
                FROM superlab_empleados WHERE usuario = ? LIMIT 1;
                """,
                (usuario_limpio,),
            )
            fila = cursor.fetchone()
            if fila is None:
                return None, False
            hash_bd = (fila["password_hash"] or "").encode("utf-8")
            if bcrypt.checkpw(password_raw.encode("utf-8"), hash_bd):
                return dict(fila), False
    except Exception as exc:
        logger.warning("SuperLab staging: login bcrypt falló — %s", exc)

    return None, False
