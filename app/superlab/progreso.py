"""
Progreso por usuario/sesión en SuperLab (fases y flags capturadas).

La identidad sigue el criterio anti-IDOR del CTF: preferencia por ``session['usuario']``
si hay login público; si no, un UUID estable en sesión Flask (no la IP).
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any, Optional

from flask import session

from app.core.timezone_fp import marca_ahora
from app.ctf_sqli.telemetria import identidad_alumno_sesion
from app.superlab.superlab_db import obtener_conexion_superlab

logger = logging.getLogger(__name__)

CLAVE_SESION_SUPERLAB_ID = "superlab_user_id"


def identidad_progreso_superlab() -> str:
    """
    Identificador único de progreso (misma filosofía que telemetría CTF).

    1) Usuario del portal público autenticado (``session['usuario']``).
    2) UUID anónimo ligado a la sesión cifrada (evita compartir progreso por IP).
    """
    ident = identidad_alumno_sesion()
    if ident:
        return ident
    if CLAVE_SESION_SUPERLAB_ID not in session:
        session[CLAVE_SESION_SUPERLAB_ID] = str(uuid.uuid4())
        session.modified = True
    return str(session[CLAVE_SESION_SUPERLAB_ID])


def _parse_flags(raw: str) -> list[str]:
    try:
        datos = json.loads(raw or "[]")
        if isinstance(datos, list):
            return [str(x) for x in datos]
    except json.JSONDecodeError:
        logger.warning("SuperLab: flags_capturadas JSON inválido")
    return []


def obtener_o_crear_progreso(usuario_sesion: Optional[str] = None) -> dict[str, Any]:
    """
    Devuelve el registro de progreso; lo crea en fase 0 si no existe.

    Returns:
        dict con fase_actual, flags_capturadas (lista), timestamps.
    """
    uid = usuario_sesion or identidad_progreso_superlab()
    ahora = marca_ahora()
    with obtener_conexion_superlab() as conexion:
        cursor = conexion.execute(
            """
            SELECT fase_actual, flags_capturadas, staging_descubierto,
                   timestamp_inicio, timestamp_ultima_actividad
            FROM superlab_progreso WHERE usuario_sesion = ?;
            """,
            (uid,),
        )
        fila = cursor.fetchone()
        if fila is None:
            conexion.execute(
                """
                INSERT INTO superlab_progreso
                    (usuario_sesion, fase_actual, flags_capturadas, staging_descubierto,
                     timestamp_inicio, timestamp_ultima_actividad)
                VALUES (?, 0, '[]', 0, ?, ?);
                """,
                (uid, ahora, ahora),
            )
            return {
                "usuario_sesion": uid,
                "fase_actual": 0,
                "flags_capturadas": [],
                "staging_descubierto": False,
                "timestamp_inicio": ahora,
                "timestamp_ultima_actividad": ahora,
            }
        return {
            "usuario_sesion": uid,
            "fase_actual": int(fila["fase_actual"]),
            "flags_capturadas": _parse_flags(fila["flags_capturadas"]),
            "staging_descubierto": bool(fila["staging_descubierto"]),
            "timestamp_inicio": fila["timestamp_inicio"],
            "timestamp_ultima_actividad": fila["timestamp_ultima_actividad"],
        }


def avanzar_fase(
    usuario_sesion: Optional[str],
    nueva_fase: int,
    flag: Optional[str] = None,
) -> dict[str, Any]:
    """
    Actualiza la fase si ``nueva_fase`` es mayor o igual a la actual y opcionalmente
    registra una flag capturada (sin duplicados).
    """
    uid = usuario_sesion or identidad_progreso_superlab()
    progreso = obtener_o_crear_progreso(uid)
    fase = max(int(progreso["fase_actual"]), int(nueva_fase))
    flags = list(progreso["flags_capturadas"])
    if flag and flag not in flags:
        flags.append(flag)
    ahora = marca_ahora()
    with obtener_conexion_superlab() as conexion:
        conexion.execute(
            """
            UPDATE superlab_progreso
            SET fase_actual = ?, flags_capturadas = ?, timestamp_ultima_actividad = ?
            WHERE usuario_sesion = ?;
            """,
            (fase, json.dumps(flags, ensure_ascii=False), ahora, uid),
        )
    return {
        "usuario_sesion": uid,
        "fase_actual": fase,
        "flags_capturadas": flags,
        "timestamp_ultima_actividad": ahora,
    }


def obtener_flags_capturadas(usuario_sesion: Optional[str] = None) -> list[str]:
    """Lista de flags ya capturadas por el jugador."""
    progreso = obtener_o_crear_progreso(usuario_sesion)
    return list(progreso.get("flags_capturadas") or [])


def staging_descubierto(usuario_sesion: Optional[str] = None) -> bool:
    """True si el jugador ejecutó el ffuf simulado y encontró la ruta staging."""
    progreso = obtener_o_crear_progreso(usuario_sesion)
    return bool(progreso.get("staging_descubierto"))


def marcar_staging_descubierto(usuario_sesion: Optional[str] = None) -> None:
    """Persiste el descubrimiento de web-nexuscorp-2.0-staging (fuzzer)."""
    uid = usuario_sesion or identidad_progreso_superlab()
    obtener_o_crear_progreso(uid)
    ahora = marca_ahora()
    with obtener_conexion_superlab() as conexion:
        conexion.execute(
            """
            UPDATE superlab_progreso
            SET staging_descubierto = 1, timestamp_ultima_actividad = ?
            WHERE usuario_sesion = ?;
            """,
            (ahora, uid),
        )
