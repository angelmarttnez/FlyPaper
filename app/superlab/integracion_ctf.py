"""
Sincroniza la flag final de SuperLab con ``flypaper.db`` (ranking /objetivos).
"""

from __future__ import annotations

import logging

from app.ctf_sqli.catalogo import (
    CATALOGO_SUPERLAB,
    RETO_SUPERLAB_NOMBRE,
    SUPERLAB_PUNTOS,
    obtener_flag_superlab_final,
)
from app.database import obtener_conexion

logger = logging.getLogger(__name__)


def asegurar_flag_superlab_en_flypaper() -> None:
    """
    Inserta o actualiza la flag fija del SuperLab en la tabla ``flags``.

    Solo la flag final puntúa; las intermedias viven en ``superlab_progreso``.
    """
    flag_final = obtener_flag_superlab_final()
    pista = (CATALOGO_SUPERLAB.get("pista") or "").strip()
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            "SELECT id, flag_string, puntos FROM flags WHERE reto_nombre = ?;",
            (RETO_SUPERLAB_NOMBRE,),
        )
        fila = cursor.fetchone()
        if fila is None:
            cursor.execute(
                """
                INSERT INTO flags (reto_nombre, flag_string, puntos, pista)
                VALUES (?, ?, ?, ?);
                """,
                (RETO_SUPERLAB_NOMBRE, flag_final, SUPERLAB_PUNTOS, pista),
            )
            logger.info("SuperLab: flag de ranking registrada en flypaper.db")
        else:
            cursor.execute(
                """
                UPDATE flags
                SET flag_string = ?, puntos = ?, pista = ?
                WHERE id = ?;
                """,
                (flag_final, SUPERLAB_PUNTOS, pista, fila["id"]),
            )
