"""
Conexión y esquema de ``superlab.db`` (BD aislada del honeypot principal).

Patrón de acceso: ``with obtener_conexion_superlab() as conexion: ...``
"""

from __future__ import annotations

import logging
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from app.database import RUTA_DATOS

logger = logging.getLogger(__name__)

RUTA_BD_SUPERLAB = RUTA_DATOS / "superlab.db"


@contextmanager
def obtener_conexion_superlab() -> Generator[sqlite3.Connection, None, None]:
    """
    Conexión SQLite a superlab.db con filas tipo dict y cierre automático.

    Yields:
        sqlite3.Connection: conexión activa; commit al salir sin excepción.
    """
    RUTA_BD_SUPERLAB.parent.mkdir(parents=True, exist_ok=True)
    conexion = sqlite3.connect(str(RUTA_BD_SUPERLAB), timeout=15.0)
    conexion.row_factory = sqlite3.Row
    conexion.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conexion
        conexion.commit()
    except Exception:
        conexion.rollback()
        raise
    finally:
        conexion.close()


def _crear_esquema(conexion: sqlite3.Connection) -> None:
    """DDL de tablas del laboratorio encadenado NexusCorp."""
    conexion.executescript(
        """
        CREATE TABLE IF NOT EXISTS superlab_empleados (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            usuario TEXT NOT NULL UNIQUE,
            estado TEXT NOT NULL CHECK (estado IN ('activo', 'vacaciones', 'baja')),
            password_hash TEXT NOT NULL,
            password_provisional TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS superlab_mensajes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            remitente TEXT NOT NULL,
            asunto TEXT NOT NULL,
            cuerpo TEXT NOT NULL,
            fecha TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS superlab_progreso (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_sesion TEXT NOT NULL UNIQUE,
            fase_actual INTEGER NOT NULL DEFAULT 0,
            flags_capturadas TEXT NOT NULL DEFAULT '[]',
            staging_descubierto INTEGER NOT NULL DEFAULT 0,
            timestamp_inicio TEXT NOT NULL,
            timestamp_ultima_actividad TEXT NOT NULL
        );
        """
    )
    _migrar_columnas_progreso(conexion)


def _migrar_columnas_progreso(conexion: sqlite3.Connection) -> None:
    """Añade columnas nuevas en BDs creadas antes del bloque fuzzer/staging."""
    columnas = {
        fila[1] for fila in conexion.execute("PRAGMA table_info(superlab_progreso);")
    }
    if "staging_descubierto" not in columnas:
        conexion.execute(
            "ALTER TABLE superlab_progreso ADD COLUMN staging_descubierto INTEGER NOT NULL DEFAULT 0;"
        )


def inicializar_superlab() -> None:
    """
    Crea el esquema y siembra datos ficticios si la BD está vacía de empleados.
    """
    from app.superlab.datos_ficticios import sembrar_datos_superlab

    from app.superlab.integracion_ctf import asegurar_flag_superlab_en_flypaper

    with obtener_conexion_superlab() as conexion:
        _crear_esquema(conexion)
        cursor = conexion.execute("SELECT COUNT(*) AS n FROM superlab_empleados;")
        fila = cursor.fetchone()
        if fila and int(fila["n"]) == 0:
            sembrar_datos_superlab(conexion)
            logger.info("SuperLab: datos semilla insertados en superlab.db")

    asegurar_flag_superlab_en_flypaper()
