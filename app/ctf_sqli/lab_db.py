"""
Laboratorios SQLi aislados: una SQLite por reto en ``data/ctf/sqli_XX.db``.

Cada BD contiene datos ficticios + la flag del reto. Las flags se sincronizan
con la tabla ``flags`` de flypaper.db para el progreso del alumno.
"""

from __future__ import annotations

import logging
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator, Optional

from app.core.timezone_fp import marca_ahora
from app.ctf_sqli.catalogo import CATALOGO_RETOS, RETO_NOMBRE
from app.database import (
    RUTA_DATOS,
    generar_flag_ctf_aleatoria,
    obtener_conexion,
)

logger = logging.getLogger(__name__)

RUTA_CTF = RUTA_DATOS / "ctf"


def ruta_bd_reto(reto_id: int) -> Path:
    """Ruta absoluta a ``sqli_01.db`` … ``sqli_04.db``."""
    return RUTA_CTF / f"sqli_{int(reto_id):02d}.db"


@contextmanager
def conexion_lab(reto_id: int) -> Generator[sqlite3.Connection, None, None]:
    """
    Conexión de corta duración a la BD aislada del reto.

    Row factory dict-like; cierra siempre al salir del with.
    """
    ruta = ruta_bd_reto(reto_id)
    if not ruta.is_file():
        asegurar_lab_reto(reto_id)
    conexion = sqlite3.connect(str(ruta), timeout=15.0)
    conexion.row_factory = sqlite3.Row
    try:
        yield conexion
        conexion.commit()
    except Exception:
        conexion.rollback()
        raise
    finally:
        conexion.close()


def _leer_meta_flag(conexion: sqlite3.Connection) -> Optional[str]:
    cursor = conexion.cursor()
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='lab_meta';"
    )
    if cursor.fetchone() is None:
        return None
    cursor.execute("SELECT flag_string FROM lab_meta WHERE id = 1;")
    fila = cursor.fetchone()
    return fila["flag_string"] if fila else None


def _escribir_meta(conexion: sqlite3.Connection, flag: str, reto_id: int) -> None:
    cursor = conexion.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS lab_meta (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            reto_id INTEGER NOT NULL,
            flag_string TEXT NOT NULL,
            creado_en TEXT
        );
        """
    )
    cursor.execute(
        """
        INSERT INTO lab_meta (id, reto_id, flag_string, creado_en)
        VALUES (1, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            flag_string = excluded.flag_string,
            reto_id = excluded.reto_id;
        """,
        (reto_id, flag, marca_ahora()),
    )


def _sembrar_reto_01(conexion: sqlite3.Connection, flag: str) -> None:
    cursor = conexion.cursor()
    cursor.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            note TEXT
        );
        DELETE FROM users;
        """
    )
    cursor.execute(
        "INSERT INTO users (username, password, role, note) VALUES (?, ?, ?, ?);",
        ("admin", "P@ssw0rd!Admin", "administrator", flag),
    )
    cursor.execute(
        "INSERT INTO users (username, password, role, note) VALUES (?, ?, ?, ?);",
        ("guest", "guest123", "user", "Cuenta de demostración"),
    )
    cursor.execute(
        "INSERT INTO users (username, password, role, note) VALUES (?, ?, ?, ?);",
        ("alice", "alice2024", "user", "RRHH"),
    )


def _sembrar_reto_02(conexion: sqlite3.Connection, flag: str) -> None:
    cursor = conexion.cursor()
    cursor.executescript(
        """
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            price REAL NOT NULL,
            category TEXT
        );
        CREATE TABLE IF NOT EXISTS secret_flags (
            id INTEGER PRIMARY KEY,
            codename TEXT,
            flag_value TEXT NOT NULL
        );
        DELETE FROM products;
        DELETE FROM secret_flags;
        """
    )
    productos = [
        (1, "Laptop Nova 14", 899.0, "hardware"),
        (2, "Monitor Ultrawide", 449.0, "hardware"),
        (3, "Teclado mecánico", 129.0, "perifericos"),
        (4, "Auriculares SOC", 79.0, "perifericos"),
        (5, "Licencia SIEM trial", 0.0, "software"),
    ]
    cursor.executemany(
        "INSERT INTO products (id, name, price, category) VALUES (?, ?, ?, ?);",
        productos,
    )
    cursor.execute(
        "INSERT INTO secret_flags (id, codename, flag_value) VALUES (1, ?, ?);",
        ("UNION_TARGET", flag),
    )


def _sembrar_reto_placeholder(conexion: sqlite3.Connection, flag: str, reto_id: int) -> None:
    """Esqueleto para retos 03/04 (aún no jugables)."""
    cursor = conexion.cursor()
    cursor.executescript(
        """
        CREATE TABLE IF NOT EXISTS placeholder (
            id INTEGER PRIMARY KEY,
            mensaje TEXT,
            flag_reservada TEXT
        );
        DELETE FROM placeholder;
        """
    )
    cursor.execute(
        "INSERT INTO placeholder (id, mensaje, flag_reservada) VALUES (1, ?, ?);",
        (f"Laboratorio SQLi-{reto_id:02d} reservado", flag),
    )


def asegurar_lab_reto(reto_id: int) -> str:
    """
    Crea/puebla la BD del reto si no existe. Devuelve la flag del laboratorio.

    Si la BD ya existe, reutiliza la flag de ``lab_meta``.
    """
    RUTA_CTF.mkdir(parents=True, exist_ok=True)
    ruta = ruta_bd_reto(reto_id)
    existe = ruta.is_file()

    conexion = sqlite3.connect(str(ruta), timeout=15.0)
    conexion.row_factory = sqlite3.Row
    try:
        flag = _leer_meta_flag(conexion) if existe else None
        if not flag:
            flag = generar_flag_ctf_aleatoria()
            if reto_id == 1:
                _sembrar_reto_01(conexion, flag)
            elif reto_id == 2:
                _sembrar_reto_02(conexion, flag)
            else:
                _sembrar_reto_placeholder(conexion, flag, reto_id)
            _escribir_meta(conexion, flag, reto_id)
            conexion.commit()
            logger.info("Lab SQLi-%02d sembrado en %s", reto_id, ruta)
        return flag
    finally:
        conexion.close()


def obtener_flag_lab(reto_id: int) -> str:
    """Lee la flag del laboratorio (crea el lab si falta)."""
    with conexion_lab(reto_id) as conexion:
        flag = _leer_meta_flag(conexion)
        if flag:
            return flag
    return asegurar_lab_reto(reto_id)


def sincronizar_flags_academia_flypaper() -> None:
    """
    Garantiza filas en ``flags`` (flypaper.db) alineadas con cada lab SQLi.

    Así ``enviar_flag_por_usuario`` y el ranking CTF puntúan la academia.
    """
    for reto in CATALOGO_RETOS:
        rid = int(reto["id"])
        nombre = RETO_NOMBRE[rid]
        flag = asegurar_lab_reto(rid)
        puntos = int(reto["puntos"])
        pista = reto.get("pista") or reto.get("descripcion") or ""

        with obtener_conexion() as conexion:
            cursor = conexion.cursor()
            cursor.execute(
                "SELECT id, flag_string FROM flags WHERE reto_nombre = ?;",
                (nombre,),
            )
            fila = cursor.fetchone()
            if fila is None:
                cursor.execute(
                    """
                    INSERT INTO flags (reto_nombre, flag_string, puntos, pista)
                    VALUES (?, ?, ?, ?);
                    """,
                    (nombre, flag, puntos, pista),
                )
            else:
                # Mantener flag del lab como fuente de verdad.
                cursor.execute(
                    """
                    UPDATE flags
                    SET flag_string = ?, puntos = ?, pista = ?
                    WHERE id = ?;
                    """,
                    (flag, puntos, pista, fila["id"]),
                )
            conexion.commit()


def inicializar_labs_sqli() -> None:
    """Punto de arranque: directorio ctf/, 4 labs y sync de flags."""
    RUTA_CTF.mkdir(parents=True, exist_ok=True)
    for reto in CATALOGO_RETOS:
        asegurar_lab_reto(int(reto["id"]))
    sincronizar_flags_academia_flypaper()
    logger.info("Academia SQLi lista en %s", RUTA_CTF)


def estado_retos_para_usuario(usuario_id: str) -> list[dict[str, Any]]:
    """
    Catálogo enriquecido con ``resuelto`` según ``objetivos_completados``.
    """
    from app.database import obtener_conexion as _oc

    resueltos: set[str] = set()
    usuario = (usuario_id or "").strip()
    if usuario:
        with _oc() as conexion:
            cursor = conexion.cursor()
            cursor.execute(
                """
                SELECT f.reto_nombre
                FROM objetivos_completados oc
                JOIN flags f ON f.id = oc.flag_id
                WHERE oc.usuario_id = ?;
                """,
                (usuario,),
            )
            resueltos = {fila["reto_nombre"] for fila in cursor.fetchall()}

    resultado = []
    for reto in CATALOGO_RETOS:
        nombre = RETO_NOMBRE[reto["id"]]
        item = dict(reto)
        item["reto_nombre"] = nombre
        item["resuelto"] = nombre in resueltos
        resultado.append(item)
    return resultado


def progreso_sqli_usuario(usuario_id: str) -> dict[str, int]:
    """Progreso 0–4 sobre retos SQLi de la academia."""
    estados = estado_retos_para_usuario(usuario_id)
    completados = sum(1 for e in estados if e.get("resuelto"))
    return {"completados": completados, "total": len(CATALOGO_RETOS)}
