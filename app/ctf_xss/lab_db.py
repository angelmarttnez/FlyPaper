"""BD aislada del lab XSS (comentarios del reto, no blog honeypot)."""

from __future__ import annotations

import logging
import secrets
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator, Optional

from app.ctf_xss.catalogo import CATALOGO_RETOS, FLAG_RETO_01, RETO_NOMBRE
from app.database import RUTA_DATOS, obtener_conexion

logger = logging.getLogger(__name__)

RUTA_CTF = RUTA_DATOS / "ctf"
RUTA_BD_XSS = RUTA_CTF / "xss_01.db"


@contextmanager
def conexion_lab(_reto_id: int = 1) -> Generator[sqlite3.Connection, None, None]:
    """Conexión al SQLite del lab XSS."""
    RUTA_CTF.mkdir(parents=True, exist_ok=True)
    conexion = sqlite3.connect(str(RUTA_BD_XSS), timeout=15.0)
    conexion.row_factory = sqlite3.Row
    try:
        yield conexion
        conexion.commit()
    except Exception:
        conexion.rollback()
        raise
    finally:
        conexion.close()


def _crear_esquema(conexion: sqlite3.Connection) -> None:
    conexion.executescript(
        """
        CREATE TABLE IF NOT EXISTS lab_meta (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            flag_string TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS comentarios_lab (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id TEXT NOT NULL,
            contenido TEXT NOT NULL,
            token_robo TEXT NOT NULL,
            revisado_bot INTEGER NOT NULL DEFAULT 0,
            explotado INTEGER NOT NULL DEFAULT 0,
            creado_en TEXT NOT NULL
        );
        """
    )


def asegurar_lab_xss() -> str:
    """Crea esquema y flag canónica del reto."""
    from app.core.timezone_fp import marca_ahora

    with conexion_lab(1) as conexion:
        _crear_esquema(conexion)
        cur = conexion.execute("SELECT flag_string FROM lab_meta WHERE id = 1;")
        fila = cur.fetchone()
        if fila is None:
            conexion.execute(
                "INSERT INTO lab_meta (id, flag_string) VALUES (1, ?);",
                (FLAG_RETO_01,),
            )
            return FLAG_RETO_01
        return fila["flag_string"]


def sincronizar_flag_flypaper() -> None:
    """Registra la flag en flypaper.db para ranking."""
    flag = asegurar_lab_xss()
    reto = CATALOGO_RETOS[0]
    nombre = RETO_NOMBRE[1]
    with obtener_conexion() as conexion:
        cur = conexion.cursor()
        cur.execute("SELECT id FROM flags WHERE reto_nombre = ?;", (nombre,))
        fila = cur.fetchone()
        if fila is None:
            cur.execute(
                "INSERT INTO flags (reto_nombre, flag_string, puntos, pista) VALUES (?, ?, ?, ?);",
                (nombre, flag, int(reto["puntos"]), reto.get("pista") or ""),
            )
        else:
            cur.execute(
                "UPDATE flags SET flag_string = ?, puntos = ?, pista = ? WHERE id = ?;",
                (flag, int(reto["puntos"]), reto.get("pista") or "", fila["id"]),
            )


def inicializar_lab_xss() -> None:
    asegurar_lab_xss()
    sincronizar_flag_flypaper()
    logger.info("Lab XSS-01 listo en %s", RUTA_BD_XSS)


def estado_retos_para_usuario(usuario_id: str) -> list[dict[str, Any]]:
    resueltos: set[str] = set()
    usuario = (usuario_id or "").strip()
    if usuario:
        with obtener_conexion() as conexion:
            cur = conexion.execute(
                """
                SELECT f.reto_nombre FROM objetivos_completados oc
                JOIN flags f ON f.id = oc.flag_id WHERE oc.usuario_id = ?;
                """,
                (usuario,),
            )
            resueltos = {r["reto_nombre"] for r in cur.fetchall()}
    out = []
    for reto in CATALOGO_RETOS:
        item = dict(reto)
        nombre = RETO_NOMBRE[int(reto["id"])]
        item["reto_nombre"] = nombre
        item["resuelto"] = nombre in resueltos
        out.append(item)
    return out


def insertar_comentario(usuario_id: str, contenido: str) -> dict[str, Any]:
    from app.core.timezone_fp import marca_ahora

    token = secrets.token_urlsafe(12)
    with conexion_lab(1) as conexion:
        _crear_esquema(conexion)
        cur = conexion.execute(
            """
            INSERT INTO comentarios_lab (usuario_id, contenido, token_robo, creado_en)
            VALUES (?, ?, ?, ?);
            """,
            (usuario_id, contenido, token, marca_ahora()),
        )
        cid = cur.lastrowid
    return {"id": cid, "token_robo": token}


def comentarios_pendientes() -> list[dict[str, Any]]:
    with conexion_lab(1) as conexion:
        cur = conexion.execute(
            """
            SELECT id, usuario_id, contenido, token_robo, revisado_bot
            FROM comentarios_lab WHERE revisado_bot = 0 ORDER BY id ASC;
            """
        )
        return [dict(r) for r in cur.fetchall()]


def marcar_revisado_bot(comentario_id: int, explotable: bool) -> None:
    with conexion_lab(1) as conexion:
        conexion.execute(
            """
            UPDATE comentarios_lab
            SET revisado_bot = 1, explotado = ?
            WHERE id = ?;
            """,
            (1 if explotable else 0, int(comentario_id)),
        )


def obtener_comentario_por_token(token: str) -> Optional[dict[str, Any]]:
    with conexion_lab(1) as conexion:
        cur = conexion.execute(
            """
            SELECT id, usuario_id, contenido, token_robo, revisado_bot, explotado
            FROM comentarios_lab WHERE token_robo = ? LIMIT 1;
            """,
            ((token or "").strip(),),
        )
        fila = cur.fetchone()
        return dict(fila) if fila else None
