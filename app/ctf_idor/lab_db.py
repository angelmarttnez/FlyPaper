"""BD aislada idor.db — nóminas ficticias."""

from __future__ import annotations

import logging
import random
import sqlite3
from contextlib import contextmanager
from typing import Any, Generator, Optional

from app.ctf_idor.catalogo import CATALOGO_RETOS, FLAG_RETO_01, RETO_NOMBRE
from app.database import RUTA_DATOS, obtener_conexion

logger = logging.getLogger(__name__)

RUTA_BD = RUTA_DATOS / "ctf" / "idor_01.db"


@contextmanager
def conexion_lab(_reto_id: int = 1) -> Generator[sqlite3.Connection, None, None]:
    RUTA_BD.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(RUTA_BD), timeout=15.0)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def _sembrar(con: sqlite3.Connection) -> None:
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS lab_meta (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            flag_string TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS nominas (
            id INTEGER PRIMARY KEY,
            empleado TEXT NOT NULL,
            puesto TEXT NOT NULL,
            importe TEXT NOT NULL
        );
        """
    )
    cur = con.execute("SELECT COUNT(*) AS n FROM nominas;")
    if int(cur.fetchone()["n"]) > 0:
        return
    con.execute("INSERT OR REPLACE INTO lab_meta (id, flag_string) VALUES (1, ?);", (FLAG_RETO_01,))
    filas = [
        (1, "Elena Vargas", "Directora Financiera", FLAG_RETO_01),
        (2, "Tomás Ruiz", "Analista SOC", "2.450 €"),
        (3, "Lucía Perales", "Desarrolladora", "2.890 €"),
        (4, "Marcos Gil", "Técnico N2", "2.610 €"),
        (5, "Irene Soler", "RRHH", "2.720 €"),
        (6, "Pablo Nieto", "Operador CTF", "2.550 €"),
    ]
    con.executemany(
        "INSERT INTO nominas (id, empleado, puesto, importe) VALUES (?, ?, ?, ?);",
        filas,
    )


def asegurar_lab_idor() -> str:
    with conexion_lab(1) as con:
        _sembrar(con)
        cur = con.execute("SELECT flag_string FROM lab_meta WHERE id = 1;")
        return cur.fetchone()["flag_string"]


def sincronizar_flag_flypaper() -> None:
    flag = asegurar_lab_idor()
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


def inicializar_lab_idor() -> None:
    asegurar_lab_idor()
    sincronizar_flag_flypaper()
    logger.info("Lab IDOR-01 listo en %s", RUTA_BD)


def obtener_nomina(nomina_id: int) -> Optional[dict[str, Any]]:
    with conexion_lab(1) as con:
        _sembrar(con)
        cur = con.execute(
            "SELECT id, empleado, puesto, importe FROM nominas WHERE id = ?;",
            (int(nomina_id),),
        )
        fila = cur.fetchone()
        return dict(fila) if fila else None


def id_nomina_asignada_aleatoria(excluir: int = 1) -> int:
    """ID propio del alumno (nunca el 1 con la flag)."""
    opciones = [2, 3, 4, 5, 6]
    return random.choice(opciones)


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
