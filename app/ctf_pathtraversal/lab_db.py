"""Rutas de archivos del lab Path Traversal (sin BD; coherencia de módulo)."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

from app.ctf_pathtraversal.catalogo import (
    CATALOGO_RETOS,
    FLAG_RETO_01,
    FLAG_RETO_02,
    RETO_NOMBRE,
    flag_por_reto_id,
)
from app.database import obtener_conexion

logger = logging.getLogger(__name__)

RUTA_MODULO = Path(__file__).resolve().parent
RUTA_ARCHIVOS = RUTA_MODULO / "archivos"


def ruta_base_archivos() -> Path:
    """Directorio publicado ``archivos/`` (punto de partida vulnerable)."""
    return RUTA_ARCHIVOS


def ruta_raiz_lab() -> Path:
    """Raíz del módulo — límite absoluto de lectura."""
    return RUTA_MODULO.resolve()


def resolver_descarga_vulnerable(nombre_archivo: str) -> tuple[Optional[Path], Optional[str]]:
    """
    Concatena ``archivos/<file>`` sin bloquear ``..`` (vulnerable a propósito).

    Tras ``resolve()``, exige que la ruta final permanezca bajo ``RUTA_MODULO``.
    """
    raiz = ruta_raiz_lab()
    bruto = (nombre_archivo or "").replace("\\", "/")
    # VULNERABLE: no se eliminan secuencias ..
    candidato = (RUTA_ARCHIVOS / bruto).resolve()
    try:
        candidato.relative_to(raiz)
    except ValueError:
        return None, "Acceso denegado: fuera del laboratorio."
    if not candidato.is_file():
        return None, "Archivo no encontrado."
    return candidato, None


def contenido_es_flag(contenido: str, reto_id: int = 1) -> bool:
    esperada = flag_por_reto_id(reto_id)
    return bool(esperada and esperada in (contenido or ""))


def sincronizar_flag_flypaper() -> None:
    for reto in CATALOGO_RETOS:
        rid = int(reto["id"])
        flag = flag_por_reto_id(rid)
        if not flag:
            continue
        nombre = RETO_NOMBRE[rid]
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


def valor_file_crudo_en_query(query_string: str) -> str:
    """
    Extrae el valor ``file`` de la query sin decodificar percent-encoding.

    El filtro ingenuo del lab 02 opera sobre este string.
    """
    qs = (query_string or "").strip()
    if not qs:
        return ""
    for fragmento in qs.split("&"):
        if not fragmento.lower().startswith("file="):
            continue
        return fragmento.split("=", 1)[1] if "=" in fragmento else ""
    return ""


def filtro_traversal_literal_bloqueado(file_crudo: str) -> bool:
    """True si el filtro del lab 02 debe rechazar (contiene ../ o ..\\ literal)."""
    bruto = file_crudo or ""
    return "../" in bruto or "..\\" in bruto


def resolver_descarga_vulnerable_filtro_02(
    nombre_decodificado: str,
    file_crudo_query: str,
) -> tuple[Optional[Path], Optional[str], Optional[int]]:
    """
    Lab 02: filtro sobre query cruda; resolución de ruta igual que el lab 01.

    Returns:
        (path, error, http_status) — http_status 400 si el filtro bloquea.
    """
    if filtro_traversal_literal_bloqueado(file_crudo_query):
        return None, "Filtro de seguridad: secuencia ../ no permitida.", 400
    ruta, err = resolver_descarga_vulnerable(nombre_decodificado)
    return ruta, err, None


def inicializar_lab_pathtraversal() -> None:
    RUTA_ARCHIVOS.mkdir(parents=True, exist_ok=True)
    (RUTA_MODULO / "archivos_secretos").mkdir(exist_ok=True)
    _asegurar_archivos_semilla()
    sincronizar_flag_flypaper()
    logger.info("Lab PathTraversal-01 listo en %s", RUTA_MODULO)


def _asegurar_archivos_semilla() -> None:
    informes = {
        "informe_q1.txt": "Informe trimestral Q1 — sin incidencias relevantes.",
        "informe_q2.txt": "Informe Q2 — revisión de accesos internos.",
        "informe_auditoria.txt": "Auditoría interna 2025 — borrador.",
        "readme.txt": "Descargas permitidas solo desde /archivos/.",
    }
    for nombre, texto in informes.items():
        ruta = RUTA_ARCHIVOS / nombre
        if not ruta.is_file():
            ruta.write_text(texto, encoding="utf-8")
    flag_path = RUTA_MODULO / "archivos_secretos" / "flag.txt"
    if not flag_path.is_file():
        flag_path.write_text(
            f"CONFIDENCIAL\n\nFlag del reto: {FLAG_RETO_01}\n",
            encoding="utf-8",
        )
    flag2 = RUTA_MODULO / "archivos_secretos" / "flag_02.txt"
    if not flag2.is_file():
        flag2.write_text(
            f"CONFIDENCIAL\n\nFlag del reto: {FLAG_RETO_02}\n",
            encoding="utf-8",
        )


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
