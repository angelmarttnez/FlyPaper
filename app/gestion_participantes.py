"""
Gestión administrativa de participantes CTF (/register → flypaper_users.db).

Mapa de rastros por participante (clave = ``username`` salvo donde se indica):

1. **flypaper.db → objetivos_completados** (``usuario_id``)
   Progreso oficial y ranking: SQLi, XSS, Path Traversal (01/02), IDOR, SuperLab, etc.
   Las filas en ``flags`` son catálogo; no se borran.

2. **flypaper.db → flags_resueltas** (``ip_atacante``)
   Progreso legacy por IP (honeypot). Los registrados puntúan en ``objetivos_completados``;
   no se usa username. Opcional limpiar por IP si se conoce; no forma parte del reset estándar.

3. **flypaper_users.db → usuarios_registrados** (``username``, ``id``)
   Cuenta del participante. Solo se elimina en ``eliminar_participante_completo``.

4. **superlab.db → superlab_progreso** (``usuario_sesion`` = username con sesión pública)
   Fases, flags intermedias y staging del SuperLab.

5. **data/ctf/xss_01.db → comentarios_lab** (``usuario_id``)
   Comentarios del lab XSS del usuario.

6. **data/ctf/sqli_XX.db** (01–04)
   Datos ficticios del lab; **sin** progreso por usuario (solo ``lab_meta`` / tablas de escenario).

7. **data/ctf/idor_01.db**, **pathtraversal** (filesystem)
   Sin tablas de progreso por usuario.

8. **Redis** (opcional, TTL ~30 min / 30 días)
   - ``flypaper:ctf:logs:{user}:{categoria}:{reto_id}``
   - ``flypaper:ctf:pista:{user}:{categoria}:{reto_id}``

9. **Sesión Flask** (SQLi quiz progresivo en ``session``)
   No persistente en BD; se pierde al cerrar sesión o borrar cookie.
"""

from __future__ import annotations

import logging
import sqlite3
from typing import Any, Optional

from app.core.ip_reputation import obtener_cliente_redis, redis_esta_disponible
from app.ctf_academia import listar_categorias_academia
from app.database import (
    RUTA_DATOS,
    contar_flags_resueltas_por_usuario,
    guardar_evento,
    obtener_conexion,
    obtener_conexion_users,
    obtener_puntos_usuario,
    reiniciar_progreso_ctf_por_usuario,
)
from app.superlab.superlab_db import obtener_conexion_superlab

logger = logging.getLogger(__name__)

RUTA_BD_XSS = RUTA_DATOS / "ctf" / "xss_01.db"

def registrar_auditoria_participantes(
    admin_username: str,
    accion: str,
    participante: str,
    detalle: Optional[dict] = None,
    ip_admin: str = "",
) -> None:
    """Registra acción admin sobre participantes en ``eventos`` (ámbito admin)."""
    payload = {
        "admin": admin_username,
        "participante": participante,
        "accion": accion,
        **(detalle or {}),
    }
    guardar_evento(
        ip=ip_admin or "127.0.0.1",
        ruta="/admin/participantes-ctf",
        metodo="ADMIN",
        payload=payload,
        user_agent="FlyPaper-Admin-Participantes",
        tipo_ataque=f"Auditoría participantes: {accion}",
        headers={},
        gravedad="BAJO",
        ambito="admin",
        firma_coincidente=accion,
    )


def _borrar_comentarios_xss(username: str) -> int:
    if not RUTA_BD_XSS.is_file():
        return 0
    conexion = sqlite3.connect(str(RUTA_BD_XSS))
    try:
        cur = conexion.cursor()
        cur.execute(
            "DELETE FROM comentarios_lab WHERE usuario_id = ?;",
            (username,),
        )
        n = cur.rowcount
        conexion.commit()
        return n
    finally:
        conexion.close()


def _borrar_superlab_progreso(username: str) -> int:
    with obtener_conexion_superlab() as conexion:
        cur = conexion.cursor()
        cur.execute(
            "DELETE FROM superlab_progreso WHERE usuario_sesion = ?;",
            (username,),
        )
        return cur.rowcount


def _purga_redis_telemetria_ctf(username: str) -> int:
    """Elimina claves Redis de logs/pistas del usuario (best-effort)."""
    if not username or not redis_esta_disponible():
        return 0
    cliente = obtener_cliente_redis()
    if not cliente:
        return 0
    eliminadas = 0
    marcador = f":{username}:"
    try:
        for patron in ("flypaper:ctf:logs:*", "flypaper:ctf:pista:*"):
            for clave in cliente.scan_iter(match=patron):
                k = clave.decode() if isinstance(clave, bytes) else str(clave)
                if marcador in k or k.endswith(f":{username}"):
                    cliente.delete(clave)
                    eliminadas += 1
    except Exception as exc:
        logger.warning("Redis: no se pudo purgar telemetría CTF de %s — %s", username, exc)
    return eliminadas


def resetear_progreso_participante(username: str) -> dict[str, int]:
    """
    Borra progreso CTF manteniendo la cuenta en flypaper_users.db.

    Returns:
        dict con contadores por área borrada.
    """
    nombre = (username or "").strip()
    if not nombre:
        return {}
    stats = {
        "objetivos_completados": reiniciar_progreso_ctf_por_usuario(nombre),
        "superlab_progreso": _borrar_superlab_progreso(nombre),
        "xss_comentarios_lab": _borrar_comentarios_xss(nombre),
        "redis_claves": _purga_redis_telemetria_ctf(nombre),
    }
    return stats


def eliminar_participante_completo(usuario_id: int) -> dict[str, Any]:
    """
    Elimina cuenta de participante y todo su progreso mapeado.

    Args:
        usuario_id: PK en ``usuarios_registrados``.

    Returns:
        dict con username y estadísticas de borrado; ``exito`` False si no existe.
    """
    with obtener_conexion_users() as conexion:
        cur = conexion.cursor()
        cur.execute(
            "SELECT id, username FROM usuarios_registrados WHERE id = ?;",
            (int(usuario_id),),
        )
        fila = cur.fetchone()
        if fila is None:
            return {"exito": False, "mensaje": "Participante no encontrado."}
        username = fila["username"]

    stats = resetear_progreso_participante(username)

    with obtener_conexion_users() as conexion:
        cur = conexion.cursor()
        cur.execute(
            "DELETE FROM usuarios_registrados WHERE id = ?;",
            (int(usuario_id),),
        )
        stats["usuarios_registrados"] = cur.rowcount
        conexion.commit()

    return {"exito": True, "username": username, "stats": stats}


def listar_participantes_resumen() -> list[dict[str, Any]]:
    """Listado para /admin/participantes-ctf."""
    with obtener_conexion_users() as conexion:
        cur = conexion.cursor()
        cur.execute(
            """
            SELECT id, username, fecha_registro, ultimo_login, activo
            FROM usuarios_registrados
            ORDER BY fecha_registro DESC;
            """
        )
        filas = cur.fetchall()

    ultimos: dict[str, str] = {}
    with obtener_conexion() as conexion:
        cur = conexion.cursor()
        cur.execute(
            """
            SELECT usuario_id, MAX(fecha) AS ultimo
            FROM objetivos_completados
            GROUP BY usuario_id;
            """
        )
        for row in cur.fetchall():
            ultimos[row["usuario_id"]] = row["ultimo"] or ""

    resultado = []
    for fila in filas:
        username = fila["username"]
        resultado.append(
            {
                "id": fila["id"],
                "username": username,
                "fecha_registro": fila["fecha_registro"] or "",
                "ultimo_login": fila["ultimo_login"] or "",
                "activo": bool(fila["activo"]),
                "puntos_totales": obtener_puntos_usuario(username),
                "flags_capturadas": contar_flags_resueltas_por_usuario(username),
                "ultimo_lab_resuelto": ultimos.get(username, ""),
            }
        )
    return resultado


def detalle_progreso_participante(username: str) -> Optional[dict[str, Any]]:
    """Desglose por categoría academia + flags resueltas con nombre de reto."""
    nombre = (username or "").strip()
    if not nombre:
        return None
    with obtener_conexion_users() as conexion:
        cur = conexion.cursor()
        cur.execute(
            "SELECT id, username, fecha_registro, ultimo_login, activo "
            "FROM usuarios_registrados WHERE username = ?;",
            (nombre,),
        )
        cuenta = cur.fetchone()
    if cuenta is None:
        return None

    categorias = listar_categorias_academia(nombre)

    consulta_flags = """
    SELECT f.reto_nombre, f.puntos, oc.fecha
    FROM objetivos_completados oc
    JOIN flags f ON f.id = oc.flag_id
    WHERE oc.usuario_id = ?
    ORDER BY oc.fecha ASC;
    """
    with obtener_conexion() as conexion:
        cur = conexion.cursor()
        cur.execute(consulta_flags, (nombre,))
        flags = [dict(r) for r in cur.fetchall()]

    superlab_fase = None
    with obtener_conexion_superlab() as conexion:
        cur = conexion.cursor()
        cur.execute(
            "SELECT fase_actual, flags_capturadas, timestamp_ultima_actividad "
            "FROM superlab_progreso WHERE usuario_sesion = ?;",
            (nombre,),
        )
        sl = cur.fetchone()
        if sl:
            superlab_fase = {
                "fase_actual": sl["fase_actual"],
                "flags_capturadas": sl["flags_capturadas"],
                "ultima_actividad": sl["timestamp_ultima_actividad"],
            }

    return {
        "id": cuenta["id"],
        "username": cuenta["username"],
        "fecha_registro": cuenta["fecha_registro"] or "",
        "ultimo_login": cuenta["ultimo_login"] or "",
        "activo": bool(cuenta["activo"]),
        "puntos_totales": obtener_puntos_usuario(nombre),
        "flags_capturadas": len(flags),
        "categorias": categorias,
        "flags_detalle": flags,
        "superlab": superlab_fase,
    }
