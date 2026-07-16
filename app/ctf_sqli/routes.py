"""
Rutas Blueprint ``ctf_sqli``: laboratorios vulnerables + verificación de quiz/flag.
"""

from __future__ import annotations

import logging
import sqlite3
from typing import Any, Optional

from flask import (
    Blueprint,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from app.ctf_sqli.catalogo import (
    SOLUCIONES_QUIZ,
    obtener_reto,
    validar_quiz,
)
from app.ctf_sqli.lab_db import (
    conexion_lab,
    estado_retos_para_usuario,
    obtener_flag_lab,
    progreso_sqli_usuario,
)
from app.ctf_sqli.telemetria import (
    identidad_alumno_sesion,
    obtener_logs_telemetria_sesion,
    registrar_intento_waf_lab,
)
from app.database import enviar_flag_por_usuario

logger = logging.getLogger(__name__)

ctf_sqli = Blueprint(
    "ctf_sqli",
    __name__,
    url_prefix="/objetivos/sqli",
)

# API de telemetría (prefijo /api/ctf) — aislada del path de labs.
ctf_api = Blueprint(
    "ctf_api",
    __name__,
    url_prefix="/api/ctf",
)

CATEGORIA_SQLI = "sqli"


def _usuario_sesion() -> str:
    return (session.get("usuario") or "").strip()


def _exige_login_json():
    if not session.get("logueado") or not _usuario_sesion():
        return jsonify({"exito": False, "mensaje": "Unauthorized"}), 401
    return None


def _pide_json() -> bool:
    """True si el cliente solicita respuesta JSON (AJAX del laboratorio)."""
    accept = (request.headers.get("Accept") or "").lower()
    xrw = (request.headers.get("X-Requested-With") or "").lower()
    return "application/json" in accept or xrw == "xmlhttprequest"


def _contexto_entrega(reto: dict[str, Any], resuelto: bool) -> dict[str, Any]:
    quiz = SOLUCIONES_QUIZ.get(reto["id"], {})
    return {
        "reto": reto,
        "resuelto": resuelto,
        "p3_opciones": quiz.get("p3_opciones", []),
        "progreso": progreso_sqli_usuario(_usuario_sesion()),
        "categoria_ctf": CATEGORIA_SQLI,
    }


# —— Laboratorio 01: Auth Bypass ——


def _login_vulnerable_reto_01(username: str, password: str) -> tuple[Optional[dict], Optional[str]]:
    """
    Login deliberadamente vulnerable (concatenación SQL).

    Returns:
        (fila_usuario|None, error_sql|None)
    """
    # VULNERABLE A PROPÓSITO — academia CTF (WAF perimetral exento; telemetría educativa sí).
    sql = (
        f"SELECT id, username, password, role, note FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )
    try:
        with conexion_lab(1) as conexion:
            cursor = conexion.cursor()
            cursor.execute(sql)
            fila = cursor.fetchone()
            return (dict(fila) if fila else None, None)
    except sqlite3.Error as exc:
        return None, str(exc)


# —— Laboratorio 02: UNION Based ——


def _buscar_productos_vulnerable(query: str) -> tuple[list[dict], Optional[str], str]:
    """
    Búsqueda UNION-friendly (3 columnas visibles: id, name, price).

    Returns:
        (filas, error_sql, sql_ejecutado)
    """
    sql = (
        f"SELECT id, name, price FROM products "
        f"WHERE name LIKE '%{query}%' OR category LIKE '%{query}%'"
    )
    try:
        with conexion_lab(2) as conexion:
            cursor = conexion.cursor()
            cursor.execute(sql)
            columnas = [d[0] for d in cursor.description] if cursor.description else []
            filas = []
            for row in cursor.fetchall():
                if columnas:
                    filas.append({columnas[i]: row[i] for i in range(len(columnas))})
                else:
                    filas.append(dict(row))
            return filas, None, sql
    except sqlite3.Error as exc:
        return [], str(exc), sql


@ctf_sqli.get("/<int:reto_id>")
def ver_reto(reto_id: int):
    """Vista dual: laboratorio real + panel de entrega SOC + consola WAF."""
    reto = obtener_reto(reto_id)
    if reto is None:
        flash("Reto no encontrado.", "error")
        return redirect(url_for("pagina_objetivos"))

    estados = {e["id"]: e for e in estado_retos_para_usuario(_usuario_sesion())}
    resuelto = bool(estados.get(reto_id, {}).get("resuelto"))
    ctx = _contexto_entrega(reto, resuelto)

    if not reto.get("activo"):
        return render_template("ctf_sqli/reto_proximamente.html", **ctx)

    if reto_id == 1:
        return render_template(
            "ctf_sqli/reto_01.html",
            login_resultado=None,
            error_sql=None,
            **ctx,
        )
    if reto_id == 2:
        return render_template(
            "ctf_sqli/reto_02.html",
            resultados=[],
            error_sql=None,
            query="",
            **ctx,
        )

    return render_template("ctf_sqli/reto_proximamente.html", **ctx)


@ctf_sqli.post("/1/lab/login")
def lab_01_login():
    """POST del formulario de login vulnerable (reto 01) + telemetría WAF."""
    reto = obtener_reto(1)
    if not reto:
        return redirect(url_for("pagina_objetivos"))

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # Telemetría educativa: no satura el SOC; solo Redis efímero del alumno.
    registrar_intento_waf_lab(
        categoria=CATEGORIA_SQLI,
        reto_id=1,
        payload={"username": username, "password": password},
        ruta="/objetivos/sqli/1/lab/login",
        metodo="POST",
    )

    usuario_fila, error_sql = _login_vulnerable_reto_01(username, password)

    estados = {e["id"]: e for e in estado_retos_para_usuario(_usuario_sesion())}
    ctx = _contexto_entrega(reto, bool(estados.get(1, {}).get("resuelto")))

    mensaje_exito = None
    if usuario_fila and (usuario_fila.get("role") or "").lower() in (
        "administrator",
        "admin",
    ):
        mensaje_exito = (
            "Acceso de administrador concedido. Revisa el campo «note» "
            "del perfil: contiene material sensible del laboratorio."
        )

    if _pide_json():
        return jsonify(
            {
                "exito": True,
                "login_resultado": usuario_fila,
                "error_sql": error_sql,
                "mensaje_exito": mensaje_exito,
                "form_username": username,
            }
        )

    return render_template(
        "ctf_sqli/reto_01.html",
        login_resultado=usuario_fila,
        error_sql=error_sql,
        mensaje_exito=mensaje_exito,
        form_username=username,
        **ctx,
    )


@ctf_sqli.post("/2/lab/search")
def lab_02_search():
    """POST del buscador UNION vulnerable (reto 02) + telemetría WAF."""
    reto = obtener_reto(2)
    if not reto:
        return redirect(url_for("pagina_objetivos"))

    query = request.form.get("query", "")

    registrar_intento_waf_lab(
        categoria=CATEGORIA_SQLI,
        reto_id=2,
        payload={"query": query},
        ruta="/objetivos/sqli/2/lab/search",
        metodo="POST",
    )

    resultados, error_sql, _sql = _buscar_productos_vulnerable(query)

    estados = {e["id"]: e for e in estado_retos_para_usuario(_usuario_sesion())}
    ctx = _contexto_entrega(reto, bool(estados.get(2, {}).get("resuelto")))

    if _pide_json():
        return jsonify(
            {
                "exito": True,
                "resultados": resultados,
                "error_sql": error_sql,
                "query": query,
            }
        )

    return render_template(
        "ctf_sqli/reto_02.html",
        resultados=resultados,
        error_sql=error_sql,
        query=query,
        **ctx,
    )


@ctf_sqli.post("/verify/<int:reto_id>")
def verificar_entrega(reto_id: int):
    """
    Valida cuestionario (3 preguntas) + flag y otorga puntos al alumno.

    Acepta form-urlencoded o JSON.
    """
    denegado = _exige_login_json()
    if denegado is not None:
        return denegado

    reto = obtener_reto(reto_id)
    if reto is None:
        return jsonify({"exito": False, "mensaje": "Reto no encontrado"}), 404
    if not reto.get("activo"):
        return jsonify(
            {"exito": False, "mensaje": "Este laboratorio aún no está disponible."}
        ), 403

    if request.is_json:
        cuerpo = request.get_json(silent=True) or {}
        p1 = cuerpo.get("p1", "")
        p2 = cuerpo.get("p2", "")
        p3 = cuerpo.get("p3", "")
        flag = cuerpo.get("flag", "")
    else:
        p1 = request.form.get("p1", "")
        p2 = request.form.get("p2", "")
        p3 = request.form.get("p3", "")
        flag = request.form.get("flag", "")

    ok_quiz, mensaje_quiz = validar_quiz(reto_id, p1, p2, p3)
    if not ok_quiz:
        return jsonify({"exito": False, "mensaje": mensaje_quiz, "fase": "quiz"}), 400

    flag_lab = obtener_flag_lab(reto_id)
    flag_limpia = (flag or "").strip()
    if flag_limpia != flag_lab:
        return jsonify(
            {
                "exito": False,
                "mensaje": "Flag incorrecta. El cuestionario es válido; revisa la bandera.",
                "fase": "flag",
            }
        ), 400

    resultado = enviar_flag_por_usuario(_usuario_sesion(), flag_limpia)
    progreso = progreso_sqli_usuario(_usuario_sesion())

    if not resultado.get("exito"):
        return jsonify(
            {
                "exito": False,
                "mensaje": resultado.get("mensaje") or "No se pudo registrar la flag",
                "fase": "registro",
            }
        ), 400

    return jsonify(
        {
            "exito": True,
            "mensaje": resultado.get("mensaje") or "¡Reto completado!",
            "puntos": resultado.get("puntos"),
            "reto_nombre": resultado.get("reto_nombre"),
            "ya_resuelta": bool(resultado.get("ya_resuelta")),
            "progreso": progreso,
        }
    )


@ctf_api.get("/telemetria/<categoria>/<int:reto_id>")
def api_telemetria_waf(categoria: str, reto_id: int):
    """
    Consola de telemetría WAF del alumno autenticado.

    Seguridad anti-IDOR:
    - Requiere sesión autenticada.
    - El user_id se toma SOLO de la sesión Flask (nunca de query/body).
    - No existe parámetro ``user_id`` aceptado en esta ruta.
    """
    # Rechazar explícitamente cualquier intento de suplantar identidad vía query.
    if "user_id" in request.args or "usuario" in request.args:
        return jsonify(
            {
                "exito": False,
                "mensaje": "Parámetro de identidad no permitido (anti-IDOR).",
            }
        ), 400

    if identidad_alumno_sesion() is None:
        return jsonify({"exito": False, "mensaje": "Unauthorized"}), 401

    cat = (categoria or "").strip().lower()
    if cat not in ("sqli", "xss", "lfi", "rce"):
        return jsonify({"exito": False, "mensaje": "Categoría no válida"}), 400

    if reto_id < 1 or reto_id > 99:
        return jsonify({"exito": False, "mensaje": "Reto no válido"}), 400

    logs = obtener_logs_telemetria_sesion(cat, reto_id)
    return jsonify(
        {
            "exito": True,
            "categoria": cat,
            "reto_id": reto_id,
            "intentos": logs,
            "total": len(logs),
        }
    )
