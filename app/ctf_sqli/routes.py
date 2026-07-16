"""
Rutas Blueprint ``ctf_sqli``: laboratorios vulnerables + verificación de quiz/flag.
"""

from __future__ import annotations

import logging
import re
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
    CUESTIONARIOS,
    obtener_cuestionario,
    obtener_pregunta,
    obtener_reto,
    validar_paso,
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

# API de telemetría / pasos de quiz (prefijo /api/ctf).
ctf_api = Blueprint(
    "ctf_api",
    __name__,
    url_prefix="/api/ctf",
)

CATEGORIA_SQLI = "sqli"
CLAVE_PROGRESO_CTF = "ctf_progress"


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


def _clave_progreso_reto(reto_id: int) -> str:
    return f"sqli:{int(reto_id)}"


def _leer_progreso_quiz(reto_id: int) -> dict[str, Any]:
    """Estado del cuestionario progresivo en sesión (por reto)."""
    raiz = session.get(CLAVE_PROGRESO_CTF) or {}
    if not isinstance(raiz, dict):
        raiz = {}
    bruto = raiz.get(_clave_progreso_reto(reto_id)) or {}
    if not isinstance(bruto, dict):
        bruto = {}
    completadas = bruto.get("completadas") or []
    if not isinstance(completadas, list):
        completadas = []
    respuestas = bruto.get("respuestas") or {}
    if not isinstance(respuestas, dict):
        respuestas = {}
    return {
        "completadas": [str(x) for x in completadas],
        "respuestas": {str(k): str(v) for k, v in respuestas.items()},
    }


def _guardar_progreso_quiz(reto_id: int, progreso: dict[str, Any]) -> None:
    """Persiste el progreso del quiz en la sesión Flask cifrada."""
    raiz = session.get(CLAVE_PROGRESO_CTF) or {}
    if not isinstance(raiz, dict):
        raiz = {}
    raiz[_clave_progreso_reto(reto_id)] = {
        "completadas": list(progreso.get("completadas") or []),
        "respuestas": dict(progreso.get("respuestas") or {}),
    }
    session[CLAVE_PROGRESO_CTF] = raiz
    session.modified = True


def _quiz_teorico_completo(reto_id: int) -> bool:
    """True si la sesión marca las 5 preguntas del reto como superadas."""
    progreso = _leer_progreso_quiz(reto_id)
    ids_ok = set(progreso.get("completadas") or [])
    preguntas = CUESTIONARIOS.get(int(reto_id)) or []
    if len(preguntas) != 5:
        return False
    return all(str(p.get("id")) in ids_ok for p in preguntas)


def _progreso_publico_quiz(reto_id: int) -> dict[str, Any]:
    """Datos seguros para hidratar el frontend (sin soluciones)."""
    progreso = _leer_progreso_quiz(reto_id)
    completadas = progreso.get("completadas") or []
    paso_actual = len(completadas) + 1
    if paso_actual > 5:
        paso_actual = 5
    return {
        "completadas": completadas,
        "respuestas": progreso.get("respuestas") or {},
        "paso_actual": paso_actual,
        "quiz_completo": _quiz_teorico_completo(reto_id),
    }


def _contexto_entrega(reto: dict[str, Any], resuelto: bool) -> dict[str, Any]:
    """Contexto Jinja: reto, progreso CTF y estado del quiz progresivo."""
    return {
        "reto": reto,
        "resuelto": resuelto,
        "preguntas_quiz": obtener_cuestionario(reto["id"]),
        "quiz_progreso": _progreso_publico_quiz(reto["id"]),
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


# —— Laboratorio 03: Bypass de filtro local ——


def _filtro_local_defectuoso(payload: str) -> str:
    """
    Sanitización deliberadamente incompleta (CTF).

    Elimina UNA sola ocurrencia de UNION y de SELECT (case-insensitive),
    sin bucle recursivo. Bypass típico: ``UNUNIONION`` / ``SELSELECTECT``.
    """
    texto = payload or ""
    texto = re.sub(r"(?i)UNION", "", texto, count=1)
    texto = re.sub(r"(?i)SELECT", "", texto, count=1)
    return texto


def _consultar_articulo_reto_03(id_param: str) -> tuple[list[dict], Optional[str], str, str]:
    """
    Consulta vulnerable con filtro local previo.

    Returns:
        (filas, error_sql, sql_ejecutado, id_tras_filtro)
    """
    id_filtrado = _filtro_local_defectuoso(id_param)
    # VULNERABLE A PROPÓSITO — concatenación tras filtro incompleto.
    sql = (
        f"SELECT id, title, body FROM articles WHERE id = {id_filtrado}"
    )
    try:
        with conexion_lab(3) as conexion:
            cursor = conexion.cursor()
            cursor.execute(sql)
            columnas = [d[0] for d in cursor.description] if cursor.description else []
            filas = []
            for row in cursor.fetchall():
                if columnas:
                    filas.append({columnas[i]: row[i] for i in range(len(columnas))})
                else:
                    filas.append(dict(row))
            return filas, None, sql, id_filtrado
    except sqlite3.Error as exc:
        return [], str(exc), sql, id_filtrado


# —— Laboratorio 04: Bypass WAF real ——


def _consultar_item_reto_04(id_param: str) -> tuple[list[dict], Optional[str], str]:
    """
    Consulta vulnerable sin filtro local (el WAF perimetral es el adversario).

    Returns:
        (filas, error_sql, sql_ejecutado)
    """
    sql = f"SELECT id, name, price FROM items WHERE id = {id_param}"
    try:
        with conexion_lab(4) as conexion:
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
    if reto_id == 3:
        return render_template(
            "ctf_sqli/reto_03.html",
            resultados=[],
            error_sql=None,
            id_param="",
            id_filtrado="",
            **ctx,
        )
    if reto_id == 4:
        return render_template(
            "ctf_sqli/reto_04.html",
            resultados=[],
            error_sql=None,
            id_param="",
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


@ctf_sqli.route("/3/lab", methods=["GET", "POST"])
def lab_03_articulo():
    """
    Lab 03: parámetro ``id`` con filtro local defectuoso (WAF global exento).

    Acepta GET ?id=… o POST form ``id`` (AJAX / formulario).
    """
    reto = obtener_reto(3)
    if not reto:
        return redirect(url_for("pagina_objetivos"))

    if request.method == "POST":
        id_param = request.form.get("id", "")
    else:
        id_param = request.args.get("id", "")

    registrar_intento_waf_lab(
        categoria=CATEGORIA_SQLI,
        reto_id=3,
        payload={"id": id_param},
        ruta="/objetivos/sqli/3/lab",
        metodo=request.method,
        modo_educativo=True,
    )

    resultados: list[dict] = []
    error_sql = None
    id_filtrado = ""
    if id_param != "":
        resultados, error_sql, _sql, id_filtrado = _consultar_articulo_reto_03(id_param)

    estados = {e["id"]: e for e in estado_retos_para_usuario(_usuario_sesion())}
    ctx = _contexto_entrega(reto, bool(estados.get(3, {}).get("resuelto")))

    if _pide_json():
        return jsonify(
            {
                "exito": True,
                "resultados": resultados,
                "error_sql": error_sql,
                "id": id_param,
                "id_filtrado": id_filtrado,
            }
        )

    return render_template(
        "ctf_sqli/reto_03.html",
        resultados=resultados,
        error_sql=error_sql,
        id_param=id_param,
        id_filtrado=id_filtrado,
        **ctx,
    )


@ctf_sqli.route("/4/lab", methods=["GET", "POST"])
def lab_04_item():
    """
    Lab 04: parámetro ``id`` con WAF real activo (riesgo Redis + Jail).

    Payloads genéricos detectados suman riesgo; ofuscación puede pasar en sigilo.
    """
    reto = obtener_reto(4)
    if not reto:
        return redirect(url_for("pagina_objetivos"))

    if request.method == "POST":
        id_param = request.form.get("id", "")
    else:
        id_param = request.args.get("id", "")

    # Telemetría con veredicto REAL (modo_educativo=False implícito por reto 4).
    registrar_intento_waf_lab(
        categoria=CATEGORIA_SQLI,
        reto_id=4,
        payload={"id": id_param},
        ruta="/objetivos/sqli/4/lab",
        metodo=request.method,
        modo_educativo=False,
    )

    resultados: list[dict] = []
    error_sql = None
    if id_param != "":
        resultados, error_sql, _sql = _consultar_item_reto_04(id_param)

    estados = {e["id"]: e for e in estado_retos_para_usuario(_usuario_sesion())}
    ctx = _contexto_entrega(reto, bool(estados.get(4, {}).get("resuelto")))

    if _pide_json():
        return jsonify(
            {
                "exito": True,
                "resultados": resultados,
                "error_sql": error_sql,
                "id": id_param,
            }
        )

    return render_template(
        "ctf_sqli/reto_04.html",
        resultados=resultados,
        error_sql=error_sql,
        id_param=id_param,
        **ctx,
    )


@ctf_sqli.post("/verify/<int:reto_id>")
def verificar_entrega(reto_id: int):
    """
    Entrega final: solo acepta la flag si el quiz teórico (5/5) está
    completado en la sesión del servidor.
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

    if not _quiz_teorico_completo(reto_id):
        return jsonify(
            {
                "exito": False,
                "mensaje": (
                    "Debes completar las 5 preguntas teóricas paso a paso "
                    "antes de entregar la flag."
                ),
                "fase": "quiz",
            }
        ), 403

    # Defensa en profundidad: revalidar respuestas guardadas en sesión.
    progreso = _leer_progreso_quiz(reto_id)
    ok_quiz, mensaje_quiz, pregunta_fallida = validar_quiz(
        reto_id, progreso.get("respuestas") or {}
    )
    if not ok_quiz:
        return jsonify(
            {
                "exito": False,
                "mensaje": mensaje_quiz or "Progreso de quiz inválido; reinicia el cuestionario.",
                "fase": "quiz",
                "pregunta": pregunta_fallida,
            }
        ), 400

    if request.is_json:
        cuerpo = request.get_json(silent=True) or {}
    else:
        cuerpo = request.form.to_dict(flat=True)

    flag = cuerpo.get("flag", "")
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
    progreso_pts = progreso_sqli_usuario(_usuario_sesion())

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
            "progreso": progreso_pts,
        }
    )


@ctf_api.post("/verify-step")
def api_verify_step():
    """
    Valida un único paso del cuestionario progresivo (zero-leak).

    Body JSON: ``reto_id``, ``pregunta_id``, ``respuesta``.
    Respuesta: ``status`` correct|incorrect, ``next_step``, ``hint`` (sin soluciones).
    """
    denegado = _exige_login_json()
    if denegado is not None:
        return denegado

    cuerpo = request.get_json(silent=True) or {}
    try:
        reto_id = int(cuerpo.get("reto_id"))
    except (TypeError, ValueError):
        return jsonify({"status": "incorrect", "hint": "reto_id inválido."}), 400

    pregunta_id = str(cuerpo.get("pregunta_id") or "").strip().lower()
    respuesta = cuerpo.get("respuesta", "")
    if isinstance(respuesta, (int, float)):
        respuesta = str(respuesta)
    else:
        respuesta = str(respuesta or "")

    reto = obtener_reto(reto_id)
    if reto is None or not reto.get("activo"):
        return jsonify({"status": "incorrect", "hint": "Reto no disponible."}), 404

    hallado = obtener_pregunta(reto_id, pregunta_id)
    if hallado is None:
        return jsonify({"status": "incorrect", "hint": "Pregunta no válida."}), 400

    indice, _preg = hallado
    paso = indice + 1
    progreso = _leer_progreso_quiz(reto_id)
    completadas = progreso.get("completadas") or []

    # Orden estricto: solo se puede validar el siguiente paso pendiente.
    esperadas = [str(p["id"]) for p in (CUESTIONARIOS.get(reto_id) or [])]
    num_hechas = len(completadas)
    if pregunta_id in completadas:
        # Idempotente: ya estaba correcta.
        siguiente = paso + 1 if paso < 5 else None
        return jsonify(
            {
                "status": "correct",
                "next_step": siguiente,
                "hint": "",
                "step": paso,
                "total": 5,
                "quiz_completo": num_hechas >= 5,
                "already_done": True,
            }
        )

    if num_hechas != indice:
        return jsonify(
            {
                "status": "incorrect",
                "hint": f"Debes completar antes la pregunta {num_hechas + 1}.",
                "next_step": None,
                "step": paso,
                "total": 5,
            }
        ), 400

    if esperadas and pregunta_id != esperadas[indice]:
        return jsonify(
            {"status": "incorrect", "hint": "Orden de preguntas inválido."}
        ), 400

    resultado = validar_paso(reto_id, pregunta_id, respuesta)
    if resultado.get("status") == "correct":
        completadas = list(completadas) + [pregunta_id]
        respuestas = dict(progreso.get("respuestas") or {})
        respuestas[pregunta_id] = respuesta.strip()
        _guardar_progreso_quiz(
            reto_id,
            {"completadas": completadas, "respuestas": respuestas},
        )
        resultado["quiz_completo"] = len(completadas) >= 5

    # Contrato zero-leak: solo status / next_step / hint (+ metadatos de paso).
    return jsonify(
        {
            "status": resultado.get("status"),
            "next_step": resultado.get("next_step"),
            "hint": resultado.get("hint") or "",
            "step": resultado.get("step"),
            "total": resultado.get("total", 5),
            "quiz_completo": bool(resultado.get("quiz_completo")),
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
