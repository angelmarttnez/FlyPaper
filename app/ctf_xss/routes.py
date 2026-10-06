"""Blueprint lab XSS almacenado."""

from __future__ import annotations

import re

from flask import Blueprint, jsonify, redirect, render_template, request, session, url_for

from app.ctf_xss.catalogo import FLAG_RETO_01, obtener_reto
from app.ctf_xss.lab_db import (
    comentarios_pendientes,
    insertar_comentario,
    marcar_revisado_bot,
    obtener_comentario_por_token,
    estado_retos_para_usuario,
)
from app.ctf_academia.telemetria_pistas import registrar_pista_solicitada, usuario_pidio_pista
from app.ctf_xss.telemetria import registrar_intento_waf_lab
from app.database import enviar_flag_por_usuario

_CATEGORIA = "xss"

ctf_xss = Blueprint("ctf_xss", __name__, url_prefix="/objetivos/xss")

_PATRON_SCRIPT = re.compile(r"<\s*script", re.IGNORECASE)
_PATRON_ROBO = re.compile(r"/objetivos/xss/01/robo-cookie", re.IGNORECASE)


def _usuario() -> str:
    return (session.get("usuario") or "").strip()


def _exige_login():
    if not session.get("logueado") or not _usuario():
        return redirect(url_for("mostrar_login", next=request.path))
    return None


def _registrar_flag(flag: str):
    res = enviar_flag_por_usuario(_usuario(), flag)
    return res


@ctf_xss.route("/01", methods=["GET"])
def reto_01():
    den = _exige_login()
    if den:
        return den
    reto = obtener_reto(1)
    estados = {r["id"]: r for r in estado_retos_para_usuario(_usuario())}
    return render_template(
        "ctf_xss/reto_01.html",
        reto=reto,
        resuelto=bool(estados.get(1, {}).get("resuelto")),
        flag_esperada=FLAG_RETO_01,
        url_pista_endpoint=url_for("ctf_xss.reto_01_pista"),
        pista_ya_pedida=usuario_pidio_pista(_CATEGORIA, 1),
    )


@ctf_xss.route("/01/pista", methods=["GET"])
def reto_01_pista():
    """Pista pedagógica (GET + JSON), registrada en telemetría."""
    den = _exige_login()
    if den:
        return den
    reto = obtener_reto(1)
    texto = (reto.get("pista") or "").strip() if reto else ""
    meta = registrar_pista_solicitada(
        _CATEGORIA, 1, texto, registrar_log_lab=registrar_intento_waf_lab
    )
    return jsonify(
        {
            "exito": True,
            "pista": texto,
            "ya_solicitada": not meta.get("primera_vez", True),
        }
    )


@ctf_xss.route("/01/comentario", methods=["POST"])
def reto_01_comentario():
    den = _exige_login()
    if den:
        return den
    contenido = request.form.get("contenido") or request.get_json(silent=True) or {}
    if isinstance(contenido, dict):
        contenido = contenido.get("contenido", "")
    contenido = str(contenido)
    registrar_intento_waf_lab(reto_id=1, payload={"contenido": contenido}, modo_educativo=True)
    fila = insertar_comentario(_usuario(), contenido)
    robo_url = url_for(
        "ctf_xss.reto_01_robo_cookie",
        token=fila["token_robo"],
        _external=False,
    )
    if request.is_json or "application/json" in (request.headers.get("Accept") or ""):
        return jsonify(
            {
                "exito": True,
                "comentario_id": fila["id"],
                "token_robo": fila["token_robo"],
                "robo_url": robo_url,
            }
        )
    return redirect(url_for("ctf_xss.reto_01"))


@ctf_xss.route("/01/admin-revisar", methods=["POST"])
def reto_01_admin_revisar():
    """Bot moderador: detecta XSS almacenado sin ejecutar JS."""
    den = _exige_login()
    if den:
        return den
    disparados = []
    for com in comentarios_pendientes():
        cuerpo = com.get("contenido") or ""
        explotable = bool(_PATRON_SCRIPT.search(cuerpo) and _PATRON_ROBO.search(cuerpo))
        marcar_revisado_bot(int(com["id"]), explotable)
        if explotable:
            disparados.append(int(com["id"]))
    return jsonify({"exito": True, "revisados": len(disparados), "explotables": disparados})


@ctf_xss.route("/01/robo-cookie", methods=["GET"])
def reto_01_robo_cookie():
    """Robo simulado tras revisión del bot."""
    token = (request.args.get("token") or "").strip()
    com = obtener_comentario_por_token(token)
    if com is None:
        return jsonify({"exito": False, "mensaje": "Token inválido."}), 404
    if com.get("usuario_id") != _usuario():
        return jsonify({"exito": False, "mensaje": "No autorizado."}), 403
    if not int(com.get("revisado_bot") or 0):
        return jsonify(
            {"exito": False, "mensaje": "El bot aún no ha revisado tu comentario."}
        ), 403
    if not int(com.get("explotado") or 0):
        return jsonify({"exito": False, "mensaje": "Payload no aceptado por el bot."}), 403

    resultado = _registrar_flag(FLAG_RETO_01)
    if request.is_json or "application/json" in (request.headers.get("Accept") or ""):
        return jsonify({"exito": True, "flag": FLAG_RETO_01, "ranking": resultado})
    return render_template(
        "ctf_xss/flag_ok.html",
        flag=FLAG_RETO_01,
        mensaje=resultado.get("mensaje"),
    )
