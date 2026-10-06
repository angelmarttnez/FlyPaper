"""Blueprint IDOR nóminas."""

from __future__ import annotations

from flask import Blueprint, jsonify, redirect, render_template, request, session, url_for

from app.ctf_idor.catalogo import FLAG_RETO_01, obtener_reto
from app.ctf_idor.lab_db import (
    estado_retos_para_usuario,
    id_nomina_asignada_aleatoria,
    obtener_nomina,
)
from app.ctf_academia.telemetria_pistas import registrar_pista_solicitada, usuario_pidio_pista
from app.ctf_idor.telemetria import registrar_intento_waf_lab
from app.database import enviar_flag_por_usuario

_CATEGORIA = "idor"

ctf_idor = Blueprint("ctf_idor", __name__, url_prefix="/objetivos/idor")

CLAVE_SESION_IDOR = "ctf_idor_01_activo"
CLAVE_NOMINA_ASIGNADA = "ctf_idor_nomina_asignada"


def _usuario():
    return (session.get("usuario") or "").strip()


def _exige_login():
    if not session.get("logueado") or not _usuario():
        return redirect(url_for("mostrar_login", next=request.path))
    return None


def _iniciar_reto_sesion() -> int:
    if CLAVE_NOMINA_ASIGNADA not in session:
        session[CLAVE_NOMINA_ASIGNADA] = id_nomina_asignada_aleatoria()
        session[CLAVE_SESION_IDOR] = True
        session.modified = True
    return int(session[CLAVE_NOMINA_ASIGNADA])


@ctf_idor.get("/01")
def reto_01():
    den = _exige_login()
    if den:
        return den
    reto = obtener_reto(1)
    mi_id = _iniciar_reto_sesion()
    est = {r["id"]: r for r in estado_retos_para_usuario(_usuario())}
    return render_template(
        "ctf_idor/reto_01.html",
        reto=reto,
        resuelto=bool(est.get(1, {}).get("resuelto")),
        mi_nomina_id=mi_id,
        url_pista_endpoint=url_for("ctf_idor.reto_01_pista"),
        pista_ya_pedida=usuario_pidio_pista(_CATEGORIA, 1),
    )


@ctf_idor.get("/01/pista")
def reto_01_pista():
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


@ctf_idor.get("/01/nomina/<int:nomina_id>")
def reto_01_nomina(nomina_id: int):
    den = _exige_login()
    if den:
        return den
    if not session.get(CLAVE_SESION_IDOR):
        return redirect(url_for("ctf_idor.reto_01"))
    registrar_intento_waf_lab(reto_id=1, payload={"nomina_id": nomina_id})
    fila = obtener_nomina(nomina_id)
    if fila is None:
        return jsonify({"exito": False, "mensaje": "Nómina no encontrada."}), 404

    flag_obtenida = None
    if int(nomina_id) == 1:
        res = enviar_flag_por_usuario(_usuario(), FLAG_RETO_01)
        if res.get("exito"):
            flag_obtenida = FLAG_RETO_01

    if request.accept_mimetypes.best == "application/json" or request.args.get("json"):
        payload = {"exito": True, "nomina": fila}
        if flag_obtenida:
            payload["flag"] = flag_obtenida
        return jsonify(payload)

    return render_template(
        "ctf_idor/nomina.html",
        nomina=fila,
        flag=flag_obtenida,
        mi_id=session.get(CLAVE_NOMINA_ASIGNADA),
    )
