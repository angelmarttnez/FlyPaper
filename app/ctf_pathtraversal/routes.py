"""Blueprint Path Traversal."""

from __future__ import annotations

from flask import Blueprint, Response, jsonify, redirect, render_template, request, session, url_for

from app.ctf_academia.telemetria_pistas import registrar_pista_solicitada, usuario_pidio_pista
from app.ctf_pathtraversal.catalogo import FLAG_RETO_01, FLAG_RETO_02, flag_por_reto_id, obtener_reto
from app.ctf_pathtraversal.lab_db import (
    contenido_es_flag,
    estado_retos_para_usuario,
    resolver_descarga_vulnerable,
    resolver_descarga_vulnerable_filtro_02,
    valor_file_crudo_en_query,
)
from app.ctf_pathtraversal.telemetria import registrar_intento_waf_lab

ctf_pathtraversal = Blueprint(
    "ctf_pathtraversal", __name__, url_prefix="/objetivos/pathtraversal"
)

_CATEGORIA = "pathtraversal"


def _usuario():
    return (session.get("usuario") or "").strip()


def _exige_login():
    if not session.get("logueado") or not _usuario():
        return redirect(url_for("mostrar_login", next=request.path))
    return None


def _respuesta_pista(reto_id: int):
    """Entrega la pista del catálogo y la registra en telemetría."""
    den = _exige_login()
    if den:
        return den
    reto = obtener_reto(reto_id)
    if reto is None:
        return jsonify({"exito": False, "mensaje": "Reto no encontrado."}), 404
    texto = (reto.get("pista") or "").strip()
    meta = registrar_pista_solicitada(
        _CATEGORIA,
        reto_id,
        texto,
        registrar_log_lab=registrar_intento_waf_lab,
    )
    return jsonify(
        {
            "exito": True,
            "pista": texto,
            "ya_solicitada": not meta.get("primera_vez", True),
        }
    )


@ctf_pathtraversal.get("/01")
def reto_01():
    den = _exige_login()
    if den:
        return den
    reto = obtener_reto(1)
    est = {r["id"]: r for r in estado_retos_para_usuario(_usuario())}
    return render_template(
        "ctf_pathtraversal/reto_01.html",
        reto=reto,
        resuelto=bool(est.get(1, {}).get("resuelto")),
        url_pista_endpoint=url_for("ctf_pathtraversal.reto_01_pista"),
        pista_ya_pedida=usuario_pidio_pista(_CATEGORIA, 1),
    )


@ctf_pathtraversal.get("/01/pista")
def reto_01_pista():
    return _respuesta_pista(1)


@ctf_pathtraversal.get("/01/descargar")
def reto_01_descargar():
    den = _exige_login()
    if den:
        return den
    nombre = request.args.get("file", "")
    registrar_intento_waf_lab(reto_id=1, payload={"file": nombre})
    ruta, error = resolver_descarga_vulnerable(nombre)
    if error or ruta is None:
        return Response(error or "Error", status=404, mimetype="text/plain; charset=utf-8")
    contenido = ruta.read_text(encoding="utf-8", errors="replace")
    if contenido_es_flag(contenido, 1):
        from app.database import enviar_flag_por_usuario

        enviar_flag_por_usuario(_usuario(), FLAG_RETO_01)
    return Response(contenido, mimetype="text/plain; charset=utf-8")


@ctf_pathtraversal.get("/02")
def reto_02():
    den = _exige_login()
    if den:
        return den
    reto = obtener_reto(2)
    est = {r["id"]: r for r in estado_retos_para_usuario(_usuario())}
    return render_template(
        "ctf_pathtraversal/reto_02.html",
        reto=reto,
        resuelto=bool(est.get(2, {}).get("resuelto")),
        url_pista_endpoint=url_for("ctf_pathtraversal.reto_02_pista"),
        pista_ya_pedida=usuario_pidio_pista(_CATEGORIA, 2),
    )


@ctf_pathtraversal.get("/02/pista")
def reto_02_pista():
    return _respuesta_pista(2)


@ctf_pathtraversal.get("/02/descargar")
def reto_02_descargar():
    den = _exige_login()
    if den:
        return den
    nombre = request.args.get("file", "")
    crudo = valor_file_crudo_en_query(request.environ.get("QUERY_STRING", ""))
    registrar_intento_waf_lab(reto_id=2, payload={"file": nombre, "file_crudo": crudo})
    ruta, error, status_filtro = resolver_descarga_vulnerable_filtro_02(nombre, crudo)
    if status_filtro == 400:
        return Response(error or "Bloqueado", status=400, mimetype="text/plain; charset=utf-8")
    if error or ruta is None:
        return Response(error or "Error", status=404, mimetype="text/plain; charset=utf-8")
    contenido = ruta.read_text(encoding="utf-8", errors="replace")
    flag = flag_por_reto_id(2)
    if flag and contenido_es_flag(contenido, 2):
        from app.database import enviar_flag_por_usuario

        enviar_flag_por_usuario(_usuario(), FLAG_RETO_02)
    return Response(contenido, mimetype="text/plain; charset=utf-8")
