"""Telemetría Redis — IDOR."""

from __future__ import annotations

import json
from typing import Any, Optional

from flask import request, session

from app.core.detector import analizar_peticion
from app.core.ip_reputation import obtener_cliente_redis, redis_esta_disponible
from app.core.timezone_fp import marca_ahora

_CATEGORIA = "idor"
_PREFIX = "flypaper:ctf:logs:"


def identidad_alumno_sesion() -> Optional[str]:
    if session.get("logueado") is not True:
        return None
    return (session.get("usuario") or "").strip() or None


def registrar_intento_waf_lab(*, reto_id: int, payload: Any, modo_educativo: bool = True):
    user_id = identidad_alumno_sesion()
    if not user_id:
        return None
    veredicto = analizar_peticion(
        ruta=request.path,
        payload=payload,
        user_agent=request.headers.get("User-Agent", ""),
        headers=dict(request.headers),
        metodo=request.method,
        modo_educativo=modo_educativo,
    )
    entrada = {"timestamp": marca_ahora(), "tipo": veredicto.get("tipo_ataque")}
    if redis_esta_disponible() and (c := obtener_cliente_redis()):
        try:
            c.lpush(f"{_PREFIX}{user_id}:{_CATEGORIA}:{reto_id}", json.dumps(entrada))
        except Exception:
            pass
    return entrada
