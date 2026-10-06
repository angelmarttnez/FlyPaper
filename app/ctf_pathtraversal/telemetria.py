"""Telemetría Redis — Path Traversal."""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from flask import request, session

from app.core.detector import analizar_peticion
from app.core.ip_reputation import obtener_cliente_redis, redis_esta_disponible
from app.core.timezone_fp import marca_ahora

logger = logging.getLogger(__name__)

_CATEGORIA = "pathtraversal"
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
    if redis_esta_disponible() and (cliente := obtener_cliente_redis()):
        clave = f"{_PREFIX}{user_id}:{_CATEGORIA}:{int(reto_id)}"
        try:
            cliente.lpush(clave, json.dumps(entrada))
            cliente.expire(clave, 1800)
        except Exception:
            pass
    return entrada
