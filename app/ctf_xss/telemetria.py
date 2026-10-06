"""Telemetría Redis del lab XSS (anti-IDOR por sesión)."""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from flask import request, session

from app.core.detector import analizar_peticion, normalizar_input_evasion
from app.core.ip_reputation import obtener_cliente_redis, redis_esta_disponible
from app.core.timezone_fp import marca_ahora

logger = logging.getLogger(__name__)

_PREFIX = "flypaper:ctf:logs:"
_MAX = 15
_TTL = 30 * 60
_CATEGORIA = "xss"


def identidad_alumno_sesion() -> Optional[str]:
    if session.get("logueado") is not True:
        return None
    bruto = session.get("usuario") or session.get("user_id") or ""
    return str(bruto).strip() or None


def clave_telemetria(user_id: str, reto_id: int) -> str:
    seguro = "".join(c if c.isalnum() or c in "._@+-" else "_" for c in user_id)[:120]
    return f"{_PREFIX}{seguro}:{_CATEGORIA}:{int(reto_id)}"


def registrar_intento_waf_lab(
    *,
    reto_id: int,
    payload: Any,
    ruta: Optional[str] = None,
    metodo: Optional[str] = None,
    modo_educativo: bool = True,
) -> Optional[dict[str, Any]]:
    user_id = identidad_alumno_sesion()
    if not user_id:
        return None
    try:
        veredicto = analizar_peticion(
            ruta=ruta or request.path,
            payload=payload,
            user_agent=request.headers.get("User-Agent", ""),
            headers=dict(request.headers),
            metodo=(metodo or request.method or "POST").upper(),
            modo_educativo=modo_educativo,
        )
    except Exception as exc:
        logger.error("Telemetría XSS: %s", exc)
        return None

    entrada = {
        "timestamp": marca_ahora(),
        "categoria": _CATEGORIA,
        "reto_id": int(reto_id),
        "payload_crudo": str(payload)[:800],
        "ataque_detectado": bool(veredicto.get("ataque_detectado")),
        "tipo_ataque": veredicto.get("tipo_ataque"),
        "gravedad": veredicto.get("gravedad"),
    }
    if not redis_esta_disponible():
        return entrada
    cliente = obtener_cliente_redis()
    if not cliente:
        return entrada
    try:
        clave = clave_telemetria(user_id, reto_id)
        pipe = cliente.pipeline()
        pipe.lpush(clave, json.dumps(entrada, ensure_ascii=False))
        pipe.ltrim(clave, 0, _MAX - 1)
        pipe.expire(clave, _TTL)
        pipe.execute()
    except Exception as exc:
        logger.warning("Telemetría XSS Redis: %s", exc)
    return entrada
