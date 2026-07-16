"""
Telemetría WAF efímera por alumno (Redis) — Zero-Trust / anti-IDOR.

Cada intento de laboratorio se analiza con ``analizar_peticion(modo_educativo=True)``
y se guarda solo bajo la clave del usuario de la sesión Flask. Nunca se acepta
``user_id`` desde query string ni cuerpo de petición.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Optional

from flask import request, session

from app.core.detector import analizar_peticion, normalizar_input_evasion
from app.core.ip_reputation import obtener_cliente_redis, redis_esta_disponible
from app.core.timezone_fp import marca_ahora

logger = logging.getLogger(__name__)

# Clave: flypaper:ctf:logs:{user_id}:{categoria}:{reto_id}
_PREFIX_CTF_LOGS = "flypaper:ctf:logs:"
MAX_LOGS_POR_LAB = 15
TTL_LOGS_SEG = 30 * 60  # 30 minutos

_CATEGORIAS_VALIDAS = frozenset({"sqli", "xss", "lfi", "rce"})
_PATRON_USER_SAFE = re.compile(r"[^a-zA-Z0-9._@+\-]+")


def identidad_alumno_sesion() -> Optional[str]:
    """
    Identidad del alumno exclusivamente desde la sesión cifrada de Flask.

    En FlyPaper el portal público usa ``session['usuario']`` como user_id.
    No lee parámetros del cliente (anti-IDOR).
    """
    if session.get("logueado") is not True:
        return None
    # Preferencia: usuario del portal; user_id solo si existiera en el futuro.
    bruto = session.get("usuario") or session.get("user_id") or ""
    identidad = str(bruto).strip()
    return identidad or None


def _sanitizar_user_id_clave(user_id: str) -> str:
    """Normaliza el user_id para usarlo de forma segura como segmento de clave Redis."""
    limpio = _PATRON_USER_SAFE.sub("_", (user_id or "").strip())
    return limpio[:120] or "anon"


def _sanitizar_categoria(categoria: str) -> Optional[str]:
    cat = (categoria or "").strip().lower()
    if cat not in _CATEGORIAS_VALIDAS:
        return None
    return cat


def clave_telemetria(user_id: str, categoria: str, reto_id: int) -> str:
    """Construye la clave Redis aislada por alumno / categoría / reto."""
    return (
        f"{_PREFIX_CTF_LOGS}"
        f"{_sanitizar_user_id_clave(user_id)}:"
        f"{_sanitizar_categoria(categoria) or 'sqli'}:"
        f"{int(reto_id)}"
    )


def _truncar(texto: str, max_len: int = 800) -> str:
    t = texto or ""
    if len(t) <= max_len:
        return t
    return t[: max_len - 1] + "…"


def registrar_intento_waf_lab(
    *,
    categoria: str,
    reto_id: int,
    payload: Any,
    ruta: Optional[str] = None,
    metodo: Optional[str] = None,
    modo_educativo: Optional[bool] = None,
) -> Optional[dict[str, Any]]:
    """
    Analiza el payload y lo empuja a Redis (LPUSH + LTRIM + EXPIRE).

    ``modo_educativo``: por defecto True en labs 01–03 (fuerza firmas pese a
    whitelist). En el reto 04 se fuerza False para reflejar el WAF real.

    Returns:
        dict del log insertado, o None si no hay sesión / Redis caído.
    """
    user_id = identidad_alumno_sesion()
    if not user_id:
        return None

    cat = _sanitizar_categoria(categoria)
    if not cat:
        logger.warning("Telemetría CTF: categoría inválida %r", categoria)
        return None

    # Reto 04: consola = veredicto real del perímetro (sin modo educativo).
    if modo_educativo is None:
        modo_educativo = int(reto_id) != 4

    ruta_analisis = ruta or request.path or f"/objetivos/{cat}/{reto_id}"
    metodo_analisis = (metodo or request.method or "POST").upper()
    ua = request.headers.get("User-Agent", "")
    headers = dict(request.headers)

    try:
        veredicto = analizar_peticion(
            ruta=ruta_analisis,
            payload=payload,
            user_agent=ua,
            headers=headers,
            metodo=metodo_analisis,
            modo_educativo=bool(modo_educativo),
        )
    except Exception as exc:
        logger.error("Telemetría CTF: fallo analizar_peticion — %s", exc)
        return None

    payload_texto = ""
    if isinstance(payload, dict):
        try:
            payload_texto = json.dumps(payload, ensure_ascii=False)
        except (TypeError, ValueError):
            payload_texto = str(payload)
    else:
        payload_texto = str(payload or "")

    payload_norm = veredicto.get("payload_normalizado") or normalizar_input_evasion(
        payload_texto
    )

    entrada = {
        "timestamp": marca_ahora(),
        "categoria": cat,
        "reto_id": int(reto_id),
        "ruta": ruta_analisis,
        "metodo": metodo_analisis,
        "payload_crudo": _truncar(payload_texto),
        "payload_normalizado": _truncar(str(payload_norm)),
        "ataque_detectado": bool(veredicto.get("ataque_detectado")),
        "tipo_ataque": veredicto.get("tipo_ataque") or "Tráfico Normal",
        "gravedad": veredicto.get("gravedad") or "Normal",
        "firma_coincidente": veredicto.get("firma_coincidente") or "",
    }

    if not redis_esta_disponible():
        logger.debug("Telemetría CTF: Redis no disponible — log no persistido.")
        return entrada

    cliente = obtener_cliente_redis()
    if not cliente:
        return entrada

    clave = clave_telemetria(user_id, cat, reto_id)
    try:
        pipe = cliente.pipeline()
        pipe.lpush(clave, json.dumps(entrada, ensure_ascii=False))
        pipe.ltrim(clave, 0, MAX_LOGS_POR_LAB - 1)
        pipe.expire(clave, TTL_LOGS_SEG)
        pipe.execute()
    except Exception as exc:
        logger.warning("Telemetría CTF: error Redis LPUSH (%s) — %s", clave, exc)

    return entrada


def obtener_logs_telemetria_sesion(
    categoria: str, reto_id: int
) -> list[dict[str, Any]]:
    """
    Lee los logs del alumno autenticado para categoría/reto.

    La identidad sale solo de la sesión; imposible consultar otra clave por diseño.
    """
    user_id = identidad_alumno_sesion()
    if not user_id:
        return []

    cat = _sanitizar_categoria(categoria)
    if not cat:
        return []

    if not redis_esta_disponible():
        return []

    cliente = obtener_cliente_redis()
    if not cliente:
        return []

    clave = clave_telemetria(user_id, cat, reto_id)
    try:
        raw_list = cliente.lrange(clave, 0, MAX_LOGS_POR_LAB - 1) or []
    except Exception as exc:
        logger.warning("Telemetría CTF: error LRANGE — %s", exc)
        return []

    resultado: list[dict[str, Any]] = []
    for raw in raw_list:
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict):
                # Defensa en profundidad: nunca devolver campos de identidad.
                obj.pop("user_id", None)
                obj.pop("usuario", None)
                resultado.append(obj)
        except (TypeError, json.JSONDecodeError):
            continue
    return resultado
