"""
Registro de pistas pedidas (Redis) — mismo criterio anti-IDOR que telemetría CTF.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Callable, Optional

from app.core.ip_reputation import obtener_cliente_redis, redis_esta_disponible
from app.core.timezone_fp import marca_ahora
from app.ctf_sqli.telemetria import identidad_alumno_sesion

logger = logging.getLogger(__name__)

_PREFIX_PISTA = "flypaper:ctf:pista:"
_TTL_PISTA_SEG = 30 * 24 * 3600  # 30 días
_PATRON_USER_SAFE = re.compile(r"[^a-zA-Z0-9._@+\-]+")


def _clave_pista(user_id: str, categoria: str, reto_id: int) -> str:
    seguro = _PATRON_USER_SAFE.sub("_", (user_id or "").strip())[:120]
    cat = (categoria or "").strip().lower()
    return f"{_PREFIX_PISTA}{seguro}:{cat}:{int(reto_id)}"


def usuario_pidio_pista(categoria: str, reto_id: int) -> bool:
    """True si este usuario ya solicitó la pista de este reto."""
    uid = identidad_alumno_sesion()
    if not uid or not redis_esta_disponible():
        return False
    cliente = obtener_cliente_redis()
    if not cliente:
        return False
    try:
        return bool(cliente.get(_clave_pista(uid, categoria, reto_id)))
    except Exception as exc:
        logger.warning("Pista CTF: lectura Redis — %s", exc)
        return False


def registrar_pista_solicitada(
    categoria: str,
    reto_id: int,
    pista_texto: str,
    registrar_log_lab: Optional[Callable[..., Any]] = None,
) -> dict[str, Any]:
    """
    Marca la pista como pedida y opcionalmente añade evento a telemetría del lab.

    Args:
        registrar_log_lab: callback ``registrar_intento_waf_lab`` del módulo.
    """
    uid = identidad_alumno_sesion()
    ahora = marca_ahora()
    primera_vez = not usuario_pidio_pista(categoria, reto_id)

    if uid and redis_esta_disponible():
        cliente = obtener_cliente_redis()
        if cliente:
            try:
                payload = json.dumps(
                    {"timestamp": ahora, "pista_preview": (pista_texto or "")[:120]},
                    ensure_ascii=False,
                )
                clave = _clave_pista(uid, categoria, reto_id)
                cliente.setex(clave, _TTL_PISTA_SEG, payload)
            except Exception as exc:
                logger.warning("Pista CTF: escritura Redis — %s", exc)

    if registrar_log_lab is not None:
        try:
            registrar_log_lab(
                reto_id=int(reto_id),
                payload={"evento": "pista_solicitada", "primera_vez": primera_vez},
                modo_educativo=True,
            )
        except TypeError:
            registrar_log_lab(
                reto_id=int(reto_id),
                payload={"evento": "pista_solicitada", "primera_vez": primera_vez},
            )

    return {"primera_vez": primera_vez, "timestamp": ahora}
