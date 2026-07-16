"""
Perímetro NGWAF de FlyPaper basado en Redis.

Sustituye ip_cache.db por Redis en memoria para:
- Caché de reputación (AbuseIPDB + VirusTotal + ip-api)
- Bloqueos con TTL nativo (24 h)
- Whitelist persistente
- Rate limiting (ventana deslizante)
- Score de riesgo acumulativo por IP
- Circuit breaker de APIs externas

Si Redis no está disponible, el perímetro degrada de forma segura
(fail-open en rate/risk; firmas WAF locales siguen activas).
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
import uuid
from typing import Any, Optional

from timezone_fp import marca_ahora

logger = logging.getLogger(__name__)

# Etiquetas SOC (compatibles con el dashboard).
GRAVEDAD_BOT = "BOT / BLOQUEADO"
TIPO_ATAQUE_BOT_WAF = "Petición Automática Interceptada (WAF)"
TIPO_ABUSO_TASA = "Abuso de Tasa / Escaneo Agresivo"
TIPO_RIESGO_ACUMULATIVO = "Riesgo Acumulativo (Autoban)"

PUNTUACION_DEFECTO = 0
VALOR_TEXTO_DEFECTO = "Desconocido"
TIMEOUT_API_SEG = 3

# TTLs y umbrales (configurables por entorno).
TTL_BLOQUEO_SEG = int(os.getenv("REDIS_BLOCK_TTL", "86400"))  # 24 h
TTL_RIESGO_SEG = int(os.getenv("REDIS_RISK_TTL", "600"))  # 10 min
TTL_CACHE_IP_SEG = int(os.getenv("REDIS_IP_CACHE_TTL", "86400"))
VENTANA_RATE_SEG = int(os.getenv("RATE_LIMIT_WINDOW_SEC", "60"))
UMBRAL_RATE_LIMIT = int(os.getenv("RATE_LIMIT_MAX_REQ", "60"))
UMBRAL_RIESGO_AUTOBAN = int(os.getenv("RISK_SCORE_AUTOBAN", "5"))
CIRCUIT_FAIL_MAX = int(os.getenv("CIRCUIT_BREAKER_FAILS", "3"))
CIRCUIT_OPEN_SEG = int(os.getenv("CIRCUIT_BREAKER_OPEN_SEC", "3600"))  # 1 h

# Puntos de riesgo por gravedad WAF.
PUNTOS_RIESGO_SOSPECHOSO = 1
PUNTOS_RIESGO_ALTA = 3
PUNTOS_RIESGO_CRITICA = 5

URL_ABUSEIPDB = "https://api.abuseipdb.com/api/v2/check"
URL_VIRUSTOTAL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
URL_IP_API = "http://ip-api.com/json/{ip}?fields=status,country,isp"

IPS_LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost"})

# Prefijos Redis.
_PREFIX = os.getenv("REDIS_KEY_PREFIX", "flypaper:")
K_IP = _PREFIX + "ip:{ip}"
K_BLOCK = _PREFIX + "block:{ip}"
K_WHITELIST = _PREFIX + "whitelist:{ip}"
K_RATE = _PREFIX + "rate:{ip}"
K_RISK = _PREFIX + "risk:{ip}"
K_CIRCUIT_OPEN = _PREFIX + "circuit:open:{servicio}"
K_CIRCUIT_FAIL = _PREFIX + "circuit:fail:{servicio}"

_cliente_redis = None
_redis_disponible_cache: Optional[bool] = None
_redis_ultimo_ping = 0.0


class RateLimitApiError(Exception):
    """La API externa devolvió HTTP 429."""


# ---------------------------------------------------------------------------
# Cliente Redis
# ---------------------------------------------------------------------------


def _url_redis() -> str:
    return (
        os.getenv("REDIS_URL", "").strip()
        or os.getenv("REDIS_URI", "").strip()
        or "redis://127.0.0.1:6379/0"
    )


def obtener_cliente_redis():
    """
    Cliente Redis singleton (redis-py).

    Returns:
        redis.Redis | None: None si la librería no está instalada.
    """
    global _cliente_redis
    if _cliente_redis is not None:
        return _cliente_redis
    try:
        import redis
    except ImportError:
        logger.error(
            "redis-py no instalado. Ejecuta: pip install redis. "
            "Perímetro NGWAF en modo degradado."
        )
        return None
    try:
        _cliente_redis = redis.Redis.from_url(
            _url_redis(),
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
            retry_on_timeout=True,
        )
        return _cliente_redis
    except Exception as exc:
        logger.error("No se pudo crear cliente Redis: %s", exc)
        _cliente_redis = None
        return None


def redis_esta_disponible(forzar: bool = False) -> bool:
    """Ping a Redis con caché breve para no saturar conexiones."""
    global _redis_disponible_cache, _redis_ultimo_ping
    ahora = time.monotonic()
    if (
        not forzar
        and _redis_disponible_cache is not None
        and (ahora - _redis_ultimo_ping) < 5.0
    ):
        return _redis_disponible_cache

    cliente = obtener_cliente_redis()
    if cliente is None:
        _redis_disponible_cache = False
        _redis_ultimo_ping = ahora
        return False
    try:
        ok = bool(cliente.ping())
        _redis_disponible_cache = ok
    except Exception as exc:
        logger.warning("Redis no reachable: %s", exc)
        _redis_disponible_cache = False
    _redis_ultimo_ping = ahora
    return bool(_redis_disponible_cache)


def inicializar_ip_cache() -> None:
    """
    Inicializa el perímetro Redis (alias histórico de inicializar_ip_cache).

    Verifica conectividad; no crea esquema (Redis es key-value).
    """
    if redis_esta_disponible(forzar=True):
        logger.info("Perímetro NGWAF: Redis operativo (%s).", _url_redis())
    else:
        logger.warning(
            "Perímetro NGWAF: Redis NO disponible. "
            "Rate-limit, riesgo y caché IP en fail-open."
        )


def inicializar_perimetro_redis() -> None:
    """Alias explícito para arranque Docker / SOC."""
    inicializar_ip_cache()


def estado_perimetro_redis() -> dict[str, Any]:
    """Resumen de salud del perímetro para el widget SOC."""
    ok = redis_esta_disponible(forzar=True)
    circuitos = {
        "abuseipdb": _circuito_esta_abierto("abuseipdb"),
        "virustotal": _circuito_esta_abierto("virustotal"),
    }
    bloqueadas = 0
    if ok:
        try:
            bloqueadas = len(listar_ips_bloqueadas_perimetro())
        except Exception:
            bloqueadas = 0
    return {
        "redis_ok": ok,
        "redis_url_mascara": _enmascarar_url(_url_redis()),
        "circuitos_abiertos": circuitos,
        "bloqueadas_activas": bloqueadas,
        "rate_limit_max": UMBRAL_RATE_LIMIT,
        "rate_limit_ventana_seg": VENTANA_RATE_SEG,
        "risk_autoban_umbral": UMBRAL_RIESGO_AUTOBAN,
        "backend": "redis" if ok else "degradado",
    }


def _enmascarar_url(url: str) -> str:
    """Oculta contraseñas en logs/UI."""
    if "@" not in url:
        return url
    try:
        esquema, resto = url.split("://", 1)
        creds, host = resto.rsplit("@", 1)
        if ":" in creds:
            user = creds.split(":", 1)[0]
            return f"{esquema}://{user}:***@{host}"
        return f"{esquema}://***@{host}"
    except ValueError:
        return url


# ---------------------------------------------------------------------------
# Score de reputación externa
# ---------------------------------------------------------------------------


def _umbral_score() -> float:
    try:
        return float(os.getenv("SCORE_THRESHOLD", "50.0"))
    except ValueError:
        return 50.0


def _calcular_score_riesgo(abuse_score: int, vt_positives: int) -> float:
    """Score = (AbuseIPDB × 0.6) + (VirusTotalPositivos × 10)."""
    return (abuse_score * 0.6) + (vt_positives * 10)


def calcular_score_riesgo_ip(abuse_score: int, vt_positives: int) -> float:
    """Expone la fórmula de score para APIs y el panel SOC."""
    return _calcular_score_riesgo(abuse_score, vt_positives)


def _fetch_json(url: str, headers: Optional[dict[str, str]] = None) -> dict[str, Any]:
    """GET JSON con timeout; propaga RateLimitApiError en HTTP 429."""
    peticion = urllib.request.Request(
        url,
        headers=headers or {},
        method="GET",
    )
    try:
        with urllib.request.urlopen(peticion, timeout=TIMEOUT_API_SEG) as respuesta:
            cuerpo = respuesta.read().decode("utf-8", errors="replace")
        return json.loads(cuerpo)
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            raise RateLimitApiError(f"HTTP 429 en {url}") from exc
        raise


# ---------------------------------------------------------------------------
# Circuit breaker (AbuseIPDB / VirusTotal)
# ---------------------------------------------------------------------------


def _circuito_esta_abierto(servicio: str) -> bool:
    if not redis_esta_disponible():
        return False
    cliente = obtener_cliente_redis()
    if not cliente:
        return False
    try:
        return bool(cliente.exists(K_CIRCUIT_OPEN.format(servicio=servicio)))
    except Exception:
        return False


def _registrar_exito_api(servicio: str) -> None:
    if not redis_esta_disponible():
        return
    cliente = obtener_cliente_redis()
    if not cliente:
        return
    try:
        cliente.delete(K_CIRCUIT_FAIL.format(servicio=servicio))
    except Exception as exc:
        logger.debug("Circuit breaker reset falló (%s): %s", servicio, exc)


def _registrar_fallo_api(servicio: str, motivo: str) -> None:
    """Incrementa fallos; abre circuito tras N errores o un 429."""
    logger.warning("API %s fallo: %s", servicio, motivo)
    if not redis_esta_disponible():
        return
    cliente = obtener_cliente_redis()
    if not cliente:
        return
    try:
        clave_fail = K_CIRCUIT_FAIL.format(servicio=servicio)
        clave_open = K_CIRCUIT_OPEN.format(servicio=servicio)
        # 429 o 3 fallos → abrir 1 h.
        es_429 = "429" in motivo
        contador = int(cliente.incr(clave_fail))
        cliente.expire(clave_fail, CIRCUIT_OPEN_SEG)
        if es_429 or contador >= CIRCUIT_FAIL_MAX:
            cliente.setex(clave_open, CIRCUIT_OPEN_SEG, motivo[:200])
            cliente.delete(clave_fail)
            logger.error(
                "Circuit breaker OPEN para %s (%ss). Motivo: %s",
                servicio,
                CIRCUIT_OPEN_SEG,
                motivo,
            )
    except Exception as exc:
        logger.debug("No se pudo actualizar circuit breaker: %s", exc)


def _consultar_abuseipdb(ip: str) -> int:
    if _circuito_esta_abierto("abuseipdb"):
        logger.info("AbuseIPDB circuito abierto — skip %s", ip)
        return PUNTUACION_DEFECTO
    api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if not api_key:
        return PUNTUACION_DEFECTO
    url = f"{URL_ABUSEIPDB}?ipAddress={urllib.request.quote(ip)}&maxAgeInDays=90"
    try:
        datos = _fetch_json(
            url,
            headers={"Key": api_key, "Accept": "application/json"},
        )
        _registrar_exito_api("abuseipdb")
        return int(datos.get("data", {}).get("abuseConfidenceScore") or 0)
    except RateLimitApiError as exc:
        _registrar_fallo_api("abuseipdb", str(exc))
        return PUNTUACION_DEFECTO
    except Exception as exc:
        _registrar_fallo_api("abuseipdb", str(exc))
        return PUNTUACION_DEFECTO


def _consultar_virustotal(ip: str) -> int:
    if _circuito_esta_abierto("virustotal"):
        logger.info("VirusTotal circuito abierto — skip %s", ip)
        return PUNTUACION_DEFECTO
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return PUNTUACION_DEFECTO
    url = URL_VIRUSTOTAL.format(ip=urllib.request.quote(ip))
    try:
        datos = _fetch_json(url, headers={"x-apikey": api_key})
        stats = (
            datos.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )
        _registrar_exito_api("virustotal")
        return int(stats.get("malicious") or 0)
    except RateLimitApiError as exc:
        _registrar_fallo_api("virustotal", str(exc))
        return PUNTUACION_DEFECTO
    except Exception as exc:
        _registrar_fallo_api("virustotal", str(exc))
        return PUNTUACION_DEFECTO


def _consultar_ip_api(ip: str) -> tuple[str, str]:
    url = URL_IP_API.format(ip=urllib.request.quote(ip))
    try:
        datos = _fetch_json(url)
        if datos.get("status") != "success":
            return VALOR_TEXTO_DEFECTO, VALOR_TEXTO_DEFECTO
        return (
            (datos.get("country") or VALOR_TEXTO_DEFECTO).strip(),
            (datos.get("isp") or VALOR_TEXTO_DEFECTO).strip(),
        )
    except Exception as exc:
        logger.warning("ip-api.com: fallo %s — %s", ip, exc)
        return VALOR_TEXTO_DEFECTO, VALOR_TEXTO_DEFECTO


# ---------------------------------------------------------------------------
# Bloqueo / whitelist / caché IP
# ---------------------------------------------------------------------------


def _ip_en_whitelist(ip: str) -> bool:
    cliente = obtener_cliente_redis()
    if not cliente or not redis_esta_disponible():
        return False
    try:
        return bool(cliente.exists(K_WHITELIST.format(ip=ip)))
    except Exception:
        return False


def _ip_esta_bloqueada(ip: str) -> bool:
    cliente = obtener_cliente_redis()
    if not cliente or not redis_esta_disponible():
        return False
    try:
        return bool(cliente.exists(K_BLOCK.format(ip=ip)))
    except Exception:
        return False


def bloquear_ip_perimetro(
    ip: str,
    motivo: str = "Bloqueo perimetral",
    ttl: int = TTL_BLOQUEO_SEG,
) -> bool:
    """
    Marca la IP como bloqueada con TTL nativo Redis (por defecto 24 h).

    Returns:
        bool: True si se escribió en Redis.
    """
    nombre = (ip or "").strip()
    if not nombre or _ip_en_whitelist(nombre):
        return False
    cliente = obtener_cliente_redis()
    if not cliente or not redis_esta_disponible():
        logger.warning("bloquear_ip_perimetro: Redis off — %s no bloqueada.", nombre)
        return False
    meta = json.dumps(
        {"motivo": motivo, "desde": marca_ahora(), "ttl": ttl},
        ensure_ascii=False,
    )
    try:
        cliente.setex(K_BLOCK.format(ip=nombre), max(1, int(ttl)), meta)
        # Actualiza caché de reputación si existe.
        clave_ip = K_IP.format(ip=nombre)
        if cliente.exists(clave_ip):
            datos = _leer_hash_ip(cliente, nombre) or {}
            datos["is_blocked"] = True
            datos["fecha_analisis"] = marca_ahora()
            _escribir_hash_ip(cliente, nombre, datos, refrescar_ttl=False)
        logger.info("Redis BLOCK %s (%ss): %s", nombre, ttl, motivo)
        return True
    except Exception as exc:
        logger.error("Error bloqueando %s en Redis: %s", nombre, exc)
        return False


def obtener_estado_ip(ip: str) -> Optional[dict[str, Any]]:
    """
    Estado de reputación/bloqueo de una IP desde Redis.

    Returns:
        dict | None: None si no hay caché ni bloqueo/whitelist.
    """
    nombre = (ip or "").strip()
    if not nombre:
        return None
    if not redis_esta_disponible():
        return None
    cliente = obtener_cliente_redis()
    if not cliente:
        return None

    try:
        whitelisted = _ip_en_whitelist(nombre)
        blocked = _ip_esta_bloqueada(nombre) and not whitelisted
        datos = _leer_hash_ip(cliente, nombre)

        if datos is None and not blocked and not whitelisted:
            return None

        if datos is None:
            datos = {
                "abuse_score": 0,
                "vt_positives": 0,
                "country": VALOR_TEXTO_DEFECTO,
                "isp": VALOR_TEXTO_DEFECTO,
                "fecha_analisis": marca_ahora(),
            }

        abuse = int(datos.get("abuse_score") or 0)
        vt = int(datos.get("vt_positives") or 0)
        return {
            "ip": nombre,
            "abuse_score": abuse,
            "vt_positives": vt,
            "country": datos.get("country") or VALOR_TEXTO_DEFECTO,
            "isp": datos.get("isp") or VALOR_TEXTO_DEFECTO,
            "is_blocked": blocked,
            "is_whitelisted": whitelisted,
            "fecha_analisis": datos.get("fecha_analisis") or "",
            "risk_score": _calcular_score_riesgo(abuse, vt),
            "block_motivo": _leer_motivo_bloqueo(cliente, nombre) if blocked else "",
        }
    except Exception as exc:
        logger.warning("obtener_estado_ip Redis error (%s): %s", nombre, exc)
        return None


def _leer_motivo_bloqueo(cliente, ip: str) -> str:
    try:
        raw = cliente.get(K_BLOCK.format(ip=ip))
        if not raw:
            return ""
        try:
            return json.loads(raw).get("motivo", "") or ""
        except (TypeError, json.JSONDecodeError):
            return str(raw)
    except Exception:
        return ""


def _leer_hash_ip(cliente, ip: str) -> Optional[dict[str, Any]]:
    raw = cliente.get(K_IP.format(ip=ip))
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return None


def _escribir_hash_ip(
    cliente, ip: str, datos: dict[str, Any], refrescar_ttl: bool = True
) -> None:
    payload = json.dumps(datos, ensure_ascii=False)
    clave = K_IP.format(ip=ip)
    if refrescar_ttl:
        cliente.setex(clave, TTL_CACHE_IP_SEG, payload)
    else:
        ttl = cliente.ttl(clave)
        if ttl and ttl > 0:
            cliente.setex(clave, ttl, payload)
        else:
            cliente.setex(clave, TTL_CACHE_IP_SEG, payload)


def guardar_analisis_ip(
    ip: str,
    abuse_score: int,
    vt_positives: int,
    country: str,
    isp: str,
    is_blocked: bool,
    is_whitelisted: bool = False,
) -> None:
    """Persiste veredicto de reputación en Redis (sustituye INSERT SQLite)."""
    nombre = (ip or "").strip()
    if not nombre:
        return
    cliente = obtener_cliente_redis()
    if not cliente or not redis_esta_disponible():
        return

    marca = marca_ahora()
    datos = {
        "abuse_score": int(abuse_score),
        "vt_positives": int(vt_positives),
        "country": country or VALOR_TEXTO_DEFECTO,
        "isp": isp or VALOR_TEXTO_DEFECTO,
        "fecha_analisis": marca,
        "is_blocked": bool(is_blocked),
        "is_whitelisted": bool(is_whitelisted),
    }
    try:
        _escribir_hash_ip(cliente, nombre, datos)
        if is_whitelisted:
            cliente.set(K_WHITELIST.format(ip=nombre), marca)
            cliente.delete(K_BLOCK.format(ip=nombre))
        elif is_blocked:
            bloquear_ip_perimetro(
                nombre,
                motivo="Reputación: score sobre umbral",
                ttl=TTL_BLOQUEO_SEG,
            )
        else:
            cliente.delete(K_BLOCK.format(ip=nombre))
    except Exception as exc:
        logger.error("guardar_analisis_ip Redis falló (%s): %s", nombre, exc)


def analizar_ip_nueva(ip: str) -> dict[str, Any]:
    """Pipeline de enriquecimiento con circuit breaker y degradación grácil."""
    nombre = (ip or "").strip()
    abuse_score = _consultar_abuseipdb(nombre)
    vt_positives = _consultar_virustotal(nombre)
    country, isp = _consultar_ip_api(nombre)
    risk_score = _calcular_score_riesgo(abuse_score, vt_positives)
    is_blocked = risk_score > _umbral_score()
    logger.info(
        "Reputación IP %s — abuse=%s vt=%s score=%.1f bloqueada=%s",
        nombre,
        abuse_score,
        vt_positives,
        risk_score,
        is_blocked,
    )
    return {
        "ip": nombre,
        "abuse_score": abuse_score,
        "vt_positives": vt_positives,
        "country": country,
        "isp": isp,
        "risk_score": risk_score,
        "is_blocked": is_blocked,
    }


def evaluar_ip_en_cache(ip: str) -> dict[str, Any]:
    """Devuelve caché Redis o analiza y persiste."""
    estado = obtener_estado_ip(ip)
    if estado is not None:
        return estado

    analisis = analizar_ip_nueva(ip)
    guardar_analisis_ip(
        ip=analisis["ip"],
        abuse_score=analisis["abuse_score"],
        vt_positives=analisis["vt_positives"],
        country=analisis["country"],
        isp=analisis["isp"],
        is_blocked=analisis["is_blocked"],
        is_whitelisted=False,
    )
    return obtener_estado_ip(ip) or {
        **analisis,
        "is_whitelisted": False,
        "fecha_analisis": marca_ahora(),
    }


def marcar_ip_verificada_humana(ip: str) -> None:
    """Whitelist persistente (sin TTL) y quita bloqueo."""
    nombre = (ip or "").strip()
    if not nombre:
        return
    cliente = obtener_cliente_redis()
    if cliente and redis_esta_disponible():
        try:
            cliente.set(K_WHITELIST.format(ip=nombre), marca_ahora())
            cliente.delete(K_BLOCK.format(ip=nombre))
            cliente.delete(K_RISK.format(ip=nombre))
            cliente.delete(K_RATE.format(ip=nombre))
        except Exception as exc:
            logger.error("Whitelist Redis falló (%s): %s", nombre, exc)

    estado = obtener_estado_ip(nombre)
    if estado is None:
        guardar_analisis_ip(
            ip=nombre,
            abuse_score=0,
            vt_positives=0,
            country=VALOR_TEXTO_DEFECTO,
            isp=VALOR_TEXTO_DEFECTO,
            is_blocked=False,
            is_whitelisted=True,
        )
        return
    guardar_analisis_ip(
        ip=nombre,
        abuse_score=estado["abuse_score"],
        vt_positives=estado["vt_positives"],
        country=estado["country"],
        isp=estado["isp"],
        is_blocked=False,
        is_whitelisted=True,
    )
    logger.info("IP %s whitelist admin (Redis, persistente).", nombre)


def whitelist_ip_perimetro(ip: str) -> bool:
    """Desbloquea IP vía whitelist administrativa."""
    marcar_ip_verificada_humana(ip)
    return True


def es_ip_loopback(ip: str) -> bool:
    if not ip:
        return False
    texto = ip.strip().lower()
    if texto in IPS_LOOPBACK:
        return True
    return texto.startswith("127.")


def ruta_exenta_reputacion_ip(ruta: str) -> bool:
    if not ruta:
        return False
    if ruta in ("/verify-ip", "/favicon.ico"):
        return True
    if ruta.startswith("/static/") or ruta.startswith("/assets/"):
        return True
    return False


def ruta_exenta_rate_limit(ruta: str) -> bool:
    """Exenciones operativas: estáticos, verify-ip, panel SOC y academia CTF."""
    if ruta_exenta_reputacion_ip(ruta):
        return True
    if (ruta or "").startswith("/admin"):
        return True
    if (ruta or "").startswith("/objetivos"):
        return True
    return False


def ip_debe_mostrar_jail(estado: dict[str, Any]) -> bool:
    return bool(estado.get("is_blocked")) and not bool(estado.get("is_whitelisted"))


def listar_ips_bloqueadas_perimetro() -> list[dict[str, Any]]:
    """Lista IPs con clave block:* activa (TTL no expirado)."""
    if not redis_esta_disponible():
        return []
    cliente = obtener_cliente_redis()
    if not cliente:
        return []

    resultado: list[dict[str, Any]] = []
    prefijo_block = _PREFIX + "block:"
    try:
        for clave in cliente.scan_iter(match=prefijo_block + "*", count=100):
            if not str(clave).startswith(prefijo_block):
                continue
            # Compatible con IPv4 e IPv6: IP = todo tras «flypaper:block:».
            ip = str(clave)[len(prefijo_block) :]
            if not ip or _ip_en_whitelist(ip):
                continue
            estado = obtener_estado_ip(ip) or {
                "ip": ip,
                "abuse_score": 0,
                "vt_positives": 0,
                "country": VALOR_TEXTO_DEFECTO,
                "isp": VALOR_TEXTO_DEFECTO,
                "risk_score": 0.0,
                "fecha_analisis": "",
            }
            ttl = cliente.ttl(clave)
            resultado.append(
                {
                    "ip": ip,
                    "abuse_score": int(estado.get("abuse_score") or 0),
                    "vt_positives": int(estado.get("vt_positives") or 0),
                    "country": estado.get("country") or VALOR_TEXTO_DEFECTO,
                    "isp": estado.get("isp") or VALOR_TEXTO_DEFECTO,
                    "risk_score": float(estado.get("risk_score") or 0),
                    "fecha_analisis": estado.get("fecha_analisis") or "",
                    "is_blocked": True,
                    "is_whitelisted": False,
                    "ttl_restante_seg": ttl if ttl and ttl > 0 else TTL_BLOQUEO_SEG,
                    "motivo": estado.get("block_motivo")
                    or _leer_motivo_bloqueo(cliente, ip),
                }
            )
    except Exception as exc:
        logger.error("listar_ips_bloqueadas_perimetro: %s", exc)
        return []

    resultado.sort(key=lambda x: x.get("fecha_analisis") or "", reverse=True)
    return resultado


def es_ip_bot_perimetro(ip: str) -> bool:
    nombre = (ip or "").strip()
    if not nombre:
        return False
    try:
        if _ip_en_whitelist(nombre):
            return False
        return _ip_esta_bloqueada(nombre)
    except Exception:
        return False


def obtener_mapa_bots_perimetro(ips: list[str]) -> dict[str, dict[str, Any]]:
    """Consulta batch: IPs bloqueadas (sin whitelist)."""
    resultado: dict[str, dict[str, Any]] = {}
    for ip in {(i or "").strip() for i in ips if (i or "").strip()}:
        if es_ip_bot_perimetro(ip):
            estado = obtener_estado_ip(ip) or {}
            resultado[ip] = {
                "is_bot": True,
                "risk_score": float(estado.get("risk_score") or 0),
                "country": estado.get("country") or VALOR_TEXTO_DEFECTO,
                "isp": estado.get("isp") or VALOR_TEXTO_DEFECTO,
            }
    return resultado


# ---------------------------------------------------------------------------
# Rate limiting — ventana deslizante (Sorted Set)
# ---------------------------------------------------------------------------


def comprobar_rate_limit(ip: str) -> dict[str, Any]:
    """
    Ventana deslizante de 60 s: más de UMBRAL_RATE_LIMIT peticiones → exceso.

    Returns:
        dict: excedido (bool), conteo, limite, motivo.
    """
    vacio = {
        "excedido": False,
        "conteo": 0,
        "limite": UMBRAL_RATE_LIMIT,
        "motivo": "",
    }
    nombre = (ip or "").strip()
    if not nombre or es_ip_loopback(nombre) or _ip_en_whitelist(nombre):
        return vacio
    if not redis_esta_disponible():
        return vacio

    cliente = obtener_cliente_redis()
    if not cliente:
        return vacio

    clave = K_RATE.format(ip=nombre)
    ahora = time.time()
    ventana_inicio = ahora - VENTANA_RATE_SEG
    miembro = f"{ahora:.6f}:{uuid.uuid4().hex[:8]}"

    try:
        pipe = cliente.pipeline()
        pipe.zremrangebyscore(clave, 0, ventana_inicio)
        pipe.zadd(clave, {miembro: ahora})
        pipe.zcard(clave)
        pipe.expire(clave, VENTANA_RATE_SEG + 5)
        resultados = pipe.execute()
        conteo = int(resultados[2] or 0)
        if conteo > UMBRAL_RATE_LIMIT:
            motivo = (
                f"Abuso de Tasa / Escaneo Agresivo: "
                f"{conteo}/{UMBRAL_RATE_LIMIT} req en {VENTANA_RATE_SEG}s"
            )
            bloquear_ip_perimetro(nombre, motivo=motivo, ttl=TTL_BLOQUEO_SEG)
            return {
                "excedido": True,
                "conteo": conteo,
                "limite": UMBRAL_RATE_LIMIT,
                "motivo": motivo,
            }
        return {
            "excedido": False,
            "conteo": conteo,
            "limite": UMBRAL_RATE_LIMIT,
            "motivo": "",
        }
    except Exception as exc:
        logger.warning("Rate limit Redis fail-open (%s): %s", nombre, exc)
        return vacio


# ---------------------------------------------------------------------------
# Riesgo acumulativo por sesión (heurística dinámica)
# ---------------------------------------------------------------------------


def puntos_por_gravedad(gravedad: Optional[str]) -> int:
    """Mapea severidad WAF → puntos de riesgo comportamental."""
    if not gravedad:
        return 0
    g = str(gravedad).strip()
    if g == "Crítica":
        return PUNTOS_RIESGO_CRITICA
    if g == "Alta":
        return PUNTOS_RIESGO_ALTA
    if g == "Sospechoso":
        return PUNTOS_RIESGO_SOSPECHOSO
    return 0


def acumular_riesgo_comportamiento(
    ip: str, gravedad: Optional[str]
) -> dict[str, Any]:
    """
    Suma puntos al score ``risk:{ip}`` (TTL 10 min).

    Si el acumulado ≥ UMBRAL_RIESGO_AUTOBAN → autoban emergencia 24 h.

    Returns:
        dict: score, puntos_anadidos, autoban (bool), motivo.
    """
    resultado = {
        "score": 0,
        "puntos_anadidos": 0,
        "autoban": False,
        "motivo": "",
    }
    nombre = (ip or "").strip()
    puntos = puntos_por_gravedad(gravedad)
    if not nombre or puntos <= 0 or es_ip_loopback(nombre):
        return resultado
    if _ip_en_whitelist(nombre):
        return resultado
    if not redis_esta_disponible():
        return resultado

    cliente = obtener_cliente_redis()
    if not cliente:
        return resultado

    clave = K_RISK.format(ip=nombre)
    try:
        score = int(cliente.incrby(clave, puntos))
        cliente.expire(clave, TTL_RIESGO_SEG)
        resultado["score"] = score
        resultado["puntos_anadidos"] = puntos
        if score >= UMBRAL_RIESGO_AUTOBAN:
            motivo = (
                f"Autoban emergencia: riesgo acumulado {score} "
                f"(umbral {UMBRAL_RIESGO_AUTOBAN}) en {TTL_RIESGO_SEG // 60} min"
            )
            bloquear_ip_perimetro(nombre, motivo=motivo, ttl=TTL_BLOQUEO_SEG)
            resultado["autoban"] = True
            resultado["motivo"] = motivo
            logger.warning("RIESGO AUTOBAN %s — %s", nombre, motivo)
        return resultado
    except Exception as exc:
        logger.warning("acumular_riesgo fail-open (%s): %s", nombre, exc)
        return resultado


def obtener_score_riesgo_comportamiento(ip: str) -> int:
    """Lee el score dinámico actual (0 si Redis off)."""
    nombre = (ip or "").strip()
    if not nombre or not redis_esta_disponible():
        return 0
    cliente = obtener_cliente_redis()
    if not cliente:
        return 0
    try:
        valor = cliente.get(K_RISK.format(ip=nombre))
        return int(valor or 0)
    except Exception:
        return 0
