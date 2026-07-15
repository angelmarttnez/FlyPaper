"""
Middleware perimetral de reputación de IPs para FlyPaper.

Consulta AbuseIPDB, VirusTotal e ip-api.com con degradación grácil,
persiste veredictos en ip_cache.db y calcula score de riesgo.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Optional

from timezone_fp import marca_ahora

logger = logging.getLogger(__name__)

RUTA_RAIZ = Path(__file__).resolve().parent
RUTA_BD_IP_CACHE = RUTA_RAIZ / "ip_cache.db"

TIMEOUT_API_SEG = 3
VALOR_TEXTO_DEFECTO = "Desconocido"

# Etiquetas SOC para tráfico bloqueado por el WAF perimetral (ip_cache.db).
GRAVEDAD_BOT = "BOT / BLOQUEADO"
TIPO_ATAQUE_BOT_WAF = "Petición Automática Interceptada (WAF)"
PUNTUACION_DEFECTO = 0

URL_ABUSEIPDB = "https://api.abuseipdb.com/api/v2/check"
URL_VIRUSTOTAL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
URL_IP_API = "http://ip-api.com/json/{ip}?fields=status,country,isp"

IPS_LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost"})


def _umbral_score() -> float:
    """Lee SCORE_THRESHOLD del entorno (por defecto 50.0)."""
    try:
        return float(os.getenv("SCORE_THRESHOLD", "50.0"))
    except ValueError:
        logger.warning(
            "SCORE_THRESHOLD inválido; usando 50.0 por defecto."
        )
        return 50.0


def _calcular_score_riesgo(abuse_score: int, vt_positives: int) -> float:
    """
    Fórmula: Score = (AbuseIPDB × 0.6) + (VirusTotalPositivos × 10).
    """
    return (abuse_score * 0.6) + (vt_positives * 10)


def _fetch_json(url: str, headers: Optional[dict[str, str]] = None) -> dict[str, Any]:
    """
    GET JSON con timeout estricto.

    Raises:
        urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, TimeoutError
    """
    peticion = urllib.request.Request(
        url,
        headers=headers or {},
        method="GET",
    )
    with urllib.request.urlopen(peticion, timeout=TIMEOUT_API_SEG) as respuesta:
        cuerpo = respuesta.read().decode("utf-8", errors="replace")
    return json.loads(cuerpo)


def obtener_conexion_ip_cache() -> sqlite3.Connection:
    """Conexión SQLite a ip_cache.db (timeout 30 s para evitar bloqueos de escritura)."""
    conexion = sqlite3.connect(RUTA_BD_IP_CACHE, timeout=30.0)
    conexion.row_factory = sqlite3.Row
    return conexion


def calcular_score_riesgo_ip(abuse_score: int, vt_positives: int) -> float:
    """Expone la fórmula de score para APIs y el panel SOC."""
    return _calcular_score_riesgo(abuse_score, vt_positives)


def inicializar_ip_cache() -> None:
    """Crea la tabla ip_cache si no existe."""
    ddl = """
    CREATE TABLE IF NOT EXISTS ip_cache (
        ip TEXT PRIMARY KEY,
        abuse_score INTEGER NOT NULL DEFAULT 0,
        vt_positives INTEGER NOT NULL DEFAULT 0,
        country TEXT NOT NULL DEFAULT 'Desconocido',
        isp TEXT NOT NULL DEFAULT 'Desconocido',
        is_blocked INTEGER NOT NULL DEFAULT 0,
        is_whitelisted INTEGER NOT NULL DEFAULT 0,
        fecha_analisis DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """
    with obtener_conexion_ip_cache() as conexion:
        conexion.executescript(ddl)
        conexion.commit()


def obtener_estado_ip(ip: str) -> Optional[dict[str, Any]]:
    """
    Consulta el caché de reputación de una IP.

    Returns:
        dict | None: Fila de ip_cache o None si no está registrada.
    """
    if not ip:
        return None
    with obtener_conexion_ip_cache() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            """
            SELECT ip, abuse_score, vt_positives, country, isp,
                   is_blocked, is_whitelisted, fecha_analisis
            FROM ip_cache
            WHERE ip = ?
            LIMIT 1;
            """,
            (ip.strip(),),
        )
        fila = cursor.fetchone()
    if fila is None:
        return None
    return {
        "ip": fila["ip"],
        "abuse_score": int(fila["abuse_score"] or 0),
        "vt_positives": int(fila["vt_positives"] or 0),
        "country": fila["country"] or VALOR_TEXTO_DEFECTO,
        "isp": fila["isp"] or VALOR_TEXTO_DEFECTO,
        "is_blocked": bool(fila["is_blocked"]),
        "is_whitelisted": bool(fila["is_whitelisted"]),
        "fecha_analisis": fila["fecha_analisis"],
        "risk_score": _calcular_score_riesgo(
            int(fila["abuse_score"] or 0),
            int(fila["vt_positives"] or 0),
        ),
    }


def guardar_analisis_ip(
    ip: str,
    abuse_score: int,
    vt_positives: int,
    country: str,
    isp: str,
    is_blocked: bool,
    is_whitelisted: bool = False,
) -> None:
    """
    Inserta o actualiza el veredicto de reputación de una IP.

    Usa bloques with para minimizar bloqueos por concurrencia.
    """
    nombre = (ip or "").strip()
    if not nombre:
        return
    marca = marca_ahora()
    with obtener_conexion_ip_cache() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            """
            INSERT INTO ip_cache (
                ip, abuse_score, vt_positives, country, isp,
                is_blocked, is_whitelisted, fecha_analisis
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                abuse_score = excluded.abuse_score,
                vt_positives = excluded.vt_positives,
                country = excluded.country,
                isp = excluded.isp,
                is_blocked = excluded.is_blocked,
                is_whitelisted = excluded.is_whitelisted,
                fecha_analisis = excluded.fecha_analisis;
            """,
            (
                nombre,
                int(abuse_score),
                int(vt_positives),
                country or VALOR_TEXTO_DEFECTO,
                isp or VALOR_TEXTO_DEFECTO,
                1 if is_blocked else 0,
                1 if is_whitelisted else 0,
                marca,
            ),
        )
        conexion.commit()


def _consultar_abuseipdb(ip: str) -> int:
    """Obtiene abuseConfidenceScore (0-100) o 0 si falla."""
    api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if not api_key:
        logger.warning("AbuseIPDB: ABUSEIPDB_API_KEY no configurada; score=0.")
        return PUNTUACION_DEFECTO

    url = f"{URL_ABUSEIPDB}?ipAddress={urllib.request.quote(ip)}&maxAgeInDays=90"
    try:
        datos = _fetch_json(
            url,
            headers={
                "Key": api_key,
                "Accept": "application/json",
            },
        )
        return int(datos.get("data", {}).get("abuseConfidenceScore") or 0)
    except Exception as exc:
        logger.warning("AbuseIPDB: fallo al consultar %s — %s", ip, exc)
        return PUNTUACION_DEFECTO


def _consultar_virustotal(ip: str) -> int:
    """Obtiene last_analysis_stats.malicious o 0 si falla."""
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        logger.warning("VirusTotal: VIRUSTOTAL_API_KEY no configurada; score=0.")
        return PUNTUACION_DEFECTO

    url = URL_VIRUSTOTAL.format(ip=urllib.request.quote(ip))
    try:
        datos = _fetch_json(
            url,
            headers={"x-apikey": api_key},
        )
        stats = datos.get("data", {}).get("attributes", {}).get(
            "last_analysis_stats", {}
        )
        return int(stats.get("malicious") or 0)
    except Exception as exc:
        logger.warning("VirusTotal: fallo al consultar %s — %s", ip, exc)
        return PUNTUACION_DEFECTO


def _consultar_ip_api(ip: str) -> tuple[str, str]:
    """Obtiene country e isp vía ip-api.com o valores por defecto."""
    url = URL_IP_API.format(ip=urllib.request.quote(ip))
    try:
        datos = _fetch_json(url)
        if datos.get("status") != "success":
            logger.warning(
                "ip-api.com: status=%s para %s",
                datos.get("status"),
                ip,
            )
            return VALOR_TEXTO_DEFECTO, VALOR_TEXTO_DEFECTO
        pais = (datos.get("country") or VALOR_TEXTO_DEFECTO).strip()
        isp = (datos.get("isp") or VALOR_TEXTO_DEFECTO).strip()
        return pais, isp
    except Exception as exc:
        logger.warning("ip-api.com: fallo al consultar %s — %s", ip, exc)
        return VALOR_TEXTO_DEFECTO, VALOR_TEXTO_DEFECTO


def analizar_ip_nueva(ip: str) -> dict[str, Any]:
    """
    Pipeline secuencial de enriquecimiento con tolerancia a fallos por API.

    Returns:
        dict: abuse_score, vt_positives, country, isp, risk_score, is_blocked.
    """
    nombre = (ip or "").strip()
    abuse_score = _consultar_abuseipdb(nombre)
    vt_positives = _consultar_virustotal(nombre)
    country, isp = _consultar_ip_api(nombre)

    risk_score = _calcular_score_riesgo(abuse_score, vt_positives)
    umbral = _umbral_score()
    is_blocked = risk_score > umbral

    logger.info(
        "Reputación IP %s — abuse=%s vt=%s score=%.1f umbral=%.1f bloqueada=%s",
        nombre,
        abuse_score,
        vt_positives,
        risk_score,
        umbral,
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
    """
    Devuelve el estado de caché o ejecuta analizar_ip_nueva y persiste el resultado.
    """
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
    return obtener_estado_ip(ip) or analisis


def marcar_ip_verificada_humana(ip: str) -> None:
    """
    Bypass interactivo (Jail Page): whitelist y desbloqueo en ip_cache.
    """
    nombre = (ip or "").strip()
    if not nombre:
        return

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
    logger.info("IP %s verificada manualmente (whitelist activa).", nombre)


def es_ip_loopback(ip: str) -> bool:
    """True si la IP es localhost (omitir análisis perimetral)."""
    if not ip:
        return False
    texto = ip.strip().lower()
    if texto in IPS_LOOPBACK:
        return True
    if texto.startswith("127."):
        return True
    return False


def ruta_exenta_reputacion_ip(ruta: str) -> bool:
    """
    Rutas que no pasan por el filtro de reputación perimetral.

    Incluye verify-ip, favicon y assets estáticos.
    """
    if not ruta:
        return False
    if ruta in ("/verify-ip", "/favicon.ico"):
        return True
    if ruta.startswith("/static/") or ruta.startswith("/assets/"):
        return True
    return False


def ip_debe_mostrar_jail(estado: dict[str, Any]) -> bool:
    """True si la IP está bloqueada y no tiene whitelist humana."""
    return bool(estado.get("is_blocked")) and not bool(estado.get("is_whitelisted"))


def listar_ips_bloqueadas_perimetro() -> list[dict[str, Any]]:
    """
    IPs en estado de bloqueo activo en el perímetro (ip_cache.db).

    Returns:
        list[dict]: Filas con score de riesgo calculado.
    """
    consulta = """
    SELECT ip, abuse_score, vt_positives, country, isp,
           is_blocked, is_whitelisted, fecha_analisis
    FROM ip_cache
    WHERE is_blocked = 1 AND is_whitelisted = 0
    ORDER BY fecha_analisis DESC;
    """
    with obtener_conexion_ip_cache() as conexion:
        cursor = conexion.cursor()
        cursor.execute(consulta)
        filas = cursor.fetchall()

    resultado = []
    for fila in filas:
        abuse = int(fila["abuse_score"] or 0)
        vt = int(fila["vt_positives"] or 0)
        resultado.append(
            {
                "ip": fila["ip"],
                "abuse_score": abuse,
                "vt_positives": vt,
                "country": fila["country"] or VALOR_TEXTO_DEFECTO,
                "isp": fila["isp"] or VALOR_TEXTO_DEFECTO,
                "risk_score": calcular_score_riesgo_ip(abuse, vt),
                "fecha_analisis": fila["fecha_analisis"] or "",
                "is_blocked": True,
                "is_whitelisted": False,
            }
        )
    return resultado


def es_ip_bot_perimetro(ip: str) -> bool:
    """True si la IP está bloqueada por el WAF y no tiene whitelist."""
    nombre = (ip or "").strip()
    if not nombre:
        return False
    try:
        estado = obtener_estado_ip(nombre)
        return ip_debe_mostrar_jail(estado) if estado else False
    except Exception:
        return False


def obtener_mapa_bots_perimetro(ips: list[str]) -> dict[str, dict[str, Any]]:
    """
    Consulta batch en ip_cache.db para IPs bloqueadas (is_blocked=1, sin whitelist).

    Returns:
        dict: ip → {is_bot, risk_score, country, isp}.
    """
    unicas = sorted({(i or "").strip() for i in ips if (i or "").strip()})
    if not unicas:
        return {}

    placeholders = ",".join("?" * len(unicas))
    consulta = f"""
    SELECT ip, abuse_score, vt_positives, country, isp
    FROM ip_cache
    WHERE ip IN ({placeholders})
      AND is_blocked = 1
      AND is_whitelisted = 0;
    """
    resultado: dict[str, dict[str, Any]] = {}
    with obtener_conexion_ip_cache() as conexion:
        cursor = conexion.cursor()
        cursor.execute(consulta, unicas)
        for fila in cursor.fetchall():
            abuse = int(fila["abuse_score"] or 0)
            vt = int(fila["vt_positives"] or 0)
            ip_nombre = fila["ip"]
            resultado[ip_nombre] = {
                "is_bot": True,
                "risk_score": calcular_score_riesgo_ip(abuse, vt),
                "country": fila["country"] or VALOR_TEXTO_DEFECTO,
                "isp": fila["isp"] or VALOR_TEXTO_DEFECTO,
            }
    return resultado


def whitelist_ip_perimetro(ip: str) -> bool:
    """
    Desbloquea una IP en ip_cache (whitelist administrativa).

    Returns:
        bool: True si la operación tuvo efecto.
    """
    marcar_ip_verificada_humana(ip)
    return True
