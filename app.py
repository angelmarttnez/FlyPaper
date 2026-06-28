"""
Aplicación principal de FlyPaper.

Este archivo define un honeypot web con Flask que:
- Simula endpoints atractivos para atacantes.
- Clasifica automáticamente cada interacción.
- Guarda eventos en SQLite para posterior análisis.
"""

from dotenv import load_dotenv

load_dotenv()

import csv
import io
import ipaddress
import json
import logging
import random
import re
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse
import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    g,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from flask_limiter import Limiter
from flask_limiter.errors import RateLimitExceeded
from flask_limiter.util import get_remote_address

from database import (
    contar_flags_resueltas_por_usuario,
    enviar_flag_por_usuario,
    guardar_evento,
    guardar_registro_peticion,
    vincular_registro_peticion_evento,
    _ruta_es_zona_administracion,
    guardar_reporte_enviado,
    inicializar_db,
    obtener_comentarios_visibles_post,
    obtener_conexion,
    obtener_ab_posts,
    obtener_ab_post_por_id,
    obtener_ab_comentarios_post,
    guardar_ab_comentario,
    obtener_conexion_autoban,
    obtener_estadisticas,
    obtener_eventos,
    obtener_registros_peticiones,
    obtener_registro_peticion_por_id,
    obtener_peticiones_publicas_por_ip_y_fecha,
    listar_ips_peticiones_publicas,
    listar_fechas_peticiones_publicas_por_ip,
    desbloquear_ip_persistente,
    ip_esta_bloqueada_en_bd,
    listar_ips_bloqueadas,
    contar_ips_bloqueadas,
    obtener_ultimas_expulsiones_autoban,
    obtener_flags_con_estado_por_usuario,
    obtener_flags_publicas,
    reiniciar_progreso_ctf_por_usuario,
    verificar_usuario_privado,
    verificar_admin_panel_privado,
    crear_usuario_publico,
    verificar_credencial_usuario_bd,
    obtener_usuarios_para_panel_admin,
    ROL_PRIV_MONITOR,
    ROL_USUARIO_ADMIN_BD,
    ROL_USUARIO_NORMAL,
    obtener_post_por_id,
    obtener_posts_blog,
    obtener_reportes_enviados,
    obtener_reportes_filtrados,
    obtener_fechas_con_eventos,
    obtener_ultima_fecha_con_eventos,
    RETO_CTF_SQLI,
    contar_eventos_en_fecha,
    guardar_resumen_diario_ia,
    obtener_resumen_diario_ia,
    listar_resumenes_diarios_ia,
    registrar_resumen_log,
    obtener_log_resumenes,
    eliminar_resumen_diario_ia,
    registrar_ip_bloqueada,
    normalizar_periodo_monitor,
    obtener_alertas_graves_monitor,
    obtener_evento_por_id,
    obtener_eventos_ultima_hora,
    obtener_agregados_seguridad_por_ip,
    obtener_ips_distintas_eventos,
)
from ai_analyzer import analizar_payload, generar_resumen_diario, detectar_anomalias
from detector import (
    GRAVEDAD_CRITICA,
    TIPO_TRAFICO_NORMAL,
    calcular_gravedad,
    clasificar_ataque,
    normalizar_gravedad_almacenada,
    normalizar_gravedad_filtro_api,
    prioridad_gravedad,
    registrar_intento_login,
)
from timezone_fp import (
    ZONA_NOMBRE,
    ahora_naive,
    fecha_hoy,
    formatear_marca,
    hace,
    marca_ahora,
    minutos_desde_marca,
)

# Intervalo entre ejecuciones del hilo de fondo (limpieza + anomalías IA, 30 minutos).
INTERVALO_LIMPIEZA_COMENTARIOS_SEG = 30 * 60

# Evita generar más de un resumen automático por día (ventana 23:59 Europe/Madrid).
_ultima_fecha_resumen_auto = None

# Caché en memoria del resumen diario por fecha (evita llamadas repetidas a la API).
_cache_resumen_diario_por_fecha = {}
TTL_RESUMEN_DIARIO_SEG = 3600

# Geolocalización ip-api.com: {ip: {lat, lon, pais, pais_codigo}}
cache_geoip = {}

# Último resultado de detección de anomalías (actualizado por el hilo de fondo).
_cache_anomalias = {"datos": None, "actualizado_en": None}

# Timestamps de comentarios enviados por IP (anti-spam en memoria).
# Ejemplo: {"203.0.113.5": [datetime, datetime, ...]}
comentarios_recientes_por_ip = {}

# ——— Bloqueo de IPs y seguimiento de actividad en tiempo real ———
RUTA_CARPETA_ASSETS = Path(__file__).resolve().parent / "assets"
# Ventana en la que una IP se considera "activa" en el monitor (navegando ahora).
VENTANA_IP_ACTIVA_SEGUNDOS = 15 * 60
ips_bloqueadas = set()
sesiones_invalidadas = set()
tokens_por_ip = defaultdict(set)
ultima_actividad_por_ip = {}


def _campo_evento_a_texto(valor):
    """Convierte payload/headers (objeto o texto) a cadena para el JSON del monitor."""
    if valor is None:
        return ""
    if isinstance(valor, (dict, list)):
        return json.dumps(valor, ensure_ascii=False)
    return str(valor)


def _timestamp_evento_formato_api(valor):
    """Formatea el timestamp como 'YYYY-MM-DD HH:MM:SS' (contrato del API de eventos)."""
    if valor is None or valor == "":
        return ""
    s = str(valor).strip().replace("Z", "")
    if "T" in s:
        s = s.replace("T", " ", 1)
    return s[:19] if len(s) >= 19 else s


def _fila_evento_a_json_monitor(fila):
    """Mapea un dict de BD al esquema JSON que consume el dashboard del monitor."""
    return {
        "id": int(fila["id"]) if fila.get("id") is not None else 0,
        "ip": fila.get("ip") or "",
        "ruta": fila.get("ruta") or "",
        "metodo": fila.get("metodo") or "",
        "payload": _campo_evento_a_texto(fila.get("payload")),
        "user_agent": fila.get("user_agent") or "",
        "tipo_ataque": fila.get("tipo_ataque") or "",
        "gravedad": normalizar_gravedad_almacenada(fila.get("gravedad")) or "",
        "pais": fila.get("pais") or "",
        "timestamp": _timestamp_evento_formato_api(fila.get("timestamp")),
        "headers": _campo_evento_a_texto(fila.get("headers")),
    }


def _evento_detalle_agrupado(fila):
    """
    Evento anidado dentro de un grupo por IP (sin repetir el campo ip en cada ítem).
    """
    return {
        "id": int(fila["id"]) if fila.get("id") is not None else 0,
        "ruta": fila.get("ruta") or "",
        "metodo": fila.get("metodo") or "",
        "payload": _campo_evento_a_texto(fila.get("payload")),
        "tipo_ataque": fila.get("tipo_ataque") or "",
        "gravedad": normalizar_gravedad_almacenada(fila.get("gravedad")) or "",
        "timestamp": _timestamp_evento_formato_api(fila.get("timestamp")),
        "user_agent": fila.get("user_agent") or "",
        "headers": _campo_evento_a_texto(fila.get("headers")),
    }


def _calcular_gravedad_maxima(lista_gravedades):
    """Devuelve la severidad más alta del grupo (Crítica > Alta > Sospechoso)."""
    maxima = ""
    rank_max = 0
    for gravedad in lista_gravedades:
        canon = normalizar_gravedad_almacenada(gravedad)
        if not canon:
            continue
        rank = prioridad_gravedad(canon)
        if rank > rank_max:
            rank_max = rank
            maxima = canon
    return maxima


def agrupar_eventos_por_ip(limite_eventos=500, periodo=None, gravedad=None, ambito="publico"):
    """
    Agrupa eventos recientes por dirección IP para el API del monitor.

    Args:
        limite_eventos (int): Máximo de filas leídas antes de agrupar.
        periodo (str|None): Filtro temporal (hoy, ayer, semana, mes, todo).
        gravedad (str|None): Crítica, Alta o Sospechoso; None = todas las amenazas.
        ambito (str): publico | autoban | admin | todo.

    Returns:
        list[dict]: Grupos con total_eventos, tipos_ataque, gravedad_maxima,
                    primera_vez, ultima_vez y lista de eventos detallados.
    """
    filas = obtener_eventos(
        limite=limite_eventos, periodo=periodo, gravedad=gravedad, ambito=ambito
    )
    mapa_grupos = {}

    for fila in filas:
        ip = fila.get("ip") or ""
        if ip not in mapa_grupos:
            mapa_grupos[ip] = {
                "ip": ip,
                "total_eventos": 0,
                "tipos_set": set(),
                "gravedades": [],
                "timestamps": [],
                "eventos": [],
            }
        grupo = mapa_grupos[ip]
        grupo["total_eventos"] += 1
        tipo = (fila.get("tipo_ataque") or "").strip() or TIPO_TRAFICO_NORMAL
        grupo["tipos_set"].add(tipo)
        grav = normalizar_gravedad_almacenada(fila.get("gravedad"))
        if grav:
            grupo["gravedades"].append(grav)
        ts = _timestamp_evento_formato_api(fila.get("timestamp"))
        if ts:
            grupo["timestamps"].append(ts)
        grupo["eventos"].append(_evento_detalle_agrupado(fila))

    resultado = []
    for grupo in mapa_grupos.values():
        timestamps_ordenados = sorted(grupo["timestamps"])
        resultado.append(
            {
                "ip": grupo["ip"],
                "total_eventos": grupo["total_eventos"],
                "tipos_ataque": sorted(grupo["tipos_set"]),
                "gravedad_maxima": _calcular_gravedad_maxima(grupo["gravedades"]),
                "primera_vez": timestamps_ordenados[0] if timestamps_ordenados else "",
                "ultima_vez": timestamps_ordenados[-1] if timestamps_ordenados else "",
                "eventos": grupo["eventos"],
            }
        )

    resultado.sort(key=lambda g: g.get("ultima_vez") or "", reverse=True)
    return resultado


def _peticion_detalle_agrupado(fila):
    """Petición HTTP anidada dentro de un grupo por IP (monitor)."""
    tipo = (fila.get("tipo_ataque") or TIPO_TRAFICO_NORMAL).strip() or TIPO_TRAFICO_NORMAL
    gravedad = ""
    if tipo != TIPO_TRAFICO_NORMAL:
        gravedad = normalizar_gravedad_almacenada(fila.get("gravedad")) or ""
    return {
        "id": int(fila["id"]) if fila.get("id") is not None else 0,
        "ruta": fila.get("ruta") or "",
        "metodo": fila.get("metodo") or "",
        "codigo_http": fila.get("codigo_http"),
        "timestamp": _timestamp_evento_formato_api(fila.get("timestamp")),
        "tipo_ataque": tipo,
        "gravedad": gravedad,
        "evento_id": fila.get("evento_id"),
    }


def agrupar_peticiones_por_ip(limite_peticiones=2000, periodo=None, ambito="publico"):
    """
    Agrupa peticiones HTTP por IP para las tablas de actividad del monitor.

    Args:
        limite_peticiones (int): Máximo de filas leídas antes de agrupar.
        periodo (str|None): Filtro temporal.
        ambito (str): «publico» o «admin».

    Returns:
        list[dict]: Grupos con total_peticiones, primera_vez, ultima_vez, peticiones.
    """
    filas = obtener_registros_peticiones(
        limite=limite_peticiones, periodo=periodo, ambito=ambito
    )
    mapa_grupos = {}

    for fila in filas:
        ip = fila.get("ip") or ""
        if ip not in mapa_grupos:
            mapa_grupos[ip] = {
                "ip": ip,
                "total_peticiones": 0,
                "timestamps": [],
                "peticiones": [],
            }
        grupo = mapa_grupos[ip]
        grupo["total_peticiones"] += 1
        ts = _timestamp_evento_formato_api(fila.get("timestamp"))
        if ts:
            grupo["timestamps"].append(ts)
        grupo["peticiones"].append(_peticion_detalle_agrupado(fila))

    resultado = []
    for grupo in mapa_grupos.values():
        timestamps_ordenados = sorted(grupo["timestamps"])
        resultado.append(
            {
                "ip": grupo["ip"],
                "total_peticiones": grupo["total_peticiones"],
                "primera_vez": timestamps_ordenados[0] if timestamps_ordenados else "",
                "ultima_vez": timestamps_ordenados[-1] if timestamps_ordenados else "",
                "peticiones": grupo["peticiones"],
            }
        )

    resultado.sort(key=lambda g: g.get("ultima_vez") or "", reverse=True)
    return resultado


def _cabeceras_http_a_lineas(headers_texto):
    """
    Convierte cabeceras almacenadas (JSON o texto) en líneas estilo petición HTTP.

    Args:
        headers_texto (str): Cabeceras serializadas en la BD.

    Returns:
        list[str]: Líneas "Nombre: valor" para el export Wireshark.
    """
    if not headers_texto:
        return []

    texto = headers_texto.strip()
    if not texto:
        return []

    try:
        objeto = json.loads(texto)
        if isinstance(objeto, dict):
            return [f"{nombre}: {valor}" for nombre, valor in objeto.items()]
    except json.JSONDecodeError:
        pass

    return [linea for linea in texto.splitlines() if linea.strip()]


def _bloques_wireshark_desde_registros(registros):
    """Genera bloques de texto estilo Wireshark a partir de filas de BD."""
    bloques = []
    for indice, fila in enumerate(registros, start=1):
        ts = _timestamp_evento_formato_api(fila.get("timestamp"))
        metodo = fila.get("metodo") or "GET"
        ruta = fila.get("ruta") or "/"
        ip = fila.get("ip") or ""
        ua = fila.get("user_agent") or ""

        lineas_bloque = [
            f"=== Petición #{indice} [{ts}] ===",
            f"IP: {ip}",
            f"{metodo} {ruta} HTTP/1.1",
        ]
        if ua:
            lineas_bloque.append(f"User-Agent: {ua}")

        lineas_bloque.extend(_cabeceras_http_a_lineas(fila.get("headers") or ""))
        bloques.append("\n".join(lineas_bloque))
    return bloques


def generar_exportacion_wireshark_headers():
    """
    Construye un .txt con flujo secuencial de peticiones simulando captura Wireshark.
    """
    eventos = obtener_eventos(limite=9999, ambito="todo")
    return "\n\n".join(_bloques_wireshark_desde_registros(eventos))


def generar_exportacion_wireshark_peticiones(peticiones):
    """Exportación Wireshark a partir de filas de `registro_peticiones`."""
    return "\n\n".join(_bloques_wireshark_desde_registros(peticiones))


MENSAJE_EXPORTACION_ACTIVIDAD_INVALIDA = (
    "Debe seleccionar una IP y una fecha exacta de 1 día para exportar"
)


def _validar_exportacion_actividad_publica():
    """
    Valida ip + fecha para exportar actividad pública.

    Returns:
        tuple: ((ip, fecha), None) si válido; (None, mensaje_error) si no.
    """
    ip = (request.args.get("ip") or "").strip()
    fecha = (request.args.get("fecha") or "").strip()
    if not ip or not fecha:
        return None, MENSAJE_EXPORTACION_ACTIVIDAD_INVALIDA

    ips_validas = set(listar_ips_peticiones_publicas())
    if ip not in ips_validas:
        return None, MENSAJE_EXPORTACION_ACTIVIDAD_INVALIDA

    fechas_validas = {
        f["fecha"] for f in listar_fechas_peticiones_publicas_por_ip(ip)
    }
    if fecha not in fechas_validas:
        return None, MENSAJE_EXPORTACION_ACTIVIDAD_INVALIDA

    return (ip, fecha), None


def _respuesta_analisis_ia(registro_id, tipo_ataque, payload, ruta, fuente):
    """Construye la respuesta JSON del análisis Claude (eventos o peticiones)."""
    if _payload_evento_vacio(payload):
        return jsonify({"error": "Este registro no tiene payload para analizar"}), 400

    resultado = analizar_payload(
        tipo_ataque or TIPO_TRAFICO_NORMAL,
        payload,
        ruta or "/",
    )
    return jsonify(
        {
            "registro_id": registro_id,
            "fuente": fuente,
            "tipo_ataque": tipo_ataque,
            "ruta": ruta,
            "analisis": resultado,
        }
    )


def _ataques_detectados_sin_trafico_normal(estadisticas_bd):
    """
    Cuenta eventos cuyo tipo no es tráfico normal (sin distinguir mayúsculas).

    Se usa la agregación `ataques_por_tipo` de `obtener_estadisticas` para no duplicar SQL.
    """
    total = 0
    for tipo, cantidad in (estadisticas_bd.get("ataques_por_tipo") or {}).items():
        texto = str(tipo).strip().lower()
        if texto not in ("otro", "tráfico normal"):
            total += int(cantidad)
    return total


def _minutos_desde_ultimo_evento(periodo=None):
    """Minutos desde el último evento del período hasta ahora (Europe/Madrid)."""
    ultimos = obtener_eventos(limite=1, periodo=periodo)
    if not ultimos:
        return None
    return minutos_desde_marca(ultimos[0].get("timestamp"))


def _actividad_por_hora_desde_buckets(estadisticas_bd):
    """
    Agrupa `eventos_por_hora_ultimas_24h` por hora del día (0–23) en claves string.

    Las claves de entrada son del estilo 'YYYY-MM-DD HH:00:00'; la salida es como {'18': 10}.
    """
    raw = estadisticas_bd.get("eventos_por_hora_ultimas_24h") or {}
    acum = defaultdict(int)
    for clave, cantidad in raw.items():
        if not isinstance(clave, str) or len(clave) < 13 or clave[10] != " ":
            continue
        try:
            hora = int(clave[11:13])
        except ValueError:
            continue
        acum[str(hora)] += int(cantidad)
    return {k: acum[k] for k in sorted(acum.keys(), key=lambda x: int(x))}


def limpiar_comentarios_antiguos():
    """
    Elimina comentarios con más de 24 horas de antigüedad (tarea de mantenimiento).

    Returns:
        int: Número de filas eliminadas.
    """
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            "DELETE FROM comentarios WHERE fecha < ?;",
            (formatear_marca(hace(hours=24)),),
        )
        eliminados = cursor.rowcount
        conexion.commit()
    print(
        f"[FlyPaper] Limpieza automática de comentarios: "
        f"{eliminados} registro(s) eliminado(s) (antigüedad > 24 h)."
    )
    return eliminados


def _debe_generar_resumen_automatico_ahora():
    """True en la ventana 23:59 si aún no hay resumen guardado para hoy."""
    global _ultima_fecha_resumen_auto
    ahora = ahora_naive()
    if not (ahora.hour == 23 and ahora.minute == 59):
        return False
    hoy = fecha_hoy()
    if _ultima_fecha_resumen_auto == hoy:
        return False
    if obtener_resumen_diario_ia(hoy):
        _ultima_fecha_resumen_auto = hoy
        return False
    return True


def _generar_y_guardar_resumen_automatico(fecha):
    """
    Genera el resumen diario con IA, lo persiste y registra en resumenes_log.

    No lanza excepciones: errores se registran con logging para no detener el hilo.
    """
    global _ultima_fecha_resumen_auto
    try:
        total = contar_eventos_en_fecha(fecha)
        texto = generar_resumen_diario(fecha)
        if texto:
            guardar_resumen_diario_ia(fecha, texto, total_eventos=total)
            registrar_resumen_log(
                fecha, "automatico", total, len(texto), ok=True
            )
            logging.info(
                "[FlyPaper] Resumen automático generado para %s: %s caracteres",
                fecha,
                len(texto),
            )
            _ultima_fecha_resumen_auto = fecha
        else:
            registrar_resumen_log(fecha, "automatico", total, 0, ok=False)
    except Exception as exc:
        logging.error(
            "[FlyPaper] Error al generar resumen automático para %s: %s",
            fecha,
            exc,
        )
        try:
            registrar_resumen_log(fecha, "automatico", 0, 0, ok=False)
        except Exception:
            pass


def ejecutar_deteccion_anomalias_fondo():
    """
    Ejecuta detectar_anomalias con eventos de la última hora y guarda el resultado en caché.

    Lo invoca el hilo de fondo cada 30 minutos para no bloquear peticiones HTTP.
    """
    eventos_hora = obtener_eventos_ultima_hora(limite=500)
    resultado = detectar_anomalias(eventos_hora)
    _cache_anomalias["datos"] = resultado
    _cache_anomalias["actualizado_en"] = ahora_naive()
    print(
        f"[FlyPaper] Detección de anomalías (IA): "
        f"{len(eventos_hora)} evento(s), hay_anomalia={resultado.get('hay_anomalia')}"
    )


def tarea_periodica_fondo():
    """
    Bucle del hilo en segundo plano: limpieza de comentarios y anomalías IA cada 30 minutos.
    """
    while True:
        try:
            limpiar_comentarios_antiguos()
        except Exception as exc:
            print(f"[FlyPaper] Error en la limpieza periódica de comentarios: {exc}")
        try:
            ejecutar_deteccion_anomalias_fondo()
        except Exception as exc:
            print(f"[FlyPaper] Error en la detección periódica de anomalías: {exc}")
        try:
            if _debe_generar_resumen_automatico_ahora():
                _generar_y_guardar_resumen_automatico(fecha_hoy())
        except Exception as exc:
            logging.error(
                "[FlyPaper] Error en el scheduler de resumen diario: %s", exc
            )
        time.sleep(INTERVALO_LIMPIEZA_COMENTARIOS_SEG)


def iniciar_hilo_limpieza_comentarios():
    """
    Arranca el hilo daemon de tareas periódicas (no bloquea el cierre del proceso Flask).
    """
    hilo = threading.Thread(
        target=tarea_periodica_fondo,
        name="flypaper-tareas-fondo",
        daemon=True,
    )
    hilo.start()
    print(
        "[FlyPaper] Hilo de fondo iniciado (limpieza, anomalías IA y resumen 23:59, "
        "cada 30 minutos)."
    )


def _limpiar_ventana_comentarios_ip(ip):
    """Deja solo los timestamps de comentarios de los últimos 5 minutos para esa IP."""
    ahora = ahora_naive()
    hace_cinco_minutos = hace(minutes=5)
    if ip not in comentarios_recientes_por_ip:
        comentarios_recientes_por_ip[ip] = []
    comentarios_recientes_por_ip[ip] = [
        marca
        for marca in comentarios_recientes_por_ip[ip]
        if marca > hace_cinco_minutos
    ]


def excede_limite_spam_comentarios(ip):
    """
    True si la IP ya envió más de 3 comentarios en los últimos 5 minutos.

    El cuarto intento (y siguientes) dentro de la ventana se rechazan con 429.
    """
    if not ip:
        return False
    _limpiar_ventana_comentarios_ip(ip)
    # Ya hay 3 en la ventana → el siguiente sería el 4.º (más de 3 en 5 minutos).
    return len(comentarios_recientes_por_ip[ip]) >= 3


def registrar_comentario_en_memoria(ip):
    """Registra en memoria un comentario guardado correctamente (control anti-spam)."""
    if not ip:
        return
    _limpiar_ventana_comentarios_ip(ip)
    comentarios_recientes_por_ip[ip].append(ahora_naive())


def respuesta_error_comentario_json(mensaje, codigo_http=429):
    """Respuesta JSON uniforme para límites y anti-spam en POST /blog/.../comentar."""
    return jsonify({"error": True, "mensaje": mensaje}), codigo_http


# Comentarios de visitantes: solo en sesión Flask (no persisten en BD global).
CLAVE_SESION_COMENTARIOS_VOLATILES = "comentarios_volatiles"
LIMITE_COMENTARIOS_SESION_POR_POST = 3


def _obtener_lista_comentarios_volatiles():
    """Lista de comentarios temporales del visitante actual (cookie de sesión firmada)."""
    if CLAVE_SESION_COMENTARIOS_VOLATILES not in session:
        session[CLAVE_SESION_COMENTARIOS_VOLATILES] = []
    return session[CLAVE_SESION_COMENTARIOS_VOLATILES]


def _comentarios_volatiles_del_post(post_id):
    """Comentarios de sesión asociados a un post concreto."""
    post_id_int = int(post_id)
    return [
        c
        for c in _obtener_lista_comentarios_volatiles()
        if int(c.get("post_id", 0)) == post_id_int
    ]


def _contar_comentarios_volatiles_post(post_id):
    """Cuenta comentarios temporales activos del usuario en este post (límite dinámico)."""
    return len(_comentarios_volatiles_del_post(post_id))


def _agregar_comentario_volatil(post_id, autor_nombre, contenido):
    """
    Añade un comentario solo a la sesión del visitante (visible para él al recargar).

    No escribe en la tabla `comentarios` de SQLite.
    """
    marca = marca_ahora()
    nuevo = {
        "id": str(uuid.uuid4()),
        "post_id": int(post_id),
        "nombre": autor_nombre,
        "comentario": contenido,
        "fecha": marca,
    }
    lista = _obtener_lista_comentarios_volatiles()
    lista.append(nuevo)
    session[CLAVE_SESION_COMENTARIOS_VOLATILES] = lista
    session.modified = True
    return nuevo


def _eliminar_comentario_volatil(post_id, comentario_id):
    """
    Quita un comentario de sesión por id. Libera cupo del límite de 3 si se borró uno activo.

    Returns:
        bool: True si existía y pertenecía a este post y sesión.
    """
    if not comentario_id:
        return False
    post_id_int = int(post_id)
    lista = _obtener_lista_comentarios_volatiles()
    nueva_lista = [
        c
        for c in lista
        if not (int(c.get("post_id", 0)) == post_id_int and c.get("id") == comentario_id)
    ]
    if len(nueva_lista) == len(lista):
        return False
    session[CLAVE_SESION_COMENTARIOS_VOLATILES] = nueva_lista
    session.modified = True
    return True


def construir_comentarios_para_vista(post_id):
    """
    Combina comentarios oficiales (BD) con los temporales de la sesión actual.

    Los de BD se cargan siempre; los volátiles solo los ve quien los creó en su sesión.
    """
    comentarios_bd = obtener_comentarios_visibles_post(post_id)
    vista = [
        {
            "nombre": c["nombre"],
            "comentario": c["comentario"],
            "fecha": c["fecha"],
            "es_sesion": False,
            "id": None,
        }
        for c in comentarios_bd
    ]
    for c in _comentarios_volatiles_del_post(post_id):
        vista.append(
            {
                "nombre": c.get("nombre") or "Anónimo",
                "comentario": c.get("comentario") or "",
                "fecha": c.get("fecha") or "",
                "es_sesion": True,
                "id": c.get("id"),
            }
        )
    vista.sort(key=lambda item: item.get("fecha") or "")
    return vista


# Creamos la instancia principal de Flask.
aplicacion = Flask(__name__)
# Clave para firmar cookies de sesión (login honeypot y otras sesiones).
aplicacion.secret_key = 'flypaper_secreto_2026'

# Sesión pública (/search, /blog, /objetivos, /documentacion): caducidad por inactividad de 15 minutos.
SESION_PUBLICA_INACTIVIDAD_SEGUNDOS = 900
SESION_PUBLICA_INACTIVIDAD = timedelta(seconds=SESION_PUBLICA_INACTIVIDAD_SEGUNDOS)
CLAVE_ULTIMA_ACTIVIDAD_PUBLICA = "ultima_actividad_publica_ts"

aplicacion.config["PERMANENT_SESSION_LIFETIME"] = SESION_PUBLICA_INACTIVIDAD
aplicacion.config["SESSION_REFRESH_EACH_REQUEST"] = True

# Límite global por IP (resto de rutas públicas). Rutas /monitor/* quedan exentas más abajo.
limiter = Limiter(
    key_func=get_remote_address,
    app=aplicacion,
    default_limits=["200 per minute"],
)


@limiter.request_filter
def _exemptir_monitor_de_rate_limit():
    """
    El panel /monitor no lleva rate limit: el acceso ya está acotado por sesión de analista.
    """
    return request.path.startswith("/monitor")


@aplicacion.errorhandler(RateLimitExceeded)
def manejar_limite_peticiones(_exc):
    """Respuesta JSON uniforme (429) cuando se supera cualquier límite de tasa."""
    return jsonify({"error": "Demasiadas peticiones. Espera un momento."}), 429


# Etiqueta legacy para logs y visitas sin sesión (p. ej. landing /).
ROL_INVITADO = "invitado"

# Inicializamos la base de datos al arrancar la aplicación para asegurar
# que la tabla `eventos` exista antes de intentar guardar información.
inicializar_db()


def cargar_cache_ips_bloqueadas():
    """Sincroniza el conjunto en memoria con la tabla persistente ips_bloqueadas."""
    ips_bloqueadas.clear()
    for ip in listar_ips_bloqueadas():
        ips_bloqueadas.add(ip)


cargar_cache_ips_bloqueadas()

# Tarea en segundo plano: purga de comentarios antiguos al cargar el módulo Flask.
iniciar_hilo_limpieza_comentarios()


def _es_ruta_sesion_publica(path):
    """True si la ruta pertenece al portal de usuario (/search, /blog, /objetivos, /documentacion)."""
    if path == "/search" or path.startswith("/search/"):
        return True
    if path == "/blog" or path.startswith("/blog/"):
        return True
    if path == "/objetivos" or path.startswith("/objetivos/"):
        return True
    if path == "/documentacion" or path.startswith("/documentacion/"):
        return True
    if path == "/diversion/carta" or path.startswith("/diversion/carta/"):
        return True
    return False


def _usuario_publico_autenticado():
    """True si hay un usuario honeypot logueado (no Invitado)."""
    return session.get("logueado") is True and bool(session.get("usuario"))


def _limpiar_estado_sesion_publica():
    """
    Elimina credenciales y estado temporal del área pública sin tocar sesión de monitor.

    Tras la limpieza el visitante debe volver a autenticarse para acceder al portal.
    """
    for clave in (
        "logueado",
        "usuario",
        "rol",
        CLAVE_ULTIMA_ACTIVIDAD_PUBLICA,
        CLAVE_SESION_COMENTARIOS_VOLATILES,
    ):
        session.pop(clave, None)
    session.modified = True


def _sesion_publica_expirada_por_inactividad():
    """True si la última actividad en rutas públicas supera el límite de 15 minutos."""
    ultima = session.get(CLAVE_ULTIMA_ACTIVIDAD_PUBLICA)
    if ultima is None:
        return False
    try:
        ultima_ts = float(ultima)
    except (TypeError, ValueError):
        return False
    return (time.time() - ultima_ts) > SESION_PUBLICA_INACTIVIDAD_SEGUNDOS


def _marcar_actividad_sesion_publica():
    """Actualiza el timestamp de última interacción en el área pública."""
    session.permanent = True
    session[CLAVE_ULTIMA_ACTIVIDAD_PUBLICA] = time.time()
    session.modified = True


def _invalidar_sesion_honeypot_en_servidor():
    """
    Destruye la sesión del visitante e invalida su token para que la cookie no se reutilice.

    No conserva rol Invitado ni credenciales; la próxima visita a rutas públicas
    creará una sesión nueva desde cero.
    """
    ip = obtener_ip_cliente()
    token = session.get("token_sesion")
    if token:
        sesiones_invalidadas.add(token)
        if ip:
            tokens_por_ip[ip].discard(token)
    session.clear()
    session.modified = True


def _destino_tras_login_seguro(destino):
    """
    Valida una ruta interna para redirigir tras login o registro.

    Solo permite destinos del portal público autenticado (evita open redirect).
    """
    texto = (destino or "").strip()
    if not texto or texto.startswith("//") or "://" in texto:
        return None
    if not texto.startswith("/"):
        return None
    parsed = urlparse(texto)
    ruta = parsed.path or ""
    if ruta in ("/", "/login", "/register"):
        return None
    if not _es_ruta_sesion_publica(ruta):
        return None
    if parsed.query:
        return f"{ruta}?{parsed.query}"
    return ruta


def _redirect_login_sin_cache(**parametros_url):
    """Redirección 302 a /login con cabeceras que impiden cachear la respuesta."""
    respuesta = redirect(url_for("mostrar_login", **parametros_url), code=302)
    respuesta.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    respuesta.headers["Pragma"] = "no-cache"
    respuesta.headers["Expires"] = "0"
    return respuesta


def _contexto_barra_sesion():
    """Variables para la barra de sesión en plantillas públicas."""
    if session.get("logueado") is True and session.get("usuario"):
        return {
            "sesion_logueado": True,
            "sesion_etiqueta": session.get("usuario"),
            "sesion_rol": session.get("rol") or "usuario",
        }
    return {
        "sesion_logueado": False,
        "sesion_etiqueta": "Invitado",
        "sesion_rol": ROL_INVITADO,
    }


def formatear_tamano_bytes(num_bytes):
    """Convierte bytes a texto legible (B, KB, MB)."""
    if num_bytes is None:
        return "—"
    try:
        n = int(num_bytes)
    except (TypeError, ValueError):
        return "—"
    if n < 0:
        return "—"
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.1f} MB"


def _usuario_activo_para_log():
    """Etiqueta de usuario de sesión pública o analista del monitor."""
    if session.get("logueado") is True and session.get("usuario"):
        return str(session.get("usuario"))
    if session.get("analyst") is True:
        return "Analista"
    return "Invitado"


def _sesion_id_corto_para_log():
    """Primeros 8 caracteres del token de sesión (auditoría)."""
    if "token_sesion" not in session:
        session["token_sesion"] = str(uuid.uuid4())
    token = session.get("token_sesion")
    if token:
        return str(token).replace("-", "")[:8]
    nombre_cookie = aplicacion.config.get("SESSION_COOKIE_NAME", "session")
    cookie_val = request.cookies.get(nombre_cookie)
    if cookie_val:
        return str(cookie_val)[:8]
    return ""


def _puerto_origen_cliente():
    """Puerto TCP efímero del cliente (o cabecera de proxy)."""
    puerto = request.environ.get("REMOTE_PORT")
    if puerto is not None:
        return str(puerto)
    xfp = request.headers.get("X-Forwarded-Port")
    if xfp:
        return str(xfp).split(",")[0].strip()
    return ""


def _tamano_respuesta_bytes(respuesta):
    """Tamaño del cuerpo de respuesta en bytes."""
    try:
        if respuesta.content_length is not None and respuesta.content_length >= 0:
            return int(respuesta.content_length)
    except (TypeError, AttributeError):
        pass
    cl_header = respuesta.headers.get("Content-Length")
    if cl_header is not None and str(cl_header).strip().isdigit():
        return int(cl_header)
    try:
        datos = respuesta.get_data()
        return len(datos) if datos else 0
    except (RuntimeError, TypeError):
        return 0


def _tiempo_procesamiento_ms():
    """Milisegundos desde before_request hasta after_request."""
    inicio = getattr(g, "_inicio_peticion_perf", None)
    if inicio is None:
        return None
    return max(0, int(round((time.perf_counter() - inicio) * 1000)))


@aplicacion.before_request
def _marcar_inicio_telemetria_peticion():
    """Marca el instante de entrada para medir tiempo de respuesta."""
    g._inicio_peticion_perf = time.perf_counter()


@aplicacion.before_request
def control_acceso_y_inactividad_portal_publico():
    """
    En /search, /blog, /objetivos y /documentacion exige sesión de usuario activa.

    Sin autenticación → /login. Con inactividad > 15 min → cierre y aviso en login.
    """
    if not _es_ruta_sesion_publica(request.path):
        return None

    if not _usuario_publico_autenticado():
        ruta = request.path or ""
        if ruta.startswith("/objetivos/") and request.method == "POST":
            return jsonify({"exito": False, "mensaje": "Unauthorized"}), 401
        return _redirect_login_sin_cache(next=request.full_path)

    if _sesion_publica_expirada_por_inactividad():
        _limpiar_estado_sesion_publica()
        return redirect(url_for("mostrar_login", reason="timeout"))

    _marcar_actividad_sesion_publica()
    return None


def _plantilla_publica(nombre, nav_activo=None, **kwargs):
    """Render con contexto de navbar y sesión unificado."""
    ctx = _contexto_barra_sesion()
    ctx["nav_activo"] = nav_activo
    ctx["sesion_inactividad_seg"] = SESION_PUBLICA_INACTIVIDAD_SEGUNDOS
    ctx.update(kwargs)
    return render_template(nombre, **ctx)


def _payload_registro_vacio(payload):
    """True si no hay formulario, JSON, query string ni cuerpo útil para clasificar."""
    if payload is None:
        return True
    if isinstance(payload, str):
        return not payload.strip()
    if isinstance(payload, dict):
        return len(payload) == 0
    return False


def construir_payload_url_404():
    """
    Payload estructurado con la URL intentada en respuestas 404 sin cuerpo.

    Permite que clasificar_ataque() detecte path traversal aunque request.form esté vacío.
    """
    path = request.path or ""
    qs = request.query_string.decode("utf-8", errors="ignore")
    url_completa = path + ("?" + qs if qs else "")
    return {
        "url_intentada": path,
        "query_string": qs,
        "url_completa": url_completa,
    }


def construir_payload_para_registro(codigo_http=None):
    """
    Construye una representación de payload útil para almacenar en la BD.

    Prioridad utilizada:
    1) Si hay formulario (`request.form`), guardamos ese diccionario.
    2) Si hay JSON (`request.get_json`), guardamos ese objeto.
    3) Si hay query string (`request.args`), guardamos esos parámetros.
    4) Si no hay estructura previa, guardamos el cuerpo en texto bruto.
    5) Si la respuesta es 404 y sigue vacío, usamos la URL completa (path traversal en GET).

    Returns:
        dict | str: Información de entrada enviada por el visitante.
    """
    if request.form:
        return request.form.to_dict(flat=True)

    contenido_json = request.get_json(silent=True)
    if contenido_json is not None:
        return contenido_json

    if request.args:
        return request.args.to_dict(flat=True)

    cuerpo = request.get_data(as_text=True) or ""
    if cuerpo.strip():
        return cuerpo

    if codigo_http == 404:
        return construir_payload_url_404()

    return ""


def debe_excluirse_del_registro(ruta_solicitada):
    """
    Indica si una ruta debe quedar fuera del almacenamiento de eventos.

    Según tu requisito, se excluyen rutas que comiencen por:
    - /dashboard
    - /static

    Args:
        ruta_solicitada (str): Ruta de la petición HTTP.

    Returns:
        bool: True si debe excluirse, False en caso contrario.
    """
    return (
        ruta_solicitada.startswith("/dashboard")
        or ruta_solicitada.startswith("/static")
        or ruta_solicitada.startswith("/assets")
    )


def omitir_registro_automatico_honeypot(ruta_solicitada, metodo):
    """
    Evita doble registro cuando una vista ya guarda el evento con reglas propias.

    POST /search, POST /secure/search y POST /secure/blog/.../comentar registran manualmente.
    """
    if ruta_solicitada == "/search" and metodo == "POST":
        return True
    if ruta_solicitada == "/secure/search" and metodo == "POST":
        return True
    if metodo == "POST" and re.match(r"^/secure/blog/\d+/comentar$", ruta_solicitada or ""):
        return True
    return False


# ——— Auto-ban: rutas señuelo /secure/* ———
TIPOS_ATAQUE_AUTOBAN_BLOQUEO = frozenset({
    "SQLi",
    "XSS",
    "Path Traversal",
    "Fuerza Bruta",
    "Scanner Automatizado",
})


def _ambito_desde_ruta(ruta):
    """Determina el ámbito de almacenamiento según la ruta visitada."""
    path = (ruta or "").strip()
    if path.startswith("/secure/"):
        return "autoban"
    if _ruta_es_zona_administracion(path):
        return "admin"
    return "publico"


def _url_completa_peticion():
    """Ruta + query string decodificada para análisis de patrones en la URL."""
    url_completa = request.path or ""
    if request.query_string:
        url_completa += "?" + request.query_string.decode("utf-8", errors="ignore")
    return url_completa


def _tipo_dispara_autoban(tipo_ataque):
    """True si el tipo de ataque debe provocar bloqueo inmediato en zona /secure/."""
    return (tipo_ataque or "").strip() in TIPOS_ATAQUE_AUTOBAN_BLOQUEO


def _debe_analizar_url_secure_en_before_request(ruta, metodo):
    """
    Decide si la URL de una petición /secure/* requiere clasificación en before_request.

    Las vistas conocidas (search, blog, comentarios) sin query string delegan el análisis
    del cuerpo POST a su propia ruta. Cualquier query o ruta desconocida se inspecciona aquí.
    """
    if request.query_string:
        return True

    ruta_base = (ruta or "").split("?")[0].rstrip("/") or "/"
    metodo_up = (metodo or "GET").upper()

    if metodo_up == "GET":
        if ruta_base in ("/secure/search", "/secure/blog"):
            return False
        if re.match(r"^/secure/blog/\d+$", ruta_base):
            return False

    if metodo_up == "POST":
        if ruta_base == "/secure/search":
            return False
        if re.match(r"^/secure/blog/\d+/comentar$", ruta_base):
            return False

    return True


def _inspeccionar_ruta_secure_autoban(ip, ruta):
    """
    Inspección temprana de peticiones /secure/* en before_request.

    Construye url_completa (ruta + query), la pasa a clasificar_ataque() y, si el tipo
    es bloqueable (Path Traversal, SQLi, XSS, Scanner, Fuerza Bruta), registra un único
    evento autoban con gravedad Crítica, bloquea la IP y devuelve expulsado (403) antes
    de que Flask resuelva la vista o dispare el manejador 404.
    """
    if not _debe_analizar_url_secure_en_before_request(ruta, request.method):
        return None

    url_completa = _url_completa_peticion()
    user_agent = request.headers.get("User-Agent", "")
    cabeceras = dict(request.headers)
    tipo_ataque = clasificar_ataque(
        ruta=ruta,
        payload=url_completa,
        user_agent=user_agent,
        headers=cabeceras,
        metodo=request.method,
    )

    if not _tipo_dispara_autoban(tipo_ataque):
        return None

    # IP ya bloqueada: expulsar sin reinsertar en BD (evita colisiones de escritura).
    if visitante_esta_bloqueado(ip):
        session.clear()
        return respuesta_expulsion_visitante()

    guardar_evento(
        ip=ip,
        ruta=ruta,
        metodo=request.method,
        payload=url_completa,
        user_agent=user_agent,
        tipo_ataque=tipo_ataque,
        headers=cabeceras,
        gravedad=GRAVEDAD_CRITICA,
        ambito="autoban",
    )
    g.autoban_evento_ya_registrado = True

    bloquear_ip_visitante(ip, motivo=f"Auto-ban: {tipo_ataque} en {ruta}")
    session.clear()
    return respuesta_expulsion_visitante()


def _autoban_si_corresponde(ip, tipo_ataque, motivo="Bloqueo automático zona /secure/"):
    """
    Bloquea la IP tras un ataque detectado en el cuerpo de una vista /secure/*.

    El evento ya debe estar guardado por la vista; aquí solo aplica el bloqueo.
    """
    if not _tipo_dispara_autoban(tipo_ataque):
        return None

    g.autoban_evento_ya_registrado = True

    if visitante_esta_bloqueado(ip):
        session.clear()
        return respuesta_expulsion_visitante()

    bloquear_ip_visitante(ip, motivo=motivo)
    session.clear()
    return respuesta_expulsion_visitante()


def _ejecutar_busqueda_vulnerable(query):
    """
    Ejecuta la consulta SQLi deliberadamente vulnerable sobre `posts`.

    Returns:
        tuple: (resultados, error_sql)
    """
    resultados = []
    error_sql = None
    sql = (
        f"SELECT id, titulo, contenido, fecha FROM posts "
        f"WHERE titulo LIKE '%{query}%' OR contenido LIKE '%{query}%'"
    )
    try:
        with obtener_conexion() as conexion:
            cursor = conexion.cursor()
            cursor.execute(sql)
            columnas = [desc[0] for desc in cursor.description] if cursor.description else []
            for fila in cursor.fetchall():
                resultados.append(dict(zip(columnas, fila)))
    except Exception as exc:
        error_sql = str(exc)
    return resultados, error_sql


def _ejecutar_busqueda_autoban_vulnerable(query):
    """
    Consulta SQLi deliberadamente vulnerable sobre ab_posts (flypaper_autoban.db).

    No accede a flypaper.db: UNION y extracciones solo ven datos genéricos del señuelo.

    Returns:
        tuple: (resultados, error_sql)
    """
    resultados = []
    error_sql = None
    sql = (
        f"SELECT id, titulo, contenido, autor FROM ab_posts "
        f"WHERE titulo LIKE '%{query}%' OR contenido LIKE '%{query}%'"
    )
    try:
        with obtener_conexion_autoban() as conexion:
            cursor = conexion.cursor()
            cursor.execute(sql)
            columnas = [desc[0] for desc in cursor.description] if cursor.description else []
            for fila in cursor.fetchall():
                resultados.append(dict(zip(columnas, fila)))
    except Exception as exc:
        error_sql = str(exc)
    return resultados, error_sql


def obtener_ip_cliente():
    """Obtiene la IP del cliente respetando X-Forwarded-For si existe."""
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    if "," in ip:
        ip = ip.split(",")[0].strip()
    return ip


def ruta_exenta_de_bloqueo_ip(ruta):
    """
    Rutas accesibles aunque la IP esté bloqueada (monitor, assets, reintento y login).

    Tras /acceso/reintentar la IP se desbloquea y el visitante puede volver al inicio.
    """
    if not ruta:
        return False
    if ruta.startswith("/monitor"):
        return True
    if ruta.startswith("/assets/"):
        return True
    if ruta in ("/acceso/reintentar", "/login", "/register", "/admin/login", "/monitor/login", "/expulsado"):
        return True
    return False


def registrar_actividad_visitante(ip):
    """Actualiza la marca de actividad y el token de sesión asociado a la IP."""
    if not ip:
        return
    ultima_actividad_por_ip[ip] = ahora_naive()
    if "token_sesion" not in session:
        session["token_sesion"] = str(uuid.uuid4())
    token = session["token_sesion"]
    tokens_por_ip[ip].add(token)


def ip_tiene_actividad_reciente(ip):
    """True si la IP ha hecho alguna petición al servidor en la ventana configurada."""
    if not ip:
        return False
    ultima = ultima_actividad_por_ip.get(ip)
    if ultima is None:
        return False
    delta = (ahora_naive() - ultima).total_seconds()
    return delta <= VENTANA_IP_ACTIVA_SEGUNDOS


def listar_ips_con_actividad_reciente():
    """Lista de IPs consideradas activas para mostrar el botón Bloquear en el monitor."""
    return [ip for ip in ultima_actividad_por_ip if ip_tiene_actividad_reciente(ip)]


def bloquear_ip_visitante(ip, motivo="Bloqueo desde monitor de seguridad"):
    """
    Bloqueo persistente (SQLite) + caché en memoria e invalidación de tokens de sesión.
    """
    if not ip:
        return False
    registrar_ip_bloqueada(ip, motivo=motivo)
    ips_bloqueadas.add(ip)
    for token in list(tokens_por_ip.get(ip, set())):
        sesiones_invalidadas.add(token)
    return True


def desbloquear_ip_visitante(ip):
    """
    Quita el bloqueo persistente y limpia tokens invalidados (flujo «Volver a intentar»).
    """
    if not ip:
        return False
    desbloquear_ip_persistente(ip)
    ips_bloqueadas.discard(ip)
    for token in list(tokens_por_ip.get(ip, set())):
        sesiones_invalidadas.discard(token)
    return True


def visitante_esta_bloqueado(ip):
    """Comprueba lista negra persistente, caché en memoria o token de sesión invalidado."""
    if not ip:
        return False
    if ip in ips_bloqueadas or ip_esta_bloqueada_en_bd(ip):
        if ip not in ips_bloqueadas:
            ips_bloqueadas.add(ip)
        return True
    token = session.get("token_sesion")
    return token is not None and token in sesiones_invalidadas


def respuesta_expulsion_visitante():
    """Pantalla de expulsión a pantalla completa (HTTP 403)."""
    return render_template("expulsado.html"), 403


@aplicacion.before_request
def middleware_bloqueo_ip_y_actividad():
    """
    Middleware global unificado: inspección /secure/*, actividad por IP y lista negra.

    Orden de ejecución (sin manejador 404 específico para /secure/*):
    1) Si la ruta empieza por /secure/, analizar la URL y cortar con 403 si hay ataque.
    2) Registrar actividad de la IP en memoria (monitor en tiempo real).
    3) Eximir /monitor y rutas de reintento del bloqueo por IP.
    4) Devolver expulsado si la IP ya está bloqueada.
    """
    ruta = request.path or ""
    ip = obtener_ip_cliente()

    # Prioridad máxima: cortar ataques en URL antes del enrutado Flask.
    if ruta.startswith("/secure/"):
        respuesta_autoban = _inspeccionar_ruta_secure_autoban(ip, ruta)
        if respuesta_autoban is not None:
            return respuesta_autoban

    registrar_actividad_visitante(ip)

    if ruta_exenta_de_bloqueo_ip(ruta):
        return None

    if visitante_esta_bloqueado(ip):
        return respuesta_expulsion_visitante()

    return None


@aplicacion.get("/expulsado")
def pagina_expulsado():
    """Pantalla de expulsión accesible tras redirección desde auto-ban o bloqueo manual."""
    return render_template("expulsado.html"), 403


@aplicacion.route("/assets/<path:nombre_archivo>")
def servir_archivo_assets(nombre_archivo):
    """Sirve recursos estáticos del proyecto (p. ej. Cat.gif en la expulsión)."""
    return send_from_directory(RUTA_CARPETA_ASSETS, nombre_archivo)


@aplicacion.post("/acceso/reintentar")
def acceso_reintentar_tras_bloqueo():
    """
    Desbloquea la IP del visitante sin cerrar su sesión del portal y redirige al inicio.

    Conserva credenciales honeypot (`logueado`, `usuario`, etc.) para que el visitante
    vuelva a la landing sin tener que autenticarse de nuevo.
    """
    ip = obtener_ip_cliente()
    desbloquear_ip_visitante(ip)
    return jsonify({"exito": True, "redirect": url_for("mostrar_landing")})


def acceso_monitor_autorizado():
    """
    Comprueba si el analista autenticó correctamente en /monitor/login.

    Solo se considera válido `session["analyst"] == True` (sin atajos por URL).

    Returns:
        bool: True si la sesión de analista está activa, False en caso contrario.
    """
    return session.get("analyst") is True


def requiere_autenticacion_monitor(funcion_vista):
    """
    Decorador para proteger rutas del monitor privado.

    Si no hay sesión de analista (`session["analyst"]`), redirige al login del monitor.
    """

    @wraps(funcion_vista)
    def envoltorio(*args, **kwargs):
        if not acceso_monitor_autorizado():
            return redirect(url_for("mostrar_admin_login"))
        return funcion_vista(*args, **kwargs)

    return envoltorio


@aplicacion.after_request
def registrar_evento_honeypot(respuesta):
    """
    Registra cada petición HTTP en la base de datos (con excepciones).

    Flujo del registro:
    - Identificar IP, ruta, método, payload, user-agent y cabeceras.
    - Clasificar automáticamente el tipo de ataque.
    - Guardar el evento en SQLite.

    Nota:
    Se hace en `after_request` para no interferir con el flujo principal
    de las rutas ni con la respuesta que recibe el cliente.
    """
    ruta_visitada = request.path or ""
    metodo_peticion = request.method
    ip_visitante = obtener_ip_cliente()
    user_agent_visitante = request.headers.get("User-Agent", "")
    cabeceras_peticion = dict(request.headers)
    payload_peticion = construir_payload_para_registro(codigo_http=respuesta.status_code)

    # En 404 sin cuerpo, forzar URL como payload para reclasificar path traversal.
    if respuesta.status_code == 404 and _payload_registro_vacio(payload_peticion):
        payload_peticion = construir_payload_url_404()

    tipo_ataque_detectado = clasificar_ataque(
        ruta=ruta_visitada,
        payload=str(payload_peticion),
        user_agent=user_agent_visitante,
        headers=cabeceras_peticion,
        metodo=metodo_peticion,
    )

    # Fuerza bruta: POST /login con más de 5 intentos/minuto por la misma IP.
    if (
        metodo_peticion == "POST"
        and ruta_visitada == "/login"
        and session.pop("_fuerza_bruta_detectada", False)
    ):
        tipo_ataque_detectado = "Fuerza Bruta"

    gravedad_evento = calcular_gravedad(tipo_ataque_detectado)
    ambito_evento = _ambito_desde_ruta(ruta_visitada)

    peticion_id = guardar_registro_peticion(
        ip=ip_visitante,
        ruta=ruta_visitada,
        metodo=metodo_peticion,
        codigo_http=respuesta.status_code,
        user_agent=user_agent_visitante,
        payload=payload_peticion,
        headers=cabeceras_peticion,
        tipo_ataque=tipo_ataque_detectado,
        gravedad=gravedad_evento,
        usuario_activo=_usuario_activo_para_log(),
        sesion_id_corto=_sesion_id_corto_para_log(),
        tiempo_ms=_tiempo_procesamiento_ms(),
        tamano_respuesta_bytes=_tamano_respuesta_bytes(respuesta),
        puerto_origen=_puerto_origen_cliente(),
        ambito=ambito_evento,
    )

    # Omitimos rutas internas/estáticas y eventos ya guardados en before_request, 404 o vistas.
    if (
        debe_excluirse_del_registro(ruta_visitada)
        or omitir_registro_automatico_honeypot(ruta_visitada, metodo_peticion)
        or getattr(g, "autoban_evento_ya_registrado", False)
        or getattr(g, "evento_404_publico_registrado", False)
    ):
        return respuesta

    # Alertas de /admin y /monitor solo en registro_peticiones (ámbito admin).
    if _ruta_es_zona_administracion(ruta_visitada):
        return respuesta

    evento_id = guardar_evento(
        ip=ip_visitante,
        ruta=ruta_visitada,
        metodo=metodo_peticion,
        payload=payload_peticion,
        user_agent=user_agent_visitante,
        tipo_ataque=tipo_ataque_detectado,
        headers=cabeceras_peticion,
        gravedad=gravedad_evento,
        ambito=ambito_evento,
    )

    if peticion_id and evento_id:
        vincular_registro_peticion_evento(peticion_id, evento_id)

    return respuesta


@aplicacion.get("/")
def mostrar_landing():
    """
    Muestra la landing pública de FlyPaper (sin autenticación).

    Cualquier visitante puede acceder. La petición se registra en SQLite
    mediante `registrar_evento_honeypot` (after_request), igual que el resto
    de rutas no excluidas del honeypot.
    """
    return render_template("index.html")


@aplicacion.get("/login")
def mostrar_login():
    """
    Muestra el formulario de autenticación falso.

    Renderiza la plantilla `login.html`, que simula una pantalla de acceso.
    """
    mensaje_timeout = None
    mensaje_cierre = None
    if request.args.get("reason") == "timeout":
        mensaje_timeout = (
            "Tu sesión ha expirado por inactividad (15 minutos). "
            "Vuelve a iniciar sesión."
        )
    elif request.args.get("cerrado") == "1":
        mensaje_cierre = "Has cerrado sesión. Vuelve a iniciar sesión para continuar."

    destino_siguiente = _destino_tras_login_seguro(request.args.get("next"))

    respuesta = make_response(
        render_template(
            "login.html",
            mensaje_timeout=mensaje_timeout,
            mensaje_cierre=mensaje_cierre,
            destino_siguiente=destino_siguiente,
        )
    )
    respuesta.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    respuesta.headers["Pragma"] = "no-cache"
    respuesta.headers["Expires"] = "0"
    return respuesta


# Usuarios de demostración sin privilegios (acceso solo a /search, /blog y /objetivos).
USUARIOS_DEMO_PUBLICOS = {
    "Angel": {"password": "Angel123", "redirige": "/search"},
    "Carlos": {"password": "Carlos123", "redirige": "/search"},
}


def _redirigir_si_no_es_admin():
    """
    Protege rutas /admin: requiere sesión activa y rol «admin».

    Returns:
        Response | None: Redirección si no cumple; None si el acceso es válido.
    """
    if session.get("logueado") is not True:
        return redirect(url_for("mostrar_admin_login"))
    if session.get("rol") != ROL_USUARIO_ADMIN_BD:
        return redirect("/search?error=acceso_denegado")
    return None


def _iniciar_sesion_publica(nombre, rol):
    """Abre sesión en el portal público (/search, /blog, /objetivos)."""
    session.permanent = True
    session["logueado"] = True
    session["usuario"] = nombre
    session["rol"] = rol
    _marcar_actividad_sesion_publica()


def _iniciar_sesion_admin_panel(nombre):
    """Abre sesión con privilegios de panel /admin (sin escalado desde login público)."""
    session.permanent = True
    session["logueado"] = True
    session["usuario"] = nombre
    session["rol"] = ROL_USUARIO_ADMIN_BD
    _marcar_actividad_sesion_publica()


@aplicacion.get("/admin/login")
def mostrar_admin_login():
    """
    Formulario de acceso al portal de administración (/admin).

    Solo valida cuentas admin_panel en flypaper_priv.db (POST dedicado).
    """
    mensaje_error = None
    if request.args.get("error") == "admin_portal":
        mensaje_error = "Credenciales no válidas para el portal de administración."
    elif request.args.get("error") == "1":
        mensaje_error = "Credenciales no válidas para el portal de administración."

    respuesta = make_response(
        render_template("admin/login.html", mensaje_error=mensaje_error)
    )
    respuesta.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    respuesta.headers["Pragma"] = "no-cache"
    respuesta.headers["Expires"] = "0"
    return respuesta


@aplicacion.post("/admin/login")
@limiter.limit("10 per minute")
def procesar_admin_login():
    """
    Autenticación exclusiva de administradores (usuarios_privados, rol admin_panel).

    Cuentas de monitor, usuarios públicos o invitados reciben error genérico.
    """
    usuario_enviado = request.form.get("username", "")
    contrasena_enviada = request.form.get("password", "")

    ip_peticion = obtener_ip_cliente()
    if registrar_intento_login(ip_peticion):
        session["_fuerza_bruta_detectada"] = True

    cuenta_admin = verificar_admin_panel_privado(usuario_enviado, contrasena_enviada)
    if cuenta_admin is not None:
        _iniciar_sesion_admin_panel(cuenta_admin["username"])
        destino = cuenta_admin.get("redirige") or "/admin"
        return redirect(destino)

    return redirect(url_for("mostrar_admin_login", error="admin_portal"))


@aplicacion.get("/register")
def mostrar_registro():
    """Formulario de alta abierta en la base de datos pública (flypaper.db)."""
    mensaje_error = request.args.get("error")
    mensaje_exito = request.args.get("exito")
    destino_siguiente = _destino_tras_login_seguro(request.args.get("next"))
    return render_template(
        "register.html",
        mensaje_error=mensaje_error,
        mensaje_exito=mensaje_exito,
        destino_siguiente=destino_siguiente,
    )


@aplicacion.post("/register")
@limiter.limit("10 per minute")
def procesar_registro():
    """Crea un usuario estándar sin privilegios de administración."""
    usuario = request.form.get("username", "")
    contrasena = request.form.get("password", "")
    contrasena_rep = request.form.get("password_confirm", "")
    email = request.form.get("email", "")
    destino = _destino_tras_login_seguro(
        request.form.get("next") or request.args.get("next")
    )

    def _volver_registro(**params):
        if destino:
            params["next"] = destino
        return redirect(url_for("mostrar_registro", **params))

    if contrasena != contrasena_rep:
        return _volver_registro(error="Las contraseñas no coinciden.")

    resultado = crear_usuario_publico(usuario, contrasena, email=email)
    if not resultado.get("exito"):
        return _volver_registro(error=resultado.get("mensaje", "No se pudo registrar."))

    _iniciar_sesion_publica(usuario.strip(), ROL_USUARIO_NORMAL)
    return redirect(destino or "/search")


@aplicacion.post("/login")
@limiter.limit("10 per minute")
def procesar_login():
    """
    Login del portal público: demo, tabla usuarios (MD5) y cuentas nuevas.

    No consulta flypaper_priv.db ni concede rol admin bajo ningún concepto.
    """
    usuario_enviado = request.form.get("username", "")
    contrasena_enviada = request.form.get("password", "")

    ip_peticion = obtener_ip_cliente()
    if registrar_intento_login(ip_peticion):
        session["_fuerza_bruta_detectada"] = True

    destino = _destino_tras_login_seguro(request.form.get("next"))

    datos_usuario = USUARIOS_DEMO_PUBLICOS.get(usuario_enviado)
    if datos_usuario is not None and datos_usuario["password"] == contrasena_enviada:
        _iniciar_sesion_publica(usuario_enviado, ROL_USUARIO_NORMAL)
        return redirect(destino or datos_usuario["redirige"])

    cuenta_bd = verificar_credencial_usuario_bd(usuario_enviado, contrasena_enviada)
    if cuenta_bd is not None:
        _iniciar_sesion_publica(cuenta_bd["username"], ROL_USUARIO_NORMAL)
        return redirect(destino or "/search")

    if destino:
        return redirect(url_for("mostrar_login", error=1, next=destino))
    return redirect("/login?error=1")


@aplicacion.get("/logout")
def cerrar_sesion_honeypot():
    """
    Cierra la sesión del honeypot y redirige siempre a /login.

    Query:
        reason=timeout — cierre por inactividad (mensaje en login).
    """
    reason = request.args.get("reason")

    _invalidar_sesion_honeypot_en_servidor()

    if reason == "timeout":
        return _redirect_login_sin_cache(reason="timeout")
    return _redirect_login_sin_cache(cerrado=1)


@aplicacion.get("/admin")
def mostrar_panel_admin():
    """
    Muestra un panel de administración falso.

    Renderiza la plantilla `admin.html`, diseñada para aparentar
    una zona sensible de gestión.
    """
    bloqueo = _redirigir_si_no_es_admin()
    if bloqueo is not None:
        return bloqueo
    return render_template("admin.html", monitor_url="/monitor/login")


@aplicacion.get("/admin/usuarios")
def admin_usuarios():
    """
    Listado de usuarios reales de la tabla `usuarios` (sin contraseñas).

    Solo accesible con session['rol'] == 'admin'.
    """
    bloqueo = _redirigir_si_no_es_admin()
    if bloqueo is not None:
        return bloqueo
    lista_usuarios = obtener_usuarios_para_panel_admin()
    return render_template(
        "admin/usuarios.html",
        usuarios=lista_usuarios,
        total_usuarios=len(lista_usuarios),
    )


@aplicacion.get("/admin/configuracion")
def admin_configuracion():
    """Pantalla de configuración del panel; solo rol admin."""
    bloqueo = _redirigir_si_no_es_admin()
    if bloqueo is not None:
        return bloqueo
    return render_template("configuracion.html")


def _formatear_datos_ataque_reporte(datos_crudos):
    """JSON legible para plantillas de reportes."""
    datos_legibles = datos_crudos or ""
    try:
        objeto = json.loads(datos_crudos)
        datos_legibles = json.dumps(objeto, ensure_ascii=False, indent=2)
    except (json.JSONDecodeError, TypeError):
        pass
    return datos_legibles


def _nis2_significativo_desde_datos_ataque(datos_ataque):
    """True si el reporte fue marcado como incidente significativo (NIS 2)."""
    if isinstance(datos_ataque, dict):
        return bool(datos_ataque.get("nis2_incidente_significativo"))
    texto = str(datos_ataque or "").strip()
    if not texto:
        return False
    try:
        parsed = json.loads(texto)
        if isinstance(parsed, dict):
            return bool(parsed.get("nis2_incidente_significativo"))
    except (json.JSONDecodeError, TypeError):
        pass
    return False


def _preparar_reportes_vista(filas):
    """Convierte filas de reportes_enviados al formato de la plantilla."""
    reportes_vista = []
    for fila in filas:
        datos_crudos = fila.get("datos_ataque")
        reportes_vista.append(
            {
                "id": fila.get("id"),
                "ip_atacante": fila.get("ip_atacante") or "",
                "datos_ataque": _formatear_datos_ataque_reporte(datos_crudos),
                "fecha": fila.get("fecha") or "",
                "nis2_significativo": _nis2_significativo_desde_datos_ataque(datos_crudos),
            }
        )
    return reportes_vista


@aplicacion.get("/admin/reportes")
def admin_reportes():
    """
    Panel de reportes con pestañas: por IP y resúmenes diarios IA.

    Query params: tab=ip|resumenes, ip=..., filtro_desde, filtro_hasta.
    """
    bloqueo = _redirigir_si_no_es_admin()
    if bloqueo is not None:
        return bloqueo

    tab = request.args.get("tab", "ip")
    if tab not in ("ip", "resumenes"):
        tab = "ip"

    ip_sel = (request.args.get("ip") or "").strip()
    fecha_inicio = (
        request.args.get("fecha_inicio") or request.args.get("filtro_desde") or ""
    ).strip() or None
    fecha_fin = (
        request.args.get("fecha_fin") or request.args.get("filtro_hasta") or ""
    ).strip() or None

    busqueda_enviada = any(
        clave in request.args
        for clave in ("ip", "fecha_inicio", "fecha_fin", "filtro_desde", "filtro_hasta")
    )
    error_validacion = None
    reportes_ip = []

    if tab == "ip" and busqueda_enviada:
        tiene_ip = bool(ip_sel)
        tiene_rango = bool(fecha_inicio and fecha_fin)
        if not tiene_ip and not tiene_rango:
            error_validacion = (
                "Debe introducir una IP o seleccionar un rango de fechas completo"
            )
        else:
            filas = obtener_reportes_filtrados(
                ip=ip_sel or None,
                fecha_inicio=fecha_inicio,
                fecha_fin=fecha_fin,
            )
            reportes_ip = _preparar_reportes_vista(filas)

    resumenes_vista = []
    for fila in listar_resumenes_diarios_ia():
        texto = fila.get("resumen") or ""
        preview = texto[:280] + ("…" if len(texto) > 280 else "")
        resumenes_vista.append(
            {
                "fecha": fila.get("fecha") or "",
                "preview": preview,
                "resumen_completo": texto,
                "total_eventos": fila.get("total_eventos") or 0,
                "caracteres": len(texto),
                "generado_en": fila.get("generado_en") or "",
            }
        )

    log_resumenes_vista = []
    for entrada in obtener_log_resumenes(limite=50):
        log_resumenes_vista.append(
            {
                "fecha": entrada.get("fecha") or "",
                "tipo": entrada.get("tipo") or "",
                "total_eventos": entrada.get("total_eventos") or 0,
                "caracteres": entrada.get("caracteres") or 0,
                "generado_en": entrada.get("generado_en") or "",
                "ok": bool(entrada.get("ok")),
            }
        )

    return render_template(
        "reportes.html",
        tab=tab,
        ip_seleccionada=ip_sel,
        reportes_ip=reportes_ip,
        fecha_inicio=fecha_inicio or "",
        fecha_fin=fecha_fin or "",
        fecha_hoy=fecha_hoy(),
        busqueda_enviada=busqueda_enviada,
        error_validacion=error_validacion,
        resumenes=resumenes_vista,
        log_resumenes=log_resumenes_vista,
    )


def _es_ip_atacante_publica(ip):
    """
    True si la IP es apta para geolocalización en el mapa (no local/privada).

    Excluye loopback, RFC1918 y rangos documentados en el requisito del panel.
    """
    texto = (ip or "").strip()
    if not texto:
        return False
    try:
        direccion = ipaddress.ip_address(texto)
    except ValueError:
        return False
    if direccion.is_loopback or direccion.is_private or direccion.is_link_local:
        return False
    return True


def _filtrar_ips_publicas_atacantes(ips):
    """Lista única de IPs públicas válidas para el mapa de amenazas."""
    vistas = set()
    resultado = []
    for ip in ips:
        texto = (ip or "").strip()
        if not texto or texto in vistas:
            continue
        if not _es_ip_atacante_publica(texto):
            continue
        vistas.add(texto)
        resultado.append(texto)
    return resultado


def _consultar_geolocalizacion_lote(ips_lote):
    """
    Consulta hasta 100 IPs en ip-api.com/batch.

    Returns:
        dict[str, dict]: Entradas exitosas listas para cache_geoip.
    """
    if not ips_lote:
        return {}
    cuerpo = json.dumps([{"query": ip} for ip in ips_lote]).encode("utf-8")
    url = (
        "http://ip-api.com/batch"
        "?fields=status,message,country,countryCode,lat,lon,query"
    )
    solicitud = urllib.request.Request(
        url,
        data=cuerpo,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(solicitud, timeout=20) as respuesta:
        datos = json.loads(respuesta.read().decode("utf-8"))
    if not isinstance(datos, list):
        return {}

    nuevas = {}
    for item in datos:
        if not isinstance(item, dict) or item.get("status") != "success":
            continue
        ip = (item.get("query") or "").strip()
        lat = item.get("lat")
        lon = item.get("lon")
        if not ip or lat is None or lon is None:
            continue
        nuevas[ip] = {
            "lat": float(lat),
            "lon": float(lon),
            "pais": item.get("country") or "",
            "pais_codigo": item.get("countryCode") or "",
        }
    return nuevas


def _geolocalizar_ips_en_cache(ips_publicas):
    """Rellena cache_geoip con lotes de hasta 100 IPs y pausa entre lotes."""
    pendientes = [ip for ip in ips_publicas if ip not in cache_geoip]
    if not pendientes:
        return

    tam_lote = 100
    for indice in range(0, len(pendientes), tam_lote):
        lote = pendientes[indice : indice + tam_lote]
        try:
            nuevas = _consultar_geolocalizacion_lote(lote)
            cache_geoip.update(nuevas)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            logging.warning("Geolocalización ip-api fallida en lote: %s", exc)
        except Exception as exc:
            logging.exception("Error inesperado en geolocalización: %s", exc)
        if len(pendientes) > 100 and indice + tam_lote < len(pendientes):
            time.sleep(1.5)


def _datos_demo_mapa():
    """IPs de demostración para entornos sin tráfico público real (laboratorio)."""
    return [
        {"ip": "185.220.101.45", "pais": "Germany", "pais_codigo": "DE", "lat": 51.165, "lon": 10.451, "total_eventos": 47, "gravedad_maxima": "Crítica", "tipos_ataque": ["SQL Injection", "Fuerza Bruta"]},
        {"ip": "45.142.212.100", "pais": "Netherlands", "pais_codigo": "NL", "lat": 52.132, "lon": 5.291, "total_eventos": 23, "gravedad_maxima": "Alta", "tipos_ataque": ["XSS", "Path Traversal"]},
        {"ip": "194.165.16.77", "pais": "Russia", "pais_codigo": "RU", "lat": 55.751, "lon": 37.618, "total_eventos": 61, "gravedad_maxima": "Crítica", "tipos_ataque": ["SQL Injection", "Escaneo de puertos"]},
        {"ip": "103.124.105.90", "pais": "China", "pais_codigo": "CN", "lat": 35.861, "lon": 104.195, "total_eventos": 18, "gravedad_maxima": "Sospechoso", "tipos_ataque": ["Escaneo de puertos"]},
        {"ip": "91.108.4.200", "pais": "United States", "pais_codigo": "US", "lat": 37.751, "lon": -97.822, "total_eventos": 34, "gravedad_maxima": "Alta", "tipos_ataque": ["Fuerza Bruta", "XSS"]},
        {"ip": "5.188.206.14", "pais": "Brazil", "pais_codigo": "BR", "lat": -14.235, "lon": -51.925, "total_eventos": 12, "gravedad_maxima": "Sospechoso", "tipos_ataque": ["Path Traversal"]},
        {"ip": "212.102.35.66", "pais": "France", "pais_codigo": "FR", "lat": 46.227, "lon": 2.213, "total_eventos": 29, "gravedad_maxima": "Alta", "tipos_ataque": ["SQL Injection"]},
    ]


def _construir_payload_mapa_atacantes():
    """Arma la respuesta JSON del mapa geopolítico de amenazas."""
    ips_crudas = obtener_ips_distintas_eventos()
    ips_publicas = _filtrar_ips_publicas_atacantes(ips_crudas)
    agregados = obtener_agregados_seguridad_por_ip()
    _geolocalizar_ips_en_cache(ips_publicas)

    atacantes = []
    total_eventos = 0
    for ip in ips_publicas:
        stats = agregados.get(ip, {})
        total_ip = int(stats.get("total_eventos") or 0)
        total_eventos += total_ip
        geo = cache_geoip.get(ip)
        if not geo:
            continue
        gravedad = stats.get("gravedad_maxima") or "Sospechoso"
        atacantes.append(
            {
                "ip": ip,
                "pais": geo.get("pais") or "",
                "pais_codigo": geo.get("pais_codigo") or "",
                "lat": geo["lat"],
                "lon": geo["lon"],
                "total_eventos": total_ip,
                "gravedad_maxima": gravedad,
                "tipos_ataque": stats.get("tipos_ataque") or [],
            }
        )

    atacantes.sort(key=lambda a: a.get("total_eventos") or 0, reverse=True)

    es_demo = len(atacantes) == 0
    if es_demo:
        atacantes = _datos_demo_mapa()
        total_eventos = sum(a["total_eventos"] for a in atacantes)

    return {
        "total_ips": len(atacantes),
        "total_eventos": total_eventos,
        "atacantes": atacantes,
        "es_demo": es_demo,
    }


@aplicacion.get("/admin/mapa")
def admin_mapa_amenazas():
    """Vista del mapa mundial de IPs atacantes (solo administradores)."""
    bloqueo = _redirigir_si_no_es_admin()
    if bloqueo is not None:
        return bloqueo
    return render_template("admin/mapa.html")


@aplicacion.get("/admin/api/mapa-ips")
def admin_api_mapa_ips():
    """API JSON con geolocalización y agregados de seguridad por IP atacante."""
    bloqueo = _redirigir_si_no_es_admin()
    if bloqueo is not None:
        return bloqueo
    return jsonify(_construir_payload_mapa_atacantes())


@aplicacion.get("/backup")
def exponer_backup_falso():
    """
    Devuelve un JSON falso con apariencia de respaldo del sistema.

    La estructura está pensada para parecer una exportación administrativa.
    """
    datos_backup_falso = {
        "backup_id": "bk-2026-05-08-001",
        "generated_at": "2026-05-08T17:00:00Z",
        "status": "completed",
        "database": {
            "name": "flypaper_prod",
            "engine": "mysql",
            "size_mb": 742,
        },
        "includes": ["users", "sessions", "admin_logs", "api_keys"],
        "storage": {
            "provider": "s3-compatible",
            "bucket": "flypaper-backups-prod",
            "path": "/daily/2026/05/backup_20260508.sql.gz",
        },
    }
    return jsonify(datos_backup_falso)


@aplicacion.get("/.env")
def exponer_env_falso():
    """
    Devuelve contenido de texto que imita un archivo `.env`.

    Se responde como texto plano para que parezca una filtración de variables
    de entorno con credenciales falsas.
    """
    contenido_env_falso = """FLASK_ENV=production
FLASK_DEBUG=0
SECRET_KEY=flypaper_super_secret_2026
DB_HOST=10.10.1.12
DB_PORT=3306
DB_USER=admin_root
DB_PASSWORD=P@ssw0rd!2026
JWT_SECRET=jwt_secret_key_internal
AWS_ACCESS_KEY_ID=AKIAFAKEKEY123456
AWS_SECRET_ACCESS_KEY=FAKESECRETACCESSKEYXYZ
"""

    respuesta = make_response(contenido_env_falso, 200)
    respuesta.headers["Content-Type"] = "text/plain; charset=utf-8"
    return respuesta


@aplicacion.get("/config")
def exponer_config_xml_falso():
    """
    Devuelve un XML falso que simula configuración interna del sistema.

    Se utiliza `application/xml` para que clientes y atacantes lo interpreten
    como archivo de configuración estructurado.
    """
    contenido_xml_falso = """<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <application name="FlyPaper" environment="production">
        <debug>false</debug>
        <adminEmail>admin@flypaper.local</adminEmail>
    </application>
    <database>
        <host>127.0.0.1</host>
        <port>5432</port>
        <name>flypaper_prod</name>
        <user>postgres_admin</user>
        <password>postgres_fake_password</password>
    </database>
    <security>
        <csrf enabled="false"/>
        <rateLimit enabled="false"/>
        <legacyMode>true</legacyMode>
    </security>
</configuration>
"""

    respuesta = make_response(contenido_xml_falso, 200)
    respuesta.headers["Content-Type"] = "application/xml; charset=utf-8"
    return respuesta


@aplicacion.get("/phpinfo")
def mostrar_phpinfo_falso():
    """
    Muestra una salida de texto que imita parcialmente `phpinfo()`.

    Esta ruta existe para atraer escaneos automatizados que buscan
    configuración sensible de servidores PHP.
    """
    texto_phpinfo_falso = """phpinfo()
PHP Version => 8.1.12

System => Linux ip-172-31-12-45 5.15.0-1020-aws x86_64
Build Date => Nov 12 2025 13:42:10
Server API => Apache 2.0 Handler
Loaded Configuration File => /etc/php/8.1/apache2/php.ini
error_log => /var/log/apache2/php_errors.log
display_errors => Off
allow_url_fopen => On
allow_url_include => Off
disable_functions => none
"""

    respuesta = make_response(texto_phpinfo_falso, 200)
    respuesta.headers["Content-Type"] = "text/plain; charset=utf-8"
    return respuesta


@aplicacion.get("/wp-admin")
def simular_wp_admin():
    """
    Responde con HTML mínimo simulando un acceso de WordPress.

    El objetivo es parecer una instalación vulnerable o mal configurada,
    atrayendo intentos de enumeración o fuerza bruta.
    """
    html_wp_admin_falso = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>WordPress › Login</title>
  </head>
  <body>
    <h1>WordPress</h1>
    <p>Error: Cookies are blocked or not supported by your browser.</p>
    <form method="post" action="/wp-login.php">
      <label for="user_login">Username or Email Address</label>
      <input type="text" name="log" id="user_login">
      <label for="user_pass">Password</label>
      <input type="password" name="pwd" id="user_pass">
      <button type="submit">Log In</button>
    </form>
  </body>
</html>
"""
    respuesta = make_response(html_wp_admin_falso, 200)
    respuesta.headers["Content-Type"] = "text/html; charset=utf-8"
    return respuesta


@aplicacion.get("/search")
@limiter.limit("30 per minute")
def mostrar_busqueda():
    """
    Búsqueda interna (requiere usuario autenticado en el portal público).

    La consulta vulnerable se envía por POST al mismo endpoint.
    """
    mensaje_acceso = None
    if request.args.get("error") == "acceso_denegado":
        mensaje_acceso = "No tienes permisos para acceder a esa sección"
    return _plantilla_publica(
        "search.html",
        nav_activo="search",
        mensaje_acceso=mensaje_acceso,
    )


@aplicacion.post("/search")
@limiter.limit("30 per minute")
def procesar_busqueda():
    """
    Búsqueda vulnerable a SQLi (concatenación directa sin sanitizar).

    - Éxito: muestra filas de `posts` en search.html.
    - Error SQLite: muestra el mensaje de error (error-based SQLi).
    - Siempre registra el evento con severidad según el tipo detectado (p. ej. Crítica en SQLi).
    """
    query = request.form.get("query", "")
    resultados, error_sql = _ejecutar_busqueda_vulnerable(query)

    payload_registro = {"query": query}
    tipo_ataque = clasificar_ataque(
        ruta="/search",
        payload=str(payload_registro),
        user_agent=request.headers.get("User-Agent", ""),
        headers=dict(request.headers),
        metodo="POST",
    )
    gravedad = calcular_gravedad(tipo_ataque)
    guardar_evento(
        ip=obtener_ip_cliente(),
        ruta="/search",
        metodo="POST",
        payload=payload_registro,
        user_agent=request.headers.get("User-Agent", ""),
        tipo_ataque=tipo_ataque,
        headers=dict(request.headers),
        gravedad=gravedad,
        ambito="publico",
    )

    return _plantilla_publica(
        "search.html",
        nav_activo="search",
        query=query,
        resultados=resultados,
        error_sql=error_sql,
        total_resultados=len(resultados),
        mensaje_acceso=None,
    )


# ——— Rutas señuelo Auto-Ban (/secure/*, sin login) ———

@aplicacion.get("/secure/search")
@limiter.limit("30 per minute")
def autoban_mostrar_busqueda():
    """
    Búsqueda interna señuelo (zona auto-ban).

    Acceso público: no requiere session['logueado'] ni ningún rol.
    """
    return render_template("auto-ban/search.html")


@aplicacion.post("/secure/search")
@limiter.limit("30 per minute")
def autoban_procesar_busqueda():
    """
    Búsqueda vulnerable sobre flypaper_autoban.db (ab_posts).

    Registra con ámbito autoban y bloquea ataques graves redirigiendo a /expulsado.
    """
    query = request.form.get("query", "")
    resultados, error_sql = _ejecutar_busqueda_autoban_vulnerable(query)
    ip = obtener_ip_cliente()
    payload_registro = {"query": query}
    user_agent = request.headers.get("User-Agent", "")
    cabeceras = dict(request.headers)

    tipo_ataque = clasificar_ataque(
        ruta="/secure/search",
        payload=str(payload_registro),
        user_agent=user_agent,
        headers=cabeceras,
        metodo="POST",
    )
    gravedad = GRAVEDAD_CRITICA if _tipo_dispara_autoban(tipo_ataque) else calcular_gravedad(tipo_ataque)
    guardar_evento(
        ip=ip,
        ruta="/secure/search",
        metodo="POST",
        payload=payload_registro,
        user_agent=user_agent,
        tipo_ataque=tipo_ataque,
        headers=cabeceras,
        gravedad=gravedad,
        ambito="autoban",
    )
    if _tipo_dispara_autoban(tipo_ataque):
        g.autoban_evento_ya_registrado = True

    respuesta_ban = _autoban_si_corresponde(ip, tipo_ataque)
    if respuesta_ban is not None:
        return respuesta_ban

    return render_template(
        "auto-ban/search.html",
        query=query,
        resultados=resultados,
        error_sql=error_sql,
        total_resultados=len(resultados),
    )


@aplicacion.get("/secure/blog")
@limiter.limit("60 per minute")
def autoban_blog_listado():
    """
    Listado de blog señuelo (ab_posts en flypaper_autoban.db).

    Acceso público sin autenticación.
    """
    posts = obtener_ab_posts()
    return render_template("auto-ban/blog.html", posts=posts)


@aplicacion.get("/secure/blog/<int:post_id>")
@limiter.limit("60 per minute")
def autoban_blog_detalle(post_id):
    """Detalle de post señuelo y comentarios de ab_comentarios."""
    post = obtener_ab_post_por_id(post_id)
    if post is None:
        return "Publicación no encontrada", 404

    comentarios = obtener_ab_comentarios_post(post_id)
    return render_template(
        "auto-ban/post.html",
        post=post,
        comentarios=comentarios,
    )


@aplicacion.post("/secure/blog/<int:post_id>/comentar")
@limiter.limit("30 per minute")
def autoban_blog_comentar(post_id):
    """
    Comentario en blog señuelo: persiste en ab_comentarios (sin límite por sesión).
    """
    post = obtener_ab_post_por_id(post_id)
    if post is None:
        return "Publicación no encontrada", 404

    nombre = (request.form.get("nombre") or "").strip() or "Anónimo"
    contenido = (request.form.get("comentario") or "").strip()
    ip = obtener_ip_cliente()
    user_agent = request.headers.get("User-Agent", "")
    cabeceras = dict(request.headers)
    payload_registro = {"nombre": nombre, "comentario": contenido}
    ruta = f"/secure/blog/{post_id}/comentar"

    tipo_ataque = clasificar_ataque(
        ruta=ruta,
        payload=str(payload_registro),
        user_agent=user_agent,
        headers=cabeceras,
        metodo="POST",
    )
    gravedad = GRAVEDAD_CRITICA if _tipo_dispara_autoban(tipo_ataque) else calcular_gravedad(tipo_ataque)
    guardar_evento(
        ip=ip,
        ruta=ruta,
        metodo="POST",
        payload=payload_registro,
        user_agent=user_agent,
        tipo_ataque=tipo_ataque,
        headers=cabeceras,
        gravedad=gravedad,
        ambito="autoban",
    )
    if _tipo_dispara_autoban(tipo_ataque):
        g.autoban_evento_ya_registrado = True

    respuesta_ban = _autoban_si_corresponde(ip, tipo_ataque)
    if respuesta_ban is not None:
        return respuesta_ban

    if contenido:
        guardar_ab_comentario(post_id, nombre, contenido)

    return redirect(url_for("autoban_blog_detalle", post_id=post_id))


@aplicacion.errorhandler(404)
def pagina_no_encontrada(e):
    """
    Página 404 genérica.

    En rutas públicas (no /secure/*, /admin/* ni /monitor/*) registra el intento
    con la URL completa para detectar path traversal y sondeo de ficheros.
    No expulsa al visitante; la inspección /secure/* sigue en before_request.
    """
    ruta = request.path or ""

    if ruta.startswith("/secure/") or _ruta_es_zona_administracion(ruta):
        return render_template("404.html"), 404

    qs = request.query_string.decode("utf-8", errors="ignore")
    url_completa = ruta + ("?" + qs if qs else "")
    ip = obtener_ip_cliente()
    ua = request.headers.get("User-Agent", "")
    hdrs = dict(request.headers)

    tipo = clasificar_ataque(
        ruta=ruta,
        payload=url_completa,
        user_agent=ua,
        headers=hdrs,
        metodo=request.method,
    )
    gravedad = calcular_gravedad(tipo)

    guardar_evento(
        ip=ip,
        ruta=ruta,
        metodo=request.method,
        payload={"url_intentada": url_completa},
        user_agent=ua,
        tipo_ataque=tipo,
        headers=hdrs,
        gravedad=gravedad,
        ambito="publico",
    )
    g.evento_404_publico_registrado = True

    return render_template("404.html"), 404


@aplicacion.get("/objetivos")
@limiter.limit("30 per minute")
def pagina_objetivos():
    """
    Página de retos CTF: lista flags (sin el secreto) y progreso individual por usuario.
    """
    usuario_id = session.get("usuario") or ""
    flags = obtener_flags_con_estado_por_usuario(usuario_id)
    resueltas = contar_flags_resueltas_por_usuario(usuario_id)
    total = len(flags)

    return _plantilla_publica(
        "objetivos.html",
        nav_activo="objetivos",
        flags=flags,
        resueltas=resueltas,
        total=total if total else 2,
        reto_sqli_titulo=RETO_CTF_SQLI,
    )


@aplicacion.post("/objetivos/submit")
@limiter.limit("10 per minute")
def objetivos_submit():
    """
    Valida una flag enviada por el jugador y la registra si es correcta.

    JSON de éxito: {"exito": true, "puntos": X, "mensaje": "¡Flag correcta!"}
    JSON de fallo: {"exito": false, "mensaje": "..."}
    """
    flag_enviada = request.form.get("flag", "")
    if not flag_enviada and request.is_json:
        cuerpo = request.get_json(silent=True) or {}
        flag_enviada = cuerpo.get("flag", "")

    usuario_id = session.get("usuario") or ""
    resultado = enviar_flag_por_usuario(usuario_id, flag_enviada)
    return jsonify(resultado)


@aplicacion.post("/objetivos/reset")
def objetivos_reset_progreso():
    """
    Borra el progreso CTF de la IP actual para poder reenviar las mismas flags (QA).

    JSON: {"exito": true, "resueltas": 0, "total": 2, "mensaje": "..."}
    """
    usuario_id = session.get("usuario") or ""
    reiniciar_progreso_ctf_por_usuario(usuario_id)
    total = len(obtener_flags_publicas())
    return jsonify(
        {
            "exito": True,
            "resueltas": 0,
            "total": total,
            "mensaje": "Progreso restablecido. Puedes resolver los retos de nuevo.",
        }
    )


CLAVE_DIVERSION_CARTA_SECRETA = "diversion_carta_secreta"
CLAVE_DIVERSION_CARTA_GANADOR = "diversion_carta_ganador"


CARTA_MIN = 1
CARTA_MAX = 6


def _generar_numero_carta_secreta():
    """Número aleatorio del 1 al 6 para el minijuego de cartas."""
    return random.randint(CARTA_MIN, CARTA_MAX)


@aplicacion.route("/diversion/carta", methods=["GET", "POST"])
@limiter.limit("60 per minute")
def diversion_carta_juego():
    """
    Minijuego de adivinanza: el visitante debe acertar una carta secreta (1-6).

    GET: inicia o reinicia la partida con una carta nueva en sesión.
    POST: valida el intento; acierto → /diversion/carta/ganador; fallo → nueva carta.
    """
    if request.method == "GET":
        session[CLAVE_DIVERSION_CARTA_SECRETA] = _generar_numero_carta_secreta()
        session.pop(CLAVE_DIVERSION_CARTA_GANADOR, None)
        session.modified = True
        return _plantilla_publica(
            "diversion/carta/juego.html",
            nav_activo="diversion",
            mensaje_error=None,
        )

    mensaje_error = None
    carta_revelada = None
    intento_raw = (request.form.get("carta") or "").strip()

    secreto = session.get(CLAVE_DIVERSION_CARTA_SECRETA)
    if secreto is None:
        secreto = _generar_numero_carta_secreta()
        session[CLAVE_DIVERSION_CARTA_SECRETA] = secreto

    try:
        intento = int(intento_raw)
        if intento < CARTA_MIN or intento > CARTA_MAX:
            raise ValueError("fuera de rango")
    except ValueError:
        carta_revelada = secreto
        mensaje_error = f"Fallo, vuelve a intentarlo. La carta era {carta_revelada}."
    else:
        if intento == secreto:
            session[CLAVE_DIVERSION_CARTA_GANADOR] = True
            session.pop(CLAVE_DIVERSION_CARTA_SECRETA, None)
            session.modified = True
            return redirect(url_for("diversion_carta_ganador"))
        carta_revelada = secreto
        mensaje_error = f"Fallo, vuelve a intentarlo. La carta era {carta_revelada}."

    session[CLAVE_DIVERSION_CARTA_SECRETA] = _generar_numero_carta_secreta()
    session.modified = True
    return _plantilla_publica(
        "diversion/carta/juego.html",
        nav_activo="diversion",
        mensaje_error=mensaje_error,
    )


@aplicacion.get("/diversion/carta/ganador")
@limiter.limit("60 per minute")
def diversion_carta_ganador():
    """Pantalla de victoria tras acertar la carta secreta."""
    if not session.get(CLAVE_DIVERSION_CARTA_GANADOR):
        return redirect(url_for("diversion_carta_juego"))
    return render_template("diversion/carta/ganador.html")


@aplicacion.get("/documentacion")
@limiter.limit("60 per minute")
def pagina_documentacion():
    """
    Documentación técnica de seguridad (requiere sesión activa en el portal público).
    """
    return _plantilla_publica("Documentacion.html", nav_activo="documentacion")


@aplicacion.get("/blog")
@limiter.limit("60 per minute")
def blog_listado():
    """
    Blog del portal de usuario: listado de posts (requiere sesión activa).
    """
    posts = obtener_posts_blog()
    return _plantilla_publica("blog.html", nav_activo="blog", posts=posts)


@aplicacion.get("/blog/<int:post_id>")
def blog_detalle(post_id):
    """
    Detalle de un post: comentarios oficiales (BD) + comentarios volátiles de la sesión.
    """
    post = obtener_post_por_id(post_id)
    if post is None:
        return "Publicación no encontrada", 404

    comentarios = construir_comentarios_para_vista(post_id)
    activos_sesion = _contar_comentarios_volatiles_post(post_id)
    cupo_restante = max(0, LIMITE_COMENTARIOS_SESION_POR_POST - activos_sesion)
    return _plantilla_publica(
        "post.html",
        nav_activo="blog",
        post=post,
        comentarios=comentarios,
        limite_sesion=LIMITE_COMENTARIOS_SESION_POR_POST,
        cupo_restante=cupo_restante,
    )


@aplicacion.post("/blog/<int:post_id>/comentar")
@limiter.limit("5 per minute")
def blog_comentar(post_id):
    """
    Publica un comentario volátil en la sesión del visitante (no en la BD global).

    Límite: 3 comentarios activos por post y sesión; borrar uno libera cupo.
    """
    post = obtener_post_por_id(post_id)
    if post is None:
        return "Publicación no encontrada", 404

    if _contar_comentarios_volatiles_post(post_id) >= LIMITE_COMENTARIOS_SESION_POR_POST:
        return respuesta_error_comentario_json(
            f"Has alcanzado el límite de {LIMITE_COMENTARIOS_SESION_POR_POST} "
            "comentarios en esta sesión para esta publicación"
        )

    nombre = (request.form.get("nombre") or "").strip() or "Anónimo"
    contenido = (request.form.get("comentario") or "").strip()
    if not contenido:
        return redirect(url_for("blog_detalle", post_id=post_id))

    _agregar_comentario_volatil(post_id, nombre, contenido)
    return redirect(url_for("blog_detalle", post_id=post_id))


@aplicacion.post("/blog/<int:post_id>/comentar/borrar")
def blog_borrar_comentario_sesion(post_id):
    """
    Elimina un comentario volátil de la sesión (solo los creados por el visitante actual).
    """
    post = obtener_post_por_id(post_id)
    if post is None:
        return "Publicación no encontrada", 404

    comentario_id = (request.form.get("id") or "").strip()
    _eliminar_comentario_volatil(post_id, comentario_id)
    return redirect(url_for("blog_detalle", post_id=post_id))


@aplicacion.get("/monitor")
@requiere_autenticacion_monitor
def monitor_dashboard():
    """
    Muestra el dashboard privado principal de FlyPaper.

    La lógica visual queda en la plantilla `dashboard.html`.
    """
    return render_template("dashboard.html")


@aplicacion.get("/monitor/login")
def monitor_login_get():
    """
    Muestra el formulario de autenticación del panel de monitorización.

    Si llega `?error=1` (p. ej. tras credenciales incorrectas), se muestra aviso.
    """
    mensaje_error = None
    if request.args.get("error") == "1":
        mensaje_error = "Usuario o contraseña incorrectos."
    return render_template("monitor_login.html", error=mensaje_error)


@aplicacion.post("/monitor/login")
def monitor_login_post():
    """
    Procesa el login del dashboard privado.

    Credenciales en tabla `usuarios_privados` (rol monitor); no accesibles vía SQLi en `usuarios`.
    """
    usuario_enviado = request.form.get("usuario", "").strip()
    contrasena_enviada = request.form.get("contrasena", "")

    cuenta_priv = verificar_usuario_privado(usuario_enviado, contrasena_enviada)
    if cuenta_priv is not None and cuenta_priv.get("rol") == ROL_PRIV_MONITOR:
        session["analyst"] = True
        return redirect(url_for("monitor_dashboard"))

    # Fallo: misma URL con query para que la plantilla muestre el error.
    return redirect("/monitor/login?error=1")


@aplicacion.get("/monitor/logout")
def monitor_logout():
    """
    Cierra únicamente la sesión del analista del monitor.

    No se usa `session.clear()` para no cerrar la sesión del honeypot (`logueado`, etc.).
    """
    session.pop("analyst", None)
    return redirect(url_for("monitor_login_get"))


def _periodo_monitor_desde_request():
    """Lee y normaliza ?periodo= de la petición (hoy, ayer, semana, mes, todo)."""
    return normalizar_periodo_monitor(request.args.get("periodo"))


@aplicacion.get("/monitor/api/eventos")
@requiere_autenticacion_monitor
def monitor_api_eventos():
    """
    Eventos del período solicitado, agrupados por IP.

    Query:
        ?periodo=hoy|ayer|semana|mes|todo (alias: 7d→semana, 30d→mes).
        ?gravedad=Crítica|Alta|Sospechoso (opcional; omitir = todas las amenazas).

    Respuesta JSON:
        periodo (str): período aplicado tras normalizar.
        grupos (list): filas agrupadas por IP con eventos detallados.
    """
    periodo = _periodo_monitor_desde_request()
    gravedad = normalizar_gravedad_filtro_api(request.args.get("gravedad"))
    grupos_por_ip = agrupar_eventos_por_ip(
        limite_eventos=500, periodo=periodo, gravedad=gravedad, ambito="publico"
    )
    return jsonify({"periodo": periodo, "gravedad": gravedad, "grupos": grupos_por_ip})


@aplicacion.get("/monitor/api/autoban/eventos")
@requiere_autenticacion_monitor
def monitor_api_autoban_eventos():
    """
    Eventos de la zona señuelo /secure/* agrupados por IP.

    Query: ?periodo=...&gravedad=... (igual que /monitor/api/eventos).
    """
    periodo = _periodo_monitor_desde_request()
    gravedad = normalizar_gravedad_filtro_api(request.args.get("gravedad"))
    grupos = agrupar_eventos_por_ip(
        limite_eventos=500,
        periodo=periodo,
        gravedad=gravedad,
        ambito="autoban",
    )
    return jsonify({"periodo": periodo, "gravedad": gravedad, "grupos": grupos})


@aplicacion.get("/monitor/api/autoban/stats")
@requiere_autenticacion_monitor
def monitor_api_autoban_stats():
    """
    Estadísticas agregadas del tráfico auto-ban (/secure/*).

    Incluye total_bloqueadas desde la tabla ips_bloqueadas.
    """
    periodo = _periodo_monitor_desde_request()
    estadisticas_bd = obtener_estadisticas(periodo=periodo, ambito="autoban")
    actividad = estadisticas_bd.get("actividad_por_periodo") or {}
    return jsonify({
        "periodo": periodo,
        "total_eventos": estadisticas_bd.get("total_eventos", 0),
        "ips_unicas": estadisticas_bd.get("ips_unicas", 0),
        "ataques_por_tipo": estadisticas_bd.get("ataques_por_tipo") or {},
        "ataques_por_gravedad": estadisticas_bd.get("ataques_por_gravedad") or {},
        "total_bloqueadas": contar_ips_bloqueadas(),
        "actividad_por_periodo": actividad,
        "ultimo_autoban_hace": estadisticas_bd.get("ultimo_ataque_hace"),
        "ultimo_autoban_gravedad": estadisticas_bd.get("ultimo_ataque_gravedad"),
        "ultimas_expulsiones": obtener_ultimas_expulsiones_autoban(10),
    })


@aplicacion.get("/monitor/api/actividad-peticiones")
@requiere_autenticacion_monitor
def monitor_api_actividad_peticiones():
    """
    Peticiones HTTP agrupadas por IP (tráfico público o de administración).

    Query:
        ?periodo=hoy|ayer|semana|mes|todo
        ?ambito=publico|admin (por defecto publico)
    """
    periodo = _periodo_monitor_desde_request()
    ambito = (request.args.get("ambito") or "publico").strip().lower()
    if ambito not in ("publico", "admin"):
        ambito = "publico"
    grupos = agrupar_peticiones_por_ip(
        limite_peticiones=2000, periodo=periodo, ambito=ambito
    )
    return jsonify({"periodo": periodo, "ambito": ambito, "grupos": grupos})


@aplicacion.post("/monitor/reportar")
@requiere_autenticacion_monitor
def monitor_reportar():
    """
    Recibe un reporte forense desde el modal del monitor y lo persiste en BD.

    Cuerpo JSON esperado: { "ip": "...", "datos_ataque": { ... } }
    """
    cuerpo = request.get_json(silent=True) or {}
    ip_atacante = (cuerpo.get("ip") or "").strip()
    datos_ataque = cuerpo.get("datos_ataque")

    if not ip_atacante:
        return jsonify({"exito": False, "mensaje": "La IP es obligatoria"}), 400

    guardar_reporte_enviado(ip_atacante, datos_ataque)
    return jsonify({"exito": True})


@aplicacion.get("/monitor/api/ips-activas")
@requiere_autenticacion_monitor
def monitor_api_ips_activas():
    """
    Devuelve las IPs con actividad reciente en el servidor (sesión/navegación activa).

    El dashboard usa esta lista para mostrar u ocultar el botón «Bloquear».
    """
    return jsonify({"ips": listar_ips_con_actividad_reciente()})


@aplicacion.post("/monitor/bloquear")
@requiere_autenticacion_monitor
def monitor_bloquear_ip():
    """
    Bloquea una IP sospechosa e invalida de inmediato sus sesiones asociadas.

    Cuerpo JSON: { "ip": "x.x.x.x" }
    """
    cuerpo = request.get_json(silent=True) or {}
    ip_objetivo = (cuerpo.get("ip") or "").strip()

    if not ip_objetivo:
        return jsonify({"exito": False, "mensaje": "La IP es obligatoria"}), 400

    if not ip_tiene_actividad_reciente(ip_objetivo):
        return jsonify(
            {
                "exito": False,
                "mensaje": "Esa IP no tiene actividad reciente en el servidor",
            }
        ), 400

    bloquear_ip_visitante(ip_objetivo)
    return jsonify({"exito": True, "ip": ip_objetivo})


@aplicacion.post("/monitor/desbloquear")
@requiere_autenticacion_monitor
def monitor_desbloquear_ip():
    """
    Quita una IP de la lista negra persistente desde el panel Auto-Ban.

    Cuerpo JSON: { "ip": "x.x.x.x", "accion": "desbloquear" }
    """
    cuerpo = request.get_json(silent=True) or {}
    ip_objetivo = (cuerpo.get("ip") or "").strip()
    accion = (cuerpo.get("accion") or "").strip().lower()

    if not ip_objetivo or accion != "desbloquear":
        return jsonify({"exito": False, "mensaje": "Petición inválida"}), 400

    desbloquear_ip_visitante(ip_objetivo)
    return jsonify({"exito": True, "ip": ip_objetivo})


@aplicacion.get("/monitor/api/stats")
@requiere_autenticacion_monitor
def monitor_api_estadisticas():
    """
    Estadísticas agregadas del período seleccionado.

    Query: ?periodo=hoy|ayer|semana|mes|todo

    Campos principales:
        variacion_eventos — % de cambio vs el período anterior equivalente.
        ips_nuevas — IPs que no constaban antes del inicio del período.
        actividad_por_periodo — por horas (hoy/ayer) o por días (semana/mes/todo).
        top_rutas — cinco rutas más atacadas.
        alertas_graves — últimas 10 alertas Crítica/Alta dentro del período.
    """
    periodo = _periodo_monitor_desde_request()
    estadisticas_bd = obtener_estadisticas(periodo=periodo, ambito="publico")
    ataques_por_tipo = dict(estadisticas_bd.get("ataques_por_tipo") or {})
    actividad = estadisticas_bd.get("actividad_por_periodo") or {}

    cuerpo = {
        "periodo": periodo,
        "total_eventos": estadisticas_bd.get("total_eventos", 0),
        "ips_unicas": estadisticas_bd.get("ips_unicas", 0),
        "ips_nuevas": estadisticas_bd.get("ips_nuevas", 0),
        "ataques_detectados": estadisticas_bd.get("ataques_detectados", 0),
        "ataques_por_tipo": ataques_por_tipo,
        "ataques_por_gravedad": estadisticas_bd.get("ataques_por_gravedad") or {},
        "variacion_eventos": estadisticas_bd.get("variacion_eventos"),
        "variacion_eventos_etiqueta": estadisticas_bd.get(
            "total_eventos_variacion_etiqueta"
        ),
        "actividad_por_periodo": actividad,
        "top_rutas": estadisticas_bd.get("top_rutas") or [],
        "alertas_graves": estadisticas_bd.get("alertas_graves") or [],
        "ultimo_ataque_hace": estadisticas_bd.get("ultimo_ataque_hace"),
        "ultimo_ataque_gravedad": estadisticas_bd.get("ultimo_ataque_gravedad"),
        "alertas_criticas_recientes": estadisticas_bd.get(
            "alertas_criticas_recientes", False
        ),
        # Alias para compatibilidad con dashboard.html existente
        "total_eventos_variacion_pct": estadisticas_bd.get("variacion_eventos"),
        "total_eventos_variacion_etiqueta": estadisticas_bd.get(
            "total_eventos_variacion_etiqueta"
        ),
        "ataques_tipo_gravedad": estadisticas_bd.get("ataques_tipo_gravedad") or {},
        "actividad_modo": actividad.get("modo"),
        "actividad_labels": actividad.get("etiquetas") or [],
        "actividad_valores": actividad.get("valores") or [],
        "actividad_pico_indice": actividad.get("pico_indice", 0),
        "ultimo_ataque_min": estadisticas_bd.get("ultimo_ataque_hace"),
        "tipos_ataque": ataques_por_tipo,
        "actividad_por_hora": dict(
            zip(actividad.get("etiquetas") or [], actividad.get("valores") or [])
        ),
        "actividad_horas": dict(
            zip(actividad.get("etiquetas") or [], actividad.get("valores") or [])
        ),
        "zona_horaria": estadisticas_bd.get("zona_horaria") or ZONA_NOMBRE,
    }
    return jsonify(cuerpo)


def _payload_evento_vacio(payload):
    """True si el evento no tiene datos útiles en el campo payload."""
    if payload is None:
        return True
    if isinstance(payload, str):
        return not payload.strip()
    if isinstance(payload, (dict, list)):
        return len(payload) == 0
    return False


def _normalizar_fecha_resumen(fecha_param):
    """Valida YYYY-MM-DD o devuelve hoy en Europe/Madrid."""
    if fecha_param:
        try:
            datetime.strptime(fecha_param, "%Y-%m-%d")
            return fecha_param
        except ValueError:
            pass
    return fecha_hoy()


def _obtener_resumen_diario_con_cache(fecha, regenerar=False):
    """
    Devuelve el resumen diario de Claude para una fecha, con caché en memoria y BD.
    """
    total = contar_eventos_en_fecha(fecha)
    if total == 0:
        return None, False, 0, True

    if not regenerar:
        guardado = obtener_resumen_diario_ia(fecha)
        if guardado and guardado.get("resumen"):
            return guardado["resumen"], True, total, False

    ahora = ahora_naive()
    entrada = _cache_resumen_diario_por_fecha.get(fecha, {})
    generado = entrada.get("generado_en")
    if (
        not regenerar
        and entrada.get("resumen")
        and generado
        and (ahora - generado).total_seconds() < TTL_RESUMEN_DIARIO_SEG
    ):
        return entrada["resumen"], True, total, False

    texto = generar_resumen_diario(fecha)
    if texto:
        guardar_resumen_diario_ia(fecha, texto, total_eventos=total)
    _cache_resumen_diario_por_fecha[fecha] = {
        "resumen": texto,
        "generado_en": ahora,
    }
    return texto, False, total, False


@aplicacion.get("/monitor/api/analizar/<int:registro_id>")
@requiere_autenticacion_monitor
def monitor_api_analizar_registro(registro_id):
    """
    Analiza con Claude un evento (`eventos`) o una petición (`registro_peticiones`).

    Query: ?fuente=evento (defecto) | peticion
    """
    fuente = (request.args.get("fuente") or "evento").strip().lower()

    if fuente == "peticion":
        peticion = obtener_registro_peticion_por_id(registro_id)
        if peticion is None:
            return jsonify({"error": f"No existe la petición con id {registro_id}"}), 404
        return _respuesta_analisis_ia(
            registro_id,
            peticion.get("tipo_ataque"),
            peticion.get("payload"),
            peticion.get("ruta"),
            "peticion",
        )

    evento = obtener_evento_por_id(registro_id)
    if evento is None:
        return jsonify({"error": f"No existe el evento con id {registro_id}"}), 404
    return _respuesta_analisis_ia(
        registro_id,
        evento.get("tipo_ataque"),
        evento.get("payload"),
        evento.get("ruta"),
        "evento",
    )


@aplicacion.get("/monitor/api/peticion/<int:peticion_id>")
@requiere_autenticacion_monitor
def monitor_api_peticion_detalle(peticion_id):
    """Detalle completo de una petición HTTP para el inspector del monitor."""
    peticion = obtener_registro_peticion_por_id(peticion_id)
    if peticion is None:
        return jsonify({"error": "Petición no encontrada"}), 404

    tamano_bytes = peticion.get("tamano_respuesta_bytes")
    tiempo_ms = peticion.get("tiempo_ms")
    tipo_ataque = (peticion.get("tipo_ataque") or TIPO_TRAFICO_NORMAL).strip()
    tipo_ataque = tipo_ataque or TIPO_TRAFICO_NORMAL
    gravedad = ""
    if tipo_ataque != TIPO_TRAFICO_NORMAL:
        gravedad = normalizar_gravedad_almacenada(peticion.get("gravedad")) or ""

    return jsonify(
        {
            "id": peticion["id"],
            "ip": peticion.get("ip") or "",
            "ruta": peticion.get("ruta") or "",
            "metodo": peticion.get("metodo") or "",
            "codigo_http": peticion.get("codigo_http"),
            "user_agent": peticion.get("user_agent") or "",
            "payload": peticion.get("payload"),
            "headers": peticion.get("headers"),
            "tipo_ataque": tipo_ataque,
            "gravedad": gravedad,
            "evento_id": peticion.get("evento_id"),
            "timestamp": _timestamp_evento_formato_api(peticion.get("timestamp")),
            "usuario_activo": peticion.get("usuario_activo") or "Invitado",
            "sesion_id_corto": peticion.get("sesion_id_corto") or "",
            "tiempo_ms": tiempo_ms,
            "tiempo_ms_legible": (
                f"{tiempo_ms} ms" if tiempo_ms is not None else "—"
            ),
            "tamano_respuesta_bytes": tamano_bytes,
            "tamano_respuesta_legible": formatear_tamano_bytes(tamano_bytes),
            "puerto_origen": peticion.get("puerto_origen") or "",
        }
    )


@aplicacion.get("/monitor/api/actividad-publica/ips")
@requiere_autenticacion_monitor
def monitor_api_actividad_publica_ips():
    """IPs disponibles en el listado de actividad pública."""
    return jsonify({"ips": listar_ips_peticiones_publicas()})


@aplicacion.get("/monitor/api/actividad-publica/fechas")
@requiere_autenticacion_monitor
def monitor_api_actividad_publica_fechas():
    """Días con tráfico público para una IP (exportación y filtro de fecha)."""
    ip = (request.args.get("ip") or "").strip()
    if not ip:
        return jsonify({"fechas": [], "mensaje": MENSAJE_EXPORTACION_ACTIVIDAD_INVALIDA})
    return jsonify({"fechas": listar_fechas_peticiones_publicas_por_ip(ip)})


@aplicacion.get("/monitor/api/fechas-con-datos")
@requiere_autenticacion_monitor
def monitor_api_fechas_con_datos():
    """Días con eventos registrados (para el selector de fecha del resumen diario)."""
    fechas = obtener_fechas_con_eventos()
    hoy = fecha_hoy()
    ultima = obtener_ultima_fecha_con_eventos()
    defecto = hoy if any(f["fecha"] == hoy for f in fechas) else (ultima or hoy)
    return jsonify(
        {
            "fechas": fechas,
            "defecto": defecto,
            "hoy": hoy,
            "zona_horaria": ZONA_NOMBRE,
        }
    )


def _json_respuesta_resumen_diario(fecha, regenerar=False, registrar_tipo_log=None):
    """Construye la respuesta JSON del resumen diario (monitor y admin)."""
    resumen, desde_cache, total, sin_datos = _obtener_resumen_diario_con_cache(
        fecha, regenerar=regenerar
    )
    if sin_datos:
        return jsonify(
            {
                "sin_datos": True,
                "mensaje": "No hay datos para este día",
                "fecha": fecha,
                "total_eventos": 0,
            }
        )
    if registrar_tipo_log and resumen and not desde_cache:
        registrar_resumen_log(
            fecha, registrar_tipo_log, total, len(resumen), ok=True
        )
    guardado = obtener_resumen_diario_ia(fecha)
    return jsonify(
        {
            "resumen": resumen,
            "fecha": fecha,
            "total_eventos": total,
            "desde_cache": desde_cache,
            "desde_bd": bool(guardado and not regenerar),
            "generado_en": (guardado or {}).get("generado_en"),
            "cache_ttl_segundos": TTL_RESUMEN_DIARIO_SEG,
        }
    )


@aplicacion.get("/admin/api/resumen-diario")
def admin_api_resumen_diario():
    """
    Resumen diario IA (misma lógica que el monitor) accesible desde el panel admin.

    Query: fecha=YYYY-MM-DD, regenerar=1 para forzar nueva generación (tipo log: manual).
    """
    bloqueo = _redirigir_si_no_es_admin()
    if bloqueo is not None:
        return jsonify({"error": "Acceso denegado"}), 403
    fecha = _normalizar_fecha_resumen(request.args.get("fecha"))
    regenerar = request.args.get("regenerar", "").lower() in ("1", "true", "si", "yes")
    return _json_respuesta_resumen_diario(
        fecha, regenerar=regenerar, registrar_tipo_log="manual"
    )


@aplicacion.get("/admin/api/resumen-preview")
def admin_api_resumen_preview():
    """Genera un resumen sin guardarlo en resumenes_diarios_ia (solo preview)."""
    bloqueo = _redirigir_si_no_es_admin()
    if bloqueo is not None:
        return jsonify({"error": "Acceso denegado"}), 403
    fecha = _normalizar_fecha_resumen(request.args.get("fecha"))
    total = contar_eventos_en_fecha(fecha)
    if total == 0:
        return jsonify(
            {
                "sin_datos": True,
                "mensaje": "No hay datos para este día",
                "fecha": fecha,
                "total_eventos": 0,
            }
        )
    texto = generar_resumen_diario(fecha)
    registrar_resumen_log(fecha, "preview", total, len(texto or ""), ok=bool(texto))
    return jsonify(
        {
            "resumen": texto,
            "fecha": fecha,
            "total_eventos": total,
            "es_preview": True,
        }
    )


@aplicacion.delete("/admin/api/resumen-diario/<fecha>")
def admin_api_eliminar_resumen_diario(fecha):
    """Elimina el resumen guardado de una fecha."""
    bloqueo = _redirigir_si_no_es_admin()
    if bloqueo is not None:
        return jsonify({"error": "Acceso denegado"}), 403
    try:
        datetime.strptime(fecha, "%Y-%m-%d")
    except ValueError:
        return jsonify({"error": "Fecha inválida"}), 400
    eliminar_resumen_diario_ia(fecha)
    return jsonify({"exito": True, "fecha": fecha})


@aplicacion.get("/admin/api/resumen-diario/<fecha>/descargar")
def admin_api_descargar_resumen_diario(fecha):
    """Descarga el resumen guardado como archivo de texto."""
    bloqueo = _redirigir_si_no_es_admin()
    if bloqueo is not None:
        return jsonify({"error": "Acceso denegado"}), 403
    try:
        datetime.strptime(fecha, "%Y-%m-%d")
    except ValueError:
        return jsonify({"error": "Fecha inválida"}), 400
    guardado = obtener_resumen_diario_ia(fecha)
    if not guardado or not guardado.get("resumen"):
        return jsonify({"error": "No hay resumen guardado para esta fecha"}), 404
    nombre = f"flypaper_resumen_{fecha}.txt"
    respuesta = make_response(guardado["resumen"], 200)
    respuesta.mimetype = "text/plain; charset=utf-8"
    respuesta.headers["Content-Disposition"] = (
        f'attachment; filename="{nombre}"'
    )
    return respuesta


@aplicacion.get("/admin/api/resumenes-log")
def admin_api_resumenes_log():
    """Últimas entradas del log de generación de resúmenes."""
    bloqueo = _redirigir_si_no_es_admin()
    if bloqueo is not None:
        return jsonify({"error": "Acceso denegado"}), 403
    return jsonify({"entradas": obtener_log_resumenes(limite=50)})


@aplicacion.get("/monitor/api/resumen-diario")
@requiere_autenticacion_monitor
def monitor_api_resumen_diario():
    """
    Resumen ejecutivo en prosa de los ataques de un día (Claude).

    Query: fecha=YYYY-MM-DD, regenerar=1 para forzar nueva generación.
    """
    fecha = _normalizar_fecha_resumen(request.args.get("fecha"))
    regenerar = request.args.get("regenerar", "").lower() in ("1", "true", "si", "yes")
    return _json_respuesta_resumen_diario(fecha, regenerar=regenerar)


@aplicacion.get("/monitor/api/anomalias")
@requiere_autenticacion_monitor
def monitor_api_anomalias():
    """
    Devuelve la última detección de anomalías (caché del hilo de fondo o cálculo en vivo).

    El hilo periódico actualiza el caché cada 30 minutos; si aún no hay datos, se calcula al vuelo.
    """
    if _cache_anomalias.get("datos") is not None:
        return jsonify(
            {
                "desde_cache": True,
                "actualizado_en": (
                    _cache_anomalias["actualizado_en"].isoformat()
                    if _cache_anomalias.get("actualizado_en")
                    else None
                ),
                **_cache_anomalias["datos"],
            }
        )

    eventos_hora = obtener_eventos_ultima_hora(limite=500)
    resultado = detectar_anomalias(eventos_hora)
    _cache_anomalias["datos"] = resultado
    _cache_anomalias["actualizado_en"] = ahora_naive()
    return jsonify({"desde_cache": False, **resultado})


@aplicacion.get("/monitor/api/alertas")
@requiere_autenticacion_monitor
def monitor_api_alertas():
    """
    Últimas alertas graves sin filtro de período (panel en tiempo real).

    Devuelve hasta 10 eventos Crítica o Alta, ordenados por timestamp DESC.
    Cada elemento incluye: ip, ruta, tipo_ataque, gravedad, timestamp.
    """
    alertas = obtener_alertas_graves_monitor(limite=10, periodo=None)
    return jsonify(alertas)


@aplicacion.get("/monitor/exportar")
@requiere_autenticacion_monitor
def monitor_exportar_csv():
    """
    Exportación forense CSV con columnas fijas para análisis externo.

    Columnas: IP, Ruta Atacada, Tipo de Ataque, Payload, User Agent,
    Gravedad, Fecha y Hora.
    """
    lista_eventos = obtener_eventos(limite=9999, ambito="todo")

    buffer_csv = io.StringIO()
    escritor_csv = csv.writer(buffer_csv)

    escritor_csv.writerow(
        [
            "IP",
            "Ruta Atacada",
            "Tipo de Ataque",
            "Payload",
            "User Agent",
            "Gravedad",
            "Fecha y Hora",
        ]
    )

    for evento in lista_eventos:
        escritor_csv.writerow(
            [
                evento.get("ip", ""),
                evento.get("ruta", ""),
                evento.get("tipo_ataque", ""),
                _campo_evento_a_texto(evento.get("payload")),
                evento.get("user_agent", ""),
                evento.get("gravedad", ""),
                _timestamp_evento_formato_api(evento.get("timestamp")),
            ]
        )

    contenido_csv = buffer_csv.getvalue()
    buffer_csv.close()

    respuesta = make_response(contenido_csv, 200)
    respuesta.mimetype = "text/csv; charset=utf-8"
    respuesta.headers["Content-Disposition"] = "attachment; filename=flypaper_forense.csv"
    return respuesta


@aplicacion.get("/monitor/exportar/actividad-publica/csv")
@requiere_autenticacion_monitor
def monitor_exportar_actividad_publica_csv():
    """CSV de peticiones públicas filtradas por IP y un día exacto."""
    datos, error = _validar_exportacion_actividad_publica()
    if error:
        return jsonify({"error": error}), 400

    ip, fecha = datos
    peticiones = obtener_peticiones_publicas_por_ip_y_fecha(ip, fecha)

    buffer_csv = io.StringIO()
    escritor_csv = csv.writer(buffer_csv)
    escritor_csv.writerow(
        [
            "IP",
            "Ruta",
            "Método",
            "Código HTTP",
            "Tipo de ataque",
            "Usuario activo",
            "ID sesión",
            "Tiempo (ms)",
            "Tamaño respuesta (bytes)",
            "Puerto origen",
            "Payload",
            "User-Agent",
            "Fecha y Hora",
        ]
    )
    for fila in peticiones:
        escritor_csv.writerow(
            [
                fila.get("ip", ""),
                fila.get("ruta", ""),
                fila.get("metodo", ""),
                fila.get("codigo_http", ""),
                fila.get("tipo_ataque", ""),
                fila.get("usuario_activo", ""),
                fila.get("sesion_id_corto", ""),
                fila.get("tiempo_ms", ""),
                fila.get("tamano_respuesta_bytes", ""),
                fila.get("puerto_origen", ""),
                _campo_evento_a_texto(fila.get("payload")),
                fila.get("user_agent", ""),
                _timestamp_evento_formato_api(fila.get("timestamp")),
            ]
        )

    contenido_csv = buffer_csv.getvalue()
    buffer_csv.close()
    nombre = f"flypaper_actividad_{ip.replace(':', '_')}_{fecha}.csv"
    respuesta = make_response(contenido_csv, 200)
    respuesta.mimetype = "text/csv; charset=utf-8"
    respuesta.headers["Content-Disposition"] = f"attachment; filename={nombre}"
    return respuesta


@aplicacion.get("/monitor/exportar/actividad-publica/headers")
@requiere_autenticacion_monitor
def monitor_exportar_actividad_publica_headers():
    """Headers estilo Wireshark para peticiones públicas (IP + día exacto)."""
    datos, error = _validar_exportacion_actividad_publica()
    if error:
        return jsonify({"error": error}), 400

    ip, fecha = datos
    peticiones = obtener_peticiones_publicas_por_ip_y_fecha(ip, fecha)
    contenido_txt = generar_exportacion_wireshark_peticiones(peticiones)
    nombre = f"flypaper_actividad_{ip.replace(':', '_')}_{fecha}_headers.txt"
    respuesta = make_response(contenido_txt, 200)
    respuesta.mimetype = "text/plain; charset=utf-8"
    respuesta.headers["Content-Disposition"] = f"attachment; filename={nombre}"
    return respuesta


@aplicacion.get("/monitor/exportar/headers")
@requiere_autenticacion_monitor
def monitor_exportar_headers_wireshark():
    """
    Descarga un .txt con cabeceras HTTP en flujo secuencial estilo captura Wireshark.
    """
    contenido_txt = generar_exportacion_wireshark_headers()
    respuesta = make_response(contenido_txt, 200)
    respuesta.mimetype = "text/plain; charset=utf-8"
    respuesta.headers["Content-Disposition"] = (
        "attachment; filename=flypaper_wireshark_headers.txt"
    )
    return respuesta


if __name__ == "__main__":
    """
    Punto de entrada local para desarrollo.

    Se deja `debug=True` para facilitar pruebas durante la construcción
    del proyecto. En producción, debería establecerse en `False`.
    """
    aplicacion.run(host="0.0.0.0", port=5000, debug=True)
