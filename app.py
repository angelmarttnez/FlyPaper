"""
Aplicación principal de FlyPaper.

Este archivo define un honeypot web con Flask que:
- Simula endpoints atractivos para atacantes.
- Clasifica automáticamente cada interacción.
- Guarda eventos en SQLite para posterior análisis.
"""

import csv
import io
import json
import threading
import time
import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)

from database import (
    contar_flags_resueltas_por_ip,
    enviar_flag,
    guardar_evento,
    guardar_reporte_enviado,
    inicializar_db,
    obtener_comentarios_visibles_post,
    obtener_conexion,
    obtener_estadisticas,
    obtener_eventos,
    desbloquear_ip_persistente,
    ip_esta_bloqueada_en_bd,
    listar_ips_bloqueadas,
    obtener_flags_con_estado_por_ip,
    obtener_flags_publicas,
    reiniciar_progreso_ctf_por_ip,
    obtener_post_por_id,
    obtener_posts_blog,
    obtener_reportes_enviados,
    registrar_ip_bloqueada,
)
from detector import calcular_gravedad, clasificar_ataque, registrar_intento_login

# Intervalo entre ejecuciones del hilo de limpieza de comentarios (30 minutos).
INTERVALO_LIMPIEZA_COMENTARIOS_SEG = 30 * 60

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
        "gravedad": fila.get("gravedad") or "BAJO",
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
        "gravedad": fila.get("gravedad") or "BAJO",
        "timestamp": _timestamp_evento_formato_api(fila.get("timestamp")),
        "user_agent": fila.get("user_agent") or "",
        "headers": _campo_evento_a_texto(fila.get("headers")),
    }


# Prioridad numérica para calcular la gravedad máxima de un grupo de eventos.
_PRIORIDAD_GRAVEDAD = {"CRÍTICO": 4, "ALTO": 3, "MEDIO": 2, "BAJO": 1}


def _calcular_gravedad_maxima(lista_gravedades):
    """Devuelve la gravedad más alta presente en una lista (por defecto BAJO)."""
    maxima = "BAJO"
    rank_max = 0
    for gravedad in lista_gravedades:
        clave = (gravedad or "BAJO").strip().upper()
        rank = _PRIORIDAD_GRAVEDAD.get(clave, 1)
        if rank > rank_max:
            rank_max = rank
            maxima = gravedad or "BAJO"
    return maxima


def agrupar_eventos_por_ip(limite_eventos=500):
    """
    Agrupa eventos recientes por dirección IP para el API del monitor.

    Returns:
        list[dict]: Grupos con total_eventos, tipos_ataque, gravedad_maxima,
                    primera_vez, ultima_vez y lista de eventos detallados.
    """
    filas = obtener_eventos(limite=limite_eventos)
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
        tipo = (fila.get("tipo_ataque") or "").strip() or "Otro"
        grupo["tipos_set"].add(tipo)
        grupo["gravedades"].append(fila.get("gravedad") or "BAJO")
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


def generar_exportacion_wireshark_headers():
    """
    Construye un .txt con flujo secuencial de peticiones simulando captura Wireshark.
    """
    eventos = obtener_eventos(limite=9999)
    bloques = []

    for indice, evento in enumerate(eventos, start=1):
        ts = _timestamp_evento_formato_api(evento.get("timestamp"))
        metodo = evento.get("metodo") or "GET"
        ruta = evento.get("ruta") or "/"
        ip = evento.get("ip") or ""
        ua = evento.get("user_agent") or ""

        lineas_bloque = [
            f"=== Petición #{indice} [{ts}] ===",
            f"IP: {ip}",
            f"{metodo} {ruta} HTTP/1.1",
        ]
        if ua:
            lineas_bloque.append(f"User-Agent: {ua}")

        lineas_bloque.extend(_cabeceras_http_a_lineas(evento.get("headers") or ""))
        bloques.append("\n".join(lineas_bloque))

    return "\n\n".join(bloques)


def _ataques_detectados_sin_otro(estadisticas_bd):
    """
    Cuenta eventos cuyo tipo de ataque no es exactamente 'Otro' (sin distinguir mayúsculas).

    Se usa la agregación `ataques_por_tipo` de `obtener_estadisticas` para no duplicar SQL.
    """
    total = 0
    for tipo, cantidad in (estadisticas_bd.get("ataques_por_tipo") or {}).items():
        if str(tipo).strip().lower() != "otro":
            total += int(cantidad)
    return total


def _minutos_desde_ultimo_evento():
    """Minutos transcurridos entre el último evento en BD y el instante actual (UTC naive)."""
    ultimos = obtener_eventos(limite=1)
    if not ultimos:
        return None
    ts = ultimos[0].get("timestamp")
    if not ts:
        return None
    try:
        s = str(ts).strip().replace("Z", "")
        if "T" in s:
            dt = datetime.fromisoformat(s)
        else:
            dt = datetime.strptime(s[:19], "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return None
    ahora = datetime.utcnow()
    if getattr(dt, "tzinfo", None) is not None:
        dt = dt.replace(tzinfo=None)
    return max(0, int((ahora - dt).total_seconds() // 60))


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
            "DELETE FROM comentarios WHERE fecha < datetime('now', '-24 hours');"
        )
        eliminados = cursor.rowcount
        conexion.commit()
    print(
        f"[FlyPaper] Limpieza automática de comentarios: "
        f"{eliminados} registro(s) eliminado(s) (antigüedad > 24 h)."
    )
    return eliminados


def tarea_periodica_limpieza_comentarios():
    """
    Bucle del hilo en segundo plano: limpia comentarios viejos cada 30 minutos.
    """
    while True:
        try:
            limpiar_comentarios_antiguos()
        except Exception as exc:
            print(f"[FlyPaper] Error en la limpieza periódica de comentarios: {exc}")
        time.sleep(INTERVALO_LIMPIEZA_COMENTARIOS_SEG)


def iniciar_hilo_limpieza_comentarios():
    """
    Arranca el hilo daemon de limpieza (no bloquea el cierre del proceso Flask).
    """
    hilo = threading.Thread(
        target=tarea_periodica_limpieza_comentarios,
        name="flypaper-limpieza-comentarios",
        daemon=True,
    )
    hilo.start()
    print("[FlyPaper] Hilo de limpieza de comentarios iniciado (cada 30 minutos).")


def _limpiar_ventana_comentarios_ip(ip):
    """Deja solo los timestamps de comentarios de los últimos 5 minutos para esa IP."""
    ahora = datetime.now()
    hace_cinco_minutos = ahora - timedelta(minutes=5)
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
    comentarios_recientes_por_ip[ip].append(datetime.now())


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
    marca = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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


def construir_payload_para_registro():
    """
    Construye una representación de payload útil para almacenar en la BD.

    Prioridad utilizada:
    1) Si hay formulario (`request.form`), guardamos ese diccionario.
    2) Si hay JSON (`request.get_json`), guardamos ese objeto.
    3) Si hay query string (`request.args`), guardamos esos parámetros.
    4) Si no hay estructura previa, guardamos el cuerpo en texto bruto.

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

    return request.get_data(as_text=True) or ""


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

    POST /search registra manualmente la búsqueda (incluye gravedad SQLi).
    """
    if ruta_solicitada == "/search" and metodo == "POST":
        return True
    return False


def obtener_ip_cliente():
    """Obtiene la IP del cliente respetando X-Forwarded-For si existe."""
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    if "," in ip:
        ip = ip.split(",")[0].strip()
    return ip


def ruta_exenta_de_bloqueo_ip(ruta):
    """
    Rutas accesibles aunque la IP esté bloqueada (monitor, assets, reintento y login).

    Tras /acceso/reintentar la IP se desbloquea; /login queda libre para autenticarse.
    """
    if not ruta:
        return False
    if ruta.startswith("/monitor"):
        return True
    if ruta.startswith("/assets/"):
        return True
    if ruta in ("/acceso/reintentar", "/login", "/monitor/login"):
        return True
    return False


def registrar_actividad_visitante(ip):
    """Actualiza la marca de actividad y el token de sesión asociado a la IP."""
    if not ip:
        return
    ultima_actividad_por_ip[ip] = datetime.now()
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
    delta = (datetime.now() - ultima).total_seconds()
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
    Middleware global: registra actividad por IP y bloquea visitantes en lista negra.

    El panel /monitor queda exento para que el analista pueda seguir operando.
    """
    ruta = request.path or ""
    ip = obtener_ip_cliente()

    registrar_actividad_visitante(ip)

    if ruta_exenta_de_bloqueo_ip(ruta):
        return None

    if visitante_esta_bloqueado(ip):
        session.clear()
        return respuesta_expulsion_visitante()

    return None


@aplicacion.route("/assets/<path:nombre_archivo>")
def servir_archivo_assets(nombre_archivo):
    """Sirve recursos estáticos del proyecto (p. ej. Cat.gif en la expulsión)."""
    return send_from_directory(RUTA_CARPETA_ASSETS, nombre_archivo)


@aplicacion.post("/acceso/reintentar")
def acceso_reintentar_tras_bloqueo():
    """
    Desbloquea la IP del visitante, destruye su sesión en servidor y permite ir al login.

    El frontend limpia cookies/localStorage y redirige a /login tras esta petición.
    """
    ip = obtener_ip_cliente()
    desbloquear_ip_visitante(ip)
    session.clear()
    return jsonify({"exito": True, "redirect": url_for("mostrar_login")})


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
            return redirect(url_for("monitor_login_get"))
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

    # Omitimos rutas internas/estáticas y las que registran el evento en su propia vista.
    if debe_excluirse_del_registro(ruta_visitada) or omitir_registro_automatico_honeypot(
        ruta_visitada, metodo_peticion
    ):
        return respuesta

    ip_visitante = obtener_ip_cliente()
    payload_peticion = construir_payload_para_registro()
    user_agent_visitante = request.headers.get("User-Agent", "")
    cabeceras_peticion = dict(request.headers)

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

    guardar_evento(
        ip=ip_visitante,
        ruta=ruta_visitada,
        metodo=metodo_peticion,
        payload=payload_peticion,
        user_agent=user_agent_visitante,
        tipo_ataque=tipo_ataque_detectado,
        headers=cabeceras_peticion,
        gravedad=gravedad_evento,
    )

    return respuesta


@aplicacion.get("/")
def redirigir_a_login():
    """
    Redirige la raíz del sitio hacia la página de login.

    Esta función existe para que el flujo inicial de la web falsa
    se parezca al de un portal real con autenticación.
    """
    return redirect(url_for("mostrar_login"))


@aplicacion.get("/login")
def mostrar_login():
    """
    Muestra el formulario de autenticación falso.

    Renderiza la plantilla `login.html`, que simula una pantalla de acceso.
    """
    return render_template("login.html")


# Usuarios de demostración: contraseña y ruta tras login correcto.
usuarios = {
    "admin": {"password": "admin", "redirige": "/admin"},
    "Angel": {"password": "Angel123", "redirige": "/search"},
}


@aplicacion.post("/login")
def procesar_login():
    """
    Valida usuario y contraseña contra el diccionario `usuarios`.

    Si las credenciales son correctas, guarda el estado en la sesión y
    redirige a la ruta asociada al usuario.
    Si fallan, redirige al login con parámetro de error (sin conceder acceso).
    """
    # Campos del formulario en `login.html` (honeypot con aspecto realista).
    usuario_enviado = request.form.get("username", "")
    contrasena_enviada = request.form.get("password", "")

    ip_peticion = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    if "," in ip_peticion:
        ip_peticion = ip_peticion.split(",")[0].strip()
    if registrar_intento_login(ip_peticion):
        session["_fuerza_bruta_detectada"] = True

    # Buscamos al usuario por nombre exacto (las claves distinguen mayúsculas).
    datos_usuario = usuarios.get(usuario_enviado)
    if datos_usuario is not None and datos_usuario["password"] == contrasena_enviada:
        # Sesión del honeypot: marcamos acceso y guardamos el nombre mostrado.
        session["logueado"] = True
        session["usuario"] = usuario_enviado
        # Credenciales válidas: vamos a la ruta configurada para ese usuario.
        return redirect(datos_usuario["redirige"])

    # Usuario inexistente o contraseña incorrecta: mismo flujo, sin entrar a zonas protegidas.
    return redirect("/login?error=1")


@aplicacion.get("/logout")
def cerrar_sesion_honeypot():
    """
    Cierra la sesión del visitante (honeypot) y vuelve al formulario de login.
    """
    # Vacía por completo la sesión Flask (incluye claves usadas por otras partes si las hubiera).
    session.clear()
    return redirect(url_for("mostrar_login"))


@aplicacion.get("/admin")
def mostrar_panel_admin():
    """
    Muestra un panel de administración falso.

    Renderiza la plantilla `admin.html`, diseñada para aparentar
    una zona sensible de gestión.
    """
    # Solo accesible tras login correcto en POST /login.
    if session.get("logueado") is not True:
        return redirect("/login?error=1")
    # Enlace al monitor real (ruta pasada al template para no duplicar literales).
    return render_template("admin.html", monitor_url="/monitor/login")


@aplicacion.get("/admin/usuarios")
def admin_usuarios():
    """
    Subsección falsa de administración: listado de usuarios.

    Misma política de acceso que el panel principal `/admin`.
    """
    # Requiere sesión creada en POST /login (honeypot).
    if session.get("logueado") is not True:
        return redirect("/login?error=1")
    return render_template("usuarios.html")


@aplicacion.get("/admin/configuracion")
def admin_configuracion():
    """
    Subsección falsa de administración: pantalla de configuración.

    Requiere autenticación por sesión igual que el resto de `/admin`.
    """
    # Sin sesión válida, no se muestra contenido sensible simulado.
    if session.get("logueado") is not True:
        return redirect("/login?error=1")
    return render_template("configuracion.html")


@aplicacion.get("/admin/reportes")
def admin_reportes():
    """
    Lista los reportes enviados desde el monitor de analista (tabla reportes_enviados).

    Protegida con la misma sesión honeypot `logueado` que el resto del panel /admin.
    """
    if session.get("logueado") is not True:
        return redirect("/login?error=1")

    filas = obtener_reportes_enviados()
    # Preparar datos legibles en plantilla (JSON formateado si aplica).
    reportes_vista = []
    for fila in filas:
        datos_crudos = fila.get("datos_ataque") or ""
        datos_legibles = datos_crudos
        try:
            objeto = json.loads(datos_crudos)
            datos_legibles = json.dumps(objeto, ensure_ascii=False, indent=2)
        except (json.JSONDecodeError, TypeError):
            pass
        reportes_vista.append(
            {
                "id": fila.get("id"),
                "ip_atacante": fila.get("ip_atacante") or "",
                "datos_ataque": datos_legibles,
                "fecha": fila.get("fecha") or "",
            }
        )

    return render_template("reportes.html", reportes=reportes_vista)


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
def mostrar_busqueda():
    """
    Muestra el formulario de búsqueda interna (requiere sesión honeypot).

    La consulta vulnerable se envía por POST al mismo endpoint.
    """
    if session.get("logueado") is not True:
        return redirect("/login?error=1")
    return render_template("search.html")


@aplicacion.post("/search")
def procesar_busqueda():
    """
    Búsqueda vulnerable a SQLi (concatenación directa sin sanitizar).

    - Éxito: muestra filas de `posts` en search.html.
    - Error SQLite: muestra el mensaje de error (error-based SQLi).
    - Siempre registra el evento; gravedad CRÍTICO si el detector ve SQLi.
    """
    if session.get("logueado") is not True:
        return redirect("/login?error=1")

    query = request.form.get("query", "")
    resultados = []
    error_sql = None

    # Consulta insegura a propósito (laboratorio / CTF).
    sql = (
        f"SELECT * FROM posts WHERE titulo LIKE '%{query}%' "
        f"OR contenido LIKE '%{query}%'"
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

    payload_registro = {"query": query}
    tipo_ataque = clasificar_ataque(
        ruta="/search",
        payload=str(payload_registro),
        user_agent=request.headers.get("User-Agent", ""),
        headers=dict(request.headers),
        metodo="POST",
    )
    gravedad = "CRÍTICO" if tipo_ataque == "SQLi" else calcular_gravedad(tipo_ataque)
    guardar_evento(
        ip=obtener_ip_cliente(),
        ruta="/search",
        metodo="POST",
        payload=payload_registro,
        user_agent=request.headers.get("User-Agent", ""),
        tipo_ataque=tipo_ataque,
        headers=dict(request.headers),
        gravedad=gravedad,
    )

    return render_template(
        "search.html",
        query=query,
        resultados=resultados,
        error_sql=error_sql,
        total_resultados=len(resultados),
    )


@aplicacion.get("/objetivos")
def pagina_objetivos():
    """
    Página pública de retos CTF: lista flags (sin el secreto) y progreso por IP.
    """
    ip_actual = obtener_ip_cliente()
    flags = obtener_flags_con_estado_por_ip(ip_actual)
    resueltas = contar_flags_resueltas_por_ip(ip_actual)
    total = len(flags)

    return render_template(
        "objetivos.html",
        flags=flags,
        resueltas=resueltas,
        total=total if total else 2,
    )


@aplicacion.post("/objetivos/submit")
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

    resultado = enviar_flag(obtener_ip_cliente(), flag_enviada)
    return jsonify(resultado)


@aplicacion.post("/objetivos/reset")
def objetivos_reset_progreso():
    """
    Borra el progreso CTF de la IP actual para poder reenviar las mismas flags (QA).

    JSON: {"exito": true, "resueltas": 0, "total": 2, "mensaje": "..."}
    """
    ip_actual = obtener_ip_cliente()
    reiniciar_progreso_ctf_por_ip(ip_actual)
    total = len(obtener_flags_publicas())
    return jsonify(
        {
            "exito": True,
            "resueltas": 0,
            "total": total,
            "mensaje": "Progreso restablecido. Puedes resolver los retos de nuevo.",
        }
    )


@aplicacion.get("/blog")
def blog_listado():
    """
    Blog público del honeypot: listado de posts reales desde la BD.
    """
    posts = obtener_posts_blog()
    return render_template("blog.html", posts=posts)


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
    return render_template(
        "post.html",
        post=post,
        comentarios=comentarios,
        limite_sesion=LIMITE_COMENTARIOS_SESION_POR_POST,
        cupo_restante=cupo_restante,
    )


@aplicacion.post("/blog/<int:post_id>/comentar")
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

    Credenciales válidas:
    - usuario: analyst
    - contraseña: FlyPaper2026!
    """
    # Importante: estos nombres deben coincidir con `name="usuario"` y
    # `name="contrasena"` definidos en `templates/monitor_login.html`.
    usuario_enviado = request.form.get("usuario", "").strip()
    contrasena_enviada = request.form.get("contrasena", "")

    if usuario_enviado == "analyst" and contrasena_enviada == "FlyPaper2026!":
        # Sesión exclusiva del monitor (clave distinta al honeypot `logueado`).
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


@aplicacion.get("/monitor/api/eventos")
@requiere_autenticacion_monitor
def monitor_api_eventos():
    """
    Devuelve eventos agrupados por IP para el dashboard del monitor.

    Cada grupo incluye resumen (total, tipos, gravedad máxima, ventana temporal)
    y la lista detallada de eventos de esa IP.
    """
    grupos_por_ip = agrupar_eventos_por_ip(limite_eventos=500)
    return jsonify(grupos_por_ip)


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


@aplicacion.get("/monitor/api/stats")
@requiere_autenticacion_monitor
def monitor_api_estadisticas():
    """
    Devuelve estadísticas agregadas reales a partir de `obtener_estadisticas()`.

    Incluye conteo de ataques distintos de 'Otro', minutos desde el último evento
    y actividad por hora del día. Se añaden alias (`tipos_ataque`, etc.) para el dashboard.
    """
    estadisticas_bd = obtener_estadisticas()
    ataques_por_tipo = dict(estadisticas_bd.get("ataques_por_tipo") or {})
    ataques_detectados = _ataques_detectados_sin_otro(estadisticas_bd)
    ultimo_hace = _minutos_desde_ultimo_evento()
    ultimo_hace = 0 if ultimo_hace is None else ultimo_hace
    actividad_por_hora = _actividad_por_hora_desde_buckets(estadisticas_bd)

    cuerpo = {
        "total_eventos": estadisticas_bd["total_eventos"],
        "ips_unicas": estadisticas_bd["ips_unicas"],
        "ataques_detectados": ataques_detectados,
        "ultimo_ataque_hace": ultimo_hace,
        "ataques_por_tipo": ataques_por_tipo,
        "actividad_por_hora": actividad_por_hora,
        # Nombres antiguos usados por `dashboard.html` (gráficas y tarjeta “último ataque”).
        "ultimo_ataque_min": ultimo_hace,
        "tipos_ataque": ataques_por_tipo,
        "actividad_horas": actividad_por_hora,
    }
    return jsonify(cuerpo)


@aplicacion.get("/monitor/exportar")
@requiere_autenticacion_monitor
def monitor_exportar_csv():
    """
    Exportación forense CSV con columnas fijas para análisis externo.

    Columnas: IP, Ruta Atacada, Tipo de Ataque, Payload, User Agent,
    Gravedad, Fecha y Hora.
    """
    lista_eventos = obtener_eventos(limite=9999)

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
