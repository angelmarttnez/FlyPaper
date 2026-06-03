"""
Módulo de detección y clasificación de ataques para FlyPaper.

Analiza rutas, payloads, user-agents y cabeceras HTTP con reglas por patrones.
Incluye contador en memoria para fuerza bruta en POST /login y niveles de gravedad.
"""

import json
import re
from datetime import datetime, timedelta
from urllib.parse import unquote_plus

# Timestamps de intentos POST /login por IP: {"203.0.113.1": [datetime, ...]}
intentos_login = {}

# Categoría por defecto: tráfico legítimo o sin patrón de ataque identificable.
TIPO_TRAFICO_NORMAL = "Tráfico Normal"

# GET /blog/<id> — detalle de publicación.
_PATRON_RUTA_BLOG_POST = re.compile(r"^/blog/\d+$")
# Query de búsqueda sin caracteres de inyección (letras, números, espacios, puntuación básica).
_PATRON_QUERY_SEARCH_LIMPIA = re.compile(
    r"^[a-zA-Z0-9\s\-_.áéíóúñüÁÉÍÓÚÑÜ]*$"
)
# Indicios de inyección en credenciales de POST /login.
_INDICIOS_LOGIN_MALICIOSO = (
    "'",
    '"',
    "<script",
    "union",
    "../",
    "..\\",
    "%2e%2e",
    "--",
    "/*",
    "<img",
    "javascript:",
    "onerror=",
)


# ---------------------------------------------------------------------------
# Patrones SQLi — inyección en formularios o parámetros
# Ejemplo: username=admin' OR 1=1--  |  id=1 UNION SELECT password FROM users
# ---------------------------------------------------------------------------
PATRONES_SQLI = [
    "select",
    "union",
    "drop",
    "insert",
    "update",
    "delete",
    "or 1=1",
    "--",
    "/*",
    "sleep",
    "exec",
    "xp_",
    "cast",
    "convert",
    "char",
    "concat",
    "group by",
    "having",
    "order by",
    "benchmark",
    "load_file",
    "into outfile",
    "information_schema",
]

# ---------------------------------------------------------------------------
# Patrones XSS — ejecución de script en el navegador de la víctima
# Ejemplo: <script>alert(1)</script>  |  <img src=x onerror=alert(1)>
# ---------------------------------------------------------------------------
PATRONES_XSS = [
    "<script",
    "javascript:",
    "onerror=",
    "onload=",
    "alert(",
    "document.cookie",
    "eval(",
    "<img src=",
    "<svg",
    "<iframe",
    "onfocus",
    "onmouseover",
    "expression(",
    "vbscript:",
    "data:text/html",
]

# ---------------------------------------------------------------------------
# Path Traversal — lectura de ficheros fuera del directorio web
# Ejemplo: /../../etc/passwd  |  ruta=%2e%2e%2fetc%2fpasswd
# ---------------------------------------------------------------------------
PATRONES_PATH_TRAVERSAL = [
    "/../",
    "/etc/passwd",
    "/etc/shadow",
    "/windows/system32",
    "%2e%2e",
    "%252e",
    "../",
    "..\\",
    "/proc/self",
]

# ---------------------------------------------------------------------------
# Rutas típicas de reconocimiento y enumeración
# Ejemplo: GET /.env  |  GET /wp-admin
# ---------------------------------------------------------------------------
RUTAS_RECONOCIMIENTO = [
    "/admin",
    "/backup",
    "/.env",
    "/config",
    "/phpinfo",
    "/wp-admin",
    "/phpmyadmin",
    "/robots.txt",
    "/.git",
    "/.htaccess",
    "/web.config",
    "/api/v1",
    "/swagger",
    "/actuator",
    "/console",
    "/.ssh",
]

# ---------------------------------------------------------------------------
# User-Agents de herramientas automatizadas de escaneo
# Ejemplo: sqlmap/1.7  |  Nikto/2.1.5
# ---------------------------------------------------------------------------
SCANNERS_CONOCIDOS = [
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "zgrab",
    "python-requests",
    "curl/",
    "wget/",
    "dirbuster",
    "gobuster",
    "wfuzz",
    "burpsuite",
    "hydra",
    "metasploit",
]


def _normalizar_headers(headers):
    """
    Convierte cabeceras Flask/Werkzeug o dict a un dict con claves en minúsculas.

    Args:
        headers: Cabeceras de la petición o None.

    Returns:
        dict: Mapa nombre → valor en minúsculas.
    """
    if not headers:
        return {}
    if hasattr(headers, "items"):
        return {str(k).lower(): str(v) for k, v in headers.items()}
    return {str(k).lower(): str(v) for k, v in headers}


def _contiene_patron(texto, patrones):
    """True si algún patrón aparece como subcadena en `texto` (ya en minúsculas)."""
    if not texto:
        return False
    return any(patron in texto for patron in patrones)


def _texto_payload_normalizado(payload):
    """Convierte payload a texto en minúsculas para reglas de clasificación."""
    if payload is None:
        return ""
    if isinstance(payload, dict):
        try:
            return json.dumps(payload, ensure_ascii=False).lower()
        except (TypeError, ValueError):
            return str(payload).lower()
    return str(payload).lower()


def _contiene_patrones_ataque(texto):
    """True si el texto incluye indicios de SQLi, XSS o path traversal."""
    texto_norm = (texto or "").lower()
    if not texto_norm.strip():
        return False
    return (
        _contiene_patron(texto_norm, PATRONES_SQLI)
        or _contiene_patron(texto_norm, PATRONES_XSS)
        or _contiene_patron(texto_norm, PATRONES_PATH_TRAVERSAL)
    )


def _payload_es_sospechoso(payload_norm):
    """True si el payload contiene indicios de SQLi, XSS o path traversal."""
    return _contiene_patrones_ataque(payload_norm)


def _normalizar_ruta_clasificacion(ruta):
    """Ruta sin query string, minúsculas, sin barra final redundante."""
    return (ruta or "").lower().split("?")[0].rstrip("/") or "/"


def _post_login_credenciales_simples(payload):
    """True si POST /login no lleva comillas, UNION, scripts ni path traversal."""
    payload_norm = _texto_payload_normalizado(payload)
    return not any(indicio in payload_norm for indicio in _INDICIOS_LOGIN_MALICIOSO)


def _extraer_query_search(ruta, payload):
    """Obtiene el parámetro query de GET /search (URL o cuerpo)."""
    if "?" in (ruta or ""):
        for parte in (ruta or "").split("?", 1)[1].split("&"):
            if parte.lower().startswith("query="):
                return unquote_plus(parte.split("=", 1)[1])
    payload_norm = _texto_payload_normalizado(payload)
    coincidencia = re.search(
        r'["\']?query["\']?\s*[:=]\s*["\']?([^&"\'}\]]+)',
        payload_norm,
        re.IGNORECASE,
    )
    if coincidencia:
        return unquote_plus(coincidencia.group(1).strip())
    return ""


def _search_get_query_es_limpia(ruta, payload):
    """True si GET /search no tiene query o solo usa caracteres no maliciosos."""
    query = _extraer_query_search(ruta, payload).strip()
    if not query:
        return True
    return bool(_PATRON_QUERY_SEARCH_LIMPIA.match(query))


def _es_trafico_legitimo_prioritario(ruta, payload, metodo):
    """
    Primera pasada en clasificar_ataque: rutas legítimas sin patrones de ataque.

    Devuelve True si la petición encaja en interacción esperada del sitio y
    ruta/payload no contienen SQLi, XSS ni path traversal.
    """
    texto_completo = f"{ruta or ''} {_texto_payload_normalizado(payload)}"
    if _contiene_patrones_ataque(texto_completo):
        return False

    ruta_norm = _normalizar_ruta_clasificacion(ruta)
    metodo_up = (metodo or "GET").upper()

    if metodo_up in ("OPTIONS", "HEAD"):
        return True

    if ruta_norm.startswith("/static/") or ruta_norm.startswith("/assets/"):
        return True

    if ruta_norm == "/login" and metodo_up == "GET":
        return True

    if ruta_norm == "/login" and metodo_up == "POST":
        return _post_login_credenciales_simples(payload)

    if ruta_norm == "/logout" and metodo_up == "GET":
        return True

    if ruta_norm == "/" and metodo_up == "GET":
        return True

    if ruta_norm == "/blog" and metodo_up == "GET":
        return True

    if metodo_up == "GET" and _PATRON_RUTA_BLOG_POST.match(ruta_norm):
        return True

    if ruta_norm == "/search" and metodo_up == "GET":
        return _search_get_query_es_limpia(ruta, payload)

    if ruta_norm.startswith("/admin") and metodo_up == "GET":
        return True

    return False


def _detectar_csrf(headers, metodo):
    """
    Detecta posible CSRF en peticiones POST sin Referer válido.

    Reglas:
    - Solo aplica a método POST.
    - Sin cabecera Referer → sospechoso.
    - Referer presente pero sin coincidir con Host → sospechoso.

    Ejemplo: POST /transfer sin Referer desde un formulario externo.

    Args:
        headers: Cabeceras HTTP de la petición.
        metodo (str): GET, POST, etc.

    Returns:
        bool: True si parece CSRF.
    """
    if (metodo or "").upper() != "POST":
        return False

    cabeceras = _normalizar_headers(headers)
    referer = cabeceras.get("referer", "").strip()
    host = cabeceras.get("host", "").strip()

    if not referer:
        return True

    if host:
        referer_lower = referer.lower()
        host_lower = host.lower().split(":")[0]
        if host_lower not in referer_lower:
            return True

    return False


def registrar_intento_login(ip):
    """
    Registra un intento de login (POST /login) y detecta fuerza bruta.

    - Añade el timestamp actual a la lista de la IP.
    - Elimina intentos con más de 1 minuto de antigüedad.
    - Devuelve True si hay más de 5 intentos en el último minuto.

    Ejemplo: la IP 10.0.0.5 envía 6 POST /login en 30 segundos → True.

    Args:
        ip (str): Dirección IP del cliente.

    Returns:
        bool: True si se supera el umbral de fuerza bruta.
    """
    if not ip:
        return False

    ahora = datetime.now()
    hace_un_minuto = ahora - timedelta(minutes=1)

    if ip not in intentos_login:
        intentos_login[ip] = []

    intentos_login[ip] = [
        marca for marca in intentos_login[ip] if marca > hace_un_minuto
    ]
    intentos_login[ip].append(ahora)

    return len(intentos_login[ip]) > 5


def clasificar_ataque(ruta, payload, user_agent, headers=None, metodo=None):
    """
    Clasifica un evento del honeypot según reglas de prioridad.

    Orden aplicado:
    0) Rutas legítimas sin patrones de ataque (retorno inmediato Tráfico Normal)
    1) SQLi (payload)
    2) XSS (payload)
    3) Path Traversal (ruta o payload)
    4) CSRF (POST sin Referer coherente con Host)
    5) Scanner Automatizado (User-Agent)
    6) Reconocimiento (ruta señuelo)
    7) Tráfico Normal (por defecto)

    La fuerza bruta se detecta con `registrar_intento_login` en POST /login;
    la aplicación puede sobrescribir el tipo a "Fuerza Bruta" cuando devuelve True.

    Args:
        ruta (str): Ruta solicitada, p. ej. "/login".
        payload (str): Cuerpo o parámetros de la petición.
        user_agent (str): Cabecera User-Agent.
        headers (dict | None): Cabeceras HTTP (necesarias para CSRF).
        metodo (str | None): Método HTTP (necesario para CSRF).

    Returns:
        str: Tipo de ataque detectado.
    """
    if _es_trafico_legitimo_prioritario(ruta, payload, metodo):
        return TIPO_TRAFICO_NORMAL

    ruta_norm = (ruta or "").lower()
    payload_norm = (payload or "").lower()
    ua_norm = (user_agent or "").lower()
    texto_ruta_payload = f"{ruta_norm} {payload_norm}"

    # 1) SQLi — ej.: payload "admin' OR 1=1--"
    if _contiene_patron(payload_norm, PATRONES_SQLI):
        return "SQLi"

    # 2) XSS — ej.: payload "<script>alert(document.cookie)</script>"
    if _contiene_patron(payload_norm, PATRONES_XSS):
        return "XSS"

    # 3) Path Traversal — ej.: ruta "/../../etc/passwd"
    if _contiene_patron(texto_ruta_payload, PATRONES_PATH_TRAVERSAL):
        return "Path Traversal"

    # 4) CSRF — ej.: POST sin Referer o Referer de otro dominio
    if _detectar_csrf(headers, metodo):
        return "CSRF"

    # 5) Scanner — ej.: User-Agent "sqlmap/1.4"
    if _contiene_patron(ua_norm, SCANNERS_CONOCIDOS):
        return "Scanner Automatizado"

    # 6) Reconocimiento — ej.: GET "/.env"
    for ruta_senal in RUTAS_RECONOCIMIENTO:
        if ruta_norm == ruta_senal or ruta_norm.startswith(ruta_senal + "/"):
            return "Reconocimiento"

    return TIPO_TRAFICO_NORMAL


# Escala SOC del monitor (tres niveles + sin gravedad para tráfico normal).
GRAVEDAD_CRITICA = "Crítica"
GRAVEDAD_ALTA = "Alta"
GRAVEDAD_SOSPECHOSO = "Sospechoso"
GRAVEDADES_MONITOR = (GRAVEDAD_CRITICA, GRAVEDAD_ALTA, GRAVEDAD_SOSPECHOSO)

# Alias legacy almacenados antes de la migración.
_MAPA_GRAVEDAD_LEGACY = {
    "CRÍTICO": GRAVEDAD_CRITICA,
    "CRITICO": GRAVEDAD_CRITICA,
    "ALTO": GRAVEDAD_ALTA,
    "MEDIO": GRAVEDAD_SOSPECHOSO,
    "BAJO": GRAVEDAD_SOSPECHOSO,
}


def normalizar_gravedad_almacenada(gravedad):
    """
    Devuelve la etiqueta canónica (Crítica/Alta/Sospechoso) o None si no aplica.

    Args:
        gravedad (str|None): Valor en BD o respuesta del detector.

    Returns:
        str | None
    """
    if gravedad is None:
        return None
    texto = str(gravedad).strip()
    if not texto:
        return None
    if texto in GRAVEDADES_MONITOR:
        return texto
    clave = texto.upper()
    if clave in _MAPA_GRAVEDAD_LEGACY:
        return _MAPA_GRAVEDAD_LEGACY[clave]
    baja = clave.replace("Í", "I")
    if baja in _MAPA_GRAVEDAD_LEGACY:
        return _MAPA_GRAVEDAD_LEGACY[baja]
    return texto


def normalizar_gravedad_filtro_api(valor):
    """
    Normaliza ?gravedad= del monitor a un nivel canónico o None (ver todos los incidentes).

    Args:
        valor (str|None): Parámetro de query.

    Returns:
        str | None: Crítica, Alta, Sospechoso, o None para «todos».
    """
    if valor is None:
        return None
    texto = str(valor).strip()
    if not texto or texto.lower() in ("todos", "todas", "all", ""):
        return None
    canon = normalizar_gravedad_almacenada(texto)
    if canon in GRAVEDADES_MONITOR:
        return canon
    alias = {
        "critica": GRAVEDAD_CRITICA,
        "crítica": GRAVEDAD_CRITICA,
        "critico": GRAVEDAD_CRITICA,
        "alta": GRAVEDAD_ALTA,
        "alto": GRAVEDAD_ALTA,
        "sospechoso": GRAVEDAD_SOSPECHOSO,
        "sospechosa": GRAVEDAD_SOSPECHOSO,
    }
    return alias.get(texto.lower())


def prioridad_gravedad(gravedad):
    """Entero para ordenar de mayor a menor severidad (0 = sin gravedad)."""
    canon = normalizar_gravedad_almacenada(gravedad)
    return {"Crítica": 3, "Alta": 2, "Sospechoso": 1}.get(canon, 0)


def calcular_gravedad(tipo_ataque):
    """
    Asigna severidad al tipo de ataque clasificado.

    - Crítica: SQLi, Path Traversal, RCE (explotación confirmada).
    - Alta: XSS, Fuerza Bruta, CSRF, escaneos automatizados.
    - Sospechoso: reconocimiento y anomalías a revisar.
    - None: tráfico normal (sin etiqueta de riesgo).

    Args:
        tipo_ataque (str): Categoría devuelta por `clasificar_ataque`.

    Returns:
        str | None: Crítica, Alta, Sospechoso, o None.
    """
    if not tipo_ataque or tipo_ataque == TIPO_TRAFICO_NORMAL:
        return None
    if tipo_ataque in ("SQLi", "Path Traversal", "RCE"):
        return GRAVEDAD_CRITICA
    if tipo_ataque in ("XSS", "Fuerza Bruta", "CSRF", "Scanner Automatizado"):
        return GRAVEDAD_ALTA
    if tipo_ataque == "Reconocimiento":
        return GRAVEDAD_SOSPECHOSO
    return GRAVEDAD_SOSPECHOSO


def es_ataque_grave(tipo_ataque):
    """
    Indica si el ataque requiere atención prioritaria en el monitor.

    Args:
        tipo_ataque (str): Tipo clasificado.

    Returns:
        bool: True para SQLi, XSS, Path Traversal, Fuerza Bruta o CSRF.

    Ejemplos:
        - es_ataque_grave("SQLi") → True
        - es_ataque_grave("Reconocimiento") → False
    """
    return tipo_ataque in {
        "SQLi",
        "XSS",
        "Path Traversal",
        "Fuerza Bruta",
        "CSRF",
        "RCE",
        "Scanner Automatizado",
    }
