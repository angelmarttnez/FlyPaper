"""
detector.py — FlyPaper
Módulo de detección y clasificación de ataques web.
Analiza rutas, payloads y user-agents para identificar el tipo de ataque.
"""

from datetime import datetime, timedelta

# ─────────────────────────────────────────────
# DICCIONARIO PARA DETECTAR FUERZA BRUTA
# Guarda los timestamps de intentos de login por IP
# Ejemplo: {"192.168.1.1": [datetime1, datetime2, ...]}
# ─────────────────────────────────────────────
intentos_login = {}


# ─────────────────────────────────────────────
# PATRONES DE DETECCIÓN
# ─────────────────────────────────────────────

# Patrones SQLi — inyección SQL
# Ejemplo de ataque: "SELECT * FROM usuarios WHERE id=1 OR 1=1--"
PATRONES_SQLI = [
    "select", "union", "drop", "insert", "update", "delete",
    "or 1=1", "--", "/*", "*/", "sleep(", "exec(", "xp_",
    "cast(", "convert(", "char(", "concat(", "group by",
    "having", "order by", "benchmark(", "load_file(",
    "into outfile", "information_schema", "or '1'='1",
    "' or '", "admin'--", "1; drop"
]

# Patrones XSS — Cross Site Scripting
# Ejemplo de ataque: "<script>alert(document.cookie)</script>"
PATRONES_XSS = [
    "<script", "javascript:", "onerror=", "onload=", "alert(",
    "document.cookie", "eval(", "<img src=", "<svg", "<iframe",
    "onfocus=", "onmouseover=", "expression(", "vbscript:",
    "data:text/html", "<body onload", "onclick=", "onsubmit="
]

# Patrones Path Traversal — acceso a archivos del sistema
# Ejemplo de ataque: "../../etc/passwd"
PATRONES_PATH_TRAVERSAL = [
    "/../", "/etc/passwd", "/etc/shadow", "/windows/system32",
    "%2e%2e", "%252e", "../", "..\\", "/proc/self",
    "/var/www", "/root/", "c:\\windows", "boot.ini"
]

# Rutas de reconocimiento — el atacante explora el sistema
# Ejemplo: visitar /.env para buscar credenciales
RUTAS_RECONOCIMIENTO = [
    "/admin", "/backup", "/.env", "/config", "/phpinfo",
    "/wp-admin", "/phpmyadmin", "/robots.txt", "/.git",
    "/.htaccess", "/web.config", "/api/v1", "/swagger",
    "/actuator", "/console", "/.ssh", "/server-status",
    "/elmah.axd", "/trace.axd", "/wp-login.php", "/xmlrpc.php"
]

# User-agents de scanners automáticos
# Ejemplo: sqlmap, nikto, nmap...
SCANNERS_CONOCIDOS = [
    "sqlmap", "nikto", "nmap", "masscan", "zgrab",
    "python-requests", "curl/", "wget/", "dirbuster",
    "gobuster", "wfuzz", "burpsuite", "hydra", "metasploit",
    "acunetix", "nessus", "openvas", "w3af", "skipfish"
]


# ─────────────────────────────────────────────
# FUNCIÓN PRINCIPAL: CLASIFICAR ATAQUE
# ─────────────────────────────────────────────

def clasificar_ataque(ruta, payload, user_agent):
    """
    Clasifica el tipo de ataque basándose en la ruta, payload y user-agent.
    
    Parámetros:
        ruta (str): La URL visitada, ej: "/search"
        payload (str): Lo que escribió en formularios, ej: "SELECT * FROM users"
        user_agent (str): El navegador/herramienta usada
    
    Devuelve:
        str: Tipo de ataque ("SQLi", "XSS", "Path Traversal", 
             "Fuerza Bruta", "CSRF", "Scanner Automatizado", 
             "Reconocimiento", "Otro")
    """
    # Convertir a minúsculas para comparación sin distinción de mayúsculas
    ruta_lower = ruta.lower() if ruta else ""
    payload_lower = payload.lower() if payload else ""
    user_agent_lower = user_agent.lower() if user_agent else ""

    # 1) COMPROBAR SQLi
    for patron in PATRONES_SQLI:
        if patron.lower() in payload_lower:
            return "SQLi"

    # 2) COMPROBAR XSS
    for patron in PATRONES_XSS:
        if patron.lower() in payload_lower:
            return "XSS"

    # 3) COMPROBAR PATH TRAVERSAL
    for patron in PATRONES_PATH_TRAVERSAL:
        if patron.lower() in ruta_lower or patron.lower() in payload_lower:
            return "Path Traversal"

    # 4) COMPROBAR SCANNER AUTOMATIZADO
    for scanner in SCANNERS_CONOCIDOS:
        if scanner.lower() in user_agent_lower:
            return "Scanner Automatizado"

    # 5) COMPROBAR RECONOCIMIENTO (rutas señuelo)
    for ruta_señuelo in RUTAS_RECONOCIMIENTO:
        if ruta_lower.startswith(ruta_señuelo.lower()):
            return "Reconocimiento"

    # 6) Si no encaja en nada conocido
    return "Otro"


# ─────────────────────────────────────────────
# DETECCIÓN DE FUERZA BRUTA
# ─────────────────────────────────────────────

def registrar_intento_login(ip):
    """
    Registra un intento de login para una IP y detecta fuerza bruta.
    
    Parámetros:
        ip (str): La IP del atacante, ej: "192.168.1.1"
    
    Devuelve:
        bool: True si hay fuerza bruta (más de 5 intentos en 1 minuto)
    """
    ahora = datetime.now()
    hace_un_minuto = ahora - timedelta(minutes=1)

    # Inicializar lista de intentos para esta IP si no existe
    if ip not in intentos_login:
        intentos_login[ip] = []

    # Limpiar intentos con más de 1 minuto de antigüedad
    intentos_login[ip] = [
        timestamp for timestamp in intentos_login[ip]
        if timestamp > hace_un_minuto
    ]

    # Añadir el intento actual
    intentos_login[ip].append(ahora)

    # Si hay más de 5 intentos en el último minuto → fuerza bruta
    if len(intentos_login[ip]) > 5:
        return True

    return False


# ─────────────────────────────────────────────
# SISTEMA DE GRAVEDAD
# ─────────────────────────────────────────────

def calcular_gravedad(tipo_ataque):
    """
    Calcula el nivel de gravedad de un ataque.
    
    Parámetros:
        tipo_ataque (str): El tipo de ataque detectado
    
    Devuelve:
        str: Nivel de gravedad ("CRÍTICO", "ALTO", "MEDIO", "BAJO")
    """
    if tipo_ataque in ["SQLi", "Path Traversal"]:
        return "CRÍTICO"
    elif tipo_ataque in ["XSS", "Fuerza Bruta", "CSRF"]:
        return "ALTO"
    elif tipo_ataque in ["Scanner Automatizado"]:
        return "MEDIO"
    else:
        # Reconocimiento y Otro
        return "BAJO"


# ─────────────────────────────────────────────
# COMPROBAR SI ES ATAQUE GRAVE
# ─────────────────────────────────────────────

def es_ataque_grave(tipo_ataque):
    """
    Comprueba si un ataque es grave y requiere atención inmediata.
    
    Parámetros:
        tipo_ataque (str): El tipo de ataque detectado
    
    Devuelve:
        bool: True si el ataque es grave
    """
    ataques_graves = ["SQLi", "XSS", "Path Traversal", "Fuerza Bruta", "CSRF"]
    return tipo_ataque in ataques_graves