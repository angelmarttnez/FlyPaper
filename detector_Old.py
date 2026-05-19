"""
Módulo de detección y clasificación de ataques para FlyPaper.

Este archivo contiene reglas simples basadas en palabras clave/patrones.
El objetivo es clasificar rápidamente eventos del honeypot en categorías
útiles para análisis y visualización.
"""


def clasificar_ataque(ruta, payload, user_agent):
    """
    Clasifica un evento según reglas de prioridad predefinidas.

    Orden de prioridad aplicado (de mayor a menor):
    1) SQLi
    2) XSS
    3) Path Traversal
    4) Reconocimiento
    5) Scanner Automatizado
    6) Otro

    Args:
        ruta (str): Ruta solicitada por el visitante (por ejemplo `/login`).
        payload (str): Datos enviados por formularios/parámetros.
        user_agent (str): Cabecera User-Agent del cliente.

    Returns:
        str: Tipo de ataque detectado.

    Ejemplos:
        - ruta="/login", payload="admin' OR 1=1 --", user_agent="Mozilla/5.0"
          -> "SQLi"
        - ruta="/search", payload="<script>alert(1)</script>", user_agent="Mozilla/5.0"
          -> "XSS"
        - ruta="/../../etc/passwd", payload="", user_agent="curl/8.0"
          -> "Path Traversal" (tiene prioridad sobre scanner)
    """
    # Normalizamos valores para evitar errores con None y facilitar búsquedas.
    ruta_normalizada = (ruta or "").lower()
    payload_normalizado = (payload or "").lower()
    user_agent_normalizado = (user_agent or "").lower()

    # ---------------------------------------------------------------------
    # Regla 1: SQLi (máxima prioridad)
    # ---------------------------------------------------------------------
    patrones_sqli = [
        "select",
        "union",
        "drop",
        "insert",
        "update",
        "delete",
        "or 1=1",
        "--",
        "/*",
        "*/",
        "sleep",
        "exec",
        "xp_",
    ]

    if any(patron in payload_normalizado for patron in patrones_sqli):
        return "SQLi"

    # ---------------------------------------------------------------------
    # Regla 2: XSS
    # ---------------------------------------------------------------------
    patrones_xss = [
        "<script",
        "javascript:",
        "onerror",
        "onload",
        "alert(",
        "document.cookie",
        "eval(",
        "<img src=",
    ]

    if any(patron in payload_normalizado for patron in patrones_xss):
        return "XSS"

    # ---------------------------------------------------------------------
    # Regla 3: Path Traversal
    # ---------------------------------------------------------------------
    patrones_path_traversal = [
        "/../",
        "/etc/passwd",
        "/windows/system",
        "%2e%2e",
    ]

    if any(patron in ruta_normalizada for patron in patrones_path_traversal):
        return "Path Traversal"

    # ---------------------------------------------------------------------
    # Regla 4: Reconocimiento de endpoints sensibles
    # ---------------------------------------------------------------------
    rutas_reconocimiento = {
        "/admin",
        "/backup",
        "/.env",
        "/config",
        "/phpinfo",
        "/wp-admin",
        "/phpmyadmin",
        "/robots.txt",
        "/.git",
    }

    if ruta_normalizada in rutas_reconocimiento:
        return "Reconocimiento"

    # ---------------------------------------------------------------------
    # Regla 5: Scanner automatizado por User-Agent
    # ---------------------------------------------------------------------
    patrones_scanner = [
        "sqlmap",
        "nikto",
        "nmap",
        "masscan",
        "zgrab",
        "python-requests",
        "curl/",
        "wget/",
    ]

    if any(patron in user_agent_normalizado for patron in patrones_scanner):
        return "Scanner Automatizado"

    # ---------------------------------------------------------------------
    # Regla 6: Sin coincidencias
    # ---------------------------------------------------------------------
    return "Otro"


def es_ataque_grave(tipo_ataque):
    """
    Indica si un tipo de ataque se considera grave.

    Se marca como grave cuando es uno de estos:
    - SQLi
    - XSS
    - Path Traversal

    Args:
        tipo_ataque (str): Categoría del ataque a evaluar.

    Returns:
        bool: True si es grave, False en caso contrario.

    Ejemplos:
        - es_ataque_grave("SQLi") -> True
        - es_ataque_grave("Reconocimiento") -> False
    """
    tipos_graves = {"SQLi", "XSS", "Path Traversal"}
    return tipo_ataque in tipos_graves
