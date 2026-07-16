"""
Módulo de detección WAF/IDS para FlyPaper (Blue Team).

Motor de detección orientado al OWASP Top 10:
- Capa anti-evasión (URL decode recursivo, comentarios SQL, case-folding).
- Firmas modulares: SQLi, XSS, Path Traversal/LFI, RCE, SSRF/RFI,
  rutas prohibidas / web shells y fingerprinting de scanners.
- Salida estructurada para persistencia SOC y dashboard.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta
from typing import Any, Optional
from urllib.parse import unquote_plus

# ---------------------------------------------------------------------------
# Constantes de clasificación (integración SOC / BD)
# ---------------------------------------------------------------------------

# Timestamps de intentos POST /login por IP: {"203.0.113.1": [datetime, ...]}
intentos_login: dict[str, list[datetime]] = {}

# Compatibilidad histórica con BD y dashboard («Tráfico Normal»).
TIPO_TRAFICO_NORMAL = "Tráfico Normal"
TIPO_NORMAL_ALIAS = "Normal"

TIPO_SQLI = "SQLi"
TIPO_XSS = "XSS"
TIPO_PATH_TRAVERSAL = "Path Traversal"
TIPO_RCE = "RCE"
TIPO_SSRF_RFI = "SSRF/RFI"
TIPO_SCANNER = "Scanner Automatizado"
TIPO_RUTA_PROHIBIDA = "Ruta Prohibida"
TIPO_FUERZA_BRUTA = "Fuerza Bruta"
TIPO_CSRF = "CSRF"
# Alias legacy (filas antiguas en BD / filtros UI).
TIPO_RECONOCIMIENTO = "Reconocimiento"

GRAVEDAD_CRITICA = "Crítica"
GRAVEDAD_ALTA = "Alta"
GRAVEDAD_SOSPECHOSO = "Sospechoso"
GRAVEDAD_NORMAL = "Normal"
GRAVEDADES_MONITOR = (GRAVEDAD_CRITICA, GRAVEDAD_ALTA, GRAVEDAD_SOSPECHOSO)

# Decodificación URL: mínimo 2 pasadas (requisito), tope anti-bucle.
_MIN_DECODIFICACIONES_URL = 2
_MAX_DECODIFICACIONES_URL = 6
_MAX_LONGITUD_ANALISIS = 65536

_PATRON_RUTA_BLOG_POST = re.compile(r"^/blog/\d+$")
_PATRON_QUERY_SEARCH_LIMPIA = re.compile(
    r"^[a-zA-Z0-9\s\-_.áéíóúñüÁÉÍÓÚÑÜ]*$"
)
_PATRON_RUTA_SECURE_BLOG_POST = re.compile(r"^/secure/blog/\d+$")
_PATRON_RUTA_SECURE_BLOG_COMENTAR = re.compile(r"^/secure/blog/\d+/comentar$")

# Comentarios SQL usados para evadir WAF.
_PATRON_COMENTARIO_SQL_BLOCK = re.compile(r"/\*.*?\*/", re.DOTALL)
_PATRON_COMENTARIO_SQL_LINEA = re.compile(r"(--|#)[^\n]*")
_PATRON_COMENTARIO_SQL_VACIO = re.compile(r"/\*+\*/")

# ---------------------------------------------------------------------------
# Firmas SQLi
# ---------------------------------------------------------------------------
_REGLAS_SQLI: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"\bunion\b.{0,120}?\bselect\b"),
        "Detectado UNION SELECT (SQLi estructurada)",
    ),
    (
        re.compile(r"\bselect\b.{0,80}?\bfrom\b"),
        "Detectado SELECT ... FROM (SQLi)",
    ),
    (
        re.compile(r"\b(or|and)\b\s+[\d'\"]+\s*=\s*[\d'\"]+"),
        "Detectado operador booleano OR/AND N=N (SQLi)",
    ),
    (
        re.compile(r"'\s*(or|and)\b"),
        "Detectado cierre de comillas con OR/AND (SQLi)",
    ),
    (
        re.compile(r"\bor\s+1\s*=\s*1\b"),
        "Detectado OR 1=1 (SQLi booleana)",
    ),
    (
        re.compile(r"\band\s+2\s*=\s*2\b"),
        "Detectado AND 2=2 (SQLi booleana)",
    ),
    (
        re.compile(r"\band\s+1\s*=\s*1\b"),
        "Detectado AND 1=1 (SQLi booleana)",
    ),
    (
        re.compile(r"\bsleep\s*\("),
        "Detectado uso de función temporal SLEEP en SQLi",
    ),
    (
        re.compile(r"\bbenchmark\s*\("),
        "Detectado BENCHMARK() time-based (SQLi)",
    ),
    (
        re.compile(r"\bwaitfor\s+delay\b"),
        "Detectado WAITFOR DELAY (SQLi MSSQL)",
    ),
    (
        re.compile(r"\bpg_sleep\s*\("),
        "Detectado pg_sleep() time-based (SQLi)",
    ),
    (
        re.compile(r"\binformation_schema\b"),
        "Detectado acceso a information_schema (SQLi)",
    ),
    (
        re.compile(r"\bload_file\s*\("),
        "Detectado LOAD_FILE() (SQLi)",
    ),
    (
        re.compile(r"\binto\s+(out|dump)file\b"),
        "Detectado INTO OUTFILE/DUMPFILE (SQLi)",
    ),
    (
        re.compile(r"\binsert\s+into\b"),
        "Detectado INSERT INTO (SQLi)",
    ),
    (
        re.compile(r"\bdrop\s+(table|database)\b"),
        "Detectado DROP TABLE/DATABASE (SQLi)",
    ),
    (
        re.compile(r"\bupdate\s+\w+\s+set\b"),
        "Detectado UPDATE SET (SQLi)",
    ),
    (
        re.compile(r"\bdelete\s+from\b"),
        "Detectado DELETE FROM (SQLi)",
    ),
    (
        re.compile(r";\s*(drop|delete|update|insert)\b"),
        "Detectado stacked query SQL",
    ),
    (
        re.compile(r"\bxp_cmdshell\b"),
        "Detectado xp_cmdshell (SQLi RCE)",
    ),
]

# Firmas de corte por comentario (aplican sobre texto SIN eliminar `--`/`#`).
_REGLAS_SQLI_COMENTARIO: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"'\s*;\s*--"), "Detectado terminador SQL con comentario --"),
    (re.compile(r"'\s*--"), "Detectado comilla + comentario SQL --"),
    (re.compile(r"'\s*/\*"), "Detectado comilla + comentario SQL /*"),
    (re.compile(r"'\s*#"), "Detectado comilla + comentario SQL #"),
]

# ---------------------------------------------------------------------------
# Firmas XSS
# ---------------------------------------------------------------------------
_REGLAS_XSS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"<\s*script\b"), "Detectado tag <script> (XSS)"),
    (re.compile(r"<\s*iframe\b"), "Detectado tag <iframe> (XSS)"),
    (re.compile(r"<\s*svg\b"), "Detectado vector SVG (XSS)"),
    (re.compile(r"<\s*embed\b"), "Detectado tag <embed> (XSS)"),
    (re.compile(r"<\s*object\b"), "Detectado tag <object> (XSS)"),
    (re.compile(r"<\s*math\b"), "Detectado vector MathML (XSS)"),
    (re.compile(r"javascript\s*:"), "Detectado esquema javascript: (XSS)"),
    (re.compile(r"vbscript\s*:"), "Detectado esquema vbscript: (XSS)"),
    (re.compile(r"data\s*:\s*text/html"), "Detectado data:text/html (XSS)"),
    (
        re.compile(r"\bon(load|error|mouseover|click|focus|toggle|submit|input)\s*="),
        "Detectado manejador de evento HTML (XSS)",
    ),
    (
        re.compile(r"<\s*img\b[^>]{0,200}?\bon\w+\s*="),
        "Detectado <img> con event handler (XSS)",
    ),
    (re.compile(r"\bdocument\s*\.\s*cookie\b"), "Detectado document.cookie (XSS)"),
    (re.compile(r"\beval\s*\("), "Detectado eval() (XSS)"),
]

# ---------------------------------------------------------------------------
# Path Traversal / LFI
# ---------------------------------------------------------------------------
_REGLAS_PATH_TRAVERSAL: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\.\./"), "Detectado traversal ../ (LFI)"),
    (re.compile(r"\.\.\\"), "Detectado traversal ..\\ (LFI Windows)"),
    (re.compile(r"\.\.%2f"), "Detectado traversal ..%2f codificado"),
    (re.compile(r"\.\.%5c"), "Detectado traversal ..%5c codificado"),
    (re.compile(r"\.{2,}/+"), "Detectado evasión ....// (LFI)"),
    (re.compile(r"\.{2,}\\+"), "Detectado evasión ....\\\\ (LFI)"),
    (re.compile(r"%2e%2e(%2f|/)"), "Detectado double-encoding %2e%2e (LFI)"),
    (re.compile(r"%252e%252e"), "Detectado triple-encoding de .. (LFI)"),
    (re.compile(r"/etc/passwd\b"), "Detectado acceso a /etc/passwd"),
    (re.compile(r"/etc/shadow\b"), "Detectado acceso a /etc/shadow"),
    (re.compile(r"/etc/hosts\b"), "Detectado acceso a /etc/hosts"),
    (re.compile(r"(?:^|[\\/])boot\.ini\b"), "Detectado acceso a boot.ini"),
    (re.compile(r"(?:^|[\\/])win\.ini\b"), "Detectado acceso a win.ini"),
    (re.compile(r"/proc/self/"), "Detectado acceso a /proc/self"),
    (re.compile(r"/windows/system32"), "Detectado acceso a system32"),
    (re.compile(r"(%00|\\x00|\x00)"), "Detectado null byte en path (LFI)"),
]

_PATRONES_SECURE_EXTENSION_REGEX = (
    re.compile(r"\.php$", re.IGNORECASE),
    re.compile(r"\.sql$", re.IGNORECASE),
    re.compile(r"\.bak$", re.IGNORECASE),
    re.compile(r"\.conf$", re.IGNORECASE),
    re.compile(r"%00", re.IGNORECASE),
    re.compile(r"\\x00", re.IGNORECASE),
)

# ---------------------------------------------------------------------------
# RCE / Command Injection
# ---------------------------------------------------------------------------
_BINARIOS_RCE = (
    r"whoami|id|uname|cat|wget|curl|powershell|cmd\.exe|"
    r"/bin/sh|/bin/bash|bash|sh|nc\b|netcat|python\s+-c|perl\s+-e|php\s+-r"
)
_REGLAS_RCE: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(rf"(;|\|\||&&)\s*({_BINARIOS_RCE})\b"),
        "Detectado encadenamiento de comandos + binario (RCE)",
    ),
    (
        re.compile(rf"`\s*({_BINARIOS_RCE})\b"),
        "Detectado ejecución con backticks (RCE)",
    ),
    (
        re.compile(rf"\$\(\s*({_BINARIOS_RCE})\b"),
        "Detectado command substitution $() (RCE)",
    ),
    (
        re.compile(r"\bpowershell\s+(-|/)"),
        "Detectado invocación PowerShell (RCE)",
    ),
    (
        re.compile(r"\bcmd\.exe\s+/c\b"),
        "Detectado cmd.exe /c (RCE)",
    ),
    (
        re.compile(r"\|\s*(sh|bash)\b"),
        "Detectado pipe hacia shell (RCE)",
    ),
]

# ---------------------------------------------------------------------------
# SSRF / RFI
# ---------------------------------------------------------------------------
_REGLAS_SSRF_RFI: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"\b(gopher|file|dict|ldap|tftp|jar)://"),
        "Detectado esquema SSRF inusual (gopher/file/dict/...)",
    ),
    (
        re.compile(r"(localhost|127\.0\.0\.1|0\.0\.0\.0|::1)(:\d+)?(/|\s|$|\")"),
        "Detectado apuntado a localhost/loopback (SSRF)",
    ),
    (
        re.compile(r"169\.254\.169\.254"),
        "Detectado metadata cloud 169.254.169.254 (SSRF)",
    ),
    (
        re.compile(r"https?://10\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
        "Detectado URL a red 10.0.0.0/8 (SSRF)",
    ),
    (
        re.compile(r"https?://192\.168\.\d{1,3}\.\d{1,3}"),
        "Detectado URL a red 192.168.0.0/16 (SSRF)",
    ),
    (
        re.compile(r"https?://172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}"),
        "Detectado URL a red 172.16.0.0/12 (SSRF)",
    ),
    (
        re.compile(
            r"(^|[?&\"'=])(url|uri|path|src|dest|redirect|next|data|host|portal|"
            r"file|page|include|doc|folder|root|pg|style|pdf|template|php_path|"
            r"feed|fetch|proxy|continue|return|callback)\s*[:=]\s*https?://"
        ),
        "Detectado parámetro con URL externa (RFI/SSRF)",
    ),
    (
        re.compile(r"(include|require)(_once)?\s*\(\s*['\"]https?://"),
        "Detectado include/require remoto (RFI)",
    ),
]

# ---------------------------------------------------------------------------
# Scanners (UA + cabeceras) → Crítica
# ---------------------------------------------------------------------------
_SCANNER_PATRONES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bsqlmap\b"), "Fingerprinting scanner: sqlmap"),
    (re.compile(r"\bnikto\b"), "Fingerprinting scanner: nikto"),
    (re.compile(r"\bnmap\b"), "Fingerprinting scanner: nmap"),
    (re.compile(r"\bnuclei\b"), "Fingerprinting scanner: nuclei"),
    (re.compile(r"\bgobuster\b"), "Fingerprinting scanner: gobuster"),
    (re.compile(r"\bdirbuster\b"), "Fingerprinting scanner: dirbuster"),
    (re.compile(r"\bdirb\b"), "Fingerprinting scanner: dirb"),
    (re.compile(r"\bwfuzz\b"), "Fingerprinting scanner: wfuzz"),
    (re.compile(r"\bacunetix\b"), "Fingerprinting scanner: acunetix"),
    (re.compile(r"\bhydra\b"), "Fingerprinting scanner: hydra"),
    (re.compile(r"\bnessus\b"), "Fingerprinting scanner: nessus"),
    (re.compile(r"\bopenvas\b"), "Fingerprinting scanner: openvas"),
    (re.compile(r"\bmetasploit\b"), "Fingerprinting scanner: metasploit"),
    (re.compile(r"\bburpsuite\b"), "Fingerprinting scanner: burpsuite"),
    (re.compile(r"\bferoxbuster\b"), "Fingerprinting scanner: feroxbuster"),
    (re.compile(r"\bmasscan\b"), "Fingerprinting scanner: masscan"),
    (re.compile(r"\bzgrab\b"), "Fingerprinting scanner: zgrab"),
    (re.compile(r"python-requests/"), "Fingerprinting scanner: python-requests"),
    (re.compile(r"\bx-sqlmap"), "Fingerprinting cabecera X-Sqlmap"),
]

# ---------------------------------------------------------------------------
# Rutas prohibidas / web shells / recon probing
# ---------------------------------------------------------------------------
RUTAS_PROHIBIDAS: list[tuple[str, str]] = [
    ("/shell.php", "Sondeo web shell: /shell.php"),
    ("/cmd.php", "Sondeo web shell: /cmd.php"),
    ("/c99.php", "Sondeo web shell: /c99.php"),
    ("/r57.php", "Sondeo web shell: /r57.php"),
    ("/wp-admin", "Sondeo recon: /wp-admin"),
    ("/wp-login.php", "Sondeo recon: /wp-login.php"),
    ("/.git/head", "Sondeo exposición: /.git/HEAD"),
    ("/.git", "Sondeo exposición: /.git"),
    ("/.env", "Sondeo exposición: /.env"),
    ("/config.bak", "Sondeo backup: /config.bak"),
    ("/phpinfo", "Sondeo recon: /phpinfo"),
    ("/phpmyadmin", "Sondeo recon: /phpmyadmin"),
    ("/backup", "Sondeo recon: /backup"),
    ("/.htaccess", "Sondeo exposición: /.htaccess"),
    ("/.ssh", "Sondeo exposición: /.ssh"),
    ("/web.config", "Sondeo exposición: /web.config"),
    ("/actuator", "Sondeo recon: /actuator"),
    ("/swagger", "Sondeo recon: /swagger"),
    ("/console", "Sondeo recon: /console"),
    ("/robots.txt", "Sondeo recon: /robots.txt"),
]

# Alias público legacy (usado por código/docs antiguos).
RUTAS_RECONOCIMIENTO = [ruta for ruta, _ in RUTAS_PROHIBIDAS]

_MAPA_GRAVEDAD_LEGACY = {
    "CRÍTICO": GRAVEDAD_CRITICA,
    "CRITICO": GRAVEDAD_CRITICA,
    "ALTO": GRAVEDAD_ALTA,
    "MEDIO": GRAVEDAD_SOSPECHOSO,
    "BAJO": GRAVEDAD_SOSPECHOSO,
}


# ===========================================================================
# Normalización anti-evasión
# ===========================================================================


def _truncar_texto(texto: str) -> str:
    """Limita longitud para evitar DoS por regex/memoria."""
    if len(texto) <= _MAX_LONGITUD_ANALISIS:
        return texto
    return texto[:_MAX_LONGITUD_ANALISIS]


def _a_texto(valor: Any) -> str:
    """Serializa dict/list a JSON; el resto a str."""
    if valor is None:
        return ""
    if isinstance(valor, dict):
        try:
            return json.dumps(valor, ensure_ascii=False)
        except (TypeError, ValueError):
            return str(valor)
    if isinstance(valor, (list, tuple)):
        try:
            return json.dumps(list(valor), ensure_ascii=False)
        except (TypeError, ValueError):
            return str(valor)
    return str(valor)


def _decodificar_url_recursivo(
    cadena: str, max_decodificaciones: int = _MAX_DECODIFICACIONES_URL
) -> str:
    """
    Decodifica URL Encoding de forma recursiva (mínimo 2 pasadas).

    Ejemplo: ``%2527`` → ``%27`` → ``'``.
    """
    tope = max(_MIN_DECODIFICACIONES_URL, max_decodificaciones)
    anterior = cadena.replace("+", " ")
    for _ in range(tope):
        try:
            actual = unquote_plus(anterior, errors="replace")
        except (TypeError, ValueError):
            break
        if actual == anterior:
            # Garantiza al menos 2 intentos aunque no cambie (idempotente).
            if _ == 0:
                continue
            break
        anterior = actual
    return anterior


def normalizar_input_evasion(
    texto: Any, max_decodificaciones: int = _MAX_DECODIFICACIONES_URL
) -> str:
    """
    Pre-procesamiento anti-evasión antes de aplicar firmas WAF.

    1. Decodificación URL recursiva (≥2 pasadas).
    2. Eliminación de comentarios SQL de bloque (``/**/``) — se borran del
       texto (no se sustituyen por espacio). Esto es un fallo pedagógico /
       realista: ``UNION/**/SELECT`` queda como ``unionselect`` y no dispara
       la firma ``\\bunion\\b...\\bselect\\b``.
    3. Comentarios de línea ``--`` / ``#`` → espacio.
    4. Colapso de espacios en blanco.
    5. Conversión a minúsculas.
    """
    cadena = _decodificar_url_recursivo(_a_texto(texto), max_decodificaciones)
    resultado = cadena.lower()
    # Fallo deliberado (CTF + realismo): strip de bloque sin insertar espacio.
    resultado = _PATRON_COMENTARIO_SQL_BLOCK.sub("", resultado)
    resultado = _PATRON_COMENTARIO_SQL_LINEA.sub(" ", resultado)
    resultado = _PATRON_COMENTARIO_SQL_VACIO.sub("", resultado)
    resultado = re.sub(r"\s+", " ", resultado).strip()
    return _truncar_texto(resultado)


def _normalizar_sin_strip_comentarios_linea(texto: Any) -> str:
    """
    Variante para firmas de corte ``--`` / ``#``.

    Solo decodifica, lower y colapsa espacios; conserva ``--`` y ``#``.
    Los comentarios de bloque se eliminan (misma política que normalizar_input_evasion).
    """
    cadena = _decodificar_url_recursivo(_a_texto(texto)).lower()
    cadena = _PATRON_COMENTARIO_SQL_BLOCK.sub("", cadena)
    cadena = _PATRON_COMENTARIO_SQL_VACIO.sub("", cadena)
    cadena = re.sub(r"\s+", " ", cadena).strip()
    return _truncar_texto(cadena)


# ===========================================================================
# Utilidades de matching
# ===========================================================================


def _normalizar_headers(headers: Any) -> dict[str, str]:
    """Convierte cabeceras HTTP a dict con claves en minúsculas."""
    if not headers:
        return {}
    if hasattr(headers, "items"):
        return {str(k).lower(): str(v) for k, v in headers.items()}
    try:
        return {str(k).lower(): str(v) for k, v in dict(headers).items()}
    except (TypeError, ValueError):
        return {}


def _texto_cabeceras_para_analisis(headers: Any) -> str:
    """Concatena cabeceras para fingerprinting de scanners."""
    cabeceras = _normalizar_headers(headers)
    partes = [f"{clave}: {valor}" for clave, valor in cabeceras.items()]
    return normalizar_input_evasion(" ".join(partes))


def _normalizar_ruta_clasificacion(ruta: Optional[str]) -> str:
    """Ruta en minúsculas, sin query string, sin slash final (salvo `/`)."""
    return (ruta or "").lower().split("?")[0].rstrip("/") or "/"


def _buscar_primera_regla(
    texto: str, reglas: list[tuple[re.Pattern[str], str]]
) -> Optional[str]:
    """Devuelve la descripción de la primera firma que coincide."""
    if not texto:
        return None
    for patron, descripcion in reglas:
        if patron.search(texto):
            return descripcion
    return None


def _detectar_scanner(user_agent: str, headers: Any) -> Optional[str]:
    """Fingerprinting de herramientas automatizadas en UA y cabeceras."""
    ua_norm = normalizar_input_evasion(user_agent or "")
    firma = _buscar_primera_regla(ua_norm, _SCANNER_PATRONES)
    if firma:
        return firma
    return _buscar_primera_regla(
        _texto_cabeceras_para_analisis(headers), _SCANNER_PATRONES
    )


def _detectar_path_traversal(texto_norm: str, ruta: Optional[str]) -> Optional[str]:
    """Path traversal / LFI en payload y ruta (refuerzo en /secure/*)."""
    ruta_cls = _normalizar_ruta_clasificacion(ruta)
    # Texto bruto también: patrones %2e pueden vivir pre-decode residuales.
    texto_completo = f"{normalizar_input_evasion(ruta or '')} {texto_norm}".strip()
    bruto = f"{(ruta or '').lower()} {_a_texto(ruta)} {texto_norm}".lower()

    firma = _buscar_primera_regla(texto_completo, _REGLAS_PATH_TRAVERSAL)
    if firma:
        return firma
    firma = _buscar_primera_regla(bruto, _REGLAS_PATH_TRAVERSAL)
    if firma:
        return firma

    if ruta_cls.startswith("/secure/"):
        for candidato in (ruta_cls, texto_completo):
            for patron in _PATRONES_SECURE_EXTENSION_REGEX:
                if patron.search(candidato):
                    return "Detectada extensión sensible en zona /secure/ (LFI)"
    return None


def _detectar_ruta_prohibida(ruta: Optional[str]) -> Optional[str]:
    """Web shells y sondeo de recon sobre rutas trampa."""
    ruta_cls = _normalizar_ruta_clasificacion(ruta)
    for ruta_senal, firma in RUTAS_PROHIBIDAS:
        senal = ruta_senal.lower().rstrip("/") or "/"
        if ruta_cls == senal or ruta_cls.startswith(senal + "/"):
            return firma
    return None


def _detectar_csrf(headers: Any, metodo: Optional[str]) -> bool:
    """Heurística básica CSRF: POST sin Referer coherente con Host."""
    if (metodo or "").upper() != "POST":
        return False
    cabeceras = _normalizar_headers(headers)
    referer = cabeceras.get("referer", "").strip()
    host = cabeceras.get("host", "").strip()
    if not referer:
        return True
    if host:
        host_lower = host.lower().split(":")[0]
        if host_lower not in referer.lower():
            return True
    return False


def _contiene_patrones_ataque(texto_norm: str, ruta: Optional[str]) -> bool:
    """True si el texto normalizado activa alguna firma de payload."""
    if not texto_norm.strip():
        return False
    if _buscar_primera_regla(texto_norm, _REGLAS_SQLI):
        return True
    if _buscar_primera_regla(
        _normalizar_sin_strip_comentarios_linea(texto_norm), _REGLAS_SQLI_COMENTARIO
    ):
        return True
    if _buscar_primera_regla(texto_norm, _REGLAS_XSS):
        return True
    if _buscar_primera_regla(texto_norm, _REGLAS_RCE):
        return True
    if _buscar_primera_regla(texto_norm, _REGLAS_SSRF_RFI):
        return True
    if _detectar_path_traversal(texto_norm, ruta):
        return True
    return False


def _post_login_credenciales_simples(payload_norm: str) -> bool:
    """Login POST sin indicios de inyección en credenciales."""
    indicadores = (
        "'",
        '"',
        "union",
        "select",
        "../",
        "..\\",
        "%2e%2e",
        "--",
        "/*",
        "<script",
        "<img",
        "javascript:",
        "onerror=",
        "sleep(",
        "or 1=1",
        "gopher://",
        "file://",
    )
    return not any(x in payload_norm for x in indicadores)


def _extraer_query_search(ruta: Optional[str], payload_norm: str) -> str:
    if "?" in (ruta or ""):
        for parte in (ruta or "").split("?", 1)[1].split("&"):
            if parte.lower().startswith("query="):
                return unquote_plus(parte.split("=", 1)[1], errors="replace")
    coincidencia = re.search(
        r'["\']?query["\']?\s*[:=]\s*["\']?([^&"\'}\]]+)',
        payload_norm,
        re.IGNORECASE,
    )
    if coincidencia:
        return unquote_plus(coincidencia.group(1).strip(), errors="replace")
    return ""


def _search_get_query_es_limpia(ruta: Optional[str], payload_norm: str) -> bool:
    query = _extraer_query_search(ruta, payload_norm).strip()
    if not query:
        return True
    return bool(_PATRON_QUERY_SEARCH_LIMPIA.match(query))


def _ruta_academia_sqli_exenta_waf(ruta_norm: str) -> bool:
    """
    Labs SQLi 01–03: WAF perimetral no interfiere (telemetría educativa sí).

    Lab 04 (WAF Evasion): NUNCA exento — firmas y riesgo Redis aplican al 100%.
    """
    if not ruta_norm.startswith("/objetivos/sqli"):
        return False
    partes = [p for p in ruta_norm.split("/") if p]
    # ['objetivos', 'sqli', '<id|lab|verify>', ...]
    if len(partes) < 3:
        return True
    segmento = partes[2]
    # /objetivos/sqli/4/...  ó  /objetivos/sqli/04/...
    if segmento in ("4", "04"):
        return False
    # /objetivos/sqli/verify/4 — el verify no es el lab ofensivo; queda exento.
    return True


def _es_trafico_legitimo_prioritario(
    ruta: Optional[str], payload: Any, metodo: Optional[str]
) -> bool:
    """
    Primera pasada: interacción esperada del honeypot sin firmas maliciosas.

    Evita falsos positivos en rutas públicas normales (login, blog, static).
    """
    payload_norm = normalizar_input_evasion(_a_texto(payload))
    ruta_norm = _normalizar_ruta_clasificacion(ruta)
    texto_completo = normalizar_input_evasion(f"{ruta or ''} {_a_texto(payload)}")

    # Academia CTF SQLi 01–03: labs deliberadamente vulnerables — WAF no interfiere.
    # Reto 04 queda fuera a propósito (entrenamiento anti-WAF + riesgo Redis).
    if _ruta_academia_sqli_exenta_waf(ruta_norm):
        return True

    if _contiene_patrones_ataque(texto_completo, ruta):
        return False
    if _detectar_ruta_prohibida(ruta):
        # /admin del SOC se trata más abajo como legítimo GET.
        if not (
            ruta_norm.startswith("/admin")
            and (metodo or "GET").upper() == "GET"
        ):
            return False

    metodo_up = (metodo or "GET").upper()

    if metodo_up in ("OPTIONS", "HEAD"):
        return True
    if ruta_norm.startswith("/static/") or ruta_norm.startswith("/assets/"):
        return True
    if ruta_norm == "/login" and metodo_up == "GET":
        return True
    if ruta_norm == "/login" and metodo_up == "POST":
        return _post_login_credenciales_simples(payload_norm)
    if ruta_norm == "/logout" and metodo_up == "GET":
        return True
    if ruta_norm == "/" and metodo_up == "GET":
        return True
    if ruta_norm == "/blog" and metodo_up == "GET":
        return True
    if metodo_up == "GET" and _PATRON_RUTA_BLOG_POST.match(ruta_norm):
        return True
    if ruta_norm == "/search" and metodo_up == "GET":
        return _search_get_query_es_limpia(ruta, payload_norm)
    # Panel SOC real: no marcar como ruta prohibida en GET autenticado.
    if ruta_norm.startswith("/admin") and metodo_up == "GET":
        return True
    if ruta_norm == "/secure/search" and metodo_up == "GET":
        return True
    if ruta_norm == "/secure/blog" and metodo_up == "GET":
        return True
    if metodo_up == "GET" and _PATRON_RUTA_SECURE_BLOG_POST.match(ruta_norm):
        return True
    if ruta_norm == "/secure/search" and metodo_up == "POST":
        return not _contiene_patrones_ataque(payload_norm, ruta)
    if metodo_up == "POST" and _PATRON_RUTA_SECURE_BLOG_COMENTAR.match(ruta_norm):
        return not _contiene_patrones_ataque(payload_norm, ruta)
    return False


# ===========================================================================
# Construcción de resultados
# ===========================================================================


def _resultado_sin_ataque(usar_alias_normal: bool = False) -> dict[str, Any]:
    """Veredicto limpio (sin amenaza)."""
    return {
        "ataque_detectado": False,
        "tipo_ataque": TIPO_NORMAL_ALIAS if usar_alias_normal else TIPO_TRAFICO_NORMAL,
        "gravedad": GRAVEDAD_NORMAL,
        "firma_coincidente": "",
    }


def _resultado_con_ataque(
    tipo: str, firma: str, gravedad: Optional[str] = None
) -> dict[str, Any]:
    """Veredicto positivo con tipo, severidad y firma WAF."""
    gravedad_final = gravedad or calcular_gravedad(tipo)
    return {
        "ataque_detectado": True,
        "tipo_ataque": tipo,
        "gravedad": gravedad_final or GRAVEDAD_SOSPECHOSO,
        "firma_coincidente": firma,
    }


def _analizar_campos_core(
    ruta: Optional[str],
    payload: Any,
    user_agent: Optional[str],
    headers: Any = None,
    metodo: Optional[str] = None,
    *,
    usar_alias_normal: bool = False,
    modo_educativo: bool = False,
) -> dict[str, Any]:
    """
    Núcleo de análisis WAF (ruta + payload + UA + cabeceras).

    Orden de prioridad (mayor a menor impacto operativo):
    1) Tráfico legítimo conocido (omitido si ``modo_educativo``)
    2) Scanner Automatizado → Crítica
    3) SQLi → Crítica
    4) RCE → Crítica
    5) SSRF/RFI → Crítica
    6) Path Traversal → Crítica
    7) XSS → Alta
    8) Ruta Prohibida → Sospechoso
    9) CSRF → Alta

    ``modo_educativo``: fuerza el matching de firmas aunque la ruta esté
    en whitelist (p. ej. labs CTF). No bloquea tráfico; solo informa.
    """
    payload_bruto = _a_texto(payload)
    payload_norm = normalizar_input_evasion(payload_bruto)

    if not modo_educativo and _es_trafico_legitimo_prioritario(ruta, payload, metodo):
        resultado = _resultado_sin_ataque(usar_alias_normal=usar_alias_normal)
        resultado["payload_normalizado"] = payload_norm
        return resultado

    ruta_norm = normalizar_input_evasion(ruta or "")
    texto_analisis = f"{ruta_norm} {payload_norm}".strip()
    texto_comentarios = _normalizar_sin_strip_comentarios_linea(
        f"{ruta or ''} {payload_bruto}"
    )

    def _con_norm(resultado: dict[str, Any]) -> dict[str, Any]:
        resultado["payload_normalizado"] = payload_norm
        return resultado

    firma_scanner = _detectar_scanner(user_agent or "", headers)
    if firma_scanner:
        return _con_norm(
            _resultado_con_ataque(TIPO_SCANNER, firma_scanner, GRAVEDAD_CRITICA)
        )

    firma = _buscar_primera_regla(texto_analisis, _REGLAS_SQLI)
    if firma:
        return _con_norm(_resultado_con_ataque(TIPO_SQLI, firma))
    firma = _buscar_primera_regla(texto_comentarios, _REGLAS_SQLI_COMENTARIO)
    if firma:
        return _con_norm(_resultado_con_ataque(TIPO_SQLI, firma))

    firma = _buscar_primera_regla(texto_analisis, _REGLAS_RCE)
    if firma:
        return _con_norm(_resultado_con_ataque(TIPO_RCE, firma))

    firma = _buscar_primera_regla(texto_analisis, _REGLAS_SSRF_RFI)
    if firma:
        return _con_norm(_resultado_con_ataque(TIPO_SSRF_RFI, firma))

    firma = _detectar_path_traversal(texto_analisis, ruta)
    if firma:
        return _con_norm(_resultado_con_ataque(TIPO_PATH_TRAVERSAL, firma))

    firma = _buscar_primera_regla(texto_analisis, _REGLAS_XSS)
    if firma:
        return _con_norm(_resultado_con_ataque(TIPO_XSS, firma))

    # En modo educativo no clasificamos CSRF ni rutas prohibidas del lab:
    # el alumno prueba payloads, no sondeo de recon.
    # Lab 04: tampoco CSRF (el foco es evasión SQLi; AJAX sin Referer no debe ensuciar).
    if not modo_educativo:
        firma = _detectar_ruta_prohibida(ruta)
        if firma:
            return _con_norm(_resultado_con_ataque(TIPO_RUTA_PROHIBIDA, firma))

        ruta_cls = _normalizar_ruta_clasificacion(ruta)
        if not ruta_cls.startswith("/objetivos/sqli/4") and _detectar_csrf(
            headers, metodo
        ):
            return _con_norm(
                _resultado_con_ataque(
                    TIPO_CSRF, "Detectado POST sin Referer coherente (CSRF)"
                )
            )

    return _con_norm(_resultado_sin_ataque(usar_alias_normal=usar_alias_normal))


# ===========================================================================
# API pública
# ===========================================================================


def analizar_peticion(
    ruta: Optional[str],
    payload: Any,
    user_agent: Optional[str],
    headers: Any = None,
    metodo: Optional[str] = None,
    *,
    modo_educativo: bool = False,
) -> dict[str, Any]:
    """
    Análisis WAF con parámetros explícitos (integración `app.py` / BD / CTF).

    Args:
        modo_educativo: Si True, ignora whitelist de rutas CTF y aplica firmas
            sobre el payload (telemetría académica; no bloquea).

    Returns:
        dict: ataque_detectado, tipo_ataque, gravedad, firma_coincidente,
        payload_normalizado.
        ``tipo_ataque`` usa «Tráfico Normal» cuando no hay amenaza (compat BD).
    """
    return _analizar_campos_core(
        ruta=ruta,
        payload=payload,
        user_agent=user_agent,
        headers=headers,
        metodo=metodo,
        usar_alias_normal=False,
        modo_educativo=modo_educativo,
    )


def evaluar_peticion(request: Any) -> dict[str, Any]:
    """
    Interfaz centralizada sobre un objeto request estilo Flask.

    Inspecciona: ``request.args``, ``request.form``, ``request.path``
    y ``request.headers`` (incluye User-Agent).

    Returns:
        dict con claves exactas:
        - ataque_detectado (bool)
        - tipo_ataque (SQLi | XSS | Path Traversal | RCE | SSRF/RFI |
          Scanner Automatizado | Ruta Prohibida | Normal)
        - gravedad (Crítica | Alta | Sospechoso | Normal)
        - firma_coincidente (str)
    """
    try:
        args = dict(getattr(request, "args", {}) or {})
    except (TypeError, ValueError):
        args = {}
    try:
        form = dict(getattr(request, "form", {}) or {})
    except (TypeError, ValueError):
        form = {}

    payload = {"args": args, "form": form}
    if not args and not form:
        # Fallback: query string cruda / cuerpo si está expuesto.
        qs = getattr(request, "query_string", b"") or b""
        if isinstance(qs, (bytes, bytearray)):
            qs = qs.decode("utf-8", errors="ignore")
        payload = {"query_string": qs}

    ruta = getattr(request, "path", None) or ""
    metodo = getattr(request, "method", None) or "GET"
    headers = getattr(request, "headers", None)
    user_agent = ""
    if headers is not None:
        try:
            user_agent = headers.get("User-Agent", "") or headers.get(
                "user-agent", ""
            )
        except Exception:
            user_agent = ""

    return _analizar_campos_core(
        ruta=ruta,
        payload=payload,
        user_agent=user_agent,
        headers=headers,
        metodo=metodo,
        usar_alias_normal=True,
    )


def clasificar_ataque(
    ruta: Optional[str],
    payload: Any,
    user_agent: Optional[str],
    headers: Any = None,
    metodo: Optional[str] = None,
) -> str:
    """API legacy: solo el tipo de ataque (str). Delega en ``analizar_peticion``."""
    return analizar_peticion(
        ruta=ruta,
        payload=payload,
        user_agent=user_agent,
        headers=headers,
        metodo=metodo,
    )["tipo_ataque"]


def registrar_intento_login(ip: Optional[str]) -> bool:
    """
    Registra POST /login y detecta fuerza bruta (>5 intentos/minuto).

    Returns:
        bool: True si supera el umbral.
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


def normalizar_gravedad_almacenada(gravedad: Any) -> Optional[str]:
    """Normaliza etiquetas de severidad legacy hacia el vocabulario del SOC."""
    if gravedad is None:
        return None
    texto = str(gravedad).strip()
    if not texto:
        return None
    if texto in GRAVEDADES_MONITOR:
        return texto
    # BOT / BLOQUEADO proviene del perímetro IP; se preserva intacto.
    if texto.upper() in ("BOT / BLOQUEADO", "BOT", "BOT/BLOQUEADO"):
        return "BOT / BLOQUEADO" if "BOT" in texto.upper() else texto
    clave = texto.upper()
    if clave in _MAPA_GRAVEDAD_LEGACY:
        return _MAPA_GRAVEDAD_LEGACY[clave]
    baja = clave.replace("Í", "I")
    if baja in _MAPA_GRAVEDAD_LEGACY:
        return _MAPA_GRAVEDAD_LEGACY[baja]
    return texto


def normalizar_gravedad_filtro_api(valor: Any) -> Optional[str]:
    """Normaliza el filtro de gravedad de las APIs del monitor."""
    if valor is None:
        return None
    texto = str(valor).strip()
    if not texto or texto.lower() in ("todos", "todas", "all", ""):
        return None
    if texto == "BOT / BLOQUEADO" or texto.upper() in ("BOT", "BOT/BLOQUEADO"):
        return "BOT / BLOQUEADO"
    canon = normalizar_gravedad_almacenada(texto)
    if canon in GRAVEDADES_MONITOR or canon == "BOT / BLOQUEADO":
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


def prioridad_gravedad(gravedad: Any) -> int:
    """Orden numérico de severidad (incluye BOT del perímetro WAF)."""
    canon = normalizar_gravedad_almacenada(gravedad)
    return {
        "Crítica": 3,
        "BOT / BLOQUEADO": 3,
        "Alta": 2,
        "Sospechoso": 1,
    }.get(canon or "", 0)


def calcular_gravedad(tipo_ataque: Optional[str]) -> Optional[str]:
    """
    Asigna severidad al tipo de ataque clasificado.

    Crítica: SQLi, Path Traversal, RCE, SSRF/RFI, Scanner Automatizado.
    Alta: XSS, Fuerza Bruta, CSRF.
    Sospechoso: Ruta Prohibida / Reconocimiento (legacy).
    None: tráfico normal.
    """
    if not tipo_ataque or tipo_ataque in (TIPO_TRAFICO_NORMAL, TIPO_NORMAL_ALIAS):
        return None
    if tipo_ataque in (
        TIPO_SQLI,
        TIPO_PATH_TRAVERSAL,
        TIPO_RCE,
        TIPO_SSRF_RFI,
        TIPO_SCANNER,
        "Abuso de Tasa / Escaneo Agresivo",
        "Riesgo Acumulativo (Autoban)",
    ):
        return GRAVEDAD_CRITICA
    if tipo_ataque in (TIPO_XSS, TIPO_FUERZA_BRUTA, TIPO_CSRF):
        return GRAVEDAD_ALTA
    if tipo_ataque in (TIPO_RUTA_PROHIBIDA, TIPO_RECONOCIMIENTO):
        return GRAVEDAD_SOSPECHOSO
    return GRAVEDAD_SOSPECHOSO


def es_ataque_grave(tipo_ataque: Optional[str]) -> bool:
    """True si el tipo justifica alerta operativa / auto-ban potencial."""
    return tipo_ataque in {
        TIPO_SQLI,
        TIPO_XSS,
        TIPO_PATH_TRAVERSAL,
        TIPO_FUERZA_BRUTA,
        TIPO_CSRF,
        TIPO_RCE,
        TIPO_SSRF_RFI,
        TIPO_SCANNER,
        TIPO_RUTA_PROHIBIDA,
    }


def normalizar_tipo_ataque_almacenado(tipo: Any) -> str:
    """
    Unifica aliases de tipo hacia el vocabulario del SOC.

    «Normal» → «Tráfico Normal»; conserva «Reconocimiento» legado.
    """
    texto = (str(tipo) if tipo is not None else "").strip()
    if not texto or texto in (TIPO_NORMAL_ALIAS, "Otro"):
        return TIPO_TRAFICO_NORMAL
    return texto
