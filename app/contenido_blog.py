"""
Catálogo de entradas del blog público (/blog).

Contenido pedagógico sobre FlyPaper: stack, zonas de la plataforma, labs CTF,
documentación, SOC y controles de seguridad. Se sincroniza en SQLite al arrancar.
"""

from __future__ import annotations

from app.core.timezone_fp import formatear_marca, hace as hace_tiempo


def _fecha_publicacion(dias_atras: int) -> str:
    """Marca temporal coherente para ordenar el listado del blog."""
    return formatear_marca(hace_tiempo(days=dias_atras))


def definiciones_posts_blog() -> list[dict]:
    """
    Devuelve las entradas del blog en orden de publicación (más reciente primero en UI).

    Campos: titulo, contenido, autor_username, fecha, imagen_url
    """
    return [
        {
            "titulo": "FlyPaper 2.0: nuevo panel de seguridad y monitorización",
            "autor_username": "lucia.vega",
            "fecha": _fecha_publicacion(3),
            "imagen_url": "/static/blog/flypaper-security.png",
            "contenido": (
                "Presentamos FlyPaper 2.0, la evolución de nuestra plataforma interna hacia un "
                "centro de operaciones de seguridad (SOC) unificado.\n\n"
                "▸ QUÉ INCLUYE\n"
                "• Panel SPA en /admin con pestañas: vista general, monitor en tiempo real, "
                "perímetro WAF, usuarios señuelo, reportes forenses y mapa de amenazas (Leaflet + CARTO).\n"
                "• Clasificación automática de ataques (SQLi, XSS, LFI, scanners, recon) con "
                "gravedad y firma coincidente en SQLite.\n"
                "• Resúmenes diarios asistidos por IA (Groq) y alertas Telegram por topics.\n\n"
                "▸ TECNOLOGÍAS\n"
                "Python 3.11+, Flask 3, SQLite multi-BD, Redis (NGWAF), Jinja2, Chart.js, "
                "Gunicorn/Docker en despliegue.\n\n"
                "▸ ZONAS RELACIONADAS\n"
                "Portal autenticado (/search, /blog, /objetivos, /documentacion), honeypots "
                "públicos (/login, /secure/*) y academia CTF bajo /objetivos/*.\n\n"
                "El equipo de IT integra detección en tiempo real; el go-live académico está "
                "documentado en /documentacion."
            ),
        },
        {
            "titulo": "Stack técnico FlyPaper: de Flask al perímetro Redis",
            "autor_username": "lucia.vega",
            "fecha": _fecha_publicacion(7),
            "imagen_url": "/static/blog/flypaper-security.png",
            "contenido": (
                "Resumen para nuevos integrantes del máster y del equipo de laboratorio.\n\n"
                "▸ BACKEND\n"
                "• Monolito Flask (app.py + paquete app/) con blueprints CTF (sqli, xss, idor, "
                "pathtraversal) y SuperLab.\n"
                "• Persistencia: flypaper.db (eventos, blog, flags), flypaper_priv.db (SOC/2FA), "
                "flypaper_users.db (portal), flypaper_autoban.db (señuelo SQLi).\n"
                "• Middleware: ProxyFix, Flask-Limiter, reputación IP (AbuseIPDB + VirusTotal + ip-api).\n\n"
                "▸ FRONTEND\n"
                "HTML/CSS/JS vanilla, sistema de temas reactivo, admin_panel.js para el SOC.\n\n"
                "▸ OPS\n"
                "Docker Compose (app + Redis 7), variables en .env, datos en ./data montado como volumen.\n\n"
                "▸ SEGURIDAD IMPLEMENTADA (LAB)\n"
                "WAF/IDS local (detector.py), jail page, autoban por score, whitelist, circuit breaker "
                "en APIs de reputación y logging forense de cada petición sospechosa."
            ),
        },
        {
            "titulo": "Academia CTF: laboratorios SQLi del 01 al 04",
            "autor_username": "lucia.vega",
            "fecha": _fecha_publicacion(11),
            "imagen_url": "/static/blog/flypaper-security.png",
            "contenido": (
                "La ruta /objetivos/sqli/ alberga cuatro retos progresivos con bases SQLite aisladas "
                "(sqli_XX.db) y cuestionario de 5 preguntas por lab.\n\n"
                "▸ RETOS\n"
                "• SQLi-01 · Auth Bypass — login vulnerable por concatenación.\n"
                "• SQLi-02 · UNION Based — extracción de columnas vía UNION SELECT.\n"
                "• SQLi-03 · Filter Bypass — evasión de filtros básicos.\n"
                "• SQLi-04 · WAF Evasion — payloads ante reglas del detector.\n\n"
                "▸ TELEMETRÍA\n"
                "Cada intento queda registrado para el SOC; las pistas consumibles viven en "
                "/objetivos/sqli/NN/pista con anti-abuso por sesión.\n\n"
                "▸ DOCUMENTACIÓN\n"
                "Teoría, cheat sheet y mitigaciones (prepared statements) en /documentacion#introduccion "
                "y writeups enlazados desde el buscador /search?q=sqli."
            ),
        },
        {
            "titulo": "Nuevos labs: XSS almacenado, IDOR y Path Traversal",
            "autor_username": "marina.rodriguez",
            "fecha": _fecha_publicacion(15),
            "imagen_url": "/static/blog/ventas-informes.png",
            "contenido": (
                "Ampliamos la academia más allá de SQLi con tres familias OWASP en rutas dedicadas.\n\n"
                "▸ XSS (/objetivos/xss/01)\n"
                "Comentarios almacenados en un blog de laboratorio; bot moderador simula revisión "
                "administrativa. Puntos: ~110.\n\n"
                "▸ IDOR (/objetivos/idor/01)\n"
                "Portal de nóminas: el identificador en URL no se valida contra la sesión. "
                "Objetivo: leer recurso ajeno (flag en ID 1).\n\n"
                "▸ PATH TRAVERSAL (/objetivos/pathtraversal/01 y /02)\n"
                "Descarga de informes con ../ clásico; reto 02 añade filtro literal y sandbox "
                "con relative_to() en backend.\n\n"
                "▸ WRITEUPS\n"
                "Markdown en docs/writeups/ expuesto vía /documentacion/writeup/<slug> — "
                "indexado por el buscador unificado."
            ),
        },
        {
            "titulo": "SuperLab NexusCorp: cadena ofensiva multi-fase",
            "autor_username": "lucia.vega",
            "fecha": _fecha_publicacion(19),
            "imagen_url": "/static/blog/flypaper-security.png",
            "contenido": (
                "SuperLab simula una intranet corporativa ficticia (NexusCorp) para practicar "
                "reconocimiento encadenado, no un único payload aislado.\n\n"
                "▸ FASES TÍPICAS\n"
                "• Home y login legacy (/superlab/...)\n"
                "• Staging con mensajes internos (auth débil)\n"
                "• IDOR / datos ficticios en panel\n"
                "• Fuzzer de parámetros\n"
                "• SQLi en entorno staging y flag final\n\n"
                "▸ INTEGRACIÓN CTF\n"
                "Checkpoints y flags enlazados al catálogo en ctf_sqli/catalogo.py; progreso "
                "persistido por usuario del portal.\n\n"
                "▸ DÓNDE EMPEZAR\n"
                "Teoría en /documentacion#teoria-superlab y entrada desde /objetivos."
            ),
        },
        {
            "titulo": "Documentación integrada: teoría, cheat sheets y writeups",
            "autor_username": "javier.pena",
            "fecha": _fecha_publicacion(23),
            "imagen_url": "/static/blog/onboarding-rrhh.png",
            "contenido": (
                "FlyPaper concentra el material del máster en /documentacion (requiere sesión de "
                "portal como /blog y /objetivos).\n\n"
                "▸ CONTENIDO\n"
                "• Introducción SQLi, teoría XSS, Path Traversal, IDOR y SuperLab.\n"
                "• Cheat sheet de payloads educativos y contramedidas.\n"
                "• Writeups por reto (idor_01, pathtraversal_01, xss_01, etc.) renderizados "
                "desde Markdown (markdown_doc.py).\n\n"
                "▸ BUSCADOR\n"
                "GET /search?q= término indexa blog + labs de las 5 categorías + secciones "
                "estáticas + rutas de writeups — sin concatenar SQL (WAF distingue tráfico legítimo).\n\n"
                "▸ BUENAS PRÁCTICAS\n"
                "Usad la documentación antes de pedir pistas; cada pista penaliza telemetría "
                "visible para instructores."
            ),
        },
        {
            "titulo": "Panel SOC: mapa de amenazas, monitor y exportación forense",
            "autor_username": "lucia.vega",
            "fecha": _fecha_publicacion(27),
            "imagen_url": "/static/blog/flypaper-security.png",
            "contenido": (
                "Tras login SOC + 2FA Telegram, /admin concentra la operación del honeypot.\n\n"
                "▸ PESTAÑAS\n"
                "• General — widgets honeypot, últimas IPs, último crítico.\n"
                "• Monitor — iframe tiempo real.\n"
                "• Perímetro — IPs bloqueadas en Redis (TTL 24h, rate 60 req/min).\n"
                "• Reportes — búsqueda por IP/fecha, CSV, resúmenes IA.\n"
                "• Mapa — geolocalización de atacantes (Leaflet, teselas CARTO con API key en .env).\n\n"
                "▸ GESTIÓN\n"
                "Cuentas SOC en /admin/usuarios-soc; participantes CTF en /admin/participantes-ctf "
                "con detalle de flags y pistas pedidas.\n\n"
                "▸ SEGURIDAD SOC\n"
                "Roles admin_panel vs analyst, cambio obligatorio de credenciales en primer acceso, "
                "sesión honeypot separada del portal alumno."
            ),
        },
        {
            "titulo": "Motor WAF/IDS y reputación IP: qué registramos",
            "autor_username": "lucia.vega",
            "fecha": _fecha_publicacion(31),
            "imagen_url": "/static/blog/flypaper-security.png",
            "contenido": (
                "Cada petición HTTP puede analizarse en app/core/detector.py antes de llegar "
                "a la vista Flask.\n\n"
                "▸ DETECCIÓN\n"
                "Firmas SQLi, XSS, path traversal, RCE, SSRF, scanners (sqlmap, nikto, dirbuster), "
                "sondeo de rutas (/.env, /wp-admin, /backup) y anti-evasión básica.\n\n"
                "▸ GRAVEDAD\n"
                "Crítica, Alta, Sospechoso — alimenta Telegram, mapa SOC y NIS2 en reportes.\n\n"
                "▸ PERÍMETRO (ip_reputation.py)\n"
                "Score = (AbuseIPDB × 0.6) + (VT positivos × 10); autoban si supera umbral; "
                "cache y circuit breaker en Redis.\n\n"
                "▸ ZONAS HONEYPOT\n"
                "Login falso, /secure/search y /secure/blog (SQLi señuelo en autoban.db), "
                "formularios CTF intencionalmente vulnerables bajo /objetivos."
            ),
        },
        {
            "titulo": "Portal de empleados: sesión, buscador y zonas autenticadas",
            "autor_username": "javier.pena",
            "fecha": _fecha_publicacion(35),
            "imagen_url": "/static/blog/onboarding-rrhh.png",
            "contenido": (
                "Desde RRHH recordamos el modelo de acceso al portal FlyPaper (flypaper_users.db).\n\n"
                "▸ RUTAS CON SESIÓN (15 min inactividad)\n"
                "/search, /blog, /objetivos, /documentacion — mismo temporizador en partial "
                "sesion_inactividad.html.\n\n"
                "▸ REGISTRO / LOGIN\n"
                "Flujo público de alta; credenciales no deben compartirse por correo.\n\n"
                "▸ BUSCADOR LEGÍTIMO\n"
                "/search?q= sustituyó al antiguo honeypot SQLi en GET /search; la búsqueda "
                "vulnerable permanece en /secure/search para trazabilidad ofensiva.\n\n"
                "▸ CTF\n"
                "El progreso de flags se asocia al usuario del portal (objetivos_completados), "
                "no solo a la IP."
            ),
        },
        {
            "titulo": "Onboarding RRHH: acceso al portal y política de contraseñas",
            "autor_username": "javier.pena",
            "fecha": _fecha_publicacion(40),
            "imagen_url": "/static/blog/onboarding-rrhh.png",
            "contenido": (
                "Guía rápida para nuevos empleados ficticios del entorno FlyPaper.\n\n"
                "▸ ACCESO\n"
                "Usuario corporativo @flypaper.io; reset vía ticket interno (simulado).\n\n"
                "▸ PORTAL\n"
                "Tras login: blog de novedades, buscador, academia de laboratorios y "
                "documentación del máster.\n\n"
                "▸ SEGURIDAD\n"
                "No reutilizar contraseñas personales; cerrar sesión en equipos compartidos; "
                "reportar enlaces sospechosos al SOC (Telegram configurado en .env).\n\n"
                "▸ DIVERSIÓN\n"
                "Minijuego Rosco (/diversion/carta) — preguntas desde preguntas_rosco.md, "
                "sin impacto en notas CTF."
            ),
        },
        {
            "titulo": "Ventas y métricas: exportación de informes sin saturar la API",
            "autor_username": "marina.rodriguez",
            "fecha": _fecha_publicacion(44),
            "imagen_url": "/static/blog/ventas-informes.png",
            "contenido": (
                "El módulo de Ventas usa el dashboard FlyPaper para CSV semanales.\n\n"
                "▸ BUENAS PRÁCTICAS\n"
                "Ventanas horarias de baja carga; paginación; no automatizar scraping contra "
                "/admin (dispara WAF y autoban).\n\n"
                "▸ RELACIÓN CON SEGURIDAD\n"
                "Los informes de tráfico ofensivo viven en el SOC, no en Ventas — separación "
                "de datos entre flypaper.db operativo y señuelos.\n\n"
                "▸ LAB CTF\n"
                "Si necesitáis datos sintéticos para pruebas IDOR/nóminas, usad los endpoints "
                "de /objetivos/idor, no datos reales."
            ),
        },
        {
            "titulo": "Despliegue Docker, Telegram y variables de entorno",
            "autor_username": "lucia.vega",
            "fecha": _fecha_publicacion(48),
            "imagen_url": "/static/blog/flypaper-security.png",
            "contenido": (
                "Notas de operaciones para desplegar FlyPaper en laboratorio o VPS (Hetzner CX22 "
                "documentado en README).\n\n"
                "▸ COMPOSE\n"
                "Servicios: flypaper (Gunicorn :5000) + redis:7 con volumen ./data.\n\n"
                "▸ .env CRÍTICO\n"
                "GROQ_API_KEY, TELEGRAM_*, ABUSEIPDB/VIRUSTOTAL, REDIS_URL, FLYPAPER_DATA_DIR, "
                "INITIAL_SOC_* (bootstrap), CARTO_API_KEY (mapa SOC).\n\n"
                "▸ TELEGRAM TOPICS\n"
                "Logins, ataques críticos y resumen diario — message_thread_id por topic.\n\n"
                "▸ DEVSECOPS\n"
                ".gitignore excluye .env y data/; solo .env.example en Git. Rotad claves si "
                "exponeis el lab a Internet público."
            ),
        },
        {
            "titulo": "Rosco y diversión: descanso cognitivo entre labs",
            "autor_username": "marina.rodriguez",
            "fecha": _fecha_publicacion(52),
            "imagen_url": "/static/blog/ventas-informes.png",
            "contenido": (
                "No todo es explotación: /diversion/carta ofrece un Pasapalabra temático.\n\n"
                "▸ IMPLEMENTACIÓN\n"
                "Parser Markdown (app/rosco.py) sobre preguntas_rosco.md; UI circular "
                "con theme-bridge reactivo.\n\n"
                "▸ OBJETIVO PEDAGÓGICO\n"
                "Repasar vocabulario de ciberseguridad en español (incl. letra Ñ) sin "
                "conexión a flags ni puntuación CTF.\n\n"
                "▸ STACK\n"
                "Misma base Flask + Jinja; estáticos en templates/diversion/."
            ),
        },
    ]


def titulos_catalogo_blog() -> set[str]:
    """Conjunto de títulos canónicos para limpiar entradas obsoletas."""
    return {entrada["titulo"] for entrada in definiciones_posts_blog()}
