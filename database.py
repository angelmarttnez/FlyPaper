"""
Módulo de acceso a datos para FlyPaper.

Esquema relacional SQLite: eventos del honeypot, usuarios/posts del entorno falso,
flags de CTF y tablas auxiliares. Incluye población inicial del escenario de laboratorio.
"""

import hashlib
import json
import re
import secrets
import sqlite3
import string
from datetime import datetime, timedelta
from pathlib import Path

# Nombres canónicos de los dos retos CTF del laboratorio.
RETO_CTF_SQLI = "SQLi"
RETO_CTF_PATH_TRAVERSAL = "Path Traversal"
# Usuario señuelo en tabla `usuarios`: nombre engañoso, sin privilegios reales de app.
USUARIO_SENUELO_SQLI = "admin"
# Formato estricto: flag{10 caracteres alfanuméricos} (grupo 1 = cuerpo de la flag).
PATRON_FLAG_CTF = re.compile(r"^flag\{([a-zA-Z0-9]{10})\}$")


RUTA_RAIZ_PROYECTO = Path(__file__).resolve().parent
RUTA_BD = RUTA_RAIZ_PROYECTO / "flypaper.db"


def obtener_conexion():
    """
    Crea una conexión SQLite con filas accesibles por nombre de columna.

    Returns:
        sqlite3.Connection: Conexión a `flypaper.db`.
    """
    conexion = sqlite3.connect(RUTA_BD)
    conexion.row_factory = sqlite3.Row
    conexion.execute("PRAGMA foreign_keys = ON;")
    return conexion


def _tabla_vacia(cursor, nombre_tabla):
    """True si la tabla no tiene filas (para decidir si poblar datos de simulación)."""
    cursor.execute(f"SELECT COUNT(*) AS n FROM {nombre_tabla};")
    return cursor.fetchone()["n"] == 0


def _asegurar_columna_gravedad(cursor):
    """
    Añade la columna `gravedad` a `eventos` si la BD existía con un esquema antiguo.
    """
    cursor.execute("PRAGMA table_info(eventos);")
    columnas = {fila[1] for fila in cursor.fetchall()}
    if "gravedad" not in columnas:
        cursor.execute(
            "ALTER TABLE eventos ADD COLUMN gravedad TEXT DEFAULT 'BAJO';"
        )


def inicializar_db():
    """
    Crea todas las tablas del modelo relacional si no existen.

    Tablas: eventos, usuarios, posts, comentarios, flags, flags_resueltas, reportes_enviados, ips_bloqueadas.
    Tras crear el esquema, llama a `poblar_entorno_simulacion()` si procede.
    """
    ddl_tablas = """
    CREATE TABLE IF NOT EXISTS eventos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        ruta TEXT,
        metodo TEXT,
        payload TEXT,
        tipo_ataque TEXT,
        gravedad TEXT DEFAULT 'BAJO',
        user_agent TEXT,
        timestamp DATETIME,
        pais TEXT DEFAULT '',
        headers TEXT
    );

    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        nombre TEXT,
        apellido TEXT,
        departamento TEXT,
        email TEXT,
        avatar_url TEXT
    );

    CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        titulo TEXT NOT NULL,
        contenido TEXT,
        autor_id INTEGER,
        fecha DATETIME,
        imagen_url TEXT,
        FOREIGN KEY (autor_id) REFERENCES usuarios(id)
    );

    CREATE TABLE IF NOT EXISTS comentarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER NOT NULL,
        ip_autor TEXT,
        autor_nombre TEXT,
        contenido TEXT,
        fecha DATETIME,
        visible INTEGER DEFAULT 1,
        FOREIGN KEY (post_id) REFERENCES posts(id)
    );

    CREATE TABLE IF NOT EXISTS flags (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        reto_nombre TEXT NOT NULL,
        flag_string TEXT UNIQUE NOT NULL,
        puntos INTEGER DEFAULT 0,
        pista TEXT
    );

    CREATE TABLE IF NOT EXISTS flags_resueltas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_atacante TEXT,
        flag_id INTEGER NOT NULL,
        fecha DATETIME,
        FOREIGN KEY (flag_id) REFERENCES flags(id)
    );

    CREATE TABLE IF NOT EXISTS reportes_enviados (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_atacante TEXT,
        datos_ataque TEXT,
        fecha DATETIME
    );

    CREATE TABLE IF NOT EXISTS ips_bloqueadas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE NOT NULL,
        fecha DATETIME,
        motivo TEXT DEFAULT ''
    );
    """

    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.executescript(ddl_tablas)
        _asegurar_columna_gravedad(cursor)
        conexion.commit()

    poblar_entorno_simulacion()
    asegurar_flags_ctf_dinamicas()
    asegurar_usuario_senuelo_sqli()


def generar_flag_ctf_aleatoria():
    """
    Genera una flag única con formato flag{10_caracteres_alfanuméricos}.

    Returns:
        str: Ejemplo flag{a7Kx9mQ2pL}
    """
    alfabeto = string.ascii_letters + string.digits
    cuerpo = "".join(secrets.choice(alfabeto) for _ in range(10))
    return f"flag{{{cuerpo}}}"


def _flag_ctf_formato_valido(flag_string):
    """True si la cadena cumple flag{10 alfanuméricos}."""
    return bool(PATRON_FLAG_CTF.match((flag_string or "").strip()))


def extraer_cuerpo_de_flag(flag_string):
    """
    Extrae los 10 caracteres alfanuméricos internos de una flag CTF.

    Ejemplo: flag{Abc12xyZ90} → Abc12xyZ90
    """
    coincidencia = PATRON_FLAG_CTF.match((flag_string or "").strip())
    return coincidencia.group(1) if coincidencia else None


def obtener_flag_string_por_reto(reto_nombre):
    """Devuelve la cadena completa flag{...} almacenada para un reto."""
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            "SELECT flag_string FROM flags WHERE reto_nombre = ?;",
            (reto_nombre,),
        )
        fila = cursor.fetchone()
        return fila["flag_string"] if fila else None


def asegurar_flags_ctf_dinamicas():
    """
    Garantiza en BD las flags de SQLi y Path Traversal con formato flag{...} aleatorio.

    Inserta retos faltantes o sustituye flags legacy (p. ej. FLAG{...} estáticas).
    """
    definicion_retos = [
        (
            RETO_CTF_SQLI,
            100,
            "Explota la inyección SQL en un formulario para leer datos sensibles de la BD.",
        ),
        (
            RETO_CTF_PATH_TRAVERSAL,
            150,
            "Accede a un archivo del sistema mediante rutas relativas (../) o LFI.",
        ),
    ]

    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        for reto_nombre, puntos, pista in definicion_retos:
            cursor.execute(
                "SELECT id, flag_string FROM flags WHERE reto_nombre = ?;",
                (reto_nombre,),
            )
            fila = cursor.fetchone()
            if fila is None:
                cursor.execute(
                    """
                    INSERT INTO flags (reto_nombre, flag_string, puntos, pista)
                    VALUES (?, ?, ?, ?);
                    """,
                    (reto_nombre, generar_flag_ctf_aleatoria(), puntos, pista),
                )
            elif not _flag_ctf_formato_valido(fila["flag_string"]):
                cursor.execute(
                    "UPDATE flags SET flag_string = ? WHERE id = ?;",
                    (generar_flag_ctf_aleatoria(), fila["id"]),
                )
        conexion.commit()

    # Si la flag SQLi cambió, la contraseña del usuario señuelo debe coincidir.
    asegurar_usuario_senuelo_sqli()


def asegurar_usuario_senuelo_sqli():
    """
    Usuario «admin» en BD (señuelo CTF): password_hash = 10 caracteres de la flag SQLi.

    No otorga acceso a /monitor ni panel honeypot (login de app.py es independiente).
    Se actualiza siempre que exista o cambie la flag del reto SQLi.
    """
    flag_sqli = obtener_flag_string_por_reto(RETO_CTF_SQLI)
    if not flag_sqli:
        return

    password_dinamica = extraer_cuerpo_de_flag(flag_sqli)
    if not password_dinamica:
        return

    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            "SELECT id FROM usuarios WHERE username = ?;",
            (USUARIO_SENUELO_SQLI,),
        )
        if cursor.fetchone():
            cursor.execute(
                """
                UPDATE usuarios
                SET password_hash = ?, departamento = ?
                WHERE username = ?;
                """,
                (password_dinamica, "Soporte", USUARIO_SENUELO_SQLI),
            )
        else:
            cursor.execute(
                """
                INSERT INTO usuarios (
                    username, password_hash, nombre, apellido,
                    departamento, email, avatar_url
                ) VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    USUARIO_SENUELO_SQLI,
                    password_dinamica,
                    "Usuario",
                    "Señuelo",
                    "Soporte",
                    "admin.ctf@flypaper.io",
                    "/static/avatars/admin.png",
                ),
            )
        conexion.commit()


def reiniciar_progreso_ctf_por_ip(ip):
    """
    Elimina todos los retos resueltos de una IP (QA / repetir pruebas en /objetivos).

    Returns:
        int: Número de filas eliminadas en flags_resueltas.
    """
    if not ip:
        return 0
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            "DELETE FROM flags_resueltas WHERE ip_atacante = ?;",
            (ip,),
        )
        eliminadas = cursor.rowcount
        conexion.commit()
        return eliminadas


def poblar_entorno_simulacion():
    """
    Inserta datos falsos del entorno corporativo y flags del CTF.

    Solo inserta si las tablas principales de simulación están vacías (usuarios, posts, flags).
    - 4 usuarios (IT, RRHH, Ventas, Admin); admin con MD5 de "admin123" (mala práctica intencional).
    - 3 posts de blog sobre FlyPaper con comentarios de empleados.
    - 2 flags: SQLi (100 pts) y Path Traversal / LFI (150 pts).
    """
    marca = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    with obtener_conexion() as conexion:
        cursor = conexion.cursor()

        # Solo sembrar si el entorno de simulación aún no tiene datos.
        if not (
            _tabla_vacia(cursor, "usuarios")
            and _tabla_vacia(cursor, "posts")
            and _tabla_vacia(cursor, "flags")
        ):
            return

        # Hash MD5 débil del usuario admin (CTF: credencial predecible).
        hash_admin_debil = hashlib.md5(b"admin123").hexdigest()

        usuarios_seed = [
            (
                "admin",
                hash_admin_debil,
                "Carlos",
                "Méndez",
                "Admin",
                "admin@flypaper.io",
                "/static/avatars/admin.png",
            ),
            (
                "lucia.vega",
                hashlib.md5(b"FlyPaper2026!").hexdigest(),
                "Lucía",
                "Vega",
                "IT",
                "lucia.vega@flypaper.io",
                "/static/avatars/it.png",
            ),
            (
                "javier.pena",
                hashlib.md5(b"rrhh2026").hexdigest(),
                "Javier",
                "Peña",
                "RRHH",
                "j.pena@flypaper.io",
                "/static/avatars/rrhh.png",
            ),
            (
                "marina.rodriguez",
                hashlib.md5(b"ventas#99").hexdigest(),
                "Marina",
                "Rodríguez",
                "Ventas",
                "marina.rodriguez@flypaper.io",
                "/static/avatars/ventas.png",
            ),
        ]

        cursor.executemany(
            """
            INSERT INTO usuarios (
                username, password_hash, nombre, apellido, departamento, email, avatar_url
            ) VALUES (?, ?, ?, ?, ?, ?, ?);
            """,
            usuarios_seed,
        )

        cursor.execute("SELECT id, username FROM usuarios ORDER BY id;")
        mapa_usuarios = {fila["username"]: fila["id"] for fila in cursor.fetchall()}

        posts_seed = [
            (
                "FlyPaper 2.0: nuevo panel de seguridad",
                (
                    "Presentamos FlyPaper 2.0, nuestra plataforma interna de monitorización "
                    "de amenazas. El equipo de IT ha integrado detección automática de SQLi, "
                    "XSS y escaneos en tiempo real. El despliegue en producción está previsto "
                    "para el próximo trimestre."
                ),
                mapa_usuarios.get("lucia.vega"),
                marca,
                "/static/blog/flypaper-security.png",
            ),
            (
                "Onboarding RRHH: acceso al portal de empleados",
                (
                    "Desde RRHH recordamos que el acceso al portal FlyPaper requiere usuario "
                    "corporativo. Si olvidáis la contraseña, abrid ticket con el departamento; "
                    "no compartáis credenciales por correo."
                ),
                mapa_usuarios.get("javier.pena"),
                marca,
                "/static/blog/onboarding-rrhh.png",
            ),
            (
                "Ventas y métricas: exportación de informes",
                (
                    "El módulo de Ventas ya puede exportar informes CSV desde el dashboard "
                    "FlyPaper. Marina Rodríguez explica en este post cómo generar reportes "
                    "semanales sin saturar la API interna."
                ),
                mapa_usuarios.get("marina.rodriguez"),
                marca,
                "/static/blog/ventas-informes.png",
            ),
        ]

        cursor.executemany(
            """
            INSERT INTO posts (titulo, contenido, autor_id, fecha, imagen_url)
            VALUES (?, ?, ?, ?, ?);
            """,
            posts_seed,
        )

        cursor.execute("SELECT id, titulo FROM posts ORDER BY id;")
        posts_por_id = list(cursor.fetchall())

        comentarios_seed = []
        if len(posts_por_id) >= 1:
            comentarios_seed.extend(
                [
                    (
                        posts_por_id[0]["id"],
                        "10.0.1.42",
                        "Carlos Méndez",
                        "Buen trabajo, equipo. Revisad los logs del honeypot antes del go-live.",
                        marca,
                        1,
                    ),
                    (
                        posts_por_id[0]["id"],
                        "10.0.1.88",
                        "Lucía Vega",
                        "Ya tenemos alertas para intentos de UNION SELECT en /login.",
                        marca,
                        1,
                    ),
                ]
            )
        if len(posts_por_id) >= 2:
            comentarios_seed.append(
                (
                    posts_por_id[1]["id"],
                    "10.0.2.15",
                    "Javier Peña",
                    "Añadido enlace al manual de política de contraseñas en la intranet.",
                    marca,
                    1,
                )
            )
        if len(posts_por_id) >= 3:
            comentarios_seed.append(
                (
                    posts_por_id[2]["id"],
                    "10.0.3.77",
                    "Marina Rodríguez",
                    "Los informes de Ventas ya no tiran del servidor de backups.",
                    marca,
                    1,
                )
            )

        if comentarios_seed:
            cursor.executemany(
                """
                INSERT INTO comentarios (
                    post_id, ip_autor, autor_nombre, contenido, fecha, visible
                ) VALUES (?, ?, ?, ?, ?, ?);
                """,
                comentarios_seed,
            )

        flags_seed = [
            (
                RETO_CTF_SQLI,
                generar_flag_ctf_aleatoria(),
                100,
                "Explota la inyección SQL en un formulario para leer datos sensibles de la BD.",
            ),
            (
                RETO_CTF_PATH_TRAVERSAL,
                generar_flag_ctf_aleatoria(),
                150,
                "Accede a un archivo del sistema mediante rutas relativas (../) o LFI.",
            ),
        ]

        cursor.executemany(
            """
            INSERT INTO flags (reto_nombre, flag_string, puntos, pista)
            VALUES (?, ?, ?, ?);
            """,
            flags_seed,
        )

        conexion.commit()


def _serializar_campo_json(valor):
    """Convierte dict/list a JSON; el resto a str."""
    if isinstance(valor, (dict, list)):
        return json.dumps(valor, ensure_ascii=False)
    if valor is None:
        return ""
    return str(valor)


def guardar_evento(
    ip,
    ruta,
    metodo,
    payload,
    user_agent,
    tipo_ataque,
    headers,
    gravedad="BAJO",
):
    """
    Inserta un evento capturado por el honeypot en la tabla `eventos`.

    Args:
        ip (str): IP del visitante.
        ruta (str): Ruta HTTP visitada.
        metodo (str): GET, POST, etc.
        payload: Cuerpo o parámetros (se serializa a texto).
        user_agent (str): User-Agent.
        tipo_ataque (str): Clasificación del detector.
        headers: Cabeceras HTTP (dict o texto).
        gravedad (str): CRÍTICO, ALTO, MEDIO o BAJO.
    """
    payload_texto = _serializar_campo_json(payload)
    headers_texto = _serializar_campo_json(headers) if headers is not None else "{}"
    marca_tiempo = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    consulta = """
    INSERT INTO eventos (
        ip, ruta, metodo, payload, tipo_ataque, gravedad,
        user_agent, timestamp, pais, headers
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """

    valores = (
        ip,
        ruta,
        metodo,
        payload_texto,
        tipo_ataque,
        gravedad,
        user_agent,
        marca_tiempo,
        "",
        headers_texto,
    )

    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(consulta, valores)
        conexion.commit()


def obtener_eventos(limite=100):
    """
    Devuelve los últimos eventos ordenados por fecha descendente.

    Args:
        limite (int): Máximo de filas (mínimo 1).

    Returns:
        list[dict]: Eventos como diccionarios.
    """
    limite_norm = max(int(limite), 1)

    consulta = """
    SELECT
        id, ip, ruta, metodo, payload, tipo_ataque, gravedad,
        user_agent, timestamp, pais, headers
    FROM eventos
    ORDER BY timestamp DESC, id DESC
    LIMIT ?;
    """

    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(consulta, (limite_norm,))
        return [dict(fila) for fila in cursor.fetchall()]


def obtener_estadisticas():
    """
    Calcula métricas agregadas para el dashboard del monitor.

    Returns:
        dict: total_eventos, ips_unicas, ataques_por_tipo, ataques_por_gravedad,
              eventos_por_hora_ultimas_24h.
    """
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()

        cursor.execute("SELECT COUNT(*) AS total FROM eventos;")
        total_eventos = cursor.fetchone()["total"]

        cursor.execute(
            """
            SELECT COUNT(DISTINCT ip) AS total_ips_unicas
            FROM eventos
            WHERE ip IS NOT NULL AND TRIM(ip) != '';
            """
        )
        total_ips_unicas = cursor.fetchone()["total_ips_unicas"]

        cursor.execute(
            """
            SELECT
                COALESCE(NULLIF(TRIM(tipo_ataque), ''), 'sin_clasificar') AS tipo_ataque,
                COUNT(*) AS cantidad
            FROM eventos
            GROUP BY COALESCE(NULLIF(TRIM(tipo_ataque), ''), 'sin_clasificar')
            ORDER BY cantidad DESC, tipo_ataque ASC;
            """
        )
        ataques_por_tipo = {
            fila["tipo_ataque"]: fila["cantidad"] for fila in cursor.fetchall()
        }

        cursor.execute(
            """
            SELECT
                COALESCE(NULLIF(TRIM(gravedad), ''), 'BAJO') AS gravedad,
                COUNT(*) AS cantidad
            FROM eventos
            GROUP BY COALESCE(NULLIF(TRIM(gravedad), ''), 'BAJO')
            ORDER BY cantidad DESC;
            """
        )
        ataques_por_gravedad = {
            fila["gravedad"]: fila["cantidad"] for fila in cursor.fetchall()
        }

        hora_actual_utc = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
        hora_inicio_utc = hora_actual_utc - timedelta(hours=23)

        eventos_por_hora = {}
        for desplazamiento in range(24):
            hora_bucket = hora_inicio_utc + timedelta(hours=desplazamiento)
            clave = hora_bucket.strftime("%Y-%m-%d %H:00:00")
            eventos_por_hora[clave] = 0

        cursor.execute(
            """
            SELECT
                strftime('%Y-%m-%d %H:00:00', timestamp) AS hora,
                COUNT(*) AS cantidad
            FROM eventos
            WHERE timestamp >= ?
            GROUP BY hora
            ORDER BY hora ASC;
            """,
            (hora_inicio_utc.strftime("%Y-%m-%d %H:%M:%S"),),
        )
        for fila in cursor.fetchall():
            if fila["hora"] in eventos_por_hora:
                eventos_por_hora[fila["hora"]] = fila["cantidad"]

    return {
        "total_eventos": total_eventos,
        "ips_unicas": total_ips_unicas,
        "ataques_por_tipo": ataques_por_tipo,
        "ataques_por_gravedad": ataques_por_gravedad,
        "eventos_por_hora_ultimas_24h": eventos_por_hora,
    }


def obtener_flags_publicas():
    """
    Lista retos CTF sin exponer el valor secreto `flag_string`.

    Returns:
        list[dict]: Filas con reto_nombre, puntos, pista.
    """
    consulta = """
    SELECT id, reto_nombre, puntos, pista
    FROM flags
    ORDER BY puntos ASC, id ASC;
    """
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(consulta)
        return [dict(fila) for fila in cursor.fetchall()]


def contar_flags_resueltas_por_ip(ip):
    """Cuenta cuántas flags distintas ha resuelto una IP."""
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            """
            SELECT COUNT(DISTINCT flag_id) AS total
            FROM flags_resueltas
            WHERE ip_atacante = ?;
            """,
            (ip,),
        )
        return cursor.fetchone()["total"]


def obtener_ids_flags_resueltas_por_ip(ip):
    """Conjunto de id de flags ya resueltas por esta IP."""
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            "SELECT DISTINCT flag_id FROM flags_resueltas WHERE ip_atacante = ?;",
            (ip,),
        )
        return {fila["flag_id"] for fila in cursor.fetchall()}


def obtener_flags_con_estado_por_ip(ip):
    """
    Lista retos públicos marcando cuáles ya resolvió la IP (para ticks en /objetivos).

    Returns:
        list[dict]: id, reto_nombre, puntos, pista, resuelta (bool).
    """
    flags = obtener_flags_publicas()
    resueltos = obtener_ids_flags_resueltas_por_ip(ip)
    for flag in flags:
        flag["resuelta"] = flag["id"] in resueltos
    return flags


def enviar_flag(ip, flag_texto):
    """
    Valida y registra una flag enviada por el jugador.

    Returns:
        dict: {"exito": bool, "mensaje": str, "puntos": int|None}
    """
    flag_limpia = (flag_texto or "").strip()
    total_retos = len(obtener_flags_publicas())

    if not flag_limpia:
        return {
            "exito": False,
            "mensaje": "La flag introducida es incorrecta",
            "puntos": None,
            "reto_nombre": None,
            "flag_id": None,
            "resueltas": contar_flags_resueltas_por_ip(ip),
            "total": total_retos,
        }

    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            "SELECT id, puntos, reto_nombre FROM flags WHERE flag_string = ?;",
            (flag_limpia,),
        )
        fila_flag = cursor.fetchone()
        if fila_flag is None:
            return {
                "exito": False,
                "mensaje": "La flag introducida es incorrecta",
                "puntos": None,
                "reto_nombre": None,
                "flag_id": None,
                "resueltas": contar_flags_resueltas_por_ip(ip),
                "total": total_retos,
            }

        flag_id = fila_flag["id"]
        reto_nombre = fila_flag["reto_nombre"]
        cursor.execute(
            """
            SELECT id FROM flags_resueltas
            WHERE ip_atacante = ? AND flag_id = ?;
            """,
            (ip, flag_id),
        )
        if cursor.fetchone() is not None:
            resueltas = contar_flags_resueltas_por_ip(ip)
            return {
                "exito": True,
                "mensaje": f"Ya habías resuelto el reto «{reto_nombre}»",
                "puntos": fila_flag["puntos"],
                "reto_nombre": reto_nombre,
                "flag_id": flag_id,
                "resueltas": resueltas,
                "total": total_retos,
                "ya_resuelta": True,
            }

        marca = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            """
            INSERT INTO flags_resueltas (ip_atacante, flag_id, fecha)
            VALUES (?, ?, ?);
            """,
            (ip, flag_id, marca),
        )
        conexion.commit()

    resueltas = contar_flags_resueltas_por_ip(ip)
    return {
        "exito": True,
        "mensaje": f"¡Reto «{reto_nombre}» completado!",
        "puntos": fila_flag["puntos"],
        "reto_nombre": reto_nombre,
        "flag_id": flag_id,
        "resueltas": resueltas,
        "total": total_retos,
        "ya_resuelta": False,
    }


def obtener_posts_blog():
    """Devuelve todos los posts del blog ordenados por fecha descendente."""
    consulta = """
    SELECT id, titulo, contenido, autor_id, fecha, imagen_url
    FROM posts
    ORDER BY fecha DESC, id DESC;
    """
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(consulta)
        return [dict(fila) for fila in cursor.fetchall()]


def obtener_post_por_id(post_id):
    """Obtiene un post por su identificador o None si no existe."""
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            """
            SELECT id, titulo, contenido, autor_id, fecha, imagen_url
            FROM posts WHERE id = ?;
            """,
            (post_id,),
        )
        fila = cursor.fetchone()
        return dict(fila) if fila else None


def obtener_comentarios_visibles_post(post_id):
    """
    Comentarios visibles de un post, adaptados a la plantilla post.html.

    Returns:
        list[dict]: Claves nombre, comentario, fecha.
    """
    consulta = """
    SELECT autor_nombre, contenido, fecha
    FROM comentarios
    WHERE post_id = ? AND visible = 1
    ORDER BY fecha ASC, id ASC;
    """
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(consulta, (post_id,))
        filas = cursor.fetchall()

    comentarios = []
    for fila in filas:
        comentarios.append(
            {
                "nombre": fila["autor_nombre"] or "Anónimo",
                "comentario": fila["contenido"] or "",
                "fecha": fila["fecha"] or "",
            }
        )
    return comentarios


def contar_comentarios_visibles_por_ip(ip):
    """Cuenta comentarios activos (visible=1) publicados por una IP."""
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM comentarios
            WHERE ip_autor = ? AND visible = 1;
            """,
            (ip,),
        )
        return cursor.fetchone()["total"]


def insertar_comentario(post_id, ip_autor, autor_nombre, contenido):
    """Inserta un comentario visible en un post."""
    marca = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            """
            INSERT INTO comentarios (
                post_id, ip_autor, autor_nombre, contenido, fecha, visible
            ) VALUES (?, ?, ?, ?, ?, 1);
            """,
            (post_id, ip_autor, autor_nombre, contenido, marca),
        )
        conexion.commit()


def guardar_reporte_enviado(ip_atacante, datos_ataque):
    """
    Registra un reporte forense enviado desde el monitor de seguridad.

    Args:
        ip_atacante (str): IP señalada en el reporte.
        datos_ataque: Texto o estructura serializable a JSON.
    """
    if isinstance(datos_ataque, (dict, list)):
        datos_serializados = json.dumps(datos_ataque, ensure_ascii=False)
    else:
        datos_serializados = str(datos_ataque or "")

    marca = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            """
            INSERT INTO reportes_enviados (ip_atacante, datos_ataque, fecha)
            VALUES (?, ?, ?);
            """,
            (ip_atacante, datos_serializados, marca),
        )
        conexion.commit()


def obtener_reportes_enviados():
    """
    Lista todos los reportes del honeypot ordenados del más reciente al más antiguo.

    Returns:
        list[dict]: Filas con id, ip_atacante, datos_ataque, fecha.
    """
    consulta = """
    SELECT id, ip_atacante, datos_ataque, fecha
    FROM reportes_enviados
    ORDER BY fecha DESC, id DESC;
    """
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(consulta)
        return [dict(fila) for fila in cursor.fetchall()]


def registrar_ip_bloqueada(ip, motivo=""):
    """
    Persiste una IP en la lista negra (sobrevive reinicios del servidor).

    Args:
        ip (str): Dirección IPv4/IPv6 del visitante bloqueado.
        motivo (str): Texto opcional (p. ej. origen del bloqueo en monitor).
    """
    if not ip:
        return
    marca = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            """
            INSERT INTO ips_bloqueadas (ip, fecha, motivo)
            VALUES (?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                fecha = excluded.fecha,
                motivo = excluded.motivo;
            """,
            (ip, marca, motivo or ""),
        )
        conexion.commit()


def ip_esta_bloqueada_en_bd(ip):
    """True si la IP figura en la tabla persistente ips_bloqueadas."""
    if not ip:
        return False
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            "SELECT 1 FROM ips_bloqueadas WHERE ip = ? LIMIT 1;",
            (ip,),
        )
        return cursor.fetchone() is not None


def desbloquear_ip_persistente(ip):
    """
    Elimina una IP de la lista negra persistente (flujo «Volver a intentar»).

    Returns:
        bool: True si existía y se eliminó.
    """
    if not ip:
        return False
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute("DELETE FROM ips_bloqueadas WHERE ip = ?;", (ip,))
        conexion.commit()
        return cursor.rowcount > 0


def listar_ips_bloqueadas():
    """Devuelve todas las IPs bloqueadas almacenadas en SQLite."""
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute("SELECT ip FROM ips_bloqueadas ORDER BY fecha DESC;")
        return [fila["ip"] for fila in cursor.fetchall()]
