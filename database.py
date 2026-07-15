"""
Módulo de acceso a datos para FlyPaper.

Esquema relacional SQLite: eventos del honeypot, usuarios/posts del entorno falso,
flags de CTF y tablas auxiliares. Incluye población inicial del escenario de laboratorio.
"""

import bcrypt
import hashlib
import json
import logging
import os
import re
import secrets
import sqlite3
import string
from datetime import datetime, timedelta
from pathlib import Path

from detector import (
    GRAVEDAD_ALTA,
    GRAVEDAD_CRITICA,
    GRAVEDAD_SOSPECHOSO,
    normalizar_gravedad_almacenada,
    normalizar_gravedad_filtro_api,
    prioridad_gravedad,
)
from timezone_fp import (
    ZONA_NOMBRE,
    ahora_naive,
    fecha_hoy,
    formatear_marca,
    hace as hace_tiempo,
    marca_ahora,
    minutos_desde_marca,
)

# Nombres canónicos de los dos retos CTF del laboratorio.
RETO_CTF_SQLI = "Inyección de Datos (UNION)"
RETO_CTF_SQLI_LEGACY = "SQLi"
RETO_CTF_PATH_TRAVERSAL = "Path Traversal"
# Único usuario público del reto UNION: password_hash = cuerpo de la flag SQLi.
USUARIO_CTF_SQLI = "SQLi_flag"
PISTA_CTF_SQLI_BREVE = (
    "Usa UNION en /search para leer la tabla usuarios y localizar al usuario SQLi_flag."
)
ROL_USUARIO_NORMAL = "usuario"
ROL_USUARIO_ADMIN_BD = "admin"
# Cuentas reales de panel / monitor viven solo en `usuarios_privados`.
ROL_PRIV_ADMIN_PANEL = "admin_panel"
ROL_PRIV_MONITOR = "monitor"
# Cuentas legacy de laboratorio eliminadas del bootstrap (admin/analyst).
USUARIOS_PRIVADOS_LEGACY_ELIMINAR = ("admin", "analyst")

logger = logging.getLogger(__name__)

# Metadatos de super-administradores; contraseñas solo vía variables de entorno.
_SUPER_ADMIN_BOOTSTRAP_ENV = (
    ("Mart.Angel", "INITIAL_ADMIN_ANGEL_PASSWORD", "Martí Angel", "mart.angel@flypaper.internal"),
    ("Best.Carlos", "INITIAL_ADMIN_CARLOS_PASSWORD", "Best Carlos", "best.carlos@flypaper.internal"),
)
# Formato estricto: flag{10 caracteres alfanuméricos} (grupo 1 = cuerpo de la flag).
PATRON_FLAG_CTF = re.compile(r"^flag\{([a-zA-Z0-9]{10})\}$")


RUTA_RAIZ_PROYECTO = Path(__file__).resolve().parent
RUTA_BD = RUTA_RAIZ_PROYECTO / "flypaper.db"
# Credenciales /admin y /monitor: BD separada, no alcanzable por SQLi en el buscador.
RUTA_BD_PRIVADA = RUTA_RAIZ_PROYECTO / "flypaper_priv.db"
# Contenido señuelo de /secure/*: sin usuarios, flags ni datos del laboratorio CTF.
RUTA_BD_AUTOBAN = RUTA_RAIZ_PROYECTO / "flypaper_autoban.db"
# Cuentas reales del portal público (registro /register con bcrypt).
RUTA_BD_USERS = RUTA_RAIZ_PROYECTO / "flypaper_users.db"

# Validación de nombre de usuario en el registro abierto.
_PATRON_USERNAME_REGISTRO = re.compile(r"^[a-zA-Z0-9_]{3,20}$")

# Tope de cuentas en flypaper_users.db (protección contra saturación del registro).
LIMITE_USUARIOS_REGISTRADOS = 500


def obtener_conexion():
    """
    Crea una conexión SQLite con filas accesibles por nombre de columna.

    Returns:
        sqlite3.Connection: Conexión a `flypaper.db` (posts, usuarios públicos, CTF, etc.).
    """
    conexion = sqlite3.connect(RUTA_BD)
    conexion.row_factory = sqlite3.Row
    conexion.execute("PRAGMA foreign_keys = ON;")
    return conexion


def obtener_conexion_privada():
    """
    Conexión a la BD de cuentas privilegiadas (no usada por `/search`).

    Returns:
        sqlite3.Connection: Conexión a `flypaper_priv.db`.
    """
    conexion = sqlite3.connect(RUTA_BD_PRIVADA)
    conexion.row_factory = sqlite3.Row
    return conexion


def obtener_conexion_users():
    """
    Conexión a la BD de usuarios registrados vía /register (bcrypt).

    Returns:
        sqlite3.Connection: Conexión a `flypaper_users.db`.
    """
    conexion = sqlite3.connect(RUTA_BD_USERS)
    conexion.row_factory = sqlite3.Row
    return conexion


def inicializar_db_users():
    """Crea la tabla de usuarios registrados si no existe."""
    with obtener_conexion_users() as conexion:
        conexion.executescript(
            """
            CREATE TABLE IF NOT EXISTS usuarios_registrados (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                fecha_registro DATETIME,
                ultimo_login DATETIME,
                activo INTEGER DEFAULT 1
            );
            """
        )
        conexion.commit()


def obtener_conexion_autoban():
    """
    Conexión a la BD señuelo del auto-ban (aislada de flypaper.db).

    Solo contiene `ab_posts` y `ab_comentarios` con contenido genérico inventado.
    Los eventos de seguridad siguen registrándose en flypaper.db.

    Returns:
        sqlite3.Connection: Conexión a `flypaper_autoban.db`.
    """
    conexion = sqlite3.connect(RUTA_BD_AUTOBAN)
    conexion.row_factory = sqlite3.Row
    conexion.execute("PRAGMA foreign_keys = ON;")
    return conexion


def inicializar_db_autoban():
    """
    Crea el esquema de flypaper_autoban.db y lo puebla si está vacío.

    Datos ficticios sin relación con usuarios, flags ni credenciales del honeypot.
    """
    ddl_autoban = """
    CREATE TABLE IF NOT EXISTS ab_posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        titulo TEXT NOT NULL,
        contenido TEXT,
        autor TEXT,
        fecha DATETIME
    );

    CREATE TABLE IF NOT EXISTS ab_comentarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER NOT NULL,
        autor_nombre TEXT,
        contenido TEXT,
        fecha DATETIME,
        FOREIGN KEY (post_id) REFERENCES ab_posts(id)
    );
    """
    with obtener_conexion_autoban() as conexion:
        cursor = conexion.cursor()
        cursor.executescript(ddl_autoban)
        conexion.commit()
        _poblar_ab_datos_si_vacio(cursor)
        conexion.commit()


def _poblar_ab_datos_si_vacio(cursor):
    """Inserta posts y comentarios genéricos si ab_posts está vacía."""
    cursor.execute("SELECT COUNT(*) AS n FROM ab_posts;")
    if cursor.fetchone()["n"] > 0:
        return

    posts = [
        (
            "Buenas prácticas de ciberseguridad en entornos corporativos",
            (
                "La segmentación de red y la autenticación multifactor siguen siendo "
                "pilares básicos en cualquier plan de protección. Este artículo resume "
                "recomendaciones habituales para equipos de infraestructura y soporte."
            ),
            "Departamento de Seguridad TI",
            formatear_marca(hace_tiempo(days=12)),
        ),
        (
            "Migración a infraestructura en la nube: lecciones aprendidas",
            (
                "Tras un año de transición gradual, compartimos aprendizajes sobre "
                "costes, monitorización y gestión de identidades en proveedores cloud. "
                "El objetivo es documentar el proceso para futuros despliegues."
            ),
            "Equipo de Arquitectura",
            formatear_marca(hace_tiempo(days=28)),
        ),
        (
            "Gestión de parches y ventanas de mantenimiento",
            (
                "Coordinar actualizaciones sin interrumpir el servicio requiere "
                "calendarios claros y comunicación con las áreas de negocio. "
                "Aquí describimos un flujo de trabajo estándar para entornos híbridos."
            ),
            "Operaciones de Sistemas",
            formatear_marca(hace_tiempo(days=45)),
        ),
    ]
    cursor.executemany(
        """
        INSERT INTO ab_posts (titulo, contenido, autor, fecha)
        VALUES (?, ?, ?, ?);
        """,
        posts,
    )

    comentarios_por_post = [
        [
            ("Marcos Vidal", "Muy útil el repaso de MFA. Lo compartiré con mi equipo."),
            ("Laura Núñez", "Faltaría un apartado sobre respuesta ante incidentes."),
        ],
        [
            ("Pablo Serrano", "La parte de costes cloud coincide con lo que vimos en auditoría."),
            ("Irene Molina", "¿Hay plantilla para el checklist de migración?"),
        ],
        [
            ("Diego Castaño", "Las ventanas de mantenimiento los viernes funcionan bien aquí."),
            ("Sofía Ríos", "Documentación clara; gracias por publicarlo."),
        ],
    ]

    for post_id, comentarios in enumerate(comentarios_por_post, start=1):
        for idx, (autor, texto) in enumerate(comentarios):
            cursor.execute(
                """
                INSERT INTO ab_comentarios (post_id, autor_nombre, contenido, fecha)
                VALUES (?, ?, ?, ?);
                """,
                (
                    post_id,
                    autor,
                    texto,
                    formatear_marca(hace_tiempo(days=10 - idx, hours=post_id * 3)),
                ),
            )


def obtener_ab_posts():
    """Listado de publicaciones de la zona señuelo /secure/blog."""
    with obtener_conexion_autoban() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            """
            SELECT id, titulo, contenido, autor, fecha
            FROM ab_posts
            ORDER BY fecha DESC, id DESC;
            """
        )
        return [dict(fila) for fila in cursor.fetchall()]


def obtener_ab_post_por_id(post_id):
    """Devuelve un post de ab_posts por id o None."""
    try:
        id_norm = int(post_id)
    except (TypeError, ValueError):
        return None
    with obtener_conexion_autoban() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            """
            SELECT id, titulo, contenido, autor, fecha
            FROM ab_posts
            WHERE id = ?;
            """,
            (id_norm,),
        )
        fila = cursor.fetchone()
        return dict(fila) if fila else None


def obtener_ab_comentarios_post(post_id):
    """Comentarios visibles de un post en ab_comentarios."""
    try:
        id_norm = int(post_id)
    except (TypeError, ValueError):
        return []
    with obtener_conexion_autoban() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            """
            SELECT id, autor_nombre, contenido, fecha
            FROM ab_comentarios
            WHERE post_id = ?
            ORDER BY fecha ASC, id ASC;
            """,
            (id_norm,),
        )
        return [
            {
                "nombre": fila["autor_nombre"] or "Anónimo",
                "comentario": fila["contenido"] or "",
                "fecha": fila["fecha"] or "",
            }
            for fila in cursor.fetchall()
        ]


def guardar_ab_comentario(post_id, autor_nombre, contenido):
    """Persiste un comentario en ab_comentarios (zona auto-ban)."""
    try:
        id_norm = int(post_id)
    except (TypeError, ValueError):
        return False
    texto = (contenido or "").strip()
    if not texto:
        return False
    with obtener_conexion_autoban() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            """
            INSERT INTO ab_comentarios (post_id, autor_nombre, contenido, fecha)
            VALUES (?, ?, ?, ?);
            """,
            (
                id_norm,
                (autor_nombre or "").strip() or "Anónimo",
                texto,
                marca_ahora(),
            ),
        )
        conexion.commit()
    return True


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


def _asegurar_columnas_registro_peticiones(cursor):
    """Añade metadatos HTTP a `registro_peticiones` en bases de datos antiguas."""
    cursor.execute("PRAGMA table_info(registro_peticiones);")
    columnas = {fila[1] for fila in cursor.fetchall()}
    nuevas = (
        ("user_agent", "TEXT"),
        ("payload", "TEXT"),
        ("headers", "TEXT"),
        ("tipo_ataque", "TEXT"),
        ("gravedad", "TEXT"),
        ("evento_id", "INTEGER"),
        ("usuario_activo", "TEXT"),
        ("sesion_id_corto", "TEXT"),
        ("tiempo_ms", "INTEGER"),
        ("tamano_respuesta_bytes", "INTEGER"),
        ("puerto_origen", "TEXT"),
    )
    for nombre, tipo_sql in nuevas:
        if nombre not in columnas:
            cursor.execute(
                f"ALTER TABLE registro_peticiones ADD COLUMN {nombre} {tipo_sql};"
            )


def _asegurar_columna_ambito(cursor):
    """Añade la columna `ambito` a eventos y registro_peticiones si no existe."""
    for tabla in ("eventos", "registro_peticiones"):
        cursor.execute(f"PRAGMA table_info({tabla});")
        columnas = {fila[1] for fila in cursor.fetchall()}
        if "ambito" not in columnas:
            try:
                cursor.execute(
                    f"ALTER TABLE {tabla} ADD COLUMN ambito TEXT DEFAULT 'publico';"
                )
            except Exception:
                pass


def _asegurar_columna_rol_usuarios(cursor):
    """Añade la columna `rol` a `usuarios` en bases de datos creadas antes del panel admin."""
    cursor.execute("PRAGMA table_info(usuarios);")
    columnas = {fila[1] for fila in cursor.fetchall()}
    if "rol" not in columnas:
        cursor.execute(
            f"ALTER TABLE usuarios ADD COLUMN rol TEXT DEFAULT '{ROL_USUARIO_NORMAL}';"
        )
    cursor.execute(
        f"UPDATE usuarios SET rol = '{ROL_USUARIO_NORMAL}' WHERE rol IS NULL OR rol = '';"
    )


def _hash_md5_password(password):
    """Hash MD5 de contraseña (formato almacenado para usuarios corporativos)."""
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def inicializar_db():
    """
    Crea todas las tablas del modelo relacional si no existen.

    Tablas en flypaper.db: eventos, usuarios, posts, comentarios, flags, etc.
    Cuentas privilegiadas en flypaper_priv.db (tabla usuarios_privados).
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
        gravedad TEXT,
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
        avatar_url TEXT,
        rol TEXT DEFAULT 'usuario'
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

    CREATE TABLE IF NOT EXISTS objetivos_completados (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        usuario_id TEXT NOT NULL,
        flag_id INTEGER NOT NULL,
        fecha DATETIME,
        UNIQUE(usuario_id, flag_id),
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

    CREATE TABLE IF NOT EXISTS resumenes_diarios_ia (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fecha TEXT UNIQUE NOT NULL,
        resumen TEXT NOT NULL,
        total_eventos INTEGER DEFAULT 0,
        generado_en DATETIME
    );

    CREATE TABLE IF NOT EXISTS resumenes_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fecha TEXT NOT NULL,
        tipo TEXT NOT NULL DEFAULT 'automatico',
        total_eventos INTEGER DEFAULT 0,
        caracteres INTEGER DEFAULT 0,
        generado_en TEXT NOT NULL,
        ok INTEGER DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS registro_peticiones (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        ruta TEXT,
        metodo TEXT,
        codigo_http INTEGER,
        user_agent TEXT,
        payload TEXT,
        headers TEXT,
        tipo_ataque TEXT,
        gravedad TEXT,
        evento_id INTEGER,
        usuario_activo TEXT,
        sesion_id_corto TEXT,
        tiempo_ms INTEGER,
        tamano_respuesta_bytes INTEGER,
        puerto_origen TEXT,
        timestamp DATETIME
    );
    """

    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.executescript(ddl_tablas)
        _asegurar_columna_gravedad(cursor)
        _asegurar_columna_rol_usuarios(cursor)
        _asegurar_columnas_registro_peticiones(cursor)
        _asegurar_columna_ambito(cursor)
        cursor.execute(
            "UPDATE eventos SET tipo_ataque = 'Tráfico Normal' WHERE tipo_ataque = 'Otro';"
        )
        cursor.execute(
            "UPDATE registro_peticiones SET tipo_ataque = 'Tráfico Normal' "
            "WHERE tipo_ataque = 'Otro';"
        )
        conexion.commit()

    _inicializar_bd_privada()
    _migrar_privados_desde_bd_publica_si_existe()
    poblar_entorno_simulacion()
    asegurar_flags_ctf_dinamicas()
    _migrar_reto_sqli_legacy()
    asegurar_usuario_ctf_sqli_flag()
    asegurar_usuarios_corporativos_extendidos()
    asegurar_cuentas_privilegiadas()
    _migrar_cuentas_privilegiadas_fuera_de_usuarios()
    _migrar_gravedades_eventos_legacy()
    inicializar_db_autoban()
    inicializar_db_users()


def _username_existe_en_usuarios_publicos(username):
    """True si el nombre ya figura en la tabla señuelo `usuarios` de flypaper.db."""
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            "SELECT 1 FROM usuarios WHERE username = ? LIMIT 1;",
            (username,),
        )
        return cursor.fetchone() is not None


def contar_usuarios_registrados():
    """
    Cuenta todas las filas de usuarios_registrados (activos e inactivos).

    Returns:
        int: Total de registros en flypaper_users.db.
    """
    with obtener_conexion_users() as conexion:
        cursor = conexion.cursor()
        cursor.execute("SELECT COUNT(*) AS total FROM usuarios_registrados;")
        fila = cursor.fetchone()
    return int(fila["total"]) if fila else 0


def limpiar_usuarios_inactivos():
    """
    Elimina cuentas activas sin uso en los últimos 60 días.

    Criterios:
    - ultimo_login anterior a hace 60 días, o
    - sin ultimo_login y fecha_registro anterior a hace 60 días.

    Returns:
        int: Número de filas eliminadas.
    """
    fecha_limite = formatear_marca(hace_tiempo(days=60))
    with obtener_conexion_users() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            """
            DELETE FROM usuarios_registrados
            WHERE activo = 1
              AND (
                    (ultimo_login IS NOT NULL AND ultimo_login < ?)
                 OR (ultimo_login IS NULL AND fecha_registro < ?)
              );
            """,
            (fecha_limite, fecha_limite),
        )
        eliminados = cursor.rowcount
        conexion.commit()
    print(f"[FlyPaper] Limpieza usuarios inactivos: {eliminados} eliminado(s)")
    return eliminados


def registrar_usuario(username, password):
    """
    Alta de usuario en flypaper_users.db con contraseña bcrypt.

    No inserta en flypaper.db: los registrados no aparecen en /admin/usuarios.

    Returns:
        dict: {"exito": True} o {"exito": False, "mensaje": "..."}
    """
    nombre = (username or "").strip()
    clave = password or ""

    if not _PATRON_USERNAME_REGISTRO.match(nombre):
        return {
            "exito": False,
            "mensaje": "Usuario inválido: use 3-20 caracteres (letras, números y _).",
        }
    if len(clave) < 8:
        return {
            "exito": False,
            "mensaje": "La contraseña debe tener al menos 8 caracteres.",
        }

    total = contar_usuarios_registrados()
    if total >= LIMITE_USUARIOS_REGISTRADOS:
        return {
            "exito": False,
            "mensaje": (
                "El registro está temporalmente cerrado. Inténtalo más tarde."
            ),
        }

    with obtener_conexion_users() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            "SELECT 1 FROM usuarios_registrados WHERE username = ? LIMIT 1;",
            (nombre,),
        )
        if cursor.fetchone():
            return {
                "exito": False,
                "mensaje": "Ese nombre de usuario ya está registrado.",
            }

    if _username_existe_en_usuarios_publicos(nombre):
        return {
            "exito": False,
            "mensaje": "Ese nombre de usuario no está disponible.",
        }

    # gensalt() usa cost factor 12 por defecto.
    hash_bytes = bcrypt.hashpw(clave.encode("utf-8"), bcrypt.gensalt())
    password_hash = hash_bytes.decode("utf-8")
    marca = marca_ahora()

    try:
        with obtener_conexion_users() as conexion:
            cursor = conexion.cursor()
            cursor.execute(
                """
                INSERT INTO usuarios_registrados (
                    username, password_hash, fecha_registro, activo
                ) VALUES (?, ?, ?, 1);
                """,
                (nombre, password_hash, marca),
            )
            conexion.commit()
    except sqlite3.IntegrityError:
        return {
            "exito": False,
            "mensaje": "Ese nombre de usuario ya está registrado.",
        }

    return {"exito": True}


def verificar_usuario_registrado(username, password):
    """
    Valida credenciales contra usuarios_registrados (bcrypt).

    Returns:
        dict | None: {"username": str, "rol": "usuario"} si es correcto; None si falla.
    """
    nombre = (username or "").strip()
    clave = password or ""
    if not nombre or not clave:
        return None

    with obtener_conexion_users() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            """
            SELECT username, password_hash
            FROM usuarios_registrados
            WHERE username = ? AND activo = 1
            LIMIT 1;
            """,
            (nombre,),
        )
        fila = cursor.fetchone()

    if fila is None:
        return None

    try:
        hash_almacenado = fila["password_hash"].encode("utf-8")
        if not bcrypt.checkpw(clave.encode("utf-8"), hash_almacenado):
            return None
    except (ValueError, TypeError):
        return None

    with obtener_conexion_users() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            "UPDATE usuarios_registrados SET ultimo_login = ? WHERE username = ?;",
            (marca_ahora(), nombre),
        )
        conexion.commit()

    return {"username": fila["username"], "rol": ROL_USUARIO_NORMAL}


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
            """
            SELECT flag_string FROM flags
            WHERE reto_nombre = ?
            ORDER BY id ASC
            LIMIT 1;
            """,
            (reto_nombre,),
        )
        fila = cursor.fetchone()
        return fila["flag_string"] if fila else None


def _consolidar_flags_reto_duplicadas(reto_nombre):
    """Elimina filas duplicadas en `flags` para un mismo reto (conserva la de menor id)."""
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            "SELECT id FROM flags WHERE reto_nombre = ? ORDER BY id ASC;",
            (reto_nombre,),
        )
        ids = [fila["id"] for fila in cursor.fetchall()]
        if len(ids) <= 1:
            return
        for dup_id in ids[1:]:
            cursor.execute(
                "DELETE FROM flags_resueltas WHERE flag_id = ?;",
                (dup_id,),
            )
            cursor.execute("DELETE FROM flags WHERE id = ?;", (dup_id,))
        conexion.commit()


def asegurar_flags_ctf_dinamicas():
    """
    Garantiza en BD las flags de SQLi y Path Traversal con formato flag{...} aleatorio.

    Inserta retos faltantes o sustituye flags legacy (p. ej. FLAG{...} estáticas).
    """
    _migrar_reto_sqli_legacy()
    _consolidar_flags_reto_duplicadas(RETO_CTF_SQLI)

    definicion_retos = [
        (
            RETO_CTF_SQLI,
            100,
            PISTA_CTF_SQLI_BREVE,
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

    _consolidar_flags_reto_duplicadas(RETO_CTF_SQLI)
    asegurar_usuario_ctf_sqli_flag()


def _es_username_admin_publico(username):
    """True si el username sugiere admin/administrador (no válido como vector del reto)."""
    u = (username or "").strip().lower()
    if not u or u == USUARIO_CTF_SQLI.lower():
        return False
    if u in ("admin", "administrador"):
        return True
    return "admin" in u or "administrador" in u


def purgar_usuarios_admin_de_tabla_publica():
    """
    Elimina de `usuarios` (BD pública) cuentas admin/administrador o variantes.

    Las cuentas reales de panel viven solo en flypaper_priv.db.
    """
    eliminados = 0
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute("SELECT id, username FROM usuarios;")
        for fila in cursor.fetchall():
            if _es_username_admin_publico(fila["username"]):
                cursor.execute("DELETE FROM usuarios WHERE id = ?;", (fila["id"],))
                eliminados += 1
        conexion.commit()
    return eliminados


def _migrar_reto_sqli_legacy():
    """Renombra el reto SQLi legacy y actualiza la pista breve en flags."""
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            """
            UPDATE flags
            SET reto_nombre = ?, pista = ?
            WHERE reto_nombre IN (?, ?);
            """,
            (RETO_CTF_SQLI, PISTA_CTF_SQLI_BREVE, RETO_CTF_SQLI_LEGACY, "sqli"),
        )
        conexion.commit()
    _consolidar_flags_reto_duplicadas(RETO_CTF_SQLI)


def _obtener_flag_sqli_activa():
    """Flag del reto UNION (nombre actual o legacy en BD)."""
    flag = obtener_flag_string_por_reto(RETO_CTF_SQLI)
    if flag:
        return flag
    return obtener_flag_string_por_reto(RETO_CTF_SQLI_LEGACY)


def asegurar_usuario_ctf_sqli_flag():
    """
    Usuario SQLi_flag en tabla pública: password_hash = cuerpo de la flag del reto UNION.

    Purga usuarios admin/administrador y deja este como vector de resolución del reto.
    """
    purgar_usuarios_admin_de_tabla_publica()

    flag_sqli = _obtener_flag_sqli_activa()
    if not flag_sqli:
        return

    password_dinamica = extraer_cuerpo_de_flag(flag_sqli)
    if not password_dinamica:
        return

    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            "SELECT id FROM usuarios WHERE username = ?;",
            (USUARIO_CTF_SQLI,),
        )
        if cursor.fetchone():
            cursor.execute(
                """
                UPDATE usuarios
                SET password_hash = ?, nombre = ?, apellido = ?,
                    departamento = ?, email = ?, avatar_url = ?, rol = ?
                WHERE username = ?;
                """,
                (
                    password_dinamica,
                    "Usuario",
                    "CTF",
                    "Seguridad",
                    "sqli_flag@flypaper.internal",
                    "/static/avatars/sqli.png",
                    ROL_USUARIO_NORMAL,
                    USUARIO_CTF_SQLI,
                ),
            )
        else:
            cursor.execute(
                """
                INSERT INTO usuarios (
                    username, password_hash, nombre, apellido,
                    departamento, email, avatar_url, rol
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    USUARIO_CTF_SQLI,
                    password_dinamica,
                    "Usuario",
                    "CTF",
                    "Seguridad",
                    "sqli_flag@flypaper.internal",
                    "/static/avatars/sqli.png",
                    ROL_USUARIO_NORMAL,
                ),
            )
        conexion.commit()


def asegurar_usuarios_corporativos_extendidos():
    """
    Inserta o actualiza usuarios corporativos (MD5) en tabla `usuarios` (sin cuentas admin).

    El vector del reto UNION lo gestiona asegurar_usuario_ctf_sqli_flag (SQLi_flag).
    """
    usuarios_nuevos = [
        (
            "elena.mora",
            "Kp9#mora2026",
            "Elena",
            "Mora",
            "IT",
            "elena.mora@flypaper.io",
            "/static/avatars/it.png",
            ROL_USUARIO_NORMAL,
        ),
        (
            "pablo.soto",
            "S0t0Fly!88",
            "Pablo",
            "Soto",
            "Ventas",
            "pablo.soto@flypaper.io",
            "/static/avatars/ventas.png",
            ROL_USUARIO_NORMAL,
        ),
        (
            "ines.calvo",
            "InesCalvo77",
            "Inés",
            "Calvo",
            "RRHH",
            "ines.calvo@flypaper.io",
            "/static/avatars/rrhh.png",
            ROL_USUARIO_NORMAL,
        ),
        (
            "ruben.fuentes",
            "RbFu3nt3s",
            "Rubén",
            "Fuentes",
            "IT",
            "ruben.fuentes@flypaper.io",
            "/static/avatars/it.png",
            ROL_USUARIO_NORMAL,
        ),
        (
            "clara.diaz",
            "ClaraD1az55",
            "Clara",
            "Díaz",
            "Ventas",
            "clara.diaz@flypaper.io",
            "/static/avatars/ventas.png",
            ROL_USUARIO_NORMAL,
        ),
    ]

    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        for (
            username,
            password_plano,
            nombre,
            apellido,
            departamento,
            email,
            avatar_url,
            rol,
        ) in usuarios_nuevos:
            if _es_username_admin_publico(username) or username == USUARIO_CTF_SQLI:
                continue
            hash_md5 = _hash_md5_password(password_plano)
            cursor.execute(
                "SELECT id FROM usuarios WHERE username = ?;",
                (username,),
            )
            if cursor.fetchone():
                cursor.execute(
                    """
                    UPDATE usuarios
                    SET password_hash = ?, nombre = ?, apellido = ?,
                        departamento = ?, email = ?, avatar_url = ?, rol = ?
                    WHERE username = ?;
                    """,
                    (
                        hash_md5,
                        nombre,
                        apellido,
                        departamento,
                        email,
                        avatar_url,
                        rol,
                        username,
                    ),
                )
            else:
                cursor.execute(
                    """
                    INSERT INTO usuarios (
                        username, password_hash, nombre, apellido,
                        departamento, email, avatar_url, rol
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        username,
                        hash_md5,
                        nombre,
                        apellido,
                        departamento,
                        email,
                        avatar_url,
                        rol,
                    ),
                )
        conexion.commit()


def obtener_usuarios_para_panel_admin():
    """
    Lista usuarios públicos para /admin/usuarios (sin password_hash).

    Returns:
        list[dict]: id, username, nombre, apellido, departamento, email, avatar_url, rol.
    """
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            """
            SELECT id, username, nombre, apellido, departamento, email, avatar_url, rol
            FROM usuarios
            ORDER BY departamento, username;
            """
        )
        return [dict(fila) for fila in cursor.fetchall()]


def verificar_credencial_usuario_bd(username, password):
    """
    Valida usuario/contraseña contra la tabla `usuarios` (hash MD5).

    El señuelo CTF guarda la flag en texto plano; no coincide con MD5 del formulario.

    Returns:
        dict | None: username y rol ('admin' | 'usuario').
    """
    if not username or password is None:
        return None

    hash_md5 = _hash_md5_password(password)
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            """
            SELECT username, rol
            FROM usuarios
            WHERE username = ? AND password_hash = ?;
            """,
            (username.strip(), hash_md5),
        )
        fila = cursor.fetchone()
        if not fila:
            return None
        rol = (fila["rol"] or ROL_USUARIO_NORMAL).strip().lower()
        if rol not in (ROL_USUARIO_ADMIN_BD, ROL_USUARIO_NORMAL):
            rol = ROL_USUARIO_NORMAL
        return {"username": fila["username"], "rol": rol}


def _inicializar_bd_privada():
    """Crea `usuarios_privados` en flypaper_priv.db (aislada del buscador SQLi)."""
    ddl = """
    CREATE TABLE IF NOT EXISTS usuarios_privados (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        rol TEXT NOT NULL,
        redirige TEXT,
        nombre TEXT,
        email TEXT
    );

    CREATE TABLE IF NOT EXISTS codigos_2fa (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        codigo TEXT NOT NULL,
        creado_en DATETIME NOT NULL,
        usado INTEGER DEFAULT 0
    );
    """
    with obtener_conexion_privada() as conexion:
        conexion.executescript(ddl)
        conexion.commit()


def _migrar_privados_desde_bd_publica_si_existe():
    """Copia filas legacy de usuarios_privados en flypaper.db hacia flypaper_priv.db."""
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='usuarios_privados';"
        )
        if not cursor.fetchone():
            return
        cursor.execute("SELECT * FROM usuarios_privados;")
        filas = cursor.fetchall()
        conexion.execute("DROP TABLE usuarios_privados;")
        conexion.commit()

    if not filas:
        return

    with obtener_conexion_privada() as priv:
        pc = priv.cursor()
        for fila in filas:
            pc.execute(
                """
                INSERT OR IGNORE INTO usuarios_privados (
                    username, password_hash, rol, redirige, nombre, email
                ) VALUES (?, ?, ?, ?, ?, ?);
                """,
                (
                    fila["username"],
                    fila["password_hash"],
                    fila["rol"],
                    fila["redirige"],
                    fila["nombre"],
                    fila["email"],
                ),
            )
        priv.commit()


def _hash_contrasena_privada(password: str) -> str:
    """Genera hash bcrypt (utf-8) para usuarios_privados."""
    hash_bytes = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    return hash_bytes.decode("utf-8")


def _verificar_hash_privado(password: str, hash_almacenado: str) -> bool:
    """Compara contraseña en texto plano con hash bcrypt almacenado."""
    if password is None or not hash_almacenado:
        return False
    try:
        return bcrypt.checkpw(
            password.encode("utf-8"),
            hash_almacenado.encode("utf-8"),
        )
    except (ValueError, TypeError, AttributeError):
        return False


def _cuentas_super_admin_bootstrap():
    """
    Super-administradores SOC para bootstrapping inicial.

    Las contraseñas se leen de variables de entorno (nunca del código fuente).
    Si falta una variable, se omite esa cuenta y se registra un warning.
    """
    cuentas = []
    for username, env_key, nombre, email in _SUPER_ADMIN_BOOTSTRAP_ENV:
        password = os.getenv(env_key)
        if not password or not str(password).strip():
            logger.warning(
                "Bootstrap SOC: omitida cuenta %s (%s no definida en el entorno).",
                username,
                env_key,
            )
            continue
        cuentas.append(
            (
                username,
                str(password).strip(),
                ROL_PRIV_ADMIN_PANEL,
                "/admin",
                nombre,
                email,
            )
        )
    return tuple(cuentas)


def _eliminar_cuentas_privadas_legacy(cursor):
    """Elimina cuentas de laboratorio obsoletas de flypaper_priv.db."""
    for username in USUARIOS_PRIVADOS_LEGACY_ELIMINAR:
        cursor.execute(
            "DELETE FROM usuarios_privados WHERE username = ?;",
            (username,),
        )
        cursor.execute(
            "DELETE FROM codigos_2fa WHERE username = ?;",
            (username,),
        )


def asegurar_cuentas_privilegiadas():
    """
    Bootstrap seguro de super-administradores en flypaper_priv.db.

    - Elimina cuentas legacy (admin/analyst).
    - Crea Mart.Angel y Best.Carlos solo si no existen (hash bcrypt, sin texto plano).
    - No sobrescribe contraseñas de cuentas ya existentes.
    """
    with obtener_conexion_privada() as conexion:
        cursor = conexion.cursor()
        _eliminar_cuentas_privadas_legacy(cursor)

        for username, password, rol, redirige, nombre, email in _cuentas_super_admin_bootstrap():
            cursor.execute(
                "SELECT id FROM usuarios_privados WHERE username = ?;",
                (username,),
            )
            if cursor.fetchone():
                continue
            password_hash = _hash_contrasena_privada(password)
            cursor.execute(
                """
                INSERT INTO usuarios_privados (
                    username, password_hash, rol, redirige, nombre, email
                ) VALUES (?, ?, ?, ?, ?, ?);
                """,
                (username, password_hash, rol, redirige, nombre, email),
            )
        conexion.commit()


def _migrar_cuentas_privilegiadas_fuera_de_usuarios():
    """
    En BDs antiguas, quita de `usuarios` filas que duplican cuentas de `usuarios_privados`.

    También elimina usuarios admin/administrador de la tabla pública (vector: SQLi_flag).
    """
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            "DELETE FROM usuarios WHERE username IN (?, ?);",
            ("analyst", "admin"),
        )
        conexion.commit()
    purgar_usuarios_admin_de_tabla_publica()
    _migrar_reto_sqli_legacy()
    asegurar_usuario_ctf_sqli_flag()


def verificar_usuario_privado(username, password):
    """
    Autenticación contra `usuarios_privados` (panel /admin) con bcrypt.

    Returns:
        dict | None: {"rol", "redirige", "username"} si las credenciales son válidas.
    """
    nombre = (username or "").strip()
    clave = password or ""
    if not nombre or not clave:
        return None
    with obtener_conexion_privada() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            """
            SELECT username, password_hash, rol, redirige
            FROM usuarios_privados
            WHERE username = ?;
            """,
            (nombre,),
        )
        fila = cursor.fetchone()
        if not fila:
            return None
        if not _verificar_hash_privado(clave, fila["password_hash"]):
            return None
        redirige = fila["redirige"]
        if not redirige:
            redirige = "/admin"
        return {
            "username": fila["username"],
            "rol": fila["rol"],
            "redirige": redirige,
        }


def verificar_admin_panel_privado(username, password):
    """
    Autenticación exclusiva del portal /admin/login (rol admin_panel en flypaper_priv.db).

    Rechaza cuentas de monitor u otros roles aunque la contraseña sea correcta.
    """
    cuenta = verificar_usuario_privado(username, password)
    if cuenta is None or cuenta.get("rol") != ROL_PRIV_ADMIN_PANEL:
        return None
    return cuenta


def generar_codigo_2fa(username):
    """
    Genera un código OTP de 6 dígitos para verificación 2FA por Telegram.

    Invalida códigos previos del mismo usuario antes de insertar uno nuevo.

    Returns:
        str: Código numérico de 6 caracteres.
    """
    nombre = (username or "").strip()
    if not nombre:
        return None

    codigo = str(secrets.randbelow(1000000)).zfill(6)
    marca = marca_ahora()

    with obtener_conexion_privada() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            "DELETE FROM codigos_2fa WHERE username = ?;",
            (nombre,),
        )
        cursor.execute(
            """
            INSERT INTO codigos_2fa (username, codigo, creado_en, usado)
            VALUES (?, ?, ?, 0);
            """,
            (nombre, codigo, marca),
        )
        conexion.commit()

    return codigo


def verificar_codigo_2fa(username, codigo_introducido):
    """
    Valida un código 2FA pendiente (no usado y con menos de 5 minutos de antigüedad).

    Returns:
        bool: True si el código es correcto y se marca como usado.
    """
    nombre = (username or "").strip()
    codigo = (codigo_introducido or "").strip()
    if not nombre or not codigo:
        return False

    with obtener_conexion_privada() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            """
            SELECT id, creado_en
            FROM codigos_2fa
            WHERE username = ? AND usado = 0 AND codigo = ?
            LIMIT 1;
            """,
            (nombre, codigo),
        )
        fila = cursor.fetchone()
        if fila is None:
            return False

        minutos = minutos_desde_marca(fila["creado_en"])
        if minutos is None or minutos > 5:
            return False

        cursor.execute(
            "UPDATE codigos_2fa SET usado = 1 WHERE id = ?;",
            (fila["id"],),
        )
        conexion.commit()

    return True


def limpiar_codigos_2fa_expirados():
    """
    Elimina códigos 2FA usados o con más de 10 minutos de antigüedad.

    Returns:
        int: Filas eliminadas.
    """
    limite = formatear_marca(hace_tiempo(minutes=10))
    with obtener_conexion_privada() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            """
            DELETE FROM codigos_2fa
            WHERE creado_en < ? OR usado = 1;
            """,
            (limite,),
        )
        eliminados = cursor.rowcount
        conexion.commit()
    return eliminados


def crear_usuario_publico(username, password, email=None, nombre=None):
    """
    Alta de usuario en flypaper.db con privilegios mínimos (rol usuario).

    Returns:
        dict: {"exito": bool, "mensaje": str}
    """
    nombre_usuario = (username or "").strip()
    if not nombre_usuario or password is None or not str(password):
        return {"exito": False, "mensaje": "Usuario y contraseña son obligatorios."}
    if len(nombre_usuario) < 3:
        return {"exito": False, "mensaje": "El usuario debe tener al menos 3 caracteres."}
    if len(str(password)) < 6:
        return {"exito": False, "mensaje": "La contraseña debe tener al menos 6 caracteres."}

    hash_md5 = _hash_md5_password(password)
    correo = (email or "").strip() or f"{nombre_usuario}@flypaper.local"
    nombre_visible = (nombre or "").strip() or nombre_usuario

    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            "SELECT id FROM usuarios WHERE username = ?;",
            (nombre_usuario,),
        )
        if cursor.fetchone():
            return {"exito": False, "mensaje": "Ese nombre de usuario ya está registrado."}
        try:
            cursor.execute(
                """
                INSERT INTO usuarios (
                    username, password_hash, nombre, email, rol
                ) VALUES (?, ?, ?, ?, ?);
                """,
                (
                    nombre_usuario,
                    hash_md5,
                    nombre_visible,
                    correo,
                    ROL_USUARIO_NORMAL,
                ),
            )
            conexion.commit()
        except sqlite3.IntegrityError:
            return {"exito": False, "mensaje": "Ese nombre de usuario ya está registrado."}

    return {"exito": True, "mensaje": "Cuenta creada correctamente. Ya puedes iniciar sesión."}


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


def reiniciar_progreso_ctf_por_usuario(usuario_id):
    """
    Borra el progreso CTF de un usuario (QA / repetir pruebas en /objetivos).
    """
    if not usuario_id:
        return 0
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            "DELETE FROM objetivos_completados WHERE usuario_id = ?;",
            (usuario_id,),
        )
        eliminadas = cursor.rowcount
        conexion.commit()
        return eliminadas


def poblar_entorno_simulacion():
    """
    Inserta datos falsos del entorno corporativo y flags del CTF.

    Solo inserta si las tablas principales de simulación están vacías (usuarios, posts, flags).
    - 3 empleados en `usuarios` (sin cuentas privilegiadas; el señuelo admin se añade aparte).
    - Cuentas /admin y /monitor en `usuarios_privados` vía `asegurar_cuentas_privilegiadas()`.
    - 3 posts de blog sobre FlyPaper con comentarios de empleados.
    - 2 flags: SQLi (100 pts) y Path Traversal / LFI (150 pts).
    """
    marca = marca_ahora()

    with obtener_conexion() as conexion:
        cursor = conexion.cursor()

        # Solo sembrar si el entorno de simulación aún no tiene datos.
        if not (
            _tabla_vacia(cursor, "usuarios")
            and _tabla_vacia(cursor, "posts")
            and _tabla_vacia(cursor, "flags")
        ):
            return

        usuarios_seed = [
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
                username, password_hash, nombre, apellido,
                departamento, email, avatar_url, rol
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """,
            [(*fila, ROL_USUARIO_NORMAL) for fila in usuarios_seed],
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
                PISTA_CTF_SQLI_BREVE,
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
    gravedad=None,
    ambito="publico",
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
        gravedad (str|None): Crítica, Alta, Sospechoso; None para tráfico normal.
        ambito (str): publico | autoban | admin.
    """
    gravedad_guardar = normalizar_gravedad_almacenada(gravedad)
    payload_texto = _serializar_campo_json(payload)
    headers_texto = _serializar_campo_json(headers) if headers is not None else "{}"
    marca_tiempo = marca_ahora()
    ambito_guardar = (ambito or "publico").strip() or "publico"

    consulta = """
    INSERT INTO eventos (
        ip, ruta, metodo, payload, tipo_ataque, gravedad,
        user_agent, timestamp, pais, headers, ambito
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """

    valores = (
        ip,
        ruta,
        metodo,
        payload_texto,
        tipo_ataque,
        gravedad_guardar,
        user_agent,
        marca_tiempo,
        "",
        headers_texto,
        ambito_guardar,
    )

    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(consulta, valores)
        conexion.commit()
        return cursor.lastrowid


def vincular_registro_peticion_evento(peticion_id, evento_id):
    """Asocia una fila de actividad HTTP con su alerta en `eventos`."""
    try:
        id_pet = int(peticion_id)
        id_ev = int(evento_id)
    except (TypeError, ValueError):
        return
    if id_pet < 1 or id_ev < 1:
        return
    consulta = """
    UPDATE registro_peticiones
    SET evento_id = ?
    WHERE id = ? AND (evento_id IS NULL OR evento_id = 0);
    """
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(consulta, (id_ev, id_pet))
        conexion.commit()


def _ruta_es_zona_administracion(ruta):
    """
    True si la ruta pertenece a /admin o /monitor (y subrutas).

    Las rutas /secure/* tienen ámbito «autoban» y no se consideran zona admin.
    """
    path = (ruta or "").strip()
    return path.startswith("/admin") or path.startswith("/monitor")


def _sql_filtro_ambito_eventos(ambito, prefijo=""):
    """
    Fragmento SQL para filtrar eventos por columna `ambito`.

    publico: filas públicas o legacy sin ámbito.
  autoban/admin: solo ese ámbito.
    todo: sin filtro.
    """
    if ambito == "todo":
        return "1=1"
    col = f"{prefijo}." if prefijo else ""
    if ambito == "publico":
        return f"({col}ambito = 'publico' OR {col}ambito IS NULL)"
    if ambito == "autoban":
        return f"{col}ambito = 'autoban'"
    if ambito == "admin":
        return f"{col}ambito = 'admin'"
    raise ValueError(f"Ámbito de eventos no válido: {ambito}")


def _sql_filtro_ambito_peticiones(ambito, prefijo=""):
    """
    Fragmento SQL para filtrar registro_peticiones por columna `ambito`.

    publico: peticiones del portal o legacy sin ámbito.
    autoban/admin: solo ese ámbito.
    todo: sin filtro.
    """
    if ambito == "todo":
        return "1=1"
    col = f"{prefijo}." if prefijo else ""
    if ambito == "publico":
        return f"({col}ambito = 'publico' OR {col}ambito IS NULL)"
    if ambito == "autoban":
        return f"{col}ambito = 'autoban'"
    if ambito == "admin":
        return f"{col}ambito = 'admin'"
    raise ValueError(f"Ámbito de peticiones no válido: {ambito}")


_CAMPOS_REGISTRO_PETICIONES = """
    id, ip, ruta, metodo, codigo_http, user_agent, payload, headers,
    tipo_ataque, gravedad, evento_id, usuario_activo, sesion_id_corto, tiempo_ms,
    tamano_respuesta_bytes, puerto_origen, timestamp
"""

_FROM_REGISTRO_PETICIONES_CON_ALERTA = """
FROM registro_peticiones rp
LEFT JOIN eventos e ON e.id = (
    SELECT COALESCE(
        rp.evento_id,
        (
            SELECT e2.id
            FROM eventos e2
            WHERE TRIM(COALESCE(e2.ip, '')) = TRIM(COALESCE(rp.ip, ''))
              AND TRIM(COALESCE(e2.ruta, '')) = TRIM(COALESCE(rp.ruta, ''))
              AND TRIM(COALESCE(e2.metodo, '')) = TRIM(COALESCE(rp.metodo, ''))
              AND datetime(e2.timestamp) = datetime(rp.timestamp)
            ORDER BY e2.id DESC
            LIMIT 1
        )
    )
)
"""

_SELECT_REGISTRO_PETICIONES_CORRELADO = f"""
    rp.id,
    rp.ip,
    rp.ruta,
    rp.metodo,
    rp.codigo_http,
    rp.user_agent,
    rp.payload,
    rp.headers,
    CASE
        WHEN COALESCE(TRIM(rp.tipo_ataque), '') NOT IN ('', 'Otro', 'Tráfico Normal')
            THEN TRIM(rp.tipo_ataque)
        WHEN e.tipo_ataque IS NOT NULL AND TRIM(e.tipo_ataque) NOT IN ('', 'Otro', 'Tráfico Normal')
            THEN TRIM(e.tipo_ataque)
        ELSE COALESCE(NULLIF(TRIM(rp.tipo_ataque), ''), 'Tráfico Normal')
    END AS tipo_ataque,
    COALESCE(NULLIF(TRIM(rp.gravedad), ''), NULLIF(TRIM(e.gravedad), '')) AS gravedad,
    COALESCE(rp.evento_id, e.id) AS evento_id,
    rp.usuario_activo,
    rp.sesion_id_corto,
    rp.tiempo_ms,
    rp.tamano_respuesta_bytes,
    rp.puerto_origen,
    rp.timestamp
"""


def guardar_registro_peticion(
    ip,
    ruta,
    metodo,
    codigo_http=None,
    user_agent=None,
    payload=None,
    headers=None,
    tipo_ataque=None,
    usuario_activo=None,
    sesion_id_corto=None,
    tiempo_ms=None,
    tamano_respuesta_bytes=None,
    puerto_origen=None,
    gravedad=None,
    evento_id=None,
    ambito="publico",
):
    """Registra cada petición HTTP para el panel de actividad por IP del monitor."""
    payload_texto = _serializar_campo_json(payload) if payload is not None else ""
    headers_texto = _serializar_campo_json(headers) if headers is not None else ""
    tipo_norm = (tipo_ataque or "Tráfico Normal").strip() or "Tráfico Normal"
    gravedad_guardar = ""
    if tipo_norm not in ("Otro", "Tráfico Normal"):
        gravedad_guardar = normalizar_gravedad_almacenada(gravedad) or ""
    ambito_guardar = (ambito or "publico").strip() or "publico"
    consulta = """
    INSERT INTO registro_peticiones (
        ip, ruta, metodo, codigo_http, user_agent, payload, headers,
        tipo_ataque, gravedad, evento_id, usuario_activo, sesion_id_corto, tiempo_ms,
        tamano_respuesta_bytes, puerto_origen, timestamp, ambito
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            consulta,
            (
                ip or "",
                ruta or "",
                metodo or "",
                codigo_http,
                user_agent or "",
                payload_texto,
                headers_texto,
                tipo_norm,
                gravedad_guardar,
                int(evento_id) if evento_id else None,
                usuario_activo or "Invitado",
                sesion_id_corto or "",
                tiempo_ms,
                tamano_respuesta_bytes,
                puerto_origen or "",
                marca_ahora(),
                ambito_guardar,
            ),
        )
        conexion.commit()
        return cursor.lastrowid


def obtener_registros_peticiones(limite=2000, periodo=None, ambito="publico"):
    """
    Devuelve peticiones HTTP del período, filtradas por ámbito (publico | admin).

    Args:
        limite (int): Máximo de filas.
        periodo (str|None): hoy | ayer | semana | mes | todo
        ambito (str): «publico» (sin admin/monitor) o «admin» (solo esas rutas).

    Returns:
        list[dict]: Filas con id, ip, ruta, metodo, codigo_http, timestamp.
    """
    limite_norm = max(int(limite), 1)
    rangos = _rangos_periodo_monitor(periodo)
    where_sql, params = _where_periodo_sql(
        rangos["desde"], rangos["hasta"], prefijo="rp"
    )
    filtro_ambito = _sql_filtro_ambito_peticiones(ambito, prefijo="rp")

    partes = [filtro_ambito]
    if where_sql:
        partes.insert(0, where_sql)

    consulta = f"""
    SELECT {_SELECT_REGISTRO_PETICIONES_CORRELADO}
    {_FROM_REGISTRO_PETICIONES_CON_ALERTA}
    WHERE {" AND ".join(partes)}
    ORDER BY rp.timestamp DESC, rp.id DESC
    LIMIT ?;
    """
    params = list(params) + [limite_norm]

    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(consulta, params)
        return [dict(fila) for fila in cursor.fetchall()]


def obtener_registro_peticion_por_id(peticion_id):
    """Devuelve una petición HTTP por id o None."""
    try:
        id_norm = int(peticion_id)
    except (TypeError, ValueError):
        return None

    consulta = f"""
    SELECT {_SELECT_REGISTRO_PETICIONES_CORRELADO}
    {_FROM_REGISTRO_PETICIONES_CON_ALERTA}
    WHERE rp.id = ?;
    """
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(consulta, (id_norm,))
        fila = cursor.fetchone()
        return dict(fila) if fila else None


def _where_peticion_dia_exacto_sql(fecha, prefijo=""):
    """Filtro de un solo día calendario (YYYY-MM-DD) sobre timestamp."""
    fecha_limpia = (fecha or "").strip()
    if len(fecha_limpia) != 10:
        return None, []
    col = f"{prefijo}." if prefijo else ""
    return (
        f"strftime('%Y-%m-%d', {col}timestamp) = ?",
        [fecha_limpia],
    )


def listar_ips_peticiones_publicas():
    """IPs distintas con tráfico público (sin /admin ni /monitor)."""
    consulta = f"""
    SELECT DISTINCT TRIM(ip) AS ip
    FROM registro_peticiones
    WHERE {_sql_filtro_ambito_peticiones("publico")}
      AND ip IS NOT NULL AND TRIM(ip) != ''
    ORDER BY ip ASC;
    """
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(consulta)
        return [fila["ip"] for fila in cursor.fetchall() if fila["ip"]]


def listar_fechas_peticiones_publicas_por_ip(ip):
    """
    Días con peticiones públicas para una IP (YYYY-MM-DD, más reciente primero).
    """
    ip_limpia = (ip or "").strip()
    if not ip_limpia:
        return []

    consulta = f"""
    SELECT strftime('%Y-%m-%d', timestamp) AS fecha, COUNT(*) AS total
    FROM registro_peticiones
    WHERE {_sql_filtro_ambito_peticiones("publico")}
      AND TRIM(ip) = ?
      AND timestamp IS NOT NULL
    GROUP BY fecha
    ORDER BY fecha DESC;
    """
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(consulta, (ip_limpia,))
        return [
            {"fecha": fila["fecha"], "total": int(fila["total"] or 0)}
            for fila in cursor.fetchall()
            if fila["fecha"]
        ]


def obtener_peticiones_publicas_por_ip_y_fecha(ip, fecha, limite=10000):
    """
    Peticiones públicas de una IP en un único día (24 h calendario).

    Args:
        ip (str): Dirección IP exacta.
        fecha (str): YYYY-MM-DD.
        limite (int): Tope de filas.

    Returns:
        list[dict]: Filas completas de registro_peticiones.
    """
    ip_limpia = (ip or "").strip()
    where_dia, params_dia = _where_peticion_dia_exacto_sql(fecha, prefijo="rp")
    if not ip_limpia or where_dia is None:
        return []

    limite_norm = max(int(limite), 1)
    partes = [
        _sql_filtro_ambito_peticiones("publico", prefijo="rp"),
        "TRIM(rp.ip) = ?",
        where_dia,
    ]
    params = [ip_limpia] + params_dia

    consulta = f"""
    SELECT {_SELECT_REGISTRO_PETICIONES_CORRELADO}
    {_FROM_REGISTRO_PETICIONES_CON_ALERTA}
    WHERE {" AND ".join(partes)}
    ORDER BY rp.timestamp ASC, rp.id ASC
    LIMIT ?;
    """
    params.append(limite_norm)

    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(consulta, params)
        return [dict(fila) for fila in cursor.fetchall()]


# Períodos admitidos en los APIs del monitor (query ?periodo=).
PERIODOS_MONITOR_VALIDOS = ("hoy", "ayer", "semana", "mes", "todo")


def normalizar_periodo_monitor(periodo):
    """
    Normaliza el parámetro ?periodo= del monitor a un valor canónico.

    Acepta alias legacy del dashboard: 7d → semana, 30d → mes.
    """
    clave = (periodo or "todo").lower().strip()
    alias = {
        "todos": "todo",
        "7d": "semana",
        "30d": "mes",
        "semanal": "semana",
        "mensual": "mes",
    }
    clave = alias.get(clave, clave)
    if clave not in PERIODOS_MONITOR_VALIDOS:
        return "todo"
    return clave


def _rangos_periodo_monitor(periodo):
    """
    Calcula ventanas en Europe/Madrid para el período actual y el anterior (tarjetas).

    Returns:
        dict: claves periodo, desde, hasta, anterior_desde, anterior_hasta,
              etiqueta_variacion, modo_actividad ('hora' | 'dia').
    """
    clave = normalizar_periodo_monitor(periodo)
    ahora = ahora_naive()
    inicio_hoy = ahora.replace(hour=0, minute=0, second=0, microsecond=0)

    if clave == "hoy":
        return {
            "periodo": "hoy",
            "desde": inicio_hoy,
            "hasta": ahora,
            "anterior_desde": inicio_hoy - timedelta(days=1),
            "anterior_hasta": inicio_hoy,
            "etiqueta_variacion": "vs ayer",
            "modo_actividad": "hora",
        }
    if clave == "ayer":
        fin_ayer = inicio_hoy
        inicio_ayer = fin_ayer - timedelta(days=1)
        return {
            "periodo": "ayer",
            "desde": inicio_ayer,
            "hasta": fin_ayer,
            "anterior_desde": inicio_ayer - timedelta(days=1),
            "anterior_hasta": inicio_ayer,
            "etiqueta_variacion": "vs antierior",
            "modo_actividad": "hora",
        }
    if clave == "semana":
        return {
            "periodo": "semana",
            "desde": ahora - timedelta(days=7),
            "hasta": ahora,
            "anterior_desde": ahora - timedelta(days=14),
            "anterior_hasta": ahora - timedelta(days=7),
            "etiqueta_variacion": "vs semana anterior",
            "modo_actividad": "dia",
        }
    if clave == "mes":
        return {
            "periodo": "mes",
            "desde": ahora - timedelta(days=30),
            "hasta": ahora,
            "anterior_desde": ahora - timedelta(days=60),
            "anterior_hasta": ahora - timedelta(days=30),
            "etiqueta_variacion": "vs mes anterior",
            "modo_actividad": "dia",
        }

    return {
        "periodo": "todo",
        "desde": None,
        "hasta": None,
        "anterior_desde": ahora - timedelta(days=30),
        "anterior_hasta": ahora,
        "etiqueta_variacion": "vs últimos 30 días",
        "modo_actividad": "dia",
    }


def _fmt_ts_sql(dt):
    """Formatea datetime (Madrid) para comparar con columnas timestamp en SQLite."""
    if dt is None:
        return None
    return formatear_marca(dt)


def _where_periodo_sql(desde, hasta, prefijo=""):
    """Fragmento WHERE y parámetros para filtrar por rango temporal."""
    col = f"{prefijo}." if prefijo else ""
    if desde is None and hasta is None:
        return "", []
    if hasta is None:
        return f"{col}timestamp >= ?", [_fmt_ts_sql(desde)]
    return (
        f"{col}timestamp >= ? AND {col}timestamp < ?",
        [_fmt_ts_sql(desde), _fmt_ts_sql(hasta)],
    )


def _es_tipo_trafico_normal(tipo):
    """True si el tipo es tráfico legítimo (no incidente SOC)."""
    texto = str(tipo or "").strip().lower()
    return texto in ("otro", "tráfico normal")


def _filtrar_mapa_sin_trafico_normal(diccionario):
    """Elimina tráfico normal de agregaciones por tipo de ataque."""
    return {
        clave: valor
        for clave, valor in (diccionario or {}).items()
        if not _es_tipo_trafico_normal(clave)
    }


def _sql_excluir_rutas_zona_admin(prefijo=""):
    """Excluye tráfico de paneles /admin y /monitor (aislamiento SOC público)."""
    col = f"{prefijo}." if prefijo else ""
    return (
        f"({col}ruta NOT LIKE '/admin%' AND {col}ruta NOT LIKE '/monitor%')"
    )


def _sql_solo_rutas_zona_admin(prefijo=""):
    """Solo rutas de administración y monitor."""
    col = f"{prefijo}." if prefijo else ""
    return f"({col}ruta LIKE '/admin%' OR {col}ruta LIKE '/monitor%')"


def _sql_condicion_amenazas_base(prefijo=""):
    """Incidentes con severidad asignada (excluye tráfico normal y gravedad vacía)."""
    col = f"{prefijo}." if prefijo else ""
    return (
        f"({col}gravedad IS NOT NULL AND TRIM({col}gravedad) <> '') "
        f"AND LOWER(TRIM(COALESCE({col}tipo_ataque, ''))) NOT IN ('', 'otro', 'tráfico normal')"
    )


def _sql_condicion_amenazas_con_ambito(ambito="publico", prefijo=""):
    """Amenazas reales filtradas por columna `ambito`."""
    base = _sql_condicion_amenazas_base(prefijo)
    if ambito == "todo":
        return base
    return f"({base}) AND ({_sql_filtro_ambito_eventos(ambito, prefijo)})"


def _sql_condicion_amenazas_reales(prefijo=""):
    """
    Incidentes con severidad en tráfico público (sin /admin ni /monitor).

    Excluye tráfico normal, gravedad vacía y rutas de paneles internos.
    """
    col = f"{prefijo}." if prefijo else ""
    return (
        f"({col}gravedad IS NOT NULL AND TRIM({col}gravedad) <> '') "
        f"AND LOWER(TRIM(COALESCE({col}tipo_ataque, ''))) NOT IN ('', 'otro', 'tráfico normal') "
        f"AND {_sql_excluir_rutas_zona_admin(prefijo)}"
    )


def _migrar_gravedades_eventos_legacy():
    """Normaliza gravedades antiguas (CRÍTICO/ALTO/MEDIO/BAJO) y limpia tráfico normal."""
    mapa = [
        (GRAVEDAD_CRITICA, ("CRÍTICO", "CRITICO", "Crítica")),
        (GRAVEDAD_ALTA, ("ALTO", "Alta")),
        (GRAVEDAD_SOSPECHOSO, ("MEDIO", "BAJO", "Sospechoso")),
    ]
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        for canon, variantes in mapa:
            for variante in variantes:
                cursor.execute(
                    "UPDATE eventos SET gravedad = ? WHERE gravedad = ?;",
                    (canon, variante),
                )
        cursor.execute(
            """
            UPDATE eventos
            SET gravedad = NULL
            WHERE LOWER(TRIM(COALESCE(tipo_ataque, ''))) IN ('otro', 'tráfico normal')
               OR TRIM(COALESCE(gravedad, '')) = '';
            """
        )
        conexion.commit()


def _where_gravedad_monitor_sql(gravedad_filtro=None, ambito="publico"):
    """
    Fragmento WHERE + parámetros para listados del monitor.

    Sin filtro concreto: solo amenazas reales del ámbito. Con filtro: gravedad exacta.
    """
    condicion = _sql_condicion_amenazas_con_ambito(ambito)
    canon = normalizar_gravedad_filtro_api(gravedad_filtro)
    if canon:
        return f"{condicion} AND gravedad = ?", [canon]
    return condicion, []


def _filtro_sql_graficos_sin_trafico_normal(filtro_periodo, ambito="publico"):
    """
    Añade exclusión de ruido al fragmento WHERE del período (métricas SOC).

    Excluye tráfico normal y filas sin gravedad asignada, filtradas por ámbito.
    """
    excl = _sql_condicion_amenazas_con_ambito(ambito)
    if filtro_periodo:
        return f"{filtro_periodo} AND {excl}"
    return f" WHERE {excl}"


def _contar_eventos_amenazas_rango(cursor, desde, hasta, ambito="publico"):
    """Cuenta solo incidentes con severidad en el ámbito indicado."""
    where_sql, params = _where_periodo_sql(desde, hasta)
    amenazas = _sql_condicion_amenazas_con_ambito(ambito)
    if where_sql:
        cursor.execute(
            f"SELECT COUNT(*) AS n FROM eventos WHERE {where_sql} AND {amenazas};",
            params,
        )
    else:
        cursor.execute(f"SELECT COUNT(*) AS n FROM eventos WHERE {amenazas};")
    return cursor.fetchone()["n"]


def obtener_evento_por_id(evento_id):
    """
    Devuelve un único evento por su identificador o None si no existe.

    Args:
        evento_id (int): ID en la tabla `eventos`.

    Returns:
        dict | None: Fila del evento como diccionario.
    """
    try:
        id_norm = int(evento_id)
    except (TypeError, ValueError):
        return None

    consulta = """
    SELECT
        id, ip, ruta, metodo, payload, tipo_ataque, gravedad,
        user_agent, timestamp, pais, headers
    FROM eventos
    WHERE id = ?;
    """
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(consulta, (id_norm,))
        fila = cursor.fetchone()
        return dict(fila) if fila else None


def obtener_eventos_ultima_hora(limite=500):
    """
    Eventos registrados en la última hora (Europe/Madrid), más recientes primero.

    Args:
        limite (int): Máximo de filas a devolver.

    Returns:
        list[dict]: Eventos de la ventana temporal.
    """
    limite_norm = max(int(limite), 1)
    desde = formatear_marca(hace_tiempo(hours=1))
    consulta = f"""
    SELECT
        id, ip, ruta, metodo, payload, tipo_ataque, gravedad,
        user_agent, timestamp, pais, headers
    FROM eventos
    WHERE timestamp >= ?
      AND {_sql_condicion_amenazas_reales()}
    ORDER BY timestamp DESC, id DESC
    LIMIT ?;
    """
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(consulta, (desde, limite_norm))
        return [dict(fila) for fila in cursor.fetchall()]


def obtener_eventos(limite=100, periodo=None, gravedad=None, ambito="publico"):
    """
    Devuelve los últimos eventos ordenados por fecha descendente.

    Args:
        limite (int): Máximo de filas (mínimo 1).
        periodo (str|None): hoy | ayer | semana | mes | todo
        gravedad (str|None): Filtro exacto (Crítica/Alta/Sospechoso); None = todas las amenazas.
        ambito (str): publico | autoban | admin | todo (sin filtro de ámbito).

    Returns:
        list[dict]: Eventos como diccionarios.
    """
    limite_norm = max(int(limite), 1)
    rangos = _rangos_periodo_monitor(periodo)
    where_sql, params = _where_periodo_sql(rangos["desde"], rangos["hasta"])

    consulta = """
    SELECT
        id, ip, ruta, metodo, payload, tipo_ataque, gravedad,
        user_agent, timestamp, pais, headers, ambito
    FROM eventos
    """
    partes = []
    grav_params = []
    if where_sql:
        partes.append(where_sql)

    if ambito == "todo":
        cond_base = _sql_condicion_amenazas_base()
        canon = normalizar_gravedad_filtro_api(gravedad)
        if canon:
            partes.append(f"{cond_base} AND gravedad = ?")
            grav_params = [canon]
        else:
            partes.append(cond_base)
    elif ambito == "admin":
        partes.append(_sql_filtro_ambito_eventos("admin"))
        partes.append(_sql_condicion_amenazas_base())
        canon = normalizar_gravedad_filtro_api(gravedad)
        if canon:
            partes.append("gravedad = ?")
            grav_params = [canon]
    else:
        grav_sql, grav_params = _where_gravedad_monitor_sql(gravedad, ambito=ambito)
        partes.append(grav_sql)

    consulta += " WHERE " + " AND ".join(partes)
    consulta += " ORDER BY timestamp DESC, id DESC LIMIT ?;"
    params = list(params) + list(grav_params) + [limite_norm]

    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(consulta, params)
        return [dict(fila) for fila in cursor.fetchall()]


def obtener_estadisticas(periodo=None, ambito="publico"):
    """
    Calcula métricas agregadas para el dashboard del monitor (filtradas por período y ámbito).

    Returns:
        dict: métricas de tarjetas, gráficas, top rutas, alertas y serie temporal.
    """
    rangos = _rangos_periodo_monitor(periodo)
    where_sql, params = _where_periodo_sql(rangos["desde"], rangos["hasta"])
    filtro = f" WHERE {where_sql}" if where_sql else ""
    filtro_graficos = _filtro_sql_graficos_sin_trafico_normal(filtro, ambito=ambito)
    condicion_ambito = _sql_condicion_amenazas_con_ambito(ambito)

    with obtener_conexion() as conexion:
        cursor = conexion.cursor()

        total_eventos = _contar_eventos_amenazas_rango(
            cursor, rangos["desde"], rangos["hasta"], ambito=ambito
        )
        total_anterior = _contar_eventos_amenazas_rango(
            cursor, rangos["anterior_desde"], rangos["anterior_hasta"], ambito=ambito
        )

        if where_sql:
            variacion_pct = None
            if total_anterior > 0:
                variacion_pct = round(
                    ((total_eventos - total_anterior) / total_anterior) * 100, 1
                )
            elif total_eventos > 0:
                variacion_pct = 100.0
        else:
            variacion_pct = None
            if total_anterior > 0:
                variacion_pct = round(
                    ((total_eventos - total_anterior) / total_anterior) * 100, 1
                )

        cursor.execute(
            f"""
            SELECT COUNT(DISTINCT ip) AS total_ips_unicas
            FROM eventos
            {filtro_graficos}
              AND ip IS NOT NULL AND TRIM(ip) != '';
            """,
            params,
        )
        total_ips_unicas = cursor.fetchone()["total_ips_unicas"]

        # IPs que no habían aparecido antes del inicio del período seleccionado
        ips_nuevas = 0
        if rangos["desde"] is not None and where_sql:
            cursor.execute(
                f"""
                SELECT COUNT(*) AS n FROM (
                    SELECT DISTINCT ip FROM eventos
                    WHERE {where_sql} AND {condicion_ambito}
                      AND ip IS NOT NULL AND TRIM(ip) != ''
                    EXCEPT
                    SELECT DISTINCT ip FROM eventos
                    WHERE timestamp < ? AND ip IS NOT NULL AND TRIM(ip) != ''
                );
                """,
                params + [_fmt_ts_sql(rangos["desde"])],
            )
            ips_nuevas = cursor.fetchone()["n"]

        cursor.execute(
            f"""
            SELECT
                COALESCE(NULLIF(TRIM(tipo_ataque), ''), 'sin_clasificar') AS tipo_ataque,
                COUNT(*) AS cantidad
            FROM eventos
            {filtro_graficos}
            GROUP BY COALESCE(NULLIF(TRIM(tipo_ataque), ''), 'sin_clasificar')
            ORDER BY cantidad DESC, tipo_ataque ASC;
            """,
            params,
        )
        ataques_por_tipo = _filtrar_mapa_sin_trafico_normal(
            {fila["tipo_ataque"]: fila["cantidad"] for fila in cursor.fetchall()}
        )

        cursor.execute(
            f"""
            SELECT TRIM(gravedad) AS gravedad, COUNT(*) AS cantidad
            FROM eventos
            {filtro_graficos}
            GROUP BY TRIM(gravedad)
            ORDER BY cantidad DESC;
            """,
            params,
        )
        ataques_por_gravedad = {}
        for fila in cursor.fetchall():
            g = normalizar_gravedad_almacenada(fila["gravedad"])
            if not g:
                continue
            ataques_por_gravedad[g] = ataques_por_gravedad.get(g, 0) + fila["cantidad"]

        # Gravedad dominante por tipo (para colorear barras)
        cursor.execute(
            f"""
            SELECT
                COALESCE(NULLIF(TRIM(tipo_ataque), ''), 'sin_clasificar') AS tipo_ataque,
                TRIM(gravedad) AS gravedad,
                COUNT(*) AS cantidad
            FROM eventos
            {filtro_graficos}
            GROUP BY tipo_ataque, gravedad;
            """,
            params,
        )
        tipos_con_gravedad = {}
        for fila in cursor.fetchall():
            tipo = fila["tipo_ataque"]
            if _es_tipo_trafico_normal(tipo):
                continue
            grav = normalizar_gravedad_almacenada(fila["gravedad"])
            if not grav:
                continue
            peso = prioridad_gravedad(grav)
            if tipo not in tipos_con_gravedad or peso > tipos_con_gravedad[tipo]["peso"]:
                tipos_con_gravedad[tipo] = {"gravedad": grav, "peso": peso}
        ataques_tipo_gravedad = _filtrar_mapa_sin_trafico_normal(
            {t: v["gravedad"] for t, v in tipos_con_gravedad.items() if not _es_tipo_trafico_normal(t)}
        )

        # Top 5 rutas
        cursor.execute(
            f"""
            SELECT COALESCE(NULLIF(TRIM(ruta), ''), '/') AS ruta, COUNT(*) AS cantidad
            FROM eventos
            {filtro_graficos}
            GROUP BY ruta
            ORDER BY cantidad DESC
            LIMIT 5;
            """,
            params,
        )
        top_rutas = [
            {"ruta": fila["ruta"], "cantidad": fila["cantidad"]}
            for fila in cursor.fetchall()
        ]

        # Serie temporal: por hora o por día
        actividad_labels = []
        actividad_valores = []
        if rangos["modo_actividad"] == "hora" and rangos["desde"]:
            for h in range(24):
                actividad_labels.append(f"{h:02d}h")
                actividad_valores.append(0)
            cursor.execute(
                f"""
                SELECT CAST(strftime('%H', timestamp) AS INTEGER) AS hora, COUNT(*) AS cantidad
                FROM eventos
                {filtro_graficos}
                GROUP BY hora
                ORDER BY hora;
                """,
                params,
            )
            for fila in cursor.fetchall():
                h = int(fila["hora"])
                if 0 <= h < 24:
                    actividad_valores[h] = fila["cantidad"]
        elif rangos["desde"]:
            cursor.execute(
                f"""
                SELECT strftime('%Y-%m-%d', timestamp) AS dia, COUNT(*) AS cantidad
                FROM eventos
                {filtro_graficos}
                GROUP BY dia
                ORDER BY dia ASC;
                """,
                params,
            )
            for fila in cursor.fetchall():
                actividad_labels.append(fila["dia"])
                actividad_valores.append(fila["cantidad"])
        else:
            cursor.execute(
                f"""
                SELECT strftime('%Y-%m-%d', timestamp) AS dia, COUNT(*) AS cantidad
                FROM eventos
                WHERE timestamp >= ?
                  AND {condicion_ambito}
                GROUP BY dia
                ORDER BY dia ASC;
                """,
                (formatear_marca(hace_tiempo(days=30)),),
            )
            for fila in cursor.fetchall():
                actividad_labels.append(fila["dia"])
                actividad_valores.append(fila["cantidad"])

        pico_indice = 0
        if actividad_valores:
            pico_indice = max(range(len(actividad_valores)), key=lambda i: actividad_valores[i])

        # Último incidente con severidad en el período
        ultimo_filtro = (
            filtro_graficos
            if filtro_graficos
            else f" WHERE {condicion_ambito}"
        )
        cursor.execute(
            f"""
            SELECT gravedad, timestamp FROM eventos
            {ultimo_filtro}
            ORDER BY timestamp DESC
            LIMIT 1;
            """,
            params,
        )
        fila_ult = cursor.fetchone()
        ultimo_gravedad = None
        ultimo_hace_min = None
        if fila_ult:
            ultimo_gravedad = normalizar_gravedad_almacenada(fila_ult["gravedad"])
            ultimo_hace_min = minutos_desde_marca(fila_ult["timestamp"])

        # Alertas recientes (Crítica / Alta) dentro del período
        partes_alerta = [
            condicion_ambito,
            f"gravedad IN ('{GRAVEDAD_CRITICA}', '{GRAVEDAD_ALTA}')",
        ]
        if where_sql:
            partes_alerta.insert(0, where_sql)
        grav_where = " AND ".join(partes_alerta)
        cursor.execute(
            f"""
            SELECT ip, tipo_ataque, gravedad, timestamp, ruta
            FROM eventos
            WHERE {grav_where}
            ORDER BY timestamp DESC
            LIMIT 10;
            """,
            params if where_sql else [],
        )
        alertas_graves = []
        for fila in cursor.fetchall():
            g = normalizar_gravedad_almacenada(fila["gravedad"]) or GRAVEDAD_ALTA
            hace_min = minutos_desde_marca(fila["timestamp"])
            alertas_graves.append(
                {
                    "ip": fila["ip"] or "—",
                    "ruta": fila["ruta"] or "/",
                    "tipo_ataque": fila["tipo_ataque"] or "Tráfico Normal",
                    "gravedad": g,
                    "timestamp": fila["timestamp"],
                    "hace_min": hace_min,
                }
            )

        # ¿Hubo severidad Crítica en los últimos 5 minutos?
        cursor.execute(
            f"""
            SELECT COUNT(*) AS n FROM eventos
            WHERE gravedad = ?
              AND timestamp >= ?
              AND {_sql_filtro_ambito_eventos(ambito)};
            """,
            (GRAVEDAD_CRITICA, formatear_marca(hace_tiempo(minutes=5))),
        )
        alertas_criticas_recientes = cursor.fetchone()["n"] > 0

    return {
        "periodo": rangos["periodo"],
        "total_eventos": total_eventos,
        "total_eventos_variacion_pct": variacion_pct,
        "total_eventos_variacion_etiqueta": rangos["etiqueta_variacion"],
        "ips_unicas": total_ips_unicas,
        "ips_nuevas": ips_nuevas,
        "ataques_por_tipo": ataques_por_tipo,
        "ataques_por_gravedad": ataques_por_gravedad,
        "ataques_tipo_gravedad": ataques_tipo_gravedad,
        "ataques_detectados": sum(ataques_por_tipo.values()),
        "top_rutas": top_rutas,
        "actividad_modo": rangos["modo_actividad"],
        "actividad_labels": actividad_labels,
        "actividad_valores": actividad_valores,
        "actividad_pico_indice": pico_indice,
        "ultimo_ataque_hace": ultimo_hace_min,
        "ultimo_ataque_gravedad": ultimo_gravedad,
        "alertas_graves": alertas_graves,
        "alertas_criticas_recientes": alertas_criticas_recientes,
        "variacion_eventos": variacion_pct,
        "actividad_por_periodo": {
            "modo": rangos["modo_actividad"],
            "etiquetas": actividad_labels,
            "valores": actividad_valores,
            "pico_indice": pico_indice,
        },
        "eventos_por_hora_ultimas_24h": {},
        "zona_horaria": ZONA_NOMBRE,
    }


def obtener_alertas_graves_monitor(limite=10, periodo=None):
    """
    Devuelve las últimas alertas Crítica o Alta (orden timestamp DESC).

    Args:
        limite (int): Máximo de filas (por defecto 10).
        periodo (str|None): Si se indica, filtra al rango; None = sin filtro temporal.

    Returns:
        list[dict]: ip, ruta, tipo_ataque, gravedad, timestamp.
    """
    limite_norm = max(int(limite), 1)
    rangos = _rangos_periodo_monitor(periodo) if periodo else {
        "desde": None,
        "hasta": None,
    }
    where_sql, params = _where_periodo_sql(rangos["desde"], rangos["hasta"])
    partes = [_sql_condicion_amenazas_reales(), f"gravedad IN ('{GRAVEDAD_CRITICA}', '{GRAVEDAD_ALTA}')"]
    if where_sql:
        partes.insert(0, where_sql)
    grav_where = " AND ".join(partes)

    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            f"""
            SELECT ip, ruta, tipo_ataque, gravedad, timestamp
            FROM eventos
            WHERE {grav_where}
            ORDER BY timestamp DESC, id DESC
            LIMIT ?;
            """,
            (params if where_sql else []) + [limite_norm],
        )
        resultado = []
        for fila in cursor.fetchall():
            g = normalizar_gravedad_almacenada(fila["gravedad"]) or GRAVEDAD_ALTA
            resultado.append(
                {
                    "ip": fila["ip"] or "—",
                    "ruta": fila["ruta"] or "/",
                    "tipo_ataque": fila["tipo_ataque"] or "Tráfico Normal",
                    "gravedad": g,
                    "timestamp": fila["timestamp"],
                }
            )
        return resultado


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


def contar_flags_resueltas_por_usuario(usuario_id):
    """Cuenta cuántas flags distintas ha resuelto un usuario."""
    if not usuario_id:
        return 0
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            """
            SELECT COUNT(DISTINCT flag_id) AS total
            FROM objetivos_completados
            WHERE usuario_id = ?;
            """,
            (usuario_id,),
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


def obtener_ids_flags_resueltas_por_usuario(usuario_id):
    """Conjunto de id de flags ya resueltas por este usuario."""
    if not usuario_id:
        return set()
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            "SELECT DISTINCT flag_id FROM objetivos_completados WHERE usuario_id = ?;",
            (usuario_id,),
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


def obtener_flags_con_estado_por_usuario(usuario_id):
    """
    Lista retos públicos marcando cuáles ya resolvió el usuario (para ticks en /objetivos).
    """
    flags = obtener_flags_publicas()
    resueltas = obtener_ids_flags_resueltas_por_usuario(usuario_id)
    for flag in flags:
        flag["resuelta"] = flag["id"] in resueltas
    return flags


def obtener_ultimas_ips_conexion(limite=3):
    """
    Últimas IPs únicas que interactuaron con el honeypot (flypaper.db).

    Returns:
        list[dict]: ip, ultima_peticion, ultima_ruta.
    """
    consulta = """
    SELECT ip, ultima_peticion, ultima_ruta FROM (
        SELECT
            TRIM(ip) AS ip,
            timestamp AS ultima_peticion,
            ruta AS ultima_ruta,
            ROW_NUMBER() OVER (PARTITION BY TRIM(ip) ORDER BY timestamp DESC) AS rn
        FROM registro_peticiones
        WHERE ip IS NOT NULL AND TRIM(ip) != ''
    ) t
    WHERE rn = 1
    ORDER BY ultima_peticion DESC
    LIMIT ?;
    """
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(consulta, (limite,))
        return [dict(fila) for fila in cursor.fetchall()]


def obtener_ultimo_evento_critico():
    """
    Evento más reciente con gravedad Crítica en flypaper.db.

    Returns:
        dict | None
    """
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            """
            SELECT id, ip, tipo_ataque, ruta, gravedad, timestamp, payload
            FROM eventos
            WHERE gravedad = ?
            ORDER BY timestamp DESC
            LIMIT 1;
            """,
            (GRAVEDAD_CRITICA,),
        )
        fila = cursor.fetchone()
    if not fila:
        return None
    evento = dict(fila)
    evento["ip_atacante"] = evento.get("ip") or ""
    return evento


def _usernames_registrados_set():
    """
    Conjunto de nombres de usuario en flypaper_users.db (activos).

    El ranking CTF solo incluye jugadores con cuenta real en /register.
    """
    with obtener_conexion_users() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            "SELECT username FROM usuarios_registrados WHERE activo = 1;"
        )
        return {fila["username"] for fila in cursor.fetchall()}


def obtener_ranking_ctf(limite=20):
    """
    Top de jugadores por puntos CTF (solo usuarios registrados en flypaper_users.db).

    Une objetivos_completados con flags en flypaper.db y filtra cuentas reales.

    Returns:
        list[dict]: username, puntos, retos, ultimo_completado, posicion.
    """
    consulta = """
    SELECT
        oc.usuario_id AS username,
        SUM(f.puntos) AS puntos_totales,
        COUNT(oc.flag_id) AS retos_completados,
        MAX(oc.fecha) AS ultimo_completado
    FROM objetivos_completados oc
    JOIN flags f ON f.id = oc.flag_id
    GROUP BY oc.usuario_id
    ORDER BY puntos_totales DESC, ultimo_completado ASC
    LIMIT ?;
    """
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(consulta, (limite,))
        filas = cursor.fetchall()

    registrados = _usernames_registrados_set()
    ranking = []
    for fila in filas:
        username = fila["username"]
        if username not in registrados:
            continue
        ranking.append(
            {
                "username": username,
                "puntos": int(fila["puntos_totales"] or 0),
                "retos": int(fila["retos_completados"] or 0),
                "ultimo_completado": fila["ultimo_completado"] or "",
            }
        )

    for posicion, entrada in enumerate(ranking, start=1):
        entrada["posicion"] = posicion

    return ranking


def obtener_completados_por_reto():
    """
    Usuarios registrados que completaron cada reto, agrupados por nombre del reto.

    Returns:
        dict[str, list[dict]]: reto_nombre → [{username, fecha}, ...]
    """
    consulta = """
    SELECT f.reto_nombre, oc.usuario_id, oc.fecha
    FROM objetivos_completados oc
    JOIN flags f ON f.id = oc.flag_id
    ORDER BY f.id ASC, oc.fecha ASC;
    """
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(consulta)
        filas = cursor.fetchall()

    registrados = _usernames_registrados_set()
    agrupado = {}
    for fila in filas:
        username = fila["usuario_id"]
        if username not in registrados:
            continue
        reto = fila["reto_nombre"]
        agrupado.setdefault(reto, []).append(
            {
                "username": username,
                "fecha": fila["fecha"] or "",
            }
        )
    return agrupado


def obtener_puntos_usuario(usuario_id):
    """
    Suma de puntos CTF de un usuario en objetivos_completados.

    Returns:
        int: Total de puntos (0 si no tiene retos completados).
    """
    if not usuario_id:
        return 0
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            """
            SELECT SUM(f.puntos) AS puntos_totales
            FROM objetivos_completados oc
            JOIN flags f ON f.id = oc.flag_id
            WHERE oc.usuario_id = ?;
            """,
            (usuario_id,),
        )
        fila = cursor.fetchone()
    if fila is None or fila["puntos_totales"] is None:
        return 0
    return int(fila["puntos_totales"])


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

        marca = marca_ahora()
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


def enviar_flag_por_usuario(usuario_id, flag_texto):
    """
    Valida y registra una flag enviada por el usuario y la persiste en `objetivos_completados`.

    Returns:
        dict: Igual que `enviar_flag` pero con progreso individual por usuario.
    """
    usuario_key = (usuario_id or "").strip()
    flag_limpia = (flag_texto or "").strip()
    total_retos = len(obtener_flags_publicas())

    if not flag_limpia:
        return {
            "exito": False,
            "mensaje": "La flag introducida es incorrecta",
            "puntos": None,
            "reto_nombre": None,
            "flag_id": None,
            "resueltas": contar_flags_resueltas_por_usuario(usuario_key),
            "total": total_retos,
        }

    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            """
            SELECT id, puntos, reto_nombre FROM flags WHERE flag_string = ?;
            """,
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
                "resueltas": contar_flags_resueltas_por_usuario(usuario_key),
                "total": total_retos,
            }

        flag_id = fila_flag["id"]
        reto_nombre = fila_flag["reto_nombre"]

        cursor.execute(
            """
            SELECT id FROM objetivos_completados
            WHERE usuario_id = ? AND flag_id = ?;
            """,
            (usuario_key, flag_id),
        )
        if cursor.fetchone() is not None:
            resueltas = contar_flags_resueltas_por_usuario(usuario_key)
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

        marca = marca_ahora()
        cursor.execute(
            """
            INSERT INTO objetivos_completados (usuario_id, flag_id, fecha)
            VALUES (?, ?, ?);
            """,
            (usuario_key, flag_id, marca),
        )
        conexion.commit()

    resueltas = contar_flags_resueltas_por_usuario(usuario_key)
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
    marca = marca_ahora()
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

    marca = marca_ahora()
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


def obtener_reportes_filtrados(ip=None, fecha_inicio=None, fecha_fin=None):
    """
    Reportes manuales con filtros dinámicos.

    Args:
        ip (str|None): IP exacta; si se omite, debe indicarse rango de fechas (ambas).
        fecha_inicio (str|None): YYYY-MM-DD inclusive.
        fecha_fin (str|None): YYYY-MM-DD inclusive.

    Returns:
        list[dict]: Filas ordenadas por fecha descendente.
    """
    ip_norm = (ip or "").strip()
    inicio = (fecha_inicio or "").strip() or None
    fin = (fecha_fin or "").strip() or None

    condiciones = []
    params = []

    if ip_norm:
        condiciones.append("ip_atacante = ?")
        params.append(ip_norm)

    if inicio and fin:
        condiciones.append("date(fecha) BETWEEN date(?) AND date(?)")
        params.extend([inicio, fin])
    elif inicio:
        condiciones.append("date(fecha) >= date(?)")
        params.append(inicio)
    elif fin:
        condiciones.append("date(fecha) <= date(?)")
        params.append(fin)

    if not condiciones:
        return []

    where = " AND ".join(condiciones)
    consulta = f"""
    SELECT id, ip_atacante, datos_ataque, fecha
    FROM reportes_enviados
    WHERE {where}
    ORDER BY fecha DESC, id DESC;
    """
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(consulta, params)
        return [dict(fila) for fila in cursor.fetchall()]


def obtener_reportes_por_ip(ip, fecha_desde=None, fecha_hasta=None):
    """Alias retrocompatible; delega en obtener_reportes_filtrados."""
    return obtener_reportes_filtrados(
        ip=ip, fecha_inicio=fecha_desde, fecha_fin=fecha_hasta
    )


def obtener_ips_distintas_eventos():
    """
    IPs únicas registradas en eventos (mismas fuentes que agrupa el monitor).

    Returns:
        list[str]: Direcciones ordenadas alfabéticamente.
    """
    consulta = """
    SELECT DISTINCT ip
    FROM eventos
    WHERE ip IS NOT NULL AND TRIM(ip) != ''
    ORDER BY ip ASC;
    """
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(consulta)
        return [fila["ip"] for fila in cursor.fetchall()]


def _gravedad_maxima_desde_lista(lista_gravedades):
    """Prioridad estricta: Crítica > Alta > Sospechoso."""
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


def obtener_agregados_seguridad_por_ip():
    """
    Agrega incidentes de la tabla eventos por dirección IP.

    Returns:
        dict[str, dict]: Clave IP; valores total_eventos, gravedad_maxima, tipos_ataque.
    """
    consulta = """
    SELECT ip, tipo_ataque, gravedad
    FROM eventos
    WHERE ip IS NOT NULL AND TRIM(ip) != '';
    """
    acumulado = {}
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(consulta)
        for fila in cursor.fetchall():
            ip = (fila["ip"] or "").strip()
            if not ip:
                continue
            if ip not in acumulado:
                acumulado[ip] = {
                    "total_eventos": 0,
                    "gravedades": [],
                    "tipos_set": set(),
                }
            bloque = acumulado[ip]
            bloque["total_eventos"] += 1
            tipo = (fila["tipo_ataque"] or "").strip()
            if tipo:
                bloque["tipos_set"].add(tipo)
            grav = normalizar_gravedad_almacenada(fila["gravedad"])
            if grav:
                bloque["gravedades"].append(grav)

    resultado = {}
    for ip, bloque in acumulado.items():
        resultado[ip] = {
            "total_eventos": bloque["total_eventos"],
            "gravedad_maxima": _gravedad_maxima_desde_lista(bloque["gravedades"]),
            "tipos_ataque": sorted(bloque["tipos_set"]),
        }
    return resultado


def obtener_fechas_con_eventos():
    """
    Días calendario (Europe/Madrid en timestamp) con al menos un evento.

    Returns:
        list[dict]: {fecha: 'YYYY-MM-DD', total: int}, más reciente primero.
    """
    consulta = """
    SELECT strftime('%Y-%m-%d', timestamp) AS fecha, COUNT(*) AS total
    FROM eventos
    WHERE timestamp IS NOT NULL
    GROUP BY fecha
    ORDER BY fecha DESC;
    """
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(consulta)
        return [
            {"fecha": fila["fecha"], "total": int(fila["total"] or 0)}
            for fila in cursor.fetchall()
            if fila["fecha"]
        ]


def obtener_ultima_fecha_con_eventos():
    """Último día con eventos en BD, o None."""
    filas = obtener_fechas_con_eventos()
    return filas[0]["fecha"] if filas else None


def contar_eventos_en_fecha(fecha):
    """Cuenta eventos cuyo timestamp cae en la fecha YYYY-MM-DD (calendario Madrid)."""
    if not fecha:
        return 0
    consulta = """
    SELECT COUNT(*) AS total
    FROM eventos
    WHERE strftime('%Y-%m-%d', timestamp) = ?;
    """
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(consulta, (fecha,))
        fila = cursor.fetchone()
        return int(fila["total"] or 0) if fila else 0


def obtener_eventos_por_fecha(fecha, limite=500):
    """
    Eventos de un día concreto (fecha en formato YYYY-MM-DD).

    Args:
        fecha (str): Día calendario.
        limite (int): Máximo de filas.

    Returns:
        list[dict]: Eventos del día, más recientes primero.
    """
    if not fecha:
        return []
    limite_norm = max(int(limite), 1)
    consulta = """
    SELECT
        id, ip, ruta, metodo, payload, tipo_ataque, gravedad,
        user_agent, timestamp, pais, headers
    FROM eventos
    WHERE strftime('%Y-%m-%d', timestamp) = ?
    ORDER BY timestamp DESC, id DESC
    LIMIT ?;
    """
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(consulta, (fecha, limite_norm))
        return [dict(fila) for fila in cursor.fetchall()]


def guardar_resumen_diario_ia(fecha, resumen, total_eventos=0):
    """Persiste o actualiza el resumen IA de un día."""
    if not fecha or not resumen:
        return
    marca = marca_ahora()
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            """
            INSERT INTO resumenes_diarios_ia (fecha, resumen, total_eventos, generado_en)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(fecha) DO UPDATE SET
                resumen = excluded.resumen,
                total_eventos = excluded.total_eventos,
                generado_en = excluded.generado_en;
            """,
            (fecha, resumen, int(total_eventos or 0), marca),
        )
        conexion.commit()


def obtener_resumen_diario_ia(fecha):
    """Resumen guardado para una fecha, o None."""
    if not fecha:
        return None
    consulta = """
    SELECT fecha, resumen, total_eventos, generado_en
    FROM resumenes_diarios_ia
    WHERE fecha = ?;
    """
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(consulta, (fecha,))
        fila = cursor.fetchone()
        return dict(fila) if fila else None


def listar_resumenes_diarios_ia():
    """
    Todos los resúmenes diarios IA guardados, del más reciente al más antiguo.

    Returns:
        list[dict]: fecha, resumen, total_eventos, generado_en.
    """
    consulta = """
    SELECT fecha, resumen, total_eventos, generado_en
    FROM resumenes_diarios_ia
    ORDER BY fecha DESC;
    """
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(consulta)
        return [dict(fila) for fila in cursor.fetchall()]


def registrar_resumen_log(fecha, tipo, total_eventos, caracteres, ok=True):
    """Registra una ejecución de generación de resumen (automático, manual o preview)."""
    if not fecha:
        return
    marca = marca_ahora()
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            """
            INSERT INTO resumenes_log (
                fecha, tipo, total_eventos, caracteres, generado_en, ok
            ) VALUES (?, ?, ?, ?, ?, ?);
            """,
            (
                fecha,
                (tipo or "automatico").strip(),
                int(total_eventos or 0),
                int(caracteres or 0),
                marca,
                1 if ok else 0,
            ),
        )
        conexion.commit()


def obtener_log_resumenes(limite=50):
    """Últimas entradas del log de resúmenes, más recientes primero."""
    limite_norm = max(1, min(int(limite or 50), 200))
    consulta = """
    SELECT id, fecha, tipo, total_eventos, caracteres, generado_en, ok
    FROM resumenes_log
    ORDER BY generado_en DESC
    LIMIT ?;
    """
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(consulta, (limite_norm,))
        return [dict(fila) for fila in cursor.fetchall()]


def eliminar_resumen_diario_ia(fecha):
    """Elimina el resumen guardado de un día y sus entradas de log (excepto preview)."""
    if not fecha:
        return
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute("DELETE FROM resumenes_diarios_ia WHERE fecha = ?;", (fecha,))
        cursor.execute(
            "DELETE FROM resumenes_log WHERE fecha = ? AND tipo != 'preview';",
            (fecha,),
        )
        conexion.commit()


def registrar_ip_bloqueada(ip, motivo=""):
    """
    Persiste una IP en la lista negra (sobrevive reinicios del servidor).

    Args:
        ip (str): Dirección IPv4/IPv6 del visitante bloqueado.
        motivo (str): Texto opcional (p. ej. origen del bloqueo en monitor).
    """
    if not ip:
        return
    marca = marca_ahora()
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


def obtener_ultimas_expulsiones_autoban(limite=10):
    """
    Últimas IPs bloqueadas con el tipo de ataque autoban más reciente (si existe).

    Returns:
        list[dict]: ip, tipo_ataque, hace_min, fecha_bloqueo, motivo
    """
    limite_norm = max(int(limite), 1)
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            """
            SELECT ip, fecha, motivo
            FROM ips_bloqueadas
            ORDER BY datetime(fecha) DESC, id DESC
            LIMIT ?;
            """,
            (limite_norm,),
        )
        filas = [dict(fila) for fila in cursor.fetchall()]

    resultado = []
    for fila in filas:
        ip = fila.get("ip") or ""
        tipo = "—"
        hace_min = minutos_desde_marca(fila.get("fecha"))
        with obtener_conexion() as conexion:
            cursor = conexion.cursor()
            cursor.execute(
                """
                SELECT tipo_ataque, timestamp
                FROM eventos
                WHERE ip = ? AND ambito = 'autoban'
                ORDER BY timestamp DESC, id DESC
                LIMIT 1;
                """,
                (ip,),
            )
            ev = cursor.fetchone()
            if ev:
                tipo = (ev["tipo_ataque"] or "—").strip() or "—"
                hace_min = minutos_desde_marca(ev["timestamp"])
        resultado.append(
            {
                "ip": ip,
                "tipo_ataque": tipo,
                "hace_min": hace_min,
                "fecha_bloqueo": fila.get("fecha"),
                "motivo": fila.get("motivo") or "",
            }
        )
    return resultado


def contar_ips_bloqueadas():
    """Devuelve el número total de IPs en la lista negra persistente."""
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute("SELECT COUNT(*) AS n FROM ips_bloqueadas;")
        return int(cursor.fetchone()["n"] or 0)


def listar_ips_bloqueadas():
    """Devuelve todas las IPs bloqueadas almacenadas en SQLite."""
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute("SELECT ip FROM ips_bloqueadas ORDER BY fecha DESC;")
        return [fila["ip"] for fila in cursor.fetchall()]


def limpiar_datos_monitor():
    """
    Borra eventos y resúmenes IA del monitor (útil tras migración de zona horaria).

    Returns:
        dict: conteos eliminados por tabla.
    """
    tablas = (
        ("eventos", "DELETE FROM eventos;"),
        ("resumenes_diarios_ia", "DELETE FROM resumenes_diarios_ia;"),
    )
    resultado = {}
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        for nombre, sql in tablas:
            cursor.execute(sql)
            resultado[nombre] = cursor.rowcount
        conexion.commit()
    return resultado
