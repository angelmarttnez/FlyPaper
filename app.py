"""
Aplicación principal de FlyPaper.

Este archivo define un honeypot web con Flask que:
- Simula endpoints atractivos para atacantes.
- Clasifica automáticamente cada interacción.
- Guarda eventos en SQLite para posterior análisis.
"""

import csv
import io
from functools import wraps

from flask import (
    Flask,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from database import guardar_evento, inicializar_db, obtener_estadisticas, obtener_eventos
from detector import clasificar_ataque


# Creamos la instancia principal de Flask.
aplicacion = Flask(__name__)
# Clave para firmar cookies de sesión (login honeypot y otras sesiones).
aplicacion.secret_key = 'flypaper_secreto_2026'

# Inicializamos la base de datos al arrancar la aplicación para asegurar
# que la tabla `eventos` exista antes de intentar guardar información.
inicializar_db()


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
    return ruta_solicitada.startswith("/dashboard") or ruta_solicitada.startswith("/static")


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

    # Omitimos rutas internas/estáticas según tu regla.
    if debe_excluirse_del_registro(ruta_visitada):
        return respuesta

    # Obtenemos la IP real si hay proxy; si no, usamos la IP remota directa.
    ip_visitante = request.headers.get("X-Forwarded-For", request.remote_addr or "")

    # Si hay varias IPs en la cabecera, nos quedamos con la primera (cliente origen).
    if "," in ip_visitante:
        ip_visitante = ip_visitante.split(",")[0].strip()

    payload_peticion = construir_payload_para_registro()
    user_agent_visitante = request.headers.get("User-Agent", "")
    tipo_ataque_detectado = clasificar_ataque(
        ruta=ruta_visitada,
        payload=str(payload_peticion),
        user_agent=user_agent_visitante,
    )

    # Convertimos cabeceras a dict plano para serialización JSON en la BD.
    cabeceras_peticion = dict(request.headers)

    guardar_evento(
        ip=ip_visitante,
        ruta=ruta_visitada,
        metodo=request.method,
        payload=payload_peticion,
        user_agent=user_agent_visitante,
        tipo_ataque=tipo_ataque_detectado,
        headers=cabeceras_peticion,
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
    Muestra el formulario de búsqueda falso.

    Renderiza la plantilla `search.html`, pensada para recibir términos
    que después se reflejan en resultados simulados.
    """
    # Misma regla que /admin: exige sesión iniciada por el login del honeypot.
    if session.get("logueado") is not True:
        return redirect("/login?error=1")
    return render_template("search.html")


@aplicacion.post("/search")
def procesar_busqueda():
    """
    Recibe una consulta y devuelve resultados falsos.

    La búsqueda no consulta base de datos real; solo construye un conjunto
    de resultados simulados para mantener la ilusión de funcionalidad.
    """
    # Evita envíos POST anónimos a la búsqueda sin pasar antes por /login.
    if session.get("logueado") is not True:
        return redirect("/login?error=1")
    termino_busqueda = request.form.get("q", "").strip()

    resultados_falsos = [
        {
            "titulo": f"Resultado interno para '{termino_busqueda or 'query'}'",
            "descripcion": "Documento confidencial indexado en caché.",
            "ruta": "/internal/docs/2026-security-overview.pdf",
        },
        {
            "titulo": "Backup incremental encontrado",
            "descripcion": "Referencia a copia diaria en almacenamiento remoto.",
            "ruta": "/backup?latest=true",
        },
        {
            "titulo": "Registro de usuarios administrativos",
            "descripcion": "Listado histórico de accesos privilegiados.",
            "ruta": "/admin/users/export.csv",
        },
    ]

    return render_template(
        "search.html",
        termino=termino_busqueda,
        resultados=resultados_falsos,
        total_resultados=len(resultados_falsos),
    )


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
    Devuelve en JSON los últimos 100 eventos para refresco dinámico del dashboard.
    """
    eventos_recientes = obtener_eventos(limite=100)
    return jsonify(eventos_recientes)


@aplicacion.get("/monitor/api/stats")
@requiere_autenticacion_monitor
def monitor_api_estadisticas():
    """
    Devuelve en JSON las estadísticas principales del sistema de monitoreo.
    """
    estadisticas = obtener_estadisticas()
    return jsonify(estadisticas)


@aplicacion.get("/monitor/exportar")
@requiere_autenticacion_monitor
def monitor_exportar_csv():
    """
    Genera y descarga un CSV con los eventos obtenidos vía `obtener_eventos`.

    Hasta 9999 filas de datos más la cabecera; columnas alineadas con el esquema pedido.
    """
    lista_eventos = obtener_eventos(limite=9999)

    buffer_csv = io.StringIO()
    escritor_csv = csv.writer(buffer_csv)

    # Cabeceras exactamente como se solicitan para hojas de cálculo externas.
    escritor_csv.writerow(
        [
            "ID",
            "IP",
            "Ruta",
            "Metodo",
            "Payload",
            "User_Agent",
            "Tipo_Ataque",
            "Pais",
            "Timestamp",
        ]
    )

    for evento in lista_eventos:
        escritor_csv.writerow(
            [
                evento.get("id", ""),
                evento.get("ip", ""),
                evento.get("ruta", ""),
                evento.get("metodo", ""),
                evento.get("payload", ""),
                evento.get("user_agent", ""),
                evento.get("tipo_ataque", ""),
                evento.get("pais", ""),
                evento.get("timestamp", ""),
            ]
        )

    contenido_csv = buffer_csv.getvalue()
    buffer_csv.close()

    respuesta = make_response(contenido_csv, 200)
    respuesta.mimetype = "text/csv"
    respuesta.headers["Content-Disposition"] = "attachment; filename=flypaper_eventos.csv"
    return respuesta


if __name__ == "__main__":
    """
    Punto de entrada local para desarrollo.

    Se deja `debug=True` para facilitar pruebas durante la construcción
    del proyecto. En producción, debería establecerse en `False`.
    """
    aplicacion.run(host="0.0.0.0", port=5000, debug=True)
