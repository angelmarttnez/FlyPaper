"""
Aplicación principal de FlyPaper.

Este archivo define un honeypot web con Flask que:
- Simula endpoints atractivos para atacantes.
- Clasifica automáticamente cada interacción.
- Guarda eventos en SQLite para posterior análisis.
"""

from flask import Flask, jsonify, make_response, redirect, render_template, request, url_for

from database import guardar_evento, inicializar_db
from detector import clasificar_ataque


# Creamos la instancia principal de Flask.
aplicacion = Flask(__name__)

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


@aplicacion.post("/login")
def procesar_login():
    """
    Acepta cualquier combinación de usuario y contraseña.

    Aunque se reciben los datos enviados por el formulario, en este honeypot
    no se valida nada: siempre redirige al dashboard falso para simular
    un acceso "exitoso".
    """
    # Leemos campos típicos de login para mantener el comportamiento realista.
    usuario_enviado = request.form.get("username", "")
    contrasena_enviada = request.form.get("password", "")

    # Las variables se usan intencionalmente aunque no haya validación todavía.
    _ = (usuario_enviado, contrasena_enviada)

    return redirect("/dashboard-falso")


@aplicacion.get("/admin")
def mostrar_panel_admin():
    """
    Muestra un panel de administración falso.

    Renderiza la plantilla `admin.html`, diseñada para aparentar
    una zona sensible de gestión.
    """
    return render_template("admin.html")


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
    return render_template("search.html")


@aplicacion.post("/search")
def procesar_busqueda():
    """
    Recibe una consulta y devuelve resultados falsos.

    La búsqueda no consulta base de datos real; solo construye un conjunto
    de resultados simulados para mantener la ilusión de funcionalidad.
    """
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


if __name__ == "__main__":
    """
    Punto de entrada local para desarrollo.

    Se deja `debug=True` para facilitar pruebas durante la construcción
    del proyecto. En producción, debería establecerse en `False`.
    """
    aplicacion.run(host="0.0.0.0", port=5000, debug=True)
