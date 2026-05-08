"""
Módulo de acceso a datos para FlyPaper.

Este archivo centraliza toda la lógica de SQLite para:
- Crear la estructura inicial de la base de datos.
- Guardar eventos capturados por el honeypot.
- Consultar eventos recientes.
- Obtener métricas para el dashboard.
"""

import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path


# Ruta absoluta al directorio raíz del proyecto (donde vive este archivo).
RUTA_RAIZ_PROYECTO = Path(__file__).resolve().parent

# Ruta completa del archivo SQLite solicitado por el proyecto.
RUTA_BD = RUTA_RAIZ_PROYECTO / "flypaper.db"


def obtener_conexion():
    """
    Crea y devuelve una conexión SQLite configurada para resultados por nombre.

    Returns:
        sqlite3.Connection: Conexión activa a `flypaper.db`.
    """
    conexion = sqlite3.connect(RUTA_BD)
    conexion.row_factory = sqlite3.Row
    return conexion


def inicializar_db():
    """
    Inicializa la base de datos creando la tabla `eventos` si no existe.

    La tabla almacena todos los intentos/interacciones relevantes del honeypot.
    Esta función es idempotente: puede ejecutarse múltiples veces sin romper nada.
    """
    consulta_creacion_tabla = """
    CREATE TABLE IF NOT EXISTS eventos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        ruta TEXT,
        metodo TEXT,
        payload TEXT,
        user_agent TEXT,
        timestamp DATETIME,
        tipo_ataque TEXT,
        pais TEXT,
        headers TEXT
    );
    """

    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(consulta_creacion_tabla)
        conexion.commit()


def guardar_evento(ip, ruta, metodo, payload, user_agent, tipo_ataque, headers):
    """
    Inserta un nuevo evento en la tabla `eventos`.

    Args:
        ip (str): Dirección IP del visitante.
        ruta (str): Ruta visitada (por ejemplo, `/login`).
        metodo (str): Método HTTP usado (GET, POST, etc.).
        payload (str | dict | None): Datos enviados por el visitante.
        user_agent (str): Cadena de navegador/agente del cliente.
        tipo_ataque (str): Clasificación del evento/ataque.
        headers (dict | str | None): Cabeceras HTTP; se guardan como JSON en texto.
    """
    # Normalizamos el payload a texto para guardarlo de forma consistente.
    if isinstance(payload, (dict, list)):
        payload_serializado = json.dumps(payload, ensure_ascii=False)
    elif payload is None:
        payload_serializado = ""
    else:
        payload_serializado = str(payload)

    # Normalizamos headers a JSON en texto.
    if isinstance(headers, (dict, list)):
        headers_serializados = json.dumps(headers, ensure_ascii=False)
    elif headers is None:
        headers_serializados = "{}"
    else:
        headers_serializados = str(headers)

    # Guardamos fecha/hora en formato ISO para facilitar filtros y orden.
    marca_tiempo = datetime.utcnow().isoformat(timespec="seconds")

    consulta_insercion = """
    INSERT INTO eventos (
        ip, ruta, metodo, payload, user_agent, timestamp, tipo_ataque, pais, headers
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
    """

    valores = (
        ip,
        ruta,
        metodo,
        payload_serializado,
        user_agent,
        marca_tiempo,
        tipo_ataque,
        "",  # Por ahora el país queda vacío como pediste.
        headers_serializados,
    )

    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(consulta_insercion, valores)
        conexion.commit()


def obtener_eventos(limite=100):
    """
    Recupera los últimos N eventos ordenados de más reciente a más antiguo.

    Args:
        limite (int, optional): Máximo número de eventos a devolver. Por defecto 100.

    Returns:
        list[dict]: Lista de eventos en formato diccionario.
    """
    # Aseguramos un límite positivo para evitar consultas inesperadas.
    limite_normalizado = max(int(limite), 1)

    consulta_eventos = """
    SELECT id, ip, ruta, metodo, payload, user_agent, timestamp, tipo_ataque, pais, headers
    FROM eventos
    ORDER BY timestamp DESC, id DESC
    LIMIT ?;
    """

    with obtener_conexion() as conexion:
        cursor = conexion.cursor()
        cursor.execute(consulta_eventos, (limite_normalizado,))
        filas = cursor.fetchall()

    return [dict(fila) for fila in filas]


def obtener_estadisticas():
    """
    Calcula estadísticas clave para el dashboard de FlyPaper.

    Devuelve:
    - Total de eventos registrados.
    - Número de IPs únicas.
    - Conteo por cada tipo de ataque.
    - Eventos por hora durante las últimas 24 horas.

    Returns:
        dict: Estructura con todas las métricas agregadas.
    """
    with obtener_conexion() as conexion:
        cursor = conexion.cursor()

        # 1) Total de eventos.
        cursor.execute("SELECT COUNT(*) AS total FROM eventos;")
        total_eventos = cursor.fetchone()["total"]

        # 2) Número de IPs únicas (ignorando valores nulos/vacíos).
        cursor.execute(
            """
            SELECT COUNT(DISTINCT ip) AS total_ips_unicas
            FROM eventos
            WHERE ip IS NOT NULL AND TRIM(ip) != '';
            """
        )
        total_ips_unicas = cursor.fetchone()["total_ips_unicas"]

        # 3) Conteo de eventos por tipo de ataque.
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
        filas_tipos_ataque = cursor.fetchall()
        conteo_por_tipo_ataque = {
            fila["tipo_ataque"]: fila["cantidad"] for fila in filas_tipos_ataque
        }

        # 4) Eventos por hora en las últimas 24 horas.
        # Se usa UTC para mantener consistencia con el timestamp guardado.
        hora_actual_utc = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
        hora_inicio_utc = hora_actual_utc - timedelta(hours=23)

        # Creamos una plantilla de 24 buckets horarios con valor inicial 0.
        eventos_por_hora = {}
        for desplazamiento_horas in range(24):
            hora_bucket = hora_inicio_utc + timedelta(hours=desplazamiento_horas)
            clave_hora = hora_bucket.strftime("%Y-%m-%d %H:00:00")
            eventos_por_hora[clave_hora] = 0

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
        filas_eventos_hora = cursor.fetchall()

        # Sobrescribimos solo las horas donde sí hubo eventos.
        for fila in filas_eventos_hora:
            hora = fila["hora"]
            if hora in eventos_por_hora:
                eventos_por_hora[hora] = fila["cantidad"]

    return {
        "total_eventos": total_eventos,
        "ips_unicas": total_ips_unicas,
        "ataques_por_tipo": conteo_por_tipo_ataque,
        "eventos_por_hora_ultimas_24h": eventos_por_hora,
    }
