"""
database.py — FlyPaper
Módulo de gestión de la base de datos SQLite.
Guarda y recupera todos los eventos/ataques registrados.
"""

import sqlite3
from datetime import datetime

# Nombre del archivo de base de datos
NOMBRE_BD = "flypaper.db"


def inicializar_db():
    """
    Crea la base de datos y la tabla 'eventos' si no existen.
    También añade la columna 'gravedad' si la BD ya existía sin ella.
    """
    conn = sqlite3.connect(NOMBRE_BD)
    cursor = conn.cursor()

    # Crear tabla principal de eventos
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS eventos (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip          TEXT,
            ruta        TEXT,
            metodo      TEXT,
            payload     TEXT,
            user_agent  TEXT,
            timestamp   DATETIME,
            tipo_ataque TEXT,
            gravedad    TEXT DEFAULT 'BAJO',
            pais        TEXT DEFAULT '',
            headers     TEXT
        )
    """)

    # Añadir columna gravedad si la BD ya existía sin ella
    try:
        cursor.execute("ALTER TABLE eventos ADD COLUMN gravedad TEXT DEFAULT 'BAJO'")
    except sqlite3.OperationalError:
        # La columna ya existe, no pasa nada
        pass

    conn.commit()
    conn.close()


def guardar_evento(ip, ruta, metodo, payload, user_agent, tipo_ataque, headers, gravedad="BAJO"):
    """
    Inserta un nuevo evento/ataque en la base de datos.

    Parámetros:
        ip (str):          IP del visitante, ej: "192.168.1.1"
        ruta (str):        URL visitada, ej: "/admin"
        metodo (str):      Método HTTP, ej: "GET" o "POST"
        payload (str):     Contenido del formulario, ej: "SELECT * FROM users"
        user_agent (str):  Navegador o herramienta usada
        tipo_ataque (str): Tipo clasificado, ej: "SQLi"
        headers (str):     Cabeceras HTTP en formato JSON
        gravedad (str):    Nivel de gravedad: CRÍTICO, ALTO, MEDIO, BAJO
    """
    conn = sqlite3.connect(NOMBRE_BD)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO eventos 
            (ip, ruta, metodo, payload, user_agent, timestamp, tipo_ataque, gravedad, pais, headers)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        ip,
        ruta,
        metodo,
        payload,
        user_agent,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        tipo_ataque,
        gravedad,
        "",  # país vacío por ahora
        headers
    ))

    conn.commit()
    conn.close()


def obtener_eventos(limite=100):
    """
    Devuelve los últimos N eventos ordenados por fecha descendente.

    Parámetros:
        limite (int): Número máximo de eventos a devolver (por defecto 100)

    Devuelve:
        list: Lista de diccionarios con los datos de cada evento
    """
    conn = sqlite3.connect(NOMBRE_BD)
    conn.row_factory = sqlite3.Row  # Para acceder por nombre de columna
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM eventos 
        ORDER BY timestamp DESC 
        LIMIT ?
    """, (limite,))

    # Convertir cada fila a diccionario
    eventos = [dict(fila) for fila in cursor.fetchall()]

    conn.close()
    return eventos


def obtener_estadisticas():
    """
    Calcula y devuelve estadísticas globales de los ataques registrados.

    Devuelve:
        dict: Diccionario con las estadísticas:
            - total_eventos: número total de registros
            - ips_unicas: número de IPs distintas
            - ataques_por_tipo: conteo por tipo de ataque
            - ataques_por_gravedad: conteo por nivel de gravedad
            - actividad_por_hora: eventos en las últimas 24 horas por hora
    """
    conn = sqlite3.connect(NOMBRE_BD)
    cursor = conn.cursor()

    # Total de eventos
    cursor.execute("SELECT COUNT(*) FROM eventos")
    total_eventos = cursor.fetchone()[0]

    # IPs únicas
    cursor.execute("SELECT COUNT(DISTINCT ip) FROM eventos")
    ips_unicas = cursor.fetchone()[0]

    # Conteo por tipo de ataque
    cursor.execute("""
        SELECT tipo_ataque, COUNT(*) as cantidad 
        FROM eventos 
        GROUP BY tipo_ataque
        ORDER BY cantidad DESC
    """)
    ataques_por_tipo = {fila[0]: fila[1] for fila in cursor.fetchall()}

    # Conteo por gravedad
    cursor.execute("""
        SELECT gravedad, COUNT(*) as cantidad 
        FROM eventos 
        GROUP BY gravedad
        ORDER BY cantidad DESC
    """)
    ataques_por_gravedad = {fila[0]: fila[1] for fila in cursor.fetchall()}

    # Actividad por hora (últimas 24 horas)
    cursor.execute("""
        SELECT strftime('%H', timestamp) as hora, COUNT(*) as cantidad
        FROM eventos
        WHERE timestamp >= datetime('now', '-24 hours')
        GROUP BY hora
        ORDER BY hora
    """)
    actividad_por_hora = {fila[0]: fila[1] for fila in cursor.fetchall()}

    conn.close()

    return {
        "total_eventos": total_eventos,
        "ips_unicas": ips_unicas,
        "ataques_por_tipo": ataques_por_tipo,
        "ataques_por_gravedad": ataques_por_gravedad,
        "actividad_por_hora": actividad_por_hora
    }