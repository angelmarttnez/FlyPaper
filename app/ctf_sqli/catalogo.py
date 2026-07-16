"""
Catálogo de retos SQLi de la academia: metadatos, quiz y nombres canónicos en BD.
"""

from __future__ import annotations

from typing import Any, Optional

# Nombres canónicos en la tabla `flags` de flypaper.db
RETO_NOMBRE = {
    1: "SQLi-01 · Auth Bypass",
    2: "SQLi-02 · UNION Based",
    3: "SQLi-03 · Error Based",
    4: "SQLi-04 · Blind Time",
}

# Soluciones conceptuales (validación estricta tras normalizar).
SOLUCIONES_QUIZ: dict[int, dict[str, Any]] = {
    1: {
        "p1": ["'"],
        "p2": ["--", "-- ", "#"],
        "p3": "auth_bypass",
        "p3_opciones": [
            {"valor": "auth_bypass", "texto": "Authentication Bypass (login)"},
            {"valor": "union", "texto": "UNION-based"},
            {"valor": "error", "texto": "Error-based"},
            {"valor": "blind", "texto": "Blind / Time-based"},
        ],
    },
    2: {
        "p1": ["'"],
        "p2": ["--", "-- ", "#"],
        "p3": "union",
        "p3_opciones": [
            {"valor": "union", "texto": "UNION-based"},
            {"valor": "auth_bypass", "texto": "Authentication Bypass (login)"},
            {"valor": "error", "texto": "Error-based"},
            {"valor": "stacked", "texto": "Stacked queries"},
        ],
    },
    3: {
        "p1": ["'"],
        "p2": ["--", "-- ", "#"],
        "p3": "error",
        "p3_opciones": [
            {"valor": "error", "texto": "Error-based"},
            {"valor": "union", "texto": "UNION-based"},
            {"valor": "auth_bypass", "texto": "Authentication Bypass (login)"},
            {"valor": "blind", "texto": "Blind / Time-based"},
        ],
    },
    4: {
        "p1": ["'"],
        "p2": ["--", "-- ", "#"],
        "p3": "blind",
        "p3_opciones": [
            {"valor": "blind", "texto": "Blind / Time-based"},
            {"valor": "union", "texto": "UNION-based"},
            {"valor": "auth_bypass", "texto": "Authentication Bypass (login)"},
            {"valor": "error", "texto": "Error-based"},
        ],
    },
}

CATALOGO_RETOS: list[dict[str, Any]] = [
    {
        "id": 1,
        "codigo": "01",
        "titulo": "Authentication Bypass",
        "subtitulo": "Rompe el login concatenando SQL",
        "dificultad": "Fácil",
        "dificultad_clase": "facil",
        "puntos": 50,
        "activo": True,
        "descripcion": (
            "Laboratorio de autenticación vulnerable. La consulta SQL se construye "
            "con concatenación directa de strings (sin prepared statements)."
        ),
        "objetivo": "Inicia sesión sin conocer la contraseña y recupera la flag.",
        "pista": "Prueba usuario `admin'--` (cierra comilla y comenta el AND de la contraseña).",
    },
    {
        "id": 2,
        "codigo": "02",
        "titulo": "UNION Based Extraction",
        "subtitulo": "Extrae datos ocultos con UNION SELECT",
        "dificultad": "Media",
        "dificultad_clase": "media",
        "puntos": 100,
        "activo": True,
        "descripcion": (
            "Buscador de productos vulnerable. Los resultados se renderizan en una "
            "tabla HTML: ideal para inyecciones UNION visibles."
        ),
        "objetivo": "Enumera columnas y extrae la flag de una tabla secundaria.",
        "pista": "Prueba ' UNION SELECT … -- y alinea el número de columnas.",
    },
    {
        "id": 3,
        "codigo": "03",
        "titulo": "Error Based",
        "subtitulo": "Fuga de datos vía mensajes de error",
        "dificultad": "Media",
        "dificultad_clase": "media",
        "puntos": 125,
        "activo": False,
        "descripcion": "Laboratorio en construcción: extracción basada en errores SQLite/MySQL.",
        "objetivo": "Próximamente.",
        "pista": "",
    },
    {
        "id": 4,
        "codigo": "04",
        "titulo": "Blind Time-Based",
        "subtitulo": "Inferencia con retardos temporales",
        "dificultad": "Difícil",
        "dificultad_clase": "dificil",
        "puntos": 150,
        "activo": False,
        "descripcion": "Laboratorio en construcción: SQLi ciega con SLEEP/BENCHMARK.",
        "objetivo": "Próximamente.",
        "pista": "",
    },
]


def obtener_reto(reto_id: int) -> Optional[dict[str, Any]]:
    """Devuelve metadatos públicos de un reto o None."""
    for reto in CATALOGO_RETOS:
        if reto["id"] == int(reto_id):
            return reto
    return None


def normalizar_respuesta_quiz(texto: str) -> str:
    """Normaliza respuestas conceptuales (trim; P2 sin espacios finales opcionales)."""
    return (texto or "").strip()


def validar_quiz(reto_id: int, p1: str, p2: str, p3: str) -> tuple[bool, str]:
    """
    Valida las 3 respuestas conceptuales del cuestionario.

    Returns:
        (ok, mensaje_error)
    """
    sol = SOLUCIONES_QUIZ.get(int(reto_id))
    if not sol:
        return False, "Reto no válido"

    r1 = normalizar_respuesta_quiz(p1)
    r2 = normalizar_respuesta_quiz(p2)
    r3 = normalizar_respuesta_quiz(p3).lower()

    if r1 not in sol["p1"]:
        return False, "P1 incorrecta: revisa el carácter que rompe la sintaxis SQL."
    # Acepta '--' y '-- ' equivalentes
    r2_ok = r2 in sol["p2"] or r2.rstrip() in [x.rstrip() for x in sol["p2"]]
    if not r2_ok:
        return False, "P2 incorrecta: revisa los caracteres de comentario SQL."
    if r3 != sol["p3"]:
        return False, "P3 incorrecta: selecciona el tipo de inyección explotada."
    return True, ""
