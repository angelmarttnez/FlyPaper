"""
Catálogo de retos SQLi de la academia: metadatos, quiz y nombres canónicos en BD.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any, Optional

# Nombres canónicos en la tabla `flags` de flypaper.db
RETO_NOMBRE = {
    1: "SQLi-01 · Auth Bypass",
    2: "SQLi-02 · UNION Based",
    3: "SQLi-03 · Filter Bypass",
    4: "SQLi-04 · WAF Evasion",
}

# ---------------------------------------------------------------------------
# Banco de preguntas: exactamente 5 por reto
#   - 3 tipo "test"  → radio A/B/C (respuesta_correcta = "A"|"B"|"C")
#   - 2 tipo "corta" → una palabra (respuesta_correcta = lista de aliases)
# ---------------------------------------------------------------------------

CUESTIONARIOS: dict[int, list[dict[str, Any]]] = {
    1: [
        {
            "id": "p1",
            "tipo": "test",
            "enunciado": (
                "¿Por qué es peligrosa la concatenación de usuario/contraseña "
                "directamente en la consulta SQL del login?"
            ),
            "opciones": [
                {
                    "letra": "A",
                    "texto": "Porque ralentiza el servidor sin riesgo de seguridad",
                },
                {
                    "letra": "B",
                    "texto": "Porque el atacante puede inyectar SQL y alterar la lógica de autenticación",
                },
                {
                    "letra": "C",
                    "texto": "Porque obliga a usar HTTPS en todas las peticiones",
                },
            ],
            "respuesta_correcta": "B",
        },
        {
            "id": "p2",
            "tipo": "test",
            "enunciado": (
                "¿Qué técnica mitiga este riesgo separando el código SQL "
                "de los datos aportados por el usuario?"
            ),
            "opciones": [
                {
                    "letra": "A",
                    "texto": "Consultas preparadas / parametrizadas (prepared statements)",
                },
                {
                    "letra": "B",
                    "texto": "Aumentar el tamaño máximo del campo password",
                },
                {
                    "letra": "C",
                    "texto": "Mostrar el SQL completo en la respuesta HTTP",
                },
            ],
            "respuesta_correcta": "A",
        },
        {
            "id": "p3",
            "tipo": "test",
            "enunciado": "¿Qué describe mejor un WAF (Web Application Firewall)?",
            "opciones": [
                {
                    "letra": "A",
                    "texto": "Un antivirus solo para estaciones Windows",
                },
                {
                    "letra": "B",
                    "texto": "Un firewall de red que únicamente cierra puertos TCP",
                },
                {
                    "letra": "C",
                    "texto": "Un filtro HTTP que analiza peticiones según firmas y reglas",
                },
            ],
            "respuesta_correcta": "C",
        },
        {
            "id": "p4",
            "tipo": "corta",
            "enunciado": (
                "¿Qué carácter (un solo símbolo) suele usarse para cerrar "
                "una cadena SQL en un bypass de login?"
            ),
            "placeholder": "un carácter",
            "respuesta_correcta": ["'", "comilla", "apostrofe", "apostrophe"],
        },
        {
            "id": "p5",
            "tipo": "corta",
            "enunciado": (
                "Escribe la sigla (3 letras) del sistema que filtra ataques "
                "web en el perímetro de la aplicación."
            ),
            "placeholder": "3 letras",
            "respuesta_correcta": ["waf"],
        },
    ],
    2: [
        {
            "id": "p1",
            "tipo": "test",
            "enunciado": (
                "En una inyección UNION, ¿qué deben cumplir las consultas "
                "unidas para no provocar error de sintaxis?"
            ),
            "opciones": [
                {
                    "letra": "A",
                    "texto": "Usar obligatoriamente la misma tabla en ambos SELECT",
                },
                {
                    "letra": "B",
                    "texto": "Tener el mismo número de columnas (y tipos compatibles)",
                },
                {
                    "letra": "C",
                    "texto": "Ejecutarse solo con el método HTTP PUT",
                },
            ],
            "respuesta_correcta": "B",
        },
        {
            "id": "p2",
            "tipo": "test",
            "enunciado": (
                "¿Para qué se usa típicamente UNION SELECT cuando hay "
                "salida visible en la página?"
            ),
            "opciones": [
                {
                    "letra": "A",
                    "texto": "Extraer datos de otras tablas y mostrarlos en el resultado",
                },
                {
                    "letra": "B",
                    "texto": "Cifrar la base de datos con AES automáticamente",
                },
                {
                    "letra": "C",
                    "texto": "Bloquear el WAF de forma permanente",
                },
            ],
            "respuesta_correcta": "A",
        },
        {
            "id": "p3",
            "tipo": "test",
            "enunciado": (
                "Si la aplicación no muestra el resultado SQL (salida ciega), "
                "¿qué familia de técnicas se usa habitualmente?"
            ),
            "opciones": [
                {
                    "letra": "A",
                    "texto": "Solo XSS almacenado",
                },
                {
                    "letra": "B",
                    "texto": "Inyección ciega (blind): boolean-based o time-based",
                },
                {
                    "letra": "C",
                    "texto": "Ataques de fuerza bruta contra SSH",
                },
            ],
            "respuesta_correcta": "B",
        },
        {
            "id": "p4",
            "tipo": "corta",
            "enunciado": (
                "Escribe la palabra clave SQL (una sola) que permite combinar "
                "el resultado de dos SELECT."
            ),
            "placeholder": "palabra SQL",
            "respuesta_correcta": ["union"],
        },
        {
            "id": "p5",
            "tipo": "corta",
            "enunciado": (
                "Nombre en inglés (una palabra) de la SQLi sin salida visible "
                "en la respuesta HTTP."
            ),
            "placeholder": "una palabra",
            "respuesta_correcta": ["blind", "ciega"],
        },
    ],
    3: [
        {
            "id": "p1",
            "tipo": "test",
            "enunciado": (
                "¿Por qué suelen fallar las listas negras (blacklists) que "
                "bloquean palabras como UNION o SELECT?"
            ),
            "opciones": [
                {
                    "letra": "A",
                    "texto": "Porque son incompletas y se evaden con variantes/ofuscación",
                },
                {
                    "letra": "B",
                    "texto": "Porque solo funcionan en bases de datos NoSQL",
                },
                {
                    "letra": "C",
                    "texto": "Porque obligan a desactivar TLS",
                },
            ],
            "respuesta_correcta": "A",
        },
        {
            "id": "p2",
            "tipo": "test",
            "enunciado": (
                "Si el filtro elimina UNA sola vez la palabra UNION, "
                "¿qué ocurre con un payload tipo UNUNIONION?"
            ),
            "opciones": [
                {
                    "letra": "A",
                    "texto": "Se rechaza siempre porque contiene la subcadena UNION dos veces",
                },
                {
                    "letra": "B",
                    "texto": "Tras borrar una ocurrencia queda UNION y el ataque puede seguir",
                },
                {
                    "letra": "C",
                    "texto": "Convierte automáticamente la query en un prepared statement",
                },
            ],
            "respuesta_correcta": "B",
        },
        {
            "id": "p3",
            "tipo": "test",
            "enunciado": (
                "Para un parámetro que debe ser solo numérico, ¿qué enfoque "
                "es más robusto que una blacklist?"
            ),
            "opciones": [
                {
                    "letra": "A",
                    "texto": "Ampliar la blacklist con más palabras prohibidas",
                },
                {
                    "letra": "B",
                    "texto": "Ocultar la URL (seguridad por oscuridad)",
                },
                {
                    "letra": "C",
                    "texto": "Lista blanca (whitelist): aceptar solo el formato esperado",
                },
            ],
            "respuesta_correcta": "C",
        },
        {
            "id": "p4",
            "tipo": "corta",
            "enunciado": (
                "Una palabra: ¿cómo se llama en inglés el enfoque de "
                "«lista negra» de filtros?"
            ),
            "placeholder": "una palabra",
            "respuesta_correcta": ["blacklist", "blacklists"],
        },
        {
            "id": "p5",
            "tipo": "corta",
            "enunciado": (
                "Una palabra: ¿cómo se llama en inglés el enfoque de "
                "«lista blanca» / allowlist?"
            ),
            "placeholder": "una palabra",
            "respuesta_correcta": ["whitelist", "allowlist", "whitelisting"],
        },
    ],
    4: [
        {
            "id": "p1",
            "tipo": "test",
            "enunciado": (
                "Con el WAF real activo, ¿qué ocurre si envías payloads SQLi "
                "genéricos detectables de forma repetida?"
            ),
            "opciones": [
                {
                    "letra": "A",
                    "texto": "Suman riesgo en Redis y pueden acabar en la Jail Page",
                },
                {
                    "letra": "B",
                    "texto": "Se invalida automáticamente tu cuenta de alumno",
                },
                {
                    "letra": "C",
                    "texto": "Nada: el WAF nunca bloquea, solo escribe logs en disco",
                },
            ],
            "respuesta_correcta": "A",
        },
        {
            "id": "p2",
            "tipo": "test",
            "enunciado": (
                "En un bypass ``UNION/**/SELECT``, ¿qué papel juegan los "
                "comentarios ``/**/`` si el WAF los elimina sin dejar espacio?"
            ),
            "opciones": [
                {
                    "letra": "A",
                    "texto": "Cifran el payload con AES antes de llegar al WAF",
                },
                {
                    "letra": "B",
                    "texto": "Actúan como delimitadores: al borrarse, rompen firmas que buscan palabras separadas",
                },
                {
                    "letra": "C",
                    "texto": "Obligan a usar siempre el método HTTP TRACE",
                },
            ],
            "respuesta_correcta": "B",
        },
        {
            "id": "p3",
            "tipo": "test",
            "enunciado": (
                "El parámetro ``id`` es numérico (sin comillas en la query). "
                "¿Por qué eso reduce firmas que buscan patrones como ``' OR``?"
            ),
            "opciones": [
                {
                    "letra": "A",
                    "texto": "Porque no hace falta (ni suele enviarse) la comilla simple en el payload",
                },
                {
                    "letra": "B",
                    "texto": "Porque SQLite ignora cualquier UNION en columnas numéricas",
                },
                {
                    "letra": "C",
                    "texto": "Porque el WAF solo inspecciona cabeceras Cookie",
                },
            ],
            "respuesta_correcta": "A",
        },
        {
            "id": "p4",
            "tipo": "corta",
            "enunciado": (
                "Escribe la sigla del componente que firma y bloquea "
                "payloads en este laboratorio (3 letras)."
            ),
            "placeholder": "3 letras",
            "respuesta_correcta": ["waf"],
        },
        {
            "id": "p5",
            "tipo": "corta",
            "enunciado": (
                "Una palabra: nombre de la página/calabozo a la que te "
                "manda el perímetro si superas el umbral de riesgo."
            ),
            "placeholder": "una palabra",
            "respuesta_correcta": ["jail", "calabozo", "jaula"],
        },
    ],
}

# Alias de compatibilidad.
SOLUCIONES_QUIZ = CUESTIONARIOS

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
        "titulo": "Bypass de Filtro Local",
        "subtitulo": "Sanitización defectuosa: una sola pasada",
        "dificultad": "Media",
        "dificultad_clase": "media",
        "puntos": 125,
        "activo": True,
        "descripcion": (
            "Endpoint con filtro casero que elimina UNA vez las palabras UNION y SELECT. "
            "El WAF global está desactivado aquí: solo luchas contra el filtro local."
        ),
        "objetivo": (
            "Bypassea el filtro incompleto, inyecta UNION y extrae la flag de la tabla vault."
        ),
        "pista": (
            "El filtro solo sustituye una ocurrencia (case-insensitive). "
            "Duplicar la keyword suele bastar: UNUNIONION / SELSELECTECT."
        ),
    },
    {
        "id": 4,
        "codigo": "04",
        "titulo": "Bypass del WAF Real",
        "subtitulo": "Ofusca el payload o acabarás en el calabozo",
        "dificultad": "Difícil",
        "dificultad_clase": "dificil",
        "puntos": 150,
        "activo": True,
        "descripcion": (
            "El motor WAF de FlyPaper está 100% activo. Payloads genéricos suman riesgo "
            "en Redis; superar el umbral te manda a la Jail Page. Extrae la flag en sigilo."
        ),
        "objetivo": (
            "Envía un UNION ofuscado que no dispare firmas del WAF y lee vault.flag_value."
        ),
        "pista": (
            "El WAF elimina comentarios de bloque ``/**/`` sin dejar espacio. "
            "Prueba a partir keywords: ``UNION/**/SELECT`` y ``FROM`` igual. "
            "Un ``UNION SELECT`` con espacios normales sí te detecta (y suma riesgo)."
        ),
    },
]


def obtener_reto(reto_id: int) -> Optional[dict[str, Any]]:
    """Devuelve metadatos públicos de un reto o None."""
    for reto in CATALOGO_RETOS:
        if reto["id"] == int(reto_id):
            return reto
    return None


def obtener_cuestionario(reto_id: int) -> list[dict[str, Any]]:
    """
    Preguntas públicas del reto para la plantilla (sin filtrar respuestas).

    No incluye ``respuesta_correcta`` para no filtrar soluciones al HTML.
    """
    preguntas = CUESTIONARIOS.get(int(reto_id), [])
    resultado = []
    for indice, preg in enumerate(preguntas):
        item = {
            "id": preg["id"],
            "tipo": preg["tipo"],
            "enunciado": preg["enunciado"],
            "placeholder": preg.get("placeholder", ""),
            "paso": indice + 1,
            "pista": preg.get("pista") or "",
        }
        if preg["tipo"] == "test":
            item["opciones"] = [
                {"letra": op["letra"], "texto": op["texto"]}
                for op in (preg.get("opciones") or [])
            ]
        resultado.append(item)
    return resultado


def obtener_pregunta(reto_id: int, pregunta_id: str) -> Optional[tuple[int, dict[str, Any]]]:
    """
    Busca una pregunta del banco.

    Returns:
        (indice_0based, pregunta) o None.
    """
    preguntas = CUESTIONARIOS.get(int(reto_id))
    if not preguntas:
        return None
    pid = (pregunta_id or "").strip().lower()
    for indice, preg in enumerate(preguntas):
        if str(preg.get("id") or "").lower() == pid:
            return indice, preg
    return None


def normalizar_respuesta_quiz(texto: str) -> str:
    """Normaliza: trim, minúsculas, sin tildes, espacios colapsados."""
    bruto = (texto or "").strip().lower()
    descompuesto = unicodedata.normalize("NFKD", bruto)
    sin_acentos = "".join(ch for ch in descompuesto if not unicodedata.combining(ch))
    return re.sub(r"\s+", " ", sin_acentos).strip()


def _numero_pregunta(pid: str, indice: int) -> int:
    """Convierte p1→1; si falla, usa el índice 1-based."""
    if pid and pid[0] == "p" and pid[1:].isdigit():
        return int(pid[1:])
    return indice + 1


def _es_respuesta_correcta(preg: dict[str, Any], respuesta: str) -> bool:
    """True si la respuesta coincide con la solución del servidor (zero-leak)."""
    tipo = preg.get("tipo") or ""
    esperado = preg.get("respuesta_correcta")

    if tipo == "test":
        valor = (respuesta or "").strip().upper()
        correcta = str(esperado or "").strip().upper()
        return bool(valor) and valor == correcta

    if tipo == "corta":
        valor = normalizar_respuesta_quiz(respuesta)
        if not valor or " " in valor:
            return False
        aliases = esperado if isinstance(esperado, (list, tuple)) else [esperado]
        aliases_norm = {
            normalizar_respuesta_quiz(str(a)) for a in aliases if a is not None
        }
        return valor in aliases_norm

    return False


def _pista_incorrecta(preg: dict[str, Any], respuesta: str) -> str:
    """Pista genérica sin revelar la solución."""
    pista_custom = (preg.get("pista") or "").strip()
    if pista_custom:
        return pista_custom
    tipo = preg.get("tipo") or ""
    if tipo == "corta":
        valor = normalizar_respuesta_quiz(respuesta)
        if not valor:
            return "Escribe una sola palabra y vuelve a verificar."
        if " " in valor:
            return "Solo se admite una palabra (sin espacios)."
        return "Respuesta incorrecta. Piensa en el concepto clave del laboratorio."
    return "Opción incorrecta. Revisa el enunciado y el objetivo del reto."


def validar_paso(
    reto_id: int, pregunta_id: str, respuesta: str
) -> dict[str, Any]:
    """
    Valida un único paso del cuestionario progresivo.

    Returns:
        dict con status («correct»|«incorrect»), next_step, hint, step, total.
        Nunca incluye la respuesta correcta.
    """
    hallado = obtener_pregunta(reto_id, pregunta_id)
    preguntas = CUESTIONARIOS.get(int(reto_id)) or []
    total = len(preguntas)

    if hallado is None or total != 5:
        return {
            "status": "incorrect",
            "hint": "Pregunta no válida para este reto.",
            "next_step": None,
            "step": None,
            "total": total,
        }

    indice, preg = hallado
    paso = indice + 1

    if _es_respuesta_correcta(preg, respuesta):
        siguiente = paso + 1 if paso < total else None
        return {
            "status": "correct",
            "next_step": siguiente,
            "hint": "",
            "step": paso,
            "total": total,
            "quiz_completo": paso >= total,
        }

    return {
        "status": "incorrect",
        "hint": _pista_incorrecta(preg, respuesta),
        "next_step": None,
        "step": paso,
        "total": total,
        "quiz_completo": False,
    }


def _validar_pregunta(
    preg: dict[str, Any], respuesta: str, indice: int
) -> tuple[bool, str]:
    """Valida una pregunta (uso interno / legado)."""
    num = _numero_pregunta(str(preg.get("id") or ""), indice)
    if _es_respuesta_correcta(preg, respuesta):
        return True, ""
    if (preg.get("tipo") or "") == "corta":
        valor = normalizar_respuesta_quiz(respuesta)
        if not valor or " " in valor:
            return False, f"Error en la pregunta {num}: escribe una sola palabra."
    return False, f"Error en la pregunta {num}: respuesta incorrecta."


def validar_quiz(
    reto_id: int, respuestas: dict[str, Any]
) -> tuple[bool, str, Optional[str]]:
    """
    Valida las 5 respuestas del cuestionario del reto.

    Returns:
        (ok, mensaje, pregunta_id_fallida|None)
    """
    preguntas = CUESTIONARIOS.get(int(reto_id))
    if not preguntas or len(preguntas) != 5:
        return False, "Reto no válido o cuestionario incompleto.", None

    for indice, preg in enumerate(preguntas):
        pid = str(preg.get("id") or f"p{indice + 1}")
        raw = respuestas.get(pid, "")
        if raw is None:
            raw = ""
        ok, mensaje = _validar_pregunta(preg, str(raw), indice)
        if not ok:
            return False, mensaje, pid
    return True, "", None
