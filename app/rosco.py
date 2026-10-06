"""
Parser y selección aleatoria del Rosco Pasapalabra (SecOps / ASIR).

Lee ``preguntas_rosco.md`` en la raíz del proyecto, agrupa por letra (A–Z + Ñ)
y elige una pregunta al azar por letra para cada partida.
"""

from __future__ import annotations

import logging
import random
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Orden canónico del rosco (27 letras, Ñ tras N).
ORDEN_LETRAS_ROSCO = list("ABCDEFGHIJKLMNÑOPQRSTUVWXYZ")

_RE_LETRA = re.compile(r"^##\s+LETRA\s+(.+?)\s*$", re.IGNORECASE)
_RE_PREGUNTA = re.compile(
    r"^-\s+\*\*(Empieza por|Contiene la)\s+([^:]+):\*\*\s*(.+?)\s*$",
    re.IGNORECASE,
)
_RE_RESPUESTA = re.compile(r"^-\s*Respuesta:\s*(.+?)\s*$", re.IGNORECASE)


def ruta_preguntas_rosco() -> Path:
    """Ruta absoluta a ``preguntas_rosco.md`` (raíz del repo / contenedor)."""
    # app/rosco.py → raíz = parent.parent
    raiz = Path(__file__).resolve().parent.parent
    return raiz / "preguntas_rosco.md"


def _normalizar_letra(texto: str) -> str:
    """Normaliza la etiqueta de letra a mayúsculas (incluye Ñ)."""
    return (texto or "").strip().upper()


def _tipo_desde_prefijo(prefijo: str) -> str:
    """Devuelve 'empieza' o 'contiene' según el encabezado Markdown."""
    p = (prefijo or "").strip().lower()
    if p.startswith("contiene"):
        return "contiene"
    return "empieza"


def _etiqueta_tipo(tipo: str, letra: str) -> str:
    """Badge semántico para la UI (EMPIEZA POR X / CONTIENE LA X)."""
    if tipo == "contiene":
        return f"CONTIENE LA {letra}"
    return f"EMPIEZA POR {letra}"


@lru_cache(maxsize=1)
def cargar_banco_preguntas_rosco(mtime_ns: int = 0) -> dict[str, list[dict[str, Any]]]:
    """
    Parsea el Markdown y agrupa preguntas por letra.

    Args:
        mtime_ns: Marca de modificación del fichero (invalida caché al cambiar).

    Returns:
        Dict letra → lista de dicts con letra, tipo, etiqueta, pregunta, respuesta.
    """
    del mtime_ns  # solo participa en la clave de lru_cache
    ruta = ruta_preguntas_rosco()
    banco: dict[str, list[dict[str, Any]]] = {letra: [] for letra in ORDEN_LETRAS_ROSCO}

    if not ruta.is_file():
        logger.error("No se encuentra el banco del rosco: %s", ruta)
        return banco

    letra_actual = None
    pendiente: dict[str, Any] | None = None

    with ruta.open(encoding="utf-8") as fichero:
        for linea_raw in fichero:
            linea = linea_raw.rstrip("\n")
            match_letra = _RE_LETRA.match(linea.strip())
            if match_letra:
                if pendiente and letra_actual:
                    banco[letra_actual].append(pendiente)
                    pendiente = None
                letra_actual = _normalizar_letra(match_letra.group(1))
                if letra_actual not in banco:
                    banco[letra_actual] = []
                continue

            match_preg = _RE_PREGUNTA.match(linea.strip())
            if match_preg and letra_actual:
                if pendiente:
                    banco[letra_actual].append(pendiente)
                tipo = _tipo_desde_prefijo(match_preg.group(1))
                letra_enunciado = _normalizar_letra(match_preg.group(2))
                # Preferir la letra de sección; el enunciado debe coincidir.
                letra_uso = letra_actual or letra_enunciado
                pendiente = {
                    "letra": letra_uso,
                    "tipo": tipo,
                    "etiqueta": _etiqueta_tipo(tipo, letra_uso),
                    "pregunta": match_preg.group(3).strip(),
                    "respuesta": "",
                }
                continue

            match_resp = _RE_RESPUESTA.match(linea.strip())
            if match_resp and pendiente is not None:
                pendiente["respuesta"] = match_resp.group(1).strip()
                if letra_actual:
                    banco[letra_actual].append(pendiente)
                pendiente = None

    if pendiente and letra_actual:
        banco[letra_actual].append(pendiente)

    return banco


def obtener_banco_preguntas_rosco() -> dict[str, list[dict[str, Any]]]:
    """Carga el banco invalidando caché si el Markdown cambió en disco."""
    ruta = ruta_preguntas_rosco()
    try:
        mtime = ruta.stat().st_mtime_ns if ruta.is_file() else 0
    except OSError:
        mtime = 0
    return cargar_banco_preguntas_rosco(mtime)


def seleccionar_rosco_aleatorio() -> list[dict[str, Any]]:
    """
    Elige una pregunta aleatoria por cada letra del rosco (27 ítems).

    Returns:
        Lista ordenada A…Z/Ñ lista para serializar a JSON en la plantilla.
    """
    banco = obtener_banco_preguntas_rosco()
    rosco: list[dict[str, Any]] = []
    for letra in ORDEN_LETRAS_ROSCO:
        opciones = [p for p in banco.get(letra, []) if p.get("pregunta") and p.get("respuesta")]
        if not opciones:
            logger.warning("Rosco: sin preguntas válidas para la letra %s", letra)
            continue
        elegida = dict(random.choice(opciones))
        rosco.append(elegida)
    return rosco
