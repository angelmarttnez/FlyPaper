"""Catálogo Path Traversal — informes."""

from __future__ import annotations

from typing import Any, Optional

RETO_NOMBRE = {
    1: "PT-01 · Informes internos",
    2: "PT-02 · Filtro evadido",
}
FLAG_RETO_01 = "flag{path_traversal_informes}"
FLAG_RETO_02 = "flag{path_traversal_encoding_bypass}"

CATALOGO_RETOS: list[dict[str, Any]] = [
    {
        "id": 1,
        "codigo": "01",
        "categoria": "pathtraversal",
        "categoria_label": "Path Traversal",
        "titulo": "Descarga de informes",
        "subtitulo": "El parámetro file no sanitiza ..",
        "dificultad": "Media",
        "dificultad_clase": "media",
        "puntos": 110,
        "activo": True,
        "descripcion": "Endpoint de descarga que concatena nombres de fichero sin filtrar traversal.",
        "objetivo": "Lee el informe secreto flag.txt dentro del árbol del módulo.",
        "pista": (
            "El endpoint busca ficheros dentro de una carpeta... "
            "¿qué pasa si le pides que suba un nivel?"
        ),
    },
    {
        "id": 2,
        "codigo": "02",
        "categoria": "pathtraversal",
        "categoria_label": "Path Traversal",
        "titulo": "Path Traversal — Filtro evadido",
        "subtitulo": "Filtro activo sobre ../ literal · encoding",
        "dificultad": "Media-Alta",
        "dificultad_clase": "media",
        "puntos": 130,
        "activo": True,
        "descripcion": (
            "Este reto incluye un filtro ingenuo que rechaza «../» y «..\\» en el parámetro "
            "file tal como llega en la query (sin interpretar encoding). La ruta final sigue "
            "construyéndose con el valor decodificado por el servidor."
        ),
        "objetivo": "Evade el filtro y lee archivos_secretos/flag_02.txt dentro del laboratorio.",
        "pista": (
            "El filtro bloquea ../ tal cual... pero, ¿y si tu navegador o el servidor "
            "decodifican la URL antes de que el filtro la vea?"
        ),
    },
]


def flag_por_reto_id(reto_id: int) -> Optional[str]:
    if int(reto_id) == 1:
        return FLAG_RETO_01
    if int(reto_id) == 2:
        return FLAG_RETO_02
    return None


def obtener_reto(reto_id: int) -> Optional[dict[str, Any]]:
    for reto in CATALOGO_RETOS:
        if int(reto["id"]) == int(reto_id):
            return reto
    return None
