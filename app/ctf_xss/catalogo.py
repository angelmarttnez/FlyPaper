"""Catálogo del reto XSS almacenado (academia FlyPaper)."""

from __future__ import annotations

from typing import Any, Optional

RETO_NOMBRE = {1: "XSS-01 · Almacenado"}
FLAG_RETO_01 = "flag{xss_almacenado_admin}"

CATALOGO_RETOS: list[dict[str, Any]] = [
    {
        "id": 1,
        "codigo": "01",
        "categoria": "xss",
        "categoria_label": "XSS",
        "titulo": "XSS Almacenado",
        "subtitulo": "Engaña al bot moderador del blog del lab",
        "dificultad": "Media",
        "dificultad_clase": "media",
        "puntos": 110,
        "activo": True,
        "descripcion": (
            "Envía un comentario malicioso almacenado. Un bot administrador revisará "
            "los comentarios nuevos sin ejecutar JavaScript real."
        ),
        "objetivo": "Haz que el bot detecte tu payload y completa el robo simulado de cookie.",
        "pista": (
            "El admin revisa los comentarios nuevos del blog, ¿qué pasaría si uno de "
            "ellos contuviera código?"
        ),
    },
]


def obtener_reto(reto_id: int) -> Optional[dict[str, Any]]:
    for reto in CATALOGO_RETOS:
        if int(reto["id"]) == int(reto_id):
            return reto
    return None
