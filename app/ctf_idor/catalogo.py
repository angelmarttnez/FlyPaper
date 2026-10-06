"""Catálogo IDOR — nóminas."""

from __future__ import annotations

from typing import Any, Optional

RETO_NOMBRE = {1: "IDOR-01 · Nóminas"}
FLAG_RETO_01 = "flag{idor_nomina_ajena}"

CATALOGO_RETOS: list[dict[str, Any]] = [
    {
        "id": 1,
        "codigo": "01",
        "categoria": "idor",
        "categoria_label": "IDOR",
        "titulo": "Nóminas internas",
        "subtitulo": "Cambia el ID en la URL",
        "dificultad": "Fácil",
        "dificultad_clase": "facil",
        "puntos": 80,
        "activo": True,
        "descripcion": (
            "Portal de nóminas: se te asigna un ID propio, pero el endpoint "
            "no verifica que solo consultes el tuyo."
        ),
        "objetivo": "Accede a la nómina ajena (ID 1) donde está la flag.",
        "pista": (
            "Tu nómina tiene un número. ¿Qué pasa si pruebas con otros números cercanos?"
        ),
    },
]


def obtener_reto(reto_id: int) -> Optional[dict[str, Any]]:
    for reto in CATALOGO_RETOS:
        if int(reto["id"]) == int(reto_id):
            return reto
    return None
