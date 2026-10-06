"""
Conversión de Markdown a HTML seguro para documentación y writeups.
"""

from __future__ import annotations

import markdown


def renderizar_markdown_a_html(texto: str) -> str:
    """
    Devuelve HTML listo para insertar en plantillas (contenido académico).

    Args:
        texto: Markdown fuente.

    Returns:
        Fragmento HTML (sin envoltorio ``html/body``).
    """
    fuente = (texto or "").strip()
    if not fuente:
        return "<p><em>Sin contenido.</em></p>"
    return markdown.markdown(
        fuente,
        extensions=["fenced_code", "tables", "sane_lists"],
    )
