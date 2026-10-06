"""

Catálogo de writeups publicados en /documentacion/writeups/<slug>.

"""



from __future__ import annotations



from pathlib import Path

from typing import Any, Callable, Optional



from flask import request
from urllib.parse import urlparse


from app.core.markdown_doc import renderizar_markdown_a_html


def _url_volver_segura(destino: Optional[str]) -> Optional[str]:
    """
    Solo rutas relativas internas (evita open redirect vía ?from=https://...).
    """
    texto = (destino or "").strip()
    if not texto or texto.startswith("//") or "://" in texto:
        return None
    if not texto.startswith("/"):
        return None
    parsed = urlparse(texto)
    ruta = parsed.path or ""
    if not ruta.startswith("/"):
        return None
    if parsed.query:
        return f"{ruta}?{parsed.query}"
    return ruta



# Raíz del proyecto (FlyPaper/)

RUTA_RAIZ = Path(__file__).resolve().parent.parent



CATALOGO_WRITEUPS: dict[str, dict[str, Any]] = {

    "superlab": {

        "titulo": "SuperLab NexusCorp",

        "subtitulo": "Cadena ofensiva multi-fase (6 pasos)",

        "archivo": RUTA_RAIZ / "preguntas_superlab_writeup.md",

        "lab_url": "/web-nexuscorp/",

    },

    "xss-01": {

        "titulo": "XSS-01 · Almacenado",

        "subtitulo": "Bot moderador y robo simulado de cookie",

        "archivo": RUTA_RAIZ / "docs" / "writeups" / "xss_01.md",

        "lab_url": "/objetivos/xss/01",

    },

    "pathtraversal-01": {

        "titulo": "PT-01 · Path Traversal",

        "subtitulo": "Descarga de informes internos",

        "archivo": RUTA_RAIZ / "docs" / "writeups" / "pathtraversal_01.md",

        "lab_url": "/objetivos/pathtraversal/01",

    },

    "idor-01": {

        "titulo": "IDOR-01 · Nóminas",

        "subtitulo": "Acceso a recursos ajenos por identificador",

        "archivo": RUTA_RAIZ / "docs" / "writeups" / "idor_01.md",

        "lab_url": "/objetivos/idor/01",

    },

}





def ruta_writeup_documentacion(slug: str) -> str:

    """URL del writeup (para plantillas; no depende de ``url_for``)."""

    clave = (slug or "").strip().lower()

    if clave not in CATALOGO_WRITEUPS:

        return "/documentacion"

    return f"/documentacion/writeups/{clave}"





def listar_writeups_documentacion() -> list[dict[str, Any]]:

    """Metadatos para índices (sidebar /documentacion)."""

    out = []

    for slug, meta in CATALOGO_WRITEUPS.items():

        out.append(

            {

                "slug": slug,

                "titulo": meta["titulo"],

                "subtitulo": meta.get("subtitulo") or "",

                "lab_url": meta.get("lab_url") or "",

                "url_writeup": ruta_writeup_documentacion(slug),

            }

        )

    return out





def obtener_writeup_renderizado(slug: str) -> Optional[dict[str, Any]]:

    """

    Carga el Markdown del slug y devuelve HTML + metadatos.



    Returns:

        None si el slug no existe o falta el fichero.

    """

    meta = CATALOGO_WRITEUPS.get((slug or "").strip().lower())

    if meta is None:

        return None

    ruta: Path = meta["archivo"]

    if not ruta.is_file():

        return None

    texto = ruta.read_text(encoding="utf-8")

    return {

        **meta,

        "slug": slug.lower(),

        "contenido_html": renderizar_markdown_a_html(texto),

    }





def render_pagina_writeup(

    plantilla_publica_fn: Callable[..., Any],

    slug: str,

):

    """Construye la respuesta HTML del writeup con navbar/sesión unificados."""

    writeup = obtener_writeup_renderizado(slug)

    if writeup is None:

        return plantilla_publica_fn("404.html", nav_activo="documentacion"), 404

    volver_url = _url_volver_segura(request.args.get("from"))

    return plantilla_publica_fn(

        "documentacion/writeup.html",

        nav_activo="documentacion",

        writeup=writeup,

        otros_writeups=listar_writeups_documentacion(),

        volver_url=volver_url,

    )





def registrar_rutas_writeups_documentacion(aplicacion, plantilla_publica_fn, limiter) -> None:

    """

    Registra la ruta de writeups en el arranque (endpoint ``pagina_writeup_documentacion``).

    """



    @aplicacion.get(

        "/documentacion/writeups/<slug>",

        endpoint="pagina_writeup_documentacion",

    )

    @limiter.limit("60 per minute")

    def pagina_writeup_documentacion(slug: str):

        return render_pagina_writeup(plantilla_publica_fn, slug)


