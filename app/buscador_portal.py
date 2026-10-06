"""
Buscador unificado del portal público (/search?q=).

Indexa blog, catálogo de labs (5 categorías) y documentación (writeups + secciones).
Todas las consultas a SQLite usan parámetros enlazados; el término ``q`` nunca se concatena en SQL.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from app.ctf_idor.catalogo import CATALOGO_RETOS as CATALOGO_IDOR
from app.ctf_pathtraversal.catalogo import CATALOGO_RETOS as CATALOGO_PT
from app.ctf_sqli.catalogo import CATALOGO_RETOS as CATALOGO_SQLI, CATALOGO_SUPERLAB
from app.ctf_xss.catalogo import CATALOGO_RETOS as CATALOGO_XSS
from app.database import RUTA_RAIZ_PROYECTO, obtener_conexion
from app.documentacion_writeups import CATALOGO_WRITEUPS, ruta_writeup_documentacion

# Texto indexable de bloques estáticos en Documentacion.html (sin parsear HTML en runtime).
SECCIONES_DOCUMENTACION: list[dict[str, str]] = [
    {
        "titulo": "Introducción a SQL Injection",
        "url": "/documentacion#introduccion",
        "texto": (
            "La inyección SQL ocurre cuando la aplicación concatena entrada de usuario "
            "en consultas. En FlyPaper el aprendizaje práctico vive en /objetivos/sqli/."
        ),
    },
    {
        "titulo": "Teoría XSS",
        "url": "/documentacion#teoria-xss",
        "texto": "Cross-Site Scripting reflejado y almacenado; labs en /objetivos/xss/.",
    },
    {
        "titulo": "Teoría Path Traversal",
        "url": "/documentacion#teoria-path-traversal",
        "texto": "Lectura de ficheros fuera del directorio previsto; labs pathtraversal.",
    },
    {
        "titulo": "Teoría IDOR",
        "url": "/documentacion#teoria-idor",
        "texto": "Insecure Direct Object Reference; acceso a recursos ajenos por identificador.",
    },
    {
        "titulo": "SuperLab NexusCorp",
        "url": "/documentacion#teoria-superlab",
        "texto": "Cadena ofensiva multi-fase: recon, legacy, IDOR, fuzzing, SQLi staging.",
    },
    {
        "titulo": "Cheat sheet SQLi",
        "url": "/documentacion#cheat-sheet",
        "texto": "UNION SELECT, sqlite_master, boolean blind, mitigaciones prepared statements.",
    },
]

_LIMITE_POR_GRUPO = 12
_SNIPPET_MAX = 180


def _normalizar_termino(q: str) -> str:
    return (q or "").strip()


def _texto_coincide(cuerpo: str, termino: str) -> bool:
    if not termino:
        return False
    return termino.lower() in (cuerpo or "").lower()


def _partes_snippet(texto: str, termino: str) -> list[dict[str, Any]]:
    """
    Divide un fragmento en trozos escapables en plantilla (sin |safe).

    Cada parte: {"texto": str, "resaltar": bool}
    """
    bruto = (texto or "").replace("\n", " ").strip()
    if not bruto:
        return [{"texto": "", "resaltar": False}]
    if not termino:
        recorte = bruto[:_SNIPPET_MAX]
        if len(bruto) > _SNIPPET_MAX:
            recorte += "…"
        return [{"texto": recorte, "resaltar": False}]

    lower = bruto.lower()
    needle = termino.lower()
    idx = lower.find(needle)
    if idx < 0:
        recorte = bruto[:_SNIPPET_MAX]
        if len(bruto) > _SNIPPET_MAX:
            recorte += "…"
        return [{"texto": recorte, "resaltar": False}]

    inicio = max(0, idx - 40)
    fin = min(len(bruto), idx + len(termino) + 80)
    ventana = bruto[inicio:fin]
    if inicio > 0:
        ventana = "…" + ventana
    if fin < len(bruto):
        ventana = ventana + "…"

    partes: list[dict[str, Any]] = []
    resto = ventana
    resto_lower = resto.lower()
    while needle in resto_lower:
        pos = resto_lower.find(needle)
        if pos > 0:
            partes.append({"texto": resto[:pos], "resaltar": False})
        partes.append({"texto": resto[pos : pos + len(termino)], "resaltar": True})
        resto = resto[pos + len(termino) :]
        resto_lower = resto.lower()
    if resto:
        partes.append({"texto": resto, "resaltar": False})
    return partes or [{"texto": ventana, "resaltar": False}]


def _buscar_blog(termino: str) -> list[dict[str, Any]]:
    if not termino:
        return []
    patron = f"%{termino}%"
    consulta = """
    SELECT id, titulo, contenido
    FROM posts
    WHERE titulo LIKE ? COLLATE NOCASE
       OR contenido LIKE ? COLLATE NOCASE
    ORDER BY fecha DESC, id DESC
    LIMIT ?;
    """
    with obtener_conexion() as conexion:
        cur = conexion.cursor()
        cur.execute(
            consulta,
            (patron, patron, _LIMITE_POR_GRUPO),
        )
        filas = cur.fetchall()

    salida = []
    for fila in filas:
        titulo = fila["titulo"] or ""
        contenido = fila["contenido"] or ""
        cuerpo = f"{titulo} {contenido}"
        salida.append(
            {
                "titulo": titulo,
                "url": f"/blog/{int(fila['id'])}",
                "snippet_partes": _partes_snippet(cuerpo, termino),
            }
        )
    return salida


def _url_lab(categoria: str, reto: dict[str, Any]) -> str:
    rid = int(reto.get("id") or 1)
    codigo = str(reto.get("codigo") or f"{rid:02d}")
    if categoria == "sqli":
        return f"/objetivos/sqli/{rid}"
    return f"/objetivos/{categoria}/{codigo}"


def _iter_retos_catalogo() -> list[tuple[str, dict[str, Any]]]:
    """Parejas (categoría_slug, reto) incluyendo SuperLab."""
    pares: list[tuple[str, dict[str, Any]]] = []
    for reto in CATALOGO_SQLI:
        if reto.get("activo", True):
            pares.append(("sqli", reto))
    for reto in CATALOGO_XSS:
        if reto.get("activo", True):
            pares.append(("xss", reto))
    for reto in CATALOGO_PT:
        if reto.get("activo", True):
            pares.append(("pathtraversal", reto))
    for reto in CATALOGO_IDOR:
        if reto.get("activo", True):
            pares.append(("idor", reto))
    if CATALOGO_SUPERLAB.get("activo", True):
        pares.append(("superlab", CATALOGO_SUPERLAB))
    return pares


def _buscar_laboratorios(termino: str) -> list[dict[str, Any]]:
    if not termino:
        return []
    salida = []
    for categoria, reto in _iter_retos_catalogo():
        titulo = (reto.get("titulo") or "").strip()
        desc = (reto.get("descripcion") or reto.get("subtitulo") or "").strip()
        objetivo = (reto.get("objetivo") or "").strip()
        blob = f"{titulo} {desc} {objetivo}"
        if not _texto_coincide(blob, termino):
            continue
        if categoria == "superlab":
            url = CATALOGO_SUPERLAB.get("url_entrada") or "/web-nexuscorp/"
        else:
            url = _url_lab(categoria, reto)
        salida.append(
            {
                "titulo": titulo,
                "url": url,
                "etiqueta_categoria": categoria,
                "snippet_partes": _partes_snippet(blob, termino),
            }
        )
        if len(salida) >= _LIMITE_POR_GRUPO:
            break
    return salida


def _buscar_writeups_md(termino: str) -> list[dict[str, Any]]:
    if not termino:
        return []
    salida = []
    vistos: set[str] = set()

    def _indexar_archivo(ruta: Path, titulo: str, url: str) -> None:
        if not ruta.is_file():
            return
        clave = str(ruta.resolve())
        if clave in vistos:
            return
        texto = ruta.read_text(encoding="utf-8", errors="replace")
        if not _texto_coincide(texto, termino) and not _texto_coincide(titulo, termino):
            return
        vistos.add(clave)
        salida.append(
            {
                "titulo": titulo,
                "url": url,
                "snippet_partes": _partes_snippet(texto, termino),
            }
        )

    for slug, meta in CATALOGO_WRITEUPS.items():
        ruta = meta.get("archivo")
        if isinstance(ruta, Path):
            _indexar_archivo(
                ruta,
                meta.get("titulo") or slug,
                ruta_writeup_documentacion(slug),
            )

    carpeta = RUTA_RAIZ_PROYECTO / "docs" / "writeups"
    if carpeta.is_dir():
        for md in sorted(carpeta.glob("*.md")):
            titulo = md.stem.replace("_", " ").title()
            _indexar_archivo(md, titulo, f"/documentacion#writeups")

    for sec in SECCIONES_DOCUMENTACION:
        blob = f"{sec['titulo']} {sec['texto']}"
        if _texto_coincide(blob, termino):
            salida.append(
                {
                    "titulo": sec["titulo"],
                    "url": sec["url"],
                    "snippet_partes": _partes_snippet(sec["texto"], termino),
                }
            )

    return salida[:_LIMITE_POR_GRUPO]


def buscar_portal(q: Optional[str]) -> dict[str, Any]:
    """
    Ejecuta la búsqueda y devuelve grupos listos para la plantilla.

    Returns:
        dict con claves: q, blog, laboratorios, documentacion, total
    """
    termino = _normalizar_termino(q or "")
    blog = _buscar_blog(termino) if termino else []
    laboratorios = _buscar_laboratorios(termino) if termino else []
    documentacion = _buscar_writeups_md(termino) if termino else []
    total = len(blog) + len(laboratorios) + len(documentacion)
    return {
        "q": termino,
        "blog": blog,
        "laboratorios": laboratorios,
        "documentacion": documentacion,
        "total": total,
        "busqueda_realizada": bool(termino),
    }

