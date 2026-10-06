"""
Agregación de catálogos CTF (SQLi, XSS, Path Traversal, IDOR) para /objetivos.
"""

from __future__ import annotations

from typing import Any


def _url_entrada_lab(slug: str, retos: list[dict[str, Any]]) -> str:
    """
    Primera URL del lab activo de la categoría (sidebar /objetivos).

    SQLi apunta al primer reto activo del catálogo; el resto tiene un único lab 01.
    """
    if slug == "sqli":
        for reto in retos:
            if reto.get("activo", True):
                return f"/objetivos/sqli/{int(reto['id'])}"
        return "/objetivos/sqli/1"
    if slug == "xss":
        return "/objetivos/xss/01"
    if slug == "pathtraversal":
        return "/objetivos/pathtraversal/01"
    if slug == "idor":
        return "/objetivos/idor/01"
    return "/objetivos"


def listar_categorias_academia(usuario_id: str) -> list[dict[str, Any]]:
    """
    Devuelve categorías con sus retos y estado ``resuelto`` por usuario.

    Returns:
        Lista de dicts: slug, nombre, icono, retos.
    """
    from app.ctf_idor.lab_db import estado_retos_para_usuario as estado_idor
    from app.ctf_pathtraversal.lab_db import estado_retos_para_usuario as estado_pt
    from app.ctf_sqli.lab_db import estado_retos_para_usuario as estado_sqli
    from app.ctf_xss.lab_db import estado_retos_para_usuario as estado_xss

    uid = (usuario_id or "").strip()
    categorias_raw = [
        {
            "slug": "sqli",
            "nombre": "SQL Injection",
            "icono": "💉",
            "retos": estado_sqli(uid),
        },
        {
            "slug": "xss",
            "nombre": "Cross-Site Scripting (XSS)",
            "icono": "🧪",
            "retos": estado_xss(uid),
        },
        {
            "slug": "pathtraversal",
            "nombre": "Path Traversal / LFI",
            "icono": "📂",
            "retos": estado_pt(uid),
        },
        {
            "slug": "idor",
            "nombre": "IDOR",
            "icono": "🔓",
            "retos": estado_idor(uid),
        },
    ]
    out: list[dict[str, Any]] = []
    for cat in categorias_raw:
        retos = cat.get("retos") or []
        out.append(
            {
                **cat,
                "url_entrada": _url_entrada_lab(cat["slug"], retos),
                "ancla_seccion": f"cat-{cat['slug']}",
            }
        )
    return out


def progreso_global_academia(usuario_id: str) -> dict[str, int]:
    """Totales completados / activos en todas las categorías."""
    categorias = listar_categorias_academia(usuario_id)
    total = 0
    completados = 0
    for cat in categorias:
        for reto in cat.get("retos") or []:
            if not reto.get("activo", True):
                continue
            total += 1
            if reto.get("resuelto"):
                completados += 1
    return {"completados": completados, "total": total or 1}
