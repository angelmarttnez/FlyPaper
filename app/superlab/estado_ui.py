"""
Estado del SuperLab para la UI (/objetivos, panel final).
"""

from __future__ import annotations

from typing import Any

from app.ctf_sqli.catalogo import CATALOGO_SUPERLAB, checkpoints_superlab
from app.superlab.datos_ficticios import FLAG_FASE_5
from app.superlab.progreso import identidad_progreso_superlab, obtener_o_crear_progreso


def estado_superlab_para_usuario(usuario_sesion: str | None = None) -> dict[str, Any]:
    """
    Progreso enriquecido para tarjetas CTF y panel NexusCorp.

    ``usuario_sesion`` debe ser ``session['usuario']`` del portal o None.
    """
    uid = usuario_sesion or identidad_progreso_superlab()
    progreso = obtener_o_crear_progreso(uid)
    flags = set(progreso.get("flags_capturadas") or [])
    fase = int(progreso.get("fase_actual") or 0)

    checkpoints = []
    for cp in checkpoints_superlab():
        flag = cp["flag"]
        checkpoints.append({**cp, "superado": flag in flags})

    resuelto = FLAG_FASE_5 in flags
    completados_cp = sum(
        1 for cp in checkpoints if cp["superado"] and not cp.get("puntua")
    )
    if resuelto:
        completados_cp = 5

    return {
        **CATALOGO_SUPERLAB,
        "fase_actual": fase,
        "staging_descubierto": bool(progreso.get("staging_descubierto")),
        "flags_capturadas": list(flags),
        "checkpoints": checkpoints,
        "checkpoints_superados": min(completados_cp, 5),
        "checkpoints_total": 5,
        "resuelto": resuelto,
    }
