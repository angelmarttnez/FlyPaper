"""
WSGI entrypoint para Gunicorn / producción.

``app.py`` (entrypoint local) y el paquete ``app/`` colisionan en el nombre
de módulo. Este archivo carga ``app.py`` por ruta de fichero y expone
``aplicacion`` sin sombrear el paquete.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_RUTA_APP_PY = Path(__file__).resolve().parent / "app.py"
_SPEC = importlib.util.spec_from_file_location("flypaper_entrypoint", _RUTA_APP_PY)
if _SPEC is None or _SPEC.loader is None:
    raise ImportError(f"No se pudo cargar el entrypoint: {_RUTA_APP_PY}")

_MODULO = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULO)

aplicacion = _MODULO.aplicacion
