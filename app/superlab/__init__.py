"""
SuperLab NexusCorp — reto encadenado multi-fase (Cyber Range FlyPaper).

Separado de ``app/ctf_sqli/``: flujo narrativo con BD aislada ``superlab.db``.
"""

from .superlab_db import inicializar_superlab
from .routes import superlab_legacy, superlab_nexus, superlab_staging, superlab_tools

__all__ = (
    "superlab_nexus",
    "superlab_legacy",
    "superlab_staging",
    "superlab_tools",
    "inicializar_superlab",
)
