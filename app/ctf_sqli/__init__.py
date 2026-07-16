"""
Academia CTF — módulo SQL Injection (Cyber Range FlyPaper).

Blueprint `ctf_sqli`: laboratorios aislados, cuestionario de 3 preguntas y
validación de flags contra `flypaper.db` / progreso en `objetivos_completados`.
"""

from .lab_db import inicializar_labs_sqli
from .routes import ctf_api, ctf_sqli

__all__ = ("ctf_sqli", "ctf_api", "inicializar_labs_sqli")
