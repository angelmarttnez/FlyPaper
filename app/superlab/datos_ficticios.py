"""
Datos semilla de NexusCorp para SuperLab (empleados, mensajes, credenciales legacy).

Las contraseñas provisionales se generan con ``secrets`` en el momento del insert.
"""

from __future__ import annotations

import secrets
import sqlite3

import bcrypt

from app.core.timezone_fp import marca_ahora

# Cuenta de servicio del sistema legacy (fase 1 — filtrada en HTML).
LEGACY_USUARIO = "legacy_support"
LEGACY_PASSWORD = "Soporte2019!"

# Flags narrativas de las fases implementadas (bloques siguientes ampliarán la lista).
FLAG_FASE_1 = "flag{fase1_credenciales_filtradas}"
FLAG_FASE_2 = "flag{fase2_control_acceso_roto}"
FLAG_FASE_3 = "flag{fase3_sqli_login}"
FLAG_FASE_4 = "flag{fase4_mensaje_correcto}"
FLAG_FASE_5 = "flag{fase5_final_cadena_completa}"

# Empleado objetivo del cierre de la cadena (estado vacaciones).
USUARIO_VACACIONES = "m.sanchez"

# Identificador del mensaje filtrado en la bandeja staging (fase 4).
ID_MENSAJE_PROVISIONALES = "it-provisionales-incidente"


def _hash_ruido(contrasena_aleatoria: str) -> str:
    """Hash bcrypt de contraseña aleatoria (ruido; no usable por el alumno)."""
    return bcrypt.hashpw(
        contrasena_aleatoria.encode("utf-8"),
        bcrypt.gensalt(rounds=10),
    ).decode("utf-8")


def _provisional_aleatoria() -> str:
    """Contraseña provisional impredecible (10–12 caracteres URL-safe)."""
    return secrets.token_urlsafe(9)[:12]


def _empleados_plantilla() -> list[dict[str, str]]:
    """
    Siete empleados: 5 activos, 1 vacaciones (objetivo de la cadena), 1 baja.
    """
    return [
        {"nombre": "Laura Méndez", "usuario": "l.mendez", "estado": "activo"},
        {"nombre": "Diego Ortega", "usuario": "d.ortega", "estado": "activo"},
        {"nombre": "Marta Sánchez", "usuario": "m.sanchez", "estado": "vacaciones"},
        {"nombre": "Iván Prieto", "usuario": "i.prieto", "estado": "activo"},
        {"nombre": "Claudia Ruiz", "usuario": "c.ruiz", "estado": "activo"},
        {"nombre": "Héctor Navas", "usuario": "h.navas", "estado": "baja"},
        {"nombre": "Sofía Almada", "usuario": "s.almada", "estado": "activo"},
    ]


def sembrar_datos_superlab(conexion: sqlite3.Connection) -> None:
    """
    Inserta empleados con hashes de ruido y provisionales aleatorias, más mensajes de ejemplo.
    """
    ahora = marca_ahora()
    for emp in _empleados_plantilla():
        ruido = secrets.token_urlsafe(16)
        conexion.execute(
            """
            INSERT INTO superlab_empleados
                (nombre, usuario, estado, password_hash, password_provisional)
            VALUES (?, ?, ?, ?, ?);
            """,
            (
                emp["nombre"],
                emp["usuario"],
                emp["estado"],
                _hash_ruido(ruido),
                _provisional_aleatoria(),
            ),
        )

    mensajes = [
        (
            "rrhh@nexuscorp.internal",
            "Actualización política de acceso",
            "Recordad rotar credenciales provisionales al activar cuentas nuevas.",
            ahora,
        ),
        (
            "it-ops@nexuscorp.internal",
            "Ventana de mantenimiento legacy",
            "El portal -2.0 seguirá accesible hasta completar la migración.",
            ahora,
        ),
        (
            "d.ortega@nexuscorp.internal",
            "Re: cobertura de equipo",
            "Marta está de vacaciones; cualquier urgencia derivar a Laura.",
            ahora,
        ),
    ]
    for remitente, asunto, cuerpo, fecha in mensajes:
        conexion.execute(
            """
            INSERT INTO superlab_mensajes (remitente, asunto, cuerpo, fecha)
            VALUES (?, ?, ?, ?);
            """,
            (remitente, asunto, cuerpo, fecha),
        )
