"""
Blueprints SuperLab NexusCorp: portal actual y sistema legacy -2.0.

Rutas públicas del reto encadenado (exentas de WAF/NGWAF vía excepción pedagógica).
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any, Optional

from flask import (
    Blueprint,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from app.core.timezone_fp import marca_ahora
from app.superlab.auth_staging import intentar_login_staging
from app.ctf_sqli.catalogo import PISTAS_SUPERLAB, obtener_pista_superlab
from app.database import enviar_flag_por_usuario
from app.superlab.datos_ficticios import (
    FLAG_FASE_1,
    FLAG_FASE_2,
    FLAG_FASE_3,
    FLAG_FASE_4,
    FLAG_FASE_5,
    ID_MENSAJE_PROVISIONALES,
    LEGACY_PASSWORD,
    LEGACY_USUARIO,
    USUARIO_VACACIONES,
)
from app.superlab.estado_ui import estado_superlab_para_usuario
from app.superlab.fuzzer import (
    NOMBRE_WORDLIST,
    WORDLIST_FFUF,
    comando_ffuf_valido,
    simular_salida_ffuf,
)
from app.superlab.progreso import (
    avanzar_fase,
    identidad_progreso_superlab,
    marcar_staging_descubierto,
    obtener_o_crear_progreso,
    staging_descubierto,
)
from app.superlab.superlab_db import obtener_conexion_superlab

logger = logging.getLogger(__name__)

# Portal corporativo actual (fases posteriores: login fase 5, etc.).
superlab_nexus = Blueprint(
    "superlab_nexus",
    __name__,
    url_prefix="/web-nexuscorp",
    template_folder="../templates/superlab",
)

# Sistema legacy migrado (fases 1–2).
superlab_legacy = Blueprint(
    "superlab_legacy",
    __name__,
    url_prefix="/web-nexuscorp-2.0",
    template_folder="../templates/superlab",
)

# Entorno staging descubierto vía fuzzer (fases 3–4).
superlab_staging = Blueprint(
    "superlab_staging",
    __name__,
    url_prefix="/web-nexuscorp-2.0-staging",
    template_folder="../templates/superlab",
)

# Herramienta externa simulada (ffuf).
superlab_tools = Blueprint(
    "superlab_tools",
    __name__,
    url_prefix="/tools",
    template_folder="../templates/superlab",
)

CLAVE_SESION_LEGACY = "superlab_legacy_authenticated"
CLAVE_LEGACY_USUARIO = "superlab_legacy_usuario"
CLAVE_STAGING_AUTH = "superlab_staging_authenticated"
CLAVE_STAGING_USUARIO = "superlab_staging_usuario"
CLAVE_STAGING_NOMBRE = "superlab_staging_nombre"
CLAVE_NEXUS_AUTH = "superlab_nexus_authenticated"
CLAVE_NEXUS_USUARIO = "superlab_nexus_usuario"

RUTA_WRITEUP_MD = Path(__file__).resolve().parent.parent.parent / "preguntas_superlab_writeup.md"

# Pasos del timeline pedagógico (panel final).
PASOS_CADENA_SUPERLAB: list[dict[str, str]] = [
    {
        "titulo": "Reconocimiento pasivo (robots.txt)",
        "evitacion": (
            "Paso 1: no publiques rutas sensibles en robots.txt; "
            "usa autenticación y no confíes en la oscuridad."
        ),
    },
    {
        "titulo": "Credenciales filtradas en código fuente",
        "evitacion": (
            "Paso 2: nunca dejes credenciales en comentarios HTML; "
            "usa un gestor de secretos (Vault, KMS)."
        ),
    },
    {
        "titulo": "Control de acceso roto (API sin rol)",
        "evitacion": (
            "Paso 3: valida identidad y autorización en cada endpoint; "
            "no basta con «tener sesión»."
        ),
    },
    {
        "titulo": "Descubrimiento de staging vía fuzzing",
        "evitacion": (
            "Paso 4: segmenta entornos, monitoriza DNS/subdominios y "
            "limita superficie expuesta."
        ),
    },
    {
        "titulo": "SQL Injection en login de staging",
        "evitacion": (
            "Paso 5: consultas parametrizadas siempre; "
            "nunca concatenes entrada de usuario en SQL."
        ),
    },
    {
        "titulo": "Filtración de provisionales + acceso final",
        "evitacion": (
            "Paso 6: cifra datos sensibles en reposo, DLP en correo "
            "y rotación inmediata tras incidentes."
        ),
    },
]


def _legacy_sesion_activa() -> bool:
    """True si el visitante completó login en el portal -2.0 (cualquier usuario válido)."""
    return session.get(CLAVE_SESION_LEGACY) is True


def _staging_sesion_activa() -> bool:
    """True si hay sesión en el portal staging (fase 3+)."""
    return session.get(CLAVE_STAGING_AUTH) is True


def _marcar_sesion_legacy(usuario: str) -> None:
    session[CLAVE_SESION_LEGACY] = True
    session[CLAVE_LEGACY_USUARIO] = usuario
    session.modified = True


def _marcar_sesion_staging(empleado: dict[str, Any]) -> None:
    session[CLAVE_STAGING_AUTH] = True
    session[CLAVE_STAGING_USUARIO] = empleado.get("usuario") or ""
    session[CLAVE_STAGING_NOMBRE] = empleado.get("nombre") or ""
    session.modified = True


def _respuesta_no_autorizado_legacy():
    """403 al estilo APIs del proyecto (JSON uniforme)."""
    return jsonify({"exito": False, "mensaje": "Acceso no autorizado"}), 403


def _staging_oculto_404():
    """404 genérico si aún no se descubrió staging con el fuzzer."""
    return render_template("superlab/staging_404.html"), 404


def _requiere_ruta_staging_visible():
    """None si OK; respuesta 404 si el fuzzer no marcó staging."""
    uid = identidad_progreso_superlab()
    if staging_descubierto(uid):
        return None
    return _staging_oculto_404()


def _nexus_sesion_activa() -> bool:
    return session.get(CLAVE_NEXUS_AUTH) is True


def _marcar_sesion_nexus(empleado: dict[str, Any]) -> None:
    session[CLAVE_NEXUS_AUTH] = True
    session[CLAVE_NEXUS_USUARIO] = empleado.get("usuario") or ""
    session.modified = True


def _intentar_login_nexus(usuario: str, password: str) -> Optional[dict[str, Any]]:
    """Login portal actual: usuario + password_provisional en superlab.db."""
    usuario_limpio = (usuario or "").strip()
    if not usuario_limpio:
        return None
    with obtener_conexion_superlab() as conexion:
        cursor = conexion.execute(
            """
            SELECT id, nombre, usuario, estado, password_provisional
            FROM superlab_empleados WHERE usuario = ? LIMIT 1;
            """,
            (usuario_limpio,),
        )
        fila = cursor.fetchone()
        if fila is None:
            return None
        if (fila["password_provisional"] or "") != (password or ""):
            return None
        return dict(fila)


def _registrar_flag_ranking_si_portal(flag_texto: str) -> dict[str, Any] | None:
    """Envía la flag final al ranking si hay sesión del portal FlyPaper."""
    if session.get("logueado") is not True:
        return None
    usuario_portal = (session.get("usuario") or "").strip()
    if not usuario_portal:
        return None
    resultado = enviar_flag_por_usuario(usuario_portal, flag_texto)
    if resultado.get("exito") and not resultado.get("ya_resuelta"):
        try:
            from app.core.telegram_notifier import notificar_flag_resuelta
            from app.core.timezone_fp import marca_ahora as _marca

            threading.Thread(
                target=notificar_flag_resuelta,
                args=(
                    usuario_portal,
                    resultado.get("reto_nombre"),
                    resultado.get("puntos"),
                    _marca(),
                ),
                daemon=True,
            ).start()
        except Exception:
            pass
    return resultado


def _requiere_reto_completado():
    """None si fase 5 OK; si no redirige al inicio del reto."""
    estado = estado_superlab_para_usuario()
    if estado.get("resuelto") or int(estado.get("fase_actual") or 0) >= 5:
        if FLAG_FASE_5 in (estado.get("flags_capturadas") or []):
            return None
    return redirect(url_for("superlab_nexus.nexuscorp_home"))


# —— NexusCorp actual ——


@superlab_nexus.get("/")
@superlab_nexus.get("")
def nexuscorp_home():
    """Web corporativa normal — pista fase 0 en footer y robots.txt global."""
    return render_template(
        "superlab/nexuscorp_home.html",
        sesion_nexus=_nexus_sesion_activa(),
    )


@superlab_nexus.route("/login", methods=["GET", "POST"])
def nexuscorp_login():
    """
    Fase 5 — login del portal actual con password_provisional (Marta / vacaciones).

    Sin fase ≥4 el login puede funcionar pero no otorga flag ni avanza el reto.
    """
    if request.method == "GET":
        return render_template(
            "superlab/nexuscorp_login.html",
            error=None,
            aviso=None,
        )

    usuario = request.form.get("usuario") or ""
    password = request.form.get("password") or ""
    empleado = _intentar_login_nexus(usuario, password)

    if empleado is None:
        return (
            render_template(
                "superlab/nexuscorp_login.html",
                error="Usuario o contraseña incorrectos.",
                aviso=None,
            ),
            401,
        )

    _marcar_sesion_nexus(empleado)
    uid = identidad_progreso_superlab()
    progreso = obtener_o_crear_progreso(uid)
    fase_prev = int(progreso.get("fase_actual") or 0)

    cumple_reto = (
        fase_prev >= 4
        and empleado.get("usuario") == USUARIO_VACACIONES
        and empleado.get("estado") == "vacaciones"
    )

    if cumple_reto:
        avanzar_fase(uid, 5, FLAG_FASE_5)
        _registrar_flag_ranking_si_portal(FLAG_FASE_5)
        return redirect(url_for("superlab_nexus.panel_superlab"))

    return render_template(
        "superlab/nexuscorp_login.html",
        error=None,
        aviso="Sesión iniciada en NexusCorp (sin progreso de reto).",
    )


@superlab_nexus.post("/api/pista")
def nexuscorp_pedir_pista():
    """
    Pista pedagógica por fase (0–4). Requiere fase_actual >= fase solicitada.
    """
    cuerpo = request.get_json(silent=True) or {}
    try:
        fase = int(cuerpo.get("fase", request.form.get("fase", -1)))
    except (TypeError, ValueError):
        fase = -1

    if fase not in PISTAS_SUPERLAB:
        return jsonify({"exito": False, "mensaje": "Fase no válida."}), 400

    uid = identidad_progreso_superlab()
    progreso = obtener_o_crear_progreso(uid)
    if int(progreso.get("fase_actual") or 0) < fase:
        return jsonify({"exito": False, "mensaje": "Aún no has llegado a esta fase."}), 403

    texto = obtener_pista_superlab(fase) or ""
    return jsonify({"exito": True, "fase": fase, "pista": texto})


@superlab_nexus.get("/panel-superlab")
def panel_superlab():
    """Fase 6 — resumen pedagógico y flags capturadas."""
    bloqueo = _requiere_reto_completado()
    if bloqueo is not None:
        return bloqueo

    estado = estado_superlab_para_usuario()
    return render_template(
        "superlab/panel_final.html",
        pasos=PASOS_CADENA_SUPERLAB,
        estado=estado,
        flag_final=FLAG_FASE_5,
        conclusion=(session.get("superlab_conclusion") or ""),
    )


@superlab_nexus.post("/panel-superlab/conclusion")
def panel_superlab_conclusion():
    """Guarda conclusión opcional del alumno en sesión (sin persistir en BD)."""
    bloqueo = _requiere_reto_completado()
    if bloqueo is not None:
        return bloqueo
    texto = (request.form.get("conclusion") or "").strip()
    session["superlab_conclusion"] = texto[:2000]
    session.modified = True
    return redirect(url_for("superlab_nexus.panel_superlab"))


@superlab_nexus.get("/panel-superlab/writeup")
def panel_superlab_writeup():
    """Writeup renderizado en documentación (solo tras completar la cadena)."""
    bloqueo = _requiere_reto_completado()
    if bloqueo is not None:
        return bloqueo

    from app.documentacion_writeups import ruta_writeup_documentacion

    return redirect(ruta_writeup_documentacion("superlab"))


# —— Legacy 2.0 ——


@superlab_legacy.get("/login")
def legacy_login_get():
    """Formulario de acceso al sistema legacy."""
    return render_template("superlab/legacy_login.html", error=None)


@superlab_legacy.post("/login")
def legacy_login_post():
    """Valida credenciales legacy; fase 1 — credenciales filtradas en código fuente."""
    usuario = (request.form.get("usuario") or "").strip()
    password = request.form.get("password") or ""

    if usuario != LEGACY_USUARIO or password != LEGACY_PASSWORD:
        return (
            render_template(
                "superlab/legacy_login.html",
                error="Usuario o contraseña incorrectos.",
            ),
            401,
        )

    _marcar_sesion_legacy(usuario)
    uid = identidad_progreso_superlab()
    avanzar_fase(uid, 1, FLAG_FASE_1)

    return redirect(url_for("superlab_legacy.legacy_panel"))


@superlab_legacy.get("/panel")
def legacy_panel():
    """Panel legacy tras login; muestra flag fase 1."""
    if not _legacy_sesion_activa():
        return redirect(url_for("superlab_legacy.legacy_login_get"))

    return render_template(
        "superlab/legacy_panel.html",
        flag_fase1=FLAG_FASE_1,
        usuario_legacy=session.get(CLAVE_LEGACY_USUARIO) or "",
    )


@superlab_legacy.get("/api/empleados")
def legacy_api_empleados():
    """Fase 2 — IDOR: basta sesión legacy."""
    if not _legacy_sesion_activa():
        return _respuesta_no_autorizado_legacy()

    uid = identidad_progreso_superlab()
    progreso_antes = obtener_o_crear_progreso(uid)
    primera_vez_fase2 = int(progreso_antes["fase_actual"]) < 2

    with obtener_conexion_superlab() as conexion:
        cursor = conexion.execute(
            """
            SELECT nombre, usuario, estado
            FROM superlab_empleados
            ORDER BY id ASC;
            """
        )
        empleados = [dict(fila) for fila in cursor.fetchall()]

    flag_obtenida = None
    if primera_vez_fase2:
        actualizado = avanzar_fase(uid, 2, FLAG_FASE_2)
        flag_obtenida = FLAG_FASE_2 if FLAG_FASE_2 in actualizado["flags_capturadas"] else None

    payload: dict[str, Any] = {
        "exito": True,
        "empleados": empleados,
        "total": len(empleados),
    }
    if flag_obtenida:
        payload["flag"] = flag_obtenida

    return jsonify(payload)


# —— Fuzzer simulado (herramienta externa) ——


@superlab_tools.route("/fuzzer", methods=["GET", "POST"])
def herramienta_fuzzer():
    """
    Simula ffuf: solo interpreta texto; sin red ni subprocess.
    """
    salida = None
    error = None
    comando = ""

    if request.method == "POST":
        comando = (request.form.get("comando") or "").strip()
        if not comando:
            error = "Introduce un comando."
        elif not comando_ffuf_valido(comando):
            error = "Comando no reconocido."
        else:
            salida = simular_salida_ffuf(comando)
            uid = identidad_progreso_superlab()
            if not staging_descubierto(uid):
                marcar_staging_descubierto(uid)

    return render_template(
        "superlab/fuzzer.html",
        wordlist=WORDLIST_FFUF,
        nombre_wordlist=NOMBRE_WORDLIST,
        comando=comando,
        salida=salida,
        error=error,
    )


# —— Staging: fase 3 login SQLi ——


@superlab_staging.route("/login", methods=["GET", "POST"])
def staging_login():
    """Login staging vulnerable; oculto hasta descubrir ruta vía fuzzer."""
    bloqueo = _requiere_ruta_staging_visible()
    if bloqueo is not None:
        return bloqueo

    if request.method == "GET":
        return render_template(
            "superlab/staging_login.html",
            error=None,
            flag_fase3=None,
        )

    usuario = request.form.get("usuario") or ""
    password = request.form.get("password") or ""
    empleado, _via_sqli = intentar_login_staging(usuario, password)

    if empleado is None:
        return (
            render_template(
                "superlab/staging_login.html",
                error="Credenciales incorrectas.",
                flag_fase3=None,
            ),
            401,
        )

    _marcar_sesion_staging(empleado)
    uid = identidad_progreso_superlab()
    progreso = avanzar_fase(uid, 3, FLAG_FASE_3)

    return render_template(
        "superlab/staging_login.html",
        error=None,
        flag_fase3=FLAG_FASE_3,
        empleado=empleado,
        mensajes_url=url_for("superlab_staging.staging_mensajes"),
    )


# —— Staging: fase 4 bandeja de mensajes ——


def _mensajes_ruido_staging() -> list[dict[str, str]]:
    """Mensajes internos sin pista (ruido)."""
    fecha = marca_ahora()
    return [
        {
            "id": "avisos-rrhh-q3",
            "remitente": "rrhh@nexuscorp.internal",
            "asunto": "Recordatorio: formación obligatoria phishing",
            "fecha": fecha,
            "preview": "Completad el módulo antes del viernes…",
        },
        {
            "id": "facilities-aire",
            "remitente": "facilities@nexuscorp.internal",
            "asunto": "Mantenimiento climatización planta 2",
            "fecha": fecha,
            "preview": "El sábado 08:00–14:00 habrá corte parcial…",
        },
        {
            "id": "comunicacion-brand",
            "remitente": "marketing@nexuscorp.internal",
            "asunto": "Nueva plantilla de firma corporativa",
            "fecha": fecha,
            "preview": "Adjuntamos el PDF con lineamientos de marca…",
        },
        {
            "id": "legal-privacidad",
            "remitente": "legal@nexuscorp.internal",
            "asunto": "Actualización política de cookies intranet",
            "fecha": fecha,
            "preview": "Sin impacto en sistemas legacy…",
        },
    ]


def _cuerpo_mensaje_provisionales() -> str:
    """Lista todas las contraseñas provisionales desde superlab.db."""
    lineas = [
        "Equipo, tras el incidente de fin de semana reenviamos las credenciales temporales.",
        "Rotadlas en el primer acceso al portal principal.",
        "",
        "Empleado | Usuario | Provisional",
        "---------|---------|------------",
    ]
    with obtener_conexion_superlab() as conexion:
        cursor = conexion.execute(
            """
            SELECT nombre, usuario, password_provisional
            FROM superlab_empleados ORDER BY id ASC;
            """
        )
        for fila in cursor.fetchall():
            lineas.append(
                f"{fila['nombre']} | {fila['usuario']} | {fila['password_provisional']}"
            )
    return "\n".join(lineas)


@superlab_staging.get("/mensajes")
def staging_mensajes():
    """Bandeja de mensajes internos (fase 4). Requiere sesión staging."""
    bloqueo = _requiere_ruta_staging_visible()
    if bloqueo is not None:
        return bloqueo
    if not _staging_sesion_activa():
        return redirect(url_for("superlab_staging.staging_login"))

    mensajes = _mensajes_ruido_staging()
    mensajes.append(
        {
            "id": ID_MENSAJE_PROVISIONALES,
            "remitente": "IT-Soporte <it-soporte@nexuscorp.internal>",
            "asunto": "Contraseñas temporales tras incidente de seguridad",
            "fecha": marca_ahora(),
            "preview": "Listado completo de provisionales — uso interno…",
        }
    )

    return render_template(
        "superlab/staging_mensajes.html",
        mensajes=mensajes,
        usuario=session.get(CLAVE_STAGING_NOMBRE) or session.get(CLAVE_STAGING_USUARIO),
    )


@superlab_staging.get("/mensajes/<mensaje_id>")
def staging_mensaje_detalle(mensaje_id: str):
    """Detalle de un mensaje; el de provisionales entrega flag fase 4."""
    bloqueo = _requiere_ruta_staging_visible()
    if bloqueo is not None:
        return bloqueo
    if not _staging_sesion_activa():
        return redirect(url_for("superlab_staging.staging_login"))

    flag_fase4 = None
    ruido = {m["id"]: m for m in _mensajes_ruido_staging()}

    if mensaje_id in ruido:
        msg = ruido[mensaje_id]
        cuerpo = f"(Contenido del aviso «{msg['asunto']}» — sin información adicional relevante.)"
        remitente = msg["remitente"]
        asunto = msg["asunto"]
    elif mensaje_id == ID_MENSAJE_PROVISIONALES:
        remitente = "IT-Soporte <it-soporte@nexuscorp.internal>"
        asunto = "Contraseñas temporales tras incidente de seguridad"
        cuerpo = _cuerpo_mensaje_provisionales()
        uid = identidad_progreso_superlab()
        progreso = avanzar_fase(uid, 4, FLAG_FASE_4)
        if FLAG_FASE_4 in progreso["flags_capturadas"]:
            flag_fase4 = FLAG_FASE_4
    else:
        return _staging_oculto_404()

    return render_template(
        "superlab/staging_mensaje_detalle.html",
        remitente=remitente,
        asunto=asunto,
        cuerpo=cuerpo,
        flag_fase4=flag_fase4,
        volver_url=url_for("superlab_staging.staging_mensajes"),
    )


