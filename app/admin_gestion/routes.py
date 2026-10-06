"""Vistas /admin/usuarios-soc, /admin/participantes-ctf y cambio de contraseña SOC."""

from __future__ import annotations

import secrets
from functools import wraps

from flask import (
    Blueprint,
    abort,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from app.core.timezone_fp import marca_ahora
from app.database import (
    ROL_PRIV_ADMIN_PANEL,
    ROL_PRIV_MONITOR,
    ROL_USUARIO_ADMIN_BD,
    completar_onboarding_soc,
    contar_admins_soc,
    crear_cuenta_soc,
    eliminar_cuenta_soc,
    listar_cuentas_soc,
    obtener_soc_por_username,
    registrar_evento_auditoria_soc,
    resetear_password_soc,
    soc_debe_cambiar_password,
)
from app.gestion_participantes import (
    detalle_progreso_participante,
    eliminar_participante_completo,
    listar_participantes_resumen as listar_participantes_resumen_fn,
    registrar_auditoria_participantes,
    resetear_progreso_participante,
)

admin_gestion = Blueprint("admin_gestion", __name__)


def _csrf_token_soc() -> str:
    """Token anti-CSRF por sesión SOC (formularios de gestión)."""
    token = session.get("_csrf_soc")
    if not token:
        token = secrets.token_hex(32)
        session["_csrf_soc"] = token
    return token


def _validar_csrf_soc() -> bool:
    """Compara el token del formulario con el de la sesión."""
    esperado = session.get("_csrf_soc") or ""
    recibido = (request.form.get("csrf_token") or "").strip()
    if not esperado or not recibido:
        return False
    return secrets.compare_digest(esperado, recibido)


def _exigir_csrf_soc():
    """Aborta 400 si el POST no incluye CSRF válido."""
    if not _validar_csrf_soc():
        abort(400, description="CSRF token inválido o ausente.")


@admin_gestion.app_context_processor
def _inyectar_csrf_soc():
    """Expone csrf_token_soc en plantillas del blueprint."""
    return {"csrf_token_soc": _csrf_token_soc}


def _ip_peticion_admin() -> str:
    """IP del operador SOC (REMOTE_ADDR tras ProxyFix; no confiar en XFF crudo)."""
    return (request.remote_addr or "127.0.0.1").strip() or "127.0.0.1"
_ENDPOINTS_SIN_BLOQUEO_PASSWORD = frozenset(
    {
        "admin_gestion.cambiar_password_soc_get",
        "admin_gestion.cambiar_password_soc_post",
        "admin_soc_logout",
        "mostrar_admin_login",
        "procesar_admin_login",
        "verificar_2fa_get",
        "verificar_2fa_post",
    }
)


def _usuario_soc() -> str:
    return (session.get("usuario") or "").strip()


def _es_admin_panel() -> bool:
    return (
        session.get("logueado") is True
        and session.get("rol") == ROL_USUARIO_ADMIN_BD
    )


def _acceso_soc():
    """True si hay sesión SOC (admin o analyst) tras 2FA."""
    if session.get("analyst") is True:
        return True
    return session.get("logueado") is True and session.get("rol") == ROL_USUARIO_ADMIN_BD


def requiere_soc_sin_password_pendiente(funcion_vista):
    """RBAC SOC + redirección a cambio de contraseña obligatorio."""

    @wraps(funcion_vista)
    def envoltorio(*args, **kwargs):
        if not _acceso_soc():
            return redirect(url_for("mostrar_admin_login"))
        fin = request.endpoint or ""
        if session.get("soc_debe_cambiar_password") and fin not in (
            "admin_gestion.cambiar_password_soc_get",
            "admin_gestion.cambiar_password_soc_post",
            "admin_soc_logout",
        ):
            return redirect(url_for("admin_gestion.cambiar_password_soc_get"))
        return funcion_vista(*args, **kwargs)

    return envoltorio


def requiere_admin_soc(funcion_vista):
    """Solo rol admin del panel (no analyst/monitor)."""

    @wraps(funcion_vista)
    def envoltorio(*args, **kwargs):
        if not _acceso_soc():
            return redirect(url_for("mostrar_admin_login"))
        if session.get("soc_debe_cambiar_password"):
            return redirect(url_for("admin_gestion.cambiar_password_soc_get"))
        if not _es_admin_panel():
            return redirect(url_for("mostrar_panel_admin"))
        return funcion_vista(*args, **kwargs)

    return envoltorio


@admin_gestion.get("/admin/cambiar-password")
@requiere_soc_sin_password_pendiente
def cambiar_password_soc_get():
    """Formulario de cambio obligatorio o voluntario."""
    if not session.get("soc_debe_cambiar_password"):
        return redirect(url_for("mostrar_panel_admin"))
    return render_template(
        "admin/cambiar_password_soc.html",
        obligatorio=True,
        usuario=_usuario_soc(),
    )


@admin_gestion.post("/admin/cambiar-password")
@requiere_soc_sin_password_pendiente
def cambiar_password_soc_post():
    _exigir_csrf_soc()
    actual = request.form.get("password_actual", "")
    usuario_nuevo = request.form.get("username_nuevo", "").strip()
    nueva = request.form.get("password_nueva", "")
    confirm = request.form.get("password_confirmacion", "")
    usuario = _usuario_soc()
    resultado = completar_onboarding_soc(
        usuario, actual, usuario_nuevo, nueva, confirm
    )
    if not resultado.get("exito"):
        return render_template(
            "admin/cambiar_password_soc.html",
            obligatorio=True,
            usuario=usuario,
            error=resultado.get("mensaje"),
        )
    session["soc_debe_cambiar_password"] = False
    session["usuario"] = resultado.get("username_nuevo") or usuario_nuevo
    registrar_evento_auditoria_soc(
        session["usuario"],
        "onboarding_soc_usuario_password",
        {"usuario_anterior": usuario, "timestamp": marca_ahora()},
        ip_admin=_ip_peticion_admin(),
    )
    return redirect(url_for("mostrar_panel_admin"))


@admin_gestion.get("/admin/usuarios-soc")
@requiere_admin_soc
def usuarios_soc_listado():
    cuentas = listar_cuentas_soc()
    return render_template(
        "admin/usuarios_soc.html",
        cuentas=cuentas,
        roles=[ROL_PRIV_ADMIN_PANEL, ROL_PRIV_MONITOR],
        usuario_actual=_usuario_soc(),
    )


@admin_gestion.post("/admin/usuarios-soc/crear")
@requiere_admin_soc
def usuarios_soc_crear():
    _exigir_csrf_soc()
    username = request.form.get("username", "").strip()
    rol = request.form.get("rol", ROL_PRIV_MONITOR)
    temp = secrets.token_urlsafe(12)
    if len(temp) < 12:
        temp = temp + "Aa1!"
    resultado = crear_cuenta_soc(username, rol, temp)
    if resultado.get("exito"):
        registrar_evento_auditoria_soc(
            _usuario_soc(),
            "soc_crear_cuenta",
            {"objetivo": username, "rol": rol},
            ip_admin=_ip_peticion_admin(),
        )
        return render_template(
            "admin/usuarios_soc.html",
            cuentas=listar_cuentas_soc(),
            roles=[ROL_PRIV_ADMIN_PANEL, ROL_PRIV_MONITOR],
            usuario_actual=_usuario_soc(),
            password_mostrada_una_vez=temp,
            cuenta_creada=username,
        )
    return render_template(
        "admin/usuarios_soc.html",
        cuentas=listar_cuentas_soc(),
        roles=[ROL_PRIV_ADMIN_PANEL, ROL_PRIV_MONITOR],
        usuario_actual=_usuario_soc(),
        error=resultado.get("mensaje"),
    )


@admin_gestion.post("/admin/usuarios-soc/<username>/reset")
@requiere_admin_soc
def usuarios_soc_reset(username):
    _exigir_csrf_soc()
    temp = secrets.token_urlsafe(12)
    if len(temp) < 12:
        temp = temp + "Xy9!"
    resultado = resetear_password_soc(username, temp)
    if resultado.get("exito"):
        registrar_evento_auditoria_soc(
            _usuario_soc(),
            "soc_reset_password",
            {"objetivo": username},
            ip_admin=_ip_peticion_admin(),
        )
    return render_template(
        "admin/usuarios_soc.html",
        cuentas=listar_cuentas_soc(),
        roles=[ROL_PRIV_ADMIN_PANEL, ROL_PRIV_MONITOR],
        usuario_actual=_usuario_soc(),
        password_mostrada_una_vez=temp if resultado.get("exito") else None,
        cuenta_reset=username if resultado.get("exito") else None,
        error=None if resultado.get("exito") else resultado.get("mensaje"),
    )


@admin_gestion.post("/admin/usuarios-soc/<username>/eliminar")
@requiere_admin_soc
def usuarios_soc_eliminar(username):
    _exigir_csrf_soc()
    confirm = request.form.get("confirmacion", "").strip()
    objetivo = (username or "").strip()
    actor = _usuario_soc()
    if confirm != objetivo:
        return render_template(
            "admin/usuarios_soc.html",
            cuentas=listar_cuentas_soc(),
            roles=[ROL_PRIV_ADMIN_PANEL, ROL_PRIV_MONITOR],
            usuario_actual=actor,
            error="Confirmación incorrecta: escribe el nombre de usuario exacto.",
        )
    if objetivo == actor:
        return render_template(
            "admin/usuarios_soc.html",
            cuentas=listar_cuentas_soc(),
            roles=[ROL_PRIV_ADMIN_PANEL, ROL_PRIV_MONITOR],
            usuario_actual=actor,
            error="No puedes eliminar tu propia sesión activa.",
        )
    cuenta = obtener_soc_por_username(objetivo)
    if cuenta and cuenta.get("rol") == ROL_PRIV_ADMIN_PANEL and contar_admins_soc() <= 1:
        return render_template(
            "admin/usuarios_soc.html",
            cuentas=listar_cuentas_soc(),
            roles=[ROL_PRIV_ADMIN_PANEL, ROL_PRIV_MONITOR],
            usuario_actual=actor,
            error="No se puede eliminar al único administrador restante.",
        )
    resultado = eliminar_cuenta_soc(objetivo)
    if resultado.get("exito"):
        registrar_evento_auditoria_soc(
            actor,
            "soc_eliminar_cuenta",
            {"objetivo": objetivo},
            ip_admin=_ip_peticion_admin(),
        )
    return render_template(
        "admin/usuarios_soc.html",
        cuentas=listar_cuentas_soc(),
        roles=[ROL_PRIV_ADMIN_PANEL, ROL_PRIV_MONITOR],
        usuario_actual=actor,
        error=None if resultado.get("exito") else resultado.get("mensaje"),
        ok="Cuenta eliminada." if resultado.get("exito") else None,
    )


@admin_gestion.get("/admin/participantes-ctf")
@requiere_admin_soc
def participantes_ctf_listado():
    participantes = listar_participantes_resumen_fn()
    return render_template(
        "admin/participantes_ctf.html",
        participantes=participantes,
    )


@admin_gestion.get("/admin/participantes-ctf/<username>")
@requiere_admin_soc
def participantes_ctf_detalle(username):
    detalle = detalle_progreso_participante(username)
    if detalle is None:
        return redirect(url_for("admin_gestion.participantes_ctf_listado"))
    return render_template(
        "admin/participantes_ctf_detalle.html",
        detalle=detalle,
    )


@admin_gestion.post("/admin/participantes-ctf/<username>/reset")
@requiere_admin_soc
def participantes_ctf_reset(username):
    _exigir_csrf_soc()
    confirm = request.form.get("confirmacion", "").strip()
    if confirm != "RESETEAR":
        return redirect(
            url_for(
                "admin_gestion.participantes_ctf_detalle",
                username=username,
            )
        )
    stats = resetear_progreso_participante(username)
    registrar_auditoria_participantes(
        _usuario_soc(),
        "reset_progreso",
        username,
        {"stats": stats},
        ip_admin=_ip_peticion_admin(),
    )
    return redirect(
        url_for("admin_gestion.participantes_ctf_detalle", username=username)
    )


@admin_gestion.post("/admin/participantes-ctf/<int:usuario_id>/eliminar")
@requiere_admin_soc
def participantes_ctf_eliminar(usuario_id):
    _exigir_csrf_soc()
    confirm1 = request.form.get("confirmacion_1", "").strip()
    confirm2 = request.form.get("confirmacion_2", "").strip()
    if confirm1 != "ELIMINAR" or confirm2 != "ELIMINAR":
        return redirect(url_for("admin_gestion.participantes_ctf_listado"))
    resultado = eliminar_participante_completo(usuario_id)
    if resultado.get("exito"):
        registrar_auditoria_participantes(
            _usuario_soc(),
            "eliminar_cuenta",
            resultado.get("username", ""),
            {"stats": resultado.get("stats")},
            ip_admin=_ip_peticion_admin(),
        )
    return redirect(url_for("admin_gestion.participantes_ctf_listado"))


def marcar_sesion_password_pendiente(username: str) -> None:
    """Sincroniza flag de sesión tras login 2FA."""
    session["soc_debe_cambiar_password"] = soc_debe_cambiar_password(username)
