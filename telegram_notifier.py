"""
Notificaciones de FlyPaper vía Telegram Bot API con Topics de grupo.

Variables de entorno (.env):
  TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
  TELEGRAM_TOPIC_LOGINS, TELEGRAM_TOPIC_ATAQUES, TELEGRAM_TOPIC_RESUMEN

Si TELEGRAM_BOT_TOKEN no está configurado, el módulo opera en modo silencioso.
"""

import html
import json
import logging
import os
import urllib.error
import urllib.request

from dotenv import load_dotenv

# override=True: el .env tiene prioridad sobre variables del sistema (evita IDs obsoletos).
load_dotenv(override=True)

logger = logging.getLogger(__name__)

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()
TIMEOUT_TELEGRAM_SEG = 5


def _leer_topic_id(nombre_variable):
    """
    Lee un message_thread_id desde el entorno.

    Acepta enteros como string ("2", "3") tal como los devuelve getUpdates de Telegram.
    """
    valor = os.getenv(nombre_variable)
    if valor is None:
        return None
    valor = str(valor).strip()
    if not valor:
        return None
    try:
        return int(valor)
    except ValueError:
        logger.warning(
            "Telegram: %s debe ser un entero (topic id), valor recibido: %r",
            nombre_variable,
            valor,
        )
        return None


# IDs de topics del grupo (message_thread_id en la API de Telegram)
TELEGRAM_TOPIC_LOGINS = _leer_topic_id("TELEGRAM_TOPIC_LOGINS")
TELEGRAM_TOPIC_ATAQUES = _leer_topic_id("TELEGRAM_TOPIC_ATAQUES")
TELEGRAM_TOPIC_RESUMEN = _leer_topic_id("TELEGRAM_TOPIC_RESUMEN")


def enviar_notificacion_telegram(mensaje, parse_mode="HTML", message_thread_id=None):
    """
    Envía un mensaje al grupo de Telegram, opcionalmente a un topic concreto.

    Returns:
        bool: True si Telegram aceptó el mensaje; False si falló o no hay configuración.
    """
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    cuerpo = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": mensaje,
        "parse_mode": parse_mode,
    }
    if message_thread_id is not None:
        cuerpo["message_thread_id"] = message_thread_id

    datos = json.dumps(cuerpo).encode("utf-8")

    try:
        peticion = urllib.request.Request(
            url,
            data=datos,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(peticion, timeout=TIMEOUT_TELEGRAM_SEG) as respuesta:
            respuesta.read()
        return True
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        print(f"[Telegram] Error {exc.code}: {error_body}")
        logger.warning(
            "Telegram: HTTP %s al enviar mensaje (topic=%s): %s",
            exc.code,
            message_thread_id,
            error_body,
        )
        return False
    except urllib.error.URLError as exc:
        print(f"[Telegram] Error de red: {exc}")
        logger.warning("Telegram: error de red al enviar notificación: %s", exc)
        return False
    except TimeoutError:
        print(f"[Telegram] Error: tiempo de espera agotado ({TIMEOUT_TELEGRAM_SEG}s)")
        logger.warning("Telegram: tiempo de espera agotado (%ss)", TIMEOUT_TELEGRAM_SEG)
        return False
    except Exception as exc:
        print(f"[Telegram] Error inesperado: {exc}")
        logger.warning("Telegram: error inesperado al enviar notificación: %s", exc)
        return False


def notificar_login_admin(usuario, ip, timestamp):
    """Avisa en el topic de logins de un acceso exitoso al panel admin."""
    usuario_seguro = html.escape(str(usuario or ""))
    ip_segura = html.escape(str(ip or ""))
    hora_segura = html.escape(str(timestamp or ""))

    mensaje = (
        "🔐 <b>Login Admin</b>\n"
        f"👤 <code>{usuario_seguro}</code>\n"
        f"🌐 <code>{ip_segura}</code>\n"
        f"🕐 <code>{hora_segura}</code>"
    )
    enviar_notificacion_telegram(mensaje, message_thread_id=TELEGRAM_TOPIC_LOGINS)


def notificar_login_monitor(usuario, ip, timestamp):
    """Avisa en el topic de logins de un acceso exitoso al monitor SOC."""
    usuario_seguro = html.escape(str(usuario or ""))
    ip_segura = html.escape(str(ip or ""))
    hora_segura = html.escape(str(timestamp or ""))

    mensaje = (
        "👁 <b>Login Monitor</b>\n"
        f"👤 <code>{usuario_seguro}</code>\n"
        f"🌐 <code>{ip_segura}</code>\n"
        f"🕐 <code>{hora_segura}</code>"
    )
    enviar_notificacion_telegram(mensaje, message_thread_id=TELEGRAM_TOPIC_LOGINS)


def notificar_nuevo_registro(username, ip, timestamp):
    """Avisa en el topic de logins de un alta en /register."""
    usuario_seguro = html.escape(str(username or ""))
    ip_segura = html.escape(str(ip or ""))
    hora_segura = html.escape(str(timestamp or ""))

    mensaje = (
        "👤 <b>Nuevo Registro</b>\n"
        f"🆔 Usuario: <code>{usuario_seguro}</code>\n"
        f"🌐 IP: <code>{ip_segura}</code>\n"
        f"🕐 Hora: <code>{hora_segura}</code>"
    )
    enviar_notificacion_telegram(mensaje, message_thread_id=TELEGRAM_TOPIC_LOGINS)


def notificar_ataque_critico(tipo_ataque, ip, ruta, payload, timestamp):
    """Avisa en el topic de ataques de un incidente con gravedad Crítica."""
    tipo_seguro = html.escape(str(tipo_ataque or ""))
    ip_segura = html.escape(str(ip or ""))
    ruta_segura = html.escape(str(ruta or ""))
    hora_segura = html.escape(str(timestamp or ""))
    payload_texto = html.escape(str(payload or "")[:120])

    mensaje = (
        "🚨 <b>ATAQUE CRÍTICO</b>\n"
        f"⚡ <code>{tipo_seguro}</code>\n"
        f"🌐 <code>{ip_segura}</code>\n"
        f"📍 <code>{ruta_segura}</code>\n"
        f"💣 <code>{payload_texto}</code>\n"
        f"🕐 <code>{hora_segura}</code>"
    )
    return enviar_notificacion_telegram(mensaje, message_thread_id=TELEGRAM_TOPIC_ATAQUES)


def notificar_resumen_diario(fecha, resumen_texto, total_eventos):
    """Publica el resumen diario generado por IA en el topic de resúmenes."""
    fecha_segura = html.escape(str(fecha or ""))
    resumen_seguro = html.escape(str(resumen_texto or "")[:800])
    total = int(total_eventos) if total_eventos is not None else 0

    mensaje = (
        f"📊 <b>Resumen Diario — {fecha_segura}</b>\n"
        f"📈 Eventos: <b>{total}</b>\n\n"
        f"{resumen_seguro}\n\n"
        "<i>Generado automáticamente por FlyPaper IA</i>"
    )
    return enviar_notificacion_telegram(mensaje, message_thread_id=TELEGRAM_TOPIC_RESUMEN)


def test_telegram():
    """
    Envía un mensaje de prueba a cada topic configurado.

    Uso desde terminal:
        python -c "from telegram_notifier import test_telegram; test_telegram()"
    """
    pruebas = [
        ("Logins", TELEGRAM_TOPIC_LOGINS, "Test - Topic Logins configurado correctamente"),
        ("Ataques", TELEGRAM_TOPIC_ATAQUES, "Test - Topic Ataques configurado correctamente"),
        ("Resumen", TELEGRAM_TOPIC_RESUMEN, "Test - Topic Resumen configurado correctamente"),
    ]

    print("=== Prueba de notificaciones Telegram (FlyPaper) ===")
    print(f"CHAT_ID: {TELEGRAM_CHAT_ID or '(no configurado)'}")
    print(f"TOKEN configurado: {'si' if TELEGRAM_BOT_TOKEN else 'no'}")
    print()

    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("ERROR: define TELEGRAM_BOT_TOKEN y TELEGRAM_CHAT_ID en .env")
        return

    for nombre, topic_id, texto in pruebas:
        print(f"Topic: {nombre}")
        if topic_id is None:
            print("  ID usado: (no configurado en .env)")
            print("  Resultado: OMITIDO - falta variable de entorno")
            print()
            continue

        print(f"  ID usado: {topic_id}")
        exito = enviar_notificacion_telegram(texto, message_thread_id=topic_id)
        if exito:
            print("  Resultado: OK")
        else:
            print("  Resultado: ERROR - revisa el mensaje [Telegram] anterior")
        print()

    print("--- Simulacion: ataque critico ---")
    exito_ataque = notificar_ataque_critico(
        "SQLi",
        "1.2.3.4",
        "/search",
        "' OR 1=1--",
        "2026-06-28 14:00:00",
    )
    print(f"  Simulacion ataque critico: {'OK' if exito_ataque else 'ERROR'}")
    print()

    print("--- Simulacion: resumen diario ---")
    exito_resumen = notificar_resumen_diario(
        "2026-06-28",
        "Resumen de prueba: se detectaron 5 ataques hoy.",
        5,
    )
    print(f"  Simulacion resumen diario: {'OK' if exito_resumen else 'ERROR'}")
    print()

    print("Prueba finalizada.")
