"""
Análisis de ataques del honeypot FlyPaper mediante la API de Anthropic (Claude).

Requiere la variable de entorno ANTHROPIC_API_KEY y el paquete `anthropic`.
"""

import json
import os
import re
from pathlib import Path

import anthropic

from database import obtener_eventos

# Modelo Claude usado en todas las llamadas al analizador.
MODELO_CLAUDE = "claude-sonnet-4-20250514"

# Respuesta por defecto si falla el análisis de un payload individual.
ANALISIS_PAYLOAD_DEFECTO = {
    "intencion": "No se pudo determinar la intención del atacante.",
    "tecnica": "Técnica no identificada (error en el análisis automático).",
    "dano_potencial": "Impacto desconocido; revise el payload manualmente.",
    "nivel_sofisticacion": "básico",
    "recomendacion": "Revise logs, aplique validación de entradas y monitoreo de la ruta afectada.",
}

# Respuesta por defecto si falla la detección de anomalías.
ANOMALIAS_DEFECTO = {
    "hay_anomalia": False,
    "descripcion": "No se pudo completar el análisis de anomalías.",
    "nivel_alerta": "bajo",
    "ips_sospechosas": [],
    "patron_detectado": "Análisis no disponible",
}


def _cargar_api_key_desde_entorno():
    """
    Obtiene ANTHROPIC_API_KEY del entorno; si falta, intenta leer .env en la raíz del proyecto.
    """
    clave = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if clave:
        return clave

    ruta_env = Path(__file__).resolve().parent / ".env"
    if ruta_env.is_file():
        for linea in ruta_env.read_text(encoding="utf-8").splitlines():
            linea = linea.strip()
            if not linea or linea.startswith("#") or "=" not in linea:
                continue
            nombre, _, valor = linea.partition("=")
            if nombre.strip() == "ANTHROPIC_API_KEY":
                valor = valor.strip().strip('"').strip("'")
                if valor:
                    os.environ["ANTHROPIC_API_KEY"] = valor
                    return valor

    return ""


def _obtener_cliente_anthropic():
    """Crea el cliente de Anthropic validando que exista la API key."""
    api_key = _cargar_api_key_desde_entorno()
    if not api_key:
        raise ValueError(
            "Falta ANTHROPIC_API_KEY. Defínela en el entorno o en el archivo .env del proyecto."
        )
    return anthropic.Anthropic(api_key=api_key)


def _texto_de_respuesta(message):
    """Extrae el texto plano del primer bloque de contenido de la respuesta de Claude."""
    if not message.content:
        return ""
    bloque = message.content[0]
    return getattr(bloque, "text", "") or ""


def _extraer_json_de_texto(texto):
    """
    Intenta parsear JSON desde la respuesta del modelo (incluye bloques ```json).

    Returns:
        dict | list | None: Objeto parseado o None si no es JSON válido.
    """
    if not texto or not texto.strip():
        return None

    texto = texto.strip()

    # Bloque markdown ```json ... ```
    match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", texto, re.IGNORECASE)
    if match:
        texto = match.group(1).strip()

    try:
        return json.loads(texto)
    except json.JSONDecodeError:
        pass

    # Algunas respuestas usan comillas simples estilo Python
    try:
        texto_normalizado = texto.replace("'", '"')
        return json.loads(texto_normalizado)
    except json.JSONDecodeError:
        return None


def _serializar_payload(payload):
    """Convierte el payload del evento a texto legible para el prompt."""
    if payload is None:
        return "(vacío)"
    if isinstance(payload, (dict, list)):
        try:
            return json.dumps(payload, ensure_ascii=False, indent=2)
        except (TypeError, ValueError):
            return str(payload)
    return str(payload)


def analizar_payload(tipo_ataque, payload, ruta):
    """
    Analiza un ataque concreto con Claude y devuelve un dict estructurado.

    Args:
        tipo_ataque (str): Clasificación del detector (p. ej. SQLi, XSS).
        payload: Cuerpo o parámetros del ataque (str, dict, etc.).
        ruta (str): Ruta HTTP atacada.

    Returns:
        dict: intencion, tecnica, dano_potencial, nivel_sofisticacion, recomendacion.
    """
    texto_payload = _serializar_payload(payload)
    tipo = (tipo_ataque or "Desconocido").strip()
    ruta_txt = (ruta or "/").strip()

    prompt = f"""Eres un experto en ciberseguridad analizando un ataque real \
registrado en un honeypot. Analiza este ataque y responde en español \
en formato JSON con exactamente estas claves:

{{
  "intencion": "qué intentaba conseguir el atacante en 1-2 frases",
  "tecnica": "nombre técnico del ataque y cómo funciona",
  "dano_potencial": "qué daño habría causado en una app real",
  "nivel_sofisticacion": "básico/intermedio/avanzado",
  "recomendacion": "cómo defenderse de este ataque"
}}

Tipo de ataque: {tipo}
Ruta atacada: {ruta_txt}
Payload: {texto_payload}

Responde únicamente con el objeto JSON, sin texto adicional."""

    try:
        cliente = _obtener_cliente_anthropic()
        mensaje = cliente.messages.create(
            model=MODELO_CLAUDE,
            max_tokens=500,
            messages=[{"role": "user", "content": prompt}],
            timeout=90.0,
        )
        texto = _texto_de_respuesta(mensaje)
        datos = _extraer_json_de_texto(texto)

        if not isinstance(datos, dict):
            return dict(ANALISIS_PAYLOAD_DEFECTO)

        resultado = dict(ANALISIS_PAYLOAD_DEFECTO)
        for clave in resultado:
            if clave in datos and datos[clave] is not None:
                resultado[clave] = str(datos[clave]).strip()
        return resultado

    except (anthropic.APIError, anthropic.APIConnectionError, anthropic.APITimeoutError) as exc:
        fallback = dict(ANALISIS_PAYLOAD_DEFECTO)
        fallback["recomendacion"] = f"Error de API Anthropic: {exc}"
        return fallback
    except ValueError as exc:
        fallback = dict(ANALISIS_PAYLOAD_DEFECTO)
        fallback["recomendacion"] = str(exc)
        return fallback
    except Exception as exc:
        fallback = dict(ANALISIS_PAYLOAD_DEFECTO)
        fallback["recomendacion"] = f"Error inesperado: {exc}"
        return fallback


def _compactar_eventos_para_prompt(eventos):
    """Resume eventos en líneas breves para no saturar el contexto del modelo."""
    if not eventos:
        return "No hay eventos registrados."

    lineas = []
    for ev in eventos:
        payload_corto = _serializar_payload(ev.get("payload"))
        if len(payload_corto) > 120:
            payload_corto = payload_corto[:117] + "..."
        lineas.append(
            f"- [{ev.get('timestamp', '?')}] IP={ev.get('ip', '?')} | "
            f"tipo={ev.get('tipo_ataque', '?')} | gravedad={ev.get('gravedad', '?')} | "
            f"ruta={ev.get('ruta', '/')} | payload={payload_corto}"
        )
    return "\n".join(lineas)


def generar_resumen_diario(fecha=None):
    """
    Genera un resumen ejecutivo en prosa de los ataques de un día.

    Args:
        fecha (str|None): YYYY-MM-DD; si es None, usa el día actual (Europe/Madrid).

    Returns:
        str: Resumen en español o mensaje si falla la API.
    """
    from database import obtener_eventos, obtener_eventos_por_fecha

    if fecha:
        eventos_dia = obtener_eventos_por_fecha(fecha, limite=500)
        etiqueta_dia = fecha
    else:
        eventos_dia = obtener_eventos(limite=500, periodo="hoy")
        etiqueta_dia = "hoy"

    if not eventos_dia:
        return ""

    eventos_resumen = _compactar_eventos_para_prompt(eventos_dia)
    total = len(eventos_dia)

    prompt = f"""Eres un analista de seguridad. Genera un resumen ejecutivo \
en español de los ataques registrados el día {etiqueta_dia} en este honeypot. \
El resumen debe ser en prosa natural, profesional y detallado. \
Incluye: total de ataques, tipos más frecuentes, IPs destacadas, \
patrones identificados y recomendaciones.

Total de eventos del día: {total}

Datos del día {etiqueta_dia}:
{eventos_resumen}"""

    try:
        cliente = _obtener_cliente_anthropic()
        mensaje = cliente.messages.create(
            model=MODELO_CLAUDE,
            max_tokens=800,
            messages=[{"role": "user", "content": prompt}],
            timeout=120.0,
        )
        texto = _texto_de_respuesta(mensaje).strip()
        return texto or "El modelo no devolvió contenido para el resumen diario."

    except (anthropic.APIError, anthropic.APIConnectionError, anthropic.APITimeoutError) as exc:
        return (
            f"No se pudo generar el resumen diario por un error de la API de Anthropic: {exc}. "
            f"El día {etiqueta_dia} tiene {total} evento(s) registrados; consulte el panel del monitor."
        )
    except ValueError as exc:
        return f"No se pudo generar el resumen: {exc}"
    except Exception as exc:
        return f"Error inesperado al generar el resumen diario: {exc}"


def detectar_anomalias(eventos_recientes):
    """
    Detecta patrones o anomalías en una lista de eventos recientes (p. ej. última hora).

    Args:
        eventos_recientes (list[dict]): Eventos con campos típicos de la tabla `eventos`.

    Returns:
        dict: hay_anomalia, descripcion, nivel_alerta, ips_sospechosas, patron_detectado.
    """
    if not eventos_recientes:
        return {
            "hay_anomalia": False,
            "descripcion": "No hay eventos recientes que analizar.",
            "nivel_alerta": "bajo",
            "ips_sospechosas": [],
            "patron_detectado": "Sin actividad en la ventana temporal",
        }

    eventos_json = json.dumps(
        [
            {
                "ip": ev.get("ip"),
                "ruta": ev.get("ruta"),
                "tipo_ataque": ev.get("tipo_ataque"),
                "gravedad": ev.get("gravedad"),
                "timestamp": ev.get("timestamp"),
                "payload": ev.get("payload"),
            }
            for ev in eventos_recientes
        ],
        ensure_ascii=False,
        indent=2,
    )

    prompt = f"""Analiza estos eventos de seguridad y detecta anomalías o \
patrones inusuales. Responde en JSON con:

{{
  "hay_anomalia": true,
  "descripcion": "descripción de la anomalía detectada",
  "nivel_alerta": "bajo",
  "ips_sospechosas": ["ip1", "ip2"],
  "patron_detectado": "descripción del patrón"
}}

Usa valores booleanos reales para hay_anomalia y nivel_alerta en: bajo, medio, alto, crítico.

Eventos:
{eventos_json}

Responde únicamente con el objeto JSON."""

    try:
        cliente = _obtener_cliente_anthropic()
        mensaje = cliente.messages.create(
            model=MODELO_CLAUDE,
            max_tokens=400,
            messages=[{"role": "user", "content": prompt}],
            timeout=90.0,
        )
        texto = _texto_de_respuesta(mensaje)
        datos = _extraer_json_de_texto(texto)

        if not isinstance(datos, dict):
            return dict(ANOMALIAS_DEFECTO)

        resultado = dict(ANOMALIAS_DEFECTO)
        if "hay_anomalia" in datos:
            resultado["hay_anomalia"] = bool(datos["hay_anomalia"])
        if datos.get("descripcion") is not None:
            resultado["descripcion"] = str(datos["descripcion"]).strip()
        if datos.get("nivel_alerta") is not None:
            resultado["nivel_alerta"] = str(datos["nivel_alerta"]).strip().lower()
        if isinstance(datos.get("ips_sospechosas"), list):
            resultado["ips_sospechosas"] = [
                str(ip).strip() for ip in datos["ips_sospechosas"] if ip
            ]
        if datos.get("patron_detectado") is not None:
            resultado["patron_detectado"] = str(datos["patron_detectado"]).strip()
        return resultado

    except (anthropic.APIError, anthropic.APIConnectionError, anthropic.APITimeoutError) as exc:
        fallback = dict(ANOMALIAS_DEFECTO)
        fallback["descripcion"] = f"Error de API Anthropic: {exc}"
        return fallback
    except ValueError as exc:
        fallback = dict(ANOMALIAS_DEFECTO)
        fallback["descripcion"] = str(exc)
        return fallback
    except Exception as exc:
        fallback = dict(ANOMALIAS_DEFECTO)
        fallback["descripcion"] = f"Error inesperado: {exc}"
        return fallback
