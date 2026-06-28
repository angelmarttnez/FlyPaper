"""
Análisis de ataques del honeypot FlyPaper mediante la API de Groq.

Requiere la variable de entorno GROQ_API_KEY y el paquete `groq`.
"""

import json
import os
import re
from pathlib import Path

from groq import Groq

from database import obtener_eventos

# Modelo Groq usado en todas las llamadas al analizador.
MODELO_GROQ = "llama-3.1-8b-instant"

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


def _cargar_groq_api_key():
    """
    Obtiene GROQ_API_KEY del entorno; si falta, intenta leer .env en la raíz del proyecto.
    """
    clave = os.environ.get("GROQ_API_KEY", "").strip()
    if clave:
        return clave

    ruta_env = Path(__file__).resolve().parent / ".env"
    if ruta_env.is_file():
        for linea in ruta_env.read_text(encoding="utf-8").splitlines():
            linea = linea.strip()
            if not linea or linea.startswith("#") or "=" not in linea:
                continue
            nombre, _, valor = linea.partition("=")
            if nombre.strip() == "GROQ_API_KEY":
                valor = valor.strip().strip('"').strip("'")
                if valor:
                    os.environ["GROQ_API_KEY"] = valor
                    return valor

    return ""


def _obtener_cliente_groq():
    """Crea el cliente de Groq validando que exista la API key."""
    api_key = _cargar_groq_api_key()
    if not api_key:
        raise ValueError(
            "Falta GROQ_API_KEY. Defínela en el entorno o en el archivo .env del proyecto."
        )
    return Groq(api_key=api_key)


def _texto_de_respuesta(response):
    """Extrae el texto plano del mensaje del modelo en la respuesta de Groq."""
    if not response.choices:
        return ""
    contenido = response.choices[0].message.content
    if contenido is None:
        return ""
    return str(contenido).strip()


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


def _ruta_excluida_ia(ruta):
    """Rutas de administración/monitor excluidas del análisis automático."""
    ruta_txt = (ruta or "").strip()
    return ruta_txt.startswith("/admin") or ruta_txt.startswith("/monitor")


def _filtrar_eventos_para_ia(eventos):
    """Elimina eventos de paneles internos antes de enviarlos al modelo."""
    return [
        ev
        for ev in (eventos or [])
        if not _ruta_excluida_ia(ev.get("ruta"))
    ]


def _es_evento_trafico_normal(ev):
    """True si el evento está clasificado como tráfico legítimo (no incidente)."""
    tipo = str(ev.get("tipo_ataque") or "").strip().lower()
    return tipo in ("tráfico normal", "otro")


_CONTEXTO_TRAFICO_NORMAL_RESUMEN = """CONTEXTO IMPORTANTE: Este honeypot recibe tanto tráfico legítimo como \
ataques reales. Las siguientes interacciones son TRÁFICO NORMAL y NO deben \
mencionarse como ataques ni incidentes:
- Accesos al formulario de login (GET /login)
- Intentos de autenticación con credenciales incorrectas sin payload malicioso (POST /login)
- Navegación por el blog, búsquedas simples, acceso al panel /admin
- Peticiones clasificadas como 'Tráfico Normal' en los datos

Solo analiza y reporta como incidentes los eventos con tipo_ataque distinto \
de 'Tráfico Normal'. Si el día solo tiene tráfico normal, indícalo \
explícitamente como 'Sin incidentes de seguridad relevantes detectados'."""


def _invocar_modelo_groq(cliente, prompt, max_tokens):
    """Envía un prompt al modelo Groq y devuelve el texto de la respuesta."""
    response = cliente.chat.completions.create(
        model=MODELO_GROQ,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=max_tokens,
        temperature=0.2,
    )
    return _texto_de_respuesta(response)


def analizar_payload(tipo_ataque, payload, ruta):
    """
    Analiza un ataque concreto con Groq y devuelve un dict estructurado.

    Args:
        tipo_ataque (str): Clasificación del detector (p. ej. SQLi, XSS).
        payload: Cuerpo o parámetros del ataque (str, dict, etc.).
        ruta (str): Ruta HTTP atacada.

    Returns:
        dict: intencion, tecnica, dano_potencial, nivel_sofisticacion, recomendacion.
    """
    ruta_txt = (ruta or "/").strip()
    if _ruta_excluida_ia(ruta_txt):
        resultado = dict(ANALISIS_PAYLOAD_DEFECTO)
        resultado["recomendacion"] = (
            "Ruta de administración excluida del análisis automático."
        )
        return resultado

    texto_payload = _serializar_payload(payload)
    tipo = (tipo_ataque or "Desconocido").strip()

    prompt = f"""Eres un analista de ciberseguridad SOC analizando un evento real capturado \
por un honeypot web. El honeypot simula un entorno corporativo vulnerable. \
Tu tarea es analizar el ataque con precisión técnica y responder en español \
estrictamente en JSON, sin texto adicional.

Tipo de ataque clasificado: {tipo}
Ruta HTTP atacada: {ruta_txt}
Payload capturado: {texto_payload}

Responde con este JSON exacto (sin bloques de código, sin explicaciones):
{{
  "intencion": "objetivo concreto del atacante en esta petición específica",
  "tecnica": "nombre técnico del vector de ataque y mecanismo de explotación",
  "dano_potencial": "impacto real si el sistema no fuera un honeypot",
  "nivel_sofisticacion": "básico|intermedio|avanzado",
  "recomendacion": "contramedida técnica específica para este vector"
}}"""

    try:
        cliente = _obtener_cliente_groq()
        texto = _invocar_modelo_groq(cliente, prompt, max_tokens=500)
        datos = _extraer_json_de_texto(texto)

        if not isinstance(datos, dict):
            return dict(ANALISIS_PAYLOAD_DEFECTO)

        resultado = dict(ANALISIS_PAYLOAD_DEFECTO)
        for clave in resultado:
            if clave in datos and datos[clave] is not None:
                resultado[clave] = str(datos[clave]).strip()
        return resultado

    except ValueError as exc:
        fallback = dict(ANALISIS_PAYLOAD_DEFECTO)
        fallback["recomendacion"] = str(exc)
        return fallback
    except Exception as exc:
        fallback = dict(ANALISIS_PAYLOAD_DEFECTO)
        fallback["recomendacion"] = f"Error de API Groq: {exc}"
        return fallback


def _compactar_eventos_para_prompt(eventos):
    """Resume incidentes (sin Tráfico Normal) en líneas breves para el prompt."""
    eventos_incidente = [
        ev for ev in (eventos or []) if not _es_evento_trafico_normal(ev)
    ]
    if not eventos_incidente:
        return "Sin eventos de seguridad relevantes en este período."

    lineas = []
    for ev in eventos_incidente:
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
        eventos_dia = obtener_eventos(limite=500, periodo="hoy", ambito="publico")
        etiqueta_dia = "hoy"

    eventos_dia = _filtrar_eventos_para_ia(eventos_dia)
    if not eventos_dia:
        return ""

    eventos_incidente = [
        ev for ev in eventos_dia if not _es_evento_trafico_normal(ev)
    ]
    if not eventos_incidente:
        return "Sin eventos de seguridad relevantes en este período."

    eventos_resumen = _compactar_eventos_para_prompt(eventos_incidente)
    total = len(eventos_incidente)

    prompt = f"""{_CONTEXTO_TRAFICO_NORMAL_RESUMEN}

Eres un analista de seguridad SOC redactando el informe diario de un honeypot web \
corporativo. Redacta un resumen ejecutivo profesional en español para el día {etiqueta_dia}.

El informe debe cubrir obligatoriamente:
1. Volumen total y comparativa con días anteriores si hay contexto
2. Tipos de ataque predominantes con porcentajes aproximados
3. IPs más activas y su comportamiento (automatizado vs manual)
4. Patrones temporales: horas pico, ráfagas, campañas coordinadas
5. Técnicas más sofisticadas o inusuales detectadas
6. Recomendaciones de acción priorizadas

Usa prosa técnica continua, sin listas de viñetas. Longitud: 3-4 párrafos.
Total de eventos: {total}
Datos del día:
{eventos_resumen}"""

    try:
        cliente = _obtener_cliente_groq()
        texto = _invocar_modelo_groq(cliente, prompt, max_tokens=800)
        return texto or "El modelo no devolvió contenido para el resumen diario."

    except ValueError as exc:
        return f"No se pudo generar el resumen: {exc}"
    except Exception as exc:
        return (
            f"No se pudo generar el resumen diario por un error de la API de Groq: {exc}. "
            f"El día {etiqueta_dia} tiene {total} evento(s) registrados; consulte el panel del monitor."
        )


def detectar_anomalias(eventos_recientes):
    """
    Detecta patrones o anomalías en una lista de eventos recientes (p. ej. última hora).

    Args:
        eventos_recientes (list[dict]): Eventos con campos típicos de la tabla `eventos`.

    Returns:
        dict: hay_anomalia, descripcion, nivel_alerta, ips_sospechosas, patron_detectado.
    """
    eventos_recientes = _filtrar_eventos_para_ia(eventos_recientes)

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

    prompt = f"""Eres un sistema de detección de anomalías SOC. Analiza estos eventos de seguridad \
de la última hora e identifica comportamientos estadísticamente inusuales o \
indicadores de compromiso (IoC).

Criterios de anomalía: velocidad de ataque >10 req/min por IP, cambios bruscos \
de tipo de ataque, IPs que prueban múltiples vectores, patrones de reconocimiento \
sistemático, payloads que sugieren herramientas automatizadas (sqlmap, nikto, etc).

Responde estrictamente en JSON sin texto adicional:
{{
  "hay_anomalia": true|false,
  "descripcion": "descripción técnica concisa de la anomalía principal",
  "nivel_alerta": "bajo|medio|alto|crítico",
  "ips_sospechosas": ["ip1", "ip2"],
  "patron_detectado": "nombre del patrón o técnica detectada"
}}

Eventos de la última hora:
{eventos_json}"""

    try:
        cliente = _obtener_cliente_groq()
        texto = _invocar_modelo_groq(cliente, prompt, max_tokens=400)
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

    except ValueError as exc:
        fallback = dict(ANOMALIAS_DEFECTO)
        fallback["descripcion"] = str(exc)
        return fallback
    except Exception as exc:
        fallback = dict(ANOMALIAS_DEFECTO)
        fallback["descripcion"] = f"Error de API Groq: {exc}"
        return fallback
