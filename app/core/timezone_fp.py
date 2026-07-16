"""
Zona horaria unificada del proyecto FlyPaper (Europe/Madrid).

Todos los timestamps persistidos y mostrados usan hora local de Madrid
en formato de 24 h: YYYY-MM-DD HH:mm:ss (sin conversión a UTC en BD).
"""

from datetime import datetime, timedelta

ZONA_NOMBRE = "Europe/Madrid"
FORMATO_MARCA = "%Y-%m-%d %H:%M:%S"
FORMATO_FECHA = "%Y-%m-%d"


def _cargar_zona():
    """ZoneInfo (stdlib + tzdata en Windows) o pytz como respaldo."""
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(ZONA_NOMBRE)
    except Exception:
        try:
            import pytz

            return pytz.timezone(ZONA_NOMBRE)
        except ImportError as exc:
            raise RuntimeError(
                "Instala el paquete 'tzdata' o 'pytz' para usar Europe/Madrid."
            ) from exc


ZONA_APP = _cargar_zona()


def ahora():
    """Instante actual con tz Europe/Madrid."""
    return datetime.now(ZONA_APP)


def ahora_naive():
    """Datetime naive en hora de Madrid (comparación con columnas SQLite)."""
    dt = ahora()
    if getattr(dt, "tzinfo", None) is not None:
        return dt.replace(tzinfo=None)
    return dt


def marca_ahora():
    """Cadena estándar para columnas timestamp/fecha en BD y logs."""
    return ahora_naive().strftime(FORMATO_MARCA)


def fecha_hoy():
    """Fecha calendario actual en Madrid (YYYY-MM-DD)."""
    return ahora_naive().strftime(FORMATO_FECHA)


def hace(**kwargs):
    """Marca naive = ahora Madrid menos el intervalo indicado."""
    return ahora_naive() - timedelta(**kwargs)


def formatear_marca(dt):
    """Convierte datetime naive/aware a string estándar del proyecto."""
    if dt is None:
        return None
    if getattr(dt, "tzinfo", None) is not None:
        if hasattr(dt, "astimezone"):
            dt = dt.astimezone(ZONA_APP).replace(tzinfo=None)
        else:
            dt = dt.replace(tzinfo=None)
    return dt.strftime(FORMATO_MARCA)


def parsear_marca(cadena):
    """Interpreta YYYY-MM-DD HH:mm:ss como hora local Madrid (naive)."""
    if not cadena:
        return None
    texto = str(cadena).strip().replace("Z", "")
    if "T" in texto:
        texto = texto.replace("T", " ")[:19]
    else:
        texto = texto[:19]
    try:
        return datetime.strptime(texto, FORMATO_MARCA)
    except (ValueError, TypeError):
        return None


def minutos_desde_marca(cadena):
    """Minutos transcurridos desde una marca guardada en BD hasta ahora (Madrid)."""
    dt = parsear_marca(cadena)
    if dt is None:
        return None
    return max(0, int((ahora_naive() - dt).total_seconds() // 60))
