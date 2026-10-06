"""
Simulador de ffuf para SuperLab (interpretación de texto, sin red ni shell).

Solo reconoce un patrón fijo tipo ``ffuf -u …/FUZZ -w <diccionario>``.
"""

from __future__ import annotations

import random
import re
from typing import Optional

# Host/path que el “escaneo” descubre (coincide con el blueprint staging).
RUTA_STAGING_DESCUBIERTA = "web-nexuscorp-2.0-staging"

# Diccionario mostrado al alumno (staging no al inicio ni al final).
NOMBRE_WORDLIST = "wordlist.txt"
WORDLIST_FFUF: tuple[str, ...] = (
    "admin",
    "backup",
    "beta",
    "demo",
    "dev",
    "internal",
    "legacy",
    "old",
    "preprod",
    "qa",
    "web-nexuscorp-2.0-staging",
    "sandbox",
    "temp",
    "test",
    "v2",
    "api",
    "portal",
    "intranet",
    "mail",
)

# Patrón estricto: comando ffuf con URL que termina en /FUZZ y wordlist.
_PATRON_COMANDO_FFUF = re.compile(
    r"^\s*ffuf\s+-u\s+https?://[\w.\-]+/FUZZ\s+-w\s+(\S+)\s*$",
    re.IGNORECASE,
)

# Palabras que simulan respuestas 404 (subconjunto del diccionario, sin el hit).
_FUZZ_404_CANDIDATAS = [w for w in WORDLIST_FFUF if w != RUTA_STAGING_DESCUBIERTA]


def comando_ffuf_valido(comando: str) -> bool:
    """True si el texto coincide con el patrón ffuf esperado."""
    return bool(_PATRON_COMANDO_FFUF.match((comando or "").strip()))


def extraer_nombre_wordlist(comando: str) -> Optional[str]:
    """Devuelve el nombre de diccionario del comando, o None."""
    m = _PATRON_COMANDO_FFUF.match((comando or "").strip())
    return m.group(1) if m else None


def _linea_ffuf(codigo: int, palabra: str, url_base: str) -> str:
    """Una línea de salida estilo ffuf con tiempo aleatorio."""
    ms = random.randint(42, 380)
    tamaño = random.randint(120, 890) if codigo == 404 else random.randint(900, 2400)
    url = f"{url_base}/{palabra}"
    return f"{palabra:<28} [Status: {codigo}, Size: {tamaño:4d}, Words: {random.randint(1, 40):2d}, Lines: {random.randint(1, 12):2d}, Duration: {ms}ms] {url}"


def simular_salida_ffuf(comando: str) -> str:
    """
    Genera salida textual realista (404 + un 200 con el host staging).

    No realiza peticiones HTTP; todo es determinista/sintético en servidor.
    """
    cmd = (comando or "").strip()
    url_match = re.search(r"-u\s+(https?://[\w.\-]+)/FUZZ", cmd, re.IGNORECASE)
    url_base = url_match.group(1) if url_match else "https://web-nexuscorp-2.0.local"

    lineas = [
        "",
        "        /'___\\  /'___\\           /'___\\       ",
        "       /\\ \\__/ /\\ \\__/  __  __  /\\ \\__/       ",
        "       \\ \\ ,__\\\\ \\ ,__\\/\\ \\/\\ \\ \\ \\ ,__\\      ",
        "        \\ \\ \\_/ \\ \\ \\_/\\ \\ \\_\\ \\ \\ \\ \\_/      ",
        "         \\ \\__\\   \\ \\__\\ \\ \\____/  \\ \\__\\     ",
        "          \\/__/    \\/__/  \\/___/    \\/__/     ",
        "",
        "       v2.1.0-dev",
        "",
        " :: Method           : GET",
        f" :: URL              : {url_base}/FUZZ",
        " :: Wordlist         : wordlist",
        " :: Follow redirects : false",
        " :: Calibration      : false",
        " :: Timeout          : 10",
        " :: Threads          : 40",
        " :: Matcher          : Response status: 200-299,301,302",
        "",
        "[*] Starting fuzzing...",
        "",
    ]

    muestra_404 = random.sample(_FUZZ_404_CANDIDATAS, k=min(5, len(_FUZZ_404_CANDIDATAS)))
    for palabra in muestra_404:
        lineas.append(_linea_ffuf(404, palabra, url_base))

    lineas.append(_linea_ffuf(200, RUTA_STAGING_DESCUBIERTA, url_base))
    lineas.extend(
        [
            "",
            "[*] Progress: [##################################################] 100%",
            f"[*] Done. Found 1 match among {len(WORDLIST_FFUF)} words.",
            "",
        ]
    )
    return "\n".join(lineas)
