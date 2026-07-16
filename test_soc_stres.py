#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_soc_stres.py — Simulador de adversario automatizado (Red Team) para FlyPaper.

Estresa y valida en directo el perímetro NGWAF:
  [1] Firmas WAF (SQLi / XSS / RCE / LFI / SSRF con evasión)
  [2] Rate Limiting global (ventana deslizante Redis >60 req/min)
  [3] Riesgo acumulativo por sesión (autoban dinámico ≥5)
  [4] Fingerprinting de scanners (User-Agent ofensivos)
  [5] Batería completa

Uso:
  python test_soc_stres.py
  python test_soc_stres.py --base http://127.0.0.1:5000
  python test_soc_stres.py --all

Requisito: servidor FlyPaper en marcha (+ Redis en el modo Docker/NGWAF).
"""

from __future__ import annotations

import argparse
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Optional

try:
    import requests
except ImportError:
    print(
        "[!] Falta la biblioteca 'requests'. Instálala con:\n"
        "    pip install requests\n"
    )
    sys.exit(1)

# colorama es opcional
try:
    from colorama import Fore, Style, init as colorama_init

    colorama_init(autoreset=True)
    C_OK = Fore.GREEN
    C_FAIL = Fore.RED
    C_WARN = Fore.YELLOW
    C_INFO = Fore.CYAN
    C_TITLE = Fore.MAGENTA + Style.BRIGHT
    C_DIM = Style.DIM
    C_RESET = Style.RESET_ALL
except ImportError:
    C_OK = C_FAIL = C_WARN = C_INFO = C_TITLE = C_DIM = C_RESET = ""

BASE_URL_DEFAULT = "http://127.0.0.1:5000"
TIMEOUT_SEG = 8
UMBRAL_RATE = 60
PETICIONES_RATE = 65

# IPs sintéticas (TEST-NET-3 RFC 5737) aisladas por módulo vía X-Forwarded-For.
IP_FIRMAS = "203.0.113.11"
IP_RATE = "203.0.113.22"
IP_RIESGO = "203.0.113.33"
IP_SCANNER = "203.0.113.44"


@dataclass
class Estadisticas:
    """Acumulador del reporte final."""

    enviadas: int = 0
    bloqueadas: int = 0  # 403 / 429 / jail
    pasaron: int = 0  # 2xx / 3xx / 404 sin jail
    errores_red: int = 0
    jail_detectado: bool = False
    detalles: list[str] = field(default_factory=list)

    def registrar(self, codigo: Optional[int], cuerpo: str = "", etiqueta: str = "") -> None:
        self.enviadas += 1
        texto = (cuerpo or "").lower()
        es_jail = (
            codigo in (403, 429)
            or "jail" in texto
            or "calabozo" in texto
            or "bloquead" in texto
        )
        if codigo is None:
            self.errores_red += 1
            self.detalles.append(f"{etiqueta}: ERROR DE RED")
            return
        if es_jail:
            self.bloqueadas += 1
            self.jail_detectado = True
            self.detalles.append(f"{etiqueta}: HTTP {codigo} [BLOQUEADO/JAIL]")
        else:
            self.pasaron += 1
            self.detalles.append(f"{etiqueta}: HTTP {codigo}")


def banner(base: str) -> None:
    print()
    print(C_TITLE + "=" * 64)
    print("  FlyPaper · test_soc_stres.py — Simulador Red Team / NGWAF")
    print("=" * 64 + C_RESET)
    print(f"  Objetivo : {C_INFO}{base}{C_RESET}")
    print(
        f"  Defensas : Firmas · Rate-Limit Redis · Riesgo acumulativo · Scanners"
    )
    print(C_DIM + "  Nota: usa X-Forwarded-For con IPs de prueba aisladas por módulo." + C_RESET)
    print()


def menu() -> None:
    print(C_TITLE + "  Selecciona una prueba:" + C_RESET)
    print("  [1] Test de Firmas WAF (SQLi, XSS, RCE, LFI, SSRF codificados)")
    print("  [2] Test de Rate Limiting Global (inundación → 429)")
    print("  [3] Test de Riesgo Acumulativo (autoban dinámico ≥5)")
    print("  [4] Test de Fingerprinting de Scanners (User-Agent)")
    print("  [5] Ejecutar toda la batería de ataques")
    print("  [0] Salir")
    print()


def _headers(ip: str, user_agent: str = "FlyPaper-RedTeam-Stress/1.0") -> dict[str, str]:
    return {
        "User-Agent": user_agent,
        "X-Forwarded-For": ip,
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        "Connection": "close",
    }


def _es_jail(codigo: Optional[int], texto: str) -> bool:
    t = (texto or "").lower()
    return codigo in (403, 429) or "jail" in t or "calabozo" in t


def peticion(
    session: requests.Session,
    metodo: str,
    url: str,
    *,
    ip: str,
    stats: Estadisticas,
    etiqueta: str,
    user_agent: str = "FlyPaper-RedTeam-Stress/1.0",
    data: Any = None,
    params: Any = None,
) -> tuple[Optional[int], str]:
    """Ejecuta una petición y actualiza estadísticas. Maneja servidor caído."""
    try:
        respuesta = session.request(
            metodo,
            url,
            headers=_headers(ip, user_agent),
            data=data,
            params=params,
            timeout=TIMEOUT_SEG,
            allow_redirects=False,
        )
        cuerpo = respuesta.text or ""
        codigo = respuesta.status_code
        stats.registrar(codigo, cuerpo, etiqueta)
        marca = (
            f"{C_FAIL}JAIL/BLOCK{C_RESET}"
            if _es_jail(codigo, cuerpo)
            else f"{C_OK}OK{C_RESET}"
        )
        print(f"    → HTTP {codigo}  [{marca}]  {etiqueta}")
        return codigo, cuerpo
    except requests.exceptions.ConnectionError:
        print(
            f"    {C_FAIL}[!] Sin conexión a {url} — ¿está FlyPaper en marcha?{C_RESET}"
        )
        stats.registrar(None, "", etiqueta)
        return None, ""
    except requests.exceptions.Timeout:
        print(f"    {C_WARN}[!] Timeout en {etiqueta}{C_RESET}")
        stats.registrar(None, "", etiqueta)
        return None, ""
    except requests.exceptions.RequestException as exc:
        print(f"    {C_FAIL}[!] Error de red: {exc}{C_RESET}")
        stats.registrar(None, "", etiqueta)
        return None, ""


def comprobar_servidor(base: str) -> bool:
    """Ping rápido a la raíz antes de lanzar módulos."""
    print(C_INFO + "[*] Comprobando disponibilidad del objetivo..." + C_RESET)
    try:
        r = requests.get(
            base.rstrip("/") + "/",
            headers=_headers("127.0.0.1"),
            timeout=TIMEOUT_SEG,
        )
        print(f"    Servidor responde HTTP {r.status_code}")
        return True
    except requests.exceptions.RequestException as exc:
        print(C_FAIL + f"[!] No se puede contactar {base}: {exc}" + C_RESET)
        print(
            C_DIM
            + "    Arranca FlyPaper (python app.py / docker compose up) e inténtalo de nuevo."
            + C_RESET
        )
        return False


# ---------------------------------------------------------------------------
# Módulo 1 — Firmas WAF
# ---------------------------------------------------------------------------


def modulo_firmas(base: str, stats: Estadisticas) -> None:
    print()
    print(C_TITLE + "[1] Firmas WAF — payloads con evasión" + C_RESET)
    print(
        C_DIM
        + "    SQLi / XSS / RCE / LFI / SSRF vía query y /secure/search"
        + C_RESET
    )

    session = requests.Session()
    root = base.rstrip("/")

    payloads = [
        (
            "GET",
            "/",
            {"q": "1' OR/**/1=1--"},
            None,
            "SQLi boolean + comentario /**/",
        ),
        (
            "GET",
            "/",
            {"q": "1' UNION/**/SELECT null,null--"},
            None,
            "SQLi UNION/**/SELECT",
        ),
        (
            "GET",
            "/",
            {"q": "1'; WAITFOR DELAY '0:0:3'--"},
            None,
            "SQLi time-based WAITFOR",
        ),
        (
            "POST",
            "/secure/search",
            None,
            {"query": "1' OR SLEEP(3)--"},
            "SQLi SLEEP vía /secure/search",
        ),
        (
            "GET",
            "/",
            {"x": "<svg/onload=alert(1)>"},
            None,
            "XSS vector SVG onload",
        ),
        (
            "GET",
            "/",
            {"x": "<img src=x onerror=alert(1)>"},
            None,
            "XSS img onerror",
        ),
        (
            "GET",
            "/",
            {"cmd": "; whoami"},
            None,
            "RCE metachar + whoami",
        ),
        (
            "GET",
            "/file",
            {"path": "..%252f..%252fetc%252fpasswd"},
            None,
            "LFI double-encoding ..%252f",
        ),
        (
            "GET",
            "/",
            {"path": "....//....//etc/passwd"},
            None,
            "LFI evasión ....//",
        ),
        (
            "GET",
            "/",
            {"url": "http://169.254.169.254/latest/meta-data/"},
            None,
            "SSRF metadata cloud",
        ),
        (
            "GET",
            "/",
            {"url": "gopher://127.0.0.1:6379/_INFO"},
            None,
            "SSRF esquema gopher://",
        ),
    ]

    for metodo, ruta, params, data, etiqueta in payloads:
        url = root + ruta
        # Codificación extra en path LFI ya viene en params
        peticion(
            session,
            metodo,
            url,
            ip=IP_FIRMAS,
            stats=stats,
            etiqueta=etiqueta,
            params=params,
            data=data,
        )
        time.sleep(0.15)

    print(C_OK + "    Módulo 1 finalizado." + C_RESET)


# ---------------------------------------------------------------------------
# Módulo 2 — Rate Limiting
# ---------------------------------------------------------------------------


def modulo_rate_limit(base: str, stats: Estadisticas) -> None:
    print()
    print(C_TITLE + "[2] Rate Limiting Global — inundación Redis ZSET" + C_RESET)
    print(
        C_DIM
        + f"    {PETICIONES_RATE} GET / consecutivos (umbral típico: {UMBRAL_RATE}/min)"
        + C_RESET
    )

    session = requests.Session()
    url = base.rstrip("/") + "/"
    primer_429: Optional[int] = None
    codigos: list[int] = []

    t0 = time.perf_counter()
    for i in range(1, PETICIONES_RATE + 1):
        codigo, cuerpo = peticion(
            session,
            "GET",
            url,
            ip=IP_RATE,
            stats=stats,
            etiqueta=f"flood #{i}/{PETICIONES_RATE}",
        )
        if codigo is not None:
            codigos.append(codigo)
        if codigo == 429 and primer_429 is None:
            primer_429 = i
            print(
                C_WARN
                + f"    ★ Primer 429 en la petición #{i} "
                f"(esperado cerca de {UMBRAL_RATE + 1})"
                + C_RESET
            )
            # Tras el jail no hace falta inundar mucho más
            if i >= UMBRAL_RATE + 1:
                break
        if codigo is None:
            break

    elapsed = time.perf_counter() - t0
    if primer_429:
        print(
            C_OK
            + f"    Rate-limit DETONADO en petición #{primer_429} "
            f"({elapsed:.2f}s, {len(codigos)} respuestas)"
            + C_RESET
        )
    else:
        print(
            C_FAIL
            + "    No se observó HTTP 429. ¿Redis activo? ¿RATE_LIMIT_MAX_REQ distinto?"
            + C_RESET
        )
        if codigos:
            print(C_DIM + f"    Códigos vistos: {sorted(set(codigos))}" + C_RESET)

    print(C_OK + "    Módulo 2 finalizado." + C_RESET)


# ---------------------------------------------------------------------------
# Módulo 3 — Riesgo acumulativo
# ---------------------------------------------------------------------------


def modulo_riesgo(base: str, stats: Estadisticas) -> None:
    print()
    print(C_TITLE + "[3] Riesgo Acumulativo — autoban dinámico (≥5 pts / 10 min)" + C_RESET)
    print(
        C_DIM
        + "    /.env (+1) → /wp-admin (+1) → SQLi SLEEP (+5) → probe Jail 403"
        + C_RESET
    )

    session = requests.Session()
    root = base.rstrip("/")

    pasos = [
        ("GET", "/.env", None, None, "Ruta prohibida /.env  (+1 Sospechoso)"),
        ("GET", "/wp-admin", None, None, "Ruta prohibida /wp-admin  (+1)"),
        (
            "GET",
            "/",
            {"q": "1'; SELECT SLEEP(2)--"},
            None,
            "SQLi SLEEP time-based  (+5 Crítica → score≥5)",
        ),
        ("GET", "/", None, None, "Probe post-autoban (esperamos 403 Jail)"),
    ]

    for metodo, ruta, params, data, etiqueta in pasos:
        codigo, cuerpo = peticion(
            session,
            metodo,
            root + ruta,
            ip=IP_RIESGO,
            stats=stats,
            etiqueta=etiqueta,
            params=params,
            data=data,
        )
        time.sleep(0.35)
        if codigo is None:
            break

    # Resumen heurístico del probe final
    print(
        C_INFO
        + "    Si el NGWAF aplicó riesgo: el último probe debería ser 403 (Jail)."
        + C_RESET
    )
    print(C_OK + "    Módulo 3 finalizado." + C_RESET)


# ---------------------------------------------------------------------------
# Módulo 4 — Fingerprinting scanners
# ---------------------------------------------------------------------------


def modulo_scanners(base: str, stats: Estadisticas) -> None:
    print()
    print(C_TITLE + "[4] Fingerprinting de Scanners — User-Agent ofensivos" + C_RESET)

    session = requests.Session()
    # Ruta no whitelisted para que el detector no salte el análisis de UA.
    url = base.rstrip("/") + "/probe-scanner-fingerprint"

    agentes = [
        "sqlmap/1.8.2#stable (http://sqlmap.org)",
        "nuclei - Nuclei - Open-source project (projectdiscovery.io)",
        "Nikto/2.5.0",
        "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
        "gobuster/3.6",
        "python-requests/2.31.0",
    ]

    for ua in agentes:
        peticion(
            session,
            "GET",
            url,
            ip=IP_SCANNER,
            stats=stats,
            etiqueta=f"UA={ua[:48]}",
            user_agent=ua,
        )
        time.sleep(0.2)

    print(
        C_DIM
        + "    Esperado: clasificación «Scanner Automatizado» / Crítica en el SOC."
        + C_RESET
    )
    print(C_OK + "    Módulo 4 finalizado." + C_RESET)


# ---------------------------------------------------------------------------
# Batería + reporte
# ---------------------------------------------------------------------------


def ejecutar_bateria(base: str, stats: Estadisticas) -> None:
    print()
    print(C_TITLE + "[5] Batería completa (orden: firmas → scanners → riesgo → rate)" + C_RESET)
    print(
        C_WARN
        + "    Rate-limit al final: deja IP 203.0.113.22 en Jail 24h (TTL Redis)."
        + C_RESET
    )
    modulo_firmas(base, stats)
    modulo_scanners(base, stats)
    modulo_riesgo(base, stats)
    modulo_rate_limit(base, stats)


def reporte_final(stats: Estadisticas) -> None:
    print()
    print(C_TITLE + "=" * 64)
    print("  REPORTE FINAL — test_soc_stres")
    print("=" * 64 + C_RESET)
    print(f"  Peticiones enviadas : {stats.enviadas}")
    print(f"  {C_OK}Pasaron (sin jail) {C_RESET}: {stats.pasaron}")
    print(f"  {C_FAIL}Bloqueadas / Jail {C_RESET}: {stats.bloqueadas}")
    print(f"  Errores de red      : {stats.errores_red}")
    print(
        f"  Jail detonado       : "
        + (
            f"{C_OK}SÍ{C_RESET}"
            if stats.jail_detectado
            else f"{C_WARN}NO observado{C_RESET}"
        )
    )
    if stats.enviadas:
        pct = 100.0 * stats.bloqueadas / stats.enviadas
        print(f"  Tasa de bloqueo     : {pct:.1f}%")
    print()
    print(C_DIM + "  Higiene post-test (opcional):" + C_RESET)
    print(
        C_DIM
        + "    redis-cli --scan --pattern 'flypaper:block:203.0.113.*' | xargs -r redis-cli DEL"
        + C_RESET
    )
    print(
        C_DIM
        + "    o Whitelist desde el panel SOC → Perímetro."
        + C_RESET
    )
    print()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Simulador Red Team para validar el NGWAF de FlyPaper",
    )
    parser.add_argument(
        "--base",
        default=BASE_URL_DEFAULT,
        help=f"URL base del honeypot (default: {BASE_URL_DEFAULT})",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Ejecuta la batería completa sin menú interactivo",
    )
    parser.add_argument(
        "--test",
        type=int,
        choices=[1, 2, 3, 4, 5],
        help="Ejecuta un módulo concreto y sale",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    base = args.base.rstrip("/")
    stats = Estadisticas()

    banner(base)
    if not comprobar_servidor(base):
        return 2

    if args.all or args.test == 5:
        ejecutar_bateria(base, stats)
        reporte_final(stats)
        return 0

    if args.test:
        {
            1: modulo_firmas,
            2: modulo_rate_limit,
            3: modulo_riesgo,
            4: modulo_scanners,
        }[args.test](base, stats)
        reporte_final(stats)
        return 0

    while True:
        menu()
        try:
            eleccion = input(C_INFO + "  Opción> " + C_RESET).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if eleccion in ("0", "q", "salir", "exit"):
            break
        if eleccion == "1":
            modulo_firmas(base, stats)
        elif eleccion == "2":
            modulo_rate_limit(base, stats)
        elif eleccion == "3":
            modulo_riesgo(base, stats)
        elif eleccion == "4":
            modulo_scanners(base, stats)
        elif eleccion == "5":
            ejecutar_bateria(base, stats)
        else:
            print(C_WARN + "  Opción no válida." + C_RESET)
            continue

        print()
        otra = input("  ¿Otra prueba? [s/N]> ").strip().lower()
        if otra not in ("s", "si", "sí", "y", "yes"):
            break

    reporte_final(stats)
    return 0


if __name__ == "__main__":
    sys.exit(main())
