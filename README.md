# FlyPaper Honeypot Web, Academia CTF y Panel SOC


FlyPaper es un honeypot web que atrae, registra y analiza ataques en tiempo real. Simula un portal corporativo vulnerable (login, blog, buscador, rutas señuelo) con **Academia CTF** (SQLi, XSS, IDOR, Path Traversal, SuperLab) y un **panel SOC** (`/admin`) con monitor, perímetro NGWAF (Redis), mapa, reportes y análisis IA (Groq).

## 1. Requisitos previos

| Requisito | Notas |

| Python 3.11+ | Desarrollo local |
| Git | Clonado del repositorio |
| Redis 7 | NGWAF (rate-limit, bloqueos). En local: contenedor en `6379` |
| Docker + Compose v2 | Despliegue en VM / producción ligera |
| (Opcional) Claves API | Groq, Telegram, AbuseIPDB, VirusTotal, CARTO |


## 2. Instalación y ejecución paso a paso (local)

```bash
# 1) Clonar
git clone https://github.com/angelmarttnez/FlyPaper.git
cd FlyPaper

# 2) Entorno virtual
python -m venv .venv
# Windows:  .venv\Scripts\activate
source .venv/bin/activate

# 3) Dependencias
pip install -r requirements.txt

# 4) Configuración (valores ficticios en la plantilla; sustituye por los tuyos)
cp .env.example .env
# Editar al menos: SECRET_KEY, y si usas IA/Telegram: GROQ_API_KEY, TELEGRAM_*

# 5) Redis (ejemplo con Docker Desktop)
docker run -d --name flypaper-redis-dev -p 6379:6379 redis:7-alpine

# 6) Arrancar
python app.py
```

Abre http://127.0.0.1:5000


## 3. Despliegue con contenedores (VM)

Ficheros: `Dockerfile`, `docker-compose.yml` (servicios `flypaper` + `redis`).

```bash
cd FlyPaper
cp .env.example .env
# En VM pública: SECRET_KEY aleatorio, INITIAL_SOC_PASSWORD fuerte,
# FLYPAPER_STRICT_DEPLOY=1, TELEGRAM_*, GROQ_API_KEY

docker compose up --build -d
docker compose ps
docker compose logs -f flypaper
```

- App: http://SERVIDOR:5000  
- Datos: volumen `./data` → `/app/data`  
- Redis: red interna Compose (no publicado al exterior)

## 4. Uso básico

| URL | Qué hace |

| `/` · `/login` | Portal honeypot |
| `/blog` · `/search` | Blog (XSS) y buscador real |
| `/objetivos` | Academia CTF |
| `/documentacion` | Docs y writeups |
| `/admin/login` | Panel SOC (2FA Telegram obligatorio) |
| `/diversion/carta` | Minijuego Rosco |

**Cara pública (atacante / alumno):** explorar señuelos (`/.env`, `/backup`, …), labs en `/objetivos`, capturar flags.  
**SOC:** login → 2FA → monitor, perímetro, reportes (resúmenes IA), mapa.

## 5. Datos de acceso de prueba (laboratorio)

> Solo para entorno local / primera BD vacía. **Cámbialos** en cualquier VM expuesta.

| Ámbito | Usuario | Contraseña | Notas |

| Panel SOC (bootstrap) | `Flypaper` | `Flypaper_123` | Solo si no defines `INITIAL_SOC_*` y `flypaper_priv.db` está vacía. Exige 2FA Telegram y cambio obligatorio de credenciales. |
| Portal demo (tests) | `demo_flypaper` | `DemoFlyPaper2026!` | Crear con `python scripts/preparar_cuenta_demo.py` |
| Variables tests | `FLYPAPER_TEST_USER` / `FLYPAPER_TEST_PASSWORD` | Ver `.env.example` | Evitan 429 en `/register` |

Sin Telegram configurado, el 2FA SOC no se puede completar: define `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` y `TELEGRAM_TOPIC_LOGINS`.

## 6. Estructura del proyecto

```
FlyPaper/
├── app.py / wsgi.py          # Aplicación Flask y entrypoint Gunicorn
├── ai_analyzer.py            # Análisis IA (Groq)
├── Dockerfile / docker-compose.yml
├── requirements.txt
├── .env.example              # Variables (valores ficticios)
├── LICENSE                   # MIT
├── README.md
├── assets/                   # JS panel SOC, estáticos
├── docs/writeups/            # Writeups Academia
├── scripts/                  # Demo, reinicio lab, forzar resumen IA
├── tests/                    # Pruebas automatizadas + tests/README.md
└── app/
    ├── database.py           # SQLite multi-BD
    ├── core/                 # WAF, Redis NGWAF, Telegram, timezone
    ├── ctf_*/ superlab/      # Laboratorios CTF
    ├── admin_gestion/        # Cuentas SOC y participantes
    └── templates/            # Jinja2
```

## 7. Configuración (`.env.example`)

Todas las variables necesarias están documentadas en [`.env.example`](.env.example) con **valores ficticios**. Copia a `.env` y sustituye por secretos reales **solo en tu máquina/servidor** (el fichero `.env` está en `.gitignore`).

Variables clave: `SECRET_KEY`, `GROQ_API_KEY`, `TELEGRAM_*`, `REDIS_URL`, `CARTO_API_KEY`, `INITIAL_SOC_PASSWORD`, `FLYPAPER_STRICT_DEPLOY`.


## 8. Pruebas automatizadas

Ver detalle en [`tests/README.md`](tests/README.md).

```bash
export PYTHONPATH=.          # Windows: $env:PYTHONPATH="."
python scripts/ejecutar_pruebas_lab.py
python tests/solve_xss_01.py
python tests/test_soc_stres.py --all
```

---

## 9. Software de terceros (origen y licencia)

| Componente | Uso | Licencia / origen |

| Flask, Werkzeug | Framework web | BSD-3 https://flask.palletsprojects.com |
| Gunicorn | WSGI | MIT |
| Redis / redis-py | Perímetro NGWAF | BSD / MIT |
| bcrypt | Hash de contraseñas | Apache-2.0 |
| Groq SDK | Análisis IA | Licencia del proveedor + ToS Groq |
| Leaflet | Mapa SOC | BSD-2  https://leafletjs.com |
| CARTO basemaps | Teselas mapa | ToS CARTO |
| Chart.js | Gráficas monitor | MIT |
| Markdown (PyPI) | Writeups | BSD |

El código propio del honeypot/CTF/SOC es original del proyecto salvo las dependencias anteriores.



