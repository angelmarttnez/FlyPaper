# FlyPaper — Honeypot Web, Academia CTF y Panel SOC

FlyPaper es un honeypot web que atrae, registra y analiza ataques en tiempo real. Simula un portal corporativo vulnerable (login, blog, buscador, rutas señuelo) con **Academia CTF** (SQLi, XSS, IDOR, Path Traversal, SuperLab) y un **panel SOC** (`/admin`) con monitor, perímetro NGWAF (Redis), mapa, reportes y análisis IA (Groq).

Entrega etiquetada: tag Git `v1.0-practica3`.

Hay **dos formas** de levantarlo:

| Forma | Cuándo | En el host necesitas |
|-------|--------|----------------------|
| **A. Local (Python)** | Desarrollo / depurar | Git, Python 3.11+, pip, venv, Redis |
| **B. Solo Docker** | VM / demo rápida | Git, Docker + Compose (**no** hace falta venv ni `pip install`) |

---

## 1. Requisitos previos

| Requisito | Notas |
|-----------|-------|
| Git | Clonado del repositorio |
| Python 3.11+, pip, venv | Solo para la vía **A** (local) |
| Redis 7 | NGWAF. En local: contenedor en `6379`. En Docker Compose va incluido |
| Docker + Compose v2 | Vía **B**, o Redis suelto en la vía **A** |
| Bot de Telegram | **Obligatorio solo para entrar a `/admin`** (2FA). La parte pública y la Academia CTF funcionan sin él. Ver §5.1 |
| Claves API opcionales | Groq, AbuseIPDB, VirusTotal, CARTO. Sin ellas el sistema degrada sin fallar (ver §7) |

---

## 2. Instalación A — local (Python + venv + pip)

En el sistema debe estar instalado Python 3.11+ (incluye `pip` y el módulo `venv`).

**Ubuntu/Debian (ejemplo):**

```bash
sudo apt update
sudo apt install -y git python3 python3-pip python3-venv docker.io
```

**Pasos del proyecto:**

```bash
# 1) Clonar
git clone https://github.com/angelmarttnez/FlyPaper.git
cd FlyPaper

# 2) Entorno virtual
python3 -m venv .venv
# Windows:  py -3.11 -m venv .venv
#           .venv\Scripts\activate
source .venv/bin/activate

# 3) Dependencias Python
python -m pip install --upgrade pip
pip install -r requirements.txt

# 4) Configuración (plantilla; edita .env)
cp .env.example .env
# SECRET_KEY = secreto para firmar cookies de sesión (no es un usuario).
#   Generar:  python -c "import secrets; print(secrets.token_hex(32))"
# Para /admin: TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, TELEGRAM_TOPIC_LOGINS (§5.1)
# Opcional: GROQ_API_KEY, CARTO_API_KEY, etc.

# 5) Redis (ejemplo con Docker)
docker run -d --name flypaper-redis-dev -p 6379:6379 redis:7-alpine

# 6) Arrancar
python app.py
```

Abre http://127.0.0.1:5000

---

## 3. Instalación B — solo Docker y Git (VM / producción ligera)

No instales Python, venv ni `requirements.txt` en el host: se instalan **dentro de la imagen** al construir.

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y git docker.io docker-compose-v2
sudo usermod -aG docker "$USER"   # cierra sesión y vuelve a entrar

git clone https://github.com/angelmarttnez/FlyPaper.git
cd FlyPaper
cp .env.example .env
# Edita .env: SECRET_KEY, TELEGRAM_*, y en VM pública
# INITIAL_SOC_PASSWORD + FLYPAPER_STRICT_DEPLOY=1 (recomendado)

docker compose up --build -d
docker compose ps
docker compose logs -f flypaper
```

- App: http://SERVIDOR:5000  
- Datos: volumen `./data` → `/app/data` (el entrypoint ajusta el dueño a `flypaper`; **no** uses `chmod 777`)  
- Redis: red interna Compose (no publicado al exterior)

Ficheros: `Dockerfile`, `docker-entrypoint.sh`, `docker-compose.yml` (servicios `flypaper` + `redis`).

---

## 4. Uso básico

| URL | Qué hace |
|-----|----------|
| `/` · `/login` | Portal honeypot |
| `/blog` · `/search` | Blog (XSS en comentarios) y buscador real |
| `/objetivos` | Academia CTF |
| `/documentacion` | Docs y writeups |
| `/admin/login` | Panel SOC (2FA Telegram obligatorio) |
| `/diversion/carta` | Minijuego Rosco |

**Cara pública (atacante / alumno):** explorar señuelos (`/.env`, `/backup`, …), labs en `/objetivos`, capturar flags. No requiere Telegram.

**SOC:** login → 2FA → cambio obligatorio de contraseña → monitor, perímetro, reportes (resúmenes IA), mapa, gestión de cuentas SOC y de participantes del CTF.

---

## 5. Acceso al panel SOC

### 5.1 Configurar Telegram (necesario para el 2FA)

El 2FA es obligatorio y no tiene vía alternativa: el código de acceso se entrega siempre por Telegram.

1. Crea un bot con [@BotFather](https://t.me/BotFather) (`/newbot`). Te dará el **token**.
2. Crea un grupo, activa **Topics** y añade el bot como miembro.
3. Obtén el **chat ID** del grupo y el **ID del topic** de logins (por ejemplo, reenviando un mensaje a un bot como @getidsbot).
4. Rellena en `.env`:

```
TELEGRAM_BOT_TOKEN=123456789:token-del-bot
TELEGRAM_CHAT_ID=-1001234567890
TELEGRAM_TOPIC_LOGINS=12
# Opcionales (alertas de ataques y resumen diario):
TELEGRAM_TOPIC_ATAQUES=
TELEGRAM_TOPIC_RESUMEN=
```

Sin estas variables la aplicación arranca y la parte pública funciona, pero el acceso a `/admin` no se puede completar.

### 5.2 Primer acceso (credencial de arranque)

> Solo aplica cuando la BD privada (`flypaper_priv.db`) está vacía. **Cámbiala en cualquier VM expuesta.**

| Ámbito | Usuario | Contraseña | Notas |
|--------|---------|------------|-------|
| Panel SOC (arranque) | `Flypaper` | `Flypaper_123` | Se aplica si no defines `INITIAL_SOC_*`. Exige 2FA por Telegram y **cambio obligatorio de usuario y contraseña** antes de acceder a nada más. |

Por qué conocer esta contraseña **no basta** (laboratorio):

1. Hace falta el código 2FA que llega al Telegram de quien administra la instancia.
2. El cambio obligatorio ocurre justo después del 2FA.
3. Con `FLYPAPER_STRICT_DEPLOY=1` (recomendado en servidores públicos) se exige definir la contraseña inicial en `.env`.
4. Tras cambiarla, reiniciar los contenedores no la restaura.

### 5.3 Cuentas de prueba para tests

| Ámbito | Usuario | Contraseña | Notas |
|--------|---------|------------|-------|
| Portal demo (tests) | `demo_flypaper` | `DemoFlyPaper2026!` | Crear con `python scripts/preparar_cuenta_demo.py`. Sin acceso al panel SOC. |
| Variables de tests | `FLYPAPER_TEST_USER` / `FLYPAPER_TEST_PASSWORD` | Ver `.env.example` | Evitan 429 en `/register` |

---

## 6. Estructura del proyecto

```
FlyPaper/
├── app.py / wsgi.py          # Aplicación Flask y entrypoint Gunicorn
├── ai_analyzer.py            # Análisis IA (Groq)
├── Dockerfile / docker-compose.yml / docker-entrypoint.sh
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

Persistencia local (no va a Git): directorio `data/*.db`.

---

## 7. Configuración (`.env.example`)

Copia [`.env.example`](.env.example) → `.env` y edita. El `.env` real **no** se sube a Git.

| Variable | ¿Qué es? | Sin ella |
|----------|----------|----------|
| `SECRET_KEY` | Secreto de Flask para **firmar cookies de sesión**. No es login ni API key. Genera uno con `python -c "import secrets; print(secrets.token_hex(32))"`. | Usa el valor de ejemplo (solo laboratorio) |
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` / `TELEGRAM_TOPIC_LOGINS` | Bot, chat y topic del 2FA SOC (ver §5.1) | No se puede entrar a `/admin`; el resto funciona |
| `TELEGRAM_TOPIC_ATAQUES` / `TELEGRAM_TOPIC_RESUMEN` | Topics de alertas y resumen diario | Esas notificaciones no se envían |
| `GROQ_API_KEY` | Clave de [console.groq.com](https://console.groq.com) para análisis IA y resúmenes | Respuesta degradada, el panel no se interrumpe |
| `ABUSEIPDB_API_KEY` / `VIRUSTOTAL_API_KEY` | Reputación de IP en el NGWAF | Solo reglas locales (ip-api no necesita clave) |
| `CARTO_API_KEY` | Teselas del mapa SOC | Mapa con funcionalidad reducida |
| `REDIS_URL` | Redis del NGWAF (`127.0.0.1` en local; Compose usa `redis://redis:6379/0`) | Perímetro en modo degradado (fail-open) |
| `INITIAL_SOC_USERNAME` / `INITIAL_SOC_PASSWORD` | Cuenta SOC inicial (BD privada vacía) | Se usa la credencial de §5.2 |
| `FLYPAPER_STRICT_DEPLOY` | `1` = obliga a definir la contraseña SOC en `.env` (recomendado en VM) | Se permite la credencial de arranque |
| `FLYPAPER_ALLOW_SOC_RECOVERY` | Recuperación de acceso SOC. Mantener en `0` salvo necesidad | Desactivada |

El resto de variables (umbrales del NGWAF, TTL, circuit breaker) tiene valores por defecto y comentarios en `.env.example`.

---

## 8. Pruebas automatizadas

Ver detalle en [`tests/README.md`](tests/README.md). Requiere la vía **A** (venv + dependencias) o ejecutar dentro del contenedor.

```bash
export PYTHONPATH=.          # Windows: $env:PYTHONPATH="."
python scripts/ejecutar_pruebas_lab.py
python tests/solve_xss_01.py
python tests/test_soc_stres.py --all
```

Las pruebas del panel SOC requieren Telegram configurado (§5.1).

---

## 9. Antes de exponer FlyPaper en un servidor público

- Activa `FLYPAPER_STRICT_DEPLOY=1` y define una `SECRET_KEY` y una `INITIAL_SOC_PASSWORD` propias.
- Pon un proxy inverso (Nginx/Caddy) con TLS delante del puerto 5000.
- Protege Redis con contraseña (`requirepass`); no lo publiques fuera de la red de Compose.
- Haz copias de seguridad periódicas de `data/`.
- Comprueba que el repositorio no contiene ningún `.env` real ni secretos en el historial.
- Realiza las pruebas de ataque solo sobre tu propia instancia.

---

## 10. Software de terceros (origen y licencia)

| Componente | Uso | Licencia / origen |
|------------|-----|-------------------|
| Flask, Werkzeug | Framework web | BSD-3 — https://flask.palletsprojects.com |
| Gunicorn | WSGI | MIT |
| Redis / redis-py | Perímetro NGWAF | BSD / MIT |
| bcrypt | Hash de contraseñas | Apache-2.0 |
| Groq SDK | Análisis IA | Licencia del proveedor + ToS Groq |
| Leaflet | Mapa SOC | BSD-2 — https://leafletjs.com |
| CARTO basemaps | Teselas mapa | ToS CARTO |
| Chart.js | Gráficas monitor | MIT |
| Markdown (PyPI) | Writeups | BSD |

El código propio del honeypot/CTF/SOC es original del proyecto salvo las dependencias anteriores.
