# Guía de despliegue

Este documento describe cómo desplegar **FlyPaper** en un servidor remoto (orientado a un VPS en **Hetzner**) usando **Docker** y **Docker Compose**, tal como se definió en el commit `42ddc1c`. El contenedor ejecuta la aplicación con **Gunicorn** sobre Python 3.11; SQLite se inicializa automáticamente al arrancar.

---

## 1. Requisitos previos

### En el servidor (VPS)

| Requisito | Versión mínima recomendada | Comprobación |
|-----------|----------------------------|--------------|
| Sistema operativo | Ubuntu 22.04 LTS o Debian 12 | `lsb_release -a` |
| Docker Engine | 24.x o superior | `docker --version` |
| Docker Compose (plugin) | v2.x | `docker compose version` |
| Git | cualquier versión reciente | `git --version` |
| Puertos libres | **5000/tcp** (HTTP del honeypot) | `ss -tlnp \| grep 5000` |

### Recursos hardware (Hetzner, orientativo)

- **1 vCPU**, **2 GB RAM** y **20 GB disco**: suficiente para laboratorio y demostración académica.
- Tipos habituales: CX22, CPX11 o equivalente.

### En el equipo de desarrollo (opcional)

- Acceso SSH al VPS (`ssh usuario@IP_DEL_SERVIDOR`).
- Clave de API de Anthropic si se desea usar el analizador IA del monitor (funcionalidad opcional).

### Instalación de Docker en Ubuntu (si no está instalado)

```bash
sudo apt update
sudo apt install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker "$USER"
```

Tras añadir el usuario al grupo `docker`, cerrar sesión y volver a entrar por SSH, o ejecutar los comandos Docker con `sudo`.

---

## 2. Obtener el código en el servidor

```bash
cd ~
git clone https://github.com/TU_USUARIO/FlyPaper.git
cd FlyPaper
```

Sustituir la URL por la del repositorio real del proyecto. Si el despliegue se hace desde una rama concreta:

```bash
git checkout main
```

---

## 3. Variables de entorno

El archivo `.env` **no se copia** dentro de la imagen (`.dockerignore`). Compose lo carga con `env_file: .env`.

### 3.1. Variables recomendadas en VM

| Variable | Obligatoria | Descripción |
|----------|-------------|-------------|
| `SECRET_KEY` | **Sí en Internet** | Firma de cookies Flask (`openssl rand -hex 32`) |
| `GROQ_API_KEY` | No | Análisis IA y resúmenes; sin ella el honeypot funciona |
| `GROQ_MODEL` | No | Por defecto `openai/gpt-oss-20b` |
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` / `TELEGRAM_TOPIC_*` | Para 2FA SOC | Topics Logins, Ataques, Resumen |
| `REDIS_URL` | Compose la fija | `redis://redis:6379/0` en red interna |
| `CARTO_API_KEY` | No | Mapa SOC (teselas `?key=`) |
| `INITIAL_SOC_USERNAME` / `INITIAL_SOC_PASSWORD` | **Sí con STRICT** | Cuenta al crear `flypaper_priv.db` |
| `FLYPAPER_STRICT_DEPLOY=1` | Recomendado VM | Exige `INITIAL_SOC_PASSWORD` (sin default débil) |
| `FLYPAPER_ALLOW_SOC_RECOVERY=0` | Recomendado VM | Desactiva reset de password por Telegram |
| `ABUSEIPDB_API_KEY` / `VIRUSTOTAL_API_KEY` | No | Reputación perimetral |
| `ANTHROPIC_API_KEY` | No | Legacy / opcional; el analizador activo es **Groq** |

Crear `.env` en el servidor:

```bash
cd ~/FlyPaper
cp .env.example .env
nano .env
```

Ejemplo mínimo VM:

```env
SECRET_KEY=cambia_esto_con_openssl_rand_hex_32
INITIAL_SOC_USERNAME=Flypaper
INITIAL_SOC_PASSWORD=TuPasswordFuerte12!
FLYPAPER_STRICT_DEPLOY=1
FLYPAPER_ALLOW_SOC_RECOVERY=0
GROQ_API_KEY=gsk_xxxxxxxx
TELEGRAM_BOT_TOKEN=...
TELEGRAM_CHAT_ID=...
TELEGRAM_TOPIC_LOGINS=...
TELEGRAM_TOPIC_ATAQUES=...
TELEGRAM_TOPIC_RESUMEN=...
```

Compose ya define `REDIS_URL=redis://redis:6379/0` y monta `./data:/app/data`.

### 3.2. Persistencia y sesión

- **SQLite**: bajo `FLYPAPER_DATA_DIR` (`/app/data` en contenedor).
- **Redis**: volumen Docker `flypaper-redis-data` (bloqueos / rate-limit / riesgo).
- **Zona horaria**: `Europe/Madrid` (`tzdata`).

### 3.3. Credenciales SOC (bootstrap)

| Ámbito | Comportamiento |
|--------|----------------|
| Primer arranque + BD privada vacía | Crea una cuenta `admin_panel` con `INITIAL_SOC_*` o, en lab sin STRICT, `Flypaper` / `Flypaper_123` |
| Tras 2FA | Obligatorio cambiar usuario y contraseña en `/admin/cambiar-password` |
| Portal CTF | Cuentas registradas por alumnos; demos locales vía `scripts/preparar_cuenta_demo.py` |

**No** uses el bootstrap de laboratorio en un VPS expuesto sin `FLYPAPER_STRICT_DEPLOY=1`.

---

## 4. Despliegue paso a paso

### Paso 1 — Revisar configuración de red

El servicio publica el puerto **5000** del contenedor en el **5000** del host (`docker-compose.yml`):

```yaml
ports:
  - "5000:5000"
```

Abrir el puerto en el firewall del VPS si se usa `ufw`:

```bash
sudo ufw allow OpenSSH
sudo ufw allow 5000/tcp
sudo ufw enable
sudo ufw status
```

En el panel de **Hetzner Cloud**, comprobar también que el **firewall del cloud** (si está activo) permita tráfico entrante TCP/5000 hacia la IP del servidor.

### Paso 2 — Construir la imagen y levantar el contenedor

Desde la raíz del proyecto:

```bash
cd ~/FlyPaper
docker compose up --build -d
```

Qué hace este comando:

1. Construye la imagen `flypaper:latest` según el `Dockerfile` (Python 3.11-slim, dependencias de `requirements.txt`, Gunicorn ≥ 22).
2. Crea el contenedor `flypaper` con política `restart: unless-stopped`.
3. Ejecuta Gunicorn:

   ```text
   gunicorn --bind 0.0.0.0:5000 --workers 1 --threads 4 app:aplicacion
   ```

   Un solo worker evita duplicar hilos de fondo del módulo; cuatro threads atienden peticiones concurrentes I/O.

### Paso 3 — Comprobar que el contenedor está en ejecución

```bash
docker compose ps
```

Salida esperada (estado **Up**):

```text
NAME       IMAGE              STATUS         PORTS
flypaper   flypaper:latest    Up X seconds   0.0.0.0:5000->5000/tcp
```

### Paso 4 — Revisar logs de arranque

```bash
docker compose logs -f flypaper
```

Indicadores de éxito:

- Proceso Gunicorn escuchando en `0.0.0.0:5000`.
- Sin tracebacks de Python al importar `app.py`.
- Tras la primera petición, creación o migración silenciosa de tablas SQLite.

Salir del seguimiento de logs: `Ctrl+C`.

---

## 5. Verificación del sistema

Sustituir `IP_DEL_SERVIDOR` por la IP pública del VPS (p. ej. la asignada por Hetzner).

### 5.1. Comprobaciones desde el propio servidor

```bash
# Respuesta HTTP del login público
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:5000/login

# Respuesta HTTP del login del monitor
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:5000/monitor/login

# Cabecera Server (Gunicorn)
curl -sI http://127.0.0.1:5000/login | head -n 5
```

**Resultado esperado:** código `200` en ambas rutas; el proceso escuchando en el puerto 5000.

### 5.2. Comprobaciones desde un navegador externo

| URL | Resultado esperado |
|-----|-------------------|
| `http://IP_DEL_SERVIDOR:5000/login` | Formulario de acceso corporativo FlyPaper |
| `http://IP_DEL_SERVIDOR:5000/search` | Buscador interno (rol Invitado o tras login) |
| `http://IP_DEL_SERVIDOR:5000/monitor/login` | Formulario de analista SOC |

Iniciar sesión en el monitor con `analyst` / `FlyPaper2026!` y comprobar que `/monitor` carga el dashboard con gráficas y tablas de actividad.

### 5.3. Verificar persistencia de bases de datos

Las bases se generan dentro del contenedor en `/app`:

```bash
docker exec flypaper ls -la /app/*.db
```

Deberían existir (tras el primer arranque):

- `flypaper.db` — eventos, usuarios públicos, CTF, registro de peticiones.
- `flypaper_priv.db` — cuentas `admin` y `analyst`.

**Importante:** al reconstruir el contenedor **sin volumen**, las bases se pierden salvo copia manual. Para respaldar:

```bash
docker cp flypaper:/app/flypaper.db ./flypaper.db.backup
docker cp flypaper:/app/flypaper_priv.db ./flypaper_priv.db.backup
```

### 5.4. Verificar registro de tráfico (honeypot activo)

Generar una petición de prueba y comprobar que el monitor la refleja:

```bash
curl "http://127.0.0.1:5000/search?q=test_despliegue"
```

En `/monitor`, la sección de actividad debería mostrar la IP del servidor (o la del cliente si se accede desde fuera).

### 5.5. Verificar analizador IA (opcional)

Solo si `ANTHROPIC_API_KEY` está definida:

```bash
docker exec flypaper printenv ANTHROPIC_API_KEY | head -c 10
```

Debe imprimir los primeros caracteres de la clave (no vacío). En el dashboard del monitor, usar una acción de análisis IA sobre un evento; debe devolver texto estructurado, no el mensaje «Falta ANTHROPIC_API_KEY».

---

## 6. Operación y mantenimiento

### Parar el servicio

```bash
cd ~/FlyPaper
docker compose down
```

### Reiniciar tras cambios en el código

```bash
git pull
docker compose up --build -d
```

### Ver uso de recursos

```bash
docker stats flypaper --no-stream
```

### Actualizar solo la variable de entorno

Editar `.env` o exportar la variable y recrear el contenedor:

```bash
docker compose up -d --force-recreate
```

---

## 7. Despliegue local (desarrollo, sin Docker)

Para pruebas en máquina de desarrollo sin contenedor:

```bash
cd FlyPaper
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Acceso: `http://localhost:5000`. El servidor integrado de Flask arranca con `debug=True`; **no usar este modo en producción**.

---

## 8. Consideraciones de producción

El repositorio incluye el mínimo necesario para un despliegue en VPS académico. Para un entorno expuesto de forma prolongada conviene:

1. **Proxy inverso** (Nginx o Caddy) con HTTPS delante del puerto 5000.
2. **No publicar** credenciales por defecto; modificar `asegurar_cuentas_privilegiadas()` o las filas en `flypaper_priv.db`.
3. **Copias de seguridad periódicas** de `flypaper.db` y `flypaper_priv.db`.
4. **Volumen Docker** montado en `/app` si se desea persistir datos entre recreaciones (evaluar implicaciones de mezclar código y BD).
5. Limitar acceso al **monitor** (`/monitor`) por IP o VPN; el honeypot público puede permanecer abierto.

---

## 9. Resolución de problemas

| Síntoma | Causa probable | Acción |
|---------|----------------|--------|
| `Connection refused` en puerto 5000 | Contenedor parado o firewall | `docker compose ps`; revisar `ufw` y firewall Hetzner |
| Contenedor reinicia en bucle | Error al importar `app.py` | `docker compose logs flypaper` |
| Monitor sin datos | BD recién creada; poco tráfico | Generar peticiones de prueba con `curl` |
| IA no responde | Falta `ANTHROPIC_API_KEY` | Configurar `.env` y `env_file` en compose |
| Pérdida de eventos tras `docker compose down` | SQLite efímera en contenedor | `docker cp` o volumen persistente |

---

## 10. Resumen de comandos

```bash
# Despliegue completo (servidor Linux)
git clone <URL_REPOSITORIO> && cd FlyPaper
echo 'ANTHROPIC_API_KEY=sk-...' > .env    # opcional
# Descomentar env_file en docker-compose.yml si se usa .env
docker compose up --build -d
docker compose ps
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:5000/login
docker compose logs --tail=50 flypaper
```

Con estos pasos, FlyPaper queda accesible en `http://IP_DEL_SERVIDOR:5000`, con Gunicorn sirviendo la aplicación Flask y SQLite inicializado automáticamente en el contenedor.
