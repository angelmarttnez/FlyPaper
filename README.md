# FlyPaper — Honeypot Web con CTF y Monitor de Seguridad

FlyPaper es un honeypot web diseñado para atraer, registrar y analizar ataques en tiempo real. Simula un entorno corporativo vulnerable con panel de administración, blog, buscador interno y un sistema CTF con flags capturables. Incluye un dashboard privado para el analista de seguridad con análisis de payloads mediante inteligencia artificial.

Desarrollado como proyecto del Master en Ciberseguridad Avanzada EVOLVE 2026.

URL del proyecto: http://91.99.214.254:5000

---

## Stack Tecnologico

| Componente       | Tecnologia          | Version |
|------------------|---------------------|---------|
| Backend          | Python + Flask      | 3.11    |
| Base de datos    | SQLite              | 3.x     |
| Servidor WSGI    | Gunicorn            | 21.x    |
| Contenedor       | Docker + Compose    | 29.x    |
| IA / Analisis    | Claude (Anthropic)  | Sonnet 4|
| Frontend         | HTML + CSS + JS     | --      |
| Graficas         | Chart.js            | 4.x     |
| Infraestructura  | Hetzner Cloud CX22  | --      |

---

## Caracteristicas

- Superficie de ataque falsa: login corporativo, panel admin, buscador, blog, rutas seneuelo
- Vulnerabilidad SQLi intencionada en /search para el sistema CTF
- XSS almacenado en comentarios del blog
- Deteccion automatica de ataques: SQLi, XSS, Path Traversal, Fuerza Bruta, CSRF, Scanner
- Niveles de gravedad: CRITICO, ALTO, MEDIO, BAJO
- Dashboard privado con graficas, filtros y agrupacion por IP atacante
- Analisis de payloads con IA en lenguaje natural
- Resumen diario automatico generado por Claude
- Deteccion de anomalias en tiempo real
- Sistema CTF con flags capturables y ranking de participantes
- Exportacion forense en CSV y cabeceras HTTP estilo Wireshark
- Sistema de expulsion activa: bloqueo de IPs desde el monitor
- Despliegue con Docker en Hetzner Cloud

---

## Arquitectura

```
flypaper/
├── app.py               # Nucleo de la aplicacion, rutas y logica principal
├── detector.py          # Motor de clasificacion y deteccion de ataques
├── database.py          # Capa de acceso a datos y esquema relacional
├── ai_analyzer.py       # Modulo de inteligencia artificial con Claude
├── timezone_fp.py       # Gestion centralizada de zona horaria (Europe/Madrid)
├── Dockerfile           # Imagen Docker de produccion
├── docker-compose.yml   # Orquestacion de contenedores
├── requirements.txt     # Dependencias del proyecto
├── templates/           # Plantillas HTML
│   ├── login.html       # Portal de acceso corporativo falso
│   ├── admin.html       # Panel de administracion falso
│   ├── search.html      # Buscador vulnerable a SQLi
│   ├── blog.html        # Blog corporativo con XSS en comentarios
│   ├── post.html        # Vista de post individual con comentarios
│   ├── objetivos.html   # Sistema CTF con flags
│   ├── dashboard.html   # Dashboard del analista de seguridad
│   ├── monitor_login.html # Acceso al monitor
│   ├── usuarios.html    # Panel de usuarios
│   ├── configuracion.html # Configuracion falsa del sistema
│   ├── reportes.html    # Reportes de incidentes
│   └── expulsado.html   # Pagina de expulsion de IPs bloqueadas
└── assets/
    └── Cat.gif          # GIF de expulsion activa
```

---

## Instalacion en Local

### Requisitos previos
- Python 3.11 o superior
- Git
- Docker Desktop (para despliegue con contenedor)

### Pasos

```bash
# Clonar el repositorio
git clone https://github.com/angelmarttnez/FlyPaper.git
cd FlyPaper

# Instalar dependencias
pip install -r requirements.txt

# Crear el archivo de variables de entorno
# Crear un archivo .env en la raiz con:
# ANTHROPIC_API_KEY=sk-ant-tu-api-key

# Arrancar la aplicacion
python app.py
```

Verificar en el navegador:
- http://localhost:5000 — Login de FlyPaper
- http://localhost:5000/blog — Blog corporativo
- http://localhost:5000/monitor/login — Dashboard del analista

---

## Despliegue con Docker

```bash
# Construir la imagen
docker-compose build

# Arrancar en segundo plano
docker-compose up -d

# Verificar estado
docker-compose ps

# Ver logs en tiempo real
docker-compose logs -f
```

---

## Credenciales de Acceso

Las credenciales de acceso se proporcionan por canal privado al evaluador.

Aún así existe la posibilidad de acceder como invitado.

---

## Uso

### Cara publica (el atacante)

1. Acceder a la URL del proyecto
2. Explorar las rutas seneuelo: /.env, /backup, /config, /phpinfo, /wp-admin
3. Intentar SQL Injection en /search
4. Probar XSS en los comentarios del blog
5. Capturar flags en /objetivos

### Dashboard del analista

1. Acceder a /monitor/login con usuario analyst
2. Seleccionar el periodo de tiempo (Hoy, 7 dias, 30 dias...)
3. Revisar la tabla de IPs agrupadas y expandir para ver eventos
4. Usar el boton Analizar para obtener analisis IA de cada payload
5. Exportar evidencias en CSV o cabeceras HTTP
6. Bloquear IPs atacantes desde el panel

---

## Superficie de Ataque Simulada

| Ruta               | Tipo              | Vulnerabilidad                         |
|--------------------|-------------------|----------------------------------------|
| /login             | Interaccion activa| Deteccion de fuerza bruta              |
| /search            | Interaccion activa| SQLi real por concatenacion de strings |
| /blog              | Interaccion activa| XSS almacenado en comentarios          |
| /admin             | Reconocimiento    | Panel corporativo falso                |
| /.env              | Reconocimiento    | Credenciales falsas                    |
| /backup            | Reconocimiento    | JSON de backup falso                   |
| /config            | Reconocimiento    | XML de configuracion falso             |
| /phpinfo           | Reconocimiento    | Simulacion phpinfo()                   |
| /wp-admin          | Reconocimiento    | Simulacion WordPress                   |
| /objetivos         | CTF               | Flags capturables                      |

---

## Licencia

MIT License — angelmarttnez 2026