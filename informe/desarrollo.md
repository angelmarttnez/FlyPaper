# Proceso de desarrollo

Este apartado describe la evolución del honeypot **FlyPaper** a lo largo del proyecto, las decisiones técnicas adoptadas y los principales obstáculos encontrados. La cronología se ha reconstruido a partir del historial de control de versiones (Git) y de la estructura actual del repositorio, que concentra la lógica en `app.py`, `database.py`, `detector.py`, `timezone_fp.py` y `ai_analyzer.py`, con plantillas Jinja2 en `templates/`.

## Metodología

El desarrollo siguió un enfoque **iterativo e incremental**: cada semana añadía una capa funcional sobre la anterior (interfaz falsa → persistencia → monitor → superficie de ataque ampliada → analítica avanzada → despliegue). Las versiones intermedias se conservaron en ficheros auxiliares (`app_old.py`, `database_old.py`, `detector_Old.py`, carpeta `malos/`) como referencia durante refactorizaciones, lo que facilitó comparar enfoques sin bloquear el avance del código principal.

Los commits del repositorio están etiquetados por semanas (`semana 1` … `semana 4`) y por hitos funcionales (`monitor avanzado`, `Dockerfile`), lo que permite alinear el informe con el calendario académico del módulo.

---

## Evolución por fases

### Semana 1 (8 de mayo de 2026): Web falsa y señuelos

**Commit:** `67386ad` — *feat: semana 1 - web falsa con login, admin y rutas señuelo*

Se estableció el **esqueleto del engaño**: aplicación Flask monolítica (`app.py`) con pantalla de login, panel de administración simulado y buscador interno (`templates/login.html`, `admin.html`, `search.html`). El objetivo era crear una fachada corporativa creíble antes de registrar o clasificar tráfico.

**Decisiones:** Flask como framework único (simplicidad, plantillas integradas, curva de aprendizaje baja). Separación inicial solo en capa de presentación (HTML/CSS embebido en plantillas).

---

### Semana 2 (8 de mayo de 2026): Persistencia y detección básica

**Commit:** `9eec3a3` — *feat: semana 2 - database.py, detector.py y logging integrado en todas las rutas*

Se extrajo la lógica transversal a dos módulos:

- **`database.py`**: creación de SQLite (`flypaper.db`), tabla `eventos` e inserción de registros.
- **`detector.py`**: clasificación heurística del tráfico (tipos de ataque, patrones de reconocimiento).

Se integró un hook **`after_request`** en Flask para capturar IP, ruta, método, payload, cabeceras y user-agent en cada petición, sin modificar el flujo visible para el atacante.

**Decisiones:** SQLite embebido (cero infraestructura externa, adecuado para laboratorio y despliegue en un solo contenedor). Registro **después** de generar la respuesta HTTP, de modo que la latencia percibida por el visitante no dependa del almacenamiento.

---

### Semana 3 (13 de mayo de 2026): Monitor SOC y panel admin

**Commits:** `8aa90d1`, `17e017d` — *dashboard monitor*, *detector real*, *APIs de estadísticas*

Se añadió el **panel de analista** (`/monitor`, `templates/dashboard.html`) con login independiente (`monitor_login.html`), rutas de administración (`/admin/usuarios`, `/admin/configuracion`) y APIs JSON para alimentar gráficas y tablas (`/monitor/api/stats`, `/monitor/api/eventos`).

En la misma línea temporal se reforzó **`detector.py`** con reglas más realistas (SQLi, XSS, escaneos, path traversal) y se incorporaron **filtros temporales** y agregaciones en el dashboard.

**Decisiones:** Monitor y honeypot público en la **misma aplicación Flask** pero con **sesión de analista** (`session["analyst"]`) distinta de la sesión del visitante. APIs REST internas para desacoplar la UI del procesamiento de datos y permitir refrescos periódicos sin recargar la página completa.

---

### Semana 4 (19 de mayo de 2026): Superficie de ataque, CTF y bloqueo de IP

**Commits:** `d138648`, `97b4f03` — *blog, objetivos, bloqueo IP*, *mejora CTF y BBDD*

Fue la fase de **mayor crecimiento funcional** (~6.300 líneas netas en un solo commit de la semana 4):

| Área | Contenido |
|------|-----------|
| **Blog** | Posts y comentarios (`blog.html`, `post.html`); comentarios volátiles en sesión para simular interacción sin contaminar la BD global. |
| **CTF** | Módulo `/objetivos` con flags dinámicas, tabla `flags` / `flags_resueltas` y reto SQLi orientado a UNION sobre la tabla pública `usuarios`. |
| **Seguridad reactiva** | Middleware `middleware_bloqueo_ip_y_actividad`, lista negra persistente (`ips_bloqueadas`), pantalla **`expulsado.html`** con respuesta HTTP 403 y recurso `/assets/Cat.gif`. |
| **Base de datos** | Ampliación masiva de `database.py` (usuarios seed, posts, flags, reportes). |

**Commit `97b4f03`:** introducción de **`flypaper_priv.db`** y tabla `usuarios_privados` para aislar credenciales de `/admin` y `/monitor` del vector SQLi del buscador — decisión crítica de diseño del reto.

**Decisiones:** Dos bases SQLite (pública vs. privada) para que el atacante pueda explotar SQLi en `usuarios` sin obtener cuentas reales del panel. Bloqueo por IP con **invalidación de token de sesión** asociado a la IP, no solo denegación en una ruta concreta.

---

### Cierre funcional (26 de mayo de 2026): Monitor avanzado, IA y cumplimiento

**Commit:** `1caf644` — *1º parte del proyecto completa - CTF básico, IA analyzer, monitor avanzado*

Consolidación de la **primera entrega completa** del proyecto:

- **`ai_analyzer.py`**: análisis de payloads y resúmenes diarios con **Anthropic Claude** (`ANTHROPIC_API_KEY` vía `.env`).
- **`timezone_fp.py`**: unificación de timestamps en **Europe/Madrid** para coherencia entre BD, gráficas y exportaciones.
- **Monitor ampliado**: tres paneles de actividad (eventos detectados, actividad pública, actividad de administración), correlación peticiones–alertas, exportación CSV/headers, modal de detalle con telemetría (usuario, sesión, tiempo de respuesta, puerto origen).
- **Escala de gravedad** de tres niveles (Crítica, Alta, Sospechoso) y **aislamiento de logs** de rutas `/admin` y `/monitor` en el panel de actividad administrativa.
- **Sesión pública** con expiración por inactividad (15 min) en `/search`, `/blog` y `/objetivos`.
- **Panel de reportes** (`/admin/reportes`) con clasificación opcional **NIS 2** y avisos normativos (RGPD, ISO 27001) en monitor y reportes.
- **Progreso CTF individual** por usuario (`objetivos_completados`) y control de acceso estricto a `/objetivos` (solo usuarios autenticados).

**Decisiones:** IA como capa **opcional** (degradación graceful si falta API key). Telemetría en `registro_peticiones` separada de alertas en `eventos` para soportar tráfico crudo y correlación posterior. Cumplimiento normativo como texto de auditoría en la UI, alineado con el rol “empresa” del honeypot.

---

### Despliegue (26 de mayo de 2026)

**Commit:** `42ddc1c` — *Dockerfile y docker-compose para despliegue en Hetzner*

Contenedorización con **`Dockerfile`** (Python 3.11-slim, Gunicorn) y **`docker-compose.yml`** para publicar el servicio en el puerto 5000. Se añadió **`.dockerignore`** para excluir secretos, bases de datos locales y artefactos de desarrollo del contexto de build.

**Decisión:** Gunicorn solo en Docker; en desarrollo local se mantiene el servidor integrado de Flask (`debug=True`), coherente con el flujo habitual del equipo.

---

## Decisiones técnicas transversales

| Decisión | Motivación |
|----------|------------|
| **Arquitectura monolítica Flask** | Un solo proceso despliega honeypot + monitor; reduce complejidad operativa en un TFG/laboratorio. |
| **SQLite dual (`flypaper.db` / `flypaper_priv.db`)** | Separar datos explotables (SQLi, CTF) de credenciales de analista y admin. |
| **`after_request` para logging** | Captura uniforme sin duplicar código en decenas de rutas; la respuesta al atacante se construye antes del registro. |
| **`detector.py` desacoplado** | Reglas de clasificación evolucionan sin tocar plantillas; facilita pruebas con payloads (`semana 4`). |
| **Middleware `before_request` para bloqueo** | Punto único de enforcement; exenciones explícitas para `/monitor` y assets. |
| **`timezone_fp.py`** | Evita ambigüedad UTC/local en gráficas y exportaciones forenses. |
| **Plantillas modulares** (`partials/`) | Navbar e inactividad compartidos entre `/search`, `/blog` y `/objetivos`. |

---

## Problemas encontrados y soluciones

### 1. Credenciales de admin expuestas vía SQLi

**Problema:** Si las cuentas del panel vivían en la misma tabla `usuarios` que el buscador vulnerable, el reto SQLi comprometía el monitor.

**Solución:** Migración a **`flypaper_priv.db`** (`usuarios_privados`), inaccesible desde la consulta UNION del buscador. Usuario señuelo del CTF (`SQLi_flag`) único en la tabla pública; purga de cuentas `admin` de la BD pública.

### 2. Doble registro de eventos (hook + vista)

**Problema:** `POST /search` podía generar entradas duplicadas si el hook global y la vista registraban el mismo ataque.

**Solución:** Función `omitir_registro_automatico_honeypot()` para excluir rutas con registro manual; la vista de búsqueda llama a `guardar_evento` con gravedad calculada explícitamente.

### 3. Mezcla de tráfico admin y alertas públicas en el monitor

**Problema:** Ataques contra `/admin` o `/monitor` aparecían en “Eventos detectados por IP”, ensuciando la vista del tráfico honeypot público.

**Solución:** Exclusión de rutas administrativas en consultas de `eventos` (`_sql_excluir_rutas_zona_admin`); dejar de insertar en `eventos` para esas rutas y centralizarlas en **Actividad de administración** (`registro_peticiones`, ámbito `admin`).

### 4. Progreso CTF compartido por IP

**Problema:** Varios usuarios detrás de la misma IP (NAT, laboratorio) compartían flags resueltas en `flags_resueltas`.

**Solución:** Tabla **`objetivos_completados`** keyed por `usuario_id`; acceso a `/objetivos` restringido a sesión autenticada (`requiere_autenticacion_objetivos`).

### 5. Timestamps inconsistentes

**Problema:** Mezcla de horas locales del sistema y criterios distintos en SQL/Python.

**Solución:** Módulo **`timezone_fp.py`** con zona fija `Europe/Madrid` y función `marca_ahora()` usada en toda la persistencia.

### 6. Análisis IA sin clave o con fallos de red

**Problema:** El monitor no debe bloquearse si Claude no está disponible.

**Solución:** Respuestas por defecto en `ai_analyzer.py` y comprobación de `ANTHROPIC_API_KEY`; endpoints de IA devuelven mensajes controlados sin tumbar el dashboard.

### 7. Despliegue en servidor remoto (Hetzner)

**Problema:** Entorno de desarrollo (`flask run`, debug) inadecuado para producción.

**Solución:** Imagen Docker con **Gunicorn** (1 worker, 4 threads) para evitar duplicar el hilo de fondo del módulo; `docker-compose` con variable opcional para la API de IA.

---

## Estructura actual del código (referencia)

```
FlyPaper/
├── app.py              # Rutas Flask, middleware, APIs /monitor, hooks de logging
├── database.py         # Esquema SQLite, migraciones, consultas del monitor y CTF
├── detector.py         # Clasificación de ataques y escala de gravedad
├── timezone_fp.py      # Hora Europe/Madrid para BD y UI
├── ai_analyzer.py      # Integración Claude (payload, resumen diario, anomalías)
├── requirements.txt    # flask, python-dotenv, anthropic, tzdata
├── Dockerfile / docker-compose.yml
├── assets/             # Recursos estáticos (p. ej. Cat.gif)
└── templates/          # Vistas honeypot, monitor, admin, reportes, partials/
```

El proyecto evolucionó de un **prototipo de login falso** (~900 líneas iniciales) a un **honeypot instrumentado** con panel SOC, reto CTF, bloqueo reactivo, exportación forense, analítica asistida por IA y contenedor de despliegue, manteniendo en todo momento un único repositorio y un historial Git alineado con las entregas semanales del módulo.
