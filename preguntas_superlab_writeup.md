================================================================================
  WRITEUP OFICIAL — SuperLab NexusCorp (FlyPaper · Academia CTF)
================================================================================

Objetivo del reto
-----------------
Completar una cadena ofensiva de 6 pasos (fases 0→5 en el motor de progreso)
simulando el compromiso de una empresa ficticia (NexusCorp). Debes obtener
5 flags en total; solo la última suma puntos en el ranking global de /objetivos.

  Checkpoint (sin puntos)     Flag
  -------------------------   ------------------------------------------
  Fase 1                      flag{fase1_credenciales_filtradas}
  Fase 2                      flag{fase2_control_acceso_roto}
  Fase 3                      flag{fase3_sqli_login}
  Fase 4                      flag{fase4_mensaje_correcto}
  Fase 5 (FINAL — 300 pts)    flag{fase5_final_cadena_completa}

Requisitos previos
------------------
  • Usa UN MISMO navegador (o la misma requests.Session en scripts) durante
    toda la cadena. El progreso (fase_actual, staging descubierto, flags) va
    ligado a la cookie de sesión Flask de FlyPaper.
  • Opcional pero recomendable: regístrate en el portal FlyPaper (/register)
    antes de empezar. Así, al obtener la flag final, se registra sola en
    objetivos_completados y sumas los 300 puntos en /objetivos.
  • Punto de entrada narrativo: /web-nexuscorp/  o la tarjeta SuperLab en
    /objetivos → «Entrar al SuperLab».

Mapa de rutas (referencia rápida)
---------------------------------
  Ruta                                      Qué es
  ----------------------------------------  --------------------------------
  GET  /robots.txt                          Pista fase 0
  GET  /web-nexuscorp/                      Portal corporativo (footer)
  GET  /web-nexuscorp/login                 Login final (fase 5)
  GET  /web-nexuscorp/panel-superlab        Panel tras completar cadena
  GET  /web-nexuscorp/panel-superlab/writeup  Este documento (solo si terminaste)
  GET  /web-nexuscorp-2.0/login             Portal legacy (fase 1)
  GET  /web-nexuscorp-2.0/panel             Tras login legacy
  GET  /web-nexuscorp-2.0/api/empleados     API sin autorización (fase 2)
  GET  /tools/fuzzer                        Fuzzer ffuf simulado (fase 3)
  *    /web-nexuscorp-2.0-staging/*         Oculto hasta fuzzer (fases 3–4)

================================================================================
  PASO 0 — Reconocimiento (fase 0 → preparación)
================================================================================

Qué debes hacer
  1. Abre en el navegador (o con curl):
       GET https://<tu-servidor>/robots.txt
  2. Lee la directiva Disallow. En FlyPaper verás:
       Disallow: /web-nexuscorp-2.0
  3. Refuerzo opcional: en /web-nexuscorp/ abre el código fuente y mira el
     footer HTML (comentario sobre migración legacy hacia /web-nexuscorp-2.0).

Qué demuestra
  Fuga de rutas “ocultas” vía robots.txt y comentarios HTML.

Comprobación
  Conoces la URL del portal legacy: /web-nexuscorp-2.0/login

================================================================================
  PASO 1 — Credenciales en código fuente (fase 1)
================================================================================

Qué debes hacer
  1. Navega a:
       GET /web-nexuscorp-2.0/login
  2. Ver código fuente de la página (Ctrl+U / Ver origen). NO basta con
     inspeccionar el DOM en DevTools: el secreto está en un comentario HTML.
  3. Localiza el comentario tipo:
       user: legacy_support / pass: Soporte2019!
  4. Envía el formulario POST con los campos exactos del formulario:
       usuario=legacy_support
       password=Soporte2019!
     (action: POST /web-nexuscorp-2.0/login)
  5. Tras login correcto serás redirigido a /web-nexuscorp-2.0/panel.

Flag obtenida
  flag{fase1_credenciales_filtradas}
  (visible en el panel legacy)

Progreso interno
  fase_actual pasa a 1.

Errores frecuentes
  • Usuario/contraseña con mayúsculas distintas (son sensibles a texto exacto).
  • No usar «Ver código fuente» y perder el comentario.

================================================================================
  PASO 2 — API sin control de acceso (fase 2)
================================================================================

Qué debes hacer
  1. Mantén la misma sesión (cookie) con la que hiciste login legacy.
  2. Solicita:
       GET /web-nexuscorp-2.0/api/empleados
  3. La API solo comprueba que exista sesión legacy; NO valida rol ni usuario
     concreto. Cualquier cuenta legacy autenticada puede leer el listado.

Respuesta esperada (JSON)
  • Campo "empleados": lista con nombre, usuario, estado (activo, vacaciones, baja…).
  • En la primera visita que avanza la fase, campo "flag":
      flag{fase2_control_acceso_roto}

Qué anotar para más adelante
  • Identifica a Marta Sánchez → usuario m.sanchez → estado "vacaciones".
    Es la cuenta objetivo del cierre de la cadena (paso 6).

Progreso interno
  fase_actual pasa a 2.

Errores frecuentes
  • Llamar a la API sin cookie de sesión → 403 JSON «Acceso no autorizado».
  • Abrir la API en ventana privada nueva sin repetir login legacy.

================================================================================
  PASO 3 — Descubrir staging con fuzzer simulado (entre fase 2 y 3)
================================================================================

Importante
  Hasta que NO ejecutes el fuzzer, cualquier URL bajo
  /web-nexuscorp-2.0-staging/ responde 404 genérico. El servidor marca en tu
  progreso staging_descubierto=1 solo tras un comando ffuf válido.

Qué debes hacer
  1. Desde el panel legacy, entra en /tools/fuzzer (enlace en el panel).
  2. Lee la wordlist mostrada en pantalla (incluye la entrada clave
     web-nexuscorp-2.0-staging).
  3. En el campo «comando», envía POST /tools/fuzzer con un comando que cumpla
     EXACTAMENTE este patrón (una línea, sin extras):
       ffuf -u https://web-nexuscorp-2.0.local/FUZZ -w wordlist.txt
     Variantes válidas: otro host en -u, otro nombre de diccionario en -w,
     siempre terminando en /FUZZ y con -w <archivo>.
  4. En la salida simulada busca una línea con Status: 200 y la palabra
     web-nexuscorp-2.0-staging.

Comprobación
  GET /web-nexuscorp-2.0-staging/login ya NO devuelve 404 de «staging oculto»;
  muestra el formulario de login staging.

Progreso interno
  staging_descubierto = true (no cambia fase_actual todavía).

Errores frecuentes
  • Comando sin /FUZZ al final de la URL → «Comando no reconocido».
  • Intentar SQLi en staging antes del fuzzer → siempre 404.

================================================================================
  PASO 4 — SQL Injection en login staging (fase 3)
================================================================================

Qué debes hacer
  1. Con staging ya visible:
       GET/POST /web-nexuscorp-2.0-staging/login
  2. Envía POST con concatenación clásica en el campo usuario:
       usuario=' OR 1=1--
       password=x          (cualquier valor; la consulta vulnerable lo concatena)
  3. Si el bypass encaja con la heurística del lab, entrarás en sesión staging.

Flag obtenida
  flag{fase3_sqli_login}
  (mostrada en la página de respuesta tras login exitoso)

Progreso interno
  fase_actual pasa a 3.

Siguiente enlace útil
  La propia respuesta suele enlazar a /web-nexuscorp-2.0-staging/mensajes

Errores frecuentes
  • Olvidar las comillas iniciales: ' OR 1=1--
  • Usar payload de UNION en lugar de bypass booleano (no es necesario aquí).

================================================================================
  PASO 5 — Mensaje con contraseñas provisionales (fase 4)
================================================================================

Qué debes hacer
  1. Con sesión staging activa (misma cookie):
       GET /web-nexuscorp-2.0-staging/mensajes
  2. En la bandeja, abre el mensaje de IT-Soporte sobre contraseñas temporales.
     URL directa:
       GET /web-nexuscorp-2.0-staging/mensajes/it-provisionales-incidente
  3. En el cuerpo verás una tabla markdown con columnas:
       Empleado | Usuario | Provisional
  4. Localiza la fila de Marta Sánchez (usuario m.sanchez) y copia el valor
     de la columna Provisional.

Flag obtenida
  flag{fase4_mensaje_correcto}
  (al abrir el mensaje it-provisionales-incidente por primera vez en tu progreso)

Progreso interno
  fase_actual pasa a 4.

Nota sobre la contraseña provisional
  • Se genera aleatoriamente al crear superlab.db (secrets.token_urlsafe).
  • NO está fija en el writeup: debes leerla del mensaje en TU instancia.
  • Formato típico: cadena alfanumérica de ~10–12 caracteres.

Errores frecuentes
  • Abrir mensajes sin sesión staging → redirección al login staging.
  • Usar contraseña de otro empleado en el paso 6 (solo m.sanchez en vacaciones
    completa el reto).

================================================================================
  PASO 6 — Login final en NexusCorp (fase 5 — FLAG DE RANKING)
================================================================================

Condiciones que el servidor exige (todas a la vez)
  1. fase_actual >= 4 en TU progreso SuperLab (misma cookie de siempre).
  2. Usuario: m.sanchez  (Marta Sánchez, estado vacaciones).
  3. Contraseña: password_provisional copiada del mensaje del paso 5.

Qué debes hacer
  1. Ve a:
       GET /web-nexuscorp/login
  2. POST al formulario corporativo:
       usuario=m.sanchez
       password=<provisional del mensaje IT>
  3. Si la cadena es correcta → redirección a:
       /web-nexuscorp/panel-superlab

Flag final (300 puntos en /objetivos si tienes login en FlyPaper)
  flag{fase5_final_cadena_completa}

Progreso interno
  fase_actual pasa a 5; flag final en flags_capturadas.

Si el login «funciona» pero NO hay flag
  • Mensaje «Sesión iniciada en NexusCorp (sin progreso de reto)» → fase < 4
    o usuario/contraseña correctos pero no es el escenario del reto.
  • Solución: repite pasos 3–5 en la misma sesión o revisa que sea m.sanchez.

Panel final
  • /web-nexuscorp/panel-superlab — timeline de la cadena y flags capturadas.
  • Puedes guardar una conclusión opcional (POST panel-superlab/conclusion).
  • Writeup completo (este documento en HTML):
      /web-nexuscorp/panel-superlab/writeup

================================================================================
  CHECKLIST DE COMPLETITUD
================================================================================

Marca cada ítem cuando lo tengas:

  [ ] robots.txt → ruta /web-nexuscorp-2.0 localizada
  [ ] Login legacy con legacy_support / Soporte2019!
  [ ] flag{fase1_credenciales_filtradas}
  [ ] GET /api/empleados con sesión legacy
  [ ] flag{fase2_control_acceso_roto}
  [ ] ffuf válido en /tools/fuzzer → staging visible
  [ ] SQLi staging ' OR 1=1--
  [ ] flag{fase3_sqli_login}
  [ ] Mensaje it-provisionales-incidente leído
  [ ] flag{fase4_mensaje_correcto}
  [ ] Provisional de m.sanchez anotada
  [ ] Login /web-nexuscorp/login con m.sanchez + provisional
  [ ] flag{fase5_final_cadena_completa}
  [ ] Panel /web-nexuscorp/panel-superlab accesible
  [ ] (Opcional) Puntos visibles en /objetivos tras login FlyPaper

================================================================================
  PISTAS OFICIALES (API in-game)
================================================================================

Solo si ya alcanzaste la fase pedida (fase_actual >= fase):

  POST /web-nexuscorp/api/pista
  Content-Type: application/json
  Body: {"fase": 0}   … hasta {"fase": 4}

Respuesta JSON: {"exito": true, "fase": N, "pista": "..."}

Textos de referencia (no sustituyen resolver el lab):
  • Fase 0: ficheros que el servidor expone a rastreadores (robots.txt).
  • Fase 1: secretos en código fuente HTML.
  • Fase 2: API que no comprueba identidad fina.
  • Fase 3: descubrir rutas con herramienta de fuzzing.
  • Fase 4: mensaje sobre contraseñas.

================================================================================
  RESOLUCIÓN AUTOMÁTICA (evidencia / profesorado)
================================================================================

Con el servidor FlyPaper en marcha y pip install requests:

  python tests/solve_superlab.py
  python tests/solve_superlab.py --base http://127.0.0.1:5000

El script reproduce la cadena completa en una sola Session, extrae la
provisional de m.sanchez del mensaje y valida las 5 flags.

Constantes fijas que usa el solver (excepto la provisional):
  LEGACY_USER = legacy_support
  LEGACY_PASS = Soporte2019!
  FFUF_CMD  = ffuf -u https://web-nexuscorp-2.0.local/FUZZ -w wordlist.txt
  SQLi_USER = ' OR 1=1--
  VACATION_USER = m.sanchez
  MSG_ID = it-provisionales-incidente

================================================================================
  RESUMEN DEFENSIVO (qué corregir en un entorno real)
================================================================================

  Paso   Fallo simulado                    Mitigación
  ----   ------------------------------    ---------------------------
  0      Rutas sensibles en robots.txt     Auth real; no confiar en oscuridad
  1      Credenciales en comentarios HTML  Secret manager; revisión CI/CD
  2      API sin RBAC                      Autorización por recurso y rol
  3      Staging expuesto / fuzzable       Inventario activos, WAF, DNS
  4      SQL por concatenación             Prepared statements / ORM
  5      Provisionales en correo claro     Cifrado, DLP, rotación inmediata
  6      Reuso de credenciales filtradas   MFA, caducidad, bloqueo incidente

================================================================================

FlyPaper · SuperLab NexusCorp · Uso académico · EVOLVE / máster ciberseguridad

Este writeup describe el comportamiento implementado en el código del proyecto
(app/superlab/, tests/solve_superlab.py). Si reinicias data/superlab.db, las
contraseñas provisionales cambiarán; las flags y la lógica de fases no.

================================================================================
