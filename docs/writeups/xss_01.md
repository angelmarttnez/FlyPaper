# Writeup — XSS-01 · Almacenado (FlyPaper Academia)

**Flag:** `flag{xss_almacenado_admin}` · **Puntos:** 110 · **Ruta del lab:** `/objetivos/xss/01`

---

## Objetivo

Enviar un comentario con XSS almacenado que el **bot moderador** considere explotable, simular el robo de cookie y registrar la flag en tu progreso CTF.

El bot **no ejecuta JavaScript real**: valida que el comentario contenga `<script` y la ruta `/objetivos/xss/01/robo-cookie`.

---

## Requisitos

1. Sesión activa en el portal FlyPaper (`/login` o `/register`).
2. Misma cookie de sesión durante todo el flujo.

---

## Paso a paso

### 1. Entrar al lab

- Abre **GET** `/objetivos/xss/01` (desde `/objetivos` → categoría XSS → *Iniciar lab*).

### 2. Publicar el payload

- **POST** `/objetivos/xss/01/comentario` con JSON o formulario:
  - Campo `contenido` con un script que referencie la ruta de robo, por ejemplo:

```html
<script>document.location='/objetivos/xss/01/robo-cookie'</script>
```

- La respuesta JSON incluye `token_robo`: guárdalo (simula la exfiltración que haría el admin).

### 3. Disparar la revisión del bot

- **POST** `/objetivos/xss/01/admin-revisar`
- El servidor marca tu comentario como revisado y explotable si cumple los patrones.

### 4. Completar el robo simulado

- **GET** `/objetivos/xss/01/robo-cookie?token=<token_robo>`
- Debe ser el token del comentario malicioso y el mismo usuario que lo publicó.
- Respuesta: flag y registro en `objetivos_completados` (ranking).

---

## Resolución automática (evidencia)

```bash
python tests/solve_xss_01.py --base http://127.0.0.1:5000
```

---

## Errores frecuentes

| Síntoma | Causa |
|--------|--------|
| 401 en comentario | Sin login en el portal |
| 403 en robo-cookie | Bot no revisó aún, token ajeno o payload sin `<script` + ruta robo |
| Flag no en ranking | Usuario no registrado en FlyPaper al resolver |

---

## Mitigación (Blue Team)

- Escapar/sanitizar salida HTML (context-aware encoding).
- CSP estricta; HttpOnly en cookies sensibles.
- No confiar en “bots” como único control: validar y almacenar contenido de forma segura.
