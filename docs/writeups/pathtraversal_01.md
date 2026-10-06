# Writeup — PT-01 · Path Traversal (FlyPaper Academia)

**Flag:** `flag{path_traversal_informes}` · **Puntos:** 110 · **Ruta del lab:** `/objetivos/pathtraversal/01`

---

## Objetivo

Abusar del parámetro `file` en la descarga de informes para leer `archivos_secretos/flag.txt` **dentro** del módulo del lab, sin escapar del sandbox `app/ctf_pathtraversal/`.

---

## Requisitos

1. Sesión activa en el portal FlyPaper.

---

## Paso a paso

### 1. Entrar al lab

- **GET** `/objetivos/pathtraversal/01`

### 2. Descarga legítima (opcional)

- **GET** `/objetivos/pathtraversal/01/descargar?file=informe_q1.txt`
- Confirma que solo se sirven ficheros bajo `archivos/`.

### 3. Path traversal dentro del módulo

- **GET** `/objetivos/pathtraversal/01/descargar?file=../archivos_secretos/flag.txt`
- El servidor concatena `archivos/` + `file` **sin** eliminar `..`, luego aplica `resolve()` y comprueba que la ruta sigue bajo la raíz del módulo.
- El cuerpo incluye la flag; se registra en el ranking CTF.

---

## Payloads que deben fallar (sandbox)

Estos **no** deben leer ficheros fuera del lab:

- `../../../etc/passwd`
- `../../../../app.py`
- Rutas absolutas hacia el sistema

Comprobación local:

```bash
python tests/solve_pathtraversal_01.py --solo-sandbox
```

---

## Resolución automática (evidencia)

```bash
python tests/solve_pathtraversal_01.py --base http://127.0.0.1:5000
```

---

## Mitigación (Blue Team)

- Usar APIs que acepten **nombre base** (basename) y whitelist de ficheros.
- `realpath` + comprobar prefijo permitido (como en este lab, pero sin la concatenación vulnerable previa).
- Separar almacenamiento público y secretos (no compartir árbol con `..` accesible).
