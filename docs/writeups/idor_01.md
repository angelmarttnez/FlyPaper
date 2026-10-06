# Writeup — IDOR-01 · Nóminas (FlyPaper Academia)

**Flag:** `flag{idor_nomina_ajena}` · **Puntos:** 80 · **Ruta del lab:** `/objetivos/idor/01`

---

## Objetivo

Explotar un **Insecure Direct Object Reference**: el endpoint de nóminas exige sesión del reto pero **no** comprueba que el `id` solicitado sea el asignado a tu usuario.

---

## Requisitos

1. Sesión activa en el portal FlyPaper.

---

## Paso a paso

### 1. Iniciar el reto

- **GET** `/objetivos/idor/01`
- El servidor te asigna una nómina propia (ID entre 2 y 6) y la guarda en sesión.
- La UI muestra “tu” número de nómina.

### 2. Consultar tu nómina (opcional)

- **GET** `/objetivos/idor/01/nomina/<tu_id>`
- Debe mostrar datos ficticios de tu empleado.

### 3. IDOR — nómina ajena

- **GET** `/objetivos/idor/01/nomina/1`
- El ID **1** corresponde al director financiero; el importe es la flag.
- También puedes usar `?json=1` para respuesta JSON con campo `flag`.

### 4. Verificar ranking

- En `/objetivos` la tarjeta IDOR debe aparecer como **RESUELTO** y sumar 80 pts.

---

## Resolución automática (evidencia)

```bash
python tests/solve_idor_01.py --base http://127.0.0.1:5000
```

---

## Errores frecuentes

| Síntoma | Causa |
|--------|--------|
| Redirección a `/objetivos/idor/01` | No visitaste el reto antes (sesión IDOR no iniciada) |
| 404 nómina | ID inexistente (válidos 1–6) |

---

## Mitigación (Blue Team)

- Autorización por objeto: `nomina_id` debe pertenecer al usuario autenticado.
- Identificadores opacos (UUID) y comprobación server-side en cada lectura.
- Auditoría de accesos a datos HR/financieros.
