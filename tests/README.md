# Pruebas automatizadas — FlyPaper

Requisitos: aplicación escuchando (p. ej. `python app.py` o `docker compose up`) y
dependencias de `requirements.txt`. Opcional: Redis en `6379` para tests de NGWAF.

Desde la **raíz del repositorio**:

```bash
# Windows PowerShell
$env:PYTHONPATH = "."
# Linux/macOS
export PYTHONPATH=.

# Batería recomendada (unitarios + CTF HTTP + stress WAF opcional)
python scripts/ejecutar_pruebas_lab.py
# o demo completa:
python scripts/ejecutar_todo_demo.py
```

## Scripts individuales (`tests/`)

| Script | Qué comprueba |
|--------|----------------|
| `solve_ctf_auth.py` | Registro/login portal CTF |
| `solve_search.py` | Buscador `/search` |
| `solve_xss_01.py` | Lab XSS |
| `solve_idor_01.py` | Lab IDOR |
| `solve_pathtraversal_01.py` / `_02.py` | Labs Path Traversal |
| `verify_pt_sandbox.py` | Sandbox PT (opcional `--sin-http`) |
| `solve_superlab.py` | Cadena SuperLab |
| `solve_admin_auth.py` | Login SOC + onboarding |
| `solve_admin_panel.py` | Gestión cuentas SOC |
| `solve_admin_participantes.py` | Participantes CTF |
| `test_soc_stres.py` | Stress NGWAF (firmas, rate-limit, autoban) |

Ejemplos:

```bash
python tests/solve_xss_01.py
python tests/test_soc_stres.py --all
python scripts/forzar_resumen_ia.py --regenerar   # requiere GROQ_API_KEY
```

Variables útiles (`.env`): `FLYPAPER_TEST_USER`, `FLYPAPER_TEST_PASSWORD` si `/register` está rate-limited.
Cuenta demo: `python scripts/preparar_cuenta_demo.py`.
