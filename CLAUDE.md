# CLAUDE.md

Instrucciones obligatorias para este proyecto. Tienen prioridad sobre cualquier comportamiento por defecto.

## Lenguaje

- Python **3.14** exclusivamente.

## Plataformas

- La librería debe funcionar en **Windows, Linux y macOS**, tanto **x64** como **ARM**, en las últimas versiones de cada sistema. Nada específico de una plataforma (rutas, APIs, dependencias) sin alternativa multiplataforma.

## Dependencias

- **Un único fichero de dependencias**: nada de separar `requirements.txt` y `requirements-dev.txt`. Todas las dependencias (runtime y desarrollo) van juntas en un solo sitio.

## Diseño

- **Clean Code**: funciones pequeñas y con una sola responsabilidad, nombres descriptivos, sin código muerto, sin imports sin usar, sin bloques comentados.
- **Clean Architecture**: la lógica de dominio no depende de infraestructura, UI ni frameworks. Depender de abstracciones, no de implementaciones concretas. No filtrar detalles de implementación entre capas. No introducir abstracciones prematuras.

## Quality Gate

Antes de dar por buena cualquier tarea, todo esto debe pasar **sin ningún error ni warning**:

- `black --check .`
- `ruff check .`
- `mypy`

## Security Gate

También sin ningún error ni warning:

- `bandit -r src`
- `pip-audit`

`bandit` cubre solo `src`, en profundidad. **Los tests los cubre `ruff`**, cuyo `select` incluye `S` (flake8-bandit, 107 reglas) y que ya recorre `src` y `tests` en el comando de la Quality Gate. Por eso el Security Gate no nombra los tests: ya están escaneados arriba.

## Prohibiciones

- **Está prohibido silenciar un hallazgo.** Nada de `# noqa`, `# type: ignore`, `# nosec`, `--exit-zero` ni bajar la severidad para hacer pasar las gates. El código se arregla, no se silencia.
- **Acotar una regla al ámbito donde aplica sí se permite**, con dos condiciones: va en `pyproject.toml` (nunca inline en el código) y lleva escrita al lado la razón por la que no aplica ahí. Silenciar es esconder un hallazgo; acotar es decir que la regla no habla de ese fichero.
- Único acotado hoy: `S101` en `tests/*`. Avisa de que `assert` desaparece bajo `python -O`; un test es aserciones y nada aquí corre bajo `-O`. Las otras 106 reglas de seguridad sí aplican a los tests, y hasta ahora no tenían ninguna.

## Tests

- Tests de regresión y tests unitarios/de integración según corresponda.
- **Prohibido usar mocks** (nada de `unittest.mock`, `MagicMock`, `monkeypatch` ni stubs artificiales): los tests ejecutan código real.
- **Cobertura 100%** (`pytest --cov` con fallo por debajo del 100%).
- Antes de refactorizar debe existir cobertura del comportamiento actual.

## Git

- Hacer **commit y push en cada avance**.
- **No añadirse como co-author** en los commits (sin línea `Co-Authored-By`).
