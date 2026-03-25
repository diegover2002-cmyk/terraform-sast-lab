# CLAUDE.md — Instrucciones para agentes IA

Este fichero define las fuentes de verdad, convenciones y límites para cualquier agente IA (Claude, Copilot, etc.) que trabaje en este repositorio.

## Qué es este repositorio

PoC de **pipeline de seguridad IaC** para Terraform en Azure.
Analiza automáticamente cada PR que modifique módulos Terraform críticos y **bloquea el merge** si detecta misconfiguraciones no justificadas.

Componentes principales:
- **Checkov** — análisis estático IaC sobre todos los módulos
- **tfsec** — reglas deterministas sobre módulos gold-tier
- **Azure OpenAI** — análisis semántico contra controles MCSB Must-priority
- **Gate enforcement** — falla el job y bloquea el merge si hay FAILs sin excepción

---

## Fuentes de verdad

| Fichero | Qué define | Quién puede modificarlo |
|---|---|---|
| `controls/azure-{service}/controls.md` | Controles MCSB por servicio (id, prioridad, regla Checkov) | Solo tras revisión de seguridad |
| `docs/compliance/exceptions-registry.json` | Excepciones aprobadas con fecha de expiración | Solo con justificación documentada |
| `.github/scripts/azure_openai_tf_check.py` | Lógica del análisis IA y mapeo módulo→controles | Cambios requieren revisar `MODULE_CONTROLS_MAP` |
| `.github/workflows/security-check.yml` | Pipeline completo (Checkov + tfsec + IA + gate) | Cambios afectan al gate de seguridad |

---

## Estructura del proyecto

```
.github/
  scripts/azure_openai_tf_check.py   # Script principal — lógica del análisis IA
  workflows/
    security-check.yml               # Pipeline unificado de seguridad (PRINCIPAL)
    codeql.yml                       # Análisis de código estático
    compliance-report.yml            # Reporte de cumplimiento periódico
    terraform.yml                    # Validación de formato Terraform

controls/
  azure-{service}/controls.md        # Controles MCSB por servicio
  MCSB-control-matrix.md             # Matriz completa de controles
  MCSB-service-control-catalog.md    # Catálogo de servicios

docs/compliance/
  exceptions-registry.json           # Registro de excepciones aprobadas

terraform/modules/
  storage/    # Azure Storage Account  ← gold-tier
  keyvault/   # Azure Key Vault        ← gold-tier
  aks/        # Azure Kubernetes Service ← gold-tier
```

---

## Módulos gold-tier

Solo estos tres módulos se someten al análisis completo (tfsec + IA):

| Módulo | Servicio | Controles MCSB |
|---|---|---|
| `terraform/modules/storage/` | Azure Storage Account | `controls/azure-storage/controls.md` |
| `terraform/modules/keyvault/` | Azure Key Vault | `controls/azure-key-vault/controls.md` |
| `terraform/modules/aks/` | Azure Kubernetes Service | `controls/azure-aks/controls.md` |

El mapeo está hardcodeado en `MODULE_CONTROLS_MAP` dentro del script. Si añades un nuevo módulo gold-tier, **debes actualizar ese diccionario** y crear su `controls.md`.

---

## Cómo añadir un nuevo módulo gold-tier

1. Crear `terraform/modules/{service}/main.tf` con la configuración segura por defecto
2. Crear `controls/azure-{service}/controls.md` siguiendo el formato existente (tabla + sección por control)
3. Añadir la entrada en `MODULE_CONTROLS_MAP` en `.github/scripts/azure_openai_tf_check.py`:
   ```python
   MODULE_CONTROLS_MAP = {
       ...
       "terraform/modules/{service}": "controls/azure-{service}/controls.md",
   }
   ```
4. Añadir el nombre legible en `MODULE_NAMES` en el mismo script

---

## Formato de controles (controls.md)

Cada fichero `controls.md` debe tener:
- Una tabla resumen con columnas: `Control ID | MCSB | Domain | Control Name | Severity | Priority | IaC Checkable | Checkov Rule`
- Una sección detallada por control con campos: MCSB, Severity, Priority, Applies, Justification, Checkov, tfsec
- Ejemplos HCL de configuración insegura y segura

**Solo los controles con `Priority: Must` entran en el análisis IA.**

Controles con `IaC Checkable: Partial` o sin regla Checkov (`Custom` / vacío) **solo están cubiertos por el análisis semántico de Azure OpenAI** — no por Checkov ni tfsec.

---

## Cómo registrar una excepción

Editar `docs/compliance/exceptions-registry.json` añadiendo una entrada en `registry[]`:

```jsonc
{
  "id": "EXC-00X",                          // ID único, incrementar
  "status": "active",                        // active | expired | revoked
  "resource": "nombre-recurso-azure",
  "resource_type": "azurerm_...",
  "reason": "Justificación clara y auditada",
  "expires_at": "YYYY-MM-DD",               // obligatorio, máximo 1 año
  "approved_by": "nombre@empresa.com",
  "policy_controls": [
    "CKV_AZURE_XXX",                        // ID de regla Checkov
    "MCSB-XX-X"                             // ID de control MCSB (alternativa)
  ]
}
```

El script carga este fichero en tiempo de ejecución. Las excepciones expiradas se ignoran automáticamente.

---

## Qué NO modificar sin revisión explícita

- `controls/azure-{service}/controls.md` — son la fuente de verdad de seguridad; cambiar prioridades de Must a Should desactiva controles
- `docs/compliance/exceptions-registry.json` — toda entrada nueva debe estar justificada y con fecha de expiración
- El step `Enforce security gate` en `security-check.yml` — es el mecanismo de bloqueo; desactivarlo anula el gate
- `MODULE_CONTROLS_MAP` en el script — un mapeo incorrecto deja módulos sin análisis

---

## Convenciones

- IDs de control: `{SERVICIO}-{NNN}` (ej. `ST-001`, `KV-003`, `AK-012`)
- IDs de excepción: `EXC-{NNN}` secuencial
- Prioridades MCSB: `Must` > `Should` > `Nice`
- Severidades: `High` > `Medium` > `Low`
- Commits: seguir Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`)

### Estrategia de ramas (GitFlow simplificado)

| Rama | Propósito | PR destino |
|---|---|---|
| `main` | Producción — solo releases | — |
| `develop` | Integración de features | `main` (release) |
| `feature/{descripcion}` | Nueva funcionalidad | `develop` |
| `fix/{descripcion}` | Corrección de bugs | `develop` |
| `chore/{descripcion}` | Mantenimiento / CI | `develop` |
| `demo/{descripcion}` | Demos del pipeline | `develop` |
| `release/{version}` | Preparación de release | `main` |

**Reglas:**
- **NUNCA** abrir PR directamente a `main` desde una rama de feature/fix/chore
- El workflow `validate-pr-target.yml` rechaza PRs a `main` que no vengan de `develop` o `release/*`
- El workflow `security-check.yml` solo corre en PRs a `develop`
- Para lanzar una release: PR de `develop` → `main`, con tag semver (`v1.0.0`)

---

## Variables de entorno requeridas

| Variable | Dónde | Para qué |
|---|---|---|
| `AZURE_API_KEY` | GitHub Secret | Autenticación con Azure OpenAI |

El endpoint y modelo están configurados en el script:
- Endpoint: `https://ai-openaidiego-pro.openai.azure.com/openai/responses`
- Modelo: `gpt-5.1-codex-mini`
