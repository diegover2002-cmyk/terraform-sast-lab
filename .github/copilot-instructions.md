# GitHub Copilot Instructions

## Contexto del repositorio

PoC de pipeline de seguridad IaC para Terraform en Azure. Cada PR en módulos gold-tier
pasa por Checkov, tfsec y análisis semántico con Azure OpenAI contra controles MCSB.
El merge se bloquea automáticamente si hay misconfiguraciones no registradas como excepción.

## Fuentes de verdad

- **Controles de seguridad:** `controls/azure-{service}/controls.md`
  - Solo los controles con `Priority: Must` entran en el análisis IA
  - Controles sin regla Checkov son cubiertos **únicamente** por Azure OpenAI
- **Excepciones aprobadas:** `docs/compliance/exceptions-registry.json`
- **Lógica del análisis:** `.github/scripts/azure_openai_tf_check.py`
- **Pipeline CI/CD:** `.github/workflows/security-check.yml`

## Al sugerir código Terraform

- Aplica siempre la configuración segura por defecto para los módulos gold-tier
- Para `azurerm_storage_account`: `allow_nested_items_to_be_public = false`, `min_tls_version = "TLS1_2"`, `https_traffic_only_enabled = true`
- Para `azurerm_key_vault`: `soft_delete_retention_days >= 7`, `purge_protection_enabled = true`, `public_network_access_enabled = false`
- Para AKS: RBAC habilitado, nodos en subred privada, sin IPs públicas en el API server si es posible
- Si introduces una misconfiguración conocida (entorno de demo), documéntala con un comentario y registra la excepción

## Al modificar controls.md

- Mantén el formato de tabla: `Control ID | MCSB | Domain | Control Name | Severity | Priority | IaC Checkable | Checkov Rule`
- No cambies `Must` a `Should` sin revisión — desactiva el control del gate
- Incluye siempre ejemplo HCL insecure/secure en la sección detallada

## Al modificar exceptions-registry.json

- Cada excepción necesita: `id`, `status`, `resource`, `reason`, `expires_at`, `approved_by`, `policy_controls`
- `expires_at` es obligatorio — máximo 1 año desde la fecha de aprobación
- Usa `"MCSB-XX-X"` como alternativa a `CKV_AZURE_XXX` cuando el control no tenga regla Checkov

## Al modificar el script azure_openai_tf_check.py

- `MODULE_CONTROLS_MAP` define qué módulos son gold-tier y qué controles aplican — cualquier cambio afecta al gate
- El script hace `exit(1)` si `total_fails > 0` — no añadas `try/except` genéricos que lo silencien
- El prompt a OpenAI debe mantener la instrucción de responder solo con JSON array

## Convenciones

- IDs de control: `{SERVICIO}-{NNN}` (ST-001, KV-003, AK-012)
- IDs de excepción: `EXC-{NNN}` secuencial
- Commits: Conventional Commits (feat:, fix:, docs:, chore:)
- Ramas de demo: `demo/{descripcion-kebab-case}`
