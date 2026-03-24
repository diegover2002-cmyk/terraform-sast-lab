# terraform-sast-lab

Standalone lab para el **pipeline SAST de Terraform** — Azure OpenAI + tfsec, catálogo MCSB, cross-reference de excepciones.

## Estructura

```
.github/
  workflows/
    azure-openai-tf-check.yml   # SAST principal (3 capas)
    terraform-pr.yml            # Plan/validate en PRs
    terraform.yml               # Apply en merge a main
    ci.yml                      # CI general
    codeql.yml                  # Análisis CodeQL
    compliance-report.yml       # Report MCSB
    release.yml                 # Release
  scripts/
    azure_openai_tf_check.py    # Script SAST
controls/
  azure-storage/controls.md    # Controles MCSB por servicio
  azure-key-vault/controls.md
  azure-aks/controls.md
  … (36 servicios)
  MCSB-control-matrix.md
terraform/modules/             # Gold-tier (vigilados por SAST)
  storage/   keyvault/   aks/
docs/compliance/
  exceptions-registry.json    # Waivers registrados
```

## Capas del pipeline SAST

| Capa | Herramienta | Qué detecta |
|---|---|---|
| 1 — Estático | tfsec | Violaciones de reglas deterministas |
| 2 — Semántico | Azure OpenAI | Gaps en controles MCSB Must-priority |
| 3 — Exception gate | Script | Cross-ref con exceptions-registry.json; FAIL→EXCEPTION si waiver activo |

## Secret requerido

`AZURE_API_KEY` — en **Settings → Secrets → Actions**.

## Trigger

Cualquier PR que modifique `terraform/modules/storage/**`, `terraform/modules/keyvault/**` o `terraform/modules/aks/**`.

## Probar el gate

Cambia `min_tls_version = "TLS1_2"` → `"TLS1_0"` en `terraform/modules/storage/main.tf` y abre una PR:

- tfsec: `🟠 HIGH`
- AI: `❌ FAIL` en ST-003
- Gate: `❌ Gate: BLOCKED — 1 FAIL`
- EXC-001/EXC-002: `🔵 EXCEPTION` (no bloquean)
