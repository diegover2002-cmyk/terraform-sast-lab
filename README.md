# terraform-sast-lab

PoC de **pipeline de seguridad IaC** para Terraform en Azure.
Demuestra la detección automática de misconfiguraciones de infraestructura en Pull Requests mediante análisis estático + semántico con IA.

---

## Pipeline de seguridad

Cada PR que modifica los módulos gold-tier (`storage`, `keyvault`, `aks`) dispara el workflow `🔒 Terraform Security Check`, que genera **un único comentario** con dos capas de análisis:

```
┌─────────────────────────────────────────────────────────────┐
│              🔒 Terraform Security Report                    │
├─────────────────────────────────────────────────────────────┤
│  📋 Checkov IaC Scan                                        │
│     Análisis estático de todos los ficheros terraform/       │
│     Passed / Failed / Skipped (excepciones registradas)      │
├─────────────────────────────────────────────────────────────┤
│  🤖 AI Security Check (gold-tier modules)                   │
│     Layer 1 — tfsec: reglas deterministas (AVD-AZU-*)       │
│     Layer 2 — Azure OpenAI: controles MCSB Must-priority    │
│     Layer 3 — Exception gate: cross-ref exceptions-registry  │
│                                                             │
│     ❌ Gate: BLOCKED — N FAIL(s) → impide el merge          │
│     ✅ Gate: PASSED  → merge autorizado                     │
└─────────────────────────────────────────────────────────────┘
```

## Módulos gold-tier

| Módulo | Controles MCSB | Must-priority |
|---|---|---|
| `terraform/modules/storage` | ST-001 … ST-012 | 8 controles |
| `terraform/modules/keyvault` | KV-001 … KV-011 | 7 controles |
| `terraform/modules/aks` | AK-001 … AK-013 | 6 controles |

## Exception registry

Las excepciones de control registradas viven en `docs/compliance/exceptions-registry.json`.
Un finding marcado como `FAIL` por el AI check se degrada a `EXCEPTION` si el control tiene un waiver activo y no expirado.
Esto garantiza que solo se bloquea por riesgos **no reconocidos**.

## Probar el gate

```bash
# Crear rama de demo
git checkout -b demo/insecure-storage-config

# Introducir misconfiguraciones intencionadas
# en terraform/modules/storage/main.tf:
#   min_tls_version                 = "TLS1_0"
#   allow_nested_items_to_be_public = true
#   https_traffic_only_enabled      = false

git commit -am "test: introduce insecure storage config"
git push origin demo/insecure-storage-config
# Abrir PR → el pipeline bloquea el merge automáticamente
```

## Configuración

| Secret | Descripción |
|---|---|
| `AZURE_API_KEY` | API key del endpoint Azure OpenAI (`ai-openaidiego-pro.openai.azure.com`) |
| `ARM_CLIENT_ID` | Service Principal para terraform plan/apply |
| `ARM_CLIENT_SECRET` | |
| `ARM_SUBSCRIPTION_ID` | |
| `ARM_TENANT_ID` | |


---

## Lógica del script de análisis IA

> **Diagrama interactivo en FigJam:** [Abrir en FigJam](https://www.figma.com/online-whiteboard/create-diagram/f2a02b17-ef7f-4f0d-9cc2-72d9ab40f0ca?utm_source=claude&utm_content=edit_in_figjam)

El script `.github/scripts/azure_openai_tf_check.py` es el núcleo del sistema.
Orquesta tres fuentes de datos y toma la decisión de bloquear o aprobar el merge.

```mermaid
sequenceDiagram
  participant GHA as GitHub Actions
  participant Script as azure_openai_tf_check.py
  participant Exc as exceptions-registry.json
  participant Ctrl as controls/azure-{service}/controls.md
  participant TF as terraform/modules/{service}/main.tf
  participant TFSEC as tfsec-output.json
  participant AI as Azure OpenAI API
  participant Out as ai-check-output.txt

  GHA->>Script: python script.py --changed-files ... --tfsec-output ...

  Script->>Exc: load_exempt_controls()
  Exc-->>Script: set de IDs activos y no expirados

  loop for each changed gold-tier module
    Script->>Ctrl: extract_must_controls()
    Note over Ctrl: Parsea tabla markdown, filtra priority=Must
    Ctrl-->>Script: lista de controles (id, domain, severity, checkov rule)

    Script->>TF: open + read código fuente HCL
    TF-->>Script: string con el código .tf

    Script->>TFSEC: parse_tfsec_findings()
    TFSEC-->>Script: hallazgos filtrados por módulo

    Script->>AI: POST /openai/responses
system: prompt revisor
user: tabla controles + código HCL
    AI-->>Script: JSON array [{id, status, finding}]
PASS / FAIL / WARN / EXCEPTION

    Script->>Script: cruzar FAILs con exempt set
FAIL + excepción registrada -> EXCEPTION

    Script->>Script: acumular total_fails (solo FAILs sin excepción)
  end

  Script->>Out: escribir reporte markdown
+ banner Gate: PASSED / BLOCKED

  alt total_fails > 0
    Script->>GHA: exit(1) -> job falla -> merge BLOQUEADO
  else total_fails == 0
    Script->>GHA: exit(0) -> job OK -> merge PERMITIDO
  end
```

### Paso a paso

#### 1. Carga de excepciones aprobadas

Lo primero que hace el script es leer `docs/compliance/exceptions-registry.json` y construir un **set de identificadores exentos**.

```
exceptions-registry.json
└── registry[]
    ├── status: "active"          ← solo activas
    ├── expires_at: "2026-12-31"  ← no expiradas
    └── policy_controls[]
        ├── "CKV_AZURE_35"        ← ID de regla Checkov
        └── "MCSB-NS-2"           ← ID de control MCSB
```

Cualquier hallazgo que coincida con un ID del set **no cuenta como FAIL** — se marca como `🔵 EXCEPTION`.

---

#### 2. Identificar módulos gold-tier cambiados

El script recibe la lista de archivos modificados en el PR.
Solo procesa los tres módulos de máxima criticidad:

| Módulo modificado | Controles MCSB que se aplican |
|---|---|
| `terraform/modules/storage/` | `controls/azure-storage/controls.md` |
| `terraform/modules/keyvault/` | `controls/azure-key-vault/controls.md` |
| `terraform/modules/aks/` | `controls/azure-aks/controls.md` |

---

#### 3. Extracción de controles MCSB Must-priority

Por cada módulo, el script parsea su `controls.md` correspondiente.
El archivo contiene una tabla con todos los controles del servicio; el script **filtra solo los de prioridad `Must`** (los obligatorios).

```
controls/azure-storage/controls.md
└── tabla markdown
    ├── ST-001 | NS | High  | Must | Disable public blob access | CKV_AZURE_190
    ├── ST-002 | DP | High  | Must | Enforce TLS 1.2+           | CKV_AZURE_36
    ├── ST-003 | NS | Medium| Should | ...                       ← ignorado
    └── ...
```

El resultado es una lista estructurada con `id`, `domain`, `severity` y la regla Checkov asociada.

---

#### 4. Llamada a Azure OpenAI

Con el código HCL del módulo y la tabla de controles, el script construye un prompt y llama a **Azure OpenAI**:

- **System prompt:** instruye al modelo a actuar como revisor de seguridad Terraform, y a responder únicamente con un JSON array.
- **User prompt:** tabla de controles Must-priority + código `.tf` completo del módulo.

La respuesta esperada es:

```json
[
  { "id": "ST-001", "status": "PASS",  "finding": "allow_nested_items_to_be_public = false" },
  { "id": "ST-002", "status": "FAIL",  "finding": "min_tls_version = TLS1_0, should be TLS1_2" },
  { "id": "ST-003", "status": "WARN",  "finding": "network_rules not defined, defaults may be permissive" }
]
```

Cada control recibe uno de cuatro estados:

| Estado | Icono | Significado |
|---|---|---|
| `PASS` | ✅ | Control correctamente implementado |
| `FAIL` | ❌ | Control ausente o mal configurado |
| `WARN` | ⚠️ | Cumplimiento parcial o condicional |
| `EXCEPTION` | 🔵 | Anotación `checkov:skip` detectada en el código |

---

#### 5. Cruce con el registro de excepciones

Tras recibir los resultados de la IA, el script recorre cada `FAIL` y lo compara contra el **set de excepciones** cargado en el paso 1.

```
FAIL en ST-002 (CKV_AZURE_36)
    └── ¿CKV_AZURE_36 está en exempt set?
            ├── SÍ → estado cambia a EXCEPTION [registered exception: CKV_AZURE_36]
            └── NO → se mantiene FAIL → suma a total_fails
```

---

#### 6. Decisión de gate y salida

```
total_fails == 0  →  Gate: PASSED  →  exit(0)  →  merge PERMITIDO
total_fails  > 0  →  Gate: BLOCKED →  exit(1)  →  merge BLOQUEADO
```

El reporte completo se escribe en `ai-check-output.txt` y el workflow lo lee para:
1. **Enforce gate step:** si contiene `Gate: BLOCKED` → falla el job (`exit 1`)
2. **Post report step:** publica o actualiza el comentario unificado en el PR

## Estructura

```
.github/
  workflows/
    security-check.yml      # Pipeline principal — Checkov + tfsec + AI
    codeql.yml              # SAST de scripts Python
    compliance-report.yml   # Dashboard MCSB semanal (push a main)
    terraform.yml           # Apply en merge a main
  scripts/
    azure_openai_tf_check.py
controls/
  azure-storage/controls.md
  azure-key-vault/controls.md
  azure-aks/controls.md
  … (36 servicios Azure)
  MCSB-control-matrix.md
terraform/
  main.tf                   # Root config (providers + módulos)
  variables.tf
  modules/
    storage/   keyvault/   aks/
docs/compliance/
  exceptions-registry.json
```

---

## Arquitectura de la solución

> **Diagrama interactivo en FigJam:** [Abrir en FigJam](https://www.figma.com/online-whiteboard/create-diagram/3c2635d5-c1c6-47f3-b78e-8b5cdf4535e9?utm_source=claude&utm_content=edit_in_figjam)

```mermaid
flowchart LR
  PR(["Pull Request\nterraform/**"])

  subgraph GHA["GitHub Actions — Security Scan"]
    direction TB
    L1["Layer 1 — Checkov\nAnálisis estático IaC\nTodos los módulos"]
    L2["Layer 2 — tfsec\nReglas deterministas\nMódulos gold-tier"]
    L3["Layer 3 — Azure OpenAI\nAnálisis semántico\nvs controles MCSB Must"]
    EX[("exceptions-registry.json\nExcepciones aprobadas")]
    GATE{"Gate\ndecision"}
    ENFORCE["Enforce gate\nexit 1 si BLOCKED"]
    COMMENT["Comentario unificado\nen el PR"]
  end

  BP["Branch Protection\nRequiere: Security Scan OK"]
  PASS(["Merge\npermitido"])
  BLOCK(["Merge\nBLOCKEADO"])

  PR --> L1
  PR --> L2
  PR --> L3
  EX --> L3
  L3 --> GATE
  GATE -->|PASS| COMMENT
  GATE -->|BLOCKED| ENFORCE
  ENFORCE --> COMMENT
  L1 --> COMMENT
  L2 --> COMMENT
  COMMENT --> BP
  BP -->|check passed| PASS
  BP -->|check failed| BLOCK
```

### Flujo detallado

| Paso | Herramienta | Scope | Acción si falla |
|------|-------------|-------|-----------------|
| 1 | **Checkov** | Todos los archivos `terraform/` | Reporta en comentario (no bloquea solo) |
| 2 | **tfsec** | Módulos gold-tier (`storage`, `keyvault`, `aks`) | Reporta en comentario |
| 3 | **Azure OpenAI** | Módulos gold-tier | Emite veredicto `PASS` / `BLOCKED` |
| 4 | **Gate enforcement** | — | `exit 1` si el veredicto es `BLOCKED` |
| 5 | **Branch protection** | Rama `main` | Bloquea el merge hasta que `Security Scan` pase |

### Excepciones

Las excepciones conocidas y aceptadas se registran en `docs/compliance/exceptions-registry.json`.
El script de Azure OpenAI las carga antes de evaluar para evitar falsos positivos sobre riesgos ya gestionados.

