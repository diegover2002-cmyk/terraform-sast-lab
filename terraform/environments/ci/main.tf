# terraform/environments/ci/main.tf
# Minimal root module used exclusively for plan-level Checkov CI scanning.
# NOT for deployment — uses local backend and placeholder variable values.
# ARM credentials required to run: terraform plan.

locals {
  env    = "ci"
  suffix = "sast"
  tags   = { environment = "ci", managed-by = "terraform-sast-lab" }

  # Placeholder IDs used only to satisfy variable requirements for plan generation.
  # These are never deployed; the plan is only consumed by Checkov for static analysis.
  ci_workspace_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ci/providers/Microsoft.OperationalInsights/workspaces/law-ci"
}

resource "azurerm_resource_group" "ci" {
  name     = "rg-sast-ci"
  location = "westeurope"
  tags     = local.tags
}

# ── Storage (gold-tier) ───────────────────────────────────────────────────────

module "storage" {
  source = "../../modules/storage"

  resource_group_name = azurerm_resource_group.ci.name
  location            = azurerm_resource_group.ci.location
  environment         = local.env
  suffix              = local.suffix
  tags                = local.tags
}

# ── Key Vault (gold-tier) ─────────────────────────────────────────────────────

module "keyvault" {
  source = "../../modules/keyvault"

  resource_group_name        = azurerm_resource_group.ci.name
  location                   = azurerm_resource_group.ci.location
  environment                = local.env
  suffix                     = local.suffix
  tags                       = local.tags
  log_analytics_workspace_id = local.ci_workspace_id

  # Placeholder secrets — CI plan generation only, never deployed
  telegram_token             = "ci-placeholder"
  riot_api_key               = "ci-placeholder"
  telegram_chat_id           = "ci-placeholder"
  cosmosdb_connection_string = "ci-placeholder"
}

# ── AKS (gold-tier) ───────────────────────────────────────────────────────────

module "aks" {
  source = "../../modules/aks"

  resource_group_name        = azurerm_resource_group.ci.name
  location                   = azurerm_resource_group.ci.location
  environment                = local.env
  tags                       = local.tags
  log_analytics_workspace_id = local.ci_workspace_id

  # Minimal secure values for Checkov plan analysis
  api_server_authorized_ip_ranges = ["10.0.0.0/8"]
  aks_admin_group_ids             = ["00000000-0000-0000-0000-000000000000"]
  disk_encryption_set_id          = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ci/providers/Microsoft.Compute/diskEncryptionSets/des-ci"
}
