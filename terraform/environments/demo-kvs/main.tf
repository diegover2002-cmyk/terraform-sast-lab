# terraform/environments/demo-kvs/main.tf
#
# 10 Azure Key Vaults split across two authorization models:
#
#   RBAC (6 KVs)           — enable_rbac_authorization = true
#                            MI access via azurerm_role_assignment (Key Vault Secrets User)
#
#   Access Policies (4 KVs) — enable_rbac_authorization = false (legacy model)
#                              MI access via access_policy block
#
# All KVs share: soft-delete 7 days, purge protection ON, standard SKU.
# Network: default_action = Allow (MI may run from dynamic IPs).
# =============================================================================

data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "demo" {
  name     = var.resource_group_name
  location = var.location
  tags     = var.tags
}

# ── Local config tables ───────────────────────────────────────────────────────

locals {
  # Indices for the two groups
  rbac_indices = toset(["01", "02", "03", "04", "05", "06"])
  ap_indices   = toset(["01", "02", "03", "04"])
}

# =============================================================================
# GROUP A — RBAC Key Vaults (6)
# Authorization: Azure RBAC roles on the data plane (recommended model).
# MI gets "Key Vault Secrets User" via azurerm_role_assignment.
# =============================================================================

#checkov:skip=CKV_AZURE_109:demo environment — dynamic runner IPs prevent IP allowlist. RBAC-only auth is the compensating control.
#checkov:skip=CKV_AZURE_189:demo environment — same rationale as CKV_AZURE_109.
resource "azurerm_key_vault" "rbac" {
  for_each = local.rbac_indices

  name                = "kv-${var.suffix}-rb${each.key}"
  location            = azurerm_resource_group.demo.location
  resource_group_name = azurerm_resource_group.demo.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  soft_delete_retention_days = 7
  purge_protection_enabled   = true
  enable_rbac_authorization  = true

  network_acls {
    default_action = "Allow"
    bypass         = "AzureServices"
  }

  tags = merge(var.tags, { auth-model = "rbac", index = each.key })
}

# MI access: Key Vault Secrets User (read secrets, no management plane)
resource "azurerm_role_assignment" "mi_secrets_user_rbac" {
  for_each = azurerm_key_vault.rbac

  scope                = each.value.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = var.mi_object_id
}

# Deploying identity (SP / user running terraform) gets Secrets Officer on all RBAC KVs
resource "azurerm_role_assignment" "deployer_secrets_officer_rbac" {
  for_each = azurerm_key_vault.rbac

  scope                = each.value.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

# =============================================================================
# GROUP B — Access Policy Key Vaults (4)
# Authorization: legacy vault access policies (pre-RBAC model).
# MI gets Get+List+Set secret permissions via access_policy block.
# Note: enable_rbac_authorization = false is the default — shown explicitly here.
# =============================================================================

#checkov:skip=CKV_AZURE_109:demo environment — dynamic runner IPs prevent IP allowlist.
#checkov:skip=CKV_AZURE_189:demo environment — same rationale as CKV_AZURE_109.
resource "azurerm_key_vault" "access_policy" {
  for_each = local.ap_indices

  name                = "kv-${var.suffix}-ap${each.key}"
  location            = azurerm_resource_group.demo.location
  resource_group_name = azurerm_resource_group.demo.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  soft_delete_retention_days = 7
  purge_protection_enabled   = true
  enable_rbac_authorization  = false # access policies (legacy)

  network_acls {
    default_action = "Allow"
    bypass         = "AzureServices"
  }

  # Managed Identity access
  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = var.mi_object_id

    secret_permissions = [
      "Get",
      "List",
      "Set",
      "Delete",
      "Recover",
      "Backup",
      "Restore",
    ]
  }

  # Deploying identity (SP / user running terraform) — full access to manage secrets
  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    secret_permissions = [
      "Get",
      "List",
      "Set",
      "Delete",
      "Recover",
      "Backup",
      "Restore",
      "Purge",
    ]
  }

  tags = merge(var.tags, { auth-model = "access-policy", index = each.key })
}
