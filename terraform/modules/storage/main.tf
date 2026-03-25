# terraform/modules/storage/main.tf
# Azure Storage Account — gold-tier module (MCSB-monitored).
# Managed by: terraform-sast-lab SAST pipeline.

#checkov:skip=CKV_AZURE_59:EXC-002 Storage network rules omitted — Function App Consumption plan (Y1) uses shared Azure infrastructure without VNet injection support. Access key stored in Key Vault. See docs/compliance/exceptions-registry.json.
#checkov:skip=CKV_AZURE_35:EXC-002 Same as CKV_AZURE_59 — network ACL Deny would block Function App runtime on Y1 plan.
resource "azurerm_storage_account" "main" {
  name                     = "stlolnotifier${var.environment}${var.suffix}"
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  min_tls_version                 = "TLS1_0"   # SAST-FAIL: ST-003 — must be TLS1_2
  allow_nested_items_to_be_public = true        # SAST-FAIL: ST-007 — public blob access
  https_traffic_only_enabled      = false       # SAST-FAIL: ST-002 — HTTP allowed
  shared_access_key_enabled       = true        # SAST-FAIL: ST-011 — SAS keys enabled

  blob_properties {
    delete_retention_policy {
      days = 7
    }
  }

  tags = var.tags
}

resource "azurerm_storage_share" "bot_data" {
  name                 = "lolnotifier-data"
  storage_account_name = azurerm_storage_account.main.name
  quota                = 1
}
