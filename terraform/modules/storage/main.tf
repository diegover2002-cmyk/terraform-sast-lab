# terraform/modules/storage/main.tf
# Azure Storage Account with a File Share for SQLite database persistence.
# SAST-TEST: intentionally insecure config — should trigger tfsec + checkov

#checkov:skip=CKV_AZURE_59:EXC-002 Storage network rules omitted — Function App Consumption plan (Y1) uses shared Azure infrastructure without VNet injection support. Access key stored in Key Vault. See docs/compliance/exceptions-registry.json.
#checkov:skip=CKV_AZURE_35:EXC-002 Same as CKV_AZURE_59 — network ACL Deny would block Function App runtime on Y1 plan.
resource "azurerm_storage_account" "main" {
  name                     = "stlolnotifier${var.environment}${var.suffix}"
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  min_tls_version                 = "TLS1_0"   # SAST-FAIL: ST-003 — should be TLS1_2
  allow_nested_items_to_be_public = true        # SAST-FAIL: public blob access enabled
  https_traffic_only_enabled      = false       # SAST-FAIL: HTTP allowed
  shared_access_key_enabled       = true

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
