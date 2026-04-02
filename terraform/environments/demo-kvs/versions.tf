# terraform/environments/demo-kvs/versions.tf
# Demo environment: 10 Key Vaults — 6 RBAC, 4 access policies.
# State stored in Azure Blob Storage (backend config passed via -backend-config at init time).

terraform {
  required_version = ">= 1.5"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }

  backend "azurerm" {}
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy    = false
      recover_soft_deleted_key_vaults = true
    }
  }
  skip_provider_registration = true
}
