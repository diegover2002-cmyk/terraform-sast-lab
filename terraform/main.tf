# terraform/main.tf
# Root config for the SAST lab — exercises storage, keyvault, and aks modules.

terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.100"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
  backend "azurerm" {}
}

provider "azurerm" {
  subscription_id = var.subscription_id
  features {}
}

resource "random_string" "suffix" {
  length  = 4
  upper   = false
  special = false
}

resource "azurerm_resource_group" "main" {
  name     = "rg-sast-lab-${var.environment}"
  location = var.location
  tags     = local.common_tags
}

module "storage" {
  source              = "./modules/storage"
  resource_group_name = azurerm_resource_group.main.name
  location            = var.location
  environment         = var.environment
  suffix              = random_string.suffix.result
  tags                = local.common_tags
}

module "keyvault" {
  source              = "./modules/keyvault"
  resource_group_name = azurerm_resource_group.main.name
  location            = var.location
  environment         = var.environment
  suffix              = random_string.suffix.result
  tags                = local.common_tags
  log_analytics_workspace_id = var.log_analytics_workspace_id
  telegram_token             = var.telegram_token
  riot_api_key               = var.riot_api_key
  telegram_chat_id           = var.telegram_chat_id
}

module "aks" {
  source              = "./modules/aks"
  resource_group_name = azurerm_resource_group.main.name
  location            = var.location
  environment         = var.environment
  tags                = local.common_tags
  log_analytics_workspace_id    = var.log_analytics_workspace_id
  api_server_authorized_ip_ranges = var.api_server_authorized_ip_ranges
  aks_admin_group_ids             = var.aks_admin_group_ids
  disk_encryption_set_id          = var.disk_encryption_set_id
}

locals {
  common_tags = {
    project     = "sast-lab"
    environment = var.environment
    managed_by  = "terraform"
  }
}
