terraform {
  required_version = ">= 1.5"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }

  # No remote backend — CI plan-level scan only, no state stored
  backend "local" {}
}

provider "azurerm" {
  features {}
  skip_provider_registration = true
}
