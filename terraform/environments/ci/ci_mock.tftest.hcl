# terraform/environments/ci/ci_mock.tftest.hcl
#
# Offline plan validation using Terraform 1.7+ mock_provider.
# No Azure credentials required — provider auth is fully bypassed.
#
# Usage (CI, no Azure access):
#   terraform init -backend=false
#   terraform test -filter=ci_mock.tftest.hcl -json
#
# The mock provider auto-generates computed attributes for every resource type.
# Only azurerm_client_config needs explicit defaults because keyvault/main.tf
# references its outputs to compute tenant_id and deployer_object_id.

mock_provider "azurerm" {
  mock_data "azurerm_client_config" {
    defaults = {
      tenant_id       = "00000000-0000-0000-0000-000000000000"
      object_id       = "00000000-0000-0000-0000-000000000000"
      client_id       = "00000000-0000-0000-0000-000000000000"
      subscription_id = "00000000-0000-0000-0000-000000000000"
    }
  }
}

run "ci_plan" {
  command = plan
}
