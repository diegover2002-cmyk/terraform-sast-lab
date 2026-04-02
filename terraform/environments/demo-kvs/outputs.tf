# terraform/environments/demo-kvs/outputs.tf

output "rbac_keyvault_ids" {
  description = "IDs of the 6 RBAC-enabled Key Vaults."
  value       = { for k, v in azurerm_key_vault.rbac : k => v.id }
}

output "access_policy_keyvault_ids" {
  description = "IDs of the 4 access-policy Key Vaults."
  value       = { for k, v in azurerm_key_vault.access_policy : k => v.id }
}

output "all_keyvault_names" {
  description = "All 10 Key Vault names."
  value = concat(
    [for v in azurerm_key_vault.rbac : v.name],
    [for v in azurerm_key_vault.access_policy : v.name],
  )
}

output "resource_group_id" {
  value = azurerm_resource_group.demo.id
}
