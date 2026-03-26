# terraform/modules/keyvault/variables.tf

variable "resource_group_name" { type = string }
variable "location"            { type = string }
variable "environment"         { type = string }
variable "suffix"              { type = string }
variable "tags"                { type = map(string) }
variable "log_analytics_workspace_id" { type = string }

# Optional overrides — allow callers to supply tenant/deployer IDs directly
# (e.g. CI plan generation) so that data.azurerm_client_config is not invoked
# and no real Azure API call is made during terraform plan.
variable "tenant_id" {
  description = "Azure tenant ID. If null, resolved via data.azurerm_client_config.current (requires ARM credentials)."
  type        = string
  default     = null
}

variable "deployer_object_id" {
  description = "Object ID of the deploying identity (user/SP/MI). If null, resolved via data.azurerm_client_config.current."
  type        = string
  default     = null
}

variable "telegram_token" {
  type      = string
  sensitive = true
}

variable "riot_api_key" {
  type      = string
  sensitive = true
}

variable "telegram_chat_id" {
  type      = string
  sensitive = true
}

variable "cosmosdb_connection_string" {
  description = "CosmosDB primary connection string — stored as a Key Vault secret"
  type        = string
  sensitive   = true
  default     = ""  # Empty until cosmosdb module is applied first
}
