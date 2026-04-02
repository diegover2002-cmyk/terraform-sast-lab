# terraform/environments/demo-kvs/variables.tf

variable "resource_group_name" {
  description = "Resource group where the Key Vaults will be created."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
  default     = "westeurope"
}

variable "suffix" {
  description = "Short unique suffix included in Key Vault names (3-6 alphanumeric chars). KV names are globally unique — pick something distinctive."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9]{3,6}$", var.suffix))
    error_message = "suffix must be 3-6 lowercase alphanumeric characters."
  }
}

variable "mi_object_id" {
  description = "Object ID of the Managed Identity (or any principal) that receives read access to all 10 Key Vaults."
  type        = string
}

variable "tags" {
  description = "Tags applied to all resources."
  type        = map(string)
  default     = { environment = "demo", managed-by = "terraform-sast-lab" }
}
