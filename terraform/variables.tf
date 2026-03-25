# terraform/variables.tf

variable "subscription_id" {
  type    = string
  default = ""
}

variable "environment" {
  type    = string
  default = "dev"
  validation {
    condition     = contains(["dev", "prod"], var.environment)
    error_message = "environment must be 'dev' or 'prod'."
  }
}

variable "location" {
  type    = string
  default = "westeurope"
}

variable "log_analytics_workspace_id" {
  type    = string
  default = ""
}

variable "telegram_token" {
  type      = string
  sensitive = true
  default   = ""
}

variable "riot_api_key" {
  type      = string
  sensitive = true
  default   = ""
}

variable "telegram_chat_id" {
  type      = string
  sensitive = true
  default   = ""
}

variable "api_server_authorized_ip_ranges" {
  type    = list(string)
  default = []
}

variable "aks_admin_group_ids" {
  type    = list(string)
  default = []
}

variable "disk_encryption_set_id" {
  type    = string
  default = ""
}
