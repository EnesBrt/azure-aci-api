variable "subscription_id" {
  description = "Azure subscription ID targeted by this deployment. Must match the reviewed and approved scope. Not a secret."
  type        = string
}

variable "tenant_id" {
  description = "Optional Azure tenant ID. Set when the approved scope requires a specific tenant. Not a secret."
  type        = string
  default     = null
  nullable    = true
}

variable "location" {
  description = "Azure region for all regional resources."
  type        = string
}

variable "project_name" {
  description = "Short project or workload name used for naming resources."
  type        = string
}

variable "environment" {
  description = "Deployment environment, for example dev, test, staging, or prod."
  type        = string
}

variable "tags" {
  description = "Common tags applied to resources."
  type        = map(string)
  default     = {}
}
