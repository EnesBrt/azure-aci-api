output "deployment_location" {
  description = "Azure region used by this deployment."
  value       = var.location
}

output "deployment_environment" {
  description = "Environment name used by this deployment."
  value       = var.environment
}
