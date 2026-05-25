locals {
  common_tags = merge(var.tags, {
    project     = var.project_name
    environment = var.environment
    managedBy   = "hermes-azure-iac-agent"
  })
}

# Add Azure resources here. Keep secrets out of .tf files and tfvars.
# Prefer managed identities, Key Vault references, private networking, and explicit SKUs.
