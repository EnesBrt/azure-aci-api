targetScope = 'resourceGroup'

@description('Azure region for all regional resources.')
param location string = resourceGroup().location

@description('Short project or workload name used for naming resources.')
param projectName string

@description('Deployment environment, for example dev, test, staging, or prod.')
param environment string

@description('Common tags applied to resources.')
param tags object = {
  project: projectName
  environment: environment
  managedBy: 'hermes-azure-iac-agent'
}

// Add resources here. Keep secrets out of parameters and templates.
// Prefer managed identities, Key Vault references, private networking, and explicit SKUs.

output deploymentLocation string = location
output deploymentEnvironment string = environment
