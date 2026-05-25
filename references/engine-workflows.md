# Azure IaC Engine Workflows

This reference expands the execution paths for Bicep, ARM JSON, Terraform, and OpenTofu.

## Shared Preflight

Before any validation, plan, or apply:

1. Confirm the intended environment: dev, test, staging, prod, or another explicit name.
2. Confirm Azure scope: tenant, management group, subscription, or resource group.
3. Confirm subscription and resource group names without exposing secrets.
4. Confirm that the active Azure identity is expected.
5. Confirm location, tags, naming prefix, and cost sensitivity.
6. Refuse to proceed if the operation depends on unknown secrets or unstated production impact.

Useful non-secret commands:

```bash
az account show --query '{name:name, subscriptionId:id, tenantId:tenantId, user:user.name}' -o json
az group show --name <resource-group> -o json
```

Do not print access tokens.

## Bicep Workflow

Bicep is the preferred Azure-native authoring format.

### Author

Create:

```text
main.bicep
parameters.<env>.json
parameters.<env>.bicepparam  # optional Bicep-native source; include in scan/hash if used
README.md
```

Use `targetScope` deliberately:

```bicep
targetScope = 'resourceGroup'
```

or:

```bicep
targetScope = 'subscription'
```

### Validate locally

```bash
bicep build main.bicep --outfile main.json
```

If `bicep` is managed through Azure CLI:

```bash
az bicep build --file main.bicep --outfile main.json
```

### Validate in Azure

Resource group:

```bash
az deployment group validate \
  --resource-group <resource-group> \
  --template-file main.json \
  --parameters @parameters.<env>.json
```

Subscription:

```bash
az deployment sub validate \
  --location <location> \
  --template-file main.json \
  --parameters @parameters.<env>.json
```

### Plan with What-If

Azure What-If is a real provider-side prediction, but it is **not** a replayable plan artifact. Save it as approval evidence and hash it with the template, parameters, scope, deployment name, and mode. If `.bicepparam` files are used during authoring, scan and hash them as source IaC too; the approval identity must also include the generated/used ARM parameter JSON or exact Azure CLI parameter input sent to What-If/apply.

Resource group:

```bash
mkdir -p ../../plans
az deployment group what-if \
  --name <deployment-name> \
  --resource-group <resource-group> \
  --template-file main.json \
  --parameters @parameters.<env>.json \
  --mode Incremental \
  --result-format FullResourcePayloads \
  --no-pretty-print \
  -o json > ../../plans/bicep-<env>-what-if.json
```

Subscription:

```bash
mkdir -p ../../plans
az deployment sub what-if \
  --name <deployment-name> \
  --location <location> \
  --template-file main.json \
  --parameters @parameters.<env>.json \
  --mode Incremental \
  --result-format FullResourcePayloads \
  --no-pretty-print \
  -o json > ../../plans/bicep-<env>-what-if.json
```

Before apply, rerun the same What-If. If the normalized summary or manifest hash differs from the approved evidence, stop and request new approval.

### Apply

Resource group:

```bash
az deployment group create \
  --name <deployment-name> \
  --resource-group <resource-group> \
  --template-file main.json \
  --parameters @parameters.<env>.json \
  --mode Incremental
```

Subscription:

```bash
az deployment sub create \
  --name <deployment-name> \
  --location <location> \
  --template-file main.json \
  --parameters @parameters.<env>.json \
  --mode Incremental
```

## ARM JSON Workflow

Use ARM JSON when the user already has ARM templates, when Bicep compilation output is needed, or when an Azure-native integration specifically requires raw templates.

### Author or ingest

Create or inspect:

```text
azuredeploy.json
azuredeploy.parameters.json
README.md
```

### Validate

```bash
az deployment group validate \
  --resource-group <resource-group> \
  --template-file azuredeploy.json \
  --parameters @azuredeploy.parameters.json
```

### Plan

```bash
mkdir -p ../../plans
az deployment group what-if \
  --name <deployment-name> \
  --resource-group <resource-group> \
  --template-file azuredeploy.json \
  --parameters @azuredeploy.parameters.json \
  --mode Incremental \
  --result-format FullResourcePayloads \
  --no-pretty-print \
  -o json > ../../plans/arm-<env>-what-if.json
```

ARM What-If follows the same rule as Bicep: it is approval evidence, not a replayable execution plan. Rerun and compare before apply.

### Apply

```bash
az deployment group create \
  --name <deployment-name> \
  --resource-group <resource-group> \
  --template-file azuredeploy.json \
  --parameters @azuredeploy.parameters.json \
  --mode Incremental
```

### Non-resource-group scopes

ARM JSON uses the same Azure deployment command families as compiled Bicep. For subscription, management-group, or tenant scope, switch from `az deployment group ...` to the matching scoped command and include required scope metadata.

Subscription:

```bash
az deployment sub validate \
  --location <location> \
  --template-file azuredeploy.json \
  --parameters @azuredeploy.parameters.json

az deployment sub what-if \
  --name <deployment-name> \
  --location <location> \
  --template-file azuredeploy.json \
  --parameters @azuredeploy.parameters.json \
  --mode Incremental \
  --result-format FullResourcePayloads \
  --no-pretty-print \
  -o json > ../../plans/arm-<env>-what-if.json

az deployment sub create \
  --name <deployment-name> \
  --location <location> \
  --template-file azuredeploy.json \
  --parameters @azuredeploy.parameters.json \
  --mode Incremental
```

Management group:

```bash
az deployment mg validate \
  --management-group-id <management-group-id> \
  --location <location> \
  --template-file azuredeploy.json \
  --parameters @azuredeploy.parameters.json

az deployment mg what-if \
  --name <deployment-name> \
  --management-group-id <management-group-id> \
  --location <location> \
  --template-file azuredeploy.json \
  --parameters @azuredeploy.parameters.json \
  --mode Incremental \
  --result-format FullResourcePayloads \
  --no-pretty-print \
  -o json > ../../plans/arm-<env>-what-if.json

az deployment mg create \
  --name <deployment-name> \
  --management-group-id <management-group-id> \
  --location <location> \
  --template-file azuredeploy.json \
  --parameters @azuredeploy.parameters.json \
  --mode Incremental
```

Tenant:

```bash
az deployment tenant validate \
  --location <location> \
  --template-file azuredeploy.json \
  --parameters @azuredeploy.parameters.json

az deployment tenant what-if \
  --name <deployment-name> \
  --location <location> \
  --template-file azuredeploy.json \
  --parameters @azuredeploy.parameters.json \
  --mode Incremental \
  --result-format FullResourcePayloads \
  --no-pretty-print \
  -o json > ../../plans/arm-<env>-what-if.json

az deployment tenant create \
  --name <deployment-name> \
  --location <location> \
  --template-file azuredeploy.json \
  --parameters @azuredeploy.parameters.json \
  --mode Incremental
```

## Azure REST Mapping for Bicep/ARM

Azure CLI is usually easier because it handles auth, polling, formatting, and long-running operations. The underlying API family is still Azure Resource Manager.

Resource group validate:

```http
POST https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Resources/deployments/{deploymentName}/validate?api-version=2025-04-01
```

Resource group what-if:

```http
POST https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Resources/deployments/{deploymentName}/whatIf?api-version=2025-04-01
```

Resource group apply:

```http
PUT https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Resources/deployments/{deploymentName}?api-version=2025-04-01
```

Typical request body:

```json
{
  "properties": {
    "mode": "Incremental",
    "template": {},
    "parameters": {}
  }
}
```

Use `Complete` mode only with extreme care. Prefer `Incremental` unless the user explicitly needs full reconciliation and accepts deletion risk.

## Terraform Workflow

Terraform is the right engine when state, modules, policy tooling, or existing team workflows are Terraform-based.

### Author

Create:

```text
versions.tf
providers.tf
main.tf
variables.tf
outputs.tf
terraform.tfvars.example
README.md
```

The AzureRM provider must target the reviewed Azure subscription. Prefer an explicit non-secret `subscription_id` variable or a checked `ARM_SUBSCRIPTION_ID` environment variable. The starter template uses `var.subscription_id` and optional `var.tenant_id`.

Do not create real `terraform.tfvars`, `terraform.tfvars.json`, `*.auto.tfvars`, or `*.auto.tfvars.json` with secrets. If a backend is needed, document it and keep sensitive backend credentials outside the repository. For deployable root modules, commit the generated `.terraform.lock.hcl` after `terraform init`/`tofu init`; do not add it to the generated gitignore.

### Validate

```bash
terraform fmt -check -recursive
terraform init -upgrade=false
terraform validate
```

### Plan

```bash
mkdir -p ../../plans
terraform plan -var-file=terraform.tfvars.example -out=../../plans/terraform-<env>-<deployment-name>.tfplan
terraform show -json ../../plans/terraform-<env>-<deployment-name>.tfplan > ../../plans/terraform-<env>-<deployment-name>.tfplan.json
```

`terraform-<env>-<deployment-name>.tfplan` and the matching `.tfplan.json` can contain sensitive values. Keep `plans/` gitignored, do not paste raw plan JSON into chat, and only summarize parsed/redacted changes. When computing the apply-bound approval hash, include the binary plan, matching JSON plan, and canonical target metadata such as `--subscription-id` and `--resource-group`; `scripts/plan_hash.py` reruns `terraform/tofu show -json` on the supplied binary plan and rejects the manifest if the supplied JSON is not derived from the exact binary plan. JSON-only hashing requires `--review-only-json-plan` and is not an apply approval gate.

Summarize resource actions from `tfplan.json`:

- `create`;
- `update`;
- `delete`;
- `delete` + `create` replacement;
- `no-op`;
- unknown computed values.

### Apply

```bash
terraform apply ../../plans/terraform-<env>-<deployment-name>.tfplan
```

Apply the exact plan file that was reviewed and approved. If the user asks for `terraform apply` without a saved plan, stop and re-plan first.

## OpenTofu Workflow

Use OpenTofu when the user asks for it or when the project has standardized on it. Do not switch an existing Terraform project to OpenTofu without explicit approval. OpenTofu mirrors the Terraform workflow but uses the `tofu` binary.

### Validate and plan

```bash
mkdir -p ../../plans
tofu fmt -check -recursive
tofu init -upgrade=false
tofu validate
tofu plan -var-file=terraform.tfvars.example -out=../../plans/opentofu-<env>-<deployment-name>.tfplan
tofu show -json ../../plans/opentofu-<env>-<deployment-name>.tfplan > ../../plans/opentofu-<env>-<deployment-name>.tfplan.json
```

### Apply

```bash
tofu apply ../../plans/opentofu-<env>-<deployment-name>.tfplan
```

Apply only the exact `tfplan` file that was reviewed and approved. If the user asks for `tofu apply` without a saved plan, stop and re-plan first.

## Scope Notes

Azure deployments can target:

- resource group;
- subscription;
- management group;
- tenant.

Commands and endpoints differ by scope. If scope is ambiguous, determine it from IaC `targetScope`, deployment files, provider configuration, variables, or user/project context before running validation or plan.

## Backend and State Notes for Terraform/OpenTofu

Before planning Terraform/OpenTofu for non-trivial infrastructure, identify state storage:

- local state for experiments only;
- Azure Storage remote backend for team/shared work;
- Terraform Cloud or another remote execution platform if the organization already uses it.

Never upload or summarize state contents. Treat state as sensitive because it may contain secrets or sensitive outputs.
