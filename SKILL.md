---
name: azure-iac-agent
description: Use when generating, reviewing, validating, planning, applying, or auditing Azure IaC with Bicep, ARM JSON, Terraform, or OpenTofu through strict author/plan/approval/apply gates.
version: 1.0.0
author: Hermes Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [azure, iac, bicep, arm, terraform, opentofu, devops, security]
    related_skills: [agent-native-iac-api, code-review, systematic-debugging]
---

# Azure IaC Agent

## Overview

Use this skill as a complete operating procedure for Azure Infrastructure as Code work. It allows an agent to author Azure infrastructure from natural language, review the generated or existing IaC, validate it, produce a real plan, summarize risks, request explicit approval, apply the approved plan, and audit the result.

This is not framed as a small MVP and not as a replacement for Azure. Azure already provides native deployment APIs for ARM/Bicep. Terraform and OpenTofu use their own runners and the AzureRM provider, which call Azure APIs underneath. This skill orchestrates those existing systems with agent-safe gates.

Central rule:

```text
Generated IaC is not trusted IaC until it has passed local validation,
provider/cloud validation, real plan or what-if, human-readable review,
and explicit human approval before apply.
```

## When to Use

Use this skill when the user asks to:

- create Azure IaC from scratch;
- create or modify Bicep, ARM JSON, Terraform, or OpenTofu for Azure;
- deploy Azure IaC safely;
- run Azure ARM/Bicep validate, what-if, or deployment;
- run Terraform/OpenTofu init, validate, plan, or apply for Azure;
- inspect IaC for public exposure, broad RBAC, cost risks, secrets, regions, tags, or destructive changes;
- convert a natural-language infrastructure request into deployable Azure IaC;
- compare Azure-native Bicep/ARM versus Terraform/OpenTofu execution paths.

Do not use this skill for:

- Kubernetes manifest design unless the Azure IaC provisions AKS or related Azure resources;
- cloud providers other than Azure, except for Terraform modules that include Azure as the target provider;
- direct imperative Azure CLI changes that bypass IaC;
- applying infrastructure without an explicit user approval after a real plan.

## Operating Model

The skill supports two high-level modes:

1. **Safe template mode** — select or adapt approved templates only. Prefer this for repeatable or production-like deployments.
2. **Authoring mode** — generate IaC from scratch. This is allowed, but the generated code is untrusted until it passes the full validation, planning, review, and approval pipeline.

Always separate the workflow into these gates:

```text
author -> review -> validate -> plan -> approve -> apply -> audit
```

Never collapse this into:

```text
natural language -> generate IaC -> apply immediately
```

## Engine Selection

Choose the engine deliberately before writing or running anything.

- **Bicep**: preferred Azure-native authoring format. Readable, maintainable, compiles to ARM JSON, deploys via Azure Resource Manager deployments.
- **ARM JSON**: supported for direct ARM template workflows, imports, generated output, or advanced Azure-native cases. Verbose; not preferred for from-scratch authoring unless the user asks.
- **Terraform**: use when the user wants Terraform workflows, existing Terraform state, modules, teams, policy tooling, or multi-cloud portability. Deploy through Terraform CLI or Terraform Cloud-style systems, not through ARM deployments.
- **OpenTofu**: use when the user explicitly prefers OpenTofu or a non-Terraform binary for HCL workflows.

Default recommendation:

```text
Azure-native project -> Bicep
Existing Terraform estate -> Terraform/OpenTofu
Raw Azure template integration -> ARM JSON
```

## Workspace Convention

For each task, create or work inside an isolated project directory. A recommended layout:

```text
<project>/
  iac/
    bicep/
      main.bicep
      parameters.dev.json
      parameters.prod.json
      README.md
    arm/
      azuredeploy.json
      azuredeploy.parameters.json
      README.md
    terraform/
      providers.tf
      versions.tf
      main.tf
      variables.tf
      outputs.tf
      terraform.tfvars.example
      README.md
  plans/
    <engine>-<env>-plan.json
    <engine>-<env>-plan.txt
    <engine>-<env>-plan.sha256
  audit/
    <timestamp>-<engine>-<env>.md
```

Keep generated plans and audit summaries separate from source IaC. Do not place credentials, secrets, state files, or private `.tfvars` files in the skill output.

## Gate 1: Author

When authoring from natural language:

1. Restate the requested architecture and assumptions.
2. Choose the engine and explain why.
3. Create minimal but complete IaC files.
4. Include required parameters/variables, outputs, tags, and a README.
5. Avoid hardcoded secrets. Use Key Vault references, secure parameters, environment variables, CI secret stores, or documented placeholders.
6. Prefer explicit region, naming, tags, SKU, and network posture.
7. Do not apply anything during authoring.

Authoring output should make the next gate possible without guessing.

### Bicep authoring output

Typical files:

```text
main.bicep
parameters.<env>.json
README.md
```

Use Bicep parameters for:

- `location`;
- `environment`;
- `projectName` or naming prefix;
- tags;
- SKU choices;
- network/public access settings.

### ARM authoring output

Typical files:

```text
azuredeploy.json
azuredeploy.parameters.json
README.md
```

Ensure the template has:

- `$schema`;
- `contentVersion`;
- typed `parameters`;
- `resources`;
- `outputs` where useful.

### Terraform/OpenTofu authoring output

Typical files:

```text
versions.tf
providers.tf
main.tf
variables.tf
outputs.tf
terraform.tfvars.example
README.md
```

Pin provider constraints and commit `.terraform.lock.hcl` for deployable root modules after `terraform init`/`tofu init` so reviewed provider selections stay reproducible. Use variables for subscription context, location, naming, SKUs, and network posture. Never commit real `terraform.tfvars`, `terraform.tfvars.json`, `*.auto.tfvars`, or `*.auto.tfvars.json` if they may contain secrets.

## Gate 2: Review

Before validation or planning, review the code in plain language.

Always report:

- resources to be created or changed;
- Azure scope: tenant, management group, subscription, or resource group;
- region and naming assumptions;
- tags;
- public endpoints and ingress rules;
- RBAC assignments;
- expensive SKUs or capacity settings;
- data persistence, backup, retention, deletion protection;
- secrets or secret-like values;
- deletes, replacements, or migration implications.

If risk is high, pause and ask for explicit design confirmation before running a plan.

## Gate 3: Validate

Run local and provider/cloud validation appropriate for the engine.

### Bicep validation

Preferred local validation:

```bash
bicep build main.bicep --outfile main.json
```

If using Azure CLI:

```bash
az bicep build --file main.bicep --outfile main.json
```

Then validate through Azure Resource Manager at the intended scope.

If you author parameters as Bicep-native `.bicepparam`, treat that file as source IaC: scan it, include it in the plan hash, and still bind the apply to the generated/used ARM parameter JSON (`parameters.<env>.json`) or the exact Azure CLI parameter input used for What-If/apply. A changed `.bicepparam` requires a new validation, What-If, hash, and approval.

Resource-group scope example:

```bash
az deployment group validate \
  --resource-group <resource-group> \
  --template-file main.json \
  --parameters @parameters.dev.json
```

### ARM JSON validation

Validate schema shape locally if possible, then call Azure validation at the intended scope. Resource-group scope example:

```bash
az deployment group validate \
  --resource-group <resource-group> \
  --template-file azuredeploy.json \
  --parameters @azuredeploy.parameters.json
```

For subscription, management-group, or tenant scope, use the matching Azure CLI command family: `az deployment sub validate`, `az deployment mg validate`, or `az deployment tenant validate` with the required `--location` / `--management-group-id` arguments.

### Terraform/OpenTofu validation

Use the selected runner consistently. For Terraform:

```bash
terraform fmt -check -recursive
terraform init -upgrade=false
terraform validate
```

For OpenTofu:

```bash
tofu fmt -check -recursive
tofu init -upgrade=false
tofu validate
```

Do not proceed to plan if validation fails. Fix the IaC first, then re-run validation.

## Gate 4: Plan

A plan must be real, not fabricated.

### Bicep/ARM plan through Azure What-If

Bicep should be compiled to ARM JSON first. Then run What-If at the intended scope and save the output as a local plan-evidence artifact.

Important distinction: Azure What-If is **not** a replayable execution plan like Terraform's `tfplan`. It is a provider-side prediction at a point in time. For Bicep/ARM, approval is bound to a saved What-If artifact plus the compiled template, parameters, scope, deployment name, and deployment mode. Before apply, rerun What-If with the same inputs and stop if the normalized summary/hash differs.

Resource-group scope example:

```bash
mkdir -p ../../plans
az deployment group what-if \
  --name <deployment-name> \
  --resource-group <resource-group> \
  --template-file main.json \
  --parameters @parameters.dev.json \
  --mode Incremental \
  --result-format FullResourcePayloads \
  --no-pretty-print \
  -o json > ../../plans/bicep-dev-what-if.json
```

Subscription scope example:

```bash
mkdir -p ../../plans
az deployment sub what-if \
  --name <deployment-name> \
  --location <location> \
  --template-file main.json \
  --parameters @parameters.dev.json \
  --mode Incremental \
  --result-format FullResourcePayloads \
  --no-pretty-print \
  -o json > ../../plans/bicep-dev-what-if.json
```

Map this mentally to Azure REST:

```text
POST Microsoft.Resources/deployments/<deploymentName>/whatIf
```

Compute a manifest-bound hash over the source, compiled ARM JSON, parameters, What-If output, and canonical scope metadata before asking for approval. For resource-group scope, include both `--subscription-id` and `--resource-group`; for subscription/management-group/tenant scopes, include the corresponding canonical target identifier.

### Terraform/OpenTofu plan

Terraform:

```bash
mkdir -p ../../plans
terraform plan -var-file=terraform.tfvars.example -out=../../plans/terraform-<env>-<deployment-name>.tfplan
terraform show -json ../../plans/terraform-<env>-<deployment-name>.tfplan > ../../plans/terraform-<env>-<deployment-name>.tfplan.json
```

OpenTofu:

```bash
mkdir -p ../../plans
tofu plan -var-file=terraform.tfvars.example -out=../../plans/opentofu-<env>-<deployment-name>.tfplan
tofu show -json ../../plans/opentofu-<env>-<deployment-name>.tfplan > ../../plans/opentofu-<env>-<deployment-name>.tfplan.json
```

Treat `tfplan`, `tfplan.json`, and any raw plan output as sensitive local artifacts. Keep `plans/` gitignored, never paste raw plan JSON into chat, and summarize only redacted creates, updates, replacements, deletes, and unknowns. Compute a manifest-bound plan hash before approval with the exact target metadata (`--subscription-id`, `--resource-group`, `--management-group-id`, or `--tenant-id` as applicable). For Bicep, include `main.bicep`, any `.bicepparam` source files, compiled `main.json`, parameter JSON, and saved What-If evidence in the reviewed manifest. Terraform/OpenTofu apply-bound hashes must include both the binary `tfplan` and the matching `tfplan.json`; `scripts/plan_hash.py` reruns `terraform/tofu show -json` against the binary plan and rejects the hash if the supplied JSON does not match or the CLI cannot verify it. `--review-only-json-plan` is for review evidence only and must not be used as an apply approval gate.

## Gate 5: Approval

Apply requires explicit approval bound to the reviewed plan. Do not accept vague permission if the plan includes destructive or high-risk changes.

Recommended approval text:

```text
I approve apply for <engine> <environment> <deployment-name> with plan hash <sha256>.
```

French equivalent:

```text
J'approuve l'apply pour <engine> <environment> <deployment-name> avec le hash de plan <sha256>.
```

Before applying, verify:

- the user saw the redacted plan/What-If summary;
- the manifest hash still matches the reviewed artifacts;
- the IaC files did not change after the plan;
- the same engine, scope, environment, deployment name, deployment mode, and parameters are being used;
- for Bicep/ARM, a fresh pre-apply What-If was run and still matches the approved summary/hash;
- for Terraform/OpenTofu, the exact saved `tfplan` file is being applied;
- no secret was printed, committed, or stored in user-facing summaries/audit notes; protected local plan artifacts may contain provider-produced sensitive values only when kept gitignored/local, hashed for approval binding, and summarized through redaction.

## Gate 6: Apply

Only apply a previously reviewed and approved plan.

### Bicep/ARM apply

For Bicep/ARM, apply does not replay the saved What-If. It sends the compiled ARM template and parameters to Azure Resource Manager. Immediately before apply, rerun What-If with the same scope, deployment name, mode, template, and parameters; if the result differs from the approved evidence, stop and require a new approval.

Resource-group scope example:

```bash
az deployment group create \
  --name <deployment-name> \
  --resource-group <resource-group> \
  --template-file main.json \
  --parameters @parameters.dev.json \
  --mode Incremental
```

Subscription scope example:

```bash
az deployment sub create \
  --name <deployment-name> \
  --location <location> \
  --template-file main.json \
  --parameters @parameters.dev.json \
  --mode Incremental
```

Map this to Azure REST:

```text
PUT Microsoft.Resources/deployments/<deploymentName>
```

### Terraform/OpenTofu apply

Apply the exact stored plan, not a fresh implicit plan.

Terraform:

```bash
terraform apply ../../plans/terraform-<env>-<deployment-name>.tfplan
```

OpenTofu:

```bash
tofu apply ../../plans/opentofu-<env>-<deployment-name>.tfplan
```

If the plan file is missing or stale, stop and re-plan.

## Gate 7: Audit

After apply, create a concise audit note containing:

- timestamp;
- engine and version if available;
- Azure account/subscription/resource group/scope, without secrets;
- IaC files used;
- plan hash;
- approval text or approval reference;
- final status;
- resource changes summary;
- non-sensitive outputs;
- follow-up actions.

Never include tokens, passwords, connection strings, SAS URLs, private keys, or full sensitive command output. Replace sensitive values with `[REDACTED]`.

## Mandatory Safety Policy

Blocker-class findings must stop apply until corrected or explicitly redesigned to remove the unsafe condition. Do not downgrade blockers to confirmation-only handling. Blockers include:

- hardcoded passwords, tokens, API keys, SAS URLs, private keys, connection strings, or other secrets embedded directly in IaC or parameter files;
- Terraform/OpenTofu state, state backups, raw plan artifacts, or provider outputs containing sensitive values committed or exposed outside protected local artifacts;
- public storage container access unless explicitly required and redesigned with compensating controls;
- Owner, Contributor, or User Access Administrator assignments at subscription or management-group scope;
- missing, failed, stale, unverifiable, or changed validation/plan/What-If evidence;
- target subscription/resource group/scope that differs from the reviewed plan;
- broad management ingress such as `0.0.0.0/0` or `::/0` to SSH, RDP, SQL, PostgreSQL, MySQL, Redis, or admin APIs;
- destructive production changes without rollback notes.

High-risk findings may proceed only with explicit extra confirmation bound to the plan hash. High-risk findings include:

- public IPs and public network access outside blocker cases;
- resource-group-scoped Owner/Contributor/User Access Administrator role assignments or narrower role assignments that still exceed least privilege;
- deletes, replacements, or force-new changes outside blocker cases;
- expensive SKUs, GPU/large VM families, high replicas, premium databases;
- missing tags or unexpected regions;
- disabled encryption, disabled soft delete, disabled purge protection;
- open management ports such as 22, 3389, 5432, 1433, 3306, 6379.

The skill may recommend safer alternatives, but must not silently weaken the policy.

## Secret Handling

Treat all command output as potentially sensitive. Redact values that look like:

- passwords;
- client secrets;
- API keys;
- tokens;
- SAS URLs;
- connection strings;
- private keys;
- Authorization headers;
- storage account keys.

Do not write `.env`, real `.tfvars`, `*.tfstate`, `*.tfstate.backup`, private key files, or cloud credentials into generated skill outputs.

## Azure REST API Mapping

For Bicep/ARM, Azure Resource Manager is the deployment substrate.

Resource group scope examples:

```http
POST /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Resources/deployments/{deploymentName}/validate?api-version=2025-04-01
POST /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Resources/deployments/{deploymentName}/whatIf?api-version=2025-04-01
PUT  /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Resources/deployments/{deploymentName}?api-version=2025-04-01
```

Bicep itself is compiled locally to ARM JSON before these APIs are called.

Terraform/OpenTofu does not use `Microsoft.Resources/deployments` as its apply interface. It uses the Terraform/OpenTofu runner and AzureRM provider, which call Azure resource provider APIs underneath.

## Common Pitfalls

1. **Calling a generated template trusted.** Generated IaC is draft code until it passes validation, plan, review, and approval.

2. **Using ARM APIs for Terraform.** ARM deployments apply ARM templates. Terraform applies through Terraform/OpenTofu and the provider.

3. **Treating Azure What-If as replayable.** For Terraform/OpenTofu, apply the exact saved plan file. For Bicep/ARM, What-If is evidence, not an executable plan: save/hash it, rerun it immediately before apply, and require new approval if it differs.

4. **Accepting vague approval.** High-risk or destructive changes need explicit approval bound to plan identity.

5. **Leaking secrets in summaries.** Never paste raw command output containing credentials. Redact aggressively.

6. **Ignoring scope.** Tenant, management group, subscription, and resource group deployments use different commands and endpoints.

7. **Treating a skill as a sandbox.** This skill is a workflow and policy. A custom API or worker sandbox is still stronger when agents must not hold broad cloud credentials.

8. **Forgetting state.** Terraform/OpenTofu state location, locking, and backend config are part of the deployment design, not an afterthought.

## Verification Checklist

Before finalizing any Azure IaC task:

- [ ] Engine selected deliberately: Bicep, ARM, Terraform, or OpenTofu.
- [ ] IaC files exist and are readable.
- [ ] No secrets are hardcoded in source, parameters, variables, plans, logs, or summaries.
- [ ] Local validation succeeded.
- [ ] Azure validation or Terraform/OpenTofu validation succeeded.
- [ ] Real What-If or plan completed and was saved as a local sensitive artifact.
- [ ] Plan summary includes creates, updates, replacements, deletes, unknowns, and risk flags.
- [ ] Manifest-bound plan/What-If hash was computed and shown.
- [ ] User explicitly approved the reviewed plan identity.
- [ ] For Bicep/ARM, a fresh pre-apply What-If matched the approved evidence.
- [ ] For Terraform/OpenTofu, apply used the exact saved `tfplan` file.
- [ ] Apply used the same files, parameters, deployment mode, environment, and scope.
- [ ] Final status and non-sensitive outputs were captured.
- [ ] Audit note was written or summarized.

## Starter Templates

The skill package includes both `.template` files and native-extension starter files so an agent can copy them directly into an IaC workspace:

- Bicep:
  - `templates/bicep/main.bicep.template`
  - `templates/bicep/parameters.dev.json.template`
  - `templates/bicep/main.bicep`
  - `templates/bicep/parameters.dev.json`
- Terraform/OpenTofu:
  - `templates/terraform/versions.tf.template`
  - `templates/terraform/providers.tf.template`
  - `templates/terraform/main.tf.template`
  - `templates/terraform/variables.tf.template`
  - `templates/terraform/outputs.tf.template`
  - `templates/terraform/terraform.tfvars.example.template`
  - `templates/terraform/versions.tf`
  - `templates/terraform/providers.tf`
  - `templates/terraform/main.tf`
  - `templates/terraform/variables.tf`
  - `templates/terraform/outputs.tf`
  - `templates/terraform/terraform.tfvars.example`
- Common guardrail:
  - `templates/common/gitignore.template`

Copy starter templates into a project workspace, then adapt names, scopes, regions, SKUs, backend configuration, and risk controls before validation or planning.

## Linked References

- `references/engine-workflows.md` — exact engine workflows and command/API mapping.
- `references/security-policy.md` — risk classes and blocking rules.
- `references/approval-and-audit.md` — approval format, plan hash, and audit note structure.

## Helper Scripts

- `scripts/plan_hash.py` — create a manifest-bound SHA-256 plan identity with per-file hashes, canonical target metadata, required plan/What-If artifact detection, and Terraform/OpenTofu binary-plan verification for apply-bound hashes.
- `scripts/scan_iac_risks.py` — lightweight static scan for common IaC risk patterns. This does not replace cloud/provider validation.
