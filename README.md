# Azure IaC Agent Skill

Hermes skill for creating Azure IaC from scratch and deploying it through Azure-native APIs with approval gates.

## What it does

- Turns a user request into Azure IaC.
- Generates Bicep, ARM JSON, Terraform, or OpenTofu files.
- Reviews generated or existing IaC before deployment.
- Runs validation and a real plan / What-If.
- Summarizes changes, risks, public exposure, RBAC, costs, and secrets.
- Applies only after explicit human approval.
- Writes a redacted audit summary after apply.

## Workflow

```text
author -> review -> validate -> plan -> approve -> apply -> audit
```

No direct path from prompt to deployment.

## Default engine

Use **Bicep** for Azure-native IaC.

Use Terraform/OpenTofu only when the project needs HCL, state, modules, or existing Terraform workflows.

## Azure deployment path

Bicep/ARM uses Azure Resource Manager deployments:

- validate: `az deployment ... validate`
- plan: `az deployment ... what-if`
- apply: `az deployment ... create`

Underlying ARM API mapping:

- `POST .../validate`
- `POST .../whatIf`
- `PUT .../deployments/{deploymentName}`

Terraform/OpenTofu uses the AzureRM provider and applies the approved saved plan file.

## Safety contract

Apply is blocked if:

- validation failed;
- no real plan or What-If exists;
- IaC or parameters changed after planning;
- the plan hash changed;
- the Azure scope changed;
- secrets, state, or raw plan artifacts are exposed;
- approval is missing or vague.

Bicep/ARM What-If is approval evidence, not a replayable plan. Re-run it before apply and stop if it changed.

Terraform/OpenTofu must apply the exact approved plan artifact.

## Repository layout

```text
SKILL.md                         Main Hermes skill procedure
references/engine-workflows.md   Bicep, ARM, Terraform, OpenTofu workflows
references/security-policy.md    Risk classes and blocker rules
references/approval-and-audit.md Plan hash, approval, audit contract
templates/bicep/                 Bicep starter files
templates/terraform/             Terraform/OpenTofu starter files
scripts/scan_iac_risks.py        Static IaC risk scanner
scripts/plan_hash.py             Plan identity/hash helper
tests/                           Regression tests
```

## Install

```bash
mkdir -p ~/.hermes/skills/devops
git clone https://github.com/EnesBrt/azure_iac_skill.git ~/.hermes/skills/devops/azure-iac-agent
```

## Use

```text
Use the azure-iac-agent skill to create, plan, and deploy Azure IaC.
```

Approval format:

```text
I approve apply for <engine> <environment> <deployment-name> with plan hash <sha256>.
```

## Helper scripts

```bash
python3 scripts/scan_iac_risks.py <iac-directory>
python3 scripts/plan_hash.py --help
```

