# Approval and Audit Contract

This reference defines how to bind human approval to a specific IaC plan and how to record the result.

## Plan Identity

A plan identity should be computed from the effective deployment artifact, not just from the prompt.

Important engine distinction:

- Terraform/OpenTofu produces a saved binary plan (`tfplan`) that can be applied directly with `terraform apply tfplan` or `tofu apply tfplan`.
- Bicep/ARM Azure What-If is **not** a replayable plan artifact. It is provider-side evidence of expected changes at a point in time. Before Bicep/ARM apply, rerun What-If with the same compiled template, parameters, scope, deployment name, and mode. If the normalized summary or manifest hash differs, stop and request a new approval.

Include the hashes of:

- IaC source files;
- parameter or variable files used for the plan;
- compiled ARM JSON for Bicep;
- saved Azure What-If output, or both Terraform/OpenTofu binary `tfplan` and matching `tfplan.json` for apply-bound approval;
- engine and version if available;
- canonical target scope identifiers, deployment name, deployment mode, and environment summary. For example: `subscription_id` plus `resource_group` for resource-group scope, `subscription_id` for subscription scope, `management_group_id` for management-group scope, and `tenant_id` for tenant scope.

Use `scripts/plan_hash.py` to produce a JSON manifest containing per-file hashes, plan artifacts, skipped files, metadata, and an aggregate digest. Do not use a source-only hash as an apply approval gate. Terraform/OpenTofu JSON-only hashes require `--review-only-json-plan`; treat them as review evidence only, not permission to apply.

## Recommended Hash Files

Bicep/ARM:

```text
main.bicep
main.json
parameters.<env>.json
plans/bicep-<env>-what-if.json
```

ARM JSON:

```text
azuredeploy.json
azuredeploy.parameters.json
plans/arm-<env>-what-if.json
```

Terraform/OpenTofu:

```text
*.tf
tfplan
tfplan.json
selected *.tfvars file if non-sensitive and intentionally used
```

Do not print secret files into the conversation. If a file is sensitive, hash it only when necessary to bind approval, never display its contents, and document the attestation boundary.

## Plan Storage Rules

Plan artifacts can contain sensitive values even when the IaC source does not. Treat these as local sensitive files:

- `tfplan`;
- `tfplan.json`;
- Azure What-If JSON output;
- raw CLI output;
- raw provider error output.

Keep `plans/` local and gitignored. Do not paste raw plan JSON into chat or audit notes. Parse and redact the summary instead.

## Approval Wording

Recommended English format:

```text
I approve apply for <engine> <environment> <deployment-name> with plan hash <sha256>.
```

Recommended French format:

```text
J'approuve l'apply pour <engine> <environment> <deployment-name> avec le hash de plan <sha256>.
```

For high-risk changes, include the risk in the approval request:

```text
This plan opens public HTTPS ingress and creates a premium database. To proceed, approve with:
J'approuve l'apply pour bicep prod webapp-prod avec le hash de plan <sha256>, y compris l'exposition publique HTTPS et la base premium.
```

## Approval Refusal Cases

Do not apply if:

- no real plan/what-if was produced;
- validation failed;
- plan hash changed;
- IaC or parameters changed after planning;
- for Bicep/ARM, a fresh pre-apply What-If differs from the approved What-If summary/hash;
- user approval is vague for high-risk or destructive changes;
- target subscription/resource group differs from reviewed scope;
- source IaC or parameter/variable files contain hardcoded secrets;
- raw plan artifacts or provider output containing sensitive values were committed, pasted into chat, or written to user-facing audit notes instead of kept as protected local files and redacted summaries;
- the user asks to bypass validation or plan for a non-trivial deployment.

## Audit Note Template

```markdown
# Azure IaC Apply Audit

- Timestamp: <ISO-8601>
- Engine: <bicep|arm|terraform|opentofu>
- Environment: <env>
- Scope: <tenant|management-group|subscription|resource-group>
- Subscription: <name or id, if non-sensitive>
- Resource group: <name, if applicable>
- Deployment name: <name>
- IaC files: <list>
- Plan hash: <sha256>
- Approval: <approval text or reference>
- Final status: <succeeded|failed|partial|cancelled>

## Planned changes

- Create: <summary>
- Modify: <summary>
- Replace: <summary>
- Delete: <summary>

## Risk flags

- <risk or none>

## Outputs

- <non-sensitive outputs only>

## Follow-up

- <next actions>
```

## Redaction Rules

Replace sensitive values with `[REDACTED]` in audit notes and user-facing summaries.

Never include:

- access tokens;
- passwords;
- private keys;
- client secrets;
- SAS signatures;
- storage account keys;
- full connection strings;
- Terraform state contents;
- raw `tfplan.json` contents;
- raw Azure What-If JSON if it contains sensitive values.
