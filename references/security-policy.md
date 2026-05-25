# Azure IaC Security Policy

This reference defines the risk classes the agent must check before plan and before apply.

## Policy Levels

### Blocker

Stop and do not apply until corrected or explicitly redesigned:

- hardcoded password, token, API key, SAS URL, private key, or connection string;
- Terraform state or state backup committed to source;
- public storage container access unless explicitly required;
- `0.0.0.0/0` or `::/0` management access to SSH, RDP, SQL, PostgreSQL, MySQL, Redis, or admin APIs;
- broad RBAC assignment such as Owner, Contributor, or User Access Administrator at subscription or management group scope;
- destructive change in production without rollback plan;
- unknown or unexpected Azure subscription for apply;
- plan cannot be produced but user wants apply anyway.

### High Risk

Pause, explain clearly, and require extra explicit confirmation:

- public IPs or public ingress;
- App Service, Container Apps, AKS, or VM endpoints exposed publicly;
- expensive SKUs, GPUs, high replica counts, premium databases, or large disks;
- delete or replacement actions in any environment;
- disabled soft delete/purge protection for Key Vault;
- public network access enabled for Key Vault, Storage, SQL, PostgreSQL, MySQL, Redis, or Container Registry;
- permissive CORS or wildcard origins;
- missing remote state backend for shared Terraform work;
- plan includes many unknown values or provider warnings.

### Medium Risk

Report in the plan summary and suggest improvements:

- missing tags;
- region differs from expected region;
- SKU not explicitly declared;
- no diagnostic settings or monitoring;
- no backup/retention policy for stateful services;
- no private endpoint where one is usually expected;
- no naming convention documented;
- defaults used without explanation.

## Required Review Questions

Before applying, answer these in the summary:

1. What resources will be created, modified, replaced, or deleted?
2. Which Azure scope is targeted?
3. Which subscription/resource group will be affected?
4. What public exposure exists?
5. What RBAC changes exist?
6. What cost-sensitive resources exist?
7. What data persistence or deletion risks exist?
8. Were any secrets found or redacted?
9. What is the plan hash or equivalent plan identity?
10. What exact approval is required?

## Secret Detection Patterns

Flag keys or assignments containing:

```text
password
passwd
pwd
secret
client_secret
credential
credentials
api_key
apikey
token
access_token
refresh_token
connection_string
AccountKey
SharedAccessSignature
sas
private_key
```

Flag values that look like:

- `Bearer ...`;
- `Basic ...`;
- Azure Storage connection strings;
- SAS URLs with `sig=`;
- PEM private key blocks;
- long unstructured tokens.

## Safer Defaults

Prefer:

- least privilege RBAC;
- private endpoints or restricted ingress for stateful services;
- Key Vault references instead of inline secrets;
- managed identities instead of client secrets;
- soft delete and purge protection for Key Vault;
- tags such as `project`, `environment`, `owner`, and `managedBy`;
- explicit SKU and capacity values;
- remote Terraform/OpenTofu state with locking for shared environments;
- `Incremental` ARM deployment mode unless deletion is explicitly intended.

## Dangerous Ports

Flag public exposure for:

```text
22    SSH
3389  RDP
1433  SQL Server
3306  MySQL
5432  PostgreSQL
6379  Redis
27017 MongoDB
9200  Elasticsearch
```

## Deletion and Replacement Rules

If the plan includes delete or replacement:

1. Identify every affected resource.
2. Identify whether data may be lost.
3. Identify whether the resource is production or stateful.
4. Ask for explicit confirmation naming the delete/replacement.
5. Do not apply if the user approval only says a vague `ok`.

## Production Rules

For production changes, require:

- real plan/what-if output;
- plan hash;
- explicit approval;
- rollback or recovery note;
- maintenance window awareness if relevant;
- audit summary after apply.
