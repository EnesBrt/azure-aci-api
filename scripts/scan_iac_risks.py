#!/usr/bin/env python3
"""Lightweight static risk scanner for Azure IaC files.

This helper catches obvious patterns before provider validation/plan. It is not
a security scanner replacement and must not be used as the only approval gate.
It redacts secret-context values before printing findings.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import NamedTuple


class PatternRule(NamedTuple):
    label: str
    pattern: re.Pattern[str]
    secret_like: bool = False


SECRET_KEY_PATTERN = (
    r"[A-Za-z0-9_-]*(?:"
    r"password|passwd|pwd|secret|clientsecret|client_secret|"
    r"credential|credentials|"
    r"api[_-]?key|apikey|token|access[_-]?token|refresh[_-]?token|"
    r"connection[_-]?string|connectionstring|account[_-]?key|"
    r"storage[_-]?account[_-]?key|shared[_-]?access[_-]?signature|sas|private[_-]?key"
    r")[A-Za-z0-9_-]*"
)
SECRET_ASSIGNMENT_RE = re.compile(
    rf"(?i)(?P<prefix>.*?(?:{SECRET_KEY_PATTERN})[\"']?\s*[:=]\s*)(?P<value>.+)"
)
BICEP_SECRET_PARAM_RE = re.compile(
    rf"(?i)^\s*param\s+(?P<key>{SECRET_KEY_PATTERN})\s+[^=\s]+(?:\s*=\s*(?P<value>.+))?"
)
BICEP_ANY_PARAM_RE = re.compile(r"(?i)^\s*param\s+(?P<key>[A-Za-z_][A-Za-z0-9_]*)\b")
BICEP_SECURE_DECORATOR_RE = re.compile(r"(?i)^\s*@secure\s*\(\s*\)\s*(?://.*)?$")
BICEP_ANY_DECORATOR_RE = re.compile(r"^\s*@")
JSON_SECRET_OBJECT_RE = re.compile(
    rf"(?i)^\s*[\"']?(?:{SECRET_KEY_PATTERN})[\"']?\s*:\s*\{{"
)
JSON_SECURE_TYPE_RE = re.compile(r"(?i)[\"']type[\"']\s*:\s*[\"']secure(?:string|object)[\"']")
JSON_OBJECT_KEY_RE = re.compile(r"^\s*[\"'](?P<key>[^\"']+)[\"']\s*:\s*[{]")
HCL_SECRET_VARIABLE_RE = re.compile(
    rf"(?i)^\s*variable\s+[\"'](?P<key>{SECRET_KEY_PATTERN})[\"']\s*\{{"
)
HCL_SECRET_OBJECT_RE = re.compile(
    rf"(?i)^\s*[\"']?(?P<key>{SECRET_KEY_PATTERN})[\"']?\s*=\s*[\{{\[]"
)
PUBLIC_IPV4_CIDR_RE = re.compile(r"0\.0\.0\.0/0")
PUBLIC_IPV6_CIDR_RE = re.compile(r"::/0")
PUBLIC_WILDCARD_SOURCE_RE = re.compile(
    r"(?i)[\"']?(?:source_?address_?prefix(?:es)?|sourceAddressPrefix(?:es)?|ipAddressRange|allowed_?origins?)"
    r"[\"']?\s*[:=]\s*(?:\[\s*)?[\"']?(?:\*|Internet|0\.0\.0\.0/0|::/0)"
)
PUBLIC_LIST_KEY_RE = re.compile(
    r"(?i)[\"']?(?:source_?address_?prefix(?:es)?|sourceAddressPrefix(?:es)?|ipAddressRange|allowed_?origins?)"
    r"[\"']?\s*[:=]\s*\["
)
GENERIC_LIST_ASSIGNMENT_RE = re.compile(r"(?i)[\"']?[A-Za-z_][A-Za-z0-9_-]*[\"']?\s*[:=]\s*\[")
PUBLIC_LIST_VALUE_RE = re.compile(r"(?i)(?:[\"']?(?:\*|Internet|0\.0\.0\.0/0|::/0)[\"']?)")
PUBLIC_NETWORK_ACCESS_RE = re.compile(r"(?i)[\"']?publicNetworkAccess[\"']?\s*[=:]\s*[\"']?Enabled[\"']?")
PUBLIC_NETWORK_ACCESS_TF_RE = re.compile(
    r"(?i)(?:public_network_access_enabled\s*=\s*true|public_network_access\s*=\s*[\"']?Enabled[\"']?)"
)
RBAC_OWNER_RE = re.compile(r"(?i)[\"']?(?:role_definition_name|roleDefinitionName)[\"']?\s*[:=]\s*[\"']?Owner[\"']?")
RBAC_CONTRIBUTOR_RE = re.compile(r"(?i)[\"']?(?:role_definition_name|roleDefinitionName)[\"']?\s*[:=]\s*[\"']?Contributor[\"']?")
RBAC_USER_ACCESS_ADMIN_RE = re.compile(
    r"(?i)[\"']?(?:role_definition_name|roleDefinitionName)[\"']?\s*[:=]\s*[\"']?User Access Administrator[\"']?"
)
RBAC_OWNER_GUID_RE = re.compile(r"(?i)\b8e3af657-a8ff-443c-a75c-2fe8c4bcb635\b")
RBAC_CONTRIBUTOR_GUID_RE = re.compile(r"(?i)\bb24988ac-6180-42a0-ab88-20f7382dd24c\b")
RBAC_USER_ACCESS_ADMIN_GUID_RE = re.compile(r"(?i)\bf1a07417-d97a-45cb-824c-7a7467783830\b")
ROLE_DEFINITION_ID_KEY_RE = re.compile(r"(?i)[\"']?role_?definition_?id[\"']?\s*[:=]")
RBAC_OWNER_ID_RE = re.compile(
    r"(?i)[\"']?role_?definition_?id[\"']?\s*[:=].*\b8e3af657-a8ff-443c-a75c-2fe8c4bcb635\b"
)
RBAC_CONTRIBUTOR_ID_RE = re.compile(
    r"(?i)[\"']?role_?definition_?id[\"']?\s*[:=].*\bb24988ac-6180-42a0-ab88-20f7382dd24c\b"
)
RBAC_USER_ACCESS_ADMIN_ID_RE = re.compile(
    r"(?i)[\"']?role_?definition_?id[\"']?\s*[:=].*\bf1a07417-d97a-45cb-824c-7a7467783830\b"
)
STORAGE_PUBLIC_ACCESS_RE = re.compile(
    r"(?i)[\"']?(?:container_access_type|publicAccess|public_access)[\"']?\s*[:=]\s*[\"']?(?:blob|container)[\"']?"
)
DANGEROUS_PORT_PATTERNS: list[PatternRule] = [
    PatternRule("public exposure to dangerous SSH port", re.compile(r"\b22\b")),
    PatternRule("public exposure to dangerous RDP port", re.compile(r"\b3389\b")),
    PatternRule("public exposure to dangerous SQL Server port", re.compile(r"\b1433\b")),
    PatternRule("public exposure to dangerous MySQL port", re.compile(r"\b3306\b")),
    PatternRule("public exposure to dangerous PostgreSQL port", re.compile(r"\b5432\b")),
    PatternRule("public exposure to dangerous Redis port", re.compile(r"\b6379\b")),
    PatternRule("public exposure to dangerous MongoDB port", re.compile(r"\b27017\b")),
    PatternRule("public exposure to dangerous Elasticsearch port", re.compile(r"\b9200\b")),
]

PATTERNS: list[PatternRule] = [
    PatternRule("possible secret assignment", re.compile(rf"(?i)(?:{SECRET_KEY_PATTERN})[\"']?\s*[:=]"), True),
    PatternRule("secret authorization value", re.compile(r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{6,}"), True),
    PatternRule("Azure SAS signature value", re.compile(r"(?i)(?:[?&]|^|\s)sig=[A-Za-z0-9%._~+/=-]{6,}"), True),
    PatternRule("Azure Storage connection string", re.compile(r"(?i)DefaultEndpointsProtocol=.*AccountKey="), True),
    PatternRule("PEM private key block", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"), True),
    PatternRule("long token-like assignment", re.compile(r"(?i)^\s*[\"']?[A-Za-z_][A-Za-z0-9_-]*[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9._~+/=-]{40,}[\"']?\s*(?:[,#].*)?$"), True),
    PatternRule("HCL secret-like variable", HCL_SECRET_VARIABLE_RE, True),
    PatternRule("HCL secret-like object", HCL_SECRET_OBJECT_RE, True),
    PatternRule("ARM secure parameter type", JSON_SECURE_TYPE_RE, True),
    PatternRule("public IPv4 CIDR", PUBLIC_IPV4_CIDR_RE),
    PatternRule("public IPv6 CIDR", PUBLIC_IPV6_CIDR_RE),
    PatternRule("public wildcard source", PUBLIC_WILDCARD_SOURCE_RE),
    PatternRule("broad RBAC Owner", RBAC_OWNER_RE),
    PatternRule("broad RBAC Contributor", RBAC_CONTRIBUTOR_RE),
    PatternRule("User Access Administrator", RBAC_USER_ACCESS_ADMIN_RE),
    PatternRule("broad RBAC Owner", RBAC_OWNER_ID_RE),
    PatternRule("broad RBAC Contributor", RBAC_CONTRIBUTOR_ID_RE),
    PatternRule("User Access Administrator", RBAC_USER_ACCESS_ADMIN_ID_RE),
    PatternRule("public storage container access", STORAGE_PUBLIC_ACCESS_RE),
    PatternRule("public network access enabled", PUBLIC_NETWORK_ACCESS_RE),
    PatternRule("public network access enabled", PUBLIC_NETWORK_ACCESS_TF_RE),
]
AUTH_VALUE_RE = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{6,}")
SECRET_ASSIGNMENT_VALUE_RE = re.compile(
    rf"(?i)((?:{SECRET_KEY_PATTERN})[\"']?\s*[:=]\s*)(?:\"(?:\\.|[^\"])*\"|'(?:\\.|[^'])*'|[^,\]}}#\n]+)"
)
SENSITIVE_JSON_VALUE_RE = re.compile(
    r"(?i)([\"']?(?:value|defaultValue)[\"']?\s*:\s*)(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')"
)
NON_SECRET_LONG_VALUE_KEY_RE = re.compile(
    r"(?i)^\s*[\"']?(?:role_?definition_?id|resource_?id|principal_?id|client_?id|tenant_?id|subscription_?id|scope)[\"']?\s*[:=]"
)
DESTINATION_PORT_KEY_RE = re.compile(r"(?i)[\"']?destination_?port_?ranges?[\"']?|[\"']?destinationPortRanges?[\"']?")
PORT_RANGE_RE = re.compile(r"\b(?P<start>\d{1,5})\s*-\s*(?P<end>\d{1,5})\b")
DANGEROUS_PORTS = {
    22: "SSH",
    3389: "RDP",
    1433: "SQL Server",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
}
SENSITIVE_ARTIFACT_EXACT_NAMES = {"tfplan", "tfplan.json", "plan.tfplan", "plan.tfplan.json"}

EXTENSIONS = {".bicep", ".bicepparam", ".json", ".tf", ".tfvars", ".hcl"}
TEMPLATE_IAC_SUFFIXES = (
    ".bicep.template",
    ".bicepparam.template",
    ".json.template",
    ".tf.template",
    ".tfvars.template",
    ".tfvars.example.template",
    ".hcl.template",
)
TERRAFORM_VARIABLE_FILENAMES = {"terraform.tfvars", "terraform.tfvars.json", "terraform.tfvars.example"}
TERRAFORM_VARIABLE_SUFFIXES = (".auto.tfvars", ".auto.tfvars.json")
SKIP_PARTS = {".terraform", ".terragrunt-cache"}


def redact_excerpt(line: str, secret_like: bool) -> str:
    stripped = line.strip()
    if secret_like:
        bicep_match = BICEP_ANY_PARAM_RE.match(stripped)
        if bicep_match:
            key = bicep_match.group("key")
            return f"param {key} [REDACTED]"
        hcl_var_match = HCL_SECRET_VARIABLE_RE.match(stripped)
        if hcl_var_match:
            key = hcl_var_match.group("key")
            return f"variable \"{key}\" [REDACTED]"
        match = SECRET_ASSIGNMENT_RE.match(stripped)
        if match:
            value = match.group("value").lstrip()
            if value.startswith(("{", "[")):
                prefix = match.group("prefix")
                if len(prefix) > 120:
                    prefix = prefix[-120:]
                return f"{prefix}[REDACTED]"
        sanitized = AUTH_VALUE_RE.sub(lambda match: f"{match.group(1)} [REDACTED]", stripped)
        sanitized = SECRET_ASSIGNMENT_VALUE_RE.sub(lambda match: f"{match.group(1)}[REDACTED]", sanitized)
        sanitized = SENSITIVE_JSON_VALUE_RE.sub(lambda match: f"{match.group(1)}[REDACTED]", sanitized)
        if sanitized != stripped:
            return sanitized[:157] + "..." if len(sanitized) > 160 else sanitized
        if match:
            prefix = match.group("prefix")
            if len(prefix) > 120:
                prefix = prefix[-120:]
            return f"{prefix}[REDACTED]"
        low = stripped.lower()
        if low.startswith(('"value"', "'value'", "value")):
            return "value: [REDACTED]"
        if low.startswith(('"defaultvalue"', "'defaultvalue'", "defaultvalue", 'default', 'sensitive')):
            return "[REDACTED] secret-like default/value field"
        return "[REDACTED] secret context"
    sanitized = AUTH_VALUE_RE.sub(lambda match: f"{match.group(1)} [REDACTED]", stripped)
    sanitized = SECRET_ASSIGNMENT_VALUE_RE.sub(lambda match: f"{match.group(1)}[REDACTED]", sanitized)
    sanitized = SENSITIVE_JSON_VALUE_RE.sub(lambda match: f"{match.group(1)}[REDACTED]", sanitized)
    if len(sanitized) > 160:
        return sanitized[:157] + "..."
    return sanitized


def line_has_secret_like_pattern(line: str) -> bool:
    return any(rule.secret_like and rule.pattern.search(line) for rule in PATTERNS)


def is_terraform_variable_file(path: Path) -> bool:
    name = path.name.lower()
    return name in TERRAFORM_VARIABLE_FILENAMES or name.endswith(TERRAFORM_VARIABLE_SUFFIXES)


def is_terraform_state_file(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith(".tfstate") or ".tfstate." in name


def is_sensitive_generated_artifact(path: Path) -> bool:
    name = path.name.lower()
    in_plans_dir = any(part.lower() == "plans" for part in path.parts)
    if name in SENSITIVE_ARTIFACT_EXACT_NAMES:
        return True
    if in_plans_dir and (
        name in {"plan.json", "plan.txt", "plan.log"}
        or name.endswith(("-plan.json", "_plan.json", "-plan.txt", "_plan.txt", "-plan.log", "_plan.log"))
    ):
        return True
    return (
        name.startswith("tfplan")
        or ".tfplan" in name
        or name.endswith((".raw.json", ".raw.log", ".raw.txt"))
        or (("what-if" in name or "whatif" in name) and name.endswith((".json", ".txt", ".log")))
    )


def is_json_like_file(path: Path) -> bool:
    name = path.name.lower()
    return path.suffix.lower() == ".json" or name.endswith(".json.template")


def is_iac_file(path: Path) -> bool:
    name = path.name.lower()
    return (
        path.suffix.lower() in EXTENSIONS
        or name.endswith(TEMPLATE_IAC_SUFFIXES)
        or is_terraform_variable_file(path)
        or is_terraform_state_file(path)
    )


def iter_iac_files(root: Path):
    if root.is_file():
        if is_iac_file(root) and (is_terraform_state_file(root) or not is_sensitive_generated_artifact(root)):
            yield root
        return
    for path in sorted(root.rglob("*")):
        if SKIP_PARTS & set(path.parts):
            continue
        if path.is_file() and is_iac_file(path) and (is_terraform_state_file(path) or not is_sensitive_generated_artifact(path)):
            yield path


def rbac_guid_label(line: str) -> str | None:
    if RBAC_OWNER_GUID_RE.search(line):
        return "broad RBAC Owner"
    if RBAC_CONTRIBUTOR_GUID_RE.search(line):
        return "broad RBAC Contributor"
    if RBAC_USER_ACCESS_ADMIN_GUID_RE.search(line):
        return "User Access Administrator"
    return None


def dangerous_port_value_label(line: str) -> str | None:
    if re.search(r"[\"']\*[\"']", line) or re.search(r"[:=,\[]\s*\*", line):
        return "public exposure to all destination ports"
    for match in PORT_RANGE_RE.finditer(line):
        start = int(match.group("start"))
        end = int(match.group("end"))
        if start > end:
            start, end = end, start
        for port, name in DANGEROUS_PORTS.items():
            if start <= port <= end:
                return f"public exposure range includes dangerous {name} port"
    for port, name in DANGEROUS_PORTS.items():
        if re.search(rf"(?<!\d){port}(?!\d)", line):
            return f"public exposure to dangerous {name} port"
    return None


def dangerous_public_port_range_label(line: str) -> str | None:
    if not DESTINATION_PORT_KEY_RE.search(line):
        return None
    return dangerous_port_value_label(line)


def strip_string_literals(line: str) -> str:
    """Replace quoted string contents with spaces for delimiter counting.

    This prevents `}` / `]` inside secret values from prematurely ending a
    redaction context. It is intentionally lightweight, not a full IaC parser.
    """
    chars: list[str] = []
    quote: str | None = None
    escape = False
    for char in line:
        if quote:
            if escape:
                chars.append(" ")
                escape = False
            elif char == "\\":
                chars.append(" ")
                escape = True
            elif char == quote:
                chars.append(char)
                quote = None
            else:
                chars.append(" ")
        else:
            chars.append(char)
            if char in {'"', "'"}:
                quote = char
    return "".join(chars)


def brace_delta(line: str) -> int:
    # Lightweight approximation; enough for redaction context, not a parser.
    structural = strip_string_literals(line)
    return structural.count("{") - structural.count("}")


def secret_json_line_numbers(lines: list[str]) -> set[int]:
    """Return 1-based JSON line numbers that belong to likely secret parameter objects.

    This pre-scan makes ARM `secureString` / `secureObject` redaction independent of
    JSON property order, e.g. `defaultValue` before `type`.
    """
    secret_lines: set[int] = set()
    for start, line in enumerate(lines):
        match = JSON_OBJECT_KEY_RE.match(line)
        if not match:
            continue
        key = match.group("key")
        key_secret_like = re.search(SECRET_KEY_PATTERN, key, re.IGNORECASE) is not None
        balance = 0
        end = start
        direct_secure_type = JSON_SECURE_TYPE_RE.search(line) is not None
        for index in range(start, len(lines)):
            current = lines[index]
            before = balance
            if index > start and before == 1 and JSON_SECURE_TYPE_RE.search(current):
                direct_secure_type = True
            balance += brace_delta(current)
            end = index
            if balance <= 0:
                break
        if key_secret_like or direct_secure_type:
            secret_lines.update(range(start + 1, end + 2))
    return secret_lines


def hcl_delta(line: str) -> int:
    structural = strip_string_literals(line)
    return structural.count("{") + structural.count("[") - structural.count("}") - structural.count("]")


def line_has_public_exposure(line: str) -> bool:
    return any(
        pattern.search(line)
        for pattern in (
            PUBLIC_IPV4_CIDR_RE,
            PUBLIC_IPV6_CIDR_RE,
            PUBLIC_WILDCARD_SOURCE_RE,
            PUBLIC_NETWORK_ACCESS_RE,
            PUBLIC_NETWORK_ACCESS_TF_RE,
        )
    )


def block_has_public_exposure(block_lines: list[str]) -> bool:
    in_public_list = False
    for line in block_lines:
        if line_has_public_exposure(line):
            return True
        if PUBLIC_LIST_KEY_RE.search(line):
            if PUBLIC_LIST_VALUE_RE.search(line):
                return True
            in_public_list = True
        elif in_public_list and PUBLIC_LIST_VALUE_RE.search(line.strip()):
            return True
        if in_public_list and "]" in strip_string_literals(line):
            in_public_list = False
    return False


def is_public_list_value(lines: list[str], line_index: int) -> bool:
    if not PUBLIC_LIST_VALUE_RE.search(lines[line_index].strip()):
        return False
    if PUBLIC_LIST_KEY_RE.search(lines[line_index]):
        return True
    for index in range(line_index - 1, -1, -1):
        stripped = lines[index].strip()
        structural = strip_string_literals(lines[index])
        if PUBLIC_LIST_KEY_RE.search(lines[index]):
            return True
        if GENERIC_LIST_ASSIGNMENT_RE.search(lines[index]) or "]" in structural:
            return False
        if stripped.startswith("}") or re.match(r"^\s*(?:resource|module|data)\b.*[{]\s*$", lines[index]):
            return False
    return False


def context_has_public_exposure(lines: list[str], line_index: int) -> bool:
    """Approximate whether a line is in the same IaC block/object as public exposure."""
    if line_has_public_exposure(lines[line_index]):
        return True

    start = 0
    for index in range(line_index - 1, -1, -1):
        stripped = lines[index].strip()
        if stripped.startswith("}"):
            start = index + 1
            break
        if re.match(r"^\s*(?:resource|module|data)\b.*[{]\s*$", lines[index]):
            start = index
            break

    end = len(lines)
    for index in range(line_index + 1, len(lines)):
        if lines[index].strip().startswith("}"):
            end = index + 1
            break

    return block_has_public_exposure(lines[start:end])


def main(argv: list[str]) -> int:
    roots = [Path(arg) for arg in argv] if argv else [Path.cwd()]
    findings: list[tuple[str, int, str, str]] = []
    errors: list[str] = []
    files_scanned = 0

    for root in roots:
        if not root.exists():
            errors.append(f"path does not exist: {root}")
            continue
        for file_path in iter_iac_files(root):
            files_scanned += 1
            if is_terraform_state_file(file_path):
                findings.append((str(file_path), 0, "Terraform state file must not be committed", "[filename only; contents not read]"))
                continue
            secret_json_depth = 0
            secret_hcl_depth = 0
            secret_bicep_depth = 0
            role_definition_id_context_remaining = 0
            destination_port_context_depth = 0
            pending_bicep_secure_param = False
            try:
                lines = file_path.read_text(errors="ignore").splitlines()
            except OSError as exc:
                findings.append((str(file_path), 0, "read error", str(exc)))
                continue
            json_secret_lines = secret_json_line_numbers(lines) if is_json_like_file(file_path) else set()
            for i, line in enumerate(lines, start=1):
                stripped = line.strip()
                if BICEP_SECURE_DECORATOR_RE.match(stripped):
                    pending_bicep_secure_param = True
                    continue

                starts_secret_json_context = JSON_SECRET_OBJECT_RE.search(line) is not None
                starts_secure_json_type_context = JSON_SECURE_TYPE_RE.search(line) is not None
                starts_secret_hcl_context = (
                    HCL_SECRET_VARIABLE_RE.search(line) is not None
                    or HCL_SECRET_OBJECT_RE.search(line) is not None
                )
                bicep_param = BICEP_ANY_PARAM_RE.search(line)
                bicep_param_has_default = bicep_param is not None and re.search(r"\s=\s", line) is not None
                bicep_param_after_secure = pending_bicep_secure_param and bicep_param is not None
                bicep_secure_param_with_default = bicep_param_after_secure and bicep_param_has_default
                bicep_secret_param = BICEP_SECRET_PARAM_RE.search(line) is not None
                starts_secret_bicep_context = bicep_secure_param_with_default or (bicep_secret_param and bicep_param_has_default)

                line_secret_like = (
                    i in json_secret_lines
                    or secret_json_depth > 0
                    or secret_hcl_depth > 0
                    or secret_bicep_depth > 0
                    or starts_secret_json_context
                    or starts_secure_json_type_context
                    or starts_secret_hcl_context
                    or bicep_secure_param_with_default
                    or line_has_secret_like_pattern(line)
                    or SECRET_ASSIGNMENT_RE.search(line) is not None
                    or (bicep_secret_param and bicep_param_has_default)
                )

                if bicep_secure_param_with_default:
                    findings.append((str(file_path), i, "Bicep @secure parameter", redact_excerpt(line, True)))

                if role_definition_id_context_remaining > 0 and not ROLE_DEFINITION_ID_KEY_RE.search(line):
                    if label := rbac_guid_label(line):
                        findings.append((str(file_path), i, label, redact_excerpt(line, line_secret_like)))

                for rule in PATTERNS:
                    if rule.pattern.search(line):
                        if rule.label == "long token-like assignment" and NON_SECRET_LONG_VALUE_KEY_RE.search(line):
                            continue
                        # Redact globally for the line if it contains any secret-like assignment/context,
                        # even when the matching rule is non-secret (e.g. a secret value equals "Owner").
                        excerpt = redact_excerpt(line, rule.secret_like or line_secret_like)
                        findings.append((str(file_path), i, rule.label, excerpt))

                if is_public_list_value(lines, i - 1):
                    findings.append((str(file_path), i, "public wildcard source", redact_excerpt(line, line_secret_like)))

                if context_has_public_exposure(lines, i - 1):
                    label = dangerous_public_port_range_label(line)
                    if label is None and destination_port_context_depth > 0:
                        label = dangerous_port_value_label(line)
                    if label:
                        findings.append((str(file_path), i, label, redact_excerpt(line, line_secret_like)))

                structural_line = strip_string_literals(line)
                if DESTINATION_PORT_KEY_RE.search(line):
                    destination_port_context_depth = max(0, hcl_delta(line))
                elif destination_port_context_depth > 0:
                    destination_port_context_depth += hcl_delta(line)
                    if destination_port_context_depth <= 0:
                        destination_port_context_depth = 0

                if ROLE_DEFINITION_ID_KEY_RE.search(line):
                    role_definition_id_context_remaining = 6
                elif role_definition_id_context_remaining > 0:
                    role_definition_id_context_remaining -= 1
                    if ")" in structural_line or "]" in structural_line or "}" in structural_line:
                        role_definition_id_context_remaining = 0

                delta = brace_delta(line)
                if starts_secret_json_context or starts_secure_json_type_context or secret_json_depth > 0:
                    if starts_secure_json_type_context and secret_json_depth == 0:
                        secret_json_depth = 1
                    secret_json_depth += delta
                    if secret_json_depth < 0:
                        secret_json_depth = 0
                if starts_secret_hcl_context or secret_hcl_depth > 0:
                    secret_hcl_depth += hcl_delta(line)
                    if secret_hcl_depth < 0:
                        secret_hcl_depth = 0
                if starts_secret_bicep_context or secret_bicep_depth > 0:
                    secret_bicep_depth += delta
                    if secret_bicep_depth < 0:
                        secret_bicep_depth = 0

                if pending_bicep_secure_param and stripped:
                    if bicep_param_after_secure:
                        pending_bicep_secure_param = False
                    elif BICEP_ANY_DECORATOR_RE.match(stripped) or stripped.startswith("//"):
                        pending_bicep_secure_param = True
                    else:
                        pending_bicep_secure_param = False

    if errors:
        print("Scan input errors:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 2

    print(f"files_scanned={files_scanned}")
    if files_scanned == 0:
        print("No IaC files were scanned; check the path or file extension.", file=sys.stderr)
        return 2

    if not findings:
        print("No obvious static risk patterns found. This does not replace validate/plan/review.")
        return 0

    print("Static risk findings:")
    for path, line_no, label, excerpt in findings:
        print(f"- {path}:{line_no}: {label}: {excerpt}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
