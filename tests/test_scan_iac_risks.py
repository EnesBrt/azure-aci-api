from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "scripts" / "scan_iac_risks.py"


def run_scanner(path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCANNER), str(path)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def test_scans_tfvars_example_and_redacts_secret(tmp_path: Path) -> None:
    tfvars_example = tmp_path / "terraform.tfvars.example"
    tfvars_example.write_text('client_secret = "super-secret-value"\n')

    result = run_scanner(tfvars_example)

    assert result.returncode == 1
    assert "files_scanned=1" in result.stdout
    assert "[REDACTED]" in result.stdout
    assert "super-secret-value" not in result.stdout


def test_flags_public_wildcard_dangerous_postgres_port(tmp_path: Path) -> None:
    rule = tmp_path / "public_pg.tf"
    rule.write_text(
        """resource "azurerm_network_security_rule" "pg" {
  source_address_prefix  = "*"
  destination_port_range = "5432"
}
"""
    )

    result = run_scanner(rule)

    assert result.returncode == 1
    assert "public" in result.stdout.lower()
    assert "5432" in result.stdout or "PostgreSQL" in result.stdout


def test_flags_public_wildcard_all_port_range(tmp_path: Path) -> None:
    rule = tmp_path / "public_all.tf"
    rule.write_text(
        """resource "azurerm_network_security_rule" "all" {
  source_address_prefix  = "*"
  destination_port_range = "*"
}
"""
    )

    result = run_scanner(rule)

    assert result.returncode == 1
    assert "all destination ports" in result.stdout


def test_flags_public_numeric_range_containing_dangerous_port(tmp_path: Path) -> None:
    rule = tmp_path / "public_range.tf"
    rule.write_text(
        """resource "azurerm_network_security_rule" "all" {
  source_address_prefix  = "*"
  destination_port_range = "1-65535"
}
"""
    )

    result = run_scanner(rule)

    assert result.returncode == 1
    assert "range includes dangerous" in result.stdout


def test_flags_long_multiline_public_destination_port_list(tmp_path: Path) -> None:
    rule = tmp_path / "public_long_ports.tf"
    rule.write_text(
        """resource "azurerm_network_security_rule" "pg" {
  source_address_prefix = "*"
  destination_port_ranges = [
    "80",
    "81",
    "82",
    "83",
    "84",
    "85",
    "5432"
  ]
}
"""
    )

    result = run_scanner(rule)

    assert result.returncode == 1
    assert "PostgreSQL" in result.stdout


def test_flags_public_wildcard_array_forms(tmp_path: Path) -> None:
    hcl_rule = tmp_path / "public_sql.tf"
    hcl_rule.write_text(
        """resource "azurerm_network_security_rule" "sql" {
  source_address_prefixes  = ["Internet"]
  destination_port_range = "1433"
}
"""
    )
    json_rule = tmp_path / "cors.json"
    json_rule.write_text('{"allowedOrigins": ["*"]}\n')

    hcl_result = run_scanner(hcl_rule)
    json_result = run_scanner(json_rule)

    assert hcl_result.returncode == 1
    assert "public wildcard source" in hcl_result.stdout
    assert "1433" in hcl_result.stdout or "SQL Server" in hcl_result.stdout
    assert json_result.returncode == 1
    assert "public wildcard source" in json_result.stdout


def test_flags_multiline_public_array_with_dangerous_port(tmp_path: Path) -> None:
    hcl_rule = tmp_path / "public_pg.tf"
    hcl_rule.write_text(
        """resource "azurerm_network_security_rule" "pg" {
  source_address_prefixes = [
    "Internet"
  ]
  destination_port_range = "5432"
}
"""
    )

    result = run_scanner(hcl_rule)

    assert result.returncode == 1
    assert "public wildcard source" in result.stdout
    assert "PostgreSQL" in result.stdout


def test_flags_public_wildcard_later_in_same_line_array(tmp_path: Path) -> None:
    hcl_rule = tmp_path / "public_pg.tf"
    hcl_rule.write_text(
        """resource "azurerm_network_security_rule" "pg" {
  source_address_prefixes = ["10.0.0.0/8", "Internet"]
  destination_port_range = "5432"
}
"""
    )

    result = run_scanner(hcl_rule)

    assert result.returncode == 1
    assert "public wildcard source" in result.stdout
    assert "PostgreSQL" in result.stdout


def test_flags_terraform_allowed_origins_wildcard(tmp_path: Path) -> None:
    hcl_rule = tmp_path / "cors.tf"
    hcl_rule.write_text(
        """resource "azurerm_storage_account" "demo" {
  cors_rule {
    allowed_origins = ["*"]
  }
}
"""
    )

    result = run_scanner(hcl_rule)

    assert result.returncode == 1
    assert "public wildcard source" in result.stdout


def test_flags_multiline_terraform_allowed_origins_wildcard(tmp_path: Path) -> None:
    hcl_rule = tmp_path / "cors.tf"
    hcl_rule.write_text(
        """resource "azurerm_storage_account" "demo" {
  cors_rule {
    allowed_origins = [
      "https://example.com",
      "*"
    ]
  }
}
"""
    )

    result = run_scanner(hcl_rule)

    assert result.returncode == 1
    assert "public wildcard source" in result.stdout


def test_unrelated_wildcard_list_after_private_source_list_is_not_public_source(tmp_path: Path) -> None:
    rule = tmp_path / "private_source_then_unrelated_wildcard.tf"
    rule.write_text(
        """resource "azurerm_network_security_rule" "example" {
  source_address_prefixes = [
    "10.0.0.0/8"
  ]
  destination_port_ranges = [
    "*"
  ]
}
"""
    )

    result = run_scanner(rule)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "public wildcard source" not in result.stdout


def test_private_dangerous_port_is_not_flagged_as_public_exposure(tmp_path: Path) -> None:
    rule = tmp_path / "private_pg.tf"
    rule.write_text(
        """resource "azurerm_network_security_rule" "pg" {
  source_address_prefix  = "10.0.0.0/8"
  destination_port_range = "5432"
}
"""
    )

    result = run_scanner(rule)

    assert result.returncode == 0
    assert "5432" not in result.stdout


def test_public_rule_does_not_taint_private_dangerous_port_rule(tmp_path: Path) -> None:
    rule = tmp_path / "mixed_rules.tf"
    rule.write_text(
        """resource "azurerm_network_security_rule" "public_http" {
  source_address_prefix  = "*"
  destination_port_range = "80"
}

resource "azurerm_network_security_rule" "private_pg" {
  source_address_prefix  = "10.0.0.0/8"
  destination_port_range = "5432"
}
"""
    )

    result = run_scanner(rule)

    assert result.returncode == 1
    assert "public wildcard source" in result.stdout
    assert "5432" not in result.stdout
    assert "PostgreSQL" not in result.stdout


def test_public_rule_priority_number_is_not_treated_as_destination_port(tmp_path: Path) -> None:
    rule = tmp_path / "public_http.tf"
    rule.write_text(
        """resource "azurerm_network_security_rule" "public_http" {
  source_address_prefix  = "*"
  destination_port_range = "80"
  priority = 3389
}
"""
    )

    result = run_scanner(rule)

    assert result.returncode == 1
    assert "public wildcard source" in result.stdout
    assert "RDP" not in result.stdout
    assert "3389" not in result.stdout


def test_owner_tag_is_not_broad_rbac_finding(tmp_path: Path) -> None:
    tf_file = tmp_path / "tags.tf"
    tf_file.write_text('tags = { owner = "platform" }\n')

    result = run_scanner(tf_file)

    assert result.returncode == 0
    assert "broad RBAC Owner" not in result.stdout


def test_flags_broad_rbac_role_definition_id_guids(tmp_path: Path) -> None:
    tf_file = tmp_path / "rbac.tf"
    tf_file.write_text(
        """resource "azurerm_role_assignment" "owner" {
  role_definition_id = "/subscriptions/000/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
}
resource "azurerm_role_assignment" "contributor" {
  role_definition_id = "/subscriptions/000/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"
}
resource "azurerm_role_assignment" "uaa" {
  role_definition_id = "/subscriptions/000/providers/Microsoft.Authorization/roleDefinitions/f1a07417-d97a-45cb-824c-7a7467783830"
}
"""
    )

    result = run_scanner(tf_file)

    assert result.returncode == 1
    assert "broad RBAC Owner" in result.stdout
    assert "broad RBAC Contributor" in result.stdout
    assert "User Access Administrator" in result.stdout
    assert "long token-like assignment" not in result.stdout


def test_flags_multiline_role_definition_id_guid(tmp_path: Path) -> None:
    bicep_file = tmp_path / "rbac.bicep"
    bicep_file.write_text(
        """resource roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, 'owner')
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
    )
  }
}
"""
    )

    result = run_scanner(bicep_file)

    assert result.returncode == 1
    assert "broad RBAC Owner" in result.stdout


def test_flags_public_storage_container_access_forms(tmp_path: Path) -> None:
    tf_file = tmp_path / "storage.tf"
    tf_file.write_text('container_access_type = "container"\n')
    arm_file = tmp_path / "storage.json"
    arm_file.write_text('{"publicAccess": "Blob"}\n')

    tf_result = run_scanner(tf_file)
    arm_result = run_scanner(arm_file)

    assert tf_result.returncode == 1
    assert "public storage container access" in tf_result.stdout
    assert arm_result.returncode == 1
    assert "public storage container access" in arm_result.stdout


def test_private_storage_container_access_is_not_flagged(tmp_path: Path) -> None:
    tf_file = tmp_path / "storage.tf"
    tf_file.write_text('container_access_type = "private"\n')
    arm_file = tmp_path / "storage.json"
    arm_file.write_text('{"publicAccess": "None"}\n')

    assert run_scanner(tf_file).returncode == 0
    assert run_scanner(arm_file).returncode == 0


def test_flags_bearer_values_with_redaction(tmp_path: Path) -> None:
    secret_value = tmp_path / "bearer.tf"
    secret_value.write_text('auth_header = "Bearer abc.def.ghi"\n')

    result = run_scanner(secret_value)

    assert result.returncode == 1
    assert "[REDACTED]" in result.stdout
    assert "abc.def.ghi" not in result.stdout


def test_non_secret_findings_on_secret_lines_are_redacted(tmp_path: Path) -> None:
    rule = tmp_path / "public_with_sas.tf"
    rule.write_text('source_address_prefix = "0.0.0.0/0" # sig=abcdef1234567890\n')

    result = run_scanner(rule)

    assert result.returncode == 1
    assert "public IPv4 CIDR" in result.stdout
    assert "abcdef1234567890" not in result.stdout
    assert "[REDACTED]" in result.stdout


def test_mixed_same_line_secret_context_redacts_all_secret_values(tmp_path: Path) -> None:
    secret_value = tmp_path / "headers.tf"
    secret_value.write_text('headers = { Authorization = "Bearer abc.def.ghi", client_secret = "x" }\n')

    result = run_scanner(secret_value)

    assert result.returncode == 1
    assert "[REDACTED]" in result.stdout
    assert "abc.def.ghi" not in result.stdout
    assert 'client_secret = "x"' not in result.stdout


def test_quoted_secret_assignment_with_delimiters_is_fully_redacted(tmp_path: Path) -> None:
    secret_value = tmp_path / "terraform.tfvars.example"
    secret_value.write_text('client_secret = "abc,def]ghi#jkl"\n')

    result = run_scanner(secret_value)

    assert result.returncode == 1
    assert "[REDACTED]" in result.stdout
    for fragment in ("abc", "def", "ghi", "jkl"):
        assert fragment not in result.stdout


def test_compound_secret_assignments_are_fully_redacted(tmp_path: Path) -> None:
    secret_value = tmp_path / "terraform.tfvars.example"
    secret_value.write_text(
        'client_secret = ["abc", "def"]\napi_key = { primary = "ghi", secondary = "jkl" }\n'
    )

    result = run_scanner(secret_value)

    assert result.returncode == 1
    assert "[REDACTED]" in result.stdout
    for fragment in ("abc", "def", "ghi", "jkl"):
        assert fragment not in result.stdout


def test_flags_quoted_json_public_network_access(tmp_path: Path) -> None:
    template = tmp_path / "template.json"
    template.write_text('{"publicNetworkAccess": "Enabled"}\n')

    result = run_scanner(template)

    assert result.returncode == 1
    assert "public network access enabled" in result.stdout.lower()


def test_flags_snake_case_public_network_access_enum(tmp_path: Path) -> None:
    tf_file = tmp_path / "public_network.tf"
    tf_file.write_text('public_network_access = "Enabled"\n')

    result = run_scanner(tf_file)

    assert result.returncode == 1
    assert "public network access enabled" in result.stdout.lower()


def test_secure_bicep_parameter_declaration_without_default_is_not_finding(tmp_path: Path) -> None:
    bicep = tmp_path / "main.bicep"
    bicep.write_text("@secure()\nparam adminPassword string\n")

    result = run_scanner(bicep)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "adminPassword" not in result.stdout


def test_flags_shared_access_signature_secret_with_redaction(tmp_path: Path) -> None:
    tfvars = tmp_path / "terraform.tfvars"
    tfvars.write_text('shared_access_signature = "sv=2024-01-01&sig=abcdef123456"\n')

    result = run_scanner(tfvars)

    assert result.returncode == 1
    assert "[REDACTED]" in result.stdout
    assert "abcdef123456" not in result.stdout


def test_secure_json_object_scans_without_traceback_and_redacts(tmp_path: Path) -> None:
    parameters = tmp_path / "parameters.json"
    parameters.write_text(
        '{"parameters":{"adminPassword":{"type":"secureString","value":"do-not-print"}}}\n'
    )

    result = run_scanner(parameters)

    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    assert "[REDACTED]" in result.stdout
    assert "do-not-print" not in result.stdout


def test_escaped_json_secret_values_are_fully_redacted(tmp_path: Path) -> None:
    parameters = tmp_path / "parameters.json"
    parameters.write_text(
        '{"parameters":{"adminPassword":{"type":"secureString","value":"abc\\\"def-secret\\\\tail"}}}\n'
    )

    result = run_scanner(parameters)

    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    assert "[REDACTED]" in result.stdout
    for fragment in ("abc", "def-secret", "tail"):
        assert fragment not in result.stdout


def test_flags_tfstate_by_filename_without_printing_contents(tmp_path: Path) -> None:
    state = tmp_path / "terraform.tfstate"
    state.write_text('{"outputs":{"client_secret":{"value":"leaked-secret"}}}')

    result = run_scanner(state)

    assert result.returncode == 1
    assert "Terraform state file" in result.stdout
    assert "terraform.tfstate" in result.stdout
    assert "leaked-secret" not in result.stdout


def test_workspace_scan_skips_sensitive_plan_artifacts(tmp_path: Path) -> None:
    iac_dir = tmp_path / "iac"
    iac_dir.mkdir()
    (iac_dir / "main.bicep").write_text("param location string = resourceGroup().location\n")
    plans_dir = tmp_path / "plans"
    plans_dir.mkdir()
    (plans_dir / "bicep-dev-what-if.json").write_text(
        '{"status":"Succeeded","properties":{"changes":[{"changeType":"Modify","after":{"publicNetworkAccess":"Enabled","secretField":"do-not-print"}}]}}\n'
    )
    (plans_dir / "plan.json").write_text(
        '{"status":"Succeeded","properties":{"changes":[{"changeType":"Modify","after":{"clientSecret":"also-do-not-print"}}]}}\n'
    )

    result = run_scanner(tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "files_scanned=1" in result.stdout
    assert "bicep-dev-what-if.json" not in result.stdout
    assert "plan.json" not in result.stdout
    assert "do-not-print" not in result.stdout
    assert "also-do-not-print" not in result.stdout
    assert "publicNetworkAccess" not in result.stdout


def test_workspace_scan_flags_tfstate_even_under_plans_without_printing_contents(tmp_path: Path) -> None:
    iac_dir = tmp_path / "iac"
    iac_dir.mkdir()
    (iac_dir / "main.bicep").write_text("param location string = resourceGroup().location\n")
    plans_dir = tmp_path / "plans"
    plans_dir.mkdir()
    (plans_dir / "terraform.tfstate").write_text('{"outputs":{"client_secret":{"value":"leaked-secret"}}}')

    result = run_scanner(tmp_path)

    assert result.returncode == 1
    assert "Terraform state file" in result.stdout
    assert "terraform.tfstate" in result.stdout
    assert "leaked-secret" not in result.stdout


def test_workspace_scan_does_not_skip_iac_source_under_plans_directory(tmp_path: Path) -> None:
    iac_dir = tmp_path / "iac"
    iac_dir.mkdir()
    (iac_dir / "main.bicep").write_text("param location string = resourceGroup().location\n")
    plans_dir = tmp_path / "plans"
    plans_dir.mkdir()
    (plans_dir / "main.tf").write_text('client_secret = "super-secret"\n')

    result = run_scanner(tmp_path)

    assert result.returncode == 1
    assert "files_scanned=2" in result.stdout
    assert "main.tf" in result.stdout
    assert "super-secret" not in result.stdout


def test_scans_bicepparam_files_and_templates(tmp_path: Path) -> None:
    bicepparam = tmp_path / "parameters.dev.bicepparam"
    bicepparam.write_text("using './main.bicep'\nparam adminPassword = 'super-secret'\n")
    bicepparam_template = tmp_path / "parameters.dev.bicepparam.template"
    bicepparam_template.write_text("using './main.bicep'\nparam clientSecret = 'do-not-print'\n")

    result = run_scanner(tmp_path)

    assert result.returncode == 1
    assert "files_scanned=2" in result.stdout
    assert "parameters.dev.bicepparam" in result.stdout
    assert "parameters.dev.bicepparam.template" in result.stdout
    assert "super-secret" not in result.stdout
    assert "do-not-print" not in result.stdout


def test_repository_templates_scan_clean() -> None:
    result = run_scanner(ROOT / "templates")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "files_scanned=16" in result.stdout
    assert "No obvious static risk patterns found" in result.stdout


def test_scans_compound_template_iac_files(tmp_path: Path) -> None:
    template_dir = tmp_path / "templates"
    template_dir.mkdir()
    (template_dir / "main.tf.template").write_text('client_secret = "super-secret"\n')
    (template_dir / "parameters.dev.json.template").write_text(
        '{"parameters":{"adminPassword":{"type":"secureString","value":"do-not-print"}}}\n'
    )
    (template_dir / "gitignore.template").write_text('client_secret = "ignored"\n')

    result = run_scanner(template_dir)

    assert result.returncode == 1
    assert "files_scanned=2" in result.stdout
    assert "main.tf.template" in result.stdout
    assert "parameters.dev.json.template" in result.stdout
    assert "gitignore.template" not in result.stdout
    assert "super-secret" not in result.stdout
    assert "do-not-print" not in result.stdout
