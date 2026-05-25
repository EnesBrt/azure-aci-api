from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLAN_HASH = ROOT / "scripts" / "plan_hash.py"
DEFAULT_TARGET_ARGS = ["--subscription-id", "00000000-0000-0000-0000-000000000000", "--resource-group", "rg-demo"]


def run_plan_hash(
    engine: str,
    *paths: Path,
    scope: str = "resource-group",
    target_args: list[str] | None = DEFAULT_TARGET_ARGS,
    extra_args: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(PLAN_HASH),
            "--engine",
            engine,
            "--environment",
            "dev",
            "--scope",
            scope,
            "--deployment-name",
            "demo",
            *(target_args or []),
            *(extra_args or []),
            *(str(path) for path in paths),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def write_representative_tfplan_json(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "format_version": "1.2",
                "terraform_version": "1.9.0",
                "planned_values": {"root_module": {}},
                "configuration": {"root_module": {}},
                "resource_changes": [
                    {
                        "address": "azurerm_resource_group.demo",
                        "mode": "managed",
                        "type": "azurerm_resource_group",
                        "name": "demo",
                        "change": {"actions": ["create"]},
                    }
                ],
            }
        )
    )


def write_representative_azure_what_if(path: Path, *, status: str = "Succeeded") -> None:
    path.write_text(
        json.dumps(
            {
                "status": status,
                "properties": {
                    "changes": [
                        {
                            "changeType": "Create",
                            "resourceId": "/subscriptions/000/resourceGroups/rg/providers/Microsoft.ContainerInstance/containerGroups/demo",
                            "after": {"apiVersion": "2023-05-01"},
                        }
                    ]
                },
            }
        )
    )


def write_representative_bicep_artifacts(tmp_path: Path) -> list[Path]:
    source = tmp_path / "main.bicep"
    source.write_text("resource demo 'Microsoft.Resources/resourceGroups@2024-03-01' existing = { name: 'rg-demo' }\n")
    compiled = tmp_path / "main.json"
    compiled.write_text(
        json.dumps(
            {
                "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                "contentVersion": "1.0.0.0",
                "parameters": {"location": {"type": "string"}},
                "resources": [],
            }
        )
    )
    parameters = tmp_path / "parameters.dev.json"
    parameters.write_text(
        json.dumps(
            {
                "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
                "contentVersion": "1.0.0.0",
                "parameters": {"location": {"value": "westeurope"}},
            }
        )
    )
    what_if = tmp_path / "bicep-dev-what-if.json"
    write_representative_azure_what_if(what_if)
    return [source, compiled, parameters, what_if]


def test_rejects_resource_group_scope_without_target_metadata(tmp_path: Path) -> None:
    tfplan_json = tmp_path / "tfplan.json"
    write_representative_tfplan_json(tfplan_json)

    result = run_plan_hash("terraform", tfplan_json, target_args=[], extra_args=["--review-only-json-plan"])

    assert result.returncode == 2
    assert "subscription" in result.stderr.lower()
    assert "resource group" in result.stderr.lower()


def test_missing_input_path_returns_clean_error() -> None:
    missing = ROOT / "does-not-exist.tfplan.json"

    result = run_plan_hash("terraform", missing, extra_args=["--review-only-json-plan"])

    assert result.returncode == 2
    assert "Plan manifest input error" in result.stderr
    assert "Traceback" not in result.stderr


def test_invalid_root_returns_clean_error(tmp_path: Path) -> None:
    tfplan_json = tmp_path / "tfplan.json"
    write_representative_tfplan_json(tfplan_json)

    result = run_plan_hash(
        "terraform",
        tfplan_json,
        extra_args=["--review-only-json-plan", "--root", str(tmp_path / "missing-root")],
    )

    assert result.returncode == 2
    assert "--root" in result.stderr
    assert "Traceback" not in result.stderr


def test_target_metadata_changes_manifest_digest(tmp_path: Path) -> None:
    tfplan_json = tmp_path / "tfplan.json"
    write_representative_tfplan_json(tfplan_json)

    first = run_plan_hash("terraform", tfplan_json, extra_args=["--review-only-json-plan"])
    second = run_plan_hash(
        "terraform",
        tfplan_json,
        target_args=["--subscription-id", "00000000-0000-0000-0000-000000000000", "--resource-group", "rg-other"],
        extra_args=["--review-only-json-plan"],
    )

    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    assert json.loads(first.stdout)["digest"] != json.loads(second.stdout)["digest"]


def test_rejects_minimal_terraform_json_plan(tmp_path: Path) -> None:
    fake_plan = tmp_path / "tfplan.json"
    fake_plan.write_text(json.dumps({"resource_changes": []}))

    result = run_plan_hash("terraform", fake_plan)

    assert result.returncode == 2
    assert "Terraform/OpenTofu" in result.stderr


def test_rejects_hand_written_minimal_terraform_review_json(tmp_path: Path) -> None:
    fake_plan = tmp_path / "tfplan.json"
    fake_plan.write_text(
        json.dumps(
            {
                "format_version": "1.2",
                "terraform_version": "1.9.0",
                "planned_values": {},
                "configuration": {},
                "resource_changes": [],
            }
        )
    )

    result = run_plan_hash("terraform", fake_plan, extra_args=["--review-only-json-plan"])

    assert result.returncode == 2
    assert "planned_values.root_module" in result.stderr


def test_rejects_invalid_utf8_plan_json(tmp_path: Path) -> None:
    tfplan_json = tmp_path / "tfplan.json"
    write_representative_tfplan_json(tfplan_json)
    tfplan_json.write_bytes(tfplan_json.read_bytes() + b"\xff")

    result = run_plan_hash("terraform", tfplan_json, extra_args=["--review-only-json-plan"])

    assert result.returncode == 2
    assert "UTF-8" in result.stderr or "invalid" in result.stderr.lower()


def test_rejects_terraform_json_only_for_apply_bound_hash(tmp_path: Path) -> None:
    tfplan_json = tmp_path / "tfplan.json"
    write_representative_tfplan_json(tfplan_json)

    result = run_plan_hash("terraform", tfplan_json)

    assert result.returncode == 2
    assert "binary" in result.stderr.lower()


def test_accepts_representative_terraform_json_plan_for_review_only(tmp_path: Path) -> None:
    tfplan_json = tmp_path / "tfplan.json"
    write_representative_tfplan_json(tfplan_json)

    result = run_plan_hash("terraform", tfplan_json, extra_args=["--review-only-json-plan"])

    assert result.returncode == 0, result.stderr
    manifest = json.loads(result.stdout)
    assert manifest["plan_artifacts"] == ["tfplan.json"]
    assert manifest["metadata"]["resource_group"] == "rg-demo"


def test_rejects_unverified_terraform_binary_plan_even_with_valid_json(tmp_path: Path) -> None:
    binary_plan = tmp_path / "tfplan"
    binary_plan.write_bytes(b"opaque terraform plan")
    tfplan_json = tmp_path / "tfplan.json"
    write_representative_tfplan_json(tfplan_json)

    result = run_plan_hash("terraform", binary_plan, tfplan_json)

    assert result.returncode == 2
    assert "verify" in result.stderr.lower() or "terraform show" in result.stderr.lower()


def test_accepts_verified_terraform_binary_plan_with_matching_json(tmp_path: Path, monkeypatch) -> None:
    binary_plan = tmp_path / "tfplan"
    binary_plan.write_bytes(b"opaque terraform plan")
    tfplan_json = tmp_path / "tfplan.json"
    write_representative_tfplan_json(tfplan_json)
    plan_payload = tfplan_json.read_text()

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_terraform = fake_bin / "terraform"
    fake_terraform.write_text(
        "#!/usr/bin/env python3\n"
        "import pathlib\n"
        "import sys\n"
        "if len(sys.argv) == 4 and sys.argv[1:3] == ['show', '-json'] and pathlib.Path(sys.argv[3]).exists():\n"
        f"    sys.stdout.write({plan_payload!r})\n"
        "    raise SystemExit(0)\n"
        "raise SystemExit(1)\n"
    )
    fake_terraform.chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}")

    result = run_plan_hash("terraform", binary_plan, tfplan_json)

    assert result.returncode == 0, result.stderr
    manifest = json.loads(result.stdout)
    assert set(manifest["plan_artifacts"]) == {"tfplan", "tfplan.json"}


def test_rejects_bicep_non_json_plan_file(tmp_path: Path) -> None:
    fake_plan = tmp_path / "plan"
    fake_plan.write_text("not an Azure What-If JSON artifact")

    result = run_plan_hash("bicep", fake_plan)

    assert result.returncode == 2
    assert "What-If" in result.stderr or "plan/what-if" in result.stderr


def test_normal_files_named_plan_are_not_implicit_plan_artifacts(tmp_path: Path) -> None:
    paths = write_representative_bicep_artifacts(tmp_path)
    support_json = tmp_path / "support_plan.json"
    support_json.write_text(json.dumps({"note": "ordinary support file, not What-If"}))
    support_tf = tmp_path / "support_plan.tf"
    support_tf.write_text('variable "name" { type = string }\n')
    tfplan_json = tmp_path / "tfplan.json"
    write_representative_tfplan_json(tfplan_json)

    bicep_result = run_plan_hash("bicep", *paths, support_json)
    tf_result = run_plan_hash("terraform", tfplan_json, support_tf, extra_args=["--review-only-json-plan"])

    assert bicep_result.returncode == 0, bicep_result.stderr
    assert tf_result.returncode == 0, tf_result.stderr
    assert json.loads(bicep_result.stdout)["plan_artifacts"] == ["bicep-dev-what-if.json"]
    assert json.loads(tf_result.stdout)["plan_artifacts"] == ["tfplan.json"]


def test_rejects_terraform_binary_plan_without_json_evidence(tmp_path: Path) -> None:
    binary_plan = tmp_path / "tfplan"
    binary_plan.write_bytes(b"opaque terraform plan")

    result = run_plan_hash("terraform", binary_plan)

    assert result.returncode == 2
    assert "tfplan.json" in result.stderr


def test_rejects_minimal_azure_changes_json(tmp_path: Path) -> None:
    fake_what_if = tmp_path / "bicep-dev-what-if.json"
    fake_what_if.write_text(json.dumps({"changes": []}))

    result = run_plan_hash("bicep", fake_what_if)

    assert result.returncode == 2
    assert "Azure What-If" in result.stderr


def test_rejects_empty_azure_properties_changes_without_provider_envelope(tmp_path: Path) -> None:
    fake_what_if = tmp_path / "bicep-dev-what-if.json"
    fake_what_if.write_text(json.dumps({"properties": {"changes": []}}))

    result = run_plan_hash("bicep", fake_what_if)

    assert result.returncode == 2
    assert "Azure What-If" in result.stderr


def test_rejects_root_level_azure_changes_even_with_succeeded_status(tmp_path: Path) -> None:
    paths = write_representative_bicep_artifacts(tmp_path)
    root_level_what_if = tmp_path / "bicep-dev-what-if.json"
    root_level_what_if.write_text(json.dumps({"status": "Succeeded", "changes": []}))

    result = run_plan_hash("bicep", *paths)

    assert result.returncode == 2
    assert "properties.changes" in result.stderr or "properties envelope" in result.stderr


def test_accepts_representative_azure_what_if_json(tmp_path: Path) -> None:
    paths = write_representative_bicep_artifacts(tmp_path)

    result = run_plan_hash("bicep", *paths)

    assert result.returncode == 0, result.stderr
    manifest = json.loads(result.stdout)
    assert manifest["plan_artifacts"] == ["bicep-dev-what-if.json"]


def test_azure_what_if_digest_ignores_volatile_provider_envelope(tmp_path: Path) -> None:
    paths = write_representative_bicep_artifacts(tmp_path)
    what_if = tmp_path / "bicep-dev-what-if.json"

    first = run_plan_hash("bicep", *paths)
    first_manifest = json.loads(first.stdout)
    what_if.write_text(
        json.dumps(
            {
                "status": "Succeeded",
                "properties": {
                    "provisioningState": "Succeeded",
                    "timestamp": "2099-01-01T00:00:00Z",
                    "duration": "PT9S",
                    "changes": [
                        {
                            "changeType": "Create",
                            "resourceId": "/subscriptions/000/resourceGroups/rg/providers/Microsoft.ContainerInstance/containerGroups/demo",
                            "after": {"apiVersion": "2023-05-01"},
                        }
                    ],
                },
            }
        )
    )

    second = run_plan_hash("bicep", *paths)

    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    second_manifest = json.loads(second.stdout)
    assert first_manifest["digest"] == second_manifest["digest"]
    first_what_if = next(entry for entry in first_manifest["files"] if entry["path"] == "bicep-dev-what-if.json")
    second_what_if = next(entry for entry in second_manifest["files"] if entry["path"] == "bicep-dev-what-if.json")
    assert first_what_if["sha256"] != second_what_if["sha256"]
    assert first_what_if["approval_sha256"] == second_what_if["approval_sha256"]


def test_approval_digest_ignores_workspace_root_and_skipped_files(tmp_path: Path) -> None:
    first_workspace = tmp_path / "first"
    first_workspace.mkdir()
    write_representative_bicep_artifacts(first_workspace)

    first = run_plan_hash("bicep", first_workspace)
    (first_workspace / ".env").write_text("SECRET=do-not-bind\n")
    second = run_plan_hash("bicep", first_workspace)
    second_workspace = tmp_path / "second"
    shutil.copytree(first_workspace, second_workspace)
    third = run_plan_hash("bicep", second_workspace)

    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    assert third.returncode == 0, third.stderr
    first_manifest = json.loads(first.stdout)
    second_manifest = json.loads(second.stdout)
    third_manifest = json.loads(third.stdout)
    assert first_manifest["root"] != third_manifest["root"]
    assert second_manifest["skipped"]
    assert first_manifest["digest"] == second_manifest["digest"] == third_manifest["digest"]


def test_bicepparam_source_is_bound_to_bicep_plan_hash(tmp_path: Path) -> None:
    paths = write_representative_bicep_artifacts(tmp_path)
    bicepparam = tmp_path / "parameters.dev.bicepparam"
    bicepparam.write_text("using './main.bicep'\nparam location = 'westeurope'\n")

    first = run_plan_hash("bicep", *paths, bicepparam)
    bicepparam.write_text("using './main.bicep'\nparam location = 'northeurope'\n")
    second = run_plan_hash("bicep", *paths, bicepparam)

    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    first_manifest = json.loads(first.stdout)
    second_manifest = json.loads(second.stdout)
    assert "parameters.dev.bicepparam" in {entry["path"] for entry in first_manifest["files"]}
    assert first_manifest["digest"] != second_manifest["digest"]


def test_rejects_bicep_what_if_without_apply_bound_artifacts(tmp_path: Path) -> None:
    what_if = tmp_path / "bicep-dev-what-if.json"
    write_representative_azure_what_if(what_if)

    result = run_plan_hash("bicep", what_if)

    assert result.returncode == 2
    assert "compiled ARM JSON" in result.stderr
    assert "bicep_source" in result.stderr


def test_rejects_failed_azure_what_if_status(tmp_path: Path) -> None:
    paths = write_representative_bicep_artifacts(tmp_path)
    what_if = tmp_path / "bicep-dev-what-if.json"
    write_representative_azure_what_if(what_if, status="Failed")

    result = run_plan_hash("bicep", *paths)

    assert result.returncode == 2
    assert "Succeeded" in result.stderr


def test_rejects_weak_root_level_azure_what_if_envelope(tmp_path: Path) -> None:
    fake_what_if = tmp_path / "bicep-dev-what-if.json"
    fake_what_if.write_text(json.dumps({"type": "not-a-what-if", "changes": []}))

    result = run_plan_hash("bicep", fake_what_if)

    assert result.returncode == 2
    assert "Azure What-If" in result.stderr


def test_subscription_scope_bicep_requires_deployment_location(tmp_path: Path) -> None:
    what_if = tmp_path / "bicep-dev-what-if.json"
    write_representative_azure_what_if(what_if)

    result = run_plan_hash(
        "bicep",
        what_if,
        scope="subscription",
        target_args=["--subscription-id", "00000000-0000-0000-0000-000000000000"],
    )

    assert result.returncode == 2
    assert "--location" in result.stderr


def test_subscription_scope_location_changes_manifest_digest(tmp_path: Path) -> None:
    paths = write_representative_bicep_artifacts(tmp_path)
    subscription = "00000000-0000-0000-0000-000000000000"

    first = run_plan_hash(
        "bicep",
        *paths,
        scope="subscription",
        target_args=["--subscription-id", subscription, "--location", "westeurope"],
    )
    second = run_plan_hash(
        "bicep",
        *paths,
        scope="subscription",
        target_args=["--subscription-id", subscription, "--location", "northeurope"],
    )

    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    first_manifest = json.loads(first.stdout)
    second_manifest = json.loads(second.stdout)
    assert first_manifest["metadata"]["location"] == "westeurope"
    assert second_manifest["metadata"]["location"] == "northeurope"
    assert first_manifest["digest"] != second_manifest["digest"]
