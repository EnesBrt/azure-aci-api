#!/usr/bin/env python3
"""Create a manifest-bound SHA-256 identity for IaC plan artifacts.

Usage:
  python scripts/plan_hash.py --engine bicep --environment dev \
    --scope resource-group --subscription-id <subscription-id> --resource-group <resource-group> \
    --deployment-name demo plans/bicep-dev-what-if.json iac/bicep
  python scripts/plan_hash.py --engine terraform --environment dev \
    --scope resource-group --subscription-id <subscription-id> --resource-group <resource-group> \
    --deployment-name demo plans/tfplan plans/tfplan.json iac/terraform

The output is a JSON manifest. It includes per-file hashes, skipped files, engine-specific plan
artifact detection, metadata, and an aggregate digest. File contents are never
printed. By default, at least one real plan/what-if JSON artifact must be included.
Terraform/OpenTofu binary plan files are accepted only when local terraform/tofu
show -json output matches one of the supplied JSON plan artifacts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

SKIP_NAMES = {
    ".terraform",
    ".terragrunt-cache",
    "terraform.tfstate",
    "terraform.tfstate.backup",
    ".env",
}
SKIP_SUFFIXES = {
    ".tfstate",
    ".tfstate.backup",
    ".pem",
    ".pfx",
    ".key",
}
TERRAFORM_PLAN_EXACT_NAMES = {"tfplan", "tfplan.json", "plan"}
TERRAFORM_PLAN_SUFFIXES = {".tfplan"}
TERRAFORM_JSON_PLAN_NAMES = {"tfplan.json", "plan.json"}


def should_skip(path: Path) -> tuple[bool, str | None]:
    parts = set(path.parts)
    matched_names = parts & SKIP_NAMES
    if matched_names:
        return True, f"matched skip name {sorted(matched_names)[0]}"
    name = path.name
    for suffix in SKIP_SUFFIXES:
        if name.endswith(suffix):
            return True, f"matched skip suffix {suffix}"
    return False, None


def terraform_plan_artifact_kind(path: Path) -> str | None:
    name = path.name.lower()
    if name.endswith(".json") and (name in TERRAFORM_JSON_PLAN_NAMES or "tfplan" in name):
        return "terraform_json_plan"
    if name in TERRAFORM_PLAN_EXACT_NAMES or "tfplan" in name:
        return "terraform_binary_plan"
    if any(name.endswith(suffix) for suffix in TERRAFORM_PLAN_SUFFIXES):
        return "terraform_binary_plan"
    return None


def azure_what_if_artifact_kind(path: Path) -> str | None:
    name = path.name.lower()
    if not name.endswith(".json"):
        return None
    if "what-if" in name or "whatif" in name or name == "plan.json":
        return "azure_what_if_json"
    return None


def plan_artifact_kind(path: Path, engine: str) -> str | None:
    if engine in {"terraform", "opentofu"}:
        return terraform_plan_artifact_kind(path)
    if engine in {"bicep", "arm"}:
        return azure_what_if_artifact_kind(path)
    return None


def validate_terraform_plan_json(obj: Any) -> tuple[bool, str | None]:
    if not isinstance(obj, dict):
        return False, "Terraform/OpenTofu plan JSON root must be an object"
    if "format_version" not in obj:
        return False, "Terraform/OpenTofu plan JSON is missing format_version"
    if not any(key in obj for key in {"terraform_version", "opentofu_version", "tofu_version"}):
        return False, "Terraform/OpenTofu plan JSON is missing a Terraform/OpenTofu version field"

    planned_values = obj.get("planned_values")
    if not isinstance(planned_values, dict) or not isinstance(planned_values.get("root_module"), dict):
        return False, "Terraform/OpenTofu plan JSON is missing planned_values.root_module"

    configuration = obj.get("configuration")
    if not isinstance(configuration, dict) or not any(
        isinstance(configuration.get(key), dict) for key in ("root_module", "provider_config")
    ):
        return False, "Terraform/OpenTofu plan JSON is missing configuration.root_module/provider_config"

    resource_changes = obj.get("resource_changes")
    if resource_changes is None:
        return False, "Terraform/OpenTofu plan JSON is missing resource_changes"
    if not isinstance(resource_changes, list):
        return False, "Terraform/OpenTofu resource_changes must be a list"
    for change in resource_changes:
        if not isinstance(change, dict):
            return False, "Terraform/OpenTofu resource_changes entries must be objects"
        for required_key in ("address", "mode", "type", "name", "change"):
            if required_key not in change:
                return False, f"Terraform/OpenTofu resource_changes entries must include {required_key}"
        change_body = change.get("change")
        if not isinstance(change_body, dict):
            return False, "Terraform/OpenTofu resource change.change must be an object"
        actions = change_body.get("actions")
        if not isinstance(actions, list) or not all(isinstance(action, str) for action in actions):
            return False, "Terraform/OpenTofu resource change.actions must be a string list"

    output_changes = obj.get("output_changes")
    if output_changes is not None and not isinstance(output_changes, dict):
        return False, "Terraform/OpenTofu output_changes must be an object"
    checks = obj.get("checks")
    if checks is not None and not isinstance(checks, list):
        return False, "Terraform/OpenTofu checks must be a list"
    return True, None


def validate_azure_what_if_json(obj: Any) -> tuple[bool, str | None]:
    if not isinstance(obj, dict):
        return False, "Azure What-If JSON root must be an object"

    properties = obj.get("properties")
    status = obj.get("status")
    if not isinstance(properties, dict):
        return False, "Azure What-If JSON is missing provider properties envelope"
    provisioning_state = properties.get("provisioningState")
    has_success_status = any(
        isinstance(value, str) and value.lower() == "succeeded" for value in (status, provisioning_state)
    )

    if "changes" not in properties:
        return False, "Azure What-If JSON is missing properties.changes"
    changes = properties["changes"]

    if not isinstance(changes, list):
        return False, "Azure What-If changes must be a list"
    if not has_success_status:
        return False, "Azure What-If JSON must have status/provisioningState Succeeded"
    if not changes:
        return True, None

    for change in changes:
        if not isinstance(change, dict):
            return False, "Azure What-If change entries must be objects"
        if "changeType" not in change:
            return False, "Azure What-If change entries must include changeType"
        if not any(key in change for key in {"resourceId", "before", "after", "delta"}):
            return False, "Azure What-If change entries need resource identity or payload fields"
    return True, None


def validate_json_plan_artifact(path: Path, obj: Any, engine: str) -> tuple[bool, str | None]:
    """Engine-specific shape check so arbitrary JSON cannot satisfy the plan gate."""
    if engine in {"terraform", "opentofu"}:
        return validate_terraform_plan_json(obj)
    if engine in {"bicep", "arm"}:
        return validate_azure_what_if_json(obj)
    return False, "JSON plan artifact has an unrecognized plan shape"


def looks_like_arm_template(obj: Any) -> bool:
    if not isinstance(obj, dict):
        return False
    schema = str(obj.get("$schema", "")).lower()
    if "deploymenttemplate" in schema:
        return True
    return isinstance(obj.get("resources"), list)


def looks_like_arm_parameters(obj: Any) -> bool:
    if not isinstance(obj, dict):
        return False
    schema = str(obj.get("$schema", "")).lower()
    parameters = obj.get("parameters")
    if "deploymentparameters" in schema and isinstance(parameters, dict):
        return True
    if not isinstance(parameters, dict) or "resources" in obj:
        return False
    return all(isinstance(value, dict) and ({"value", "reference"} & set(value)) for value in parameters.values())


def azure_artifact_flags(path: Path, obj: Any | None, engine: str) -> set[str]:
    flags: set[str] = set()
    name = path.name.lower()
    if engine == "bicep" and name.endswith(".bicep"):
        flags.add("bicep_source")
    if obj is not None:
        if looks_like_arm_template(obj):
            flags.add("arm_template")
        if looks_like_arm_parameters(obj):
            flags.add("arm_parameters")
    return flags


def missing_azure_apply_bound_artifacts(flags: set[str], engine: str) -> list[str]:
    required = ["arm_template", "arm_parameters"]
    if engine == "bicep":
        required.insert(0, "bicep_source")
    return [item for item in required if item not in flags]


def canonical_json_payload(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonical_json_digest(obj: Any) -> str:
    return hashlib.sha256(canonical_json_payload(obj)).hexdigest()


def azure_what_if_changes(obj: dict[str, Any]) -> list[Any]:
    properties = obj.get("properties")
    if isinstance(properties, dict) and "changes" in properties:
        changes = properties["changes"]
    else:
        changes = obj.get("changes", [])
    return changes if isinstance(changes, list) else []


def normalized_azure_what_if(obj: dict[str, Any]) -> dict[str, Any]:
    changes = azure_what_if_changes(obj)
    normalized_changes = sorted(changes, key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
    return {"changes": normalized_changes}


def approval_digest_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    """Return the stable approval identity payload.

    The printed manifest keeps local diagnostics such as checkout root and skipped files,
    but those must not affect approval identity. Only target metadata, included reviewed
    artifacts, and detected plan artifacts are part of the approval digest.
    """
    files: list[dict[str, Any]] = []
    for source_entry in manifest.get("files", []):
        entry = dict(source_entry)
        approval_sha256 = entry.pop("approval_sha256", None)
        approval_bytes = entry.pop("approval_bytes", None)
        entry.pop("approval_hash_kind", None)
        if approval_sha256:
            entry["sha256"] = approval_sha256
        if approval_bytes is not None:
            entry["bytes"] = approval_bytes
        files.append(entry)
    return {
        "manifest_version": manifest["manifest_version"],
        "metadata": manifest["metadata"],
        "files": files,
        "plan_artifacts": manifest["plan_artifacts"],
    }


def terraform_show_binary_plan(binary_plan: Path, engine: str) -> tuple[dict[str, Any] | None, str | None]:
    candidates = ["terraform"] if engine == "terraform" else ["tofu", "opentofu"]
    executable = next((candidate for candidate in candidates if shutil.which(candidate)), None)
    if executable is None:
        return None, f"Cannot verify binary plan {binary_plan.name}: {engine} CLI is not available for show -json"

    result = subprocess.run(
        [executable, "show", "-json", str(binary_plan)],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        return None, f"Cannot verify binary plan {binary_plan.name}: {executable} show -json failed with exit {result.returncode}"
    try:
        parsed = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        return None, f"Cannot verify binary plan {binary_plan.name}: {executable} show -json returned invalid JSON: {exc}"
    if not isinstance(parsed, dict):
        return None, f"Cannot verify binary plan {binary_plan.name}: {executable} show -json did not return an object"
    return parsed, None


def collect_files(paths: list[Path]) -> tuple[list[Path], list[dict[str, str]]]:
    files: list[Path] = []
    skipped: list[dict[str, str]] = []
    for path in paths:
        if not path.exists():
            raise FileNotFoundError(path)
        skip, reason = should_skip(path)
        if skip:
            skipped.append({"path": str(path), "reason": reason or "skipped"})
            continue
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            for child in sorted(path.rglob("*")):
                skip_child, child_reason = should_skip(child)
                if skip_child:
                    skipped.append({"path": str(child), "reason": child_reason or "skipped"})
                elif child.is_file():
                    files.append(child)
    return sorted(set(files)), skipped


def common_root(paths: list[Path], explicit_root: str | None) -> Path:
    if explicit_root:
        root = Path(explicit_root).resolve()
        if not root.exists() or not root.is_dir():
            raise ValueError(f"--root must be an existing directory: {root}")
        return root
    anchors: list[str] = []
    for path in paths:
        resolved = path.resolve()
        anchors.append(str(resolved.parent if resolved.is_file() else resolved))
    return Path(os.path.commonpath(anchors)).resolve()


def file_entry(path: Path, root: Path, engine: str) -> tuple[dict[str, Any], bytes]:
    data = path.read_bytes()
    kind = plan_artifact_kind(path, engine)
    try:
        rel = path.resolve().relative_to(root)
    except ValueError:
        rel = path.resolve()
    return {
        "path": str(rel),
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "plan_artifact": kind is not None,
        "plan_artifact_kind": kind,
    }, data


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create a manifest-bound hash for IaC plan artifacts.")
    parser.add_argument("paths", nargs="+", help="Files or directories to include in the manifest")
    parser.add_argument("--root", help="Stable root used for relative paths in the manifest")
    parser.add_argument("--engine", choices=["bicep", "arm", "terraform", "opentofu"], required=True)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--scope", required=True, help="tenant, management-group, subscription, or resource-group")
    parser.add_argument("--deployment-name", required=True)
    parser.add_argument("--deployment-mode", default="Incremental", help="ARM/Bicep deployment mode or Terraform/OpenTofu apply mode note")
    parser.add_argument("--subscription-id", help="Canonical Azure subscription ID for subscription/resource-group scope")
    parser.add_argument("--resource-group", help="Azure resource group name for resource-group scope")
    parser.add_argument("--management-group-id", help="Azure management group ID for management-group scope")
    parser.add_argument("--tenant-id", help="Azure tenant ID for tenant scope or explicit provider tenant binding")
    parser.add_argument("--location", help="Canonical Azure deployment location for subscription/management-group/tenant ARM/Bicep scopes")
    parser.add_argument(
        "--review-only-json-plan",
        action="store_true",
        help="Allow Terraform/OpenTofu tfplan.json-only hashing for review evidence. Do not use as an apply approval gate.",
    )
    parser.add_argument("--allow-no-plan-artifact", action="store_true", help="Allow hashing source-only files. Do not use for apply approval gates.")
    return parser.parse_args(argv)


def validate_target_metadata(args: argparse.Namespace) -> str | None:
    scope = args.scope.lower()
    if scope == "resource-group":
        missing = []
        if not args.subscription_id:
            missing.append("--subscription-id")
        if not args.resource_group:
            missing.append("--resource-group")
        if missing:
            return "resource group scope requires " + " and ".join(missing)
    elif scope == "subscription":
        if not args.subscription_id:
            return "subscription scope requires --subscription-id"
    elif scope == "management-group":
        if not args.management_group_id:
            return "management-group scope requires --management-group-id"
    elif scope == "tenant":
        if not args.tenant_id:
            return "tenant scope requires --tenant-id"
    else:
        return "--scope must be tenant, management-group, subscription, or resource-group"
    if args.engine in {"bicep", "arm"} and scope in {"subscription", "management-group", "tenant"} and not args.location:
        return f"{scope} scope for {args.engine} requires --location"
    return None


def target_metadata(args: argparse.Namespace) -> dict[str, str]:
    metadata = {
        "engine": args.engine,
        "environment": args.environment,
        "scope": args.scope,
        "deployment_name": args.deployment_name,
        "deployment_mode": args.deployment_mode,
    }
    for attr in ("subscription_id", "resource_group", "management_group_id", "tenant_id", "location"):
        value = getattr(args, attr)
        if value:
            metadata[attr] = value
    if args.review_only_json_plan:
        metadata["review_only_json_plan"] = "true"
    return metadata


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    target_error = validate_target_metadata(args)
    if target_error:
        print(target_error, file=sys.stderr)
        return 2

    input_paths = [Path(arg).resolve() for arg in args.paths]
    try:
        root = common_root(input_paths, args.root)
        files, skipped = collect_files(input_paths)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Plan manifest input error: {exc}", file=sys.stderr)
        return 2

    if not files:
        print("No files were included in the plan manifest; refusing to create an empty hash.", file=sys.stderr)
        return 2

    entries: list[dict[str, Any]] = []
    path_by_entry_path: dict[str, Path] = {}
    data_by_entry_path: dict[str, bytes] = {}
    for source_path in files:
        entry, data = file_entry(source_path, root, args.engine)
        entries.append(entry)
        path_by_entry_path[entry["path"]] = source_path
        data_by_entry_path[entry["path"]] = data

    azure_flags: set[str] = set()
    if args.engine in {"bicep", "arm"}:
        for entry in entries:
            parsed_json_for_flags = None
            if str(entry["path"]).lower().endswith(".json"):
                try:
                    parsed_json_for_flags = json.loads(data_by_entry_path[entry["path"]].decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    parsed_json_for_flags = None
            azure_flags.update(azure_artifact_flags(path_by_entry_path[entry["path"]], parsed_json_for_flags, args.engine))

    plan_artifacts = [entry["path"] for entry in entries if entry["plan_artifact"]]
    if not plan_artifacts and not args.allow_no_plan_artifact:
        print(
            "No engine-specific plan/what-if artifact detected. Include tfplan.json from terraform/tofu show -json "
            "for Terraform/OpenTofu, or saved Azure What-If JSON for Bicep/ARM; pass --allow-no-plan-artifact "
            "only for source-only review hashes.",
            file=sys.stderr,
        )
        return 2

    has_valid_json_plan = False
    terraform_json_plan_digests: set[str] = set()
    terraform_binary_plan_paths: list[str] = []
    for entry in entries:
        if not entry["plan_artifact"]:
            continue
        if entry["bytes"] == 0:
            print(f"Plan artifact is empty and cannot bind approval: {entry['path']}", file=sys.stderr)
            return 2
        artifact_kind = entry["plan_artifact_kind"]
        if str(entry["path"]).lower().endswith(".json"):
            try:
                parsed_json = json.loads(data_by_entry_path[entry["path"]].decode("utf-8"))
            except UnicodeDecodeError as exc:
                print(f"Plan artifact JSON is not valid UTF-8: {entry['path']}: {exc}", file=sys.stderr)
                return 2
            except json.JSONDecodeError as exc:
                print(f"Plan artifact JSON is invalid: {entry['path']}: {exc}", file=sys.stderr)
                return 2
            valid_shape, reason = validate_json_plan_artifact(path_by_entry_path[entry["path"]], parsed_json, args.engine)
            if not valid_shape:
                print(f"Plan artifact JSON shape is not recognized: {entry['path']}: {reason}", file=sys.stderr)
                return 2
            has_valid_json_plan = True
            if args.engine in {"terraform", "opentofu"} and artifact_kind == "terraform_json_plan":
                terraform_json_plan_digests.add(canonical_json_digest(parsed_json))
            if args.engine in {"bicep", "arm"} and artifact_kind == "azure_what_if_json":
                normalized_what_if = normalized_azure_what_if(parsed_json)
                entry["approval_sha256"] = canonical_json_digest(normalized_what_if)
                entry["approval_bytes"] = len(canonical_json_payload(normalized_what_if))
                entry["approval_hash_kind"] = "normalized_azure_what_if_changes"
        elif args.engine in {"bicep", "arm"}:
            print(f"Azure What-If plan artifacts must be JSON for {args.engine}: {entry['path']}", file=sys.stderr)
            return 2
        elif args.engine in {"terraform", "opentofu"} and artifact_kind == "terraform_binary_plan":
            terraform_binary_plan_paths.append(entry["path"])

    if plan_artifacts and args.engine in {"bicep", "arm"}:
        missing_azure_artifacts = missing_azure_apply_bound_artifacts(azure_flags, args.engine)
        if missing_azure_artifacts:
            print(
                "Bicep/ARM apply-bound approval hashes require source IaC, compiled ARM JSON, "
                "parameter JSON, and saved successful What-If JSON; missing: "
                + ", ".join(missing_azure_artifacts),
                file=sys.stderr,
            )
            return 2

    if terraform_binary_plan_paths:
        if not terraform_json_plan_digests:
            print(
                "Terraform/OpenTofu binary plans require a matching tfplan.json produced from the same saved plan.",
                file=sys.stderr,
            )
            return 2
        for binary_entry_path in terraform_binary_plan_paths:
            with tempfile.TemporaryDirectory(prefix="plan-hash-") as temp_dir:
                temp_plan = Path(temp_dir) / Path(binary_entry_path).name
                temp_plan.write_bytes(data_by_entry_path[binary_entry_path])
                shown_json, error = terraform_show_binary_plan(temp_plan, args.engine)
            if error is not None:
                print(error, file=sys.stderr)
                return 2
            if canonical_json_digest(shown_json) not in terraform_json_plan_digests:
                print(
                    f"Cannot verify binary plan {binary_entry_path}: terraform/tofu show -json output does not match supplied tfplan.json",
                    file=sys.stderr,
                )
                return 2
    elif args.engine in {"terraform", "opentofu"} and has_valid_json_plan and not args.review_only_json_plan:
        print(
            "Terraform/OpenTofu apply-bound approval hashes require the binary tfplan plus matching tfplan.json. "
            "Pass --review-only-json-plan only for review evidence that will not be used as an apply approval gate.",
            file=sys.stderr,
        )
        return 2

    if plan_artifacts and args.engine in {"terraform", "opentofu"} and not has_valid_json_plan:
        print(
            "Terraform/OpenTofu approval hashes require a tfplan.json artifact produced by terraform/tofu show -json. "
            "Include it alongside any binary tfplan used for apply.",
            file=sys.stderr,
        )
        return 2

    manifest: dict[str, Any] = {
        "manifest_version": 1,
        "metadata": target_metadata(args),
        "root": str(root),
        "files": entries,
        "plan_artifacts": plan_artifacts,
        "skipped": skipped,
    }
    payload = json.dumps(approval_digest_manifest(manifest), sort_keys=True, separators=(",", ":")).encode("utf-8")
    manifest["digest"] = hashlib.sha256(payload).hexdigest()
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
