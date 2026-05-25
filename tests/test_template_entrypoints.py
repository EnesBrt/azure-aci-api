from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

BICEP_PARAM_RE = re.compile(r"^\s*param\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s+[^=\s]+(?P<default>\s*=\s*.+)?")
TERRAFORM_VARIABLE_RE = re.compile(r'^\s*variable\s+"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"\s*{')
TERRAFORM_ASSIGNMENT_RE = re.compile(r"^\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=")


def test_bicep_template_builds_when_tooling_is_available(tmp_path: Path) -> None:
    main_bicep = ROOT / "templates" / "bicep" / "main.bicep"
    output = tmp_path / "main.json"

    if shutil.which("bicep"):
        command = ["bicep", "build", str(main_bicep), "--outfile", str(output)]
    elif shutil.which("az"):
        version = subprocess.run(["az", "bicep", "version"], text=True, capture_output=True, check=False)
        if version.returncode != 0:
            if os.environ.get("CI"):
                pytest.fail("Azure CLI is present but Bicep is not installed in CI")
            pytest.skip("Azure CLI is present but Bicep is not installed")
        command = ["az", "bicep", "build", "--file", str(main_bicep), "--outfile", str(output)]
    else:
        if os.environ.get("CI"):
            pytest.fail("Bicep tooling must be installed in CI")
        pytest.skip("Bicep tooling is not installed")

    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)

    assert result.returncode == 0, result.stdout + result.stderr
    assert output.exists()


def test_bicep_parameter_example_matches_template_contract() -> None:
    main_bicep = (ROOT / "templates" / "bicep" / "main.bicep").read_text().splitlines()
    parameter_file = json.loads((ROOT / "templates" / "bicep" / "parameters.dev.json").read_text())

    declared: set[str] = set()
    required: set[str] = set()
    for line in main_bicep:
        match = BICEP_PARAM_RE.match(line)
        if not match:
            continue
        name = match.group("name")
        declared.add(name)
        if match.group("default") is None:
            required.add(name)

    provided = set(parameter_file["parameters"])

    assert required <= provided
    assert provided <= declared


def test_bicep_parameter_example_uses_derived_common_tags() -> None:
    parameter_file = json.loads((ROOT / "templates" / "bicep" / "parameters.dev.json").read_text())

    assert "tags" not in parameter_file["parameters"]


def require_cli_or_skip(binary: str, reason: str) -> str:
    path = shutil.which(binary)
    if path:
        return path
    if os.environ.get("CI"):
        pytest.fail(f"{reason}; {binary} must be installed in CI")
    pytest.skip(reason)


def run_terraform_like_template_validation(binary: str, tmp_path: Path) -> None:
    binary_name = Path(binary).name
    workdir = tmp_path / binary_name
    shutil.copytree(ROOT / "templates" / "terraform", workdir)

    checks = [
        [binary, "fmt", "-check", "-recursive"],
        [binary, "init", "-backend=false", "-upgrade=false"],
        [binary, "validate"],
        [
            binary,
            "plan",
            "-input=false",
            "-lock=false",
            "-refresh=false",
            "-var-file=terraform.tfvars.example",
            f"-out={tmp_path / f'{binary_name}.tfplan'}",
        ],
    ]
    for command in checks:
        result = subprocess.run(command, cwd=workdir, text=True, capture_output=True, check=False)
        assert result.returncode == 0, " ".join(command) + "\n" + result.stdout + result.stderr


def test_terraform_template_validates_when_tooling_is_available(tmp_path: Path) -> None:
    terraform = require_cli_or_skip("terraform", "Terraform CLI is not installed")

    run_terraform_like_template_validation(terraform, tmp_path)


def test_opentofu_template_validates_when_tooling_is_available(tmp_path: Path) -> None:
    tofu = require_cli_or_skip("tofu", "OpenTofu CLI is not installed")

    run_terraform_like_template_validation(tofu, tmp_path)


def test_terraform_tfvars_example_matches_variable_contract() -> None:
    variables_text = (ROOT / "templates" / "terraform" / "variables.tf").read_text().splitlines()
    tfvars_text = (ROOT / "templates" / "terraform" / "terraform.tfvars.example").read_text().splitlines()

    declared = {match.group("name") for line in variables_text if (match := TERRAFORM_VARIABLE_RE.match(line))}
    required: set[str] = set()
    for name in declared:
        block_start = next(i for i, line in enumerate(variables_text) if f'variable "{name}"' in line)
        block = []
        depth = 0
        for line in variables_text[block_start:]:
            block.append(line)
            depth += line.count("{") - line.count("}")
            if depth <= 0 and len(block) > 1:
                break
        if not any(re.match(r"^\s*default\s*=", line) for line in block):
            required.add(name)

    assigned: set[str] = set()
    depth = 0
    for line in tfvars_text:
        if depth == 0 and (match := TERRAFORM_ASSIGNMENT_RE.match(line)):
            assigned.add(match.group("name"))
        depth += line.count("{") - line.count("}")
        if depth < 0:
            depth = 0

    assert required <= assigned
    assert assigned <= declared
