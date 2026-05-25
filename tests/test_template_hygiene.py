from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GITIGNORE_TEMPLATE = ROOT / "templates" / "common" / "gitignore.template"


def test_gitignore_keeps_provider_lock_but_ignores_json_tfvars() -> None:
    patterns = set(GITIGNORE_TEMPLATE.read_text().splitlines())

    assert ".terraform/" in patterns
    assert "*.tfstate" in patterns
    assert "*.tfstate.*" in patterns
    assert ".terraform.lock.hcl" not in patterns
    assert "terraform.tfvars" in patterns
    assert "terraform.tfvars.json" in patterns
    assert "*.auto.tfvars" in patterns
    assert "*.auto.tfvars.json" in patterns
    assert "tfplan" in patterns
    assert "tfplan.*" in patterns
    assert "*.tfplan" in patterns
    assert "*.tfplan.*" in patterns
    assert ".env.*" in patterns
    assert "*.env" in patterns
    assert "*.env.*" in patterns
    assert "!.env.example" in patterns
    assert "!*.env.example" in patterns
    assert "main.json" not in patterns
    assert "/templates/bicep/main.json" in patterns
