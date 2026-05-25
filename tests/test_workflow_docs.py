from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def fenced_bash_blocks(text: str) -> list[str]:
    return re.findall(r"```bash\n(.*?)\n```", text, flags=re.DOTALL)


def section(text: str, heading: str, next_heading: str) -> str:
    start = text.index(heading)
    end = text.index(next_heading, start)
    return text[start:end]


def test_what_if_json_snippets_disable_pretty_print_for_machine_readable_hashing() -> None:
    for relative_path in ("SKILL.md", "references/engine-workflows.md"):
        text = (ROOT / relative_path).read_text()
        for block in fenced_bash_blocks(text):
            if " what-if" in block and "what-if.json" in block:
                assert "--no-pretty-print" in block, relative_path + ":\n" + block


def test_opentofu_docs_separate_apply_from_combined_plan_snippet() -> None:
    text = (ROOT / "references" / "engine-workflows.md").read_text()
    opentofu = section(text, "## OpenTofu Workflow", "## Scope Notes")
    first_block = fenced_bash_blocks(opentofu)[0]

    assert "tofu apply" not in first_block
    assert "../../plans/tfplan" not in opentofu
    assert "### Apply" in opentofu
    apply_section = opentofu[opentofu.index("### Apply") :]
    assert "tofu apply ../../plans/opentofu-<env>-<deployment-name>.tfplan" in apply_section
    assert "approved" in apply_section.lower()


def test_terraform_and_opentofu_docs_use_scoped_plan_artifact_names() -> None:
    for relative_path in ("SKILL.md", "references/engine-workflows.md"):
        text = (ROOT / relative_path).read_text()
        assert "../../plans/tfplan" not in text
        assert "terraform-<env>-<deployment-name>.tfplan" in text
        assert "opentofu-<env>-<deployment-name>.tfplan" in text


def test_arm_json_docs_cover_all_azure_deployment_scopes() -> None:
    text = (ROOT / "references" / "engine-workflows.md").read_text()
    arm = section(text, "## ARM JSON Workflow", "## Azure REST Mapping for Bicep/ARM")

    for scope in ("sub", "mg", "tenant"):
        assert f"az deployment {scope} validate" in arm
        assert f"az deployment {scope} what-if" in arm
        assert f"az deployment {scope} create" in arm
    assert "--management-group-id <management-group-id>" in arm
    assert "--location <location>" in arm


def test_mandatory_safety_policy_keeps_blockers_separate_from_confirmation_only_risks() -> None:
    text = (ROOT / "SKILL.md").read_text()
    policy = section(text, "## Mandatory Safety Policy", "## Secret Handling")

    assert "Blocker-class findings must stop apply" in policy
    assert "Do not downgrade blockers to confirmation-only handling" in policy
    assert "hardcoded passwords" in policy
    assert "public storage container access" in policy
    assert "Owner, Contributor, or User Access Administrator assignments at subscription or management-group scope" in policy
    assert "missing, failed, stale, unverifiable, or changed validation/plan/What-If evidence" in policy
    assert "High-risk findings may proceed only with explicit extra confirmation" in policy


def test_bicepparam_contract_is_documented() -> None:
    skill = (ROOT / "SKILL.md").read_text()
    workflows = (ROOT / "references" / "engine-workflows.md").read_text()

    for text in (skill, workflows):
        assert ".bicepparam" in text
        assert "scan" in text.lower()
        assert "hash" in text.lower()
