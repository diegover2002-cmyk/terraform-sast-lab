"""
Terraform SAST — Azure OpenAI Security Check
Analyses changed gold-tier Terraform modules against MCSB controls.

Layers:
  1. Static scan    — tfsec deterministic rules (optional, via --tfsec-output)
  2. Semantic scan  — Azure OpenAI LLM, MCSB Must-priority controls
  3. Exception gate — cross-references docs/compliance/exceptions-registry.json;
                      active exceptions are not counted as FAILs
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

# ── Configuration ─────────────────────────────────────────────────────────────

API_KEY  = os.getenv("AZURE_API_KEY")
ENDPOINT = (
    "https://ai-openaidiego-pro.openai.azure.com"
    "/openai/responses?api-version=2025-04-01-preview"
)
MODEL = "gpt-5.1-codex-mini"

EXCEPTIONS_REGISTRY = "docs/compliance/exceptions-registry.json"
POLICY_MAPPING_FILE = "docs/compliance/policy-mapping.json"

MODULE_CONTROLS_MAP = {
    "terraform/modules/storage":  "controls/azure-storage/controls.md",
    "terraform/modules/keyvault": "controls/azure-key-vault/controls.md",
    "terraform/modules/aks":      "controls/azure-aks/controls.md",
}

MODULE_NAMES = {
    "terraform/modules/storage":  "Azure Storage Account",
    "terraform/modules/keyvault": "Azure Key Vault",
    "terraform/modules/aks":      "Azure Kubernetes Service (AKS)",
}

# Primary resource type per module — used to extract plan attributes
RESOURCE_TYPES = {
    "terraform/modules/storage":  "azurerm_storage_account",
    "terraform/modules/keyvault": "azurerm_key_vault",
    "terraform/modules/aks":      "azurerm_kubernetes_cluster",
}

# Secondary resource types whose plan attributes are relevant for Partial controls
# (e.g. diagnostic settings, private endpoints) — extracted alongside the primary resource
SECONDARY_RESOURCE_TYPES: dict[str, list[str]] = {
    "terraform/modules/storage":  [
        "azurerm_monitor_diagnostic_setting",  # ST-008
    ],
    "terraform/modules/keyvault": [
        "azurerm_private_endpoint",            # KV-002
        "azurerm_monitor_diagnostic_setting",  # KV-004
        "azurerm_role_assignment",             # KV-007 (RBAC grant)
    ],
    "terraform/modules/aks": [
        "azurerm_monitor_diagnostic_setting",  # AK-009
    ],
}

STATUS_ICON   = {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️", "EXCEPTION": "🔵"}
TFSEC_SEV_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}

# ── Policy mapping ────────────────────────────────────────────────────────────

def load_policy_mapping(mapping_file: str) -> dict[str, dict]:
    """
    Loads docs/compliance/policy-mapping.json.
    Returns a dict keyed by control_id, e.g.:
      {"ST-001": {"azure_policy_definition_id": "...", "azure_policy_display_name": "...", ...}}
    Returns empty dict if the file is missing (non-blocking).
    """
    try:
        with open(mapping_file, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}
    return {c["control_id"]: c for c in data.get("controls", [])}


# ── Exceptions registry ────────────────────────────────────────────────────────

def load_exempt_controls(registry_file: str) -> set[str]:
    """
    Returns a set of identifiers (Checkov rule IDs + MCSB composite keys) that
    have an active, non-expired registered exception.
    e.g. {"CKV_AZURE_109", "CKV_AZURE_35", "MCSB-NS-2"}
    """
    now = datetime.now(timezone.utc)
    exempt: set[str] = set()
    try:
        with open(registry_file, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return exempt
    for exc in data.get("registry", []):
        if exc.get("status") != "active":
            continue
        expires = datetime.fromisoformat(exc["expires_at"].replace("Z", "+00:00"))
        if expires <= now:
            continue
        for ctrl in exc.get("policy_controls", []):
            exempt.add(ctrl)
    return exempt


def is_exempt(ctrl_meta: dict, exempt: set[str]) -> str | None:
    """Returns matched exception ID if this control is covered, else None."""
    checkov = ctrl_meta.get("checkov", "")
    if checkov and checkov in exempt:
        return checkov
    mcsb = ctrl_meta.get("mcsb", "")
    mcsb_key = f"MCSB-{mcsb}" if mcsb else ""
    if mcsb_key and mcsb_key in exempt:
        return mcsb_key
    return None


# ── Controls extraction ────────────────────────────────────────────────────────

def extract_must_controls(controls_file: str) -> list[dict]:
    """
    Parse the summary table in controls.md.
    Returns only Must-priority rows; captures Checkov rule for exception lookup.
    """
    with open(controls_file, encoding="utf-8") as f:
        content = f.read()

    checkov_re = re.compile(r"`?(CKV2?_AZURE_\d+)`?")
    controls: list[dict] = []

    for line in content.splitlines():
        if not re.match(r"\|\s*\*{0,2}[A-Z]{1,3}-\d{3}\*{0,2}\s*\|", line):
            continue
        fields = [f.strip() for f in line.split("|") if f.strip()]
        if len(fields) < 5:
            continue

        ctrl_id  = re.sub(r"\*", "", fields[0]).strip()
        priority = next((f for f in fields if re.search(r"Must|Should|Nice", f, re.I)), "")
        if not re.search(r"Must", priority, re.I):
            continue

        severity = next((f for f in fields if re.match(r"^(High|Medium|Low)$", f, re.I)), "—")
        domain   = next((f for f in fields if re.match(r"^[A-Z]{2}$", f)), "—")
        mcsb     = next((f for f in fields if re.match(r"^[A-Z]{2}-\d{1,2}$", f)), "")
        name     = re.sub(r"\*", "", fields[3]).strip() if len(fields) > 3 else ""
        checkov       = next((checkov_re.search(f).group(1) for f in fields if checkov_re.search(f)), "")
        iac_checkable = next((f for f in fields if re.match(r"^(Yes|Partial|No)$", f, re.I)), "Yes")

        controls.append({"id": ctrl_id, "mcsb": mcsb, "domain": domain,
                         "name": name, "severity": severity, "checkov": checkov,
                         "iac_checkable": iac_checkable})
    return controls


def controls_to_compact_table(controls: list[dict]) -> str:
    lines = ["Control ID | Domain | Severity | Name | IaC Checkable | Checkov Rule"]
    for c in controls:
        checkov = c.get("checkov") or "Custom"
        iac     = c.get("iac_checkable", "Yes")
        lines.append(f"{c['id']} | {c['domain']} | {c['severity']} | {c['name']} | {iac} | {checkov}")
    return "\n".join(lines)


# ── tfsec ─────────────────────────────────────────────────────────────────────

def parse_tfsec_findings(tfsec_file: str, module_dir: str) -> list[dict]:
    try:
        with open(tfsec_file, encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []
    findings = []
    for result in data.get("results", []):
        loc = result.get("location", {})
        if module_dir not in loc.get("filename", ""):
            continue
        findings.append({
            "rule_id":     result.get("rule_id", result.get("legacy_rule_id", "?")),
            "description": result.get("description", result.get("rule_description", "")),
            "severity":    result.get("severity", "?").upper(),
            "resource":    result.get("resource", ""),
            "start_line":  loc.get("start_line", "?"),
        })
    return findings


def render_tfsec_section(findings: list[dict], exempt: set[str]) -> str:
    if not findings:
        return "**tfsec:** ✅ No findings\n"
    lines = [
        "**tfsec static scan:**\n",
        "| Rule | Severity | Resource | Line | Status |",
        "|---|---|---|---|---|",
    ]
    for f in findings:
        sev_icon = TFSEC_SEV_ICON.get(f["severity"], "⚪")
        status   = "🔵 EXCEPTION" if f["rule_id"] in exempt else f"{sev_icon} {f['severity']}"
        lines.append(
            f"| `{f['rule_id']}` | {sev_icon} {f['severity']} "
            f"| `{f['resource']}` | {f['start_line']} | {status} |"
        )
    return "\n".join(lines) + "\n"


# ── Prompt context builders ───────────────────────────────────────────────────

def build_tfsec_context(findings: list[dict], exempt: set[str]) -> str:
    """Format tfsec findings as a prompt pre-analysis block."""
    if not findings:
        return ""
    lines = ["tfsec pre-analysis (static tool — do not contradict these results):"]
    for f in findings:
        status = "EXCEPTION" if f["rule_id"] in exempt else f["severity"]
        lines.append(f"  - {f['rule_id']}: {status} — {f['description']}")
    return "\n".join(lines)


def parse_checkov_output(checkov_file: str) -> dict[str, str]:
    """
    Parse Checkov JSON output (--output json) into {rule_id: status}.
    Handles both single-result and array-of-results formats.
    Merges ALL list items so checks from every scanned module are captured.
    FAIL always wins over PASS or SKIP for the same rule ID.
    """
    try:
        with open(checkov_file, encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

    # Checkov outputs a list when scanning a directory or multiple frameworks
    items = data if isinstance(data, list) else [data]

    results: dict[str, str] = {}
    for item in items:
        check_results = item.get("results", item)
        # Set PASS only when not already FAIL
        for check in check_results.get("passed_checks", []):
            cid = check.get("check_id", "")
            if cid and results.get(cid) != "FAIL":
                results[cid] = "PASS"
        # FAIL always wins — any failure in any scanned file marks the rule failed
        for check in check_results.get("failed_checks", []):
            cid = check.get("check_id", "")
            if cid:
                results[cid] = "FAIL"
        # SKIP only if rule not already PASS or FAIL
        for check in check_results.get("skipped_checks", []):
            cid = check.get("check_id", "")
            if cid and results.get(cid) not in ("FAIL", "PASS"):
                results[cid] = "SKIP"
    return results


def build_checkov_context(
    checkov_results: dict[str, str],
    controls_meta:   list[dict],
    exempt:          set[str],
) -> str:
    """Format Checkov findings as a prompt pre-analysis block, annotated with control IDs."""
    if not checkov_results:
        return ""
    rule_to_ctrl = {c["checkov"]: c["id"] for c in controls_meta if c.get("checkov")}
    lines = ["Checkov pre-analysis (static tool — do not contradict these results):"]
    for rule_id, status in sorted(checkov_results.items()):
        ctrl_id  = rule_to_ctrl.get(rule_id, "")
        exc_note = " (exception)" if rule_id in exempt else ""
        ctrl_note = f" → {ctrl_id}" if ctrl_id else ""
        lines.append(f"  - {rule_id}: {status}{exc_note}{ctrl_note}")
    return "\n".join(lines)


def _extract_scalars(rc: dict, skip: set[str]) -> list[str]:
    """Return list of 'key: value' lines for scalar top-level attributes of a resource_change."""
    after = rc.get("change", {}).get("after")
    if not after:
        return []
    lines = [f"resource: {rc.get('address', rc.get('type', '?'))}"]
    for k, v in after.items():
        if k in skip or v is None or isinstance(v, (dict, list)):
            continue
        lines.append(f"  {k}: {json.dumps(v)}")
    return lines if len(lines) > 1 else []


def extract_plan_resources(plan_file: str, module_dir: str) -> str:
    """
    Extract top-level scalar security attributes from terraform plan JSON.
    Covers the primary resource type AND secondary types (diagnostic settings,
    private endpoints, role assignments) that are relevant for Partial controls.
    Ignores metadata/secret fields to keep the prompt compact.
    """
    try:
        with open(plan_file, encoding="utf-8") as f:
            plan = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return ""

    primary_type = RESOURCE_TYPES.get(module_dir)
    if not primary_type:
        return ""

    _SKIP = {
        "id", "name", "location", "resource_group_name", "resource_group_id",
        "tags", "timeouts", "dns_prefix", "fqdn", "hostname", "portal_url",
        "primary_connection_string", "primary_access_key", "secondary_access_key",
        "primary_blob_connection_string", "secondary_blob_connection_string",
        "target_resource_id", "log_analytics_workspace_id",
    }

    secondary_types = set(SECONDARY_RESOURCE_TYPES.get(module_dir, []))
    all_types = {primary_type} | secondary_types

    results: list[str] = []
    for rc in plan.get("resource_changes", []):
        if rc.get("type") not in all_types:
            continue
        lines = _extract_scalars(rc, _SKIP)
        if lines:
            results.append("\n".join(lines))

    if not results:
        return ""
    return (
        "Terraform plan — provider-resolved values (may include provider defaults not in HCL):\n"
        + "\n\n".join(results)
    )


# ── Azure OpenAI ──────────────────────────────────────────────────────────────

_OPENAI_TIMEOUT    = 45          # seconds per attempt
_OPENAI_MAX_TRIES  = 3           # total attempts
_OPENAI_BACKOFF    = [0, 10, 20] # seconds to wait before each attempt


def call_openai(
    tf_code:         str,
    controls_table:  str,
    service_name:    str,
    tfsec_context:   str = "",
    checkov_context: str = "",
    plan_context:    str = "",
) -> list[dict]:
    system_prompt = (
        "You are a Terraform security reviewer for Azure infrastructure. "
        "For each control ID in the list, inspect the Terraform code and decide: "
        "PASS (correctly implemented), FAIL (missing or wrong), "
        "WARN (partially met or conditional), "
        "EXCEPTION (a checkov:skip annotation is present for this control). "
        "The controls table includes 'IaC Checkable' and 'Checkov Rule' columns: "
        "  'Yes' with a known Checkov rule = the static tool can fully verify; confirm its result. "
        "  'Partial' or 'Custom' = the static tool cannot fully verify; apply deeper semantic reasoning. "
        "  'No' = purely semantic judgment required. "
        "When tfsec or Checkov pre-analysis is provided, use it as a starting point — "
        "but apply these two override rules that take absolute priority over the static tools: "
        "Override Rule 1 — HCL literal beats Checkov PASS: if the Terraform code contains "
        "a literal `false` or `null` for a security-critical attribute "
        "(e.g. enable_rbac_authorization = false, local_account_disabled = false, "
        "purge_protection_enabled = false), report FAIL even if Checkov says PASS. "
        "The HCL source is ground truth for explicit literal values. "
        "Override Rule 2 — Plan context beats Checkov FAIL: if Checkov reports FAIL for an attribute "
        "but the Terraform plan context shows that same attribute set to a non-null, non-empty value, "
        "report PASS. The plan reflects provider-resolved variable values and supersedes static "
        "analysis for unresolved variable references (e.g. disk_encryption_set_id = var.xxx). "
        "For rules not listed in the pre-analysis, analyze directly from HCL — never infer PASS from absence. "
        "Reply ONLY with a JSON array — no markdown, no prose — like: "
        '[{"id":"ST-001","status":"PASS","finding":"allow_nested_items_to_be_public = false"}]'
    )

    context_parts = [p for p in (tfsec_context, checkov_context, plan_context) if p]
    context_block = ("\n\n" + "\n\n".join(context_parts) + "\n\n") if context_parts else "\n\n"

    user_prompt = (
        f"Service: {service_name}\n\n"
        f"Must-priority MCSB controls to check:\n{controls_table}"
        f"{context_block}"
        f"Terraform code:\n```hcl\n{tf_code}\n```"
    )
    headers = {"Content-Type": "application/json", "api-key": API_KEY}
    payload = {
        "model": MODEL,
        "input": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_prompt},
        ],
        "max_output_tokens": 4096,
    }

    last_exc: Exception = RuntimeError("No attempts made")
    for attempt, wait in enumerate(zip(range(_OPENAI_MAX_TRIES), _OPENAI_BACKOFF)):
        attempt_n, backoff = wait
        if backoff:
            print(f"  ↻ Retry {attempt_n}/{_OPENAI_MAX_TRIES - 1} — waiting {backoff}s...")
            time.sleep(backoff)
        try:
            resp = requests.post(ENDPOINT, headers=headers, json=payload, timeout=_OPENAI_TIMEOUT)
            resp.raise_for_status()
            result = resp.json()

            raw_text = ""
            for item in result.get("output", []):
                if isinstance(item, dict):
                    content = item.get("content", "")
                    if isinstance(content, list):
                        for block in content:
                            if isinstance(block, dict) and block.get("type") == "output_text":
                                raw_text += block.get("text", "")
                    elif isinstance(content, str):
                        raw_text += content

            raw_text = re.sub(r"```[a-z]*", "", raw_text).strip()
            if not raw_text:
                raise ValueError(
                    "API returned empty output — model may not have produced a response. "
                    "Check that the Azure OpenAI deployment is active and the model supports this payload format."
                )
            return json.loads(raw_text)
        except Exception as exc:
            last_exc = exc
            print(f"  ⚠ Attempt {attempt_n + 1} failed: {exc}", file=sys.stderr)

    raise last_exc


# ── Report rendering ──────────────────────────────────────────────────────────

def render_module_report(
    module_dir:     str,
    tf_file:        str,
    ai_findings:    list[dict],
    controls_meta:  list[dict],
    exempt:         set[str],
    tfsec_section:  str,
    policy_mapping: dict[str, dict] | None = None,
) -> tuple[str, int]:
    """Returns (markdown_section, fail_count). Demotes FAIL→EXCEPTION when registered."""
    service_name = MODULE_NAMES.get(module_dir, module_dir)
    meta_by_id   = {c["id"]: c for c in controls_meta}
    policy_map   = policy_mapping or {}

    for f in ai_findings:
        if f["status"] == "FAIL":
            exc_id = is_exempt(meta_by_id.get(f["id"], {}), exempt)
            if exc_id:
                f["status"]  = "EXCEPTION"
                f["finding"] = f"{f['finding']} [registered exception: {exc_id}]"

    pass_n = sum(1 for f in ai_findings if f["status"] == "PASS")
    fail_n = sum(1 for f in ai_findings if f["status"] == "FAIL")
    warn_n = sum(1 for f in ai_findings if f["status"] == "WARN")
    exc_n  = sum(1 for f in ai_findings if f["status"] == "EXCEPTION")

    use_policy_col = bool(policy_map)
    if use_policy_col:
        header = "| Control | Domain | Severity | Status | Finding | Azure Policy |"
        sep    = "|---|---|---|---|---|---|"
    else:
        header = "| Control | Domain | Severity | Status | Finding |"
        sep    = "|---|---|---|---|---|"

    lines = [
        f"#### `{tf_file}` — {service_name}", "",
        tfsec_section,
        "**AI semantic analysis (MCSB Must-priority):**\n",
        header,
        sep,
    ]
    for f in ai_findings:
        meta   = meta_by_id.get(f["id"], {})
        row    = (
            f"| {f['id']} | {meta.get('domain','—')} | {meta.get('severity','—')} "
            f"| {STATUS_ICON.get(f['status'],'❓')} {f['status']} | {f.get('finding','')} |"
        )
        if use_policy_col:
            pm = policy_map.get(f["id"], {})
            pol_id   = pm.get("azure_policy_definition_id", "")
            pol_name = pm.get("azure_policy_display_name", "—")
            policy_cell = f"`{pol_id}`" if pol_id else "—"
            row += f" {pol_name} {policy_cell} |"
        lines.append(row)

    lines += ["", f"**Summary: {pass_n} PASS · {fail_n} FAIL · {warn_n} WARN · {exc_n} EXCEPTION**",
              "", "---", ""]
    return "\n".join(lines), fail_n


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    if not API_KEY:
        print("ERROR: AZURE_API_KEY environment variable is not set.", file=sys.stderr)
        sys.exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument("--changed-files",   nargs="+", required=True)
    parser.add_argument("--output",          required=True)
    parser.add_argument("--tfsec-output",    default=None)
    parser.add_argument("--checkov-output",      default=None,
                        help="Path to Checkov static JSON output file (--output json)")
    parser.add_argument("--checkov-plan-output", default=None,
                        help="Path to Checkov plan-level JSON (checkov --framework terraform_plan)")
    parser.add_argument("--plan-file",           default=None,
                        help="Path to terraform plan JSON (terraform show -json tfplan.out)")
    args = parser.parse_args()

    exempt         = load_exempt_controls(EXCEPTIONS_REGISTRY)
    policy_mapping = load_policy_mapping(POLICY_MAPPING_FILE)
    print(f"Loaded {len(exempt)} exempt control identifiers from registry")
    print(f"Loaded {len(policy_mapping)} Azure Policy mappings")

    modules_to_check: dict[str, str] = {}
    for tf_file in args.changed_files:
        module_dir = str(Path(tf_file).parent)
        if module_dir in MODULE_CONTROLS_MAP and module_dir not in modules_to_check:
            modules_to_check[module_dir] = tf_file
        else:
            print(f"  skip: {tf_file} — no gold-tier controls mapping")

    report_sections = [
        "## 🔒 Terraform SAST — AI Security Check\n",
        "> Gold-tier modules: Storage Account · Key Vault · AKS\n",
    ]
    total_fails = 0
    api_errors  = 0

    if not modules_to_check:
        report_sections.append("_No gold-tier Terraform changes detected._\n")
    else:
        for module_dir, tf_file in modules_to_check.items():
            service_name   = MODULE_NAMES.get(module_dir, module_dir)
            controls_file  = MODULE_CONTROLS_MAP[module_dir]
            print(f"\n→ Checking {service_name} ({tf_file})")

            tfsec_findings = parse_tfsec_findings(args.tfsec_output, module_dir) \
                             if args.tfsec_output else []
            tfsec_section  = render_tfsec_section(tfsec_findings, exempt)

            try:
                controls_meta = extract_must_controls(controls_file)
            except FileNotFoundError:
                report_sections.append(
                    f"#### `{tf_file}`\n\n⚠️ Controls file not found: `{controls_file}` — skipped.\n\n---\n")
                continue

            if not controls_meta:
                report_sections.append(
                    f"#### `{tf_file}`\n\nℹ️ No Must-priority controls found — skipped.\n\n---\n")
                continue

            print(f"   {len(controls_meta)} Must-priority controls loaded")

            # Build static-tool pre-analysis context for the OpenAI prompt
            checkov_results  = parse_checkov_output(args.checkov_output) if args.checkov_output else {}
            # Plan-level Checkov is more accurate (variables resolved) — overrides static for same rule
            if args.checkov_plan_output:
                plan_checkov = parse_checkov_output(args.checkov_plan_output)
                checkov_results.update(plan_checkov)  # plan values win
                print(f"   Checkov plan-level: {len(plan_checkov)} rules loaded (override static)")
            # Filter to only rules referenced by this module's Must controls (reduces LLM noise)
            relevant_rules   = {c["checkov"] for c in controls_meta if c.get("checkov")}
            filtered_checkov = {k: v for k, v in checkov_results.items() if k in relevant_rules}
            tfsec_context    = build_tfsec_context(tfsec_findings, exempt)
            checkov_context  = build_checkov_context(filtered_checkov, controls_meta, exempt)
            plan_context     = extract_plan_resources(args.plan_file, module_dir) if args.plan_file else ""

            if filtered_checkov:
                print(f"   Checkov pre-analysis: {len(filtered_checkov)}/{len(checkov_results)} rules (module-filtered)")
            if plan_context:
                print("   Terraform plan: provider-resolved attributes loaded")

            try:
                with open(tf_file, encoding="utf-8") as f:
                    tf_code = f.read()
            except FileNotFoundError:
                report_sections.append(
                    f"#### `{tf_file}`\n\n⚠️ File not found — skipped.\n\n---\n")
                continue

            try:
                ai_findings = call_openai(
                    tf_code,
                    controls_to_compact_table(controls_meta),
                    service_name,
                    tfsec_context=tfsec_context,
                    checkov_context=checkov_context,
                    plan_context=plan_context,
                )
            except Exception as e:
                api_errors += 1
                report_sections.append(
                    f"#### `{tf_file}` — {service_name}\n\n"
                    f"❌ **AI check failed** — cannot confirm security posture for this module.\n"
                    f"Error: `{e}`\n\n---\n")
                print(f"   API error: {e}", file=sys.stderr)
                continue

            section, module_fails = render_module_report(
                module_dir, tf_file, ai_findings, controls_meta, exempt, tfsec_section,
                policy_mapping=policy_mapping or None,
            )
            total_fails += module_fails
            report_sections.append(section)

    if modules_to_check:
        if api_errors > 0:
            banner = (
                f"### ❌ Gate: BLOCKED — AI security check could not complete "
                f"({api_errors} API error(s)); cannot confirm security posture. "
                f"Investigate Azure OpenAI connectivity before merging.\n"
            )
        elif total_fails == 0:
            banner = "### ✅ Gate: PASSED — no unregistered FAIL findings\n"
        else:
            banner = (
                f"### ❌ Gate: BLOCKED — {total_fails} FAIL finding(s) must be "
                f"remediated or registered in exceptions-registry.json before merging\n"
            )
        report_sections.insert(2, banner)

    full_report = "\n".join(report_sections)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(full_report)

    print(f"\nReport written to {args.output}")
    print(full_report)

    if total_fails > 0 or api_errors > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
