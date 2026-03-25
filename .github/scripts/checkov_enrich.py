"""
checkov_enrich.py — Enriches Checkov JSON output with MCSB control metadata.

Reads:
  checkov-output.json          — Checkov JSON results
  controls/azure-*/controls.md — MCSB control definitions (builds CKV→MCSB map)
  docs/compliance/exceptions-registry.json — registered exceptions

Outputs:
  checkov-enriched.txt         — markdown table ready to paste in PR comment
"""

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

EXCEPTIONS_REGISTRY = "docs/compliance/exceptions-registry.json"
CONTROLS_DIR        = Path("controls")

SEV_ICON   = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢", "CRITICAL": "🔴", "UNKNOWN": "⚪"}
MODULE_LABEL = {
    "storage":  "Azure Storage Account",
    "keyvault": "Azure Key Vault",
    "aks":      "Azure Kubernetes Service",
}


# ── Build CKV → MCSB map from all controls.md files ──────────────────────────

def build_checkov_map() -> dict:
    """Returns {CKV_AZURE_XXX: {ctrl_id, mcsb, name, severity, service}} for all controls."""
    ckv_re = re.compile(r"`?(CKV2?_AZURE_\d+)`?")
    mapping: dict = {}

    for md_file in sorted(CONTROLS_DIR.glob("*/controls.md")):
        service = md_file.parent.name  # e.g. azure-storage
        try:
            content = md_file.read_text(encoding="utf-8")
        except OSError:
            continue

        for line in content.splitlines():
            if not re.match(r"\|\s*\*{0,2}[A-Z]{1,3}-\d{3}\*{0,2}\s*\|", line):
                continue
            fields = [f.strip() for f in line.split("|") if f.strip()]
            if len(fields) < 5:
                continue

            ctrl_id  = re.sub(r"\*", "", fields[0]).strip()
            mcsb     = next((f for f in fields if re.match(r"^[A-Z]{2}-\d+$", f)), "")
            name     = re.sub(r"\*", "", fields[3]).strip() if len(fields) > 3 else ""
            severity = next((f for f in fields if re.match(r"^(High|Medium|Low|Critical)$", f, re.I)), "")
            priority = next((f for f in fields if re.search(r"Must|Should|Nice", f, re.I)), "")

            for field in fields:
                for m in ckv_re.finditer(field):
                    ckv = m.group(1)
                    mapping[ckv] = {
                        "ctrl_id":  ctrl_id,
                        "mcsb":     mcsb,
                        "name":     name,
                        "severity": severity.upper() if severity else "UNKNOWN",
                        "priority": priority,
                        "service":  service,
                    }
    return mapping


# ── Load exceptions ───────────────────────────────────────────────────────────

def load_exceptions() -> dict:
    """Returns {CKV_AZURE_XXX: exception_id} for active, non-expired exceptions."""
    now = datetime.now(timezone.utc)
    result: dict = {}
    try:
        data = json.loads(Path(EXCEPTIONS_REGISTRY).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return result
    for exc in data.get("registry", []):
        if exc.get("status") != "active":
            continue
        expires = datetime.fromisoformat(exc["expires_at"].replace("Z", "+00:00"))
        if expires <= now:
            continue
        for ctrl in exc.get("policy_controls", []):
            if ctrl.startswith("CKV"):
                result[ctrl] = exc["id"]
    return result


# ── Parse Checkov JSON ────────────────────────────────────────────────────────

def parse_checkov(json_file: str) -> tuple[list, list, list]:
    """Returns (failed_checks, passed_checks, skipped_checks)."""
    try:
        raw = json.loads(Path(json_file).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Cannot read {json_file}: {e}", file=sys.stderr)
        return [], [], []

    # Checkov JSON can be a list (one entry per runner) or a single object
    if isinstance(raw, list):
        results = raw[0].get("results", {}) if raw else {}
    else:
        results = raw.get("results", {})

    return (
        results.get("failed_checks",  []),
        results.get("passed_checks",  []),
        results.get("skipped_checks", []),
    )


def module_from_path(file_path: str) -> str:
    """Extracts short module name from file path, e.g. 'storage'."""
    for part in Path(file_path).parts:
        if part in MODULE_LABEL:
            return part
    return "other"


# ── Render ────────────────────────────────────────────────────────────────────

def render(json_file: str, output_file: str) -> None:
    ckv_map    = build_checkov_map()
    exceptions = load_exceptions()
    failed, passed, skipped = parse_checkov(json_file)

    total_passed  = len(passed)
    total_failed  = len(failed)
    total_skipped = len(skipped)
    total         = total_passed + total_failed + total_skipped

    # Group failures by module
    by_module: dict[str, list] = {}
    for check in failed:
        mod = module_from_path(check.get("repo_file_path", check.get("file_path", "")))
        by_module.setdefault(mod, []).append(check)

    lines = [
        "### 📋 Checkov IaC Scan",
        "",
        f"| ✅ Passed | ❌ Failed | ⏭️ Skipped | Total |",
        f"|---|---|---|---|",
        f"| {total_passed} | {total_failed} | {total_skipped} | {total} |",
        "",
    ]

    if not failed:
        lines.append("✅ No failed checks — all IaC controls passed.")
    else:
        lines.append(f"<details><summary>❌ <strong>{total_failed} failed check(s) — click to expand</strong></summary>")
        lines.append("")

        for mod, checks in sorted(by_module.items()):
            label = MODULE_LABEL.get(mod, mod)
            lines += [f"#### `terraform/modules/{mod}/` — {label}", ""]
            lines += [
                "| Rule | Resource | Severity | MCSB Control | Priority | Finding | Status |",
                "|---|---|---|---|---|---|---|",
            ]
            for c in sorted(checks, key=lambda x: x.get("check_id", "")):
                ckv_id   = c.get("check_id", "?")
                resource = c.get("resource", "?")
                file_ln  = c.get("file_line_range", ["?", "?"])
                location = f"L{file_ln[0]}–{file_ln[1]}" if file_ln[0] != "?" else ""
                meta     = ckv_map.get(ckv_id, {})

                severity = (c.get("severity") or meta.get("severity") or "UNKNOWN").upper()
                sev_icon = SEV_ICON.get(severity, "⚪")
                ctrl_id  = meta.get("ctrl_id", "—")
                mcsb     = meta.get("mcsb", "—")
                ctrl_name = meta.get("name", c.get("check", {}).get("name", c.get("check_type", "?")))
                priority = meta.get("priority", "—")

                exc_id   = exceptions.get(ckv_id)
                if exc_id:
                    status = f"🔵 EXCEPTION ({exc_id})"
                else:
                    status = "❌ FAIL"

                ctrl_cell = f"{ctrl_id} / {mcsb}" if ctrl_id != "—" else "—"
                loc_cell  = f"`{resource}`" + (f" {location}" if location else "")

                lines.append(
                    f"| `{ckv_id}` | {loc_cell} | {sev_icon} {severity} "
                    f"| {ctrl_cell} | {priority} | {ctrl_name} | {status} |"
                )
            lines.append("")

        lines.append("</details>")

    # Skipped checks summary
    if skipped:
        lines += [
            "",
            f"<details><summary>⏭️ <strong>{total_skipped} skipped check(s) — registered exceptions</strong></summary>",
            "",
            "| Rule | Resource | Suppression comment |",
            "|---|---|---|",
        ]
        for c in skipped:
            ckv_id   = c.get("check_id", "?")
            resource = c.get("resource", "?")
            suppress = c.get("suppress_comment", "—")
            lines.append(f"| `{ckv_id}` | `{resource}` | {suppress} |")
        lines.append("")
        lines.append("</details>")

    output = "\n".join(lines)
    Path(output_file).write_text(output, encoding="utf-8")
    print(output)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkov-json", default="checkov-output.json")
    parser.add_argument("--output",       default="checkov-enriched.txt")
    args = parser.parse_args()
    render(args.checkov_json, args.output)
