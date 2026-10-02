"""Audit AWS IAM policy documents for broad permissions and policies requiring manual review."""
def values(value):
    return value if isinstance(value, list) else [value]

def audit(data):
    findings = []
    statements = data.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for index, statement in enumerate(statements):
        if statement.get("Effect") != "Allow":
            continue
        actions = values(statement.get("Action", []))
        resources = values(statement.get("Resource", []))
        conditions = bool(statement.get("Condition"))
        checks = []
        if any("*" in str(a) for a in actions):
            checks.append(("WILDCARD_ACTION", "Action pattern grants multiple operations."))
        if "*" in resources:
            checks.append(("WILDCARD_RESOURCE", "Allow applies to all resources; some AWS actions require this."))
        if "NotAction" in statement or "NotResource" in statement:
            checks.append(("NEGATED_ALLOW", "Negated Allow needs manual evaluation."))
        principal = statement.get("Principal")
        if principal == "*" or (isinstance(principal, dict) and "*" in values(principal.get("AWS", []))):
            checks.append(("PUBLIC_PRINCIPAL", "Wildcard principal can allow external access."))
        for check, detail in checks:
            findings.append({"resource": statement.get("Sid", f"statement-{index}"), "severity": "MEDIUM" if conditions else "HIGH", "check": check, "detail": detail + (" Conditions exist and require review." if conditions else ""), "remediation": "Review effective permissions including conditions, explicit denies, boundaries and organization policies."})
    return findings

import argparse
import json
import sys
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Input JSON file")
    parser.add_argument("--output", type=Path, help="Write JSON report")
    parser.add_argument("--fail-on-high", action="store_true", help="Exit 1 when HIGH findings exist")
    args = parser.parse_args()
    try:
        data = json.loads(args.input.read_text(encoding="utf-8-sig"))
        if not isinstance(data, dict):
            raise ValueError("Input must be a JSON object")
        findings = audit(data)
        report = {"findings": findings, "finding_count": len(findings), "scope": "Only documented checks and supplied input are evaluated."}
        text = json.dumps(report, indent=2)
        if args.output:
            args.output.write_text(text + "\n", encoding="utf-8")
        else:
            print(text)
        return int(args.fail_on_high and any(f["severity"] == "HIGH" for f in findings))
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        print(f"Invalid input or report error: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())

