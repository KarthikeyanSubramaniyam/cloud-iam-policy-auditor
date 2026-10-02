# cloud-iam-policy-auditor

Audit AWS IAM policy documents for broad permissions and policies requiring manual review.

## Run

Requires Python 3.10+ on Windows, Linux or macOS. No dependencies.

```bash
python scanner.py sample.json
python scanner.py sample.json --output report.json --fail-on-high
python -m unittest -v
```

Exit codes: 0 = completed, 1 = high findings with --fail-on-high, 2 = invalid input or I/O failure.

## Scope

Input: one AWS IAM policy JSON document. Checks wildcard actions/resources, negated Allow and wildcard principals. This is a review aid; it does not simulate effective access or combine multiple policies. Conditions lower severity but do not prove safety.

Reports include severity, resource, check, detail and remediation. No cloud credentials are needed; these tools inspect local JSON only. A clean report means none of the implemented checks matched, not that the cloud account is secure. Treat inventory and Terraform plans as sensitive; do not commit real account data. Sample data is fictional.

## Publish

```powershell
git init
git add .
git commit -m "Initial cloud security scanner"
gh repo create cloud-iam-policy-auditor --public --source . --remote origin --push
```

