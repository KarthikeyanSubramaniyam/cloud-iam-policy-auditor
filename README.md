# AWS IAM Policy Syntax & Wildcard Risk Auditor

<p align="center">
  <img src="https://img.shields.io/badge/Security-Defensive_Auditor-blue?style=flat" alt="Type">
  <img src="https://img.shields.io/badge/Status-Architectural_Showcase-success?style=flat" alt="Status">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white" alt="Python">
</p>

> 🔒 **Technical Showcase & Architecture Specification**  
> *This repository provides public architectural documentation, system specifications, and implementation summaries. Full production source code, internal test suites, and proprietary algorithms are maintained in a secure private repository.*

---

## 📌 Executive Summary

**Category**: Identity & Access Management (IAM)  
**Tech Stack**: `Python 3.10+ · AWS IAM Grammar · Least Privilege · Security Auditing`  

Defensive auditor analyzing raw IAM policy JSON documents to flag wildcard permissions, missing conditions, and risky administrative grants.

---

## 🎯 The Problem It Solves

Developers frequently use wildcards like `"Action": "*"` or `"Action": "s3:*"` to quickly fix permission issues, inadvertently granting excessive administrative capabilities across cloud accounts.

---

## ⚙️ How the Engine Works

1. **Statement Normalization**: Parses complex IAM policy structures, normalizing single-string and array declarations for `Effect`, `Action`, `Resource`, and `Condition`.
2. **Wildcard & Broad Action Detection**: Identifies policies granting unrestricted actions (`*`) or dangerous prefixes (`iam:*`, `kms:*`, `organizations:*`).
3. **Resource Exposure Audit**: Detects `"Resource": "*"` statements coupled with state-modifying actions that bypass resource-level boundaries.
4. **Condition Block Evaluation**: Flags missing IP restriction, MFA, or VPC endpoint condition keys on privileged operations.
5. **Least-Privilege Recommendations**: Suggests scoped action replacements and explicit resource ARNs.

---

## 🚀 Key Capabilities

- Flags full administrative `*:*` grants in identity and resource policies
- Detects dangerous combinations like `s3:PutBucketPolicy` on all resources
- Verifies mandatory condition keys on sensitive administrative roles
- Produces structured audit reports with remediation policy templates

---

## 🏗️ System Data Flow & Architecture

```
+-----------------------------------+
|  Target Input / Configuration    |
|  (JSON Snapshots / Policies)      |
+-----------------+-----------------+
                  |
                  v
+-----------------------------------+
|  1. Schema Normalization Engine   |
|  Validates types & formats        |
+-----------------+-----------------+
                  |
                  v
+-----------------------------------+
|  2. Core Analytical Pipeline      |
|  Heuristic rule evaluation,       |
|  invariant checks & drift diffs   |
+-----------------+-----------------+
                  |
                  v
+-----------------------------------+
|  3. Risk Classification           |
|  Assigns severity: INFO / HIGH    |
+-----------------+-----------------+
                  |
                  v
+-----------------------------------+
|  4. Structured Findings & Report  |
|  Root cause, evidence &           |
|  actionable remediation steps     |
+-----------------------------------+
```

---

## 📄 Findings Output Structure

The engine generates structured, machine-parsable JSON reports adhering to this standard audit schema:

```json
{
  "results": [
    {
      "resource": "resource-identifier",
      "severity": "HIGH",
      "check": "CHECK_IDENTIFIER",
      "detail": "Descriptive analysis of the identified security posture issue.",
      "remediation": "Actionable step-by-step guidance to restore compliant state.",
      "evidence": {
        "observed_field": "value",
        "required_policy": "enforced_policy"
      }
    }
  ],
  "count": 1,
  "scope": "Comprehensive defensive security audit"
}
```

---

## 🔒 Source Code & Enterprise Inquiries

To protect proprietary intellectual property and client operational security:
* **Public Repository**: Contains comprehensive architecture specifications, schemas, and design overviews.
* **Private Repository**: Contains the complete production implementation, continuous integration pipelines, and full regression test suites.

For architectural questions or enterprise inquiries, connect via [LinkedIn](https://www.linkedin.com/in/karthikeyansubramaniam04/) or visit the [Portfolio Site](https://karthikeyansubramaniyam.github.io).
