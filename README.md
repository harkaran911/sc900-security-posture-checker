# SC-900 Security Posture Checker

A Python-based automated security posture assessment tool for **Microsoft 365 and Azure AD environments**, built on the [Microsoft SC-900](https://learn.microsoft.com/en-us/certifications/exams/sc-900/) (Security, Compliance, and Identity Fundamentals) certification framework.

> Built as part of Industrial Training at Chandigarh University — by a SC-900 certified engineer (Score: 988/1000).

---

## What It Does

Runs **27 security control checks** across the four SC-900 exam domains, produces a colour-coded terminal report with PASS / FAIL / WARN / INFO results, an overall security score out of 100, and an optional exportable HTML dashboard.

| Domain | Focus Area | Checks |
|--------|-----------|--------|
| Domain 1 | Identity & Access Management | 7 |
| Domain 2 | Threat Protection | 8 |
| Domain 3 | Information Protection & Governance | 6 |
| Domain 4 | Compliance Management | 6 |

Each failed or warned control includes a **remediation recommendation** pointing to the exact Microsoft portal path or Conditional Access policy to fix it.

---

## Requirements

- Python 3.8+
- Zero external dependencies — standard library only

---

## Usage

```bash
# Full audit across all 4 domains
python3 sc900_security_checker.py

# Run a single domain only (1–4)
python3 sc900_security_checker.py --domain 1

# Export an HTML assessment dashboard
python3 sc900_security_checker.py --report

# Custom HTML output filename
python3 sc900_security_checker.py --report --output my_audit.html

# Export raw JSON (useful for CI/CD pipelines)
python3 sc900_security_checker.py --json > results.json
```

---

## Sample Output

```
╔══════════════════════════════════════════════════════════════════════════╗
║          Microsoft SC-900 Security Posture Assessment Tool              ║
║          Harkaran Singh | 24BCY70083 | Chandigarh University            ║
║          SC-900 Certified — Score: 988/1000 | Oct 29, 2026              ║
╚══════════════════════════════════════════════════════════════════════════╝

  Domain 1: Identity & Access Management  (7 checks)

  [⚠ WARN] IAM-01: MFA User Registration Coverage
         Detail     : 78% of users have MFA registered (target: 90%+).
         Remediation: Enable Security Defaults or Conditional Access to enforce MFA registration.

  [✓ PASS] IAM-02: Conditional Access: MFA Enforcement
         Detail     : Conditional Access policy enforcing MFA is ACTIVE.

  [✗ FAIL] IAM-03: Legacy Authentication Protocols Blocked
         Detail     : Legacy authentication protocols are still ALLOWED — bypasses MFA.
         Remediation: Create a CA policy that blocks legacy auth clients (applies to 'Other clients').
  ...

  ASSESSMENT SUMMARY
  Total Checks   : 27    Passed : 15 (56%)
  Failed         : 2     Warnings : 9 (33%)
  Overall Score  : 56/100   Grade: D
```

---

## Customising the Mock Data

The tool ships with a **simulated Contoso Ltd tenant** as the data source. To test different configurations, edit the mock data dictionaries near the top of the script:

```python
# Example: flip IAM-03 from PASS to FAIL
IDENTITY_DATA = {
    ...
    "legacy_auth_blocked": False,   # change True → False
    ...
}
```

Dictionaries by domain:
- `IDENTITY_DATA` — Domain 1 (IAM)
- `THREAT_DATA` — Domain 2 (Threat Protection)
- `INFOPROT_DATA` — Domain 3 (Information Protection)
- `COMPLIANCE_DATA` — Domain 4 (Compliance)

For a production integration, replace these dictionaries with live **Microsoft Graph API** calls.

---

## Check Reference

| ID | Check Name | Domain |
|----|-----------|--------|
| IAM-01 | MFA User Registration Coverage | Identity |
| IAM-02 | Conditional Access: MFA Enforcement | Identity |
| IAM-03 | Legacy Authentication Protocols Blocked | Identity |
| IAM-04 | Self-Service Password Reset (SSPR) | Identity |
| IAM-05 | Privileged Account MFA Coverage | Identity |
| IAM-06 | Privileged Identity Management (PIM) | Identity |
| IAM-07 | CA: Device Compliance Requirement | Identity |
| THR-01 | Defender for Endpoint Deployment | Threat |
| THR-02 | Defender for Office 365 | Threat |
| THR-03 | Safe Links Policy Active | Threat |
| THR-04 | Safe Attachments Policy Active | Threat |
| THR-05 | Anti-Phishing Policy Configured | Threat |
| THR-06 | Microsoft Defender for Identity (MDI) | Threat |
| THR-07 | Attack Simulation Training | Threat |
| THR-08 | Defender for Cloud Apps (CASB) | Threat |
| INF-01 | Sensitivity Labels Created & Published | Info Protection |
| INF-02 | DLP Policies Active | Info Protection |
| INF-03 | DLP — Endpoint Protection | Info Protection |
| INF-04 | Retention Policies Configured | Info Protection |
| INF-05 | Auto-Labeling Policies Active | Info Protection |
| INF-06 | Insider Risk Management | Info Protection |
| COM-01 | Microsoft Compliance Score | Compliance |
| COM-02 | Unified Audit Log Enabled | Compliance |
| COM-03 | Audit Log Retention Duration | Compliance |
| COM-04 | eDiscovery Cases Configured | Compliance |
| COM-05 | Regulatory Compliance Templates Active | Compliance |
| COM-06 | Microsoft Purview Audit Level | Compliance |

---

## Project Context

This tool was built as the practical artifact for Industrial Training under the **Bachelor of Engineering in Computer Science & Engineering (Cyber Security)** program at Chandigarh University.

The SC-900 certification (October 29, 2026 — Score: 988/1000) served as the primary knowledge source and design framework. The four SC-900 exam domains map directly to the tool's four check modules, demonstrating that certification knowledge is directly reusable in operational security tooling.

---

## Author

**Harkaran Singh**  
UID: 24BCY70083 | Section: 24BCY-1(A)  
B.E. CSE (Cyber Security) — Chandigarh University  
Microsoft Certified: Security, Compliance, and Identity Fundamentals (SC-900)

---

## License

MIT — do whatever you want with it.
