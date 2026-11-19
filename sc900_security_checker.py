#!/usr/bin/env python3
"""
sc900_security_checker.py
Microsoft SC-900 Security Posture Assessment Tool
-------------------------------------------------
Simulates security configuration checks against a Microsoft 365 / Azure AD
tenant, mapped to the four SC-900 exam domain areas:
  1. Identity & Access Management
  2. Threat Protection
  3. Information Protection & Governance
  4. Compliance Management

Usage:
    python sc900_security_checker.py                 # Run full assessment
    python sc900_security_checker.py --domain 1      # Run only Domain 1
    python sc900_security_checker.py --report        # Also export HTML report
    python sc900_security_checker.py --domain 2 --report
"""

import argparse
import json
import os
import sys
import time
import datetime
from typing import List, Dict, Optional, Tuple

# ─────────────────────────────────────────────────────────────────────────────
# ANSI colour helpers (gracefully disabled on non-TTY)
# ─────────────────────────────────────────────────────────────────────────────

USE_COLOR = sys.stdout.isatty()

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text

def green(t):   return _c("92", t)
def red(t):     return _c("91", t)
def yellow(t):  return _c("93", t)
def cyan(t):    return _c("96", t)
def bold(t):    return _c("1",  t)
def dim(t):     return _c("2",  t)
def blue(t):    return _c("94", t)

# ─────────────────────────────────────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────────────────────────────────────

PASS    = "PASS"
FAIL    = "FAIL"
WARN    = "WARN"
INFO    = "INFO"

class CheckResult:
    def __init__(self, check_id: str, name: str, domain: int, domain_name: str,
                 status: str, detail: str, remediation: str):
        self.check_id    = check_id
        self.name        = name
        self.domain      = domain
        self.domain_name = domain_name
        self.status      = status
        self.detail      = detail
        self.remediation = remediation

    def as_dict(self) -> dict:
        return {
            "id":          self.check_id,
            "name":        self.name,
            "domain":      self.domain,
            "domain_name": self.domain_name,
            "status":      self.status,
            "detail":      self.detail,
            "remediation": self.remediation,
        }

# ─────────────────────────────────────────────────────────────────────────────
# Simulated tenant data  (realistic mock — in production, replace these
# dictionaries with live calls to Microsoft Graph API endpoints)
# ─────────────────────────────────────────────────────────────────────────────

MOCK_TENANT = {
    "name": "Contoso Ltd (Demo Tenant)",
    "tenant_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "domain": "contoso.onmicrosoft.com",
    "users_total": 342,
    "licensed_users": 318,
}

# Domain 1 — Identity & Access Management
IDENTITY_DATA = {
    "mfa_enabled_percent":          78,      # % of users with MFA registered
    "mfa_enforced_conditional_access": True,
    "legacy_auth_blocked":          False,   # FAIL — legacy protocols still allowed
    "sspr_enabled":                 True,
    "admin_mfa_percent":            95,
    "privileged_identity_mgmt":     True,    # Azure AD PIM enabled
    "guest_access_policy":          "moderate",  # 'restrictive' | 'moderate' | 'open'
    "password_protection_enabled":  True,
    "device_compliance_required":   False,   # WARN — no Conditional Access device check
    "named_locations_configured":   True,
}

# Domain 2 — Threat Protection
THREAT_DATA = {
    "defender_endpoint_plan":       "P1",    # None | P1 | P2
    "defender_office365_plan":      "P1",
    "safe_links_enabled":           True,
    "safe_attachments_enabled":     True,
    "anti_phishing_policy":         True,
    "anti_spam_policy":             True,
    "defender_identity_enabled":    False,   # WARN — no MDI
    "attack_simulator_training":    False,   # WARN — phishing sims not running
    "cloud_app_security":           False,   # FAIL — Defender for Cloud Apps not licensed
    "incident_response_playbooks":  True,
}

# Domain 3 — Information Protection & Governance
INFOPROT_DATA = {
    "sensitivity_labels_created":   True,
    "sensitivity_labels_published":  True,
    "dlp_policies_count":           3,
    "dlp_teams_enabled":            True,
    "dlp_endpoint_enabled":         False,   # WARN
    "retention_policies_count":     5,
    "records_management_enabled":   True,
    "auto_labeling_policies":       True,
    "communication_compliance":     False,   # INFO
    "insider_risk_management":      False,   # INFO
}

# Domain 4 — Compliance Management
COMPLIANCE_DATA = {
    "compliance_score":             72,      # /100
    "audit_log_enabled":            True,
    "audit_retention_days":         90,
    "content_search_enabled":       True,
    "ediscovery_configured":        True,
    "legal_hold_in_use":            False,   # INFO
    "regulatory_compliance_templates": ["ISO 27001", "NIST 800-53", "GDPR"],
    "data_residency_configured":    False,   # INFO
    "communication_compliance":     False,   # INFO
    "privacy_risk_management":      False,   # INFO
    "purview_audit_level":          "standard",  # 'standard' | 'premium'
}

# ─────────────────────────────────────────────────────────────────────────────
# Check functions
# ─────────────────────────────────────────────────────────────────────────────

def run_identity_checks() -> List[CheckResult]:
    d = IDENTITY_DATA
    results = []

    # IAM-01: MFA registration coverage
    mfa_pct = d["mfa_enabled_percent"]
    status = PASS if mfa_pct >= 90 else (WARN if mfa_pct >= 70 else FAIL)
    results.append(CheckResult(
        "IAM-01", "MFA User Registration Coverage", 1, "Identity & Access",
        status,
        f"{mfa_pct}% of users have MFA registered (target: 90%+).",
        "Enable Security Defaults or Conditional Access to enforce MFA registration for all users."
        if status != PASS else "No action needed."
    ))

    # IAM-02: Conditional Access MFA enforcement
    ca_mfa = d["mfa_enforced_conditional_access"]
    results.append(CheckResult(
        "IAM-02", "Conditional Access: MFA Enforcement", 1, "Identity & Access",
        PASS if ca_mfa else FAIL,
        "Conditional Access policy enforcing MFA is ACTIVE." if ca_mfa
        else "No Conditional Access policy found that enforces MFA.",
        "Create a CA policy: All users → All cloud apps → Require MFA."
        if not ca_mfa else "No action needed."
    ))

    # IAM-03: Legacy authentication blocked
    legacy_blocked = d["legacy_auth_blocked"]
    results.append(CheckResult(
        "IAM-03", "Legacy Authentication Protocols Blocked", 1, "Identity & Access",
        PASS if legacy_blocked else FAIL,
        "Legacy authentication (IMAP/POP3/SMTP AUTH) is BLOCKED." if legacy_blocked
        else "Legacy authentication protocols are still ALLOWED — bypasses MFA.",
        "Create a CA policy that blocks legacy auth clients (applies to 'Other clients')."
        if not legacy_blocked else "No action needed."
    ))

    # IAM-04: Self-Service Password Reset
    sspr = d["sspr_enabled"]
    results.append(CheckResult(
        "IAM-04", "Self-Service Password Reset (SSPR)", 1, "Identity & Access",
        PASS if sspr else WARN,
        "SSPR is ENABLED for all users." if sspr
        else "SSPR is DISABLED — users must call helpdesk to reset passwords.",
        "Enable SSPR under Azure AD → Password reset → Properties → All."
        if not sspr else "No action needed."
    ))

    # IAM-05: Admin MFA coverage
    admin_mfa = d["admin_mfa_percent"]
    results.append(CheckResult(
        "IAM-05", "Privileged Account MFA Coverage", 1, "Identity & Access",
        PASS if admin_mfa == 100 else WARN,
        f"{admin_mfa}% of admin accounts have MFA registered (required: 100%).",
        "Enforce MFA for all Global Admins and privileged roles immediately."
        if admin_mfa < 100 else "No action needed."
    ))

    # IAM-06: Azure AD PIM
    pim = d["privileged_identity_mgmt"]
    results.append(CheckResult(
        "IAM-06", "Privileged Identity Management (PIM)", 1, "Identity & Access",
        PASS if pim else WARN,
        "Azure AD PIM is ENABLED — just-in-time privileged access active." if pim
        else "Azure AD PIM is NOT configured — permanent privileged assignments in use.",
        "Enable and configure PIM (requires Azure AD P2 license)."
        if not pim else "No action needed."
    ))

    # IAM-07: Device compliance in CA
    dev_comp = d["device_compliance_required"]
    results.append(CheckResult(
        "IAM-07", "Conditional Access: Device Compliance Requirement", 1, "Identity & Access",
        PASS if dev_comp else WARN,
        "CA policy requires device compliance for resource access." if dev_comp
        else "No CA policy requires device compliance — unmanaged devices can access resources.",
        "Add a CA policy condition: Require device to be marked as compliant (via Intune)."
        if not dev_comp else "No action needed."
    ))

    return results


def run_threat_checks() -> List[CheckResult]:
    d = THREAT_DATA
    results = []

    # THR-01: Defender for Endpoint
    plan = d["defender_endpoint_plan"]
    results.append(CheckResult(
        "THR-01", "Microsoft Defender for Endpoint Deployment", 2, "Threat Protection",
        PASS if plan else FAIL,
        f"Defender for Endpoint Plan {plan} is active on enrolled devices." if plan
        else "Defender for Endpoint is NOT licensed or deployed.",
        "License Defender for Endpoint P1/P2 and onboard all devices via Intune or Group Policy."
        if not plan else "Consider upgrading to Plan 2 for EDR and threat analytics."
    ))

    # THR-02: Defender for Office 365
    o365_plan = d["defender_office365_plan"]
    results.append(CheckResult(
        "THR-02", "Microsoft Defender for Office 365", 2, "Threat Protection",
        PASS if o365_plan else FAIL,
        f"Defender for Office 365 Plan {o365_plan} active." if o365_plan
        else "Defender for Office 365 NOT enabled — email threat protection absent.",
        "Enable Defender for Office 365 via Microsoft 365 Defender portal."
        if not o365_plan else "No action needed."
    ))

    # THR-03: Safe Links
    results.append(CheckResult(
        "THR-03", "Safe Links Policy Active", 2, "Threat Protection",
        PASS if d["safe_links_enabled"] else FAIL,
        "Safe Links is ENABLED — URLs rewritten and scanned at click time."
        if d["safe_links_enabled"] else "Safe Links is DISABLED.",
        "Enable Safe Links in Defender for Office 365 → Policies → Safe Links."
        if not d["safe_links_enabled"] else "No action needed."
    ))

    # THR-04: Safe Attachments
    results.append(CheckResult(
        "THR-04", "Safe Attachments Policy Active", 2, "Threat Protection",
        PASS if d["safe_attachments_enabled"] else FAIL,
        "Safe Attachments is ENABLED — email attachments detonated in sandbox."
        if d["safe_attachments_enabled"] else "Safe Attachments is DISABLED.",
        "Enable Safe Attachments in Defender for Office 365 → Policies."
        if not d["safe_attachments_enabled"] else "No action needed."
    ))

    # THR-05: Anti-phishing
    results.append(CheckResult(
        "THR-05", "Anti-Phishing Policy Configured", 2, "Threat Protection",
        PASS if d["anti_phishing_policy"] else FAIL,
        "Anti-phishing policy is ACTIVE with impersonation protection."
        if d["anti_phishing_policy"] else "No anti-phishing policy found.",
        "Create an anti-phishing policy in Microsoft Defender → Email & Collaboration."
        if not d["anti_phishing_policy"] else "No action needed."
    ))

    # THR-06: Defender for Identity
    mdi = d["defender_identity_enabled"]
    results.append(CheckResult(
        "THR-06", "Microsoft Defender for Identity (MDI)", 2, "Threat Protection",
        PASS if mdi else WARN,
        "MDI is ACTIVE — on-premises identity threat detection enabled." if mdi
        else "MDI is NOT deployed — on-premises identity attacks may go undetected.",
        "Deploy MDI sensors on domain controllers for lateral movement and credential theft detection."
        if not mdi else "No action needed."
    ))

    # THR-07: Attack Simulator
    sim = d["attack_simulator_training"]
    results.append(CheckResult(
        "THR-07", "Attack Simulation Training", 2, "Threat Protection",
        PASS if sim else WARN,
        "Attack Simulation Training is RUNNING — user phishing awareness being measured." if sim
        else "No phishing simulation campaigns configured.",
        "Launch a phishing simulation in Microsoft Defender → Attack simulation training."
        if not sim else "No action needed."
    ))

    # THR-08: Defender for Cloud Apps
    casb = d["cloud_app_security"]
    results.append(CheckResult(
        "THR-08", "Microsoft Defender for Cloud Apps (CASB)", 2, "Threat Protection",
        PASS if casb else FAIL,
        "Defender for Cloud Apps is ACTIVE — shadow IT and anomalous app usage monitored." if casb
        else "Defender for Cloud Apps is NOT licensed — no CASB protection.",
        "License Defender for Cloud Apps (MCAS) or use the lite Discovery integration with Defender for Endpoint."
        if not casb else "No action needed."
    ))

    return results


def run_infoprot_checks() -> List[CheckResult]:
    d = INFOPROT_DATA
    results = []

    # INF-01: Sensitivity labels created
    results.append(CheckResult(
        "INF-01", "Sensitivity Labels Created and Published", 3, "Information Protection",
        PASS if d["sensitivity_labels_created"] and d["sensitivity_labels_published"] else FAIL,
        "Sensitivity labels are CREATED and PUBLISHED to users."
        if d["sensitivity_labels_created"] else "No sensitivity labels found in Microsoft Purview.",
        "Create label taxonomy in Purview → Information Protection → Labels."
        if not d["sensitivity_labels_created"] else "No action needed."
    ))

    # INF-02: DLP policies
    dlp_count = d["dlp_policies_count"]
    results.append(CheckResult(
        "INF-02", "Data Loss Prevention (DLP) Policies", 3, "Information Protection",
        PASS if dlp_count >= 2 else WARN,
        f"{dlp_count} DLP policies active across Exchange, SharePoint, OneDrive, and Teams.",
        "Create DLP policies for sensitive data types (PII, financial, health data)."
        if dlp_count == 0 else "No action needed."
    ))

    # INF-03: DLP on endpoints
    results.append(CheckResult(
        "INF-03", "DLP — Endpoint Protection", 3, "Information Protection",
        PASS if d["dlp_endpoint_enabled"] else WARN,
        "Endpoint DLP is ACTIVE — data leaving managed devices is monitored." if d["dlp_endpoint_enabled"]
        else "Endpoint DLP is NOT enabled — data exfiltration via USB/browser not blocked.",
        "Enable endpoint DLP in Purview and onboard devices via Intune."
        if not d["dlp_endpoint_enabled"] else "No action needed."
    ))

    # INF-04: Retention policies
    ret_count = d["retention_policies_count"]
    results.append(CheckResult(
        "INF-04", "Retention Policies Configured", 3, "Information Protection",
        PASS if ret_count >= 1 else WARN,
        f"{ret_count} retention policies active across Exchange, SharePoint, and Teams.",
        "Configure retention policies in Purview → Data lifecycle management."
        if ret_count == 0 else "No action needed."
    ))

    # INF-05: Auto-labeling
    results.append(CheckResult(
        "INF-05", "Auto-Labeling Policies Active", 3, "Information Protection",
        PASS if d["auto_labeling_policies"] else WARN,
        "Auto-labeling policies ACTIVE — documents auto-classified at rest/in-transit."
        if d["auto_labeling_policies"] else "No auto-labeling policies — all labeling is manual.",
        "Create simulation-mode auto-labeling policies in Purview → Auto-labeling."
        if not d["auto_labeling_policies"] else "No action needed."
    ))

    # INF-06: Insider Risk Management
    irm = d["insider_risk_management"]
    results.append(CheckResult(
        "INF-06", "Insider Risk Management", 3, "Information Protection",
        PASS if irm else INFO,
        "Insider Risk Management is CONFIGURED — anomalous user data handling detected." if irm
        else "Insider Risk Management is NOT enabled.",
        "Enable Insider Risk Management in Purview (requires Microsoft 365 E5 Compliance license)."
        if not irm else "No action needed."
    ))

    return results


def run_compliance_checks() -> List[CheckResult]:
    d = COMPLIANCE_DATA
    results = []

    # COM-01: Compliance score
    score = d["compliance_score"]
    results.append(CheckResult(
        "COM-01", "Microsoft Compliance Score", 4, "Compliance",
        PASS if score >= 80 else (WARN if score >= 60 else FAIL),
        f"Compliance Manager Score: {score}/100 (target: 80+).",
        "Review Compliance Manager improvement actions in Microsoft Purview → Compliance Manager."
        if score < 80 else "No action needed."
    ))

    # COM-02: Audit log
    results.append(CheckResult(
        "COM-02", "Unified Audit Log Enabled", 4, "Compliance",
        PASS if d["audit_log_enabled"] else FAIL,
        "Unified Audit Log is ENABLED — all M365 activity is being logged."
        if d["audit_log_enabled"] else "Unified Audit Log is DISABLED — no forensic trail.",
        "Enable audit logging: Security & Compliance Center → Search → Audit log search → Turn on."
        if not d["audit_log_enabled"] else "No action needed."
    ))

    # COM-03: Audit retention
    days = d["audit_retention_days"]
    results.append(CheckResult(
        "COM-03", "Audit Log Retention Duration", 4, "Compliance",
        PASS if days >= 180 else WARN,
        f"Audit logs retained for {days} days (recommended: 180+ days / 1 year for E5).",
        "Upgrade to audit premium for 1-year retention, or configure custom retention policies."
        if days < 180 else "No action needed."
    ))

    # COM-04: eDiscovery
    results.append(CheckResult(
        "COM-04", "eDiscovery Cases Configured", 4, "Compliance",
        PASS if d["ediscovery_configured"] else WARN,
        "eDiscovery is configured — legal search and export capabilities ready."
        if d["ediscovery_configured"] else "eDiscovery has not been configured.",
        "Set up eDiscovery in Purview → eDiscovery → Standard cases."
        if not d["ediscovery_configured"] else "No action needed."
    ))

    # COM-05: Regulatory compliance templates
    templates = d["regulatory_compliance_templates"]
    results.append(CheckResult(
        "COM-05", "Regulatory Compliance Templates Active", 4, "Compliance",
        PASS if len(templates) >= 1 else WARN,
        f"Active compliance templates: {', '.join(templates)}." if templates
        else "No regulatory compliance templates configured.",
        "Add regulation templates in Purview → Compliance Manager → Regulations."
        if not templates else "No action needed."
    ))

    # COM-06: Purview audit level
    audit_level = d["purview_audit_level"]
    results.append(CheckResult(
        "COM-06", "Microsoft Purview Audit Level", 4, "Compliance",
        PASS if audit_level == "premium" else WARN,
        f"Audit level: {audit_level.upper()} (Premium includes longer retention + MailItemsAccessed)."
        if audit_level else "Audit level not configured.",
        "Upgrade to Audit Premium for high-value events, intelligent insights, and 1-year default retention."
        if audit_level != "premium" else "No action needed."
    ))

    return results

# ─────────────────────────────────────────────────────────────────────────────
# Output formatting
# ─────────────────────────────────────────────────────────────────────────────

STATUS_SYMBOLS = {
    PASS: green("✓ PASS"),
    FAIL: red("✗ FAIL"),
    WARN: yellow("⚠ WARN"),
    INFO: blue("ℹ INFO"),
}

STATUS_SYMBOLS_PLAIN = {
    PASS: "PASS",
    FAIL: "FAIL",
    WARN: "WARN",
    INFO: "INFO",
}

DOMAIN_NAMES = {
    1: "Identity & Access Management",
    2: "Threat Protection",
    3: "Information Protection & Governance",
    4: "Compliance Management",
}

def print_banner():
    banner = """
╔══════════════════════════════════════════════════════════════════════════╗
║          Microsoft SC-900 Security Posture Assessment Tool              ║
║          Harkaran Singh | 24BCY70083 | Chandigarh University            ║
║          SC-900 Certified — Score: 988/1000 | Oct 29, 2026              ║
╚══════════════════════════════════════════════════════════════════════════╝
"""
    print(cyan(banner))

def print_tenant_info():
    t = MOCK_TENANT
    print(bold("  Tenant Information"))
    print(f"  {'Name':25s}: {t['name']}")
    print(f"  {'Tenant ID':25s}: {t['tenant_id']}")
    print(f"  {'Domain':25s}: {t['domain']}")
    print(f"  {'Total Users':25s}: {t['users_total']:,} ({t['licensed_users']:,} licensed)")
    print(f"  {'Assessment Date':25s}: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

def print_domain_header(domain_num: int, check_count: int):
    name = DOMAIN_NAMES[domain_num]
    print(bold(f"\n  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
    print(bold(f"  Domain {domain_num}: {name}  ({check_count} checks)"))
    print(bold(f"  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))

def print_check(r: CheckResult):
    sym = STATUS_SYMBOLS.get(r.status, r.status)
    print(f"\n  [{sym}] {bold(r.check_id)}: {r.name}")
    print(f"         {dim('Detail')}     : {r.detail}")
    if r.status in (FAIL, WARN):
        print(f"         {dim('Remediation')}: {yellow(r.remediation)}")

def print_summary(results: List[CheckResult]):
    total  = len(results)
    passes = sum(1 for r in results if r.status == PASS)
    fails  = sum(1 for r in results if r.status == FAIL)
    warns  = sum(1 for r in results if r.status == WARN)
    infos  = sum(1 for r in results if r.status == INFO)

    pct = round((passes / total) * 100) if total else 0

    print(bold(f"\n\n  {'━'*66}"))
    print(bold(f"  ASSESSMENT SUMMARY"))
    print(bold(f"  {'━'*66}"))
    print(f"  {'Total Checks':35s}: {total}")
    print(f"  {green('Passed'):35s}: {passes}  ({round(passes/total*100)}%)")
    print(f"  {red('Failed'):35s}: {fails}  ({round(fails/total*100)}%)")
    print(f"  {yellow('Warnings'):35s}: {warns}  ({round(warns/total*100)}%)")
    print(f"  {blue('Informational'):35s}: {infos}")
    print(f"\n  {'Overall Security Score':35s}: {bold(cyan(str(pct) + '/100'))}")

    grade = "A" if pct >= 90 else "B" if pct >= 80 else "C" if pct >= 70 else "D"
    grade_color = green(grade) if grade in ("A", "B") else yellow(grade) if grade == "C" else red(grade)
    print(f"  {'Security Grade':35s}: {grade_color}")
    print(bold(f"  {'━'*66}\n"))

    # Per-domain breakdown
    print(bold("  Domain Breakdown:"))
    for domain_num, domain_name in DOMAIN_NAMES.items():
        d_results = [r for r in results if r.domain == domain_num]
        if not d_results:
            continue
        d_pass = sum(1 for r in d_results if r.status == PASS)
        d_total = len(d_results)
        d_pct = round(d_pass / d_total * 100)
        bar_filled = "█" * (d_pct // 5)
        bar_empty  = "░" * (20 - d_pct // 5)
        bar = (green if d_pct >= 80 else yellow if d_pct >= 60 else red)(bar_filled) + dim(bar_empty)
        print(f"  Domain {domain_num} [{bar}] {d_pct:3d}%  {domain_name}")

    print()

# ─────────────────────────────────────────────────────────────────────────────
# HTML Report Generator
# ─────────────────────────────────────────────────────────────────────────────

STATUS_HTML_CLASS = {PASS: "pass", FAIL: "fail", WARN: "warn", INFO: "info"}
STATUS_HTML_LABEL = {PASS: "✓ PASS", FAIL: "✗ FAIL", WARN: "⚠ WARN", INFO: "ℹ INFO"}

def generate_html_report(results: List[CheckResult], output_path: str):
    total  = len(results)
    passes = sum(1 for r in results if r.status == PASS)
    fails  = sum(1 for r in results if r.status == FAIL)
    warns  = sum(1 for r in results if r.status == WARN)
    infos  = sum(1 for r in results if r.status == INFO)
    score  = round((passes / total) * 100) if total else 0
    grade  = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D"
    now    = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    domain_rows = ""
    for domain_num, domain_name in DOMAIN_NAMES.items():
        d_results = [r for r in results if r.domain == domain_num]
        if not d_results:
            continue
        d_pass = sum(1 for r in d_results if r.status == PASS)
        d_total = len(d_results)
        d_pct   = round(d_pass / d_total * 100)
        rows_html = ""
        for r in d_results:
            rem_html = (f'<div class="remediation">🔧 {r.remediation}</div>'
                        if r.status in (FAIL, WARN) else "")
            rows_html += f"""
            <tr>
                <td><code>{r.check_id}</code></td>
                <td>{r.name}</td>
                <td><span class="badge {STATUS_HTML_CLASS[r.status]}">{STATUS_HTML_LABEL[r.status]}</span></td>
                <td>{r.detail}{rem_html}</td>
            </tr>"""

        domain_rows += f"""
        <div class="domain-section">
            <h3>Domain {domain_num}: {domain_name}
                <span class="domain-score">Score: {d_pass}/{d_total} ({d_pct}%)</span>
            </h3>
            <table>
                <thead><tr><th>ID</th><th>Check</th><th>Status</th><th>Details & Remediation</th></tr></thead>
                <tbody>{rows_html}</tbody>
            </table>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SC-900 Security Posture Assessment — {MOCK_TENANT['name']}</title>
<style>
  :root {{
    --bg: #0f1117; --surface: #1a1d2e; --surface2: #242740;
    --pass: #22c55e; --fail: #ef4444; --warn: #f59e0b; --info: #3b82f6;
    --text: #e2e8f0; --muted: #94a3b8; --border: #2d3348;
    --accent: #6366f1;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif;
         font-size: 14px; line-height: 1.6; padding: 24px; }}
  .header {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px;
             padding: 28px 32px; margin-bottom: 24px; }}
  .header h1 {{ font-size: 22px; color: var(--accent); margin-bottom: 4px; }}
  .header .meta {{ color: var(--muted); font-size: 13px; }}
  .score-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
                 gap: 16px; margin-bottom: 24px; }}
  .score-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
                 padding: 20px; text-align: center; }}
  .score-card .num {{ font-size: 36px; font-weight: 700; }}
  .score-card .label {{ font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; }}
  .score-card.pass-card .num {{ color: var(--pass); }}
  .score-card.fail-card .num {{ color: var(--fail); }}
  .score-card.warn-card .num {{ color: var(--warn); }}
  .score-card.grade-card .num {{ color: var(--accent); font-size: 48px; }}
  .domain-section {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
                     padding: 24px; margin-bottom: 20px; }}
  .domain-section h3 {{ font-size: 16px; margin-bottom: 16px; color: var(--accent);
                        display: flex; justify-content: space-between; align-items: center; }}
  .domain-score {{ font-size: 13px; background: var(--surface2); padding: 4px 10px;
                   border-radius: 20px; color: var(--text); font-weight: 400; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ background: var(--surface2); padding: 10px 12px; text-align: left; font-size: 12px;
        text-transform: uppercase; letter-spacing: .05em; color: var(--muted); }}
  td {{ padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: rgba(255,255,255,.02); }}
  .badge {{ display: inline-block; padding: 2px 10px; border-radius: 20px; font-size: 12px; font-weight: 600; white-space: nowrap; }}
  .badge.pass {{ background: rgba(34,197,94,.15); color: var(--pass); border: 1px solid rgba(34,197,94,.3); }}
  .badge.fail {{ background: rgba(239,68,68,.15); color: var(--fail); border: 1px solid rgba(239,68,68,.3); }}
  .badge.warn {{ background: rgba(245,158,11,.15); color: var(--warn); border: 1px solid rgba(245,158,11,.3); }}
  .badge.info {{ background: rgba(59,130,246,.15); color: var(--info); border: 1px solid rgba(59,130,246,.3); }}
  .remediation {{ margin-top: 6px; font-size: 12px; color: var(--warn); background: rgba(245,158,11,.08);
                  padding: 6px 10px; border-radius: 6px; border-left: 3px solid var(--warn); }}
  code {{ font-family: 'Consolas', monospace; background: var(--surface2); padding: 1px 6px;
           border-radius: 4px; font-size: 12px; color: var(--accent); }}
  .footer {{ text-align: center; margin-top: 32px; color: var(--muted); font-size: 12px; }}
</style>
</head>
<body>
<div class="header">
  <h1>🛡️ SC-900 Security Posture Assessment</h1>
  <div class="meta">
    Tenant: <strong>{MOCK_TENANT['name']}</strong> &nbsp;|&nbsp;
    Domain: {MOCK_TENANT['domain']} &nbsp;|&nbsp;
    Users: {MOCK_TENANT['users_total']:,} &nbsp;|&nbsp;
    Assessment run: {now}<br>
    Tool: sc900_security_checker.py &nbsp;|&nbsp;
    Author: Harkaran Singh (24BCY70083) &nbsp;|&nbsp;
    SC-900 Score: 988/1000 (Oct 29, 2026)
  </div>
</div>

<div class="score-grid">
  <div class="score-card grade-card"><div class="num">{grade}</div><div class="label">Overall Grade</div></div>
  <div class="score-card pass-card"><div class="num">{score}</div><div class="label">Score (/100)</div></div>
  <div class="score-card pass-card"><div class="num">{passes}</div><div class="label">Checks Passed</div></div>
  <div class="score-card fail-card"><div class="num">{fails}</div><div class="label">Checks Failed</div></div>
  <div class="score-card warn-card"><div class="num">{warns}</div><div class="label">Warnings</div></div>
  <div class="score-card"><div class="num">{total}</div><div class="label">Total Checks</div></div>
</div>

{domain_rows}

<div class="footer">
  Generated by sc900_security_checker.py &nbsp;·&nbsp;
  Industrial Training Project &nbsp;·&nbsp;
  Harkaran Singh | 24BCY70083 | Chandigarh University
</div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(green(f"\n  ✓ HTML report saved → {output_path}"))

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

DOMAIN_RUNNERS = {
    1: run_identity_checks,
    2: run_threat_checks,
    3: run_infoprot_checks,
    4: run_compliance_checks,
}

def main():
    parser = argparse.ArgumentParser(
        description="SC-900 Security Posture Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sc900_security_checker.py                 # Full assessment
  python sc900_security_checker.py --domain 1      # Identity & Access only
  python sc900_security_checker.py --report        # Full assessment + HTML report
  python sc900_security_checker.py --domain 2 --report
  python sc900_security_checker.py --json          # Output raw JSON
        """
    )
    parser.add_argument("--domain",  type=int, choices=[1, 2, 3, 4],
                        help="Run checks for a single domain only")
    parser.add_argument("--report",  action="store_true",
                        help="Export HTML security report")
    parser.add_argument("--output",  default="sc900_assessment_report.html",
                        help="HTML report output filename (default: sc900_assessment_report.html)")
    parser.add_argument("--json",    action="store_true",
                        help="Print results as JSON to stdout")
    args = parser.parse_args()

    print_banner()
    print_tenant_info()

    all_results: List[CheckResult] = []
    domains_to_run = [args.domain] if args.domain else [1, 2, 3, 4]

    for domain_num in domains_to_run:
        runner = DOMAIN_RUNNERS[domain_num]
        print(f"  Running Domain {domain_num} checks", end="", flush=True)
        time.sleep(0.3)
        results = runner()
        all_results.extend(results)
        print_domain_header(domain_num, len(results))
        for r in results:
            print_check(r)
            time.sleep(0.05)

    print_summary(all_results)

    if args.json:
        print(json.dumps([r.as_dict() for r in all_results], indent=2))

    if args.report:
        generate_html_report(all_results, args.output)

    # Exit code: 1 if any FAIL, 0 otherwise
    has_fails = any(r.status == FAIL for r in all_results)
    sys.exit(1 if has_fails else 0)


if __name__ == "__main__":
    main()
