# PCI DSS v4.0 Compliance Matrix

This document maps each FleetDM endpoint policy to relevant PCI DSS v4.0
requirements. PCI DSS (Payment Card Industry Data Security Standard) applies
to any organisation that stores, processes, or transmits cardholder data (CHD)
or sensitive authentication data (SAD).

PCI DSS v4.0 replaced v3.2.1 in March 2022 with a transition deadline of
March 2025. This matrix references v4.0 requirement numbers.

**Scope note:** PCI DSS applies to systems in the Cardholder Data Environment
(CDE) and systems that can affect the security of the CDE. For most organisations,
employee endpoints are in scope if they can access the CDE, cardholder data, or
systems that process payment data. Confirm scope with your Qualified Security
Assessor (QSA) before relying on this matrix.

Each policy has a corresponding YAML definition under `fleet/policies/` containing
the full osquery query, resolution steps, and detailed compliance rationale.
The watched policy list is maintained in `remediation/policies.yml`.

> **EDR note:** Entries referencing CrowdStrike also apply to Cisco Secure Endpoint
> and SentinelOne. Substitute the appropriate policy file for your deployed EDR:
> `crowdstrike-*.yml` → `cisco-secure-endpoint-*.yml` or `sentinelone-*.yml`

---

## Relevant PCI DSS Requirements

| Requirement | Title | Relevance |
|---|---|---|
| Req 1 | Install and Maintain Network Security Controls | Firewall, network controls |
| Req 2 | Apply Secure Configurations | Hardened baseline, unnecessary services |
| Req 3 | Protect Stored Account Data | Encryption at rest |
| Req 5 | Protect All Systems Against Malware | EDR, antimalware |
| Req 6 | Develop and Maintain Secure Systems | Patching, vulnerability management |
| Req 7 | Restrict Access to System Components | Least privilege, access control |
| Req 8 | Identify Users and Authenticate Access | Authentication, password policy |
| Req 10 | Log and Monitor All Access | Audit logging, NTP |
| Req 11 | Test Security of Systems and Networks | Continuous monitoring |
| Req 12 | Support Information Security with Policies | Organisational controls |

---

## Coverage Summary

| PCI DSS Requirement | Coverage | Notes |
|---|---|---|
| Req 1 — Network Security Controls | Partial | Host firewall covered; network segmentation is infrastructure |
| Req 2 — Secure Configurations | Strong | Hardened baseline across sharing/service policies |
| Req 3 — Protect Stored Account Data | Covered | FileVault encryption at rest |
| Req 5 — Protect Against Malware | Strong | EDR running + version + kernel extension (5.3.3) |
| Req 6 — Secure Systems and Software | Covered | OS patching, auto-updates, Gatekeeper |
| Req 7 — Restrict Access | Covered | Least privilege, guest disabled, admin accounts |
| Req 8 — Identify and Authenticate | Strong | Password, screen lock, session timeout, MFA (Okta Verify) |
| Req 10 — Log and Monitor | Strong | Audit logging + flags configured + NTP |
| Req 11 — Test Security | Covered | Drift check provides continuous automated testing |
| Req 12 — Organisational Policies | Gap | Policies, training, incident response are organisational |

---

## Requirement 1 — Install and Maintain Network Security Controls

### 1.3 — Network Access Controls

| Sub-requirement | Description | Policy | File |
|---|---|---|---|
| 1.3.2 | Restrict inbound traffic to only necessary communications | Firewall enabled | `firewall-enabled.yml` |
| 1.3.2 | Restrict inbound traffic to only necessary communications | SSH remote login disabled | `ssh-disabled.yml` |
| 1.3.2 | Restrict inbound traffic to only necessary communications | Screen sharing disabled | `screen-sharing-disabled.yml` |
| 1.3.2 | Restrict inbound traffic to only necessary communications | Remote management disabled | `remote-management-disabled.yml` |
| 1.3.2 | Restrict inbound traffic to only necessary communications | Internet sharing disabled | `internet-sharing-disabled.yml` |
| 1.3.2 | Restrict inbound traffic to only necessary communications | Printer sharing disabled | `printer-sharing-disabled.yml` |
| 1.3.2 | Restrict inbound traffic to only necessary communications | Content caching disabled | `content-caching-disabled.yml` |
| 1.3.2 | Restrict inbound traffic to only necessary communications | Bluetooth managed via configuration profile | `bluetooth-managed.yml` |
| 1.3.2 | Restrict inbound traffic to only necessary communications | DNS filtering configured | `dns-filtering-configured.yml` |

---

## Requirement 2 — Apply Secure Configurations to All System Components

### 2.2 — System Components Configured and Managed Securely

| Sub-requirement | Description | Policy | File |
|---|---|---|---|
| 2.2.1 | Configuration standards developed and implemented | All policies | All policy files — defines the approved baseline |
| 2.2.4 | Only necessary services, protocols, daemons enabled | SSH remote login disabled | `ssh-disabled.yml` |
| 2.2.4 | Only necessary services, protocols, daemons enabled | Screen sharing disabled | `screen-sharing-disabled.yml` |
| 2.2.4 | Only necessary services, protocols, daemons enabled | Remote management disabled | `remote-management-disabled.yml` |
| 2.2.4 | Only necessary services, protocols, daemons enabled | Internet sharing disabled | `internet-sharing-disabled.yml` |
| 2.2.4 | Only necessary services, protocols, daemons enabled | Printer sharing disabled | `printer-sharing-disabled.yml` |
| 2.2.4 | Only necessary services, protocols, daemons enabled | Content caching disabled | `content-caching-disabled.yml` |
| 2.2.4 | Only necessary services, protocols, daemons enabled | AirDrop disabled | `airdrop-disabled.yml` |
| 2.2.7 | All non-console admin access encrypted | SSH remote login disabled | `ssh-disabled.yml` |

---

## Requirement 3 — Protect Stored Account Data

### 3.5 — Primary Account Number (PAN) Secured

| Sub-requirement | Description | Policy | File |
|---|---|---|---|
| 3.5.1 | PAN secured with strong cryptography if stored | Disk encryption enabled | `disk-encryption.yml` |
| 3.5.1 | PAN secured with strong cryptography if stored | FileVault recovery key escrowed | `filevault-key-escrowed.yml` |

> PCI DSS Req 3 is primarily satisfied by application-level controls that
> prevent PAN storage on endpoints. FileVault encryption provides defence-in-depth
> for any cardholder data that transiently exists on managed devices.

---

## Requirement 5 — Protect All Systems and Networks from Malicious Software

### 5.2 — Malware Solution Deployed and Active

| Sub-requirement | Description | Policy | File |
|---|---|---|---|
| 5.2.1 | Anti-malware solution deployed on all applicable components | CrowdStrike running | `crowdstrike-running.yml` |
| 5.2.2 | Anti-malware solution detects, removes, protects | CrowdStrike running | `crowdstrike-running.yml` |
| 5.2.3 | Periodic evaluations of components not at risk | CrowdStrike running | `crowdstrike-running.yml` |

### 5.3 — Anti-malware Mechanisms and Processes Active

| Sub-requirement | Description | Policy | File |
|---|---|---|---|
| 5.3.1 | Anti-malware solution kept current | CrowdStrike version current | `crowdstrike-version.yml` |
| 5.3.2 | Periodic scans or continuous behavioural analysis | CrowdStrike running | `crowdstrike-running.yml` |
| 5.3.3 | Anti-malware cannot be disabled by users | CrowdStrike running | `crowdstrike-running.yml` |
| 5.3.3 | Anti-malware cannot be disabled by users | CrowdStrike kernel extension loaded | `crowdstrike-kernel-extension.yml` |

> **5.3.3** is best evidenced by the kernel extension check, not the process
> check alone. The kernel extension operates at a privilege level above user
> processes and cannot be unloaded without disabling SIP — providing strong
> technical proof that CrowdStrike cannot be disabled by users.

### 5.4 — Phishing Protections

| Sub-requirement | Description | Policy | File |
|---|---|---|---|
| 5.4.1 | Processes in place to detect and protect against phishing | Gatekeeper enabled | `gatekeeper-enabled.yml` |

---

## Requirement 6 — Develop and Maintain Secure Systems and Software

### 6.3 — Security Vulnerabilities Identified and Addressed

| Sub-requirement | Description | Policy | File |
|---|---|---|---|
| 6.3.3 | All system components protected from known vulnerabilities | OS up to date | `os-up-to-date.yml` |
| 6.3.3 | All system components protected from known vulnerabilities | Automatic updates enabled | `auto-updates-enabled.yml` |
| 6.3.3 | All system components protected from known vulnerabilities | CrowdStrike version current | `crowdstrike-version.yml` |

### 6.4 — Public-Facing Web Applications Protected

| Sub-requirement | Description | Policy | File |
|---|---|---|---|
| 6.4.1 | Web-based attacks identified and protected against | Firewall enabled | `firewall-enabled.yml` |

---

## Requirement 7 — Restrict Access to System Components and Cardholder Data

### 7.2 — Access Control System Implemented

| Sub-requirement | Description | Policy | File |
|---|---|---|---|
| 7.2.1 | Access control system covering all system components | Guest account disabled | `guest-account-disabled.yml` |
| 7.2.1 | Access control system covering all system components | No unauthorized local admin accounts | `no-local-admin-accounts.yml` |
| 7.2.2 | Access assigned based on need-to-know and least privilege | No unauthorized local admin accounts | `no-local-admin-accounts.yml` |
| 7.2.5 | Default accounts managed appropriately | Guest account disabled | `guest-account-disabled.yml` |

---

## Requirement 8 — Identify Users and Authenticate Access

### 8.2 — User Identification and Related Accounts Managed

| Sub-requirement | Description | Policy | File |
|---|---|---|---|
| 8.2.1 | All users assigned unique ID | Guest account disabled | `guest-account-disabled.yml` |
| 8.2.1 | All users assigned unique ID | Login window shows name and password fields | `login-window-display.yml` |
| 8.2.2 | Group, shared, and generic accounts managed | Guest account disabled | `guest-account-disabled.yml` |
| 8.2.6 | Inactive accounts removed or disabled within 90 days | No unauthorized local admin accounts | `no-local-admin-accounts.yml` |
| 8.2.8 | Session idle timeout — re-authentication after ≤15 minutes | PCI session idle timeout configured | `pci-session-timeout.yml` |
| 8.2.8 | Session idle timeout — re-authentication after ≤15 minutes | Password required after lock | `password-required-after-lock.yml` |

### 8.3 — User Authentication for Users and Admins

| Sub-requirement | Description | Policy | File |
|---|---|---|---|
| 8.3.6 | Minimum password complexity requirements | Password complexity enforced | `password-complexity.yml` |
| 8.3.9 | Passwords/passphrases changed at least once every 90 days | Password complexity enforced | `password-complexity.yml` |

### 8.4 — Multi-Factor Authentication

| Sub-requirement | Description | Policy | File |
|---|---|---|---|
| 8.4.2 | MFA implemented for all access into the CDE | Okta Verify installed | `okta-verify-running.yml` |
| 8.4.3 | MFA implemented for all remote network access | Okta Verify installed | `okta-verify-running.yml` |

### 8.6 — System and Application Accounts Managed

| Sub-requirement | Description | Policy | File |
|---|---|---|---|
| 8.6.1 | Interactive login for application and system accounts managed | No unauthorized local admin accounts | `no-local-admin-accounts.yml` |

---

## Requirement 10 — Log and Monitor All Access to System Components and Cardholder Data

### 10.2 — Audit Logs Implemented

| Sub-requirement | Description | Policy | File |
|---|---|---|---|
| 10.2.1 | Audit logs capturing required events | Audit logging enabled | `audit-logging-enabled.yml` |
| 10.2.1 | Audit logs capturing required events | BSM audit flags configured | `audit-flags-configured.yml` |
| 10.2.1.1 | Individual user access to CHD | Audit logging enabled | `audit-logging-enabled.yml` |
| 10.2.1.1 | Individual user access to CHD | BSM audit flags configured | `audit-flags-configured.yml` |
| 10.2.1.2 | All actions by individuals with root or admin access | Audit logging enabled | `audit-logging-enabled.yml` |
| 10.2.1.2 | All actions by individuals with root or admin access | BSM audit flags configured | `audit-flags-configured.yml` |
| 10.2.1.4 | Invalid logical access attempts | BSM audit flags configured | `audit-flags-configured.yml` |
| 10.2.1.5 | Authentication mechanism usage and changes | BSM audit flags configured | `audit-flags-configured.yml` |
| 10.2.1.6 | Initialisation, stopping, or pausing of audit logs | Audit logging enabled | `audit-logging-enabled.yml` |
| 10.2.1.7 | Creation and deletion of system-level objects | BSM audit flags configured | `audit-flags-configured.yml` |

> **audit-flags-configured.yml** and **audit-logging-enabled.yml** form a control
> pair: the first confirms auditd is running; the second confirms it captures
> the specific event classes required by Req 10.2.1. Both are required for
> complete coverage. QSAs will test audit log completeness explicitly.

### 10.6 — Time Synchronisation Mechanisms

| Sub-requirement | Description | Policy | File |
|---|---|---|---|
| 10.6.1 | System clocks and time synchronised using accepted technology | NTP time synchronisation configured | `ntp-configured.yml` |
| 10.6.2 | Systems configured to correct time from authoritative source | NTP time synchronisation configured | `ntp-configured.yml` |
| 10.6.3 | Time synchronisation settings and data protected | NTP time synchronisation configured | `ntp-configured.yml` |

> **PCI DSS 10.6 is explicit about NTP** — it is one of the few requirements
> that directly mandates time synchronisation by name. A QSA will specifically
> test for this. The `ntp-configured.yml` policy provides continuous automated
> evidence that time sync is enforced via managed profile.

### 10.7 — Failures of Critical Security Controls Detected and Reported

| Sub-requirement | Description | Policy | File |
|---|---|---|---|
| 10.7.2 | Failures of critical security controls detected and reported promptly | CrowdStrike running | `crowdstrike-running.yml` |
| 10.7.2 | Failures of critical security controls detected and reported promptly | Audit logging enabled | `audit-logging-enabled.yml` |
| 10.7.2 | Failures of critical security controls detected and reported promptly | Firewall enabled | `firewall-enabled.yml` |
| 10.7.2 | Failures of critical security controls detected and reported promptly | Endpoint backup agent running | `backup-agent-running.yml` |
| 10.7.2 | Failures of critical security controls detected and reported promptly | MDM enrollment certificate valid | `mdm-enrollment-valid.yml` |

---

## Requirement 11 — Test Security of Systems and Networks Regularly

### 11.3 — External and Internal Vulnerabilities Identified and Addressed

| Sub-requirement | Description | Policy | File |
|---|---|---|---|
| 11.3.1 | Internal vulnerability scans performed | OS up to date | `os-up-to-date.yml` |
| 11.3.1 | Internal vulnerability scans performed | CrowdStrike version current | `crowdstrike-version.yml` |

### 11.5 — Network Intrusions and Unexpected File Changes Detected

| Sub-requirement | Description | Policy | File |
|---|---|---|---|
| 11.5.1 | Intrusion detection / prevention techniques employed | CrowdStrike running | `crowdstrike-running.yml` |
| 11.5.2 | Change detection mechanism deployed | System Integrity Protection enabled | `sip-enabled.yml` |
| 11.5.2 | Change detection mechanism deployed | Audit logging enabled | `audit-logging-enabled.yml` |

### 11.6 — Unauthorised Changes to Payment Pages Detected

| Sub-requirement | Description | Policy | File |
|---|---|---|---|
| 11.6.1 | Change and tamper detection mechanisms | System Integrity Protection enabled | `sip-enabled.yml` |

---

## Key Gaps

These PCI DSS requirements are not addressed by endpoint policies and require
separate infrastructure, application, or organisational controls. These are
the most significant gaps for a QSA assessment:

### Infrastructure Gaps

| Requirement | Gap | Coverage Approach |
|---|---|---|
| Req 1.2 | Network security controls between CDE and other networks | Network segmentation, VLANs, perimeter firewall |
| Req 1.3.1 | Inbound traffic from internet to CDE restricted | Perimeter firewall / WAF |
| Req 1.4 | Network controls between trusted and untrusted networks | VPN, network segmentation |
| Req 4.2 | PAN protected in transit with strong cryptography | TLS enforcement, certificate management |
| Req 9 | Physical access to system components restricted | Office physical security, badge access |

### Application and Data Gaps

| Requirement | Gap | Coverage Approach |
|---|---|---|
| Req 3.3 | SAD not retained after authorisation | Application-level data handling |
| Req 3.4 | PAN masked when displayed | Application-level masking controls |
| Req 3.5 | PAN secured with strong cryptography | Application-level encryption, tokenisation |
| Req 6.2 | Bespoke software developed securely | Secure SDLC, code review, SAST/DAST |
| Req 6.3.2 | Application inventory maintained | Software asset management |

### Organisational Gaps

| Requirement | Gap | Coverage Approach |
|---|---|---|
| Req 12.1 | Information security policy established | Information security policy document |
| Req 12.3 | Risks identified, assessed, and managed | Annual risk assessment process |
| Req 12.5 | PCI DSS scope documented and validated | QSA-assisted scope definition and annual validation |
| Req 12.6 | Security awareness programme implemented | Annual security awareness training |
| Req 12.8 | Third-party service provider risk managed | TPSP agreements, PCI DSS compliance verification |
| Req 12.9 | TPSP acknowledgement of responsibility | Written acknowledgement from all relevant TPSPs |
| Req 12.10 | Incident response plan implemented | IR plan covering payment data breach scenarios |

### Assessment Gaps

| Requirement | Gap | Coverage Approach |
|---|---|---|
| Req 11.3.2 | External penetration testing annually | Annual pentest by QSA or approved vendor |
| Req 11.4 | Network intrusion detection / prevention | Network-level IDS/IPS (not just endpoint EDR) |
| Req 11.6 | Payment page tamper detection | Specific to web payment pages — application control |

> **Most critical for Abridge:** If Abridge processes payments directly, Req 3
> (cardholder data protection), Req 4 (encryption in transit), Req 12.5 (scope
> definition), and Req 12.8 (TPSP management) are the highest priority gaps.
> If Abridge uses a payment processor that handles all CHD (e.g. Stripe in
> iframe/redirect mode), scope may be significantly reduced. Confirm with a QSA.
