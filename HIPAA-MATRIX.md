# HIPAA Security Rule Compliance Matrix

This document maps each FleetDM endpoint policy to its corresponding HIPAA
Security Rule requirements. Required specifications must be implemented.
Addressable specifications should be treated as required for a healthcare AI
company handling ePHI.

Each policy has a corresponding YAML definition under `fleet/policies/` containing
the full osquery query, resolution steps, and detailed compliance rationale.
The watched policy list is maintained in `remediation/policies.yml`.

> **EDR note:** Entries referencing CrowdStrike also apply to Cisco Secure Endpoint
> and SentinelOne. Substitute the appropriate policy file for your deployed EDR:
> `crowdstrike-*.yml` → `cisco-secure-endpoint-*.yml` or `sentinelone-*.yml`

---

## Coverage Summary

| Section | Description | Status |
|---|---|---|
| § 164.308(a)(1) | Security Management Process | Partial — policies support risk management |
| § 164.308(a)(3) | Workforce Access Management | Covered — local admin, guest account |
| § 164.308(a)(5) | Security Awareness and Training | Covered — malware protection, password mgmt |
| § 164.308(a)(7) | Contingency Plan | Covered — backup agent running |
| § 164.308(a)(8) | Evaluation | Covered — continuous monitoring via Fleet |
| § 164.310(d) | Device and Media Controls | Covered — encryption, AirDrop, backup |
| § 164.312(a) | Access Control | Strong — guest, admin, screen lock, password, Okta Verify |
| § 164.312(b) | Audit Controls | Covered — BSM audit logging, NTP |
| § 164.312(c) | Integrity | Covered — SIP, Gatekeeper, MDM enrollment |
| § 164.312(d) | Person or Entity Authentication | Strong — password, lock, Okta Verify |
| § 164.312(e) | Transmission Security | Strong — firewall, SSH, screen sharing, Bluetooth, DNS |

---

## § 164.308 — Administrative Safeguards

### § 164.308(a)(1) — Security Management Process

| Specification | Type | Policy | File |
|---|---|---|---|
| (ii)(B) Risk Management | Required | OS up to date | `os-up-to-date.yml` |
| (ii)(B) Risk Management | Required | CrowdStrike running | `crowdstrike-running.yml` |
| (ii)(B) Risk Management | Required | Firewall enabled | `firewall-enabled.yml` |
| (ii)(D) Information System Activity Review | Required | Audit logging enabled | `audit-logging-enabled.yml` |

### § 164.308(a)(3) — Workforce Access Management

| Specification | Type | Policy | File |
|---|---|---|---|
| (ii)(A) Authorization / Supervision | Addressable | No unauthorized local admin accounts | `no-local-admin-accounts.yml` |
| (ii)(B) Workforce Clearance | Addressable | No unauthorized local admin accounts | `no-local-admin-accounts.yml` |
| (ii)(C) Termination Procedures | Addressable | Guest account disabled | `guest-account-disabled.yml` |

### § 164.308(a)(5) — Security Awareness and Training

| Specification | Type | Policy | File |
|---|---|---|---|
| (ii)(B) Protection from Malicious Software | Addressable | CrowdStrike running | `crowdstrike-running.yml` |
| (ii)(B) Protection from Malicious Software | Addressable | CrowdStrike version current | `crowdstrike-version.yml` |
| (ii)(B) Protection from Malicious Software | Addressable | OS up to date | `os-up-to-date.yml` |
| (ii)(B) Protection from Malicious Software | Addressable | Gatekeeper enabled | `gatekeeper-enabled.yml` |
| (ii)(B) Protection from Malicious Software | Addressable | Automatic updates enabled | `auto-updates-enabled.yml` |
| (ii)(D) Password Management | Addressable | Password complexity enforced | `password-complexity.yml` |
| (ii)(D) Password Management | Addressable | Password required after lock | `password-required-after-lock.yml` |

### § 164.308(a)(7) — Contingency Plan

| Specification | Type | Policy | File |
|---|---|---|---|
| (ii)(A) Data Backup Plan | Required | Endpoint backup agent running | `backup-agent-running.yml` |
| (ii)(B) Disaster Recovery Plan | Required | Endpoint backup agent running | `backup-agent-running.yml` |

> The backup agent policy verifies the backup mechanism is in place. Backup
> completion and restore testing must be verified separately in your backup
> management console to fully satisfy § 164.308(a)(7).

### § 164.308(a)(8) — Evaluation

| Specification | Type | Policy | File |
|---|---|---|---|
| Periodic Technical Evaluation | Required | All 24 policies — continuous automated evaluation via Fleet drift check | `policies.yml` |

---

## § 164.310 — Physical Safeguards

### § 164.310(d) — Device and Media Controls

| Specification | Type | Policy | File |
|---|---|---|---|
| (1) Device and Media Controls | Required | Disk encryption enabled | `disk-encryption.yml` |
| (1) Device and Media Controls | Required | AirDrop disabled | `airdrop-disabled.yml` |
| (2)(iv) Data Backup and Storage | Addressable | FileVault recovery key escrowed | `filevault-key-escrowed.yml` |
| (2)(iv) Data Backup and Storage | Addressable | Endpoint backup agent running | `backup-agent-running.yml` |

---

## § 164.312 — Technical Safeguards

### § 164.312(a) — Access Control

| Specification | Type | Policy | File |
|---|---|---|---|
| (1) Access Control | Required | Guest account disabled | `guest-account-disabled.yml` |
| (1) Access Control | Required | No unauthorized local admin accounts | `no-local-admin-accounts.yml` |
| (2)(i) Unique User Identification | Required | Guest account disabled | `guest-account-disabled.yml` |
| (2)(i) Unique User Identification | Required | No unauthorized local admin accounts | `no-local-admin-accounts.yml` |
| (2)(iii) Automatic Logoff | Addressable | Screen lock enabled | `screen-lock.yml` |
| (2)(iii) Automatic Logoff | Addressable | Password required after lock | `password-required-after-lock.yml` |
| (2)(iv) Encryption and Decryption | Addressable | Disk encryption enabled | `disk-encryption.yml` |
| (2)(iv) Encryption and Decryption | Addressable | FileVault recovery key escrowed | `filevault-key-escrowed.yml` |

### § 164.312(b) — Audit Controls

| Specification | Type | Policy | File |
|---|---|---|---|
| Audit Controls | Required | Audit logging enabled | `audit-logging-enabled.yml` |
| Audit Controls | Required | NTP time synchronisation configured | `ntp-configured.yml` |

> **§ 164.312(b)** is one of the most commonly cited HIPAA technical safeguard
> gaps during audits. BSM audit logging satisfies the mechanism requirement.
> NTP synchronisation ensures audit log timestamps are accurate and reliable —
> skewed clocks undermine the integrity of audit evidence.

### § 164.312(c) — Integrity

| Specification | Type | Policy | File |
|---|---|---|---|
| (1) Integrity | Required | System Integrity Protection enabled | `sip-enabled.yml` |
| (1) Integrity | Required | Gatekeeper enabled | `gatekeeper-enabled.yml` |
| (1) Integrity | Required | Disk encryption enabled | `disk-encryption.yml` |
| (1) Integrity | Required | MDM enrollment certificate valid | `mdm-enrollment-valid.yml` |
| (2) Mechanism to Authenticate ePHI | Addressable | Password complexity enforced | `password-complexity.yml` |
| (2) Mechanism to Authenticate ePHI | Addressable | Password required after lock | `password-required-after-lock.yml` |

### § 164.312(d) — Person or Entity Authentication

| Specification | Type | Policy | File |
|---|---|---|---|
| Authentication | Required | Password complexity enforced | `password-complexity.yml` |
| Authentication | Required | Password required after lock | `password-required-after-lock.yml` |
| Authentication | Required | Guest account disabled | `guest-account-disabled.yml` |
| Authentication | Required | Login window shows name and password fields | `login-window-display.yml` |
| Authentication | Required | Okta Verify installed | `okta-verify-running.yml` |

### § 164.312(e) — Transmission Security

| Specification | Type | Policy | File |
|---|---|---|---|
| (1) Transmission Security | Required | Firewall enabled | `firewall-enabled.yml` |
| (1) Transmission Security | Required | SSH remote login disabled | `ssh-disabled.yml` |
| (1) Transmission Security | Required | Screen sharing disabled | `screen-sharing-disabled.yml` |
| (1) Transmission Security | Required | Remote management disabled | `remote-management-disabled.yml` |
| (1) Transmission Security | Required | Internet sharing disabled | `internet-sharing-disabled.yml` |
| (1) Transmission Security | Required | Printer sharing disabled | `printer-sharing-disabled.yml` |
| (1) Transmission Security | Required | Content caching disabled | `content-caching-disabled.yml` |
| (1) Transmission Security | Required | Bluetooth managed via configuration profile | `bluetooth-managed.yml` |
| (1) Transmission Security | Required | DNS filtering configured | `dns-filtering-configured.yml` |
| (2)(ii) Encryption in Transit | Addressable | AirDrop disabled | `airdrop-disabled.yml` |
| (2)(ii) Encryption in Transit | Addressable | FileVault recovery key escrowed | `filevault-key-escrowed.yml` |

---

## Key Gaps

These HIPAA requirements are not addressed by endpoint policies and must be
covered by other organisational controls:

| Requirement | Coverage Approach |
|---|---|
| § 164.308(a)(2) Assigned Security Responsibility | Designate a HIPAA Security Officer |
| § 164.308(a)(4) Information Access Management | Okta access policies and provisioning |
| § 164.308(a)(6) Security Incident Procedures | Incident response plan and runbook |
| § 164.310(a) Facility Access Controls | Office physical security controls |
| § 164.310(b) Workstation Use | Acceptable use policy document |
| § 164.310(c) Workstation Security | Clean desk and screen placement policy |
