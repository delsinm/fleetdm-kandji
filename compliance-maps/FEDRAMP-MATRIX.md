# FedRAMP / NIST 800-53 Compliance Matrix

This document maps each FleetDM endpoint policy to its corresponding NIST 800-53
control requirements under the FedRAMP High baseline. Use this as evidence mapping
for 3PAO assessments, continuous monitoring reporting, and control implementation
documentation.

Each policy has a corresponding YAML definition under `fleet/policies/` containing
the full osquery query, resolution steps, and detailed compliance rationale.
The watched policy list is maintained in `remediation/policies.yml`.

> **EDR note:** Entries referencing CrowdStrike also apply to Cisco Secure Endpoint
> and SentinelOne. Substitute the appropriate policy file for your deployed EDR:
> `crowdstrike-*.yml` → `cisco-secure-endpoint-*.yml` or `sentinelone-*.yml`

---

## Coverage Summary

| Control Family | Controls Covered |
|---|---|
| AC — Access Control | AC-2, AC-2(9), AC-3, AC-4, AC-6, AC-6(1), AC-6(5), AC-11, AC-11(1), AC-17, AC-17(1), AC-19, AC-20 |
| AU — Audit & Accountability | AU-2, AU-3, AU-8, AU-8(1), AU-8(2), AU-9, AU-12 |
| CM — Configuration Management | CM-6, CM-7, CM-7(1), CM-7(2), CM-11 |
| CP — Contingency Planning | CP-9, CP-9(1), CP-10 |
| IA — Identification & Authentication | IA-2, IA-5, IA-5(1), IA-11 |
| MA — Maintenance | MA-4 |
| MP — Media Protection | MP-5, MP-7, MP-8 |
| RA — Risk Assessment | RA-5 |
| SC — System & Communications Protection | SC-7, SC-7(12), SC-8, SC-28, SC-28(1), SC-39 |
| SI — System & Information Integrity | SI-2, SI-2(2), SI-2(3), SI-3, SI-3(1), SI-3(2), SI-4, SI-7, SI-7(6) |

---

## AC — Access Control

| Control | Description | Policy | File |
|---|---|---|---|
| AC-2 | Account Management | Guest account disabled | `guest-account-disabled.yml` |
| AC-2 | Account Management | No unauthorized local admin accounts | `no-local-admin-accounts.yml` |
| AC-2 | Account Management | Password complexity enforced | `password-complexity.yml` |
| AC-2(9) | Restrictions on Shared Accounts | Guest account disabled | `guest-account-disabled.yml` |
| AC-3 | Access Enforcement | Guest account disabled | `guest-account-disabled.yml` |
| AC-4 | Information Flow Enforcement | Internet sharing disabled | `internet-sharing-disabled.yml` |
| AC-6 | Least Privilege | No unauthorized local admin accounts | `no-local-admin-accounts.yml` |
| AC-6(1) | Authorize Access to Security Functions | No unauthorized local admin accounts | `no-local-admin-accounts.yml` |
| AC-6(5) | Privileged Accounts | No unauthorized local admin accounts | `no-local-admin-accounts.yml` |
| AC-11 | Session Lock | Screen lock enabled | `screen-lock.yml` |
| AC-11 | Session Lock | Password required after lock | `password-required-after-lock.yml` |
| AC-11(1) | Pattern-Hiding Displays | Screen lock enabled | `screen-lock.yml` |
| AC-11(1) | Pattern-Hiding Displays | Password required after lock | `password-required-after-lock.yml` |
| AC-17 | Remote Access | SSH remote login disabled | `ssh-disabled.yml` |
| AC-17 | Remote Access | Screen sharing disabled | `screen-sharing-disabled.yml` |
| AC-17 | Remote Access | Remote management disabled | `remote-management-disabled.yml` |
| AC-17(1) | Automated Monitoring / Control | SSH remote login disabled | `ssh-disabled.yml` |
| AC-19 | Access Control for Mobile Devices | AirDrop disabled | `airdrop-disabled.yml` |
| AC-20 | Use of External Information Systems | AirDrop disabled | `airdrop-disabled.yml` |

---

## AU — Audit and Accountability

| Control | Description | Policy | File |
|---|---|---|---|
| AU-2 | Audit Events | Audit logging enabled | `audit-logging-enabled.yml` |
| AU-3 | Content of Audit Records | Audit logging enabled | `audit-logging-enabled.yml` |
| AU-8 | Time Stamps | NTP time synchronisation configured | `ntp-configured.yml` |
| AU-8(1) | Synchronisation with Authoritative Time Source | NTP time synchronisation configured | `ntp-configured.yml` |
| AU-8(2) | Secondary Authoritative Time Source | NTP time synchronisation configured | `ntp-configured.yml` |
| AU-9 | Protection of Audit Information | Audit logging enabled | `audit-logging-enabled.yml` |
| AU-12 | Audit Record Generation | Audit logging enabled | `audit-logging-enabled.yml` |

> **AU-8(1) and AU-8(2)** are FedRAMP High baseline required controls not present
> at Moderate. Configure both a primary (time.nist.gov) and secondary NTP server
> in the Kandji profile to satisfy AU-8(2).

---

## CM — Configuration Management

| Control | Description | Policy | File |
|---|---|---|---|
| CM-6 | Configuration Settings | Automatic updates enabled | `auto-updates-enabled.yml` |
| CM-6 | Configuration Settings | OS up to date | `os-up-to-date.yml` |
| CM-7 | Least Functionality | Firewall enabled | `firewall-enabled.yml` |
| CM-7 | Least Functionality | Gatekeeper enabled | `gatekeeper-enabled.yml` |
| CM-7 | Least Functionality | SSH remote login disabled | `ssh-disabled.yml` |
| CM-7 | Least Functionality | Screen sharing disabled | `screen-sharing-disabled.yml` |
| CM-7 | Least Functionality | Remote management disabled | `remote-management-disabled.yml` |
| CM-7 | Least Functionality | Internet sharing disabled | `internet-sharing-disabled.yml` |
| CM-7 | Least Functionality | Printer sharing disabled | `printer-sharing-disabled.yml` |
| CM-7 | Least Functionality | Content caching disabled | `content-caching-disabled.yml` |
| CM-7(1) | Periodic Review | Firewall enabled | `firewall-enabled.yml` |
| CM-7(1) | Periodic Review | SSH remote login disabled | `ssh-disabled.yml` |
| CM-7(1) | Periodic Review | Printer sharing disabled | `printer-sharing-disabled.yml` |
| CM-7(1) | Periodic Review | Content caching disabled | `content-caching-disabled.yml` |
| CM-7(2) | Prevent Program Execution | Remote management disabled | `remote-management-disabled.yml` |
| CM-11 | User-Installed Software | Gatekeeper enabled | `gatekeeper-enabled.yml` |

---

## CP — Contingency Planning

| Control | Description | Policy | File |
|---|---|---|---|
| CP-9 | System Backup | Endpoint backup agent running | `backup-agent-running.yml` |
| CP-9(1) | Testing for Reliability and Integrity | Endpoint backup agent running | `backup-agent-running.yml` |
| CP-10 | System Recovery and Reconstitution | Endpoint backup agent running | `backup-agent-running.yml` |

> **CP-9(1)** requires testing backup reliability and integrity — the policy
> verifies the agent is running but does not verify backup completion or restore
> success. Backup restore testing must be conducted and documented separately
> in your backup management console.

---

## IA — Identification and Authentication

| Control | Description | Policy | File |
|---|---|---|---|
| IA-2 | Identification and Authentication | Guest account disabled | `guest-account-disabled.yml` |
| IA-2 | Identification and Authentication | Login window shows name and password fields | `login-window-display.yml` |
| IA-5 | Authenticator Management | Password complexity enforced | `password-complexity.yml` |
| IA-5 | Authenticator Management | Login window shows name and password fields | `login-window-display.yml` |
| IA-5(1) | Password-Based Authentication | Password complexity enforced | `password-complexity.yml` |
| IA-11 | Re-Authentication | Screen lock enabled | `screen-lock.yml` |
| IA-11 | Re-Authentication | Password required after lock | `password-required-after-lock.yml` |

---

## MA — Maintenance

| Control | Description | Policy | File |
|---|---|---|---|
| MA-4 | Non-Local Maintenance | Remote management disabled | `remote-management-disabled.yml` |

---

## MP — Media Protection

| Control | Description | Policy | File |
|---|---|---|---|
| MP-5 | Media Transport | Disk encryption enabled | `disk-encryption.yml` |
| MP-7 | Media Use | AirDrop disabled | `airdrop-disabled.yml` |
| MP-8 | Media Downgrading | Disk encryption enabled | `disk-encryption.yml` |

---

## RA — Risk Assessment

| Control | Description | Policy | File |
|---|---|---|---|
| RA-5 | Vulnerability Scanning | OS up to date | `os-up-to-date.yml` |
| RA-5 | Vulnerability Scanning | CrowdStrike version current | `crowdstrike-version.yml` |

---

## SC — System and Communications Protection

| Control | Description | Policy | File |
|---|---|---|---|
| SC-7 | Boundary Protection | Firewall enabled | `firewall-enabled.yml` |
| SC-7(12) | Host-Based Protection | Firewall enabled | `firewall-enabled.yml` |
| SC-8 | Transmission Confidentiality and Integrity | AirDrop disabled | `airdrop-disabled.yml` |
| SC-28 | Protection of Information at Rest | Disk encryption enabled | `disk-encryption.yml` |
| SC-28(1) | Cryptographic Protection | FileVault recovery key escrowed | `filevault-key-escrowed.yml` |
| SC-39 | Process Isolation | System Integrity Protection enabled | `sip-enabled.yml` |

---

## SI — System and Information Integrity

| Control | Description | Policy | File |
|---|---|---|---|
| SI-2 | Flaw Remediation | Automatic updates enabled | `auto-updates-enabled.yml` |
| SI-2 | Flaw Remediation | OS up to date | `os-up-to-date.yml` |
| SI-2 | Flaw Remediation | CrowdStrike version current | `crowdstrike-version.yml` |
| SI-2(2) | Automated Flaw Remediation Status | Automatic updates enabled | `auto-updates-enabled.yml` |
| SI-2(2) | Automated Flaw Remediation Status | OS up to date | `os-up-to-date.yml` |
| SI-2(3) | Time to Remediate Flaws | OS up to date | `os-up-to-date.yml` |
| SI-3 | Malware Protection | CrowdStrike running | `crowdstrike-running.yml` |
| SI-3 | Malware Protection | CrowdStrike version current | `crowdstrike-version.yml` |
| SI-3(1) | Central Management | CrowdStrike running | `crowdstrike-running.yml` |
| SI-3(1) | Central Management | CrowdStrike version current | `crowdstrike-version.yml` |
| SI-3(2) | Automatic Updates | CrowdStrike running | `crowdstrike-running.yml` |
| SI-4 | Information System Monitoring | CrowdStrike running | `crowdstrike-running.yml` |
| SI-7 | Software, Firmware, and Information Integrity | System Integrity Protection enabled | `sip-enabled.yml` |
| SI-7 | Software, Firmware, and Information Integrity | Gatekeeper enabled | `gatekeeper-enabled.yml` |
| SI-7(6) | Cryptographic Protection | System Integrity Protection enabled | `sip-enabled.yml` |
