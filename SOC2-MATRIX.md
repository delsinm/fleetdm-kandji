# SOC 2 Trust Services Criteria Compliance Matrix

This document maps each FleetDM endpoint policy to the relevant SOC 2 Trust
Services Criteria (TSC). SOC 2 is principles-based -- auditors assess whether
controls are suitably designed and operating effectively. Pair these policies
with documented procedures, owner assignments, and review cadences.

Each policy has a corresponding YAML definition under `fleet/policies/` containing
the full osquery query, resolution steps, and detailed compliance rationale.
The watched policy list is maintained in `remediation/policies.yml`.

> **EDR note:** Entries referencing CrowdStrike also apply to Cisco Secure Endpoint
> and SentinelOne. Substitute the appropriate policy file for your deployed EDR:
> `crowdstrike-*.yml` → `cisco-secure-endpoint-*.yml` or `sentinelone-*.yml`

---

## Coverage Summary

| Category | Criteria Covered |
|---|---|
| CC2 — Communication and Information | CC2.2 |
| CC4 — Monitoring Activities | CC4.1 |
| CC6 — Logical and Physical Access | CC6.1, CC6.2, CC6.3, CC6.6, CC6.7, CC6.8 |
| CC7 — System Operations | CC7.1, CC7.2, CC7.3 |
| CC8 — Change Management | CC8.1 |
| A1 — Availability | A1.2, A1.3 |

---

## CC2 — Communication and Information

| Criteria | Description | Policy | File |
|---|---|---|---|
| CC2.2 | Communicates internally about objectives and responsibilities | AirDrop disabled | `airdrop-disabled.yml` |

---

## CC4 — Monitoring Activities

| Criteria | Description | Policy | File |
|---|---|---|---|
| CC4.1 | Monitors for security breaches and anomalies | Audit logging enabled | `audit-logging-enabled.yml` |
| CC4.1 | Monitors for security breaches and anomalies | CrowdStrike running | `crowdstrike-running.yml` |
| CC4.1 | Monitors for security breaches and anomalies | NTP time synchronisation configured | `ntp-configured.yml` |

---

## CC6 — Logical and Physical Access Controls

### CC6.1 — Logical Access Security

| Policy | File | Contribution |
|---|---|---|
| Guest account disabled | `guest-account-disabled.yml` | Eliminates unauthenticated local access |
| No unauthorized local admin accounts | `no-local-admin-accounts.yml` | Enforces least privilege access |
| Screen lock enabled | `screen-lock.yml` | Prevents unattended physical access |
| Password required after lock | `password-required-after-lock.yml` | Ensures authentication enforced at resumption |
| Password complexity enforced | `password-complexity.yml` | Strengthens credential-based access control |
| Login window shows name and password fields | `login-window-display.yml` | Prevents username enumeration at login screen |
| Disk encryption enabled | `disk-encryption.yml` | Prevents physical access to data |
| FileVault recovery key escrowed | `filevault-key-escrowed.yml` | Demonstrates organisational key management |
| Okta Verify installed | `okta-verify-running.yml` | Device trust gate — only managed compliant devices authenticate |
| MDM enrollment certificate valid | `mdm-enrollment-valid.yml` | Verifies device management is operational |

### CC6.2 — Prior to Issuing System Credentials

| Policy | File | Contribution |
|---|---|---|
| Guest account disabled | `guest-account-disabled.yml` | Prevents access without formal provisioning |
| No unauthorized local admin accounts | `no-local-admin-accounts.yml` | Detects accounts granted outside formal process |
| SSH remote login disabled | `ssh-disabled.yml` | Eliminates credential-based remote access path |
| Login window shows name and password fields | `login-window-display.yml` | Prevents exposing provisioned account names |

### CC6.3 — Role-Based Access and Least Privilege

| Policy | File | Contribution |
|---|---|---|
| No unauthorized local admin accounts | `no-local-admin-accounts.yml` | Enforces role-appropriate privilege levels |
| Guest account disabled | `guest-account-disabled.yml` | Removes anonymous access role |

### CC6.6 — Security Measures Against Threats from Outside

| Policy | File | Contribution |
|---|---|---|
| Firewall enabled | `firewall-enabled.yml` | Primary host-based boundary control |
| SSH remote login disabled | `ssh-disabled.yml` | Eliminates inbound SSH attack surface |
| Screen sharing disabled | `screen-sharing-disabled.yml` | Eliminates inbound VNC attack surface |
| Remote management disabled | `remote-management-disabled.yml` | Eliminates inbound ARD attack surface |
| Internet sharing disabled | `internet-sharing-disabled.yml` | Prevents endpoint acting as network relay |
| Printer sharing disabled | `printer-sharing-disabled.yml` | Removes unnecessary inbound IPP listener |
| Content caching disabled | `content-caching-disabled.yml` | Prevents endpoint acting as content relay |
| Bluetooth managed via configuration profile | `bluetooth-managed.yml` | Eliminates Bluetooth-based attack surface |
| DNS filtering configured | `dns-filtering-configured.yml` | Blocks connections to known malicious infrastructure |
| CrowdStrike running | `crowdstrike-running.yml` | Detects and prevents external threat execution |
| CrowdStrike version current | `crowdstrike-version.yml` | Ensures detection is current against recent threats |

### CC6.7 — Restricts Transmission of Confidential Information

| Policy | File | Contribution |
|---|---|---|
| AirDrop disabled | `airdrop-disabled.yml` | Prevents transmission to unmanaged devices |
| Bluetooth managed via configuration profile | `bluetooth-managed.yml` | Prevents wireless data transfer to unmanaged devices |
| DNS filtering configured | `dns-filtering-configured.yml` | Blocks DNS tunnelling exfiltration attempts |
| Disk encryption enabled | `disk-encryption.yml` | Protects data if device is transmitted or lost |
| FileVault recovery key escrowed | `filevault-key-escrowed.yml` | Demonstrates managed encryption governance |

### CC6.8 — Prevents or Detects Unauthorised Software

| Policy | File | Contribution |
|---|---|---|
| CrowdStrike running | `crowdstrike-running.yml` | Primary control for malicious software detection |
| CrowdStrike version current | `crowdstrike-version.yml` | Ensures detection capability is current |
| Gatekeeper enabled | `gatekeeper-enabled.yml` | Prevents unsigned software execution |
| System Integrity Protection enabled | `sip-enabled.yml` | Prevents system-level tampering |
| Firewall enabled | `firewall-enabled.yml` | Blocks uninvited inbound connections |

---

## CC7 — System Operations

### CC7.1 — Detects and Monitors for Vulnerabilities

| Policy | File | Contribution |
|---|---|---|
| OS up to date | `os-up-to-date.yml` | Verifies patches applied, eliminates known CVEs |
| Automatic updates enabled | `auto-updates-enabled.yml` | Ensures device is checking for new vulnerabilities |
| CrowdStrike version current | `crowdstrike-version.yml` | Verifies detection capability is current |
| Audit logging enabled | `audit-logging-enabled.yml` | Provides log data for vulnerability event detection |

### CC7.2 — Monitors System Components for Anomalies

| Policy | File | Contribution |
|---|---|---|
| CrowdStrike running | `crowdstrike-running.yml` | Continuous endpoint behavioural monitoring |
| CrowdStrike version current | `crowdstrike-version.yml` | Ensures monitoring capability is effective |
| Audit logging enabled | `audit-logging-enabled.yml` | Provides endpoint event data for anomaly detection |
| NTP time synchronisation configured | `ntp-configured.yml` | Ensures timestamps are accurate for event correlation |
| System Integrity Protection enabled | `sip-enabled.yml` | Generates alerts on system tampering attempts |
| MDM enrollment certificate valid | `mdm-enrollment-valid.yml` | Detects devices that have silently lost MDM management |

### CC7.3 — Evaluates Security Events

| Policy | File | Contribution |
|---|---|---|
| Audit logging enabled | `audit-logging-enabled.yml` | Primary source of endpoint security event data |
| CrowdStrike running | `crowdstrike-running.yml` | Generates structured security events for evaluation |
| NTP time synchronisation configured | `ntp-configured.yml` | Ensures event timestamps are reliable for investigation |
| Screen sharing disabled | `screen-sharing-disabled.yml` | Removes blind spot in session event detection |

---

## CC8 — Change Management

### CC8.1 — Authorises and Implements Changes

| Policy | File | Contribution |
|---|---|---|
| Remote management disabled | `remote-management-disabled.yml` | Enforces changes occur through approved MDM channels |
| Gatekeeper enabled | `gatekeeper-enabled.yml` | Prevents installation of unauthorised software |
| System Integrity Protection enabled | `sip-enabled.yml` | Prevents unauthorised system-level changes |

---

## A1 — Availability

### A1.2 — Recovery Infrastructure

| Policy | File | Contribution |
|---|---|---|
| FileVault recovery key escrowed | `filevault-key-escrowed.yml` | Enables device recovery, supports replacement workflows |
| Disk encryption enabled | `disk-encryption.yml` | Supports secure decommission and recovery procedures |
| Endpoint backup agent running | `backup-agent-running.yml` | Verifies backup mechanism is active for data recovery |

### A1.3 — Recovery Plan Testing

| Policy | File | Contribution |
|---|---|---|
| Endpoint backup agent running | `backup-agent-running.yml` | Confirms backup agent is operational for restore testing |

> **A1.3** requires that recovery plans be tested. The backup agent policy confirms
> the mechanism is in place. Actual restore tests must be conducted and documented
> separately in your backup management console.

---

## Key Gaps

These SOC 2 criteria are not fully addressed by endpoint policies and require
additional organisational or infrastructure controls:

| Criteria | Gap | Coverage Approach |
|---|---|---|
| CC5.1 | Control environment and risk assessment | Risk assessment documentation and security program |
| CC5.2 | Selects and develops control activities | Control documentation and ownership assignments |
| CC9.1 | Identifies risk of business disruption | Business continuity plan and risk register |
| CC9.2 | Vendor risk management | Third-party vendor assessment program |
| A1.1 | Capacity planning | Infrastructure monitoring and scaling procedures |
| PI1 | Processing integrity | Application-level controls and data validation |
