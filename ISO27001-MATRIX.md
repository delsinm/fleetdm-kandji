# ISO 27001:2022 Compliance Matrix

This document maps each FleetDM endpoint policy to its corresponding ISO 27001:2022 Annex A controls. ISO 27001 is a management system standard - certification requires both an operational ISMS (clauses 4-10) and implementation of applicable Annex A controls.

Endpoint policies address Theme 4 (Technological Controls) and a small subset of Theme 1 (Organisational Controls). Themes 2 (People) and 3 (Physical) require separate organisational and physical controls not addressable by endpoint policy.

Each policy has a corresponding YAML definition under `fleet/policies/` containing the full osquery query, resolution steps, and detailed rationale.

> **EDR note:** Entries referencing CrowdStrike also apply to Cisco Secure Endpoint
> and SentinelOne. Substitute the appropriate policy file for your deployed EDR:
> `edr-crowdstrike-*.yml` → `edr-cisco-secure-endpoint-*.yml` or `edr-sentinelone-*.yml`

---

## Coverage Summary

| Theme | Controls Covered |
|---|---|
| A.8 — Technological | A.8.1, A.8.2, A.8.3, A.8.5, A.8.7, A.8.8, A.8.9, A.8.13, A.8.15, A.8.16, A.8.17, A.8.20, A.8.24 |
| A.5 — Organisational | A.5.17 (partial) |
| A.6 — People | None — requires HR and training program |
| A.7 — Physical | None — requires physical security controls |

---

## A.5 — Organisational Controls

| Control | Description | Policy | File |
|---|---|---|---|
| A.5.17 | Authentication Information | Password complexity enforced | `password-complexity.yml` |

> A.5.17 is an organisational control but is implemented technically via a
> managed password policy profile. The remaining A.5 controls require security
> policy documentation, risk assessment, incident management, and supplier
> management processes outside the scope of endpoint policies.

---

## A.8 — Technological Controls

### A.8.1 — User Endpoint Devices

Requires that information processed, stored, or transmitted by user endpoint devices is protected. Policies implementing rules for managing user endpoint devices must be established and applied.

| Policy | File | Contribution |
|---|---|---|
| Disk encryption enabled | `disk-encryption.yml` | Protects information stored on endpoint |
| FileVault recovery key escrowed | `filevault-key-escrowed.yml` | Ensures encryption is organisationally managed |
| Screen lock enabled | `screen-lock.yml` | Automatic locking after inactivity |
| Password required after lock | `password-required-after-lock.yml` | Re-authentication on session resume |
| AirDrop disabled | `airdrop-disabled.yml` | Restricts data transfer to unmanaged devices |

### A.8.2 — Privileged Access Rights

Requires that the allocation and use of privileged access rights be restricted, controlled, managed, and reviewed.

| Policy | File | Contribution |
|---|---|---|
| No unauthorized local admin accounts | `no-local-admin-accounts.yml` | Detects and remediates unauthorised admin rights |
| Guest account disabled | `guest-account-disabled.yml` | Removes unprovisioned access account |

### A.8.3 — Information Access Restriction

Requires that access to information and application system functions be restricted in accordance with the access control policy.

| Policy | File | Contribution |
|---|---|---|
| Guest account disabled | `guest-account-disabled.yml` | Eliminates unauthenticated local access |
| Screen sharing disabled | `screen-sharing-disabled.yml` | Prevents remote graphical access to information |
| AirDrop disabled | `airdrop-disabled.yml` | Prevents transfer to uncontrolled devices |
| Login window shows name and password fields | `login-window-display.yml` | Prevents account enumeration at login |
| No unauthorized local admin accounts | `no-local-admin-accounts.yml` | Enforces access restrictions via least privilege |

### A.8.5 — Secure Authentication

Requires that secure authentication technologies and procedures be
implemented based on information access restrictions.

| Policy | File | Contribution |
|---|---|---|
| Screen lock enabled | `screen-lock.yml` | Session lock with re-authentication requirement |
| Password required after lock | `password-required-after-lock.yml` | Enforces re-authentication after inactivity |
| Password complexity enforced | `password-complexity.yml` | Password quality requirements |
| Login window shows name and password fields | `login-window-display.yml` | Strengthens authentication challenge |

### A.8.7 — Protection Against Malware

Requires that protection against malware be implemented and supported by
appropriate user awareness.

| Policy | File | Contribution |
|---|---|---|
| EDR software running | `edr-*-running.yml` | Primary endpoint malware detection and prevention |
| EDR software version current | `edr-*-version.yml` | Ensures malware protection is current |
| Gatekeeper enabled | `gatekeeper-enabled.yml` | Prevents execution of unsigned/untrusted software |
| System Integrity Protection enabled | `sip-enabled.yml` | Prevents system-level malware persistence |

### A.8.8 — Management of Technical Vulnerabilities

Requires that information about technical vulnerabilities of systems be obtained, the organisation's exposure evaluated, and appropriate measures taken.

| Policy | File | Contribution |
|---|---|---|
| OS up to date | `os-up-to-date.yml` | Primary patch compliance outcome check |
| Automatic updates enabled | `auto-updates-enabled.yml` | Ensures device checks for available patches |
| EDR software version current | `edr-*-version.yml` | Remediates vulnerability in agent software itself |

### A.8.9 — Configuration Management

Requires that configurations, including security configurations, of hardware, software, services, and networks be established, documented, implemented, monitored, and reviewed.

| Policy | File | Contribution |
|---|---|---|
| Firewall enabled | `firewall-enabled.yml` | Verified baseline security configuration |
| SSH remote login disabled | `ssh-disabled.yml` | Hardened baseline — unnecessary service disabled |
| Screen sharing disabled | `screen-sharing-disabled.yml` | Hardened baseline — unnecessary service disabled |
| Remote management disabled | `remote-management-disabled.yml` | Hardened baseline — legacy service disabled |
| Internet sharing disabled | `internet-sharing-disabled.yml` | Hardened baseline — unnecessary relay disabled |
| Printer sharing disabled | `printer-sharing-disabled.yml` | Hardened baseline — unnecessary listener disabled |
| Content caching disabled | `content-caching-disabled.yml` | Hardened baseline — relay service disabled |
| Gatekeeper enabled | `gatekeeper-enabled.yml` | Verified baseline software execution policy |
| System Integrity Protection enabled | `sip-enabled.yml` | Verified baseline system integrity configuration |
| Automatic updates enabled | `auto-updates-enabled.yml` | Verified baseline update mechanism configuration |

### A.8.13 — Information Backup

Requires that backup copies of information, software, and system images be taken and tested regularly in accordance with an agreed backup policy.

| Policy | File | Contribution |
|---|---|---|
| Endpoint backup agent running | `backup-agent-running.yml` | Verifies backup mechanism is active on endpoint |

> **A.8.13** also requires that backups be tested. The policy confirms the agent
> is running. Restore testing must be conducted and documented separately in your
> backup management console to fully satisfy this control.

### A.8.15 — Logging

Requires that logs recording user activities, exceptions, faults, and information security events be produced, stored, protected, and analysed.

| Policy | File | Contribution |
|---|---|---|
| Audit logging enabled | `audit-logging-enabled.yml` | BSM audit daemon provides structured, tamper-evident endpoint logging |
| NTP time synchronisation configured | `ntp-configured.yml` | Ensures log timestamps are accurate and reliable |

### A.8.16 — Monitoring Activities

Requires that networks, systems, and applications be monitored for anomalous behaviour and appropriate actions taken to evaluate potential information security incidents.

| Policy | File | Contribution |
|---|---|---|
| EDR software running | `edr-*-running.yml` | Continuous endpoint behavioural monitoring |
| EDR software version current | `edr-*-version.yml` | Ensures monitoring capability is effective |
| Audit logging enabled | `audit-logging-enabled.yml` | Provides endpoint event data for monitoring |

### A.8.17 — Clock Synchronisation

Requires that the clocks of all relevant information processing systems be
synchronised to an approved time source to ensure the accuracy of audit logs
and facilitate incident investigation.

| Policy | File | Contribution |
|---|---|---|
| NTP time synchronisation configured | `ntp-configured.yml` | Enforces synchronisation to authoritative NTP via managed profile |

> **A.8.17** is a direct Annex A control specifically requiring NTP synchronisation.
> For FedRAMP environments use NIST time servers (time.nist.gov). For corporate
> environments Apple's default (time.apple.com) is acceptable.

### A.8.20 — Networks Security

Requires that networks and network devices be secured, managed, and controlled to protect information in systems and applications.

| Policy | File | Contribution |
|---|---|---|
| Firewall enabled | `firewall-enabled.yml` | Host-based network boundary protection |
| SSH remote login disabled | `ssh-disabled.yml` | Eliminates inbound SSH attack surface |
| Screen sharing disabled | `screen-sharing-disabled.yml` | Eliminates inbound VNC attack surface |
| Remote management disabled | `remote-management-disabled.yml` | Eliminates inbound ARD attack surface |
| Internet sharing disabled | `internet-sharing-disabled.yml` | Prevents endpoint acting as network relay |
| Printer sharing disabled | `printer-sharing-disabled.yml` | Removes unnecessary inbound IPP listener |
| Content caching disabled | `content-caching-disabled.yml` | Prevents unmonitored content relay behaviour |

### A.8.24 — Use of Cryptography

Requires that rules for the effective use of cryptography, including cryptographic key management, be defined and implemented.

| Policy | File | Contribution |
|---|---|---|
| Disk encryption enabled | `disk-encryption.yml` | AES full-disk encryption of endpoint storage |
| FileVault recovery key escrowed | `filevault-key-escrowed.yml` | Organisational management of cryptographic keys |

---

## Key Gaps

These Annex A controls are not addressed by endpoint policies and require separate organisational, people, or physical controls:

| Control | Description | Coverage Approach |
|---|---|---|
| A.5.1 | Policies for information security | Information security policy document |
| A.5.2 | Information security roles | CISO / security officer assignment |
| A.5.9 | Asset inventory | Fleet provides endpoint inventory; broader asset register needed |
| A.5.10 | Acceptable use | Acceptable use policy document |
| A.5.23 | Cloud services security | Cloud governance policy and vendor assessments |
| A.5.24 | Incident management | IR plan and response procedures |
| A.5.29 | IS during disruption | Business continuity plan |
| A.5.35 | Independent review | Internal audit program and penetration testing |
| A.6.3 | Awareness and training | Annual security awareness training program |
| A.6.5 | Responsibilities after termination | Offboarding process (Okta handles access) |
| A.7.1-7.4 | Physical security | Office physical security controls |
| A.8.6 | Capacity management | Infrastructure monitoring and scaling |
| A.8.12 | Data leakage prevention | DLP tooling or CrowdStrike DLP |
| A.8.23 | Web filtering | DNS filtering or proxy layer |
| A.8.25-8.28 | Secure development | SDLC process and secure coding standards |

---

## ISMS Requirements (Clauses 4-10)

ISO 27001 certification also requires implementing the management system clauses. None of these are addressed by endpoint policies:

| Clause | Requirement |
|---|---|
| 4 | Context of the organisation — scope definition, interested parties |
| 5 | Leadership — management commitment, security policy, roles |
| 6 | Planning — risk assessment, Statement of Applicability, objectives |
| 7 | Support — resources, competence, awareness, communication, documentation |
| 8 | Operation — implement plans, manage risks, handle changes |
| 9 | Performance evaluation — monitoring, internal audit, management review |
| 10 | Improvement — nonconformity, corrective action, continual improvement |

> The Statement of Applicability (SoA) is a mandatory certification artifact.
> It documents every Annex A control, whether it is applicable, and if excluded,
> the justification. Our endpoint policies provide evidence for the applicable
> A.8 controls in the SoA.
