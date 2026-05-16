# GDPR Compliance Matrix

This document maps each FleetDM endpoint policy to relevant GDPR requirements. GDPR (General Data Protection Regulation) applies to organisations that process personal data of EU/EEA data subjects, regardless of where the organisation is based. This covers EU employees, EU customers, and any EU personal data processed by the platform.

GDPR is a principles-based regulation — it does not prescribe specific technical controls. Instead, Articles 25 and 32 require "appropriate technical and organisational measures" proportionate to the risk. Endpoint security policies
are technical measures that demonstrate compliance with these articles.

Each policy has a corresponding YAML definition under `fleet/policies/` containing the full osquery query, resolution steps, and detailed compliance rationale. The watched policy list is maintained in `remediation/policies.yml`.

> **EDR note:** Entries referencing CrowdStrike also apply to Cisco Secure Endpoint 
> and SentinelOne. Substitute the appropriate policy file for your deployed EDR:
> `crowdstrike-*.yml` → `cisco-secure-endpoint-*.yml` or `sentinelone-*.yml`

---

## Relevant GDPR Articles

| Article | Title | Relevance to Endpoint Policies |
|---|---|---|
| Art. 5 | Principles of Processing | Integrity and confidentiality principle (5(1)(f)) |
| Art. 25 | Data Protection by Design and Default | Technical measures must be implemented by design |
| Art. 32 | Security of Processing | Appropriate technical measures against unauthorised access |
| Art. 33 | Notification of Personal Data Breach | Logging and monitoring enables breach detection |
| Art. 34 | Communication of Breach to Data Subject | Encryption limits breach notification obligations |
| Art. 35 | Data Protection Impact Assessment | DPIA may reference endpoint controls as mitigations |

---

## Coverage Summary

| GDPR Requirement | Coverage | Notes |
|---|---|---|
| Art. 5(1)(f) Integrity and Confidentiality | Strong | Encryption, access control, malware protection |
| Art. 25 Data Protection by Design | Partial | Technical controls implemented; design process is organisational |
| Art. 32(1)(a) Pseudonymisation and Encryption | Covered | FileVault encryption, key escrow |
| Art. 32(1)(b) Ongoing Confidentiality and Integrity | Covered | Multiple policies across access, integrity, network |
| Art. 32(1)(c) Availability and Resilience | Partial | Backup agent; full resilience requires infrastructure controls |
| Art. 32(1)(d) Regular Testing and Evaluation | Covered | Drift check provides continuous automated evaluation |
| Art. 33/34 Breach Notification | Partial | Logging enables detection; notification process is organisational |

---

## Art. 5(1)(f) — Integrity and Confidentiality Principle

Personal data must be processed in a manner that ensures appropriate security,
including protection against unauthorised or unlawful processing and against
accidental loss, destruction, or damage.

| Policy | File | Contribution |
|---|---|---|
| Disk encryption enabled | `disk-encryption.yml` | Protects personal data from unauthorised access if device is lost or stolen |
| FileVault recovery key escrowed | `filevault-key-escrowed.yml` | Ensures encryption is organisationally managed and recoverable |
| CrowdStrike running | `crowdstrike-running.yml` | Protects against malicious software that could exfiltrate personal data |
| CrowdStrike version current | `crowdstrike-version.yml` | Ensures malware protection is current against recent threats |
| Firewall enabled | `firewall-enabled.yml` | Prevents unauthorised inbound network access to endpoint |
| Bluetooth managed via configuration profile | `bluetooth-managed.yml` | Prevents unauthorised wireless access to device and data |
| DNS filtering configured | `dns-filtering-configured.yml` | Blocks connections to known malicious infrastructure |
| Screen lock enabled | `screen-lock.yml` | Prevents physical access to personal data on unattended device |
| Password required after lock | `password-required-after-lock.yml` | Enforces authentication after inactivity |
| No unauthorized local admin accounts | `no-local-admin-accounts.yml` | Limits access to personal data to authorised users |
| Guest account disabled | `guest-account-disabled.yml` | Eliminates unauthenticated access to device |
| Okta Verify installed | `okta-verify-running.yml` | Device trust gate — only managed devices can authenticate to data systems |
| MDM enrollment certificate valid | `mdm-enrollment-valid.yml` | Ensures device management controls are operational |

---

## Art. 25 — Data Protection by Design and Default

The controller must implement appropriate technical measures to ensure that
data protection principles are implemented by default.

| Policy | File | Contribution |
|---|---|---|
| Disk encryption enabled | `disk-encryption.yml` | Encryption by default on all managed endpoints |
| AirDrop disabled | `airdrop-disabled.yml` | Data minimisation by default — prevents uncontrolled sharing |
| Screen sharing disabled | `screen-sharing-disabled.yml` | Limits remote access to personal data by default |
| Guest account disabled | `guest-account-disabled.yml` | Access restriction by default — no unauthenticated users |
| Password complexity enforced | `password-complexity.yml` | Strong authentication enforced by default |
| Gatekeeper enabled | `gatekeeper-enabled.yml` | Only authorised software executes by default |
| SSH remote login disabled | `ssh-disabled.yml` | Minimal attack surface by default |
| Internet sharing disabled | `internet-sharing-disabled.yml` | No uncontrolled network relay by default |
| Printer sharing disabled | `printer-sharing-disabled.yml` | No unnecessary network exposure by default |
| Content caching disabled | `content-caching-disabled.yml` | No unmonitored data relay by default |

---

## Art. 32(1)(a) — Pseudonymisation and Encryption

Implementation of appropriate technical measures including encryption of
personal data.

| Policy | File | Contribution |
|---|---|---|
| Disk encryption enabled | `disk-encryption.yml` | AES encryption of all data at rest on endpoint |
| FileVault recovery key escrowed | `filevault-key-escrowed.yml` | Demonstrates encryption is organisationally managed |

> **Breach notification impact:** Under Art. 34, if a lost or stolen device is 
> encrypted, notification to data subjects may not be required as the data is
> rendered unintelligible to unauthorised persons. FileVault encryption directly
> reduces breach notification obligations.

---

## Art. 32(1)(b) — Ongoing Confidentiality, Integrity, Availability and Resilience

Ability to ensure the ongoing confidentiality, integrity, availability, and
resilience of processing systems and services.

**Confidentiality:**

| Policy | File | Contribution |
|---|---|---|
| Disk encryption enabled | `disk-encryption.yml` | Data confidentiality at rest |
| Firewall enabled | `firewall-enabled.yml` | Network-level confidentiality |
| SSH remote login disabled | `ssh-disabled.yml` | Eliminates remote access confidentiality risk |
| Screen sharing disabled | `screen-sharing-disabled.yml` | Prevents visual data exposure via remote access |
| AirDrop disabled | `airdrop-disabled.yml` | Prevents uncontrolled data transfer |
| Bluetooth managed via configuration profile | `bluetooth-managed.yml` | Prevents wireless data exfiltration to unmanaged devices |
| DNS filtering configured | `dns-filtering-configured.yml` | Blocks DNS tunnelling and malicious domain connections |
| No unauthorized local admin accounts | `no-local-admin-accounts.yml` | Least privilege access to data |

**Integrity:**

| Policy | File | Contribution |
|---|---|---|
| System Integrity Protection enabled | `sip-enabled.yml` | Prevents system-level tampering |
| Gatekeeper enabled | `gatekeeper-enabled.yml` | Prevents execution of unauthorised software |
| CrowdStrike running | `crowdstrike-running.yml` | Detects and prevents malicious modification |
| OS up to date | `os-up-to-date.yml` | Patches known integrity vulnerabilities |

**Availability and Resilience:**

| Policy | File | Contribution |
|---|---|---|
| Endpoint backup agent running | `backup-agent-running.yml` | Ensures data recovery capability |
| CrowdStrike running | `crowdstrike-running.yml` | Prevents ransomware that disrupts availability |
| OS up to date | `os-up-to-date.yml` | Patches vulnerabilities that could disrupt availability |

---

## Art. 32(1)(d) — Regular Testing, Assessing, and Evaluating

A process for regularly testing, assessing, and evaluating the effectiveness
of technical and organisational measures for ensuring the security of processing.

| Policy | File | Contribution |
|---|---|---|
| All 24 policies via drift check | `policies.yml` | Continuous automated technical evaluation every hour |
| Audit logging enabled | `audit-logging-enabled.yml` | Provides evidence of control operation for assessment |
| NTP time synchronisation configured | `ntp-configured.yml` | Ensures evaluation timestamps are accurate |

> The drift check (drift_check.py) running hourly satisfies the "regular testing"
> requirement by continuously verifying that technical measures are in place and
> operational. GitHub Actions run history provides an auditable record of every
> evaluation cycle.

---

## Art. 33/34 — Breach Detection and Notification

Art. 33 requires notification to the supervisory authority within 72 hours of
becoming aware of a personal data breach. Art. 34 requires notification to data
subjects where the breach is likely to result in a high risk to their rights.

| Policy | File | Contribution |
|---|---|---|
| Audit logging enabled | `audit-logging-enabled.yml` | Provides logs for breach detection and investigation |
| CrowdStrike running | `crowdstrike-running.yml` | Detects security events that may constitute a breach |
| NTP time synchronisation configured | `ntp-configured.yml` | Ensures breach timeline reconstruction is accurate |
| Disk encryption enabled | `disk-encryption.yml` | Encrypted devices may reduce Art. 34 notification obligation |

---

## Key Gaps

GDPR compliance requires organisational measures that endpoint policies cannot
address. These are the most significant gaps:

| Requirement | Gap | Coverage Approach |
|---|---|---|
| Art. 13/14 Privacy Notices | No technical control | Draft and publish privacy notices for EU data subjects |
| Art. 17 Right to Erasure | Endpoint policies don't address data deletion | Data deletion procedures and technical capability in systems |
| Art. 20 Data Portability | No technical control | Data export capability in application systems |
| Art. 25 DPIA | Risk assessment process, not a technical control | Conduct Data Protection Impact Assessments for high-risk processing |
| Art. 27 EU Representative | Organisational requirement | Appoint an EU representative if required |
| Art. 28 Data Processing Agreements | Contractual, not technical | DPAs with all data processors (vendors, cloud providers) |
| Art. 30 Records of Processing | Documentation requirement | Maintain Records of Processing Activities (RoPA) |
| Art. 32 Organisational Measures | Policies and training | Security awareness training, incident response procedures |
| Art. 37 Data Protection Officer | Organisational role | Assess whether a DPO is required and appoint if so |
| Art. 44-49 International Transfers | Contractual and legal | Standard Contractual Clauses or adequacy decisions for data transfers |
| Supervisory Authority Registration | Jurisdictional requirement | Register with relevant EU supervisory authority if required |
