![security_boat_sm](./images/security_boat_sm.png)

# FleetDM &  Kandji IT Endpoint Compliance Remediation

This repository provides automated endpoint compliance monitoring and remediation for macOS device fleets. It connects three tools - FleetDM, Kandji, and Slack - to continuously verify that managed devices meet security policy requirements and automatically nudge non-compliant devices back into compliance.

---

## What problem does this solve?

In a managed device environment, security controls are deployed via MDM (Kandji). But MDM enforcement is not instant — devices that are offline, recently enrolled, or experiencing profile delivery issues can drift out of compliance silently. Without this system, the only way to know a device is non-compliant is to manually check it, or wait for an audit finding. 

With this system:

- Non-compliant devices are detected within one hour, around the clock
- Kandji is automatically triggered to re-enforce controls on the affected device
- The security team is alerted in Slack with details of what failed and on which device
- Every run produces an auditable log for compliance reporting

---

## Why independent verification matters

Kandji is the primary enforcement mechanism — it pushes device configuration continuously via MDM and is the source of truth for what a compliant device looks like. Under normal circumstances it handles everything. This system is the independent verification layer on top of that. The two roles are distinct and complementary:

```
Kandji (MDM enforcement)          FleetDM + drift check (independent verification)
────────────────────────          ──────────────────────────────────────────────────
Pushes controls to devices        Verifies controls are actually in effect
Enforces on enrollment            Catches drift that occurs after enforcement
Trusts the delivery mechanism     Checks the outcome regardless of delivery
```

**Why Kandji alone is not sufficient**

MDM enforcement can silently fail or be undone:


| Scenario                               | Kandji                         | This system                |
| -------------------------------------- | ------------------------------ | -------------------------- |
| Device offline when profile was pushed | Misses it until next check-in  | Detects on next drift run  |
| Profile delivery silently failed       | Thinks device is compliant     | Detects the actual state   |
| User manually disabled a control       | Already enforced — now drifted | Detects and re-enforces    |
| EDR software crashed after install      | Enforced at install time       | Detects it stopped running |
| New device not yet fully enrolled      | Controls not yet applied       | Detects missing controls   |


**Why this matters for compliance**

Every major framework requires not just enforcement but independent verification that controls are actually operating as intended:


| Framework             | Control                                   | Requirement                                                         |
| --------------------- | ----------------------------------------- | ------------------------------------------------------------------- |
| FedRAMP / NIST 800-53 | CA-7 Continuous Monitoring                | Verify controls are operating effectively on an ongoing basis       |
| FedRAMP / NIST 800-53 | SI-2(2) Automated Flaw Remediation Status | Automated mechanisms to determine patch compliance state            |
| HIPAA                 | § 164.308(a)(8) Evaluation                | Periodic technical evaluation of security measures                  |
| SOC 2                 | CC7.2 Monitor for Anomalies               | Independent monitoring of system components for anomalous behaviour |
| SOC 2                 | CC7.3 Evaluate Security Events            | Evaluation of whether security events represent control failures    |
| ISO 27001             | A.8.16 Monitoring Activities              | Verify that controls are effective, not just deployed               |


Kandji satisfies the enforcement requirement. This system satisfies the independent verification requirement. Having both is a more defensible position with a 3PAO, HIPAA auditor, or SOC 2 assessor than relying on MDM enforcement alone.

---

## How the pieces fit together

```
FleetDM                    Kandji                     Slack
(sees policy failures)  →  (fixes the device)     →  (alerts the team)
```

**FleetDM** runs a lightweight agent (osquery) on every managed Mac. This agent continuously checks whether each device passes your security policies - things like "is FileVault on?" or "is CrowdStrike running?". When a device fails a policy, FleetDM knows about it.

**Kandji** is your MDM — it manages device configuration, pushes security profiles, and enforces settings. When a device is told to check in (via a "blankpush"), it pulls its current blueprint and re-enforces all configured controls.

**Slack** is where your team gets notified. Rather than logging into FleetDM to check compliance status, the system posts alerts and summary reports directly to your configured Slack channel.

---

## The script

There is one active script: `drift_check.py`. A real-time webhook handler (`fleet_remediation.py`) also exists in the `archive/` folder. It is complete and production-ready but not currently deployed — see `archive/README.md` for context on when to revisit it.

### `drift_check.py` — Scheduled compliance sweep

This script runs on a schedule (hourly, 24/7). It actively polls FleetDM for any devices currently failing any watched policy, then remediates them.

For each failing device it:

1. Builds a cache of all enrolled Kandji devices (once per run, not per device)
2. Looks up the failing device in that cache by serial number
3. Sends a blankpush to force the device to check in and re-enforce its controls
4. Records the result for the Slack summary

At the end of each run it posts a single summary to Slack listing every affected device grouped by policy. If all devices are compliant, no Slack message is sent. 

**Response time:** up to 1 hour, but typically within the next scheduled run.

---

## The policies

The `fleet/policies/` folder contains 23 FleetDM policy definitions. Each policy is a simple check that runs on every managed device and returns pass or fail.

Policies are organised into categories:


| Category                   | Policies                                                                                                      |
| -------------------------- | ------------------------------------------------------------------------------------------------------------- |
| Malware & Threat Detection | CrowdStrike running, CrowdStrike version current                                                              |
| Encryption                 | Disk encryption, FileVault key escrowed                                                                       |
| Network & Boundary         | Firewall, SSH, Screen sharing, Remote management, AirDrop, Internet sharing, Printer sharing, Content caching |
| System Integrity           | SIP enabled, Gatekeeper enabled                                                                               |
| Patching                   | Automatic updates, OS up to date                                                                              |
| Access Control             | Guest account, Local admin accounts, Screen lock, Password after lock, Password complexity, Login window      |
| Audit & Logging            | Audit logging                                                                                                 |


Each policy file documents exactly what it checks, why it matters, and how to fix it if a device fails. Compliance mappings are included for FedRAMP, HIPAA, SOC 2, and ISO 27001.

The list of policies the drift check watches is controlled by `policies.yml`. To add or remove a watched policy, edit that file and commit — no code change needed.

---

## How a remediation works end to end

Example: Here is what happens when a device loses CrowdStrike:

```
1. FleetDM detects falcond is not running on mac-042.local

2. On the next drift check run (within 1 hour):
      → drift_check.py asks Fleet: "who is failing CrowdStrike running?"
      → Fleet returns mac-042.local (serial: C02XL0PH)
      → drift_check.py looks up C02XL0PH in its Kandji device cache
      → sends blankpush to Kandji for that device

3. Kandji sends an APNs nudge to mac-042.local

4. mac-042.local checks in with Kandji and pulls its blueprint

5. Kandji re-installs/restarts the CrowdStrike library item

6. CrowdStrike starts running again

7. On next Fleet policy check, mac-042.local passes

8. Slack receives a summary of the run noting mac-042.local was remediated
```

---

## Logging

The drift check produces two log streams simultaneously — one for human operators, one for SIEM ingestion.

### Human-readable log

Standard Python logging written to stderr. Useful for local debugging, cron monitoring, and GitHub Actions run logs. Format:

```
2024-01-15 14:00:01 INFO  Starting drift check -- watching 23 policies
2024-01-15 14:00:02 INFO  Built Kandji device cache: 600 devices
2024-01-15 14:00:03 INFO  Policy OK: Firewall enabled
2024-01-15 14:00:04 INFO  Policy 'CrowdStrike running' -- 2 failing host(s)
2024-01-15 14:00:05 INFO  Blankpush sent to Kandji device abc-123
2024-01-15 14:00:06 INFO  Drift check complete -- 2 unique device(s) pushed
```

### Structured JSON log (SIEM)

Every compliance event is also emitted as a JSON Lines record — one JSON object per line — written to stdout by default. This format is natively understood by Splunk HEC, Elastic Filebeat, Datadog Agent, and Google Cloud Logging.

Each record contains a UTC ISO 8601 timestamp and a self-describing event type:

```json
{"timestamp": "2024-01-15T14:00:01Z", "event": "drift_check_start", "policies_watched": 23}
{"timestamp": "2024-01-15T14:00:03Z", "event": "policy_ok", "policy": "Firewall enabled"}
{"timestamp": "2024-01-15T14:00:04Z", "event": "policy_failure", "policy": "CrowdStrike running", "hostname": "mac-042.local", "serial": "C02XL0PH", "kandji_device_id": "abc-123", "lookup_failure": null}
{"timestamp": "2024-01-15T14:00:05Z", "event": "blankpush_sent", "hostname": "mac-042.local", "kandji_device_id": "abc-123", "action": "blankpush", "outcome": "success"}
{"timestamp": "2024-01-15T14:00:06Z", "event": "drift_check_complete", "policies_checked": 23, "hosts_remediated": 2, "blankpush_failures": 0, "outcome": "success"}
```

**Event types:**


| Event                  | When emitted                        |
| ---------------------- | ----------------------------------- |
| `drift_check_start`    | Beginning of each run               |
| `policy_ok`            | All hosts passing a policy          |
| `policy_failure`       | A host is failing a policy          |
| `blankpush_sent`       | MDM check-in successfully triggered |
| `blankpush_failed`     | Blankpush API call failed           |
| `drift_check_complete` | End of run, with summary counts     |
| `drift_check_error`    | Unhandled exception aborted the run |


### Configuration

By default JSON logs go to stdout alongside the human-readable output. To separate them, set the `JSON_LOG_FILE` environment variable to a file path — the script will append JSON lines there while human-readable logs continue to stderr:

```bash
JSON_LOG_FILE=/var/log/drift_check_json.log python drift_check.py
```

### Why two streams?

Kandji logs what it *did* — profile delivery, check-ins, blankpush receipt. Our JSON logs record the compliance *outcome* — independent verification that controls are actually in effect. A SIEM with both can answer: "was the control enforced AND was it effective?" That correlation is what satisfies the evidence requirements for CA-7 (FedRAMP), CC7.2 (SOC 2), and A.8.16 (ISO 27001).

---

## Repository structure

```
it-infrastructure/
│
├── README.md                        ← this file
├── ARCHITECTURE.md                  ← detailed technical architecture
│
├── remediation/
│   ├── drift_check.py               ← scheduled compliance sweep (active)
│   └── policies.yml                 ← list of policies the drift check watches
│
├── fleet/
│   ├── policies/                    ← FleetDM policy YAML definitions (23 files)
│   ├── queries/                     ← FleetDM scheduled query definitions
│   └── config/
│       └── agent-options.yml        ← osquery agent configuration
│
├── archive/
│   ├── README.md                    ← explains archived contents
│   └── fleet_remediation.py        ← real-time webhook handler (not deployed)
│
└── .github/
    └── workflows/
        ├── fleet-sync.yml           ← applies Fleet policies to Fleet server on merge
        └── drift-check.yml          ← runs drift_check.py hourly, 24/7
```

### Compliance documentation


| File                 | Contents                                        |
| -------------------- | ----------------------------------------------- |
| `FEDRAMP-MATRIX.md`  | Policy → NIST 800-53 control mapping            |
| `HIPAA-MATRIX.md`    | Policy → HIPAA Security Rule section mapping    |
| `SOC2-MATRIX.md`     | Policy → SOC 2 Trust Services Criteria mapping  |
| `ISO27001-MATRIX.md` | Policy → ISO 27001:2022 Annex A control mapping |


---

## Setup guide

### What you need before starting

- A running FleetDM server with osquery agents enrolled on your Mac fleet
- A Kandji account with devices enrolled
- A Slack workspace with a bot token
- A GitHub repository with Actions enabled

### Step 1 — Configure secrets

The drift check uses environment variables for credentials. Store these in your secrets manager (GCP Secret Manager, AWS Secrets Manager, or HashiCorp Vault) and inject them at runtime. Never store credentials in the repository.

Add each as a GitHub Actions secret under **Settings → Secrets and variables → Actions** in your repository.


| Variable           | Where to get it                                                                        |
| ------------------ | -------------------------------------------------------------------------------------- |
| `FLEET_URL`        | Your Fleet server URL, e.g. `https://fleet.company.com`                                |
| `FLEET_API_TOKEN`  | Fleet → Settings → Integrations → API token                                            |
| `SLACK_BOT_TOKEN`  | Slack app settings → OAuth → Bot token (starts with `xoxb-`)                           |
| `SLACK_CHANNEL_ID` | Right-click `#it-security` (or whatever channel you choose) in Slack → Copy channel ID |
| `KANDJI_API_TOKEN` | Kandji → Settings → Access → API token                                                 |
| `KANDJI_SUBDOMAIN` | Your Kandji subdomain, e.g. `acme` for `acme.api.kandji.io`                            |


### Step 2 — Install Fleet policies

Apply the policy YAML files to your Fleet server using the FleetDM CLI:

```bash
# Install the Fleet CLI
npm install -g fleetctl

# Log in to your Fleet server
fleetctl login --address https://fleet.company.com

# Apply all 23 policies
fleetctl apply -f fleet/policies/
```

Once applied, policies will begin evaluating on enrolled devices within minutes. Verify they appear in Fleet under **Policies** in the web UI - each should show pass/fail counts across your fleet.

### Step 3 — Set up the drift check

The drift check runs automatically via GitHub Actions. The workflow file is already in the repository at `.github/workflows/drift-check.yml`. Push the repository to GitHub. The workflow will run automatically on the configured schedule:

```
Hourly, 24/7 — continuous monitoring with no time restriction
```

This ensures compliance drift is detected within one hour regardless of when it occurs, which satisfies the "continuous monitoring" requirement across FedRAMP, HIPAA, SOC 2, and ISO 27001. Clean runs produce no Slack message, so there is no operational noise from off-hours execution.

To verify it works before waiting for the schedule, go to **Actions → Fleet Drift Check → Run workflow** in GitHub to trigger it manually.

### Step 4 — Verify everything is working

1. **Check Fleet policies** — confirm all 23 policies appear in Fleet under Policies and are evaluating (showing pass/fail counts per device).
2. **Run the drift check manually** — trigger the GitHub Action and confirm it completes without errors. If all devices are compliant no Slack message will be sent — this is expected and correct.
3. **Simulate a failure** — in Fleet, find a test device and check which policies it is currently failing (if any). The next drift check run should pick it up and post a Slack summary.
4. **Check Slack** — confirm the summary appears in your configured Slack channel when drift is detected. A clean fleet produces no message.

---

## Day-to-day operations

### Adding a new policy

1. Create a new YAML file in `fleet/policies/` following the existing format
2. Add the policy name to `remediation/policies.yml`
3. Update the relevant compliance matrix files
4. Open a pull request — on merge, the Fleet sync workflow applies it automatically

### Changing the drift check schedule

Edit the cron expression in `.github/workflows/drift-check.yml`. The current schedule runs hourly, 24/7, which satisfies the continuous monitoring requirement across all targeted compliance frameworks. GitHub Actions cron runs in UTC — if you need to restrict to specific hours, adjust the expression but be prepared to justify the gap to auditors.

### Investigating a Slack alert

When the drift check posts a summary:

1. Note the hostname and serial number from the Slack message
2. Find the device in Fleet to see all policy pass/fail status
3. Find the device in Kandji to confirm the blankpush was received
4. If the device is still failing after the next drift check run, investigate manually

### Updating the CrowdStrike version threshold

The `crowdstrike-version.yml` policy checks against a minimum agent version.  
Update it quarterly or when CrowdStrike releases a new required minimum:

```yaml
# fleet/policies/crowdstrike-version.yml
query: >
  SELECT 1 FROM apps
  WHERE name = 'Falcon.app'
    AND bundle_short_version >= '7.10';  ← update this version
```

Commit the change and the Fleet sync workflow will apply it on merge.

---

## Compliance documentation

Full framework mapping is available in the matrix files at the root of this repository. Each policy file also contains inline compliance rationale in its header comments.

For audit purposes, the drift check GitHub Actions run history provides a timestamped record of every compliance sweep, including which devices were found non-compliant and whether remediation was triggered.

---

## Further reading

- `ARCHITECTURE.md` — detailed technical design, component diagrams, and known limitations
- `FEDRAMP-MATRIX.md` — NIST 800-53 control mapping
- `HIPAA-MATRIX.md` — HIPAA Security Rule mapping
- `PCI-DSS.md` — PCI-DSS 4.0 control mapping
- `SOC2-MATRIX.md` — SOC 2 Trust Services Criteria mapping
- `ISO27001-MATRIX.md` — ISO 27001:2022 Annex A mapping
- [FleetDM documentation](https://fleetdm.com/docs)
- [Kandji API reference](https://api.kandji.io)
