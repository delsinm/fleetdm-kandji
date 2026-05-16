# IT Endpoint Compliance — Architecture

## Overview

This system provides automated endpoint compliance monitoring and remediation by connecting FleetDM policy failures to Kandji MDM enforcement. One active script runs on a continuous schedule and serves as the primary compliance automation layer.

| Component | File | Trigger | Purpose |
|---|---|---|---|
| Drift check | `drift_check.py` | GitHub Actions hourly, 24/7 | Poll Fleet, remediate via Kandji, alert Slack |
| Webhook handler | `archive/fleet_remediation.py` | Fleet webhook (not deployed) | Real-time handler — archived |

See `archive/README.md` for context on when to deploy the webhook handler.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Identity Layer                           │
│                           Okta                                  │
│              (device trust gated on compliance)                 │
└────────────────────────────┬────────────────────────────────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
┌─────────────▼──────────-────┐  ┌──────────▼─────────-─────────────┐
│         FleetDM             │  │          EDR (CrowdStrike        │
│   (compliance / visibility) │  │          / Cisco / SentinelOne)  │
│                             │  │                                  │
│  osquery agents on all      │  │  Agents on all managed devices   │
│  managed endpoints          │  │  stream telemetry to EDR cloud   │
│                             │  │                                  │
│  32 policies (pass/fail)    │  │  Feed device risk signal         │
│  evaluated continuously     │  │  into Okta device trust          │
└──────┬──────────────────────┘  └──────────────────────────────────┘
       │
       │  Hourly, 24/7 (GitHub Actions)
       │
       ▼
┌──────────────────────────────────────────┐
│              drift_check.py              │
│                                          │
│  Phase 1: collect                        │
│    For each of 32 watched policies:      │
│    → Query Fleet API for failing hosts   │
│                                          │
│  Phase 2: remediate (deduplicated)       │
│    For each unique failing device:       │
│    → Look up serial in Kandji cache      │
│    → Issue one blankpush per device      │
│                                          │
│  Phase 3: report                         │
│    → Post summary to Slack (if drift)    │
│    → Emit JSON log lines to stdout       │
│    → Human-readable log to stderr        │
└──────────────┬───────────────────────────┘
               │
     ┌─────────┴──────────┐
     │                    │
     ▼                    ▼
  Kandji               Slack
  (blankpush →         (summary if
  device checks in,    drift found,
  re-enforces          silent on
  blueprint)           clean run)
               │
               ▼
        JSON log stream
        (stdout → SIEM)
```

---

## Component Detail

### `drift_check.py` — Scheduled Drift Detection

Standalone script that actively polls Fleet for policy failures and remediates them, independent of any webhook delivery. The only active script in this system.

**Flow:**

1. Builds a serial → device_id cache from Kandji (once per run, ~2-3 API calls)
2. Resolves watched policy names to IDs via Fleet API
3. For each of 32 watched policies, queries Fleet for currently-failing hosts
4. Deduplicates: issues one blankpush per unique device regardless of how many
   policies it is failing — a single blankpush re-enforces all blueprint controls
5. Posts a single Slack summary covering all findings (silent on clean runs)
6. Emits structured JSON log lines to stdout for SIEM ingestion

**Key design decisions:**

- **Single Slack summary per run** — avoids alert fatigue on large fleets
- **Deduplicated blankpush** — one push per device regardless of policy failure count
- **Kandji device cache** — built once at startup (~2-3 calls for 600 devices)
  rather than one per failing host (up to 600 × 32 = 19,200 calls without it)
- **Two log streams** — structured JSON to stdout for SIEM, human-readable to stderr
- **Per-service timeouts** — Fleet (5, 10)s, Kandji (5, 15)s, Slack (5, 10)s
- **Exits with code 1** on unhandled error — works cleanly with cron/CI monitoring

**Deployment:**

```bash
# cron — hourly, 24/7
0 * * * * /usr/bin/python3 /opt/fleet/drift_check.py >> /var/log/drift_check.log 2>&1

# or GitHub Actions (see below — recommended)
```

---

## Logging Architecture

The script produces two independent log streams simultaneously.

### Human-readable log → stderr

Standard Python logging. Useful for local debugging, cron monitoring, and reading GitHub Actions run logs directly.

```
2024-01-15 14:00:01 INFO  Starting drift check -- watching 32 policies
2024-01-15 14:00:02 INFO  Built Kandji device cache: 600 devices
2024-01-15 14:00:03 INFO  Policy OK: Firewall enabled
2024-01-15 14:00:04 INFO  Policy 'CrowdStrike running' -- 2 failing host(s)
2024-01-15 14:00:05 INFO  Blankpush sent to Kandji device abc-123
2024-01-15 14:00:06 INFO  Drift check complete -- 2 unique device(s) pushed
```

### Structured JSON log → stdout (SIEM)

Every compliance event is emitted as a JSON Lines record — one self-contained JSON object per line. Natively understood by Splunk HEC, Elastic Filebeat, Datadog Agent, and Google Cloud Logging.

```json
{"timestamp": "2024-01-15T14:00:01Z", "event": "drift_check_start", "policies_watched": 32}
{"timestamp": "2024-01-15T14:00:03Z", "event": "policy_ok", "policy": "Firewall enabled"}
{"timestamp": "2024-01-15T14:00:04Z", "event": "policy_failure", "policy": "CrowdStrike running", "hostname": "mac-042.local", "serial": "C02XL0PH", "kandji_device_id": "abc-123", "lookup_failure": null}
{"timestamp": "2024-01-15T14:00:05Z", "event": "blankpush_sent", "hostname": "mac-042.local", "kandji_device_id": "abc-123", "action": "blankpush", "outcome": "success"}
{"timestamp": "2024-01-15T14:00:06Z", "event": "drift_check_complete", "policies_checked": 32, "hosts_remediated": 2, "blankpush_failures": 0, "outcome": "success"}
```

**Event types:**

| Event | When emitted |
|---|---|
| `drift_check_start` | Beginning of each run |
| `policy_ok` | All hosts passing a policy |
| `policy_failure` | A host is failing a policy |
| `blankpush_sent` | MDM check-in successfully triggered |
| `blankpush_failed` | Blankpush API call failed |
| `drift_check_complete` | End of run, with summary counts |
| `drift_check_error` | Unhandled exception aborted the run |

**Configuration:**

```bash
# Default: JSON to stdout, human-readable to stderr
python drift_check.py

# Separate streams: JSON to file, human-readable to stderr
JSON_LOG_FILE=/var/log/drift_check_json.log python drift_check.py
```

**Why two streams:**

Kandji logs what it *did* — profile delivery, check-ins, blankpush receipt. Our JSON logs record the compliance *outcome* — independent verification that controls are actually in effect. A SIEM with both can answer: "was the control
enforced AND was it effective?" That correlation satisfies CA-7 (FedRAMP), CC7.2 (SOC 2), and A.8.16 (ISO 27001).

---

## Environment Variables

Store in a secrets manager (AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault) and inject at runtime — never commit to source control.

| Variable | Description |
|---|---|
| `FLEET_URL` | Base URL of Fleet server (e.g. `https://fleet.company.com`) |
| `FLEET_API_TOKEN` | Fleet API bearer token |
| `SLACK_BOT_TOKEN` | `xoxb-` bot token with `chat:write` scope |
| `SLACK_CHANNEL_ID` | Channel ID for your configured Slack channel |
| `KANDJI_API_TOKEN` | Kandji API bearer token |
| `KANDJI_SUBDOMAIN` | Kandji subdomain (e.g. `acme` for `acme.api.kandji.io`) |
| `DRIFT_POLICY_CONFIG` | Optional. Path to policy YAML file (default: `policies.yml`) |
| `JSON_LOG_FILE` | Optional. Path to write JSON log lines (default: stdout) |

---

## Repository Structure

```
it-infrastructure/
│
├── README.md                        ← operational overview
├── ARCHITECTURE.md                  ← this file
├── FEDRAMP-MATRIX.md                ← NIST 800-53 control mapping
├── HIPAA-MATRIX.md                  ← HIPAA Security Rule mapping
├── SOC2-MATRIX.md                   ← SOC 2 TSC mapping
├── ISO27001-MATRIX.md               ← ISO 27001:2022 Annex A mapping
├── GDPR-MATRIX.md                   ← GDPR Article mapping
├── PCI-DSS-MATRIX.md                ← PCI DSS v4.0 requirement mapping
│
├── remediation/
│   ├── drift_check.py               ← scheduled compliance sweep (active)
│   ├── policies.yml                 ← 28 watched policies (32 total files)
│   └── requirements.txt             ← requests>=2.31.0, pyyaml>=6.0.1
│
├── fleet/
│   ├── policies/                    ← 32 FleetDM policy YAML definitions
│   ├── queries/                     ← FleetDM scheduled query definitions
│   └── config/
│       └── agent-options.yml        ← osquery agent configuration
│
├── archive/
│   ├── README.md                    ← explains archived contents
│   └── fleet_remediation.py         ← real-time webhook handler (not deployed)
│
└── .github/
    └── workflows/
        ├── drift-check.yml          ← runs drift_check.py hourly, 24/7
        ├── fleet-plan-apply.yml     ← Fleet policy plan/apply (recommended)
        ├── fleet-sync.yml           ← Fleet policy sync, apply only
        └── README.md                ← workflow documentation
```

Kandji is managed through the Kandji UI and is not represented in this repository. Blueprints, library items, and enrollment settings are configured directly in Kandji and treated as the source of truth. The remediation scripts interact with Kandji only to trigger blankpushes — they do not read or modify any Kandji configuration.

---

## GitHub Actions — Scheduled Drift Check

```yaml
name: Fleet Drift Check

on:
  schedule:
    - cron: '0 * * * *'    # hourly, 24/7 — continuous monitoring
  workflow_dispatch:

jobs:
  drift-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Get current week
        id: date
        run: echo "week=$(date +'%Y-%U')" >> $GITHUB_OUTPUT

      - name: Cache pip downloads
        uses: actions/cache@v4
        with:
          path: ~/.cache/pip
          key: drift-check-${{ runner.os }}-${{ steps.date.outputs.week }}

      - name: Install dependencies
        run: pip install -r remediation/requirements.txt

      - name: Run drift check
        env:
          FLEET_URL:        ${{ secrets.FLEET_URL }}
          FLEET_API_TOKEN:  ${{ secrets.FLEET_API_TOKEN }}
          SLACK_BOT_TOKEN:  ${{ secrets.SLACK_BOT_TOKEN }}
          SLACK_CHANNEL_ID: ${{ secrets.SLACK_CHANNEL_ID }}
          KANDJI_API_TOKEN: ${{ secrets.KANDJI_API_TOKEN }}
          KANDJI_SUBDOMAIN: ${{ secrets.KANDJI_SUBDOMAIN }}
        run: python remediation/drift_check.py
```

---

## Performance Profile

| Scenario | Kandji API calls | Estimated runtime |
|---|---|---|
| All 600 devices compliant | ~3 (cache only) | ~60s (mostly Actions overhead) |
| 10 failing devices | ~13 | ~70s |
| 200 failing devices | ~203 | ~2-3 minutes |
| All 600 devices failing | ~603 | ~6-7 minutes |

**Rate Limits:**

* Kandji rate limit: 300 requests/minute. 
* Per-service timeouts: 
** Fleet (5, 10)s 
** Kandji (5, 15)s Slack (5, 10)s 
** GitHub Actions job timeout: 6 hours (not a practical concern at these volumes).

---

## NIST 800-53 Control Mapping

The drift check itself contributes to several controls beyond those covered by individual policies:

| Control | Description | How satisfied |
|---|---|---|
| CA-7 | Continuous Monitoring | Hourly automated policy evaluation, 24/7 |
| CM-3 | Configuration Change Control | All policy definitions managed in Git |
| CM-6 | Configuration Settings | Automated enforcement of baseline via blankpush |
| SI-2(2) | Automated Flaw Remediation Status | Automated detection and remediation of drift |
| SI-7 | Software/Firmware Integrity | Continuous verification controls are in effect |

See `FEDRAMP-MATRIX.md` for the full control mapping across all 32 policies.

---

## Known Limitations

**Blankpush latency** — a blankpush wakes the device via APNs but the device still needs to check in and apply its blueprint. On a healthy network this is seconds to a few minutes. Devices that are powered off, lid-closed for extended periods, or on restricted networks will not respond until they reconnect.

**Kandji device cache** — built once at startup. Devices enrolled in Kandji after the run starts will not be found until the next run.

**Global policies only** — `drift_check.py` queries global Fleet policies. If policies are scoped to Fleet teams, `get_all_policies()` would need to iterate team IDs and call the team policies endpoint for each.

**Agent verification, not outcome** — backup and EDR policies verify the agent process is running, not that it is operating correctly. A running agent can still fail silently. Verify outcomes in the respective management consoles.

**SIP failures require manual intervention** — SIP cannot be re-enabled via MDM. A device failing `sip-enabled.yml` requires physical access to Recovery Mode. Treat as a potential security incident.
