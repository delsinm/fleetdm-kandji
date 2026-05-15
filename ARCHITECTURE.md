# Fleet Remediation Architecture

## Overview

This system provides automated endpoint compliance remediation by connecting FleetDM policy failures to Kandji MDM enforcement. It has two complementary components that together ensure no compliance drift goes unaddressed.

| Component | File | Trigger | Purpose |
|---|---|---|---|
| Webhook handler | `fleet_remediation.py` | Fleet pushes on failure | Near-real-time response |
| Drift check | `drift_check.py` | Cron / scheduled | Safety net sweep |

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
┌─────────────▼─────────-─────┐  ┌──────────▼─────────────-─────────┐
│         FleetDM             │  │          CrowdStrike             │
│   (compliance / visibility) │  │      (EDR / threat detection)    │
│                             │  │                                  │
│  osquery agents on all      │  │  Falcon agents on all devices    │
│  managed endpoints          │  │  streams telemetry to CS cloud   │
│                             │  │                                  │
│  Policies (pass/fail):      │  │  Feeds device risk signal        │
│  - CrowdStrike running      │  │  into Okta device trust          │
│  - Disk encryption on       │  └──────────────────────────────────┘
│  - Firewall enabled         │
│  - OS up to date            │
└──────┬──────────────────────┘
       │
       │  Two paths to remediation
       │
  ┌────┴──────────────────────────────────────────────┐
  │                                                   │
  │  PATH 1: Webhook (real-time)                      │  PATH 2: Drift check (scheduled)
  │  Fleet detects failure → POST to webhook handler  │  Cron polls Fleet API every hour
  │                                                   │  for any currently-failing hosts
  ▼                                                   ▼
┌──────────────────────────┐          ┌───────────────────────────┐
│   fleet_remediation.py   │          │      drift_check.py       │
│   (FastAPI webhook)      │          │   (standalone script)     │
└──────────┬───────────────┘          └──────────┬────────────────┘
           │                                     │
           │  Both do the same three things:     │
           └───────────────┬─────────────────────┘
                           │
          ┌────────────────┼────────────────┐
          │                │                │
          ▼                ▼                ▼
  Validate sig      Alert Slack       Blankpush via
  (webhook only)    #it-security         Kandji
                                          │
                                          ▼
                                   Device checks in
                                   with MDM, pulls
                                   current blueprint,
                                   re-enforces controls
```

---

## Component Detail

### `fleet_remediation.py` — Webhook Handler

FastAPI server that receives Fleet policy failure webhooks.

**Flow:**

1. Fleet detects a host failing a policy
2. Fleet POSTs to `/webhook/fleet/policy-failure`
3. Handler validates HMAC-SHA256 signature
4. For each failing host in the payload:
   - Posts alert to Slack `#it-security`
   - Looks up device in Kandji by serial number
   - Issues blankpush → device pulls updated blueprint

**Key design decisions:**

- HMAC validation uses `hmac.compare_digest` to prevent timing attacks
- Hosts are processed independently — one failure doesn't abort the batch
- Returns structured JSON with `remediated` and `failed` lists per run

**Deployment:**

```bash
pip install flask requests
python fleet_remediation.py
```

Point Fleet's policy webhook at: `https://your-server/webhook/fleet/policy-failure`

---

### `drift_check.py` — Scheduled Drift Detection

Standalone script that actively polls Fleet for policy failures and remediates them, independent of webhook delivery.

**Flow:**

1. Resolves watched policy names to IDs via Fleet API
2. For each watched policy, queries Fleet for currently-failing hosts (paginated)
3. For each failing host:
   - Looks up device in Kandji by serial number
   - Issues blankpush
4. Posts a single summary message to Slack covering all findings

**Key design decisions:**

- Single Slack summary per run rather than per host — avoids alert fatigue on large fleets
- Only posts to Slack if drift is found — clean runs are silent
- Paginates Fleet host results — safe at any fleet size
- Exits with code 1 on unhandled error — works cleanly with cron monitoring

**Deployment:**

```bash
# cron — hourly, 24/7
0 * * * * /usr/bin/python3 /opt/fleet/drift_check.py >> /var/log/drift_check.log 2>&1

# or systemd timer
# or GitHub Actions (see below)
```

---

## Why Both Components

| Scenario | Webhook handler | Drift check |
|---|---|---|
| Host fails policy while online | Catches it | Also catches it |
| Host was offline when webhook fired | Misses it | Catches it on next run |
| Webhook delivery fails (network, downtime) | Misses it | Catches it on next run |
| Failure has been persisting for days | May have stopped alerting | Always catches it |
| New failure just occurred | Catches within seconds | Catches within 1 hour max |

Together they form a closed loop: the webhook handler minimizes time-to-remediation, the drift check ensures nothing stays broken indefinitely.

---

## NIST 800-53 Control Mapping

Each watched policy maps to one or more FedRAMP controls:

| Policy | Control | Family |
|---|---|---|
| CrowdStrike running | SI-3 (Malware Protection) | System & Information Integrity |
| Disk encryption enabled | SC-28 (Protection at Rest) | System & Communications Protection |
| Firewall enabled | SC-7 (Boundary Protection) | System & Communications Protection |
| OS up to date | SI-2 (Flaw Remediation) | System & Information Integrity |

The blankpush + re-enforcement loop also contributes to:

- **CM-6** (Configuration Settings) — automated enforcement of baseline configs
- **CM-3** (Configuration Change Control) — all policy definitions managed in Git
- **SI-7** (Software, Firmware, and Information Integrity) — continuous verification that security controls are in effect

Drift check run logs and Slack summaries serve as continuous monitoring evidence for a 3PAO audit.

---

## Environment Variables

Both scripts share a common set of environment variables. Store in a secrets manager (AWS Secrets Manager, HashiCorp Vault) and inject at runtime — never in source.

| Variable | Used by | Description |
|---|---|---|
| `FLEET_URL` | drift_check | Base URL of Fleet server |
| `FLEET_API_TOKEN` | drift_check | Fleet API bearer token |
| `FLEET_WEBHOOK_SECRET` | fleet_remediation | HMAC secret for webhook validation |
| `SLACK_BOT_TOKEN` | both | `xoxb-` bot token with `chat:write` |
| `SLACK_CHANNEL_ID` | both | Channel ID for `#it-security` |
| `KANDJI_API_TOKEN` | both | Kandji API bearer token |
| `KANDJI_SUBDOMAIN` | both | Kandji subdomain (e.g. `acme`) |

---

## Repository Structure

```
it-infrastructure/
├── fleet/
│   ├── policies/
│   │   ├── crowdstrike-running.yml
│   │   ├── disk-encryption.yml
│   │   ├── firewall-enabled.yml
│   │   └── os-up-to-date.yml
│   ├── queries/
│   │   └── get-local-admins.yml
│   └── config/
│       └── agent-options.yml
├── remediation/
│   ├── fleet_remediation.py    ← webhook handler (Flask)
│   ├── drift_check.py          ← scheduled drift check
│   ├── policies.yml            ← watched policy list for drift_check
│   └── requirements.txt
└── .github/
    └── workflows/
        ├── fleet-sync.yml      ← applies Fleet policy/query YAML on merge
        └── drift-check.yml     ← runs drift_check.py on a schedule
```

Kandji is managed entirely through the Kandji UI and is not represented in this repository. Blueprints, library items, and enrollment settings are configured directly in Kandji and treated as the source of truth. The remediation scripts interact with Kandji only to trigger blankpushes - they do not read or modify any Kandji configuration.

---

## GitHub Actions — Scheduled Drift Check

```yaml
# .github/workflows/drift-check.yml
name: Fleet Drift Check

on:
  schedule:
    - cron: '0 * * * *'   # hourly, 24/7 — continuous monitoring
  workflow_dispatch:               # allow manual trigger

jobs:
  drift-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: pip install requests pyyaml

      - name: Run drift check
        env:
          FLEET_URL: ${{ secrets.FLEET_URL }}
          FLEET_API_TOKEN: ${{ secrets.FLEET_API_TOKEN }}
          SLACK_BOT_TOKEN: ${{ secrets.SLACK_BOT_TOKEN }}
          SLACK_CHANNEL_ID: ${{ secrets.SLACK_CHANNEL_ID }}
          KANDJI_API_TOKEN: ${{ secrets.KANDJI_API_TOKEN }}
          KANDJI_SUBDOMAIN: ${{ secrets.KANDJI_SUBDOMAIN }}
        run: python remediation/drift_check.py
```

---

## Known Limitations

**Blankpush latency** — a blankpush wakes the device via APNs but the device still needs to check in and apply its blueprint. On a healthy network this is seconds to a few minutes. Devices that are powered off, lid-closed for extended periods, or on restricted networks will not respond until they reconnect.

**Kandji device lookup** — the drift check builds a full serial -> device_id cache at startup via paginated requests. At 600 devices this is 2-3 API calls rather than one per host. The cache is not refreshed mid-run, so devices enrolled in Kandji after the run starts will not be found until the next run. The webhook handler (`fleet_remediation.py`) still uses per-host lookups since it processes smaller batches in real time.

**Fleet team policies** — `drift_check.py` currently queries global policies only. If policies are scoped to Fleet teams, `get_all_policies()` would need to iterate team IDs and call the team policies endpoint for each.

**No deduplication between components** — if a host is failing when both the webhook fires and the drift check runs, it will receive two blankpushes. This is harmless but worth knowing.
