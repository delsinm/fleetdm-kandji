# GitHub Actions Workflows

This directory contains three workflows that automate Fleet policy management and compliance drift detection. Together they implement a GitOps approach to endpoint compliance — policy changes are reviewed, previewed, and applied through pull requests, and compliance is continuously verified on a schedule.

---

## Workflows

### `drift-check.yml` — Continuous Compliance Monitoring

**Trigger:** Scheduled (hourly, 24/7) and manual Runs `drift_check.py` on a recurring schedule. Polls FleetDM for any devices currently failing a watched policy, issues a Kandji blankpush to force each failing device to check in and re-enforce its controls, then posts a summary  
to Slack if any drift was found. Clean runs produce no Slack message.

```
Every hour, around the clock
         │
         ▼
   drift_check.py
         │
    ┌────┴────┐
    │         │
Fleet API   Kandji API
(who's       (blankpush
 failing?)    per device)
    │
    ▼
  Slack
(summary if
 drift found)
```

**Why 24/7:** Compliance drift does not respect business hours. Running continuously satisfies the "ongoing" monitoring requirement under CA-7 (FedRAMP), CC7.2 (SOC 2), A.8.16 (ISO 27001), and HIPAA § 164.308(a)(8).

**Secrets required:**


| Secret             | Description                    |
| ------------------ | ------------------------------ |
| `FLEET_URL`        | Base URL of your Fleet server  |
| `FLEET_API_TOKEN`  | Fleet API bearer token         |
| `SLACK_BOT_TOKEN`  | Slack bot token (`xoxb-`)      |
| `SLACK_CHANNEL_ID` | Channel ID for `#it-security`  |
| `KANDJI_API_TOKEN` | Kandji API bearer token        |
| `KANDJI_SUBDOMAIN` | Kandji subdomain (e.g. `acme`) |


---

### `fleet-plan-apply.yml` — Policy Plan and Apply (GitOps)

**Trigger:** Pull request to `main` (plan) and push to `main` (apply), scoped to changes under `fleet/policies/`

Mirrors the common Terraform plan/apply workflow. When a policy file is changed in a pull request, this workflow runs a dry-run and posts the output as a PR comment so reviewers can see exactly what would change on the Fleet server before approving. On merge to main, the changes are applied for real.

```
PR opened              →   validate YAML
                           dry-run (fleetctl apply --dry-run)
                           post output as PR comment

Merge to main          →   apply (fleetctl apply)
                           verify (fleetctl get policies)
```

**Step breakdown:**


| Step                       | What it does                                                     | When              |
| -------------------------- | ---------------------------------------------------------------- | ----------------- |
| Validate policy YAML       | Fast syntax check via `fleetctl validate` — no server connection | PR + push         |
| Post Validation Failure    | Comments on the PR if validation fails                           | PR only           |
| Fleet Dry Run              | Shows what would change without touching Fleet                   | PR only           |
| Post Dry Run as PR Comment | Posts dry-run output to the PR for review                        | PR only           |
| Apply Fleet Policies       | Applies changes to the Fleet server                              | Push to main only |
| Verify policies applied    | Confirms applied state via `fleetctl get policies`               | Push to main only |


**Note on dry-run vs Terraform plan:** `fleetctl apply --dry-run` is the  
closest equivalent to `terraform plan` but is less structured — it does not  
produce colour-coded diffs or resource counts. It validates the YAML and  
describes what would be created or modified.

**Secrets required:**


| Secret            | Description                                        |
| ----------------- | -------------------------------------------------- |
| `FLEET_URL`       | Base URL of your Fleet server                      |
| `FLEET_API_TOKEN` | Fleet API bearer token (needs policy write access) |


---

### `fleet-sync.yml` — Simple Policy Sync (apply only)

**Trigger:** Push to `main` scoped to `fleet/policies/`, and manual A simpler alternative to `fleet-plan-apply.yml` that only applies — no PR dry-run, no comment posting. Useful if you want a lightweight sync without the plan/apply ceremony, or as a fallback if `fleet-plan-apply.yml` is not being used.

```
Push to main (policy files changed)
         │
         ▼
   fleetctl apply -f fleet/policies/
         │
         ▼
   fleetctl get policies (verify)
```

**When to use this vs `fleet-plan-apply.yml`:**


|                    | `fleet-plan-apply.yml`                      | `fleet-sync.yml`                      |
| ------------------ | ------------------------------------------- | ------------------------------------- |
| PR dry-run comment | Yes                                         | No                                    |
| Apply on merge     | Yes                                         | Yes                                   |
| Manual trigger     | No                                          | Yes                                   |
| Complexity         | Higher                                      | Lower                                 |
| Best for           | Teams that want PR review of policy changes | Teams that want simple push-to-deploy |


Use `fleet-plan-apply.yml` if your team reviews policy changes via pull request. Use `fleet-sync.yml` if you prefer a simpler sync with manual override capability. Do not use both simultaneously for the same path — they will both trigger on push to main and apply twice.

**Secrets required:**


| Secret            | Description                                        |
| ----------------- | -------------------------------------------------- |
| `FLEET_URL`       | Base URL of your Fleet server                      |
| `FLEET_API_TOKEN` | Fleet API bearer token (needs policy write access) |


---

## Setup

### 1. Add secrets to your repository

Go to **Settings → Secrets and variables → Actions** and add each secret listed for the workflows you intend to use.

### 2. Choose your Fleet sync workflow

Pick either `fleet-plan-apply.yml` or `fleet-sync.yml` — not both. If you are using pull request reviews for policy changes, `fleet-plan-apply.yml `is recommended. Delete or disable the other.

### 3. Enable the drift check

`drift-check.yml` runs automatically once pushed to the repository. Verify it is working by going to **Actions → Fleet Drift Check → Run workflow** to trigger it manually. A successful run with no drift produces no Slack message. 

### 4. Verify Fleet connectivity

Both Fleet sync workflows require `fleetctl` to authenticate and reach your Fleet server. If your Fleet server is behind a VPN or private network, the GitHub Actions runner will not be able to reach it without additional networking configuration (e.g. a self-hosted runner inside your network, or a VPN step in the workflow).

---

## Relationship to other files

```
.github/workflows/
├── drift-check.yml         runs remediation/drift_check.py
├── fleet-plan-apply.yml    applies fleet/policies/*.yml (with PR preview)
└── fleet-sync.yml          applies fleet/policies/*.yml (apply only)

remediation/
├── drift_check.py          the script drift-check.yml runs
└── policies.yml            the watchlist drift_check.py reads

fleet/policies/             the policy YAMLs fleet-plan-apply / fleet-sync apply
```

See the root `README.md` for a full overview of how all components fit together.