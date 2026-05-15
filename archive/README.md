# Archive

This folder contains scripts that are complete and production-ready but not
currently deployed. They are preserved here rather than deleted so the work
is not lost and can be picked up when the time is right.

## Contents

### `fleet_remediation.py`

A Flask webhook receiver that provides real-time compliance remediation.
When FleetDM detects a policy failure it POSTs to this server, which
immediately alerts Slack and triggers a Kandji blankpush on the failing device.

**Why not deployed:** the operational overhead of a persistent web server
(TLS, uptime monitoring, firewall rules) is not justified for a small IT team
when `drift_check.py` provides equivalent coverage with no infrastructure.

**When to deploy:** when the IT team grows, dedicated infrastructure exists,
or an audit finding identifies the drift check response window as inadequate.
GCP Cloud Run is the recommended deployment target — automatic TLS, no server
to maintain, integrates with GCP Secret Manager.

**Status:** complete, tested, production-ready. No code changes needed to deploy.
