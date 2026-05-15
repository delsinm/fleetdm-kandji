"""
ARCHIVED -- NOT DEPLOYED
========================
This script is not currently in use. It is preserved here for future reference.

Context
-------
fleet_remediation.py is a real-time webhook handler. When FleetDM detects a
policy failure it POSTs to this server, which immediately alerts Slack and
triggers a Kandji blankpush on the failing device.

Why it was archived
-------------------
For a small IT team, the operational overhead of running a persistent web
server (TLS, uptime monitoring, firewall rules, deployment pipeline) is not
justified by the marginal benefit over the scheduled drift check. The drift
check (drift_check.py) provides equivalent coverage with no infrastructure
to maintain.

When to revisit
---------------
Consider deploying this when:
  - The IT team grows and can own a persistent service
  - An audit finding or incident identifies the drift check window as inadequate
  - Infrastructure exists to host it cleanly (e.g. GCP Cloud Run)

Deployment notes (when ready)
------------------------------
  - Deploy on GCP Cloud Run for automatic TLS and zero infrastructure overhead
  - Restrict inbound access to Fleet server IP only (defence in depth)
  - Store credentials in GCP Secret Manager, injected at runtime
  - The HMAC signature validation and Slack alert format are production-ready

fleet_remediation.py
====================
Flask webhook receiver for FleetDM policy failures.

When Fleet detects a host failing a policy it POSTs a signed payload to this
server. For every failing host in that payload the handler will:

  1. Validate the HMAC-SHA256 webhook signature.
  2. Post a per-host alert to Slack #it-security.
  3. Look up the device in Kandji by hardware serial number.
  4. Issue a blankpush so the device checks in with MDM immediately
     and re-enforces its blueprint controls.

This is the real-time half of the remediation system. See drift_check.py
for the scheduled sweep that catches anything this handler misses (e.g.
devices that were offline when the webhook fired).

Kandji is treated as the source of truth for device configuration. Blueprints
are managed in the Kandji UI -- this script only triggers check-ins, it does
not modify any Kandji configuration.

Environment variables
---------------------
FLEET_WEBHOOK_SECRET  Shared secret used to validate Fleet webhook signatures.
SLACK_BOT_TOKEN       Bot token (xoxb-) with the chat:write scope.
SLACK_CHANNEL_ID      Channel ID for #it-security (not the name).
KANDJI_API_TOKEN      Kandji API bearer token.
KANDJI_SUBDOMAIN      Kandji subdomain, e.g. "acme" for acme.api.kandji.io.

Usage
-----
  pip install flask requests
  python fleet_remediation.py

Then configure Fleet to POST policy-failure webhooks to:
  https://<your-host>/webhook/fleet/policy-failure
"""

import hashlib
import hmac
import logging
import os
from typing import Any

import requests
from flask import Flask, abort, jsonify, request

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

FLEET_WEBHOOK_SECRET: str = os.environ["FLEET_WEBHOOK_SECRET"]
SLACK_BOT_TOKEN: str      = os.environ["SLACK_BOT_TOKEN"]
SLACK_CHANNEL_ID: str     = os.environ["SLACK_CHANNEL_ID"]
KANDJI_API_TOKEN: str     = os.environ["KANDJI_API_TOKEN"]
KANDJI_BASE_URL: str      = (
    f"https://{os.environ['KANDJI_SUBDOMAIN']}.api.kandji.io/api/v1"
)

# Reusable auth headers for each downstream service.
KANDJI_HEADERS: dict[str, str] = {
    "Authorization": f"Bearer {KANDJI_API_TOKEN}",
    "Content-Type":  "application/json",
}

SLACK_HEADERS: dict[str, str] = {
    "Authorization": f"Bearer {SLACK_BOT_TOKEN}",
    "Content-Type":  "application/json",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

app = Flask(__name__)


# ---------------------------------------------------------------------------
# Signature validation
# ---------------------------------------------------------------------------

def verify_fleet_signature(body: bytes, signature: str) -> bool:
    """Validate a Fleet webhook signature.

    Fleet signs every webhook payload with HMAC-SHA256 using the shared
    secret configured in Fleet -> Settings -> Integrations -> Webhooks. The
    resulting digest is sent in the Fleet-Webhook-Signature header in the
    form sha256=<hex-digest>.

    hmac.compare_digest is used for the final comparison to prevent timing
    attacks -- never use == for comparing secrets.

    Args:
        body:      Raw request body bytes, read before any JSON parsing.
        signature: Value of the Fleet-Webhook-Signature header.

    Returns:
        True if the signature is valid, False otherwise.
    """
    expected = "sha256=" + hmac.new(
        FLEET_WEBHOOK_SECRET.encode(),
        body,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------

def build_slack_blocks(host: dict, policy: dict) -> list[dict]:
    """Build a Slack Block Kit message for a single policy failure.

    Produces a structured message with a header, a four-field summary
    (policy name, hostname, serial, platform), and a footer noting that
    a blankpush was triggered.

    Args:
        host:   Fleet host object from the webhook payload.
        policy: Fleet policy object from the webhook payload.

    Returns:
        List of Slack Block Kit block dicts ready to pass to chat.postMessage.
    """
    hostname    = host.get("hostname", "unknown")
    serial      = host.get("hardware_serial", "unknown")
    policy_name = policy.get("name", "unknown")
    platform    = host.get("platform", "unknown")

    return [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": ":red_circle: FleetDM Policy Failure",
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Policy:*\n{policy_name}"},
                {"type": "mrkdwn", "text": f"*Host:*\n{hostname}"},
                {"type": "mrkdwn", "text": f"*Serial:*\n{serial}"},
                {"type": "mrkdwn", "text": f"*Platform:*\n{platform}"},
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    "_Kandji blankpush triggered -- device will re-enforce "
                    "controls on next check-in._"
                ),
            },
        },
    ]


def post_slack_alert(host: dict, policy: dict) -> None:
    """Post a per-host policy failure alert to Slack.

    Sends one message per failing host so that each device gets its own
    visible, actionable alert in #it-security. For batch-style summaries
    (e.g. from a scheduled drift run) use post_drift_summary() instead.

    Args:
        host:   Fleet host object containing hostname, serial, platform.
        policy: Fleet policy object containing the policy name.

    Raises:
        requests.HTTPError: If the Slack API returns a non-2xx status.
        RuntimeError:       If the Slack API returns ok=false in the body
                            (e.g. invalid_channel, not_in_channel).
    """
    hostname = host.get("hostname", "unknown")

    payload: dict[str, Any] = {
        "channel": SLACK_CHANNEL_ID,
        "text":    ":red_circle: FleetDM Policy Failure",
        "blocks":  build_slack_blocks(host, policy),
    }

    response = requests.post(
        "https://slack.com/api/chat.postMessage",
        headers=SLACK_HEADERS,
        json=payload,
    )
    response.raise_for_status()

    body = response.json()
    if not body.get("ok"):
        raise RuntimeError(f"Slack API error: {body.get('error')}")

    log.info("Slack alert posted for host %s", hostname)


# ---------------------------------------------------------------------------
# Kandji
# ---------------------------------------------------------------------------

def get_kandji_device_id(serial: str) -> str | None:
    """Look up a Kandji device ID by hardware serial number.

    Kandji has no direct serial-lookup endpoint, so this function calls the
    devices list endpoint with a server-side filter to narrow results, then
    exact-matches on serial locally (case-insensitive). On very large fleets
    (10k+ devices) consider replacing with a pre-built serial->device_id cache.

    Args:
        serial: Hardware serial number of the device (e.g. "C02XL0PHJHD2").

    Returns:
        The Kandji device_id string if found, or None if not enrolled.

    Raises:
        requests.HTTPError: If the Kandji API returns a non-2xx status.
    """
    response = requests.get(
        f"{KANDJI_BASE_URL}/devices",
        headers=KANDJI_HEADERS,
        params={"filter": serial},
    )
    response.raise_for_status()

    devices: list[dict] = response.json().get("results") or []

    for device in devices:
        if device.get("serial_number", "").upper() == serial.upper():
            return device["device_id"]

    return None


def blankpush(device_id: str) -> None:
    """Send a Kandji blankpush to force an immediate MDM check-in.

    A blankpush sends an Apple Push Notification (APNs) nudge to the device,
    prompting it to check in with Kandji and pull its current blueprint. It
    does not push any payload itself -- it simply wakes the MDM agent.

    Devices that are powered off, lid-closed for extended periods, or on
    restricted networks will not respond until they reconnect.

    Args:
        device_id: Kandji device UUID (from get_kandji_device_id).

    Raises:
        requests.HTTPError: If the Kandji API returns a non-2xx status.
    """
    response = requests.post(
        f"{KANDJI_BASE_URL}/devices/{device_id}/action/blankpush",
        headers=KANDJI_HEADERS,
    )
    response.raise_for_status()
    log.info("Blankpush sent to Kandji device %s", device_id)


# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------

def remediate_host(host: dict, policy: dict) -> dict:
    """Run the full remediation sequence for a single failing host.

    Orchestrates the three remediation steps -- Slack alert, Kandji device
    lookup, and blankpush -- and returns a structured result regardless of
    whether each step succeeded. Failures are caught and recorded rather than
    re-raised so that a single bad host does not abort the batch.

    Args:
        host:   Fleet host object (must include hardware_serial and hostname).
        policy: Fleet policy object (must include name).

    Returns:
        Dict with keys:
            hostname (str)  -- hostname of the device.
            success  (bool) -- True if blankpush was sent, False otherwise.
            reason   (str)  -- Failure reason if success is False, else "".
    """
    hostname = host.get("hostname", "unknown")
    serial   = host.get("hardware_serial")

    if not serial:
        log.warning("Host %s has no serial number, skipping", hostname)
        return {"hostname": hostname, "success": False, "reason": "no serial number"}

    try:
        post_slack_alert(host, policy)

        device_id = get_kandji_device_id(serial)
        if not device_id:
            log.warning("Serial %s not found in Kandji", serial)
            return {"hostname": hostname, "success": False, "reason": "not found in Kandji"}

        blankpush(device_id)
        return {"hostname": hostname, "success": True, "reason": ""}

    except Exception as exc:
        log.error("Remediation failed for %s: %s", hostname, exc)
        return {"hostname": hostname, "success": False, "reason": str(exc)}


# ---------------------------------------------------------------------------
# Webhook endpoint
# ---------------------------------------------------------------------------

@app.post("/webhook/fleet/policy-failure")
def handle_policy_failure():
    """Handle a Fleet policy-failure webhook.

    Fleet webhook payload shape::

        {
          "timestamp": "2024-01-01T00:00:00Z",
          "policy": {
            "id": 1,
            "name": "CrowdStrike running",
            ...
          },
          "hosts": [
            {
              "hostname": "mac-01.local",
              "hardware_serial": "C02XL0PHJHD2",
              "platform": "darwin",
              ...
            }
          ]
        }

    Each host in the payload is remediated independently via remediate_host().
    The response always returns HTTP 200 with a structured summary -- callers
    should inspect the failed list rather than relying on HTTP status alone.

    Returns:
        JSON body with keys:
            status     -- "ok"
            policy     -- Name of the failing policy.
            remediated -- List of hostnames that received a blankpush.
            failed     -- List of dicts (hostname, reason) for each failure.

    Aborts:
        401 if the Fleet-Webhook-Signature header is missing or invalid.
        400 if the request body is not valid JSON.
    """
    # Read raw body before JSON parsing -- signature is computed over raw bytes.
    body      = request.get_data()
    signature = request.headers.get("Fleet-Webhook-Signature", "")

    if not signature or not verify_fleet_signature(body, signature):
        abort(401, description="Invalid webhook signature")

    payload: dict      = request.get_json(force=True) or {}
    policy: dict       = payload.get("policy", {})
    hosts: list[dict]  = payload.get("hosts", [])

    log.info("Fleet webhook received -- policy: %s, hosts: %d", policy.get("name"), len(hosts))

    if not hosts:
        log.info("No failing hosts in payload, nothing to do")
        return jsonify({"status": "ok", "policy": policy.get("name"), "remediated": [], "failed": []})

    results    = [remediate_host(host, policy) for host in hosts]
    remediated = [r["hostname"] for r in results if r["success"]]
    failed     = [
        {"hostname": r["hostname"], "reason": r["reason"]}
        for r in results
        if not r["success"]
    ]

    log.info(
        "Policy '%s' complete -- %d remediated, %d failed",
        policy.get("name"), len(remediated), len(failed),
    )

    return jsonify({
        "status":     "ok",
        "policy":     policy.get("name"),
        "remediated": remediated,
        "failed":     failed,
    })


# ---------------------------------------------------------------------------
# Local dev entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
