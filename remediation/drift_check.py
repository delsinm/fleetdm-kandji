"""
drift_check.py
==============
Scheduled drift detection job for FleetDM policy compliance.

Polls the Fleet API for hosts currently failing any watched policy, then for
each failing host issues a Kandji blankpush to force an immediate MDM check-in
and re-enforce blueprint controls. All findings are summarised in a single
Slack message per run.

This is the scheduled half of the remediation system -- the safety net that
catches anything fleet_remediation.py misses:

  fleet_remediation.py  --  reacts to Fleet webhooks in near-real-time.
  drift_check.py        --  scheduled sweep for persistent failures, offline
                            devices, or missed webhook deliveries.

The list of policies to watch is read from a YAML file (default: policies.yml)
so policies can be added or removed without touching this script.

Environment variables
---------------------
FLEET_URL             Base URL of your Fleet server (e.g. https://fleet.company.com).
FLEET_API_TOKEN       Fleet API token (Settings -> Integrations -> API).
SLACK_BOT_TOKEN       Bot token (xoxb-) with the chat:write scope.
SLACK_CHANNEL_ID      Channel ID for your configured Slack channel (not the channel name, use the ID).
KANDJI_API_TOKEN      Kandji API bearer token.
KANDJI_SUBDOMAIN      Kandji subdomain, e.g. "acme" for acme.api.kandji.io.
DRIFT_POLICY_CONFIG   Optional. Path to the policy YAML file (default: policies.yml).
JSON_LOG_FILE         Optional. Path to write JSON log lines (default: stdout).
                      Set to a file path to write JSON separately from human logs.
                      If unset, JSON lines are written to stdout interleaved with
                      human-readable output -- redirect stdout to your log shipper.

Usage
-----
  pip install requests pyyaml

  # Run once manually
  python drift_check.py

  # Run on a schedule via cron (hourly, 24/7)
  0 * * * *  /usr/bin/python3 /opt/fleet/drift_check.py >> /var/log/drift_check.log 2>&1

  # Run on a schedule via GitHub Actions (see ARCHITECTURE.md)
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any

import requests
import yaml

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

FLEET_URL: str      = os.environ["FLEET_URL"].rstrip("/")
FLEET_API_TOKEN: str = os.environ["FLEET_API_TOKEN"]
SLACK_BOT_TOKEN: str = os.environ["SLACK_BOT_TOKEN"]
SLACK_CHANNEL_ID: str = os.environ["SLACK_CHANNEL_ID"]
KANDJI_API_TOKEN: str = os.environ["KANDJI_API_TOKEN"]
KANDJI_BASE_URL: str  = (
    f"https://{os.environ['KANDJI_SUBDOMAIN']}.api.kandji.io/api/v1"
)

# Path to the policy config file. Override with DRIFT_POLICY_CONFIG env var.
POLICY_CONFIG_PATH: str = os.environ.get("DRIFT_POLICY_CONFIG", "policies.yml")

# Maximum number of hosts to list per policy in the Slack summary.
# Hosts beyond this threshold are collapsed into a count line to keep
# the message readable on large fleets.
MAX_HOSTS_IN_SUMMARY: int = 20

# Per-service request timeouts as (connect_timeout, read_timeout) tuples.
# Connect timeout: maximum seconds to establish a TCP connection.
# Read timeout:    maximum seconds to wait for data after connecting.
# Using separate values prevents hanging on slow or unresponsive services
# without being too aggressive on legitimate slow responses.
#
# Worst-case run time with these timeouts and 600 failing devices:
#   600 Kandji blankpushes × 15s read timeout = 150 minutes maximum
#   (only reached if every single call hangs at the limit, which is unlikely)
FLEET_TIMEOUT:  tuple[int, int] = (5, 10)   # Fleet is self-hosted — should be fast
KANDJI_TIMEOUT: tuple[int, int] = (5, 15)   # Kandji cloud — more generous for blankpush volume
SLACK_TIMEOUT:  tuple[int, int] = (5, 10)   # Slack is highly reliable

# Reusable auth headers for each downstream service.
FLEET_HEADERS: dict[str, str] = {
    "Authorization": f"Bearer {FLEET_API_TOKEN}",
    "Content-Type":  "application/json",
}

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


# ---------------------------------------------------------------------------
# Structured JSON logging
# ---------------------------------------------------------------------------

class JsonLogger:
    """Writes structured JSON log lines for SIEM ingestion.

    Runs alongside the standard human-readable logger. Each event is a
    self-contained JSON object on a single line (JSON Lines format), making
    it easy to ingest into Splunk, Elastic, Datadog, Google SecOps, or any
    log shipper that understands newline-delimited JSON.

    Output destination is controlled by the JSON_LOG_FILE environment variable:
      - If set: writes JSON lines to that file path (appends).
      - If unset: writes to stdout, interleaved with human-readable output.
        Redirect stdout to your log shipper in that case.

    Every event includes a UTC ISO 8601 timestamp and an event type string
    so records are self-describing and sortable without additional metadata.

    Event types emitted:
      drift_check_start         -- run began, N policies watched
      policy_ok                 -- all hosts passing a policy
      policy_failure            -- host failing a policy, device lookup result
      blankpush_sent            -- MDM check-in triggered for a device
      blankpush_failed          -- blankpush API call failed
      drift_check_complete      -- run finished, summary counts
      drift_check_error         -- unhandled exception aborted the run
    """

    def __init__(self) -> None:
        """Initialise the JSON logger.

        Opens JSON_LOG_FILE for appending if set, otherwise uses stdout.
        Line-buffered so each JSON record is flushed immediately -- important
        for log shippers that tail the file.
        """
        json_log_path = os.environ.get("JSON_LOG_FILE")
        if json_log_path:
            self._fh = open(json_log_path, "a", buffering=1)  # line-buffered
        else:
            self._fh = sys.stdout

    def _emit(self, event: str, **kwargs: Any) -> None:
        """Write a single JSON log line to the output destination.

        Args:
            event:   Event type string identifying the log record.
            **kwargs: Additional fields to include in the JSON object.
        """
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event":     event,
            **kwargs,
        }
        print(json.dumps(record), file=self._fh, flush=True)

    def run_start(self, policy_count: int) -> None:
        """Log the start of a drift check run.

        Args:
            policy_count: Number of policies being watched this run.
        """
        self._emit("drift_check_start", policies_watched=policy_count)

    def policy_ok(self, policy: str) -> None:
        """Log that all hosts are passing a policy.

        Args:
            policy: Name of the passing policy.
        """
        self._emit("policy_ok", policy=policy)

    def policy_failure(
        self,
        policy:    str,
        hostname:  str,
        serial:    str,
        device_id: str | None,
        reason:    str,
    ) -> None:
        """Log a single host failing a policy and the device lookup outcome.

        Args:
            policy:    Name of the failing policy.
            hostname:  Fleet hostname of the failing device.
            serial:    Hardware serial number of the device.
            device_id: Kandji device_id if found in cache, else None.
            reason:    Failure reason if device_id is None, else "".
        """
        self._emit(
            "policy_failure",
            policy=policy,
            hostname=hostname,
            serial=serial,
            kandji_device_id=device_id,
            lookup_failure=reason or None,
        )

    def blankpush_sent(self, hostname: str, device_id: str) -> None:
        """Log a successful blankpush to a Kandji device.

        Args:
            hostname:  Hostname of the device for correlation.
            device_id: Kandji device_id that received the push.
        """
        self._emit(
            "blankpush_sent",
            hostname=hostname,
            kandji_device_id=device_id,
            action="blankpush",
            outcome="success",
        )

    def blankpush_failed(self, hostname: str, device_id: str, error: str) -> None:
        """Log a failed blankpush attempt.

        Args:
            hostname:  Hostname of the device.
            device_id: Kandji device_id that could not be pushed.
            error:     Exception message from the failed API call.
        """
        self._emit(
            "blankpush_failed",
            hostname=hostname,
            kandji_device_id=device_id,
            action="blankpush",
            outcome="failure",
            error=error,
        )

    def run_complete(
        self,
        policies_checked:  int,
        hosts_remediated:  int,
        blankpush_failures: int,
    ) -> None:
        """Log a summary of the completed drift check run.

        Args:
            policies_checked:   Number of policies evaluated this run.
            hosts_remediated:   Number of unique devices that received a blankpush.
            blankpush_failures: Number of blankpush attempts that failed.
        """
        self._emit(
            "drift_check_complete",
            policies_checked=policies_checked,
            hosts_remediated=hosts_remediated,
            blankpush_failures=blankpush_failures,
            outcome="success",
        )

    def run_error(self, error: str) -> None:
        """Log an unhandled exception that aborted the run.

        Args:
            error: Exception message.
        """
        self._emit(
            "drift_check_error",
            outcome="failure",
            error=error,
        )


jlog = JsonLogger()


# ---------------------------------------------------------------------------
# Policy config
# ---------------------------------------------------------------------------

def load_policies(path: str) -> list[str]:
    """Load the list of watched policy names from a YAML file.

    Expected file format::

        policies:
          - CrowdStrike running
          - Disk encryption enabled (macOS)
          - Firewall enabled
          - OS up to date

    Policy names must match exactly what is configured in Fleet (case-sensitive).
    To add or remove a policy, edit the YAML file and commit -- no code change needed.

    Args:
        path: Path to the YAML config file.

    Returns:
        List of policy name strings.

    Exits:
        sys.exit(1) if the file is missing, unparseable, or contains no
        valid policies list. Fail-fast here is intentional -- a misconfigured
        drift check should not silently check nothing.
    """
    try:
        with open(path, "r") as fh:
            config = yaml.safe_load(fh)
    except FileNotFoundError:
        log.error("Policy config file not found: %s", path)
        sys.exit(1)
    except yaml.YAMLError as exc:
        log.error("Failed to parse policy config %s: %s", path, exc)
        sys.exit(1)

    policies = config.get("policies") if isinstance(config, dict) else None
    if not policies or not isinstance(policies, list):
        log.error("Policy config must contain a 'policies' list: %s", path)
        sys.exit(1)

    log.info("Loaded %d policies from %s", len(policies), path)
    return [str(p) for p in policies]


# ---------------------------------------------------------------------------
# Fleet
# ---------------------------------------------------------------------------

def get_all_policies() -> dict[str, dict]:
    """Fetch all global policies from Fleet and index them by name.

    Covers global policies only. If policies are scoped to Fleet teams,
    this function would need to be extended to call the team policies
    endpoint for each team_id.

    Returns:
        Dict mapping policy name -> full policy object from the Fleet API.

    Raises:
        requests.HTTPError: If the Fleet API returns a non-2xx status.
    """
    response = requests.get(
        f"{FLEET_URL}/api/v1/fleet/policies",
        headers=FLEET_HEADERS,
        timeout=FLEET_TIMEOUT,
    )
    response.raise_for_status()

    policies: list[dict] = response.json().get("policies") or []
    return {policy["name"]: policy for policy in policies}


def get_failing_hosts(policy_id: int) -> list[dict]:
    """Fetch all hosts currently failing a given policy from Fleet.

    Paginates through all results using Fleet's page/per_page params so
    this is safe at any fleet size. Uses per_page=100 (Fleet's max) to
    minimise the number of API calls.

    Args:
        policy_id: Numeric ID of the Fleet policy to check.

    Returns:
        List of Fleet host objects for all hosts failing the policy.
        Returns an empty list if no hosts are failing.

    Raises:
        requests.HTTPError: If the Fleet API returns a non-2xx status.
    """
    failing:  list[dict] = []
    page:     int        = 0
    per_page: int        = 100

    while True:
        response = requests.get(
            f"{FLEET_URL}/api/v1/fleet/hosts",
            headers=FLEET_HEADERS,
            params={
                "policy_id":       policy_id,
                "policy_response": "failing",
                "per_page":        per_page,
                "page":            page,
            },
            timeout=FLEET_TIMEOUT,
        )
        response.raise_for_status()

        batch: list[dict] = response.json().get("hosts") or []
        failing.extend(batch)

        # Fleet returns fewer than per_page results on the final page.
        if len(batch) < per_page:
            break
        page += 1

    return failing


# ---------------------------------------------------------------------------
# Kandji
# ---------------------------------------------------------------------------

def build_device_cache() -> dict[str, str]:
    """Fetch all Kandji devices once and index them by serial number.

    Replaces per-host serial lookups with a single paginated fetch at the
    start of each run. At 600 devices this reduces Kandji API calls from
    600 lookups down to 2-3 paginated requests, well within rate limits.

    Pagination uses limit/offset. Kandji returns up to 300 devices per page;
    iteration stops when a page returns fewer than the requested limit.

    Returns:
        Dict mapping uppercase serial number -> Kandji device_id.
        Devices with no serial number are silently skipped.

    Raises:
        requests.HTTPError: If the Kandji API returns a non-2xx status.
    """
    cache:    dict[str, str] = {}
    page:     int            = 1
    per_page: int            = 300

    while True:
        response = requests.get(
            f"{KANDJI_BASE_URL}/devices",
            headers=KANDJI_HEADERS,
            params={"limit": per_page, "offset": (page - 1) * per_page},
            timeout=KANDJI_TIMEOUT,
        )
        response.raise_for_status()

        devices: list[dict] = response.json().get("results") or []

        for device in devices:
            serial = device.get("serial_number", "").upper()
            if serial:
                cache[serial] = device["device_id"]

        if len(devices) < per_page:
            break
        page += 1

    log.info("Built Kandji device cache: %d devices", len(cache))
    return cache


def blankpush(device_id: str) -> None:
    """Send a Kandji blankpush to force an immediate MDM check-in.

    A blankpush sends an Apple Push Notification (APNs) nudge to the device,
    prompting it to check in with Kandji and pull its current blueprint. It
    does not push any payload itself -- it simply wakes the MDM agent.

    Devices that are powered off, lid-closed for extended periods, or on
    restricted networks will not respond until they reconnect.

    Args:
        device_id: Kandji device UUID (from build_device_cache).

    Raises:
        requests.HTTPError: If the Kandji API returns a non-2xx status.
    """
    response = requests.post(
        f"{KANDJI_BASE_URL}/devices/{device_id}/action/blankpush",
        headers=KANDJI_HEADERS,
        timeout=KANDJI_TIMEOUT,
    )
    response.raise_for_status()
    log.info("Blankpush sent to Kandji device %s", device_id)


# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------

def remediate_host(host: dict, device_cache: dict[str, str]) -> dict:
    """Resolve a failing host to a Kandji device_id using the cache.

    Looks up the device_id from the pre-built cache and returns a structured
    result. Does not issue a blankpush -- blankpushes are deduplicated and
    issued separately in run() to ensure each device is pushed at most once
    regardless of how many policies it is failing.

    Failures are caught and recorded rather than re-raised so that a single
    bad host does not abort the batch.

    Args:
        host:         Fleet host object (must include hardware_serial and hostname).
        device_cache: Dict of serial (upper) -> device_id from build_device_cache().

    Returns:
        Dict with keys:
            hostname  (str)       -- hostname of the device.
            serial    (str)       -- hardware serial number (empty string if absent).
            device_id (str|None)  -- Kandji device_id if found, else None.
            success   (bool)      -- True if device_id was resolved, False otherwise.
            reason    (str)       -- Failure reason if success is False, else "".
    """
    hostname = host.get("hostname", "unknown")
    serial   = host.get("hardware_serial", "")

    if not serial:
        log.warning("Host %s has no serial number, skipping", hostname)
        return {"hostname": hostname, "serial": "", "device_id": None, "success": False, "reason": "no serial number"}

    device_id = device_cache.get(serial.upper())
    if not device_id:
        log.warning("Serial %s not found in Kandji cache", serial)
        return {"hostname": hostname, "serial": serial, "device_id": None, "success": False, "reason": "not found in Kandji"}

    return {"hostname": hostname, "serial": serial, "device_id": device_id, "success": True, "reason": ""}


# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------

def build_policy_block(policy_name: str, results: list[dict]) -> dict:
    """Build a single Slack section block summarising one policy's findings.

    Lists up to MAX_HOSTS_IN_SUMMARY hosts per outcome (resolved/unresolved),
    then collapses any remainder into a count line. Blankpushes are issued
    separately and deduplicated across policies -- this block reflects whether
    the device was found in Kandji, not whether a push was sent for this
    specific policy.

    Args:
        policy_name: Display name of the Fleet policy.
        results:     List of remediate_host() result dicts for this policy.

    Returns:
        A Slack Block Kit section block dict.
    """
    lines    = [f"*{policy_name}*"]
    resolved = [r for r in results if r["success"]]
    failed   = [r for r in results if not r["success"]]

    for result in resolved[:MAX_HOSTS_IN_SUMMARY]:
        lines.append(f"  :white_check_mark: `{result['hostname']}` -- blankpush queued")
    if len(resolved) > MAX_HOSTS_IN_SUMMARY:
        lines.append(f"  _...and {len(resolved) - MAX_HOSTS_IN_SUMMARY} more_")

    for result in failed[:MAX_HOSTS_IN_SUMMARY]:
        lines.append(f"  :x: `{result['hostname']}` -- {result['reason']}")
    if len(failed) > MAX_HOSTS_IN_SUMMARY:
        lines.append(f"  _...and {len(failed) - MAX_HOSTS_IN_SUMMARY} more failed_")

    return {
        "type": "section",
        "text": {"type": "mrkdwn", "text": "\n".join(lines)},
    }


def post_drift_summary(policy_results: list[dict]) -> None:
    """Post a single Slack summary covering all drift findings from this run.

    Sends one message per drift-check run rather than one per host to avoid
    alert fatigue on large fleets. Only called when at least one host is out
    of compliance -- clean runs produce no Slack message.

    Args:
        policy_results: List of per-policy result dicts, each with keys:
            policy     (str)       -- policy name.
            results    (list[dict])-- list of remediate_host() result dicts.

    Raises:
        requests.HTTPError: If the Slack API returns a non-2xx status.
        RuntimeError:       If the Slack API returns ok=false in the body.
    """
    total_hosts      = sum(len(pr["results"]) for pr in policy_results)
    total_remediated = sum(
        sum(1 for r in pr["results"] if r["success"]) for pr in policy_results
    )
    total_failed = total_hosts - total_remediated

    policy_blocks = [
        build_policy_block(pr["policy"], pr["results"])
        for pr in policy_results
    ]

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": ":mag: FleetDM Drift Check Results",
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Hosts with drift:*\n{total_hosts}"},
                {"type": "mrkdwn", "text": f"*Blankpushes sent:*\n{total_remediated}"},
                {"type": "mrkdwn", "text": f"*Lookup failures:*\n{total_failed}"},
            ],
        },
        {"type": "divider"},
        *policy_blocks,
    ]

    payload: dict[str, Any] = {
        "channel": SLACK_CHANNEL_ID,
        "text":    f":mag: FleetDM drift check -- {total_hosts} host(s) out of compliance",
        "blocks":  blocks,
    }

    response = requests.post(
        "https://slack.com/api/chat.postMessage",
        headers=SLACK_HEADERS,
        json=payload,
        timeout=SLACK_TIMEOUT,
    )
    response.raise_for_status()

    body = response.json()
    if not body.get("ok"):
        raise RuntimeError(f"Slack API error: {body.get('error')}")

    log.info("Drift summary posted to Slack")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run() -> None:
    """Execute one full drift-check run.

    Runs in two distinct phases to avoid redundant Kandji API calls:

    Phase 1 -- Collect: query Fleet for all failing hosts across every watched
    policy. Build a per-policy result set for the Slack summary.

    Phase 2 -- Remediate: issue one blankpush per unique device_id regardless
    of how many policies that device is failing. A single blankpush causes the
    device to check in and re-enforce all blueprint controls at once, so pushing
    the same device multiple times per run is wasteful and burns Kandji API quota.

    Worst-case Kandji API calls with 600 devices and 32 policies all failing:
        build_device_cache:  ~2 calls  (paginated device list)
        blankpushes:         600 calls (one per unique device)
        total:               ~602 calls (~2 minutes at 300 req/min limit)

    Raises:
        Any unhandled exception propagates to __main__ which logs it and
        exits with code 1 so cron / CI monitoring can detect failures.
    """
    watched_policies = load_policies(POLICY_CONFIG_PATH)
    log.info("Starting drift check -- watching %d policies", len(watched_policies))
    jlog.run_start(policy_count=len(watched_policies))

    # Build the serial -> device_id cache once per run.
    device_cache       = build_device_cache()
    all_fleet_policies = get_all_policies()

    # -------------------------------------------------------------------------
    # Phase 1: collect failing hosts per policy
    # -------------------------------------------------------------------------
    policy_results: list[dict] = []

    for policy_name in watched_policies:
        fleet_policy = all_fleet_policies.get(policy_name)
        if not fleet_policy:
            log.warning("Policy not found in Fleet: %s", policy_name)
            continue

        failing_hosts = get_failing_hosts(fleet_policy["id"])
        if not failing_hosts:
            log.info("Policy OK: %s", policy_name)
            jlog.policy_ok(policy=policy_name)
            continue

        log.info("Policy '%s' -- %d failing host(s)", policy_name, len(failing_hosts))

        results = [remediate_host(host, device_cache) for host in failing_hosts]

        for result in results:
            jlog.policy_failure(
                policy=policy_name,
                hostname=result["hostname"],
                serial=result.get("serial", ""),
                device_id=result.get("device_id"),
                reason=result.get("reason", ""),
            )

        policy_results.append({"policy": policy_name, "results": results})

    if not policy_results:
        log.info("Drift check complete -- all policies passing, no Slack message sent")
        jlog.run_complete(
            policies_checked=len(watched_policies),
            hosts_remediated=0,
            blankpush_failures=0,
        )
        return

    # -------------------------------------------------------------------------
    # Phase 2: deduplicated blankpush -- one push per unique device
    # -------------------------------------------------------------------------
    pushed:       set[str]  = set()
    failed:       list[str] = []
    hostname_map: dict[str, str] = {
        result["device_id"]: result["hostname"]
        for pr in policy_results
        for result in pr["results"]
        if result.get("device_id")
    }

    for pr in policy_results:
        for result in pr["results"]:
            device_id = result.get("device_id")
            if not device_id or device_id in pushed:
                continue
            hostname = result["hostname"]
            try:
                blankpush(device_id)
                pushed.add(device_id)
                jlog.blankpush_sent(hostname=hostname, device_id=device_id)
            except Exception as exc:
                log.error("Blankpush failed for %s (%s): %s", hostname, device_id, exc)
                failed.append(hostname)
                jlog.blankpush_failed(hostname=hostname, device_id=device_id, error=str(exc))

    log.info(
        "Drift check complete -- %d unique device(s) pushed, %d blankpush failure(s)",
        len(pushed), len(failed),
    )
    jlog.run_complete(
        policies_checked=len(watched_policies),
        hosts_remediated=len(pushed),
        blankpush_failures=len(failed),
    )

    post_drift_summary(policy_results)


if __name__ == "__main__":
    try:
        run()
    except Exception as exc:
        log.exception("Drift check failed: %s", exc)
        jlog.run_error(error=str(exc))
        sys.exit(1)
