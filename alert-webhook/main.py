"""Alert Webhook — Container App replacement for Azure Function.

Receives Azure Monitor alert webhooks and creates Devin API sessions
to automatically investigate production incidents. Deployed as an
Azure Container App for zero-cost operation at demo scale.
"""

import json
import logging
import os
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI(title="EventFlow Alert Webhook", version="1.0.0")

# Allow storefront origins to call the proxy endpoint
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https://ef-store-(team\d+|main)\..*\.azurecontainerapps\.io",
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["*"],
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DEVIN_API_BASE = os.environ.get("DEVIN_API_BASE", "https://api.devin.ai")
DEVIN_API_KEY = os.environ.get("DEVIN_API_KEY", "")
DEVIN_ORG_ID = os.environ.get("DEVIN_ORG_ID", "")
GITHUB_ORG = "Cognition-Partner-Workshops"


def _devin_sessions_url() -> str:
    """Build the Devin API sessions URL (v3 with org ID)."""
    return f"{DEVIN_API_BASE}/v3/organizations/{DEVIN_ORG_ID}/sessions"

REPOS = [
    "app_eventflow-order-service",
    "app_eventflow-payment-service",
    "app_eventflow-infra",
    "app_eventflow-storefront",
]


def extract_team_id(payload: dict) -> str:
    """Extract team ID from Azure Monitor Common Alert Schema payload."""
    data = payload.get("data", {})
    alert_context = data.get("alertContext", {})
    conditions = alert_context.get("conditions", [])

    for condition in conditions:
        dimensions = condition.get("dimensions", [])
        for dim in dimensions:
            if dim.get("name") == "cloud_RoleName":
                role_name = dim.get("value", "")
                if "team" in role_name:
                    parts = role_name.split("team")
                    if len(parts) > 1:
                        return f"team{parts[-1]}"
    return ""


def classify_alert(alert_payload: dict) -> str:
    """Classify an Azure Monitor alert into a handler category.

    Inspects the alert rule name and metric conditions to determine
    whether this is a high-latency alert, a 5xx error spike, or a
    generic incident.

    Returns:
        One of: ``"high_latency"``, ``"error_spike"``, or ``"generic"``.
    """
    data = alert_payload.get("data", {})
    essentials = data.get("essentials", {})
    alert_rule = essentials.get("alertRule", "").lower()
    description = essentials.get("description", "").lower()

    alert_context = data.get("alertContext", {})
    conditions = alert_context.get("conditions", [])
    metric_names = [
        c.get("metricName", "").lower() for c in conditions
    ]

    latency_keywords = ["latency", "slow", "duration", "response time", "p95", "p99"]
    if any(kw in alert_rule for kw in latency_keywords) or any(
        kw in description for kw in latency_keywords
    ) or any("duration" in m or "latency" in m or "responsetime" in m for m in metric_names):
        return "high_latency"

    error_keywords = ["500", "5xx", "error", "exception", "failure", "http5xx"]
    if any(kw in alert_rule for kw in error_keywords) or any(
        kw in m for m in metric_names for kw in error_keywords
    ):
        return "error_spike"

    return "generic"


def build_prompt(team_id: str, alert_payload: dict) -> str:
    """Build the Devin investigation prompt.

    Describes operational symptoms only — does NOT reveal the root cause.
    Devin must investigate the code and services to figure out what's wrong.
    """
    data = alert_payload.get("data", {})
    essentials = data.get("essentials", {})

    fired_at = essentials.get("firedDateTime", datetime.now(timezone.utc).isoformat())

    repos_list = "\n".join(
        f"  - https://github.com/{GITHUB_ORG}/{repo}" for repo in REPOS
    )

    branch = team_id if team_id else "main"
    order_url = f"https://ef-order-{team_id}.salmonbush-13ada168.eastus.azurecontainerapps.io" if team_id else "https://ef-order-team1.salmonbush-13ada168.eastus.azurecontainerapps.io"
    payment_url = order_url.replace("ef-order-", "ef-payment-")

    return f"""## Production Incident

**Team**: {team_id}
**Time detected**: {fired_at}

### Impacted Services

- **Order Service**: {order_url}
- **Payment Service**: {payment_url}

Some customer orders are failing. We received reports of orders not completing successfully.

### Production Logs

Query the production logs to understand what is happening. Azure CLI credentials are already configured as environment variables (`AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`).

```bash
az login --service-principal -u $AZURE_CLIENT_ID -p $AZURE_CLIENT_SECRET --tenant $AZURE_TENANT_ID -o none

az monitor log-analytics query \\
  --workspace "4cf2afba-136e-4018-9f2d-42b3dbafc3a8" \\
  --analytics-query "ContainerAppConsoleLogs_CL | where TimeGenerated > ago(2h) | where Log_s !contains 'GET /health' | order by TimeGenerated desc | take 50 | project TimeGenerated, ContainerAppName_s, Log_s" \\
  -o table
```

Start by querying the logs. They are the source of truth for what is happening at runtime.

### Repositories

{repos_list}

All repos use the `{branch}` branch for this team's deployment.

### Your Task

1. **Query logs** — Pull production logs and determine what is going wrong.
2. **Investigate** — Examine the source code to understand the root cause of the failures.
3. **Fix** — Open a Pull Request on the appropriate repository against the `{branch}` branch with the fix.
4. **Verify** — Make sure the fix passes CI.

Open your fix PR against the `{branch}` branch, not `main`.
"""


def build_high_latency_prompt(team_id: str, alert_payload: dict) -> str:
    """Build a Devin investigation prompt for high-latency alerts.

    Focuses the investigation on database query performance, connection
    pool exhaustion, and resource contention — the most common causes
    of latency spikes in the EventFlow payment stack.
    """
    data = alert_payload.get("data", {})
    essentials = data.get("essentials", {})

    fired_at = essentials.get("firedDateTime", datetime.now(timezone.utc).isoformat())
    severity = essentials.get("severity", "Sev2")
    alert_rule = essentials.get("alertRule", "High Latency")
    description = essentials.get("description", "")

    repos_list = "\n".join(
        f"  - https://github.com/{GITHUB_ORG}/{repo}" for repo in REPOS
    )

    branch = team_id if team_id else "main"
    order_url = (
        f"https://ef-order-{team_id}.salmonbush-13ada168.eastus.azurecontainerapps.io"
        if team_id
        else "https://ef-order-team1.salmonbush-13ada168.eastus.azurecontainerapps.io"
    )
    payment_url = order_url.replace("ef-order-", "ef-payment-")

    return f"""## Production Incident — High Latency

**Alert Rule**: {alert_rule}
**Severity**: {severity}
**Team**: {team_id}
**Time detected**: {fired_at}
**Description**: {description}

### Impacted Services

- **Order Service**: {order_url}
- **Payment Service**: {payment_url}

The payment service is experiencing abnormally high response times. End-user
requests are timing out or taking significantly longer than normal.

### Production Logs

Query the production logs to understand what is happening. Azure CLI credentials
are already configured as environment variables (`AZURE_CLIENT_ID`,
`AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`).

```bash
az login --service-principal -u $AZURE_CLIENT_ID -p $AZURE_CLIENT_SECRET --tenant $AZURE_TENANT_ID -o none

# Slow requests — look for high-duration entries
az monitor log-analytics query \\
  --workspace "4cf2afba-136e-4018-9f2d-42b3dbafc3a8" \\
  --analytics-query "ContainerAppConsoleLogs_CL | where TimeGenerated > ago(2h) | where Log_s has_any ('slow', 'timeout', 'latency', 'pool', 'connection', 'duration') | order by TimeGenerated desc | take 50 | project TimeGenerated, ContainerAppName_s, Log_s" \\
  -o table
```

Start by querying the logs. They are the source of truth for what is happening
at runtime.

### Repositories

{repos_list}

All repos use the `{branch}` branch for this team's deployment.

### Investigation Focus — Database & Connection Pool

High latency in the payment service is most commonly caused by:

1. **Slow database queries** — Look for N+1 query patterns, missing indexes,
   full table scans, or unoptimised JOINs. Check ORM-generated SQL in the logs.
2. **Connection pool exhaustion** — Check pool size configuration, connection
   leak patterns (connections not returned), and pool wait-time metrics. Look
   for "pool exhausted", "connection timeout", or "waiting for connection" in
   logs.
3. **Lock contention** — Look for database deadlocks, long-held row/table
   locks, or serialisation bottlenecks in transaction-heavy code paths.
4. **Missing or stale caches** — Check whether frequently-accessed data is
   cached and whether cache hit rates have dropped.
5. **External service timeouts** — Verify timeouts and circuit breakers for
   downstream calls (e.g. payment gateway, order service).

### Your Task

1. **Query logs** — Pull production logs focusing on slow queries, connection
   pool warnings, and timeout errors.
2. **Profile database access** — Identify the slowest queries and any
   connection pool saturation.
3. **Investigate** — Examine the source code for inefficient data access
   patterns, missing indexes, or pool misconfiguration.
4. **Fix** — Open a Pull Request on the appropriate repository against the
   `{branch}` branch with the fix.
5. **Verify** — Make sure the fix passes CI.

Open your fix PR against the `{branch}` branch, not `main`.
"""


def route_alert_to_prompt(team_id: str, alert_payload: dict) -> str:
    """Select the appropriate prompt builder based on alert classification.

    Returns the generated investigation prompt string.
    """
    alert_type = classify_alert(alert_payload)
    if alert_type == "high_latency":
        return build_high_latency_prompt(team_id, alert_payload)
    return build_prompt(team_id, alert_payload)


@app.get("/health")
async def health():
    """Health check endpoint for Container App probes."""
    return {"status": "healthy", "service": "eventflow-alert-webhook"}


@app.post("/alert-webhook")
async def alert_webhook(request: Request):
    """Receive Azure Monitor alert webhook and create Devin session."""
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    team_id = extract_team_id(payload)
    logger.info("Alert received for team: %s", team_id or "unknown")

    if not DEVIN_API_KEY:
        logger.error("DEVIN_API_KEY not configured")
        return JSONResponse(
            {"error": "DEVIN_API_KEY not configured", "team_id": team_id},
            status_code=500,
        )

    prompt = route_alert_to_prompt(team_id, payload)

    # Call Devin API (v3)
    try:
        url = _devin_sessions_url()
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                url,
                headers={
                    "Authorization": f"Bearer {DEVIN_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={"prompt": prompt},
            )
            response.raise_for_status()
            result = response.json()

        logger.info("Devin session created: %s", result.get("session_id", "unknown"))
        return JSONResponse({
            "status": "investigation_started",
            "team_id": team_id,
            "devin_session_id": result.get("session_id"),
            "devin_url": result.get("url"),
        })

    except httpx.HTTPStatusError as e:
        logger.error("Devin API error: %s %s", e.response.status_code, e.response.text)
        return JSONResponse(
            {"error": f"Devin API returned {e.response.status_code}", "team_id": team_id},
            status_code=502,
        )
    except Exception as e:
        logger.exception("Failed to create Devin session")
        return JSONResponse(
            {"error": str(e), "team_id": team_id},
            status_code=500,
        )


class InvestigateRequest(BaseModel):
    """Request body for the ops dashboard proxy endpoint."""
    team_id: str
    prompt: str


@app.post("/investigate")
async def investigate_proxy(body: InvestigateRequest):
    """Proxy endpoint for the ops dashboard — accepts a prompt from the
    storefront UI and forwards it to the Devin API server-side,
    avoiding browser CORS restrictions."""

    if not DEVIN_API_KEY:
        return JSONResponse(
            {"error": "DEVIN_API_KEY not configured", "team_id": body.team_id},
            status_code=500,
        )

    try:
        url = _devin_sessions_url()
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                url,
                headers={
                    "Authorization": f"Bearer {DEVIN_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={"prompt": body.prompt},
            )
            response.raise_for_status()
            result = response.json()

        logger.info("Devin session created via proxy for %s: %s", body.team_id, result.get("session_id", "unknown"))
        return JSONResponse({
            "status": "investigation_started",
            "team_id": body.team_id,
            "devin_session_id": result.get("session_id"),
            "devin_url": result.get("url"),
        })

    except httpx.HTTPStatusError as e:
        logger.error("Devin API error (proxy): %s %s", e.response.status_code, e.response.text)
        return JSONResponse(
            {"error": f"Devin API returned {e.response.status_code}", "detail": e.response.text, "team_id": body.team_id},
            status_code=502,
        )
    except Exception as e:
        logger.exception("Failed to create Devin session (proxy)")
        return JSONResponse(
            {"error": str(e), "team_id": body.team_id},
            status_code=500,
        )


@app.post("/trigger/{team_id}")
async def manual_trigger(team_id: str):
    """Manual trigger endpoint — creates a Devin session for a specific team
    without requiring an Azure Monitor alert payload. Useful for testing."""

    if not DEVIN_API_KEY:
        return JSONResponse(
            {"error": "DEVIN_API_KEY not configured", "team_id": team_id},
            status_code=500,
        )

    mock_payload = {
        "data": {
            "essentials": {
                "alertRule": "Payment Processing Failure",
                "severity": "Sev1",
                "description": f"Payment service errors detected for {team_id}",
                "firedDateTime": datetime.now(timezone.utc).isoformat(),
            },
            "alertContext": {
                "conditions": [{
                    "dimensions": [{
                        "name": "cloud_RoleName",
                        "value": f"ef-payment-{team_id}",
                    }]
                }]
            },
        }
    }

    prompt = build_prompt(team_id, mock_payload)

    try:
        url = _devin_sessions_url()
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                url,
                headers={
                    "Authorization": f"Bearer {DEVIN_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={"prompt": prompt},
            )
            response.raise_for_status()
            result = response.json()

        return JSONResponse({
            "status": "investigation_started",
            "team_id": team_id,
            "devin_session_id": result.get("session_id"),
            "devin_url": result.get("url"),
        })

    except Exception as e:
        logger.exception("Failed to create Devin session")
        return JSONResponse(
            {"error": str(e), "team_id": team_id},
            status_code=500,
        )
