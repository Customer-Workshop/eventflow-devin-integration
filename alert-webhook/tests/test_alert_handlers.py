"""Tests for alert classification, prompt generation, and the webhook endpoint."""

import pytest
from fastapi.testclient import TestClient

from main import (
    app,
    build_high_latency_prompt,
    build_prompt,
    classify_alert,
    extract_team_id,
    route_alert_to_prompt,
)


# ---------------------------------------------------------------------------
# Helpers — reusable alert payload factories
# ---------------------------------------------------------------------------

def _make_alert(
    *,
    alert_rule: str = "Some Alert",
    severity: str = "Sev1",
    description: str = "",
    fired_at: str = "2026-07-02T13:00:00Z",
    role_name: str = "ef-payment-team3",
    metric_name: str = "",
) -> dict:
    """Build a minimal Azure Monitor Common Alert Schema payload."""
    condition: dict = {
        "dimensions": [{"name": "cloud_RoleName", "value": role_name}],
    }
    if metric_name:
        condition["metricName"] = metric_name
    return {
        "schemaId": "azureMonitorCommonAlertSchema",
        "data": {
            "essentials": {
                "alertId": "/subscriptions/xxx/alerts/test-id",
                "alertRule": alert_rule,
                "severity": severity,
                "description": description,
                "firedDateTime": fired_at,
            },
            "alertContext": {
                "conditionType": "SingleResourceMultipleMetricCriteria",
                "conditions": [condition],
            },
        },
    }


# ---------------------------------------------------------------------------
# extract_team_id
# ---------------------------------------------------------------------------

class TestExtractTeamId:
    def test_extracts_team_from_role_name(self):
        payload = _make_alert(role_name="ef-payment-team5")
        assert extract_team_id(payload) == "team5"

    def test_returns_empty_when_no_team(self):
        payload = _make_alert(role_name="ef-payment-main")
        assert extract_team_id(payload) == ""

    def test_returns_empty_for_missing_dimensions(self):
        payload = {"data": {"alertContext": {"conditions": []}}}
        assert extract_team_id(payload) == ""

    def test_returns_empty_for_empty_payload(self):
        assert extract_team_id({}) == ""


# ---------------------------------------------------------------------------
# classify_alert
# ---------------------------------------------------------------------------

class TestClassifyAlert:
    # --- high_latency ---
    @pytest.mark.parametrize("rule", [
        "High Latency - Payment Service",
        "P95 Response Time Exceeded",
        "Slow Request Duration Alert",
        "Payment Service p99 Degradation",
        "Response Time Spike Detected",
    ])
    def test_high_latency_by_rule_name(self, rule: str):
        payload = _make_alert(alert_rule=rule)
        assert classify_alert(payload) == "high_latency"

    def test_high_latency_by_description(self):
        payload = _make_alert(
            alert_rule="Custom Metric Alert",
            description="Payment service latency exceeded 2s threshold",
        )
        assert classify_alert(payload) == "high_latency"

    @pytest.mark.parametrize("metric", [
        "AverageDuration",
        "requestLatency",
        "ResponseTime",
    ])
    def test_high_latency_by_metric_name(self, metric: str):
        payload = _make_alert(
            alert_rule="Metric Alert",
            metric_name=metric,
        )
        assert classify_alert(payload) == "high_latency"

    # --- error_spike ---
    @pytest.mark.parametrize("rule", [
        "500 Internal Server Error Spike",
        "5xx Error Rate Exceeded",
        "Payment Processing Error Alert",
        "Exception Rate High",
        "Payment Failure Rate",
    ])
    def test_error_spike_by_rule_name(self, rule: str):
        payload = _make_alert(alert_rule=rule)
        assert classify_alert(payload) == "error_spike"

    def test_error_spike_by_metric_name(self):
        payload = _make_alert(
            alert_rule="Metric Alert",
            metric_name="Http5xx",
        )
        assert classify_alert(payload) == "error_spike"

    # --- generic ---
    def test_generic_for_unrecognised_alert(self):
        payload = _make_alert(alert_rule="CPU Usage Alert")
        assert classify_alert(payload) == "generic"

    def test_generic_for_empty_payload(self):
        assert classify_alert({}) == "generic"

    # --- latency takes priority over error keywords ---
    def test_latency_wins_over_error_when_both_present(self):
        payload = _make_alert(alert_rule="High Latency Error on Payment")
        assert classify_alert(payload) == "high_latency"


# ---------------------------------------------------------------------------
# build_prompt  (existing error-spike / generic prompt)
# ---------------------------------------------------------------------------

class TestBuildPrompt:
    def test_contains_team_and_services(self):
        payload = _make_alert(fired_at="2026-07-02T13:00:00Z")
        prompt = build_prompt("team3", payload)
        assert "**Team**: team3" in prompt
        assert "ef-order-team3" in prompt
        assert "ef-payment-team3" in prompt

    def test_contains_repos(self):
        prompt = build_prompt("team1", _make_alert())
        assert "app_eventflow-payment-service" in prompt
        assert "app_eventflow-order-service" in prompt

    def test_branch_defaults_to_main(self):
        prompt = build_prompt("", _make_alert())
        assert "`main` branch" in prompt

    def test_contains_log_query(self):
        prompt = build_prompt("team1", _make_alert())
        assert "az monitor log-analytics query" in prompt

    def test_uses_fired_datetime(self):
        payload = _make_alert(fired_at="2025-01-15T08:30:00Z")
        prompt = build_prompt("team1", payload)
        assert "2025-01-15T08:30:00Z" in prompt


# ---------------------------------------------------------------------------
# build_high_latency_prompt
# ---------------------------------------------------------------------------

class TestBuildHighLatencyPrompt:
    def test_header_identifies_high_latency(self):
        payload = _make_alert(alert_rule="High Latency - Payment Service")
        prompt = build_high_latency_prompt("team2", payload)
        assert "High Latency" in prompt

    def test_contains_alert_rule_and_severity(self):
        payload = _make_alert(
            alert_rule="P95 Response Time",
            severity="Sev2",
        )
        prompt = build_high_latency_prompt("team2", payload)
        assert "P95 Response Time" in prompt
        assert "Sev2" in prompt

    def test_contains_team_services(self):
        payload = _make_alert()
        prompt = build_high_latency_prompt("team4", payload)
        assert "ef-order-team4" in prompt
        assert "ef-payment-team4" in prompt

    def test_contains_db_investigation_guidance(self):
        payload = _make_alert()
        prompt = build_high_latency_prompt("team1", payload)
        assert "database" in prompt.lower() or "Database" in prompt
        assert "connection pool" in prompt.lower() or "Connection Pool" in prompt
        assert "N+1" in prompt
        assert "Lock contention" in prompt

    def test_contains_slow_query_log_filter(self):
        payload = _make_alert()
        prompt = build_high_latency_prompt("team1", payload)
        assert "slow" in prompt.lower()
        assert "timeout" in prompt.lower()
        assert "pool" in prompt.lower()

    def test_contains_repos(self):
        payload = _make_alert()
        prompt = build_high_latency_prompt("team1", payload)
        assert "app_eventflow-payment-service" in prompt

    def test_branch_defaults_to_main_when_no_team(self):
        payload = _make_alert()
        prompt = build_high_latency_prompt("", payload)
        assert "`main` branch" in prompt

    def test_uses_fired_datetime(self):
        payload = _make_alert(fired_at="2026-06-15T10:00:00Z")
        prompt = build_high_latency_prompt("team1", payload)
        assert "2026-06-15T10:00:00Z" in prompt

    def test_includes_description(self):
        payload = _make_alert(description="P95 > 5s for payment endpoint")
        prompt = build_high_latency_prompt("team1", payload)
        assert "P95 > 5s for payment endpoint" in prompt


# ---------------------------------------------------------------------------
# route_alert_to_prompt
# ---------------------------------------------------------------------------

class TestRouteAlertToPrompt:
    def test_routes_latency_to_high_latency_prompt(self):
        payload = _make_alert(alert_rule="High Latency Alert")
        prompt = route_alert_to_prompt("team1", payload)
        assert "High Latency" in prompt
        assert "connection pool" in prompt.lower() or "Connection Pool" in prompt

    def test_routes_error_spike_to_generic_prompt(self):
        payload = _make_alert(alert_rule="500 Internal Server Error Spike")
        prompt = route_alert_to_prompt("team1", payload)
        assert "Some customer orders are failing" in prompt

    def test_routes_generic_to_generic_prompt(self):
        payload = _make_alert(alert_rule="CPU Spike")
        prompt = route_alert_to_prompt("team1", payload)
        assert "Some customer orders are failing" in prompt


# ---------------------------------------------------------------------------
# Webhook endpoint integration tests
# ---------------------------------------------------------------------------

@pytest.fixture()
def client():
    return TestClient(app)


class TestAlertWebhookEndpoint:
    def test_health_check(self, client: TestClient):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

    def test_invalid_json_returns_400(self, client: TestClient):
        resp = client.post(
            "/alert-webhook",
            content=b"not json",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 400

    def test_missing_api_key_returns_500(self, client: TestClient):
        payload = _make_alert(alert_rule="500 Internal Server Error Spike")
        resp = client.post("/alert-webhook", json=payload)
        assert resp.status_code == 500
        body = resp.json()
        assert "DEVIN_API_KEY" in body["error"]
        assert body["team_id"] == "team3"

    def test_missing_api_key_returns_team_id_for_latency_alert(
        self, client: TestClient
    ):
        payload = _make_alert(
            alert_rule="High Latency - Payment Service",
            role_name="ef-payment-team7",
        )
        resp = client.post("/alert-webhook", json=payload)
        assert resp.status_code == 500
        assert resp.json()["team_id"] == "team7"
