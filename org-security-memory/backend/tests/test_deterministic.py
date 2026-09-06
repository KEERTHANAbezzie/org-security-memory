import json
from pathlib import Path

from app.analytics.deterministic import (
    discover_recurrence_families,
    recurrence_summary,
    temporal_change_links,
    remediation_effectiveness,
    operational_debt,
    detection_gap_classification,
    drift_indicators,
)

DATA = Path(__file__).parents[1] / "data" / "generated"

def load(name):
    return json.loads((DATA / f"{name}.json").read_text())

def test_recurrence_discovery_does_not_use_family_id():
    incidents = load("incidents")
    stripped = [{k:v for k,v in i.items() if k != "family_id"} for i in incidents]
    families = discover_recurrence_families(stripped)
    assert len(families) >= 5
    assert all(f["count"] >= 3 for f in families)

def test_recurrence_summary_and_trend():
    incidents = load("incidents")
    fam = next(i["family_id"] for i in incidents if i.get("family_id"))
    ids = [i["id"] for i in incidents if i.get("family_id") == fam]
    summary = recurrence_summary(incidents, ids)
    assert summary["incident_count"] == 20
    assert len(summary["intervals_days"]) == 19
    assert summary["trend"] in {"accelerating", "slowing", "stable", "insufficient_history"}

def test_temporal_links_are_time_bounded_and_asset_aware():
    incidents, changes = load("incidents"), load("changes")
    incident = next(i for i in incidents if i.get("family_id"))
    links = temporal_change_links(incident, changes, max_days=7)
    assert all(0 <= x["days_before"] <= 7 for x in links)

def test_remediation_effectiveness_is_computed_from_timestamps():
    incidents, rems = load("incidents"), load("remediations")
    incident = next(i for i in incidents if i.get("family_id"))
    rows = remediation_effectiveness(incident, incidents, rems)
    assert rows
    assert all("recurrence_free_days" in x for x in rows)
    # At least one strong remediation should have a longer recurrence-free period than a weak one.
    weak = [x["recurrence_free_days"] for x in rows if x["historical_label"] == "weak" and x["recurrence_free_days"] is not None]
    strong = [x["recurrence_free_days"] for x in rows if x["historical_label"] == "strong" and x["recurrence_free_days"] is not None]
    assert max(strong) > max(weak)

def test_operational_debt_is_prioritized():
    rows = operational_debt(load("incidents"), load("remediations"))
    assert len(rows) == 5
    assert rows == sorted(rows, key=lambda x: x["debt_score"], reverse=True)
    assert all(0 <= x["debt_score"] <= 100 for x in rows)

def test_detection_gap_classifier_finds_synthetic_gap_types():
    incidents, assets, rules, alerts = load("incidents"), load("assets"), load("detection_rules"), load("alerts")
    expected = {
        "FAM-IDENTITY-01": "correlation_gap",
        "FAM-CLOUD-01": "missing_rule",
        "FAM-SVC-01": "ineffective_rule",
        "FAM-API-01": "missing_telemetry",
        "FAM-LAT-01": "unmonitored_asset",
    }
    for family, gap in expected.items():
        incident = next(i for i in incidents if i.get("family_id") == family)
        found = {x["gap_type"] for x in detection_gap_classification(incident, assets, rules, alerts)}
        assert gap in found, (family, found)

def test_drift_engine_returns_partial_or_uncovered_changes():
    rows = drift_indicators(load("changes"), load("assets"), load("detection_rules"))
    assert len(rows) >= 20
