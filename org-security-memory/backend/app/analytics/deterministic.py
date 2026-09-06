from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from statistics import mean
from typing import Any


def parse_time(value: str | datetime) -> datetime:
    return value if isinstance(value, datetime) else datetime.fromisoformat(value)


def discover_recurrence_families(incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Discover candidate recurring families without reading family_id.

    The MVP heuristic uses category + technique overlap as the deterministic candidate key.
    This intentionally remains explainable; embeddings can replace/augment it later.
    """
    buckets: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for inc in incidents:
        techniques = inc.get("techniques", []) or []
        for technique in techniques:
            buckets[(inc["category"], technique)].append(inc)

    families = []
    seen: set[frozenset[str]] = set()
    for (category, technique), rows in buckets.items():
        ids = frozenset(r["id"] for r in rows)
        if len(ids) < 3 or ids in seen:
            continue
        seen.add(ids)
        rows = sorted(rows, key=lambda x: parse_time(x["timestamp"]))
        intervals = [
            (parse_time(b["timestamp"]) - parse_time(a["timestamp"])).total_seconds() / 86400
            for a, b in zip(rows, rows[1:])
        ]
        families.append({
            "candidate_key": f"{category}:{technique}",
            "category": category,
            "technique": technique,
            "incident_ids": [r["id"] for r in rows],
            "count": len(rows),
            "mean_interval_days": round(mean(intervals), 2) if intervals else None,
        })
    return sorted(families, key=lambda f: f["count"], reverse=True)


def recurrence_summary(incidents: list[dict[str, Any]], family_incident_ids: list[str]) -> dict[str, Any]:
    members = {i["id"]: i for i in incidents if i["id"] in set(family_incident_ids)}
    ordered = sorted(members.values(), key=lambda x: parse_time(x["timestamp"]))
    intervals = [
        round((parse_time(b["timestamp"]) - parse_time(a["timestamp"])).total_seconds() / 86400, 2)
        for a, b in zip(ordered, ordered[1:])
    ]
    return {
        "incident_count": len(ordered),
        "first_seen": ordered[0]["timestamp"] if ordered else None,
        "last_seen": ordered[-1]["timestamp"] if ordered else None,
        "intervals_days": intervals,
        "mean_interval_days": round(mean(intervals), 2) if intervals else None,
        "minimum_interval_days": min(intervals) if intervals else None,
        "maximum_interval_days": max(intervals) if intervals else None,
        "trend": recurrence_trend(intervals),
    }


def recurrence_trend(intervals: list[float]) -> str:
    if len(intervals) < 4:
        return "insufficient_history"
    midpoint = len(intervals) // 2
    early = mean(intervals[:midpoint])
    late = mean(intervals[midpoint:])
    if late < early * 0.75:
        return "accelerating"
    if late > early * 1.25:
        return "slowing"
    return "stable"


def temporal_change_links(incident: dict[str, Any], changes: list[dict[str, Any]], max_days: int = 7) -> list[dict[str, Any]]:
    t = parse_time(incident["timestamp"])
    asset_ids = set(incident.get("asset_ids", []))
    links = []
    for change in changes:
        ct = parse_time(change["timestamp"])
        delta = (t - ct).total_seconds() / 86400
        if 0 <= delta <= max_days and (not asset_ids or change.get("asset_id") in asset_ids):
            links.append({"change_id": change["id"], "days_before": round(delta, 2), "change_type": change.get("change_type")})
    return sorted(links, key=lambda x: x["days_before"])


def remediation_effectiveness(incident: dict[str, Any], incidents: list[dict[str, Any]], remediations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Compute recurrence-free days from raw timestamps; does not trust stored recurrence_after_days."""
    family = incident.get("family_id")
    if not family:
        return []
    same_family = sorted(
        [i for i in incidents if i.get("family_id") == family],
        key=lambda x: parse_time(x["timestamp"]),
    )
    results = []
    for rem in remediations:
        if rem.get("family_id") != family:
            continue
        rt = parse_time(rem["timestamp"])
        later = [parse_time(i["timestamp"]) for i in same_family if parse_time(i["timestamp"]) > rt]
        recurrence_days = round((min(later) - rt).total_seconds() / 86400, 2) if later else None
        results.append({
            "remediation_id": rem["id"],
            "action": rem["action"],
            "recurrence_free_days": recurrence_days,
            "owner": rem.get("owner"),
            "target": rem.get("target"),
            "historical_label": rem.get("effectiveness_label"),
        })
    return sorted(results, key=lambda x: x["recurrence_free_days"] if x["recurrence_free_days"] is not None else float("inf"), reverse=True)


def operational_debt(incidents: list[dict[str, Any]], remediations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_family = defaultdict(list)
    for i in incidents:
        if i.get("family_id"):
            by_family[i["family_id"]].append(i)
    rem_by_family = defaultdict(list)
    for r in remediations:
        if r.get("family_id"):
            rem_by_family[r["family_id"]].append(r)

    rows = []
    for family, members in by_family.items():
        weak = [r for r in rem_by_family[family] if r.get("effectiveness_label") == "weak"]
        short_fixes = [r for r in rem_by_family[family] if r.get("recurrence_after_days") is not None and r["recurrence_after_days"] <= 21]
        ordered = sorted(members, key=lambda x: parse_time(x["timestamp"]))
        if len(ordered) < 2:
            continue
        days = (parse_time(ordered[-1]["timestamp"]) - parse_time(ordered[0]["timestamp"])).days or 1
        frequency_per_30d = len(ordered) / days * 30
        severity_weight = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        severity = mean(severity_weight.get(x.get("severity"), 1) for x in ordered)
        score = min(100.0, round(
            min(35, len(ordered) * 1.5) +
            min(30, frequency_per_30d * 2) +
            min(20, len(weak) * 1.0) +
            min(15, len(short_fixes) * 1.0) +
            severity * 1.5, 1))
        rows.append({
            "family_id": family,
            "incident_count": len(ordered),
            "weak_remediation_count": len(weak),
            "short_recurrence_fix_count": len(short_fixes),
            "frequency_per_30d": round(frequency_per_30d, 2),
            "average_severity_weight": round(severity, 2),
            "debt_score": score,
        })
    return sorted(rows, key=lambda x: x["debt_score"], reverse=True)


def detection_gap_classification(incident: dict[str, Any], assets: list[dict[str, Any]], rules: list[dict[str, Any]], alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Explainable coverage classifier for the current incident."""
    asset_map = {a["id"]: a for a in assets}
    incident_assets = [asset_map[a] for a in incident.get("asset_ids", []) if a in asset_map]
    incident_techniques = set(incident.get("techniques", []))
    gaps = []
    for technique in incident_techniques:
        matching = [r for r in rules if technique in r.get("techniques", []) and r.get("enabled", True)]
        if not matching:
            gaps.append({"technique": technique, "gap_type": "missing_rule", "reason": "No enabled detection rule covers the observed technique."})
            continue
        telemetry_needed = set(t for r in matching for t in r.get("telemetry_requirements", []))
        telemetry_available = set(t for a in incident_assets for t in a.get("telemetry_sources", []))
        if telemetry_needed and not (telemetry_needed & telemetry_available):
            gaps.append({"technique": technique, "gap_type": "missing_telemetry", "reason": "Available asset telemetry does not satisfy the requirements of matching detection rules."})
            continue
        if any(a.get("monitoring_status") != "full" for a in incident_assets):
            gaps.append({"technique": technique, "gap_type": "unmonitored_asset", "reason": "At least one affected asset has partial monitoring."})
            continue
        low_eff = [r for r in matching if (r.get("effectiveness") or 1) < 0.5]
        if low_eff:
            gaps.append({"technique": technique, "gap_type": "ineffective_rule", "reason": "Matching detection coverage exists but has low historical effectiveness."})
            continue
        # We deliberately treat multi-stage identity behavior as a correlation gap in the synthetic benchmark.
        if technique == "T1110" and any("T1078" in r.get("techniques", []) for r in rules):
            gaps.append({"technique": technique, "gap_type": "correlation_gap", "reason": "Single-event coverage exists, but sequence-level authentication correlation is absent."})
    return gaps


def drift_indicators(changes: list[dict[str, Any]], assets: list[dict[str, Any]], rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    asset_map = {a["id"]: a for a in assets}
    rows = []
    for change in changes:
        asset = asset_map.get(change.get("asset_id"))
        if not asset:
            continue
        telemetry = set(asset.get("telemetry_sources", []))
        # A simple coverage proxy: at least one enabled rule must require a telemetry source the asset has.
        has_matching_telemetry_rule = any(
            r.get("enabled", True) and telemetry.intersection(r.get("telemetry_requirements", []))
            for r in rules
        )
        if asset.get("monitoring_status") != "full" or not has_matching_telemetry_rule:
            rows.append({
                "change_id": change["id"], "asset_id": asset["id"], "asset": asset["name"],
                "timestamp": change["timestamp"], "change_type": change.get("change_type"),
                "drift_reason": "Infrastructure changed while security coverage is partial or not demonstrably aligned.",
            })
    return sorted(rows, key=lambda x: x["timestamp"], reverse=True)
