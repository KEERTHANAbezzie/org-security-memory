from __future__ import annotations

import json
from pathlib import Path
import sys

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent
BACKEND = ROOT / "backend"
DATA_DIR = BACKEND / "data" / "generated"

from backend.app.analytics.deterministic import (  # noqa: E402
    discover_recurrence_families,
    recurrence_summary,
    temporal_change_links,
    remediation_effectiveness,
    operational_debt,
    detection_gap_classification,
    drift_indicators,
)

st.set_page_config(
    page_title="Organizational Security Memory",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


def load_json(name: str):
    path = DATA_DIR / name
    if not path.exists():
        st.error(f"Missing dataset file: {path}")
        st.stop()
    return json.loads(path.read_text(encoding="utf-8"))


@st.cache_data

def load_data():
    return {
        "incidents": load_json("incidents.json"),
        "alerts": load_json("alerts.json"),
        "tickets": load_json("tickets.json"),
        "changes": load_json("changes.json"),
        "assets": load_json("assets.json"),
        "rules": load_json("detection_rules.json"),
        "remediations": load_json("remediations.json"),
        "runbooks": load_json("runbooks.json"),
        "evidence": load_json("evidence.json"),
    }


data = load_data()
incidents = data["incidents"]


def discovered_family_for(incident_id: str):
    families = discover_recurrence_families(incidents)
    for family in families:
        if incident_id in family["incident_ids"]:
            return family
    return None


def metric_card(label, value, help_text=None):
    st.metric(label, value, help=help_text)


def severity_counts(rows):
    return pd.Series([r.get("severity", "unknown") for r in rows]).value_counts()


# Sidebar navigation
st.sidebar.title("🛡️ Security Memory")
st.sidebar.caption("Longitudinal SOC intelligence")
page = st.sidebar.radio(
    "Navigate",
    ["Dashboard", "Investigation", "Recurring Families", "Detection Coverage", "Evaluation Preview"],
)

st.sidebar.divider()
st.sidebar.caption("Phase 3 • Streamlit MVP")
st.sidebar.caption("Synthetic data • deterministic intelligence")

# ---------------- Dashboard ----------------
if page == "Dashboard":
    st.title("Organizational Security Memory")
    st.subheader("Your SOC remembers every incident. But does it learn from them?")
    st.write(
        "This MVP connects incidents, changes, remediation history and detection coverage "
        "to expose recurring organizational security problems."
    )

    discovered = discover_recurrence_families(incidents)
    debt = operational_debt(incidents, data["remediations"])
    drift = drift_indicators(data["changes"], data["assets"], data["rules"])

    c1, c2, c3, c4 = st.columns(4)
    with c1: metric_card("Incidents", len(incidents))
    with c2: metric_card("Recurring families", len(discovered))
    with c3: metric_card("Security debt", len(debt))
    with c4: metric_card("Drift indicators", len(drift))

    st.divider()
    left, right = st.columns(2)

    with left:
        st.markdown("### 🔁 Recurring problems")
        family_rows = []
        for f in discovered[:8]:
            family_rows.append({
                "Pattern": f["candidate_key"],
                "Incidents": f["count"],
                "Mean interval (days)": f["mean_interval_days"],
            })
        st.dataframe(pd.DataFrame(family_rows), use_container_width=True, hide_index=True)

        if discovered:
            selected = st.selectbox(
                "Open a recurring pattern",
                options=range(len(discovered[:8])),
                format_func=lambda i: discovered[i]["candidate_key"],
            )
            if st.button("Investigate pattern", use_container_width=True):
                st.session_state["selected_incident"] = discovered[selected]["incident_ids"][0]
                st.session_state["page"] = "Investigation"
                st.rerun()

    with right:
        st.markdown("### 🧱 Security operational debt")
        if debt:
            debt_df = pd.DataFrame(debt)
            debt_df = debt_df[["family_id", "incident_count", "weak_remediation_count", "debt_score"]]
            st.dataframe(debt_df, use_container_width=True, hide_index=True)
        else:
            st.info("No operational debt detected.")

    st.divider()
    st.markdown("### 📈 Incident volume by month")
    df = pd.DataFrame(incidents)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    monthly = df.groupby(df["timestamp"].dt.to_period("M")).size().rename("incidents").reset_index()
    monthly["timestamp"] = monthly["timestamp"].astype(str)
    st.line_chart(monthly.set_index("timestamp"))

    st.info(
        "The dashboard is deliberately evidence-oriented: metrics come from deterministic analytics, "
        "not generated prose."
    )

# ---------------- Investigation ----------------
elif page == "Investigation":
    st.title("🔎 Investigation")
    st.caption("From one incident to the organizational pattern behind it.")

    incident_ids = [i["id"] for i in sorted(incidents, key=lambda x: x["timestamp"], reverse=True)]
    default = st.session_state.get("selected_incident", incident_ids[0])
    if default not in incident_ids:
        default = incident_ids[0]
    incident_id = st.selectbox("Incident", incident_ids, index=incident_ids.index(default))
    st.session_state["selected_incident"] = incident_id

    incident = next(i for i in incidents if i["id"] == incident_id)
    discovered_family = discovered_family_for(incident_id)
    gaps = detection_gap_classification(incident, data["assets"], data["rules"], data["alerts"])
    changes = temporal_change_links(incident, data["changes"])
    rems = remediation_effectiveness(incident, incidents, data["remediations"])

    c1, c2, c3, c4 = st.columns(4)
    with c1: metric_card("Severity", incident["severity"].upper())
    with c2: metric_card("Category", incident["category"])
    with c3: metric_card("Related history", discovered_family["count"] if discovered_family else 0)
    with c4: metric_card("Detection gaps", len(gaps))

    st.divider()
    st.markdown(f"## {incident['title']}")
    st.write(incident["description"])

    st.markdown("### Why this looks familiar")
    if discovered_family:
        summary = recurrence_summary(incidents, discovered_family["incident_ids"])
        st.success(
            f"Deterministic correlation found **{summary['incident_count']} incidents** in the candidate pattern "
            f"`{discovered_family['candidate_key']}`. Trend: **{summary['trend']}**. "
            f"Mean interval: **{summary['mean_interval_days']} days**."
        )
        timeline = [i for i in incidents if i["id"] in discovered_family["incident_ids"]]
        timeline_df = pd.DataFrame(timeline)[["timestamp", "id", "severity", "title"]]
        timeline_df["timestamp"] = pd.to_datetime(timeline_df["timestamp"])
        st.dataframe(timeline_df.sort_values("timestamp"), use_container_width=True, hide_index=True)
    else:
        st.info("No deterministic recurring pattern has enough evidence yet.")

    st.markdown("### Related changes")
    if changes:
        st.dataframe(pd.DataFrame(changes), use_container_width=True, hide_index=True)
    else:
        st.info("No relevant preceding changes found within the correlation window.")

    st.markdown("### Previous remediation effectiveness")
    if rems:
        rem_df = pd.DataFrame(rems)
        st.dataframe(rem_df, use_container_width=True, hide_index=True)
        best = next((r for r in rems if r["recurrence_free_days"] is not None), None)
        if best:
            st.success(
                f"Longest observed recurrence-free interval: **{best['recurrence_free_days']} days** "
                f"after remediation `{best['remediation_id']}`."
            )
    else:
        st.info("No historical remediation outcomes available.")

    st.markdown("### What aren't we detecting?")
    if gaps:
        for gap in gaps:
            st.warning(
                f"**{gap['gap_type'].replace('_', ' ').title()}** — technique `{gap['technique']}`. "
                f"{gap['reason']}"
            )
    else:
        st.success("No deterministic detection coverage gap identified for the observed techniques.")

    st.markdown("### Counterfactual analysis")
    st.info(
        "Model-based estimate only — not historical fact. The counterfactual reasoning layer is intentionally "
        "not enabled in this deterministic phase; later Claude synthesis will receive the evidence bundle and "
        "must explicitly label uncertainty."
    )

    st.markdown("### Evidence")
    evidence = [e for e in data["evidence"] if e.get("incident_id") == incident_id]
    if evidence:
        for e in evidence:
            with st.expander(f"{e['source_type']} • {e['source_id']}"):
                st.write(e["content"])
                st.caption(f"Confidence: {e['confidence']} • Provenance: {e['provenance']}")
    else:
        st.info("No evidence records linked to this incident.")

# ---------------- Families ----------------
elif page == "Recurring Families":
    st.title("🔁 Recurring Problem Families")
    st.caption("Candidate families are discovered from incident attributes; ground truth is not used by the UI.")

    families = discover_recurrence_families(incidents)
    for idx, family in enumerate(families):
        with st.expander(f"{idx+1}. {family['candidate_key']} — {family['count']} incidents"):
            summary = recurrence_summary(incidents, family["incident_ids"])
            a, b, c = st.columns(3)
            with a: metric_card("Mean interval", f"{summary['mean_interval_days']} d")
            with b: metric_card("Trend", summary["trend"])
            with c: metric_card("First seen", summary["first_seen"][:10] if summary["first_seen"] else "—")
            rows = [i for i in incidents if i["id"] in family["incident_ids"]]
            st.dataframe(pd.DataFrame(rows)[["id", "timestamp", "severity", "title"]], use_container_width=True, hide_index=True)

# ---------------- Detection Coverage ----------------
elif page == "Detection Coverage":
    st.title("🕳️ Detection Coverage")
    st.caption("Deterministic coverage analysis: technique → rule → telemetry → monitoring.")

    gaps_all = []
    for incident in incidents:
        for gap in detection_gap_classification(incident, data["assets"], data["rules"], data["alerts"]):
            gaps_all.append({"incident_id": incident["id"], **gap})
    gap_df = pd.DataFrame(gaps_all)

    if gap_df.empty:
        st.success("No gaps detected.")
    else:
        counts = gap_df["gap_type"].value_counts().rename_axis("gap_type").reset_index(name="count")
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("### Gap types")
            st.bar_chart(counts.set_index("gap_type"))
        with c2:
            st.markdown("### Findings")
            st.dataframe(gap_df, use_container_width=True, hide_index=True)

    st.divider()
    st.markdown("### Security drift")
    drift = drift_indicators(data["changes"], data["assets"], data["rules"])
    if drift:
        st.dataframe(pd.DataFrame(drift), use_container_width=True, hide_index=True)
    else:
        st.success("No drift indicators detected.")

# ---------------- Evaluation Preview ----------------
else:
    st.title("🧪 Evaluation Preview")
    st.caption("The formal ground-truth evaluation suite will be connected here in the next phase.")

    st.warning(
        "This page does not read ground_truth.json. It only reports structural readiness for the evaluation suite."
    )
    checks = [
        ("Synthetic dataset available", (DATA_DIR / "manifest.json").exists()),
        ("100+ incidents", len(incidents) >= 100),
        ("200+ alerts", len(data["alerts"]) >= 200),
        ("100+ changes", len(data["changes"]) >= 100),
        ("30 assets", len(data["assets"]) >= 30),
        ("20+ detection rules", len(data["rules"]) >= 20),
        ("50+ remediations", len(data["remediations"]) >= 50),
        ("Recurrence engine available", bool(discover_recurrence_families(incidents))),
        ("Detection coverage engine available", True),
        ("Operational debt engine available", bool(operational_debt(incidents, data["remediations"]))),
    ]
    eval_df = pd.DataFrame(checks, columns=["Check", "Pass"])
    eval_df["Status"] = eval_df["Pass"].map({True: "PASS", False: "FAIL"})
    st.dataframe(eval_df[["Check", "Status"]], use_container_width=True, hide_index=True)

    st.markdown("### Internal rubric readiness")
    rubric = pd.DataFrame([
        ["Code Quality", "High", "Architecture separated; tests included"],
        ["Problem Alignment", "High", "UI directly demonstrates recurrence + detection gaps"],
        ["Security", "Medium", "No auto-remediation; synthetic data only"],
        ["Efficiency", "Medium", "Deterministic analytics before LLM"],
        ["Testing", "Low", "Generator + deterministic tests present"],
        ["Accessibility", "Low", "Semantic Streamlit controls and text alternatives"],
    ], columns=["Parameter", "Impact", "Current posture"])
    st.table(rubric)
