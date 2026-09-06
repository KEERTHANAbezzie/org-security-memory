from __future__ import annotations

import argparse
import json
from pathlib import Path
from datetime import datetime

from sqlalchemy import create_engine, insert
from sqlalchemy.orm import Session

from app.models.models import Base, Incident, Alert, Ticket, Change, Asset, DetectionRule, Remediation, Runbook, Evidence
from app.models.models import incident_assets, incident_users, incident_techniques, rule_techniques


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def dt(v):
    return datetime.fromisoformat(v) if isinstance(v, str) else v


def seed_database(data_dir: Path, db_url: str = "sqlite:///./security_memory.db"):
    engine = create_engine(db_url, connect_args={"check_same_thread": False} if db_url.startswith("sqlite") else {})
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)

    assets = load_json(data_dir / "assets.json")
    rules = load_json(data_dir / "detection_rules.json")
    runbooks = load_json(data_dir / "runbooks.json")
    incidents = load_json(data_dir / "incidents.json")
    alerts = load_json(data_dir / "alerts.json")
    tickets = load_json(data_dir / "tickets.json")
    changes = load_json(data_dir / "changes.json")
    remediations = load_json(data_dir / "remediations.json")
    evidence = load_json(data_dir / "evidence.json")

    with Session(engine) as s:
        s.add_all([Asset(**a) for a in assets])
        s.add_all([DetectionRule(**{k:v for k,v in r.items() if k != "techniques"}) for r in rules])
        s.add_all([Runbook(**{**r, "last_validated": dt(r["last_validated"])}) for r in runbooks])
        s.add_all([Incident(**{**{k:v for k,v in i.items() if k not in {"asset_ids","user_ids","techniques"}}, "timestamp": dt(i["timestamp"])}) for i in incidents])
        s.add_all([Alert(**{**a, "timestamp": dt(a["timestamp"])}) for a in alerts])
        s.add_all([Ticket(**{**t, "timestamp": dt(t["timestamp"])}) for t in tickets])
        s.add_all([Change(**{**c, "timestamp": dt(c["timestamp"])}) for c in changes])
        s.add_all([Remediation(**{**r, "timestamp": dt(r["timestamp"])}) for r in remediations])
        s.add_all([Evidence(**{**e, "timestamp": dt(e["timestamp"])}) for e in evidence])
        s.flush()

        s.execute(insert(incident_assets), [
            {"incident_id": i["id"], "asset_id": a}
            for i in incidents for a in i.get("asset_ids", [])
        ])
        s.execute(insert(incident_users), [
            {"incident_id": i["id"], "user_id": u}
            for i in incidents for u in i.get("user_ids", [])
        ])
        s.execute(insert(incident_techniques), [
            {"incident_id": i["id"], "technique_id": t}
            for i in incidents for t in i.get("techniques", [])
        ])
        s.execute(insert(rule_techniques), [
            {"rule_id": r["id"], "technique_id": t}
            for r in rules for t in r.get("techniques", [])
        ])
        s.commit()

    return engine


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--data", default="backend/data/generated")
    p.add_argument("--db", default="sqlite:///./security_memory.db")
    args = p.parse_args()
    engine = seed_database(Path(args.data), args.db)
    print(f"Seeded {args.db}")
