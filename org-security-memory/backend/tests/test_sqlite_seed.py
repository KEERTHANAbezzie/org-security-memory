from pathlib import Path
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from app.models.models import Incident, Alert, Ticket, Change, Asset, DetectionRule, Remediation, Evidence
from data.load_sqlite import seed_database

DATA = Path(__file__).parents[1] / "data" / "generated"

def test_sqlite_seed_round_trip(tmp_path):
    db = f"sqlite:///{tmp_path / 'security_memory.db'}"
    engine = seed_database(DATA, db)
    with Session(engine) as s:
        assert s.scalar(select(func.count()).select_from(Incident)) == 115
        assert s.scalar(select(func.count()).select_from(Alert)) == 250
        assert s.scalar(select(func.count()).select_from(Ticket)) == 100
        assert s.scalar(select(func.count()).select_from(Change)) == 120
        assert s.scalar(select(func.count()).select_from(Asset)) == 30
        assert s.scalar(select(func.count()).select_from(DetectionRule)) == 22
        assert s.scalar(select(func.count()).select_from(Remediation)) == 100
        assert s.scalar(select(func.count()).select_from(Evidence)) == 100
