from pathlib import Path

ROOT = Path(__file__).parents[1] / "app"

def test_runtime_code_does_not_reference_ground_truth_file():
    hits=[]
    for p in ROOT.rglob("*.py"):
        text=p.read_text(encoding="utf-8")
        if "ground_truth.json" in text:
            hits.append(str(p))
    assert hits == []
