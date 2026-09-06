import json
from pathlib import Path
from data.generate_synthetic import main

def test_dataset_minimums(tmp_path: Path):
    out=tmp_path/"generated"; main(out,20260906)
    c=json.loads((out/"manifest.json").read_text())["counts"]
    assert c["incidents"]>=100 and c["alerts"]>=200 and c["tickets"]>=100
    assert c["changes"]>=100 and c["assets"]>=30 and c["detection_rules"]>=20 and c["remediations"]>=50

def test_ground_truth_separation(tmp_path: Path):
    out=tmp_path/"generated"; main(out,20260906)
    gt=json.loads((out/"ground_truth.json").read_text())
    assert len(gt["families"])==5
    assert len(gt["blind_spots"])==5
    assert len(gt["temporal_links"])>=100

def test_reproducible(tmp_path: Path):
    a,b=tmp_path/"a",tmp_path/"b"; main(a,123); main(b,123)
    assert (a/"incidents.json").read_text()==(b/"incidents.json").read_text()
    assert (a/"ground_truth.json").read_text()==(b/"ground_truth.json").read_text()
