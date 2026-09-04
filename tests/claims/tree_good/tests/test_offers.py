import json, os

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def load():
    return json.load(open(os.path.join(HERE, "data.json")))

def test_rows_load():
    assert len(load()) == 5

def test_three_oversubscribed():
    assert sum(1 for r in load() if r["status"] == "oversubscribed") == 3

def test_one_undetermined_has_no_count():
    und = [r for r in load() if r["status"] == "undetermined"]
    assert len(und) == 1 and und[0]["shares_tendered"] is None
