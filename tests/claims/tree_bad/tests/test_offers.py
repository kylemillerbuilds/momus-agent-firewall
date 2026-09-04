import json, sys

def load():
    return json.load(open("data.json"))

def test_rows_load():
    rows = load()
    assert len(rows) == 5

def test_smoke():
    load()

def test_always_green():
    assert True
