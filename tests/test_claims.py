"""The claim tier's own tests.

Every rule is tested three ways, because a checker that has never gone red is a
decoration:

  1. the fabricated delivery (tests/claims/tree_bad + report_bad + diff_bad) must FAIL it
  2. the honest delivery (tree_good + report_good + diff_good) must PASS it
  3. a CONTROL: take the honest delivery, corrupt exactly one thing, and the rule must
     go red. If the corruption is not caught, the rule cannot fail and the test fails.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from momus_firewall.claims import (
    BLIND, FAIL, PASS, RULES, audit_claims, render_prompt, render_table,
)

HERE = Path(__file__).parent / "claims"
BAD_TREE, GOOD_TREE = HERE / "tree_bad", HERE / "tree_good"
BAD_REPORT = (HERE / "report_bad.md").read_text()
GOOD_REPORT = (HERE / "report_good.md").read_text()
BAD_DIFF = (HERE / "diff_bad.patch").read_text()
GOOD_DIFF = (HERE / "diff_good.patch").read_text()


def states(rep):
    return {r.rule: r.state for r in rep.results}


@pytest.fixture(scope="module")
def bad():
    return audit_claims(BAD_REPORT, BAD_TREE, diff=BAD_DIFF, run_tests=True)


@pytest.fixture(scope="module")
def good():
    return audit_claims(GOOD_REPORT, GOOD_TREE, diff=GOOD_DIFF, run_tests=True)


# ── 1 + 2: the two deliveries ────────────────────────────────────────────────

def test_every_rule_fails_the_fabricated_delivery(bad):
    assert states(bad) == {r: FAIL for r in RULES}, states(bad)


def test_every_rule_passes_the_honest_delivery(good):
    assert states(good) == {r: PASS for r in RULES}, states(good)


def test_bad_counted_nothing_names_the_34_tests(bad):
    f = [x for x in bad.findings if x.rule == "counted-nothing"]
    assert any("34 tests" in x.what and "3 test function" in x.what for x in f)
    assert any("Rows shipped: 121" in x.what for x in f)
    assert any("Oversubscribed: 15" in x.what for x in f)


def test_bad_ran_nothing_reports_the_observed_run(bad):
    f = [x for x in bad.findings if x.rule == "ran-nothing"]
    assert len(f) == 1
    assert "observed 3 passed" in f[0].what
    assert "Change the count to 3" in f[0].fix


def test_bad_clipped_number_shows_the_longer_figure(bad):
    f = [x for x in bad.findings if x.rule == "clipped-number"]
    assert len(f) == 1
    assert "99,724" in f[0].what and "12,099,724" in f[0].what and "filing.txt" in f[0].what


def test_bad_quote_unbound_names_the_file(bad):
    f = [x for x in bad.findings if x.rule == "quote-unbound"]
    assert len(f) == 1 and "filing.txt" in f[0].what


def test_bad_cannot_fail_finds_all_three_shapes(bad):
    f = [x for x in bad.findings if x.rule == "cannot-fail"]
    whats = " ".join(x.what for x in f)
    assert "except-handler swallows" in whats
    assert "test_smoke()" in whats and "test_always_green()" in whats


def test_bad_carve_out_quotes_the_line(bad):
    f = [x for x in bad.findings if x.rule == "carve-out"]
    assert len(f) == 1 and 'r["ticker"] == "CVBF"' in f[0].what


def test_bad_control_removed_finds_three_controls_and_one_skip(bad):
    f = [x for x in bad.findings if x.rule == "control-removed"]
    whats = " ".join(x.what for x in f)
    assert "@login_required" in whats
    assert "assert user_id" in whats
    assert "TLS verification" in whats
    assert "test was skipped" in whats
    assert len(f) == 4


def test_every_finding_carries_a_fix(bad):
    for f in bad.findings:
        assert f.fix and len(f.fix) > 20, f


# ── 3: controls — corrupt the honest delivery one way per rule ───────────────

def _copy_good(tmp_path):
    dst = tmp_path / "tree"
    shutil.copytree(GOOD_TREE, dst)
    return dst


def test_control_counted_nothing(tmp_path):
    rep = audit_claims(GOOD_REPORT.replace("Rows shipped: 5", "Rows shipped: 500"), _copy_good(tmp_path))
    assert states(rep)["counted-nothing"] == FAIL


def test_control_ran_nothing(tmp_path):
    tree = _copy_good(tmp_path)
    t = tree / "tests" / "test_offers.py"
    t.write_text(t.read_text().replace("== 5", "== 999"))
    rep = audit_claims(GOOD_REPORT, tree, run_tests=True)
    assert states(rep)["ran-nothing"] == FAIL
    assert "failed" in rep.results[1].findings[0].what


def test_control_clipped_number(tmp_path):
    rep = audit_claims(GOOD_REPORT.replace("12,099,724 shares. The", "99,724 shares. The"), _copy_good(tmp_path))
    assert states(rep)["clipped-number"] == FAIL


def test_control_quote_unbound(tmp_path):
    rep = audit_claims(GOOD_REPORT.replace("properly tendered and not withdrawn", "tendered and gladly accepted"), _copy_good(tmp_path))
    assert states(rep)["quote-unbound"] == FAIL


def test_control_cannot_fail(tmp_path):
    tree = _copy_good(tmp_path)
    v = tree / "verify.py"
    v.write_text(v.read_text().replace('    fails.append(f"COULD NOT LOOK: receipt ({e})")', "    pass"))
    rep = audit_claims(GOOD_REPORT, tree)
    assert states(rep)["cannot-fail"] == FAIL


def test_control_carve_out(tmp_path):
    tree = _copy_good(tmp_path)
    v = tree / "verify.py"
    v.write_text(v.read_text().replace("for r in rows:\n", 'for r in rows:\n    if r["ticker"] == "DNOW":\n        continue\n'))
    rep = audit_claims(GOOD_REPORT, tree)
    assert states(rep)["carve-out"] == FAIL


def test_control_control_removed(tmp_path):
    corrupted = GOOD_DIFF.replace(" @login_required\n", "-@login_required\n")
    rep = audit_claims(GOOD_REPORT, _copy_good(tmp_path), diff=corrupted)
    assert states(rep)["control-removed"] == FAIL


# ── the third state is loud ──────────────────────────────────────────────────

def test_could_not_look_is_a_state_not_a_pass(tmp_path):
    rep = audit_claims(GOOD_REPORT, _copy_good(tmp_path))  # no diff, tests not run
    s = states(rep)
    assert s["ran-nothing"] == BLIND
    assert s["control-removed"] == BLIND
    assert rep.to_dict()["summary"]["could_not_look"] == 2
    prompt = render_prompt(rep)
    assert "could not look" in prompt.lower()
    assert "ran-nothing" in prompt and "control-removed" in prompt


def test_empty_tree_is_blind_not_clean(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    rep = audit_claims('All tests pass. "some quoted words here from" per notes.txt. Figure 45,000.', empty)
    s = states(rep)
    assert s["clipped-number"] == BLIND
    assert s["cannot-fail"] == BLIND
    assert s["carve-out"] == BLIND
    assert s["ran-nothing"] == BLIND


# ── rendering ────────────────────────────────────────────────────────────────

def test_prompt_is_paste_ready(bad):
    p = render_prompt(bad)
    assert p.startswith("Momus blocked this change.")
    assert "Fix:" in p
    assert "[clipped-number]" in p and "12,099,724" in p


def test_table_has_the_summary_line(good):
    t = render_table(good)
    assert "7 rules · 7 looked · 0 failed · 0 could not look" in t


# ── CLI ──────────────────────────────────────────────────────────────────────

def _cli(*args):
    return subprocess.run([sys.executable, "-m", "momus_firewall.cli", *args], capture_output=True, text=True)


def test_cli_claims_bad_exits_1_and_scans_the_diff_too():
    r = _cli("claims", str(HERE / "report_bad.md"), "--tree", str(BAD_TREE), "--diff", str(HERE / "diff_bad.patch"))
    assert r.returncode == 1
    assert "CODE TIER" in r.stdout and "Sledgehammer" in r.stdout


def test_cli_claims_good_exits_0():
    r = _cli("claims", str(HERE / "report_good.md"), "--tree", str(GOOD_TREE), "--diff", str(HERE / "diff_good.patch"), "--run-tests")
    assert r.returncode == 0, r.stdout + r.stderr


def test_cli_blind_is_fail_exits_2():
    r = _cli("claims", str(HERE / "report_good.md"), "--tree", str(GOOD_TREE), "--blind-is-fail")
    assert r.returncode == 2


def test_cli_json_shape():
    r = _cli("claims", str(HERE / "report_good.md"), "--tree", str(GOOD_TREE), "--json")
    d = json.loads(r.stdout)
    assert set(d) == {"rules", "summary", "code_tier"}
    assert [x["rule"] for x in d["rules"]] == RULES


def test_cli_as_prompt_on_stdin():
    r = subprocess.run(
        [sys.executable, "-m", "momus_firewall.cli", "claims", "-", "--tree", str(BAD_TREE), "--as-prompt"],
        input=BAD_REPORT, capture_output=True, text=True,
    )
    assert r.returncode == 1
    assert r.stdout.startswith("Momus blocked this change.")


def test_cli_code_tier_as_prompt():
    r = _cli(str(Path(__file__).parent / "mock_malicious.py"), "--as-prompt")
    assert r.returncode == 1
    assert "Fix:" in r.stdout
