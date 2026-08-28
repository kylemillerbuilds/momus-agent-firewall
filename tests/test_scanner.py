import pytest
import json
from pathlib import Path
from momus_firewall.scanner import MomusScanner

TESTS_DIR = Path(__file__).parent

def test_evm_positive():
    scanner = MomusScanner()
    findings = scanner.scan_file(str(TESTS_DIR / "mock_malicious.py"))
    evm_findings = [f for f in findings if f.rule_name == "Hex Scanner (EVM)" and "0x89205A3A3b2A69De6Dbf7f01ED13B2108B2c43e7" in f.content]
    assert len(evm_findings) == 1
    assert evm_findings[0].line_number == 13
    assert evm_findings[0].content == "0x89205A3A3b2A69De6Dbf7f01ED13B2108B2c43e7"

def test_solana_positive():
    scanner = MomusScanner()
    findings = scanner.scan_file(str(TESTS_DIR / "mock_malicious.py"))
    sol_findings = [f for f in findings if f.rule_name == "Hex Scanner (Solana)" and "HN7cABqLq46Es1jh92dQQisAq662SmxELLLsHHe4YWrH" in f.content]
    assert len(sol_findings) == 1
    assert sol_findings[0].line_number == 16
    assert sol_findings[0].content == "HN7cABqLq46Es1jh92dQQisAq662SmxELLLsHHe4YWrH"

def test_env_strictness_python():
    scanner = MomusScanner()
    findings = scanner.scan_file(str(TESTS_DIR / "mock_malicious.py"))
    env_findings_1 = [f for f in findings if f.rule_name == "Env Strictness" and "API_KEY" in f.content and "SECRET_API_KEY" not in f.content]
    assert len(env_findings_1) == 1
    assert env_findings_1[0].line_number == 5
    
    env_findings_2 = [f for f in findings if f.rule_name == "Env Strictness" and "WALLET_SECRET" in f.content]
    assert len(env_findings_2) == 1
    assert env_findings_2[0].line_number == 6

def test_env_strictness_js_in_python_comment():
    scanner = MomusScanner()
    findings = scanner.scan_file(str(TESTS_DIR / "mock_malicious.py"))
    js_findings = [f for f in findings if f.rule_name == "Env Strictness" and "SECRET_API_KEY" in f.content]
    assert len(js_findings) == 1
    assert js_findings[0].line_number == 40
    # The scanner is line-regex-based and comment-blind, so we pin this documented current behavior.

def test_sledgehammer_verify_false():
    scanner = MomusScanner()
    findings = scanner.scan_file(str(TESTS_DIR / "mock_malicious.py"))
    # There are two verify=False lines, one is a comment (line 24) and one is code (line 26)
    sledge_findings = [f for f in findings if f.rule_name == "Sledgehammer Catcher" and "verify=False" in f.content]
    assert len(sledge_findings) == 2
    assert sledge_findings[0].line_number == 24
    assert sledge_findings[1].line_number == 26
    # Pinning comment-blind behavior as documented

def test_sledgehammer_shell_true():
    scanner = MomusScanner()
    findings = scanner.scan_file(str(TESTS_DIR / "mock_malicious.py"))
    # There are two shell=True lines, comment (28) and code (30)
    sledge_findings = [f for f in findings if f.rule_name == "Sledgehammer Catcher" and "shell=True" in f.content]
    assert len(sledge_findings) == 2
    assert sledge_findings[0].line_number == 28
    assert sledge_findings[1].line_number == 30
    # Pinning comment-blind behavior as documented

def test_lazy_agent_placeholder():
    scanner = MomusScanner()
    findings = scanner.scan_file(str(TESTS_DIR / "mock_malicious.py"))
    lazy = [f for f in findings if f.rule_name == "Lazy Agent Placeholder"]
    assert len(lazy) == 3
    assert lazy[0].line_number == 33
    assert lazy[0].content == 'user_token = "YOUR_USER_TOKEN_HERE"'
    assert lazy[1].line_number == 34
    assert lazy[1].content == 'secret_key = "[REDACTED]"'
    assert lazy[2].line_number == 36
    assert lazy[2].content == '# TODO: implement auth'

def test_negative_control_clean_file():
    scanner = MomusScanner()
    findings = scanner.scan_file(str(TESTS_DIR / "fixture_clean.py"))
    assert len(findings) == 0

def test_negative_control_no_fallback():
    scanner = MomusScanner()
    findings = scanner.scan_file(str(TESTS_DIR / "mock_malicious.py"))
    # Line 9 is: strict_token = os.getenv("PROD_TOKEN")
    line_9_env = [f for f in findings if f.rule_name == "Env Strictness" and f.line_number == 9]
    assert len(line_9_env) == 0

def test_allowlist_matches_by_substring_documented_behavior():
    with open(TESTS_DIR / "allowlist.json", "r") as f:
        allowlist = json.load(f)
    
    scanner_no = MomusScanner()
    findings_no = scanner_no.scan_file(str(TESTS_DIR / "mock_malicious.py"))
    
    scanner_yes = MomusScanner(allowlist=allowlist)
    findings_yes = scanner_yes.scan_file(str(TESTS_DIR / "mock_malicious.py"))
    
    assert len(findings_no) - len(findings_yes) == 1
    
    # Identify the missing finding
    missing = [f for f in findings_no if f not in findings_yes]
    assert len(missing) == 1
    assert missing[0].content == "0x0000000000000000000000000000000000000000"
    assert missing[0].line_number == 19
    # Pinning mechanism honestly: is_allowlisted uses a substring check (`if allowed in text`), so it matches by substring

def test_scan_diff_findings():
    scanner = MomusScanner()
    with open(TESTS_DIR / "mock_diff.patch", "r") as f:
        diff_content = f.read()
    findings = scanner.scan_diff(diff_content, str(TESTS_DIR / "mock_diff.patch"))
    
    # Assert exactly 3 findings
    assert len(findings) == 3
    
    # The `+++` line should not produce findings
    # Pinning honest quirk: scan_diff line numbers are diff-relative, not target-file-relative.
    assert findings[0].line_number == 7
    assert "DB_PASSWORD" in findings[0].content
    
    assert findings[1].line_number == 8
    assert "0x89205A3A3b2A69De6Dbf7f01ED13B2108B2c43e7" in findings[1].content
    
    assert findings[2].line_number == 9
    assert "HN7cABqLq46Es1jh92dQQisAq662SmxELLLsHHe4YWrH" in findings[2].content

def test_scan_diff_removal_no_findings():
    scanner = MomusScanner()
    with open(TESTS_DIR / "mock_removal.patch", "r") as f:
        diff_content = f.read()
    findings = scanner.scan_diff(diff_content, str(TESTS_DIR / "mock_removal.patch"))
    assert len(findings) == 0
