import subprocess
import pytest
import sys
from pathlib import Path

TESTS_DIR = Path(__file__).parent

def test_cli_malicious_exit_1():
    result = subprocess.run([sys.executable, "-m", "momus_firewall.cli", str(TESTS_DIR / "mock_malicious.py")], capture_output=True, text=True)
    assert result.returncode == 1
    assert "Momus Firewall Alert" in result.stdout

def test_cli_clean_exit_0():
    result = subprocess.run([sys.executable, "-m", "momus_firewall.cli", str(TESTS_DIR / "fixture_clean.py")], capture_output=True, text=True)
    assert result.returncode == 0
    assert "Clean" in result.stdout

def test_cli_missing_path():
    result = subprocess.run([sys.executable, "-m", "momus_firewall.cli", str(TESTS_DIR / "does_not_exist.py")], capture_output=True, text=True)
    assert result.returncode == 1
    assert "does not exist" in result.stderr

def test_cli_malformed_allowlist(tmp_path):
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{bad_json: True}")
    
    result = subprocess.run([sys.executable, "-m", "momus_firewall.cli", str(TESTS_DIR / "fixture_clean.py"), "--allowlist", str(bad_json)], capture_output=True, text=True)
    assert result.returncode == 1
    assert "Error loading allowlist" in result.stderr

def test_cli_directory_mode_aggregates():
    # Run over tests dir, expect failure since mock_malicious is in it
    result = subprocess.run([sys.executable, "-m", "momus_firewall.cli", str(TESTS_DIR)], capture_output=True, text=True)
    assert result.returncode == 1
    assert "mock_malicious.py" in result.stdout
