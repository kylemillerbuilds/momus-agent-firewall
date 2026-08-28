import re
import os
import json
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class Finding:
    rule_name: str
    file_path: str
    line_number: int
    content: str
    message: str

class MomusScanner:
    def __init__(self, allowlist: Optional[List[str]] = None):
        self.allowlist = allowlist or []
        
        # Rule 1: EVM and Solana address regexes
        self.evm_regex = re.compile(r'0x[a-fA-F0-9]{40}')
        self.solana_regex = re.compile(r'\b[1-9A-HJ-NP-Za-km-z]{32,44}\b')
        
        # Rule 2: Env strictness (detect os.getenv or JS process.env fallbacks for sensitive variables)
        self.env_strict_regexes = [
            re.compile(r'os\.(?:environ\.get|getenv)\(\s*([\'"])(.*?)\1\s*,'),
            re.compile(r'process\.env\.([a-zA-Z0-9_]+)\s*\|\|')
        ]
        self.sensitive_keywords = ['secret', 'key', 'token', 'password', 'auth', 'cred', 'api']

        # Rule 3: The "Sledgehammer" Catcher
        self.sledgehammer_patterns = [
            (re.compile(r'chmod\s+777'), "AI taking permission shortcuts (chmod 777). Use least-privilege."),
            (re.compile(r'verify\s*=\s*False'), "AI disabling SSL verification. This permits Man-in-the-Middle attacks."),
            (re.compile(r'shell\s*=\s*True'), "AI using shell=True in subprocess. This introduces command injection risks.")
        ]

        # Rule 4: "Lazy Agent" Placeholders
        self.placeholder_regex = re.compile(r'(YOUR_[A-Z0-9_]+_HERE|\[REDACTED\]|<insert\s+[^>]+>|TODO:\s*implement\s+(?:auth|logic|security))', re.IGNORECASE)

    def is_allowlisted(self, text: str) -> bool:
        return text in self.allowlist

    def scan_line(self, line: str, file_path: str, line_number: int) -> List[Finding]:
        findings = []
        
        # Check EVM addresses
        for evm_match in self.evm_regex.finditer(line):
            match_text = evm_match.group()
            if not self.is_allowlisted(match_text):
                findings.append(Finding(
                    rule_name="Hex Scanner (EVM)",
                    file_path=file_path,
                    line_number=line_number,
                    content=match_text,
                    message="Detected non-allowlisted EVM wallet address. AIs may hallucinate rogue addresses."
                ))
                
        # Check Solana addresses
        for sol_match in self.solana_regex.finditer(line):
            match_text = sol_match.group()
            if not self.is_allowlisted(match_text):
                if re.search(r'[A-Z]', match_text) and re.search(r'[a-z]', match_text) and re.search(r'[0-9]', match_text):
                    findings.append(Finding(
                        rule_name="Hex Scanner (Solana)",
                        file_path=file_path,
                        line_number=line_number,
                        content=match_text,
                        message="Detected potential non-allowlisted Solana wallet address."
                    ))
                
        # Check Env Strictness
        for regex in self.env_strict_regexes:
            for env_match in regex.finditer(line):
                # Python regex captures var name in group 2, JS regex captures in group 1
                var_name = env_match.group(2).lower() if len(env_match.groups()) > 1 else env_match.group(1).lower()
                if any(keyword in var_name for keyword in self.sensitive_keywords):
                    findings.append(Finding(
                        rule_name="Env Strictness",
                        file_path=file_path,
                        line_number=line_number,
                        content=line.strip(),
                        message=f"Sensitive env var must not have a fallback. Use strict loading (e.g. os.environ['VAR'] or fail-fast) to prevent fail-open vulnerabilities."
                    ))

        # Check Sledgehammers
        for pattern, msg in self.sledgehammer_patterns:
            if pattern.search(line):
                findings.append(Finding(
                    rule_name="Sledgehammer Catcher",
                    file_path=file_path,
                    line_number=line_number,
                    content=line.strip(),
                    message=msg
                ))

        # Check Lazy Agent Placeholders
        for ph_match in self.placeholder_regex.finditer(line):
            findings.append(Finding(
                rule_name="Lazy Agent Placeholder",
                file_path=file_path,
                line_number=line_number,
                content=line.strip(),
                message=f"Detected synthetic placeholder: '{ph_match.group(1)}'. AI agent failed to implement actual logic."
            ))
                
        return findings

    def scan_file(self, file_path: str) -> List[Finding]:
        findings = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for i, line in enumerate(f, 1):
                    findings.extend(self.scan_line(line, file_path, i))
        except UnicodeDecodeError:
            pass
        return findings

    def scan_diff(self, diff_content: str, file_path: str = "diff") -> List[Finding]:
        findings = []
        lines = diff_content.splitlines()
        for i, line in enumerate(lines, 1):
            if line.startswith('+') and not line.startswith('+++'):
                findings.extend(self.scan_line(line[1:], file_path, i))
        return findings
