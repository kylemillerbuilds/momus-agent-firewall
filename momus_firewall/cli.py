import argparse
import sys
import json
from pathlib import Path
from .scanner import MomusScanner

def main():
    parser = argparse.ArgumentParser(description="Momus Agent Firewall: Scan AI-generated code for security risks.")
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--diff", action="store_true", help="Treat the input file as a unified diff patch")
    parser.add_argument("--allowlist", type=str, help="Path to JSON file containing an allowlist of strings (e.g. valid wallets)")
    
    args = parser.parse_args()
    
    allowlist = []
    if args.allowlist:
        try:
            with open(args.allowlist, 'r') as f:
                allowlist = json.load(f)
        except Exception as e:
            print(f"Error loading allowlist: {e}", file=sys.stderr)
            sys.exit(1)
            
    scanner = MomusScanner(allowlist=allowlist)
    all_findings = []
    target_path = Path(args.path)
    
    if not target_path.exists():
        print(f"Error: Path {args.path} does not exist.", file=sys.stderr)
        sys.exit(1)
        
    if args.diff:
        with open(target_path, 'r', encoding='utf-8') as f:
            content = f.read()
        all_findings.extend(scanner.scan_diff(content, file_path=str(target_path)))
    elif target_path.is_file():
        all_findings.extend(scanner.scan_file(str(target_path)))
    elif target_path.is_dir():
        for file_path in target_path.rglob('*'):
            if file_path.is_file() and not file_path.name.startswith('.'):
                all_findings.extend(scanner.scan_file(str(file_path)))
                
    if all_findings:
        print("🚨 Momus Firewall Alert: Malicious or risky patterns detected!\n")
        for finding in all_findings:
            print(f"[{finding.rule_name}] {finding.file_path}:{finding.line_number}")
            print(f"  Reason: {finding.message}")
            print(f"  Snippet: {finding.content.strip()}\n")
        sys.exit(1)
    else:
        print("✅ Momus Firewall: Clean. No risky patterns detected.")
        sys.exit(0)

if __name__ == "__main__":
    main()
