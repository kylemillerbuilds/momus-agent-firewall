"""momus-firewall — two commands.

    momus-firewall PATH [--diff] [--allowlist FILE] [--as-prompt] [--json]
        The code tier. Scans a file, a directory, or a unified diff for the four
        things coding agents get wrong in ways that survive review.

    momus-firewall claims REPORT [--tree DIR] [--diff PATCH] [--run-tests]
                          [--as-prompt] [--json] [--blind-is-fail]
        The claim tier. Reads the agent's REPORT (a PR description, a commit
        message, a VERIFICATION.md, a pasted summary) and checks what it claims
        against the tree and the diff. Every rule ends PASS, FAIL, or COULD NOT
        LOOK, and the third one is printed, never hidden.

Exit codes: 0 clean · 1 something failed · 2 nothing failed but a rule could not
look and --blind-is-fail was set.
"""

import argparse
import json
import sys
from pathlib import Path

from .scanner import MomusScanner
from .claims import audit_claims, render_table, render_prompt


def _load_allowlist(path):
    if not path:
        return []
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading allowlist: {e}", file=sys.stderr)
        sys.exit(1)


def run_scan(argv):
    parser = argparse.ArgumentParser(
        prog="momus-firewall",
        description="Momus Agent Firewall, code tier: scan AI-generated code for the four mistakes that survive review.",
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--diff", action="store_true", help="Treat the input file as a unified diff patch")
    parser.add_argument("--allowlist", type=str, help="Path to a JSON array of allowed strings (e.g. valid wallets)")
    parser.add_argument("--as-prompt", action="store_true", help="Print the findings as a paste-ready correction prompt for the agent")
    parser.add_argument("--json", action="store_true", help="Print the findings as JSON")
    args = parser.parse_args(argv)

    scanner = MomusScanner(allowlist=_load_allowlist(args.allowlist))
    target = Path(args.path)
    if not target.exists():
        print(f"Error: Path {args.path} does not exist.", file=sys.stderr)
        sys.exit(1)

    findings = []
    if args.diff:
        findings.extend(scanner.scan_diff(target.read_text(encoding="utf-8"), file_path=str(target)))
    elif target.is_file():
        findings.extend(scanner.scan_file(str(target)))
    else:
        for fp in target.rglob("*"):
            if fp.is_file() and not fp.name.startswith(".") and ".git" not in fp.parts:
                findings.extend(scanner.scan_file(str(fp)))

    if args.json:
        print(json.dumps([f.__dict__ for f in findings], indent=2))
    elif args.as_prompt:
        from .claims import ClaimReport
        print(render_prompt(ClaimReport([]), code_findings=findings))
    elif findings:
        print("🚨 Momus Firewall Alert: Malicious or risky patterns detected!\n")
        for f in findings:
            print(f"[{f.rule_name}] {f.file_path}:{f.line_number}")
            print(f"  Reason: {f.message}")
            print(f"  Snippet: {f.content.strip()}")
            if f.fix:
                print(f"  Fix: {f.fix}")
            print()
    else:
        print("✅ Momus Firewall: Clean. No risky patterns detected.")
    sys.exit(1 if findings else 0)


def run_claims(argv):
    parser = argparse.ArgumentParser(
        prog="momus-firewall claims",
        description="Momus Agent Firewall, claim tier: check what the agent's report claims against what the tree and diff contain.",
    )
    parser.add_argument("report", help="The agent's report: a file path, or '-' to read stdin")
    parser.add_argument("--tree", default=".", help="The tree the report describes (default: .)")
    parser.add_argument("--diff", type=str, help="A unified diff of the change (enables control-removed and scopes the checker rules)")
    parser.add_argument("--run-tests", action="store_true", help="Let Momus run pytest in the tree and compare the run to the claim")
    parser.add_argument("--test-timeout", type=int, default=600)
    parser.add_argument("--allowlist", type=str, help="Allowlist for the code-tier scan that also runs when --diff is given")
    parser.add_argument("--no-code-tier", action="store_true", help="Skip the code-tier scan of the diff")
    parser.add_argument("--as-prompt", action="store_true", help="Print the result as a paste-ready correction prompt for the agent")
    parser.add_argument("--json", action="store_true", help="Print the result as JSON")
    parser.add_argument("--blind-is-fail", action="store_true", help="Exit 2 when any rule could not look")
    args = parser.parse_args(argv)

    if args.report == "-":
        report = sys.stdin.read()
    else:
        rp = Path(args.report)
        if not rp.exists():
            print(f"Error: report {args.report} does not exist.", file=sys.stderr)
            sys.exit(1)
        report = rp.read_text(encoding="utf-8", errors="ignore")

    tree = Path(args.tree)
    if not tree.is_dir():
        print(f"Error: tree {args.tree} is not a directory.", file=sys.stderr)
        sys.exit(1)

    diff = None
    if args.diff:
        dp = Path(args.diff)
        if not dp.exists():
            print(f"Error: diff {args.diff} does not exist.", file=sys.stderr)
            sys.exit(1)
        diff = dp.read_text(encoding="utf-8", errors="ignore")

    rep = audit_claims(report, tree, diff=diff, run_tests=args.run_tests, test_timeout=args.test_timeout)

    code_findings = []
    if diff is not None and not args.no_code_tier:
        code_findings = MomusScanner(allowlist=_load_allowlist(args.allowlist)).scan_diff(diff, file_path=args.diff)

    if args.json:
        d = rep.to_dict()
        d["code_tier"] = [f.__dict__ for f in code_findings]
        print(json.dumps(d, indent=2))
    elif args.as_prompt:
        print(render_prompt(rep, code_findings=code_findings))
    else:
        print(render_table(rep))
        if code_findings:
            print("\nCODE TIER (from the diff)\n")
            for f in code_findings:
                print(f"[{f.rule_name}] {f.file_path}:{f.line_number}")
                print(f"  Reason: {f.message}")
                if f.fix:
                    print(f"  Fix: {f.fix}")
                print()

    if rep.failed or code_findings:
        sys.exit(1)
    if rep.blind and args.blind_is_fail:
        sys.exit(2)
    sys.exit(0)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "claims":
        run_claims(argv[1:])
    else:
        run_scan(argv)


if __name__ == "__main__":
    main()
