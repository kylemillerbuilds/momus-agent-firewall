#!/usr/bin/env python3
"""Momus as a Claude Code PreToolUse hook: the commit message is the agent's report.

When the agent runs `git commit -m "..."`, this hook takes the message as the
report and the staged diff as the change, runs both tiers, and if anything fails
it DENIES the commit and hands the agent the correction prompt as the reason.
The agent reads the reason, fixes the work, and commits again. That is the whole
loop: the criticism is the next prompt.

Install (in .claude/settings.json):

    {
      "hooks": {
        "PreToolUse": [
          {
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": "python3 /path/to/momus_hook.py"}]
          }
        ]
      }
    }

Environment:
    MOMUS_RUN_TESTS=1       let Momus run pytest before allowing the commit
    MOMUS_ALLOWLIST=path    JSON array of allowed strings (wallets etc.)
    MOMUS_BLIND_IS_FAIL=1   deny when a rule could not look

This hook fails OPEN on its own errors: if Momus itself crashes, the commit
proceeds and the crash is printed to stderr. That is deliberate. The hook guards
against the agent's claims, not against its own bugs, and a firewall that blocks
every commit when it breaks gets uninstalled by lunchtime.
"""

import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from momus_firewall.claims import audit_claims, render_prompt  # noqa: E402
from momus_firewall.scanner import MomusScanner  # noqa: E402


def _commit_message(cmd: str):
    """The -m text(s) of a git commit command, or None if this is not a commit."""
    try:
        argv = shlex.split(cmd)
    except ValueError:
        return None
    if "git" not in argv or "commit" not in argv:
        return None
    msgs = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-m", "--message") and i + 1 < len(argv):
            msgs.append(argv[i + 1])
            i += 2
            continue
        if a.startswith("-m") and len(a) > 2:
            msgs.append(a[2:])
        elif a.startswith("--message="):
            msgs.append(a[len("--message="):])
        i += 1
    return "\n\n".join(msgs) if msgs else ""


def main():
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        return 0
    if payload.get("tool_name") != "Bash":
        return 0
    cmd = (payload.get("tool_input") or {}).get("command", "")
    msg = _commit_message(cmd)
    if msg is None:
        return 0

    cwd = payload.get("cwd") or os.getcwd()
    try:
        diff = subprocess.run(["git", "diff", "--cached"], capture_output=True, text=True, cwd=cwd, timeout=60).stdout
    except (OSError, subprocess.TimeoutExpired):
        diff = ""

    allow = []
    if os.environ.get("MOMUS_ALLOWLIST"):
        try:
            allow = json.load(open(os.environ["MOMUS_ALLOWLIST"]))
        except (OSError, ValueError):
            allow = []

    code = MomusScanner(allowlist=allow).scan_diff(diff, file_path="staged diff") if diff else []
    rep = audit_claims(msg, Path(cwd), diff=diff or None,
                       run_tests=os.environ.get("MOMUS_RUN_TESTS") == "1")

    blind_fail = os.environ.get("MOMUS_BLIND_IS_FAIL") == "1" and rep.blind
    if rep.failed or code or blind_fail:
        reason = render_prompt(rep, code_findings=code)
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # fail open, loudly
        print(f"momus_hook: could not run ({e!r}); allowing the command", file=sys.stderr)
        sys.exit(0)
