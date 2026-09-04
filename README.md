# Momus Agent Firewall

**Everyone scans the code. Momus reads the report.**

Your agent says *"done, 34 tests pass."* Momus counts the test functions in the tree, runs
them, and checks whether 34 is a number that exists. It reads the figure the agent quoted
and looks for it in the source, and if it only ever appears as the tail of a longer number,
it says so. It opens the checker the agent wrote and asks whether that checker can go red at
all. Then it hands the agent one block of text: what was wrong, and what to do about it.

Nothing in it consults a model. Every rule is a regex or an AST walk, so the same input gives
the same verdict every time, and every rule ends in one of three states:

```
PASS            it looked, and found nothing
FAIL            it looked, and found something
COULD NOT LOOK  it could not check, and says so instead of passing
```

A gate that cannot say "I could not look" will say "pass." That is the bug this repo exists
to refuse.

## Why it exists

A payment address in one of my own projects carried a code comment asserting it was my
verified wallet. It was not mine. That comment stood for five weeks, through a grant
application and past two separate reviews, because every check that looked at it read the
comment.

When an agent later changed that address, my own audit called the change unauthorized and
published that conclusion. **I was wrong the second time too.** I opened my wallet app and
the change turned out to have been sanctioned. Both halves of that episode produced a
confident, well-cited, wrong claim about who owned an address.

> **A label cannot corroborate itself, and a commit identity proves whose machine ran, never
> whose wallet it is.**

So the first tier checks values against an allowlist a human maintains, never against the
justification sitting next to them in the diff. The second tier came from months of auditing
agent deliveries and finding that the report is where the lying happens. In
[The Scoreboard](https://github.com/Themis-Foundry/the-scoreboard), 22 of 220 audited
deliveries claimed a verification that never took place. In half of those, the delivery's own
proof script passed.

## What it caught, on one fabricated delivery

`tests/claims/` ships two deliveries of the same job. One is honest. The other is what a
fabricating agent produces, and every rule in the second tier fires on it:

```
$ momus-firewall claims report.md --tree . --diff change.patch --run-tests

MOMUS · the claim tier

  counted-nothing  FAIL           3 finding(s)
  ran-nothing      FAIL           1 finding(s)
  clipped-number   FAIL           1 finding(s)
  quote-unbound    FAIL           1 finding(s)
  cannot-fail      FAIL           3 finding(s)
  carve-out        FAIL           1 finding(s)
  control-removed  FAIL           4 finding(s)

7 rules · 7 looked · 7 failed · 0 could not look

[counted-nothing] report:3
  The report says "34 tests". The tree holds 3 test function(s) (tests/test_offers.py: 3) and no file counts to 34.
  fix: State the number you observed after running the tests, or add the tests you claimed. Do not change the number without a run.

[ran-nothing] report:3
  The report says "34 tests passed". Momus ran pytest and observed 3 passed.
  fix: Change the count to 3, the number that actually ran, or add the tests you claimed.

[clipped-number] report:8
  The report gives 99,724. In the sources that figure only ever appears inside a longer one: 12,099,724 (filing.txt).
  fix: Read the whole number from filing.txt and replace 99,724 with it. A number parsed out of a quote is not evidence.

[carve-out] verify.py:6
  An assertion is skipped for rows matching a name or label: `if r["ticker"] == "CVBF":`. That is how a delivery exempts its own bad rows.
  fix: Remove the exemption. If the row is genuinely special, record it as a finding with the reason, not as a pass.

[control-removed] app/views.py:diff line 5
  The change deletes an auth or permission decorator and adds nothing in its place: `@login_required`.
  fix: Put an auth or permission decorator back, or say in the report why it is gone and what now does its job.
```

The honest delivery of the same job passes all seven. Both are in the test suite, and so is a
third thing: for every rule, a test that takes the honest delivery, corrupts exactly one
thing, and requires the rule to go red. A checker that has never failed is a decoration.

## The two tiers

**Tier 1 reads the code.** Four rules, the ones a dozen other scanners also have:
hallucinated wallet addresses checked against a human-maintained allowlist; secrets that
fall back to a default (`os.getenv("KEY", "x")`); controls deleted to get past friction
(`chmod 777`, `verify=False`, `shell=True`); placeholders left where finished work should be.

**Tier 2 reads the report.** Seven rules nobody else runs:

| rule | the question it asks the report |
|---|---|
| `counted-nothing` | you said 34. What in this tree counts to 34? |
| `ran-nothing` | you said the tests pass. I ran them. Did they, and how many? |
| `clipped-number` | you quoted 99,724. The source says 12,099,724. Which is it? |
| `quote-unbound` | you put that in quotation marks. Is that string in the file you cited? |
| `cannot-fail` | your checker swallows its own crash and asserts nothing. When would it ever say no? |
| `carve-out` | your checker skips rows named CVBF. Why that one? |
| `control-removed` | the diff deleted `@login_required` and skipped a test. Where did they go? |

The incident behind each rule is in [docs/adversarial_patterns.md](docs/adversarial_patterns.md).

## The criticism is the next prompt

Every finding carries a `fix:` line written as an instruction to the agent. With
`--as-prompt`, the whole result becomes one block you paste back:

```
Momus blocked this change. Fix every item below, then resubmit. Do not remove or weaken the checks that caught you.

1. [counted-nothing] report:3: The report says "34 tests". The tree holds 3 test function(s) ...
   Fix: State the number you observed after running the tests, or add the tests you claimed. ...
2. [clipped-number] report:8: The report gives 99,724. In the sources that figure only ever appears inside a longer one: 12,099,724 (filing.txt).
   Fix: Read the whole number from filing.txt and replace 99,724 with it. ...

Momus could not look at the following. Say so in your report; do not claim them as verified:
- ran-nothing: the report claims the tests pass (1 time(s)) and Momus was not allowed to run them; pass --run-tests
```

The loop closes by itself in Claude Code. [`hooks/claude_code/momus_hook.py`](hooks/claude_code/momus_hook.py)
treats the commit message as the report and the staged diff as the change. When the agent
runs `git commit -m "..."`, the hook runs both tiers and, if anything fails, **denies the
commit with the block above as the reason.** The agent reads it, fixes the work, and commits
again. You never see the first version.

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{"type": "command", "command": "MOMUS_RUN_TESTS=1 python3 /path/to/momus-agent-firewall/hooks/claude_code/momus_hook.py"}]
      }
    ]
  }
}
```

## Usage

```bash
pip install -e .

# Tier 1: the code
momus-firewall src/
momus-firewall change.patch --diff --allowlist allowlist.json
momus-firewall src/ --as-prompt

# Tier 2: the report, against the tree and the diff
momus-firewall claims PR_BODY.md --tree . --diff change.patch --run-tests
momus-firewall claims - --tree . < commit_message.txt      # report on stdin
momus-firewall claims VERIFICATION.md --tree . --json
momus-firewall claims report.md --tree . --blind-is-fail   # exit 2 if any rule could not look
```

Exit codes: `0` clean, `1` something failed, `2` nothing failed but a rule could not look and
you asked for that to count.

### As a GitHub Action

```yaml
name: AI PR Audit
on: [pull_request]

jobs:
  momus:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Write the PR body to a file
        run: printf '%s' "$PR_BODY" > /tmp/report.md
        env:
          PR_BODY: ${{ github.event.pull_request.body }}
      - name: Write the diff to a file
        run: git fetch origin ${{ github.base_ref }} && git diff origin/${{ github.base_ref }}...HEAD > /tmp/change.patch
      - name: Run Momus
        uses: Themis-Foundry/momus-agent-firewall@main
        with:
          path: .
          report: /tmp/report.md
          diff: /tmp/change.patch
          run_tests: "true"
          allowlist: .github/momus-allowlist.json
```

## What Momus will not do

It does not judge intent, and it never decides a value is safe because a comment says so. It
does not resolve package names or domains; other tools do that, use them too. It runs nothing
but `pytest`, and only when asked. And it cannot see what is not in the tree or the diff.
When that happens it says COULD NOT LOOK, in the output, every time.

The four code rules and the seven report rules all come from running agents against my own
repos. Each one is a pattern I hit and then wrote a check for. Treat the list as a record of
what went wrong here, not a taxonomy of everything that can.

## Tests

```bash
pip install pytest
pytest
```

45 tests. The 27 for the claim tier are the two deliveries, the seven controls, the three
states, and the CLI. Every one of the seven rules is proven able to fail before it is trusted
to pass.

## License

MIT.
