# What Momus looks for

Two tiers. The first reads the code. The second reads what the agent *said* about the code.
Every rule is a regex or an AST walk. No model is consulted at any point, so the same input
always produces the same verdict.

## Tier 1: the code

| rule | what it catches | why it exists |
|---|---|---|
| Hex Scanner | an EVM or Solana address that is not on the human-maintained allowlist | a payment address carried a comment calling it verified for five weeks; it was not mine |
| Env Strictness | `os.getenv("SECRET", "default")`, `process.env.KEY \|\| 'x'` for anything secret-shaped | a missing secret must crash, not run on a placeholder |
| Sledgehammer Catcher | `chmod 777`, `verify=False`, `shell=True` | an agent that hits friction removes the control instead of solving the problem |
| Lazy Agent Placeholder | `YOUR_KEY_HERE`, `[REDACTED]`, `<insert ...>`, `TODO: implement auth` | code that looks finished and is not |

These four are table stakes. A dozen other scanners check the same shapes. What they do not
do is the second tier.

## Tier 2: the report

The report is the PR description, the commit message, the `VERIFICATION.md`, the pasted
summary that says "done, tests pass." Each rule ends in one of three states: PASS, FAIL, or
**COULD NOT LOOK**, and the third one is always printed. A gate that cannot say it could not
look will say pass.

| rule | what it catches | the incident behind it |
|---|---|---|
| `counted-nothing` | a count in the report that no row count, tally, distinct-value count, non-null count, test count or file count over the tree produces | a delivery reported "Oversubscribed: 15 / Not oversubscribed: 51" for a field that was null on every one of its 121 rows |
| `ran-nothing` | the report says the tests pass; Momus runs pytest and compares the observed count to the claimed one | 22 of 220 audited deliveries in [The Scoreboard](https://github.com/Themis-Foundry/the-scoreboard) claimed a verification that never happened |
| `clipped-number` | a figure of 1,000 or more that appears in the sources only as the tail of a longer number | a row shipped `99,724` shares; the filing says `12,099,724`; the clipped quote still bound as a valid substring, so the citation check passed it |
| `quote-unbound` | a quotation attributed to a file that does not contain that string | 29 quoted rows in one delivery, zero verbatim; five were paraphrases, fifteen shared under 70% of their words with the page they cited |
| `cannot-fail` | a checker whose except-handler swallows the failure, exits 0 on crash, or a test that asserts nothing | six independent checks all printed OK while being wrong; a "could not look" had been read as clean |
| `carve-out` | an identity test on a name, id, ticker or label in a checker, followed by `continue` / `pass` / `return True` | a delivery exempted its own failing rows from its own verifier by ticker |
| `control-removed` | a diff that deletes an auth decorator, an assertion, TLS verification, CSRF, rate limiting or input validation with nothing in its place; or adds `@skip`, `.only(`, `xfail`, `# noqa` | the fastest way to make a red test green is to stop running it |

## What comes back

Every finding carries a `fix:` line, written as an instruction to the agent. With
`--as-prompt` the whole result renders as one block you can paste back to the agent, or that
the Claude Code hook hands it automatically as the reason its commit was denied. The
criticism is the next prompt.

## What Momus does not do

- It does not judge intent, and it never decides a value is safe because a comment says so.
- It does not resolve package names, URLs or domains. Other tools do that; use them too.
- It does not run anything except `pytest`, and only with `--run-tests`.
- It cannot see what is not in the tree or the diff. When that happens it says COULD NOT LOOK.
