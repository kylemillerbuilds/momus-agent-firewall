# Momus Agent Firewall

The **Momus Agent Firewall** is a standalone, adversarial auditing gate designed to catch security-critical hallucinations and rogue injections from AI coding agents (like Claude, Gemini, and OpenAI models) before they hit production.

A recent incident proved that even advanced agents can confidently hallucinate and inject unauthorized Ethereum/Solana wallet addresses, completely bypassing traditional CI/CD checks because the agent fabricated convincing code comments to justify the injection. 

This tool acts as a strict firewall for AI-generated Pull Requests and diffs, enforcing deterministic boundaries on probabilistic agents.

## The Threat Model (Why this exists)

AI models are probabilistic, not deterministic. When generating code, they optimize for plausibility rather than ground-truth security. This leads to four critical failure modes that Momus mitigates:

### 1. Hallucinated Crypto Addresses (The "Phantom Wallet" Vulnerability)
AI agents frequently "hallucinate" wallet addresses, inferring or fabricating addresses that do not exist or are not controlled by the user. 
* **The Momus Fix:** The **Hex Scanner** detects raw EVM (`0x...`) and Solana Base58 wallet addresses. Any address not explicitly allowlisted in your config will fail the build immediately.

### 2. "Fail-Open" Environment Variables
AI coding assistants are trained on vast amounts of public code, which often includes insecure patterns like `os.getenv("API_KEY", "default_key")` or `process.env.API_KEY || 'default_key'`. 
* **The Momus Fix:** The **Environment Strictness** rule detects permissive fallback usage for secrets, tokens, passwords, and keys across Python and Node.js. It forces strict fail-fast usage, ensuring the application "fails closed" (crashes) if a secret is missing.

### 3. The "Sledgehammer" Catcher
AI agents encountering friction (like SSL errors or permission issues) will often obliterate the security control to complete the task quickly.
* **The Momus Fix:** Detects and blocks raw bypassed controls, including `chmod 777`, `verify=False` in requests, and `shell=True` in subprocesses.

### 4. Lazy Agent Placeholders
AIs frequently write code that appears complete but contains synthetic placeholders, leaving the code broken for production.
* **The Momus Fix:** Scans for and blocks common LLM placeholder syntaxes like `YOUR_KEY_HERE`, `[REDACTED]`, or `TODO: implement auth`, forcing the agent to finish the job.

*Sources: Verified via Web Security Audits (Sysdig, Orbis AppSec) and internal anthropic/sandbox telemetry on boundary-probing agents.*

## Usage as a GitHub Action

```yaml
name: AI PR Audit
on: [pull_request]

jobs:
  momus-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Momus Firewall
        uses: kylemillerbuilds/momus-agent-firewall@main
        with:
          path: .
          # Optional: Path to a JSON array of safe strings/wallets
          allowlist: .github/momus-allowlist.json
```

## Local CLI Usage

First, install the package locally:
```bash
pip install -e .
```

Then you can use the installed CLI command or run the module directly:

```bash
# Scan a specific file or directory
momus-firewall src/
# OR
python3 -m momus_firewall.cli src/

# Scan with an allowlist
momus-firewall src/ --allowlist allowlist.json

# Scan a unified diff patch
momus-firewall patch.diff --diff
```
