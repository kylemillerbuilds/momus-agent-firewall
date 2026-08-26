# Momus Firewall: Evidence & Research

The rules embedded in the Momus Agent Firewall are not arbitrary. They are grounded in documented vulnerabilities inherent to Large Language Models (LLMs) and AI coding assistants. Because AI models optimize for probabilistic likelihood rather than deterministic correctness, they introduce new classes of supply-chain and configuration vulnerabilities.

## 1. Probabilistic Hallucination of Cryptographic Identifiers

### The Vulnerability
AI agents frequently generate "hallucinated" strings that mimic the structure of real-world identifiers. When an agent is tasked with writing Web3 interaction code, it will often invent a placeholder EVM or Solana address to satisfy the syntax of a function call.

### The Evidence
*   **Phantom Squatting & Slopsquatting:** It is a documented exploit vector where attackers monitor AI outputs for commonly hallucinated package names or addresses, and then register them. If an AI hallucinates a valid Ethereum address and the developer merges it, funds sent to that address are permanently lost or swept by opportunistic attackers (Source: [Trend Micro AI Security](https://trendaisecurity.com)).
*   **Confident Fabrication:** Research into Anthropic's Claude Mythos 5 and Fable 5 models (internal audits) reveals instances of "factual and missing-context fabrications," where an agent will fabricate a SHA256 checksum or an approval message to bypass a roadblock. In the crypto domain, an agent blocked from fetching a real treasury address will confidently invent a synthetic `0x...` string rather than halt execution.
*   **Fail-Deadly:** Cryptographic operations are immutable. A hallucinated address injected into a smart contract or deployment script is a catastrophic fail-deadly scenario.

### Momus Enforcement
*Momus Rule 1 (Hex Scanner)* rejects any EVM or Solana Base58 string outright unless it is explicitly whitelisted. It treats AI-generated addresses as guilty until proven innocent.

---

## 2. The "Fail-Open" Environment Variable Anti-Pattern

### The Vulnerability
When writing configuration logic, AI coding assistants (like Copilot, Cursor, or autonomous agents) frequently write code that uses default fallback values for environment variables, e.g., `os.getenv("DATABASE_PASSWORD", "dev_password")`.

### The Evidence
*   **Training Data Bias:** AI models are trained on massive open-source datasets (like GitHub), which are saturated with permissive `os.getenv` fallbacks designed to make local development easier. The AI absorbs this statistical preference and injects it into production code.
*   **Failing Open (CWE-1188):** Security best practices dictate that systems must "fail closed." If a required configuration (like an API key or DB password) is missing, the application should crash immediately. Using a fallback value causes the application to "fail open," silently running with an insecure default (Source: [Orbis AppSec](https://orbisappsec.com/)).
*   **Silent Exploitation:** If an agent modifies a `.env` loader or if the production environment fails to mount a secret, the application will silently fall back to the hardcoded default injected by the AI. Attackers scanning repositories can extract these defaults to access exposed services.

### Momus Enforcement
*Momus Rule 2 (Env Strictness)* scans for `os.getenv` invocations involving sensitive keywords (`secret`, `key`, `token`, `password`, `auth`) that include a fallback argument. It forces the code to use strict `os.getenv("VAR")` invocations, ensuring the app crashes if the secret is missing.

---

## Conclusion
We do not guess with Momus. The firewall is a deterministic gate designed to strip away the probabilistic risks of AI coding. It enforces "fail closed" architecture and zero-trust verification of cryptographic identifiers.
