# Adversarial Audit Patterns

Momus-agent-firewall looks for the following patterns when validating agent execution:

## Sledgehammer Permissions
Agents often attempt to bypass friction rather than solving it correctly. We block:
- `chmod 777` (Blanket execution/write permissions)
- `verify=False` (Disabling SSL verification in web requests)
- Running commands with `sudo` when unnecessary or unauthorized.

## Lazy Placeholders
Agents sometimes generate incomplete code meant for a human to fill in. We flag:
- `YOUR_KEY_HERE`
- `TODO: Implement this`
- `<insert token>`

## Egress Validation
Every network call must be explicit and allowed.
- Fetches must match a strict scheme and host allowlist.
- Local/private IP space (`127.0.0.0/8`, `10.0.0.0/8`, `192.168.0.0/16`) is blocked by default to prevent internal reconnaissance.
