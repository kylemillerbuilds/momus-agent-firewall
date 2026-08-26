import os

def load_config():
    # Rule 2 Violation: using getenv with fallback for a secret
    api_key = os.getenv("API_KEY", "default_dev_key")
    wallet_secret = os.getenv('WALLET_SECRET', 'fallback_secret')
    
    # Safe env var (no fallback)
    strict_token = os.getenv("PROD_TOKEN")

def process_payment():
    # Rule 1 Violation: EVM address injection
    treasury_wallet = "0x89205A3A3b2A69De6Dbf7f01ED13B2108B2c43e7"
    
    # Rule 1 Violation: Solana base58 address injection
    sol_treasury = "HN7cABqLq46Es1jh92dQQisAq662SmxELLLsHHe4YWrH"
    
    # This should be skipped if in allowlist
    allowlisted_wallet = "0x0000000000000000000000000000000000000000"
    
    print(f"Sending funds to {treasury_wallet} and {sol_treasury}")

def fetch_data():
    # Rule 3 Violation: Sledgehammer (verify=False)
    import requests
    response = requests.get("https://api.example.com", verify=False)
    
    # Rule 3 Violation: Sledgehammer (shell=True)
    import subprocess
    subprocess.run("ls -la", shell=True)
    
    # Rule 4 Violation: Lazy Placeholder
    user_token = "YOUR_USER_TOKEN_HERE"
    secret_key = "[REDACTED]"
    
    # TODO: implement auth
    return True
    
    # Rule 2 JS Violation: process.env fallback
    # const apiKey = process.env.SECRET_API_KEY || "default_dev_key";
    
    return True
