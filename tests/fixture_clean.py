import os
def load_config():
    # Safe env var (no fallback)
    strict_token = os.getenv("PROD_TOKEN")
    return strict_token
