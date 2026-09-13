"""
Configuration loader for Chain-Mind Auditor.
Reads secrets from environment variables (or a local .env file) so API
keys never get hardcoded or committed to source control.
"""
import os
from dotenv import load_dotenv

load_dotenv()

ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY", "")

# Etherscan deprecated the old V1 endpoints on 2025-08-15. Every request
# now goes through the unified V2 endpoint and needs a chainid param
# (1 = Ethereum mainnet). See https://docs.etherscan.io/v2-migration
ETHERSCAN_BASE_URL = "https://api.etherscan.io/v2/api"
ETHERSCAN_CHAIN_ID = os.getenv("ETHERSCAN_CHAIN_ID", "1")

# Optional: a WebSocket provider URL (Infura/Alchemy) for real pending-tx
# streaming. Etherscan's REST API has no mempool endpoint, so true
# "pending transaction" ingestion requires a node provider's WSS feed.
MEMPOOL_WSS_URL = os.getenv("MEMPOOL_WSS_URL", "")

# Rate limiting: Etherscan free tier is ~5 req/sec (some plans 2/sec).
# Kept conservative and configurable.
ETHERSCAN_MAX_CALLS_PER_SEC = float(os.getenv("ETHERSCAN_MAX_CALLS_PER_SEC", "4"))
ETHERSCAN_MAX_RETRIES = int(os.getenv("ETHERSCAN_MAX_RETRIES", "5"))


def require_api_key() -> str:
    if not ETHERSCAN_API_KEY:
        raise RuntimeError(
            "ETHERSCAN_API_KEY is not set. Copy .env.example to .env and "
            "add your key (see README.md for how to get one)."
        )
    return ETHERSCAN_API_KEY
