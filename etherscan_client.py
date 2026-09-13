"""
Wrapper around the Etherscan API calls I actually need: source code,
bytecode, and a list of recent transactions.

Spent more time on this file than I expected because the free tier
rate-limits pretty aggressively and it took a few crashes before I
added proper backoff instead of just letting requests fail outright.
"""
import time
import logging
import requests

import config

logger = logging.getLogger("chain_mind_auditor.etherscan")

# Etherscan sometimes returns HTTP 200 with an error message in the body,
# so we check both the HTTP status AND the payload's "status"/"message".
RATE_LIMIT_MARKERS = ("rate limit", "max calls per sec", "429")


class EtherscanError(Exception):
    """Raised when Etherscan returns a definitive (non-retryable) error."""


class RateLimiter:
    """Simple sleep-based limiter to stay under N calls/second."""

    def __init__(self, max_calls_per_sec: float):
        self.min_interval = 1.0 / max_calls_per_sec if max_calls_per_sec > 0 else 0
        self._last_call = 0.0

    def wait(self):
        now = time.monotonic()
        elapsed = now - self._last_call
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self._last_call = time.monotonic()


class EtherscanClient:
    def __init__(self, api_key: str = None, base_url: str = None):
        self.api_key = api_key or config.require_api_key()
        self.base_url = base_url or config.ETHERSCAN_BASE_URL
        self.limiter = RateLimiter(config.ETHERSCAN_MAX_CALLS_PER_SEC)
        self.max_retries = config.ETHERSCAN_MAX_RETRIES

    # ------------------------------------------------------------------
    # Low-level request handling with backoff
    # ------------------------------------------------------------------
    def _get(self, params: dict) -> dict:
        params = dict(params)
        params["apikey"] = self.api_key
        # Required since the V2 migration - one chain per request.
        params.setdefault("chainid", config.ETHERSCAN_CHAIN_ID)

        last_exc = None
        for attempt in range(1, self.max_retries + 1):
            self.limiter.wait()
            try:
                resp = requests.get(self.base_url, params=params, timeout=10)
            except requests.RequestException as exc:
                last_exc = exc
                backoff = min(2 ** attempt, 30)
                logger.warning(
                    "Network error (%s). Retrying in %ss (attempt %s/%s)",
                    exc, backoff, attempt, self.max_retries,
                )
                time.sleep(backoff)
                continue

            if resp.status_code == 429:
                backoff = min(2 ** attempt, 30)
                logger.warning(
                    "Etherscan rate limit hit (HTTP 429). Backing off %ss "
                    "(attempt %s/%s)", backoff, attempt, self.max_retries,
                )
                time.sleep(backoff)
                continue

            if resp.status_code >= 500:
                backoff = min(2 ** attempt, 30)
                logger.warning(
                    "Etherscan server error (%s). Retrying in %ss",
                    resp.status_code, backoff,
                )
                time.sleep(backoff)
                continue

            if resp.status_code != 200:
                raise EtherscanError(
                    f"Unexpected HTTP status {resp.status_code}: {resp.text[:200]}"
                )

            try:
                data = resp.json()
            except ValueError as exc:
                raise EtherscanError(f"Non-JSON response from Etherscan: {exc}")

            message = str(data.get("message", "")).lower()
            if any(marker in message for marker in RATE_LIMIT_MARKERS):
                backoff = min(2 ** attempt, 30)
                logger.warning(
                    "Etherscan reported rate limiting in payload. "
                    "Backing off %ss", backoff,
                )
                time.sleep(backoff)
                continue

            return data

        raise EtherscanError(
            f"Exceeded {self.max_retries} retries against Etherscan"
        ) from last_exc

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def get_source_code(self, address: str) -> dict:
        """Fetch verified source code + metadata for a contract address."""
        data = self._get({
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
        })
        result = data.get("result")
        if not result or not isinstance(result, list):
            # Surface Etherscan's actual message instead of hiding it -
            # this is usually more informative than "no source data"
            # (e.g. a bad key, missing chainid, or rate limit message).
            raise EtherscanError(
                f"No source data returned for {address}. "
                f"Etherscan said: {data.get('message')} / {result}"
            )
        return result[0]

    def get_bytecode(self, address: str) -> str:
        """Fetch the deployed runtime bytecode for a contract address."""
        data = self._get({
            "module": "proxy",
            "action": "eth_getCode",
            "address": address,
            "tag": "latest",
        })
        code = data.get("result", "")
        if not code or code == "0x":
            raise EtherscanError(
                f"No bytecode found at {address} (not a contract, or wrong network)"
            )
        return code

    def get_recent_transactions(self, address: str, limit: int = 20) -> list:
        """
        Fetch the most recent confirmed transactions for an address.

        Note: Etherscan's REST API does not expose the live mempool
        (pending/unconfirmed transactions) — that requires a node
        provider's WebSocket subscription (see mempool_monitor.py).
        This is used as the closest ingestion-side equivalent when only
        a REST API key is available.
        """
        data = self._get({
            "module": "account",
            "action": "txlist",
            "address": address,
            "startblock": 0,
            "endblock": 99999999,
            "page": 1,
            "offset": limit,
            "sort": "desc",
        })
        result = data.get("result", [])
        return result if isinstance(result, list) else []
