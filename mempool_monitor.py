"""
Optional real-time pending-transaction ingestion.

Etherscan's REST API has no mempool endpoint, so genuine "pending
transaction" streaming requires a node provider's WebSocket subscription
(e.g. Infura, Alchemy, a self-hosted geth node with --ws). This module
subscribes to `newPendingTransactions`, fetches each transaction's full
payload, and runs it through the same pattern-matching engine used for
confirmed transactions.

Configure MEMPOOL_WSS_URL in .env, e.g.:
    MEMPOOL_WSS_URL=wss://mainnet.infura.io/ws/v3/<your-infura-project-id>

If not configured, this exits with a clear message instead of crashing.
"""
import asyncio
import json
import logging

import config
import pattern_engine

logger = logging.getLogger("chain_mind_auditor.mempool")


async def _listen():
    try:
        import websockets
    except ImportError:
        logger.error(
            "The 'websockets' package is required for mempool mode. "
            "Install it with: pip install websockets"
        )
        return

    if not config.MEMPOOL_WSS_URL:
        logger.error(
            "MEMPOOL_WSS_URL is not set. Add a node provider WSS URL to "
            ".env to use live mempool monitoring (see README.md)."
        )
        return

    subscribe_msg = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "eth_subscribe",
        "params": ["newPendingTransactions"],
    })

    backoff = 1
    while True:
        try:
            async with websockets.connect(config.MEMPOOL_WSS_URL) as ws:
                await ws.send(subscribe_msg)
                logger.info("Subscribed to pending transactions. Listening...")
                backoff = 1  # reset after a successful connection

                async for message in ws:
                    await _handle_message(ws, message)

        except Exception as exc:  # noqa: BLE001 - must never crash the loop
            logger.warning(
                "Mempool connection dropped (%s). Reconnecting in %ss.",
                exc, backoff,
            )
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30)


async def _handle_message(ws, message: str):
    try:
        payload = json.loads(message)
    except json.JSONDecodeError:
        logger.debug("Skipping non-JSON mempool message.")
        return

    params = payload.get("params", {})
    tx_hash = params.get("result")
    if not tx_hash:
        return  # subscription ack or unrelated message

    fetch_msg = json.dumps({
        "jsonrpc": "2.0", "id": 2, "method": "eth_getTransactionByHash",
        "params": [tx_hash],
    })
    try:
        await ws.send(fetch_msg)
        response = await asyncio.wait_for(ws.recv(), timeout=5)
        tx_data = json.loads(response).get("result")
    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not fetch tx %s: %s", tx_hash, exc)
        return

    if not tx_data:
        return

    findings = pattern_engine.analyze_transactions([tx_data], flood_window_count=999)
    for f in findings:
        print(f"[LIVE] {tx_hash}: {f['flag']} — {f['detail']}")


def run_mempool_monitor():
    try:
        asyncio.run(_listen())
    except KeyboardInterrupt:
        logger.info("Mempool monitor stopped.")
