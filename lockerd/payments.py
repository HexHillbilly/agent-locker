"""x402 payment challenge and Base USDC receipt verification."""
from __future__ import annotations

import logging

import httpx

logger = logging.getLogger("lockerd.payments")

BASE_CHAIN_ID = 8453
USDC_DECIMALS = 6
# keccak256("Transfer(address,address,uint256)")
TRANSFER_EVENT_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


class PaymentVerificationError(Exception):
    """Raised when a payment proof fails validation."""


def usdc_amount(units: int) -> str:
    """Human-readable USDC amount for an integer count of atomic units (6 decimals)."""
    return f"{units / 10 ** USDC_DECIMALS:.6f}".rstrip("0").rstrip(".")


def www_authenticate_header(wallet: str, required_units: int) -> str:
    return (f'X402 network="base", token="USDC", '
            f'amount="{usdc_amount(required_units)}", recipient="{wallet}"')


def build_challenge(wallet: str, usdc_contract: str, required_units: int) -> dict:
    return {
        "error": "payment_required",
        "network": "base",
        "chain_id": BASE_CHAIN_ID,
        "currency": "USDC",
        "token_contract": usdc_contract,
        "amount": usdc_amount(required_units),
        "amount_units": required_units,
        "recipient": wallet,
        "instructions": (
            f"Send {usdc_amount(required_units)} USDC on Base to {wallet}, then retry "
            f"with the header X-Payment-Proof: <transaction_hash>."
        ),
    }


async def get_transaction_receipt(rpc_url: str, tx_hash: str) -> dict:
    """Fetch the receipt for ``tx_hash`` via eth_getTransactionReceipt.

    Returns the parsed JSON-RPC ``result`` (a receipt dict) or ``None`` if the
    transaction is not (yet) known to the node.
    """
    payload = {"jsonrpc": "2.0", "id": 1, "method": "eth_getTransactionReceipt",
               "params": [tx_hash]}
    async with httpx.AsyncClient(timeout=15.0) as client:
        r = await client.post(rpc_url, json=payload)
        r.raise_for_status()
    data = r.json()
    if data.get("error"):
        raise PaymentVerificationError(f"RPC error: {data['error']}")
    return data.get("result")


def _address_from_topic(topic: str) -> str:
    return "0x" + topic[-40:].lower()


def validate_receipt(receipt, wallet: str, usdc_contract: str, required_units: int):
    """Validate a receipt. Returns ``(payer_address, amount_units)`` on success.

    Raises :class:`PaymentVerificationError` otherwise.
    """
    if not receipt:
        raise PaymentVerificationError("transaction not found")
    if receipt.get("status") != "0x1":
        raise PaymentVerificationError("transaction reverted")
    wallet_l = wallet.lower()
    contract_l = usdc_contract.lower()
    for log in receipt.get("logs", []):
        topics = log.get("topics") or []
        if not topics or topics[0].lower() != TRANSFER_EVENT_TOPIC:
            continue
        if (log.get("address") or "").lower() != contract_l:
            continue
        if len(topics) < 3:
            continue
        recipient = _address_from_topic(topics[2])
        if recipient != wallet_l:
            continue
        payer = _address_from_topic(topics[1])
        amount_units = int(log.get("data") or "0x0", 16)
        if amount_units < required_units:
            raise PaymentVerificationError(
                f"underpaid: {amount_units} units < {required_units} required")
        return payer, amount_units
    raise PaymentVerificationError("no USDC transfer to the payment wallet found")
