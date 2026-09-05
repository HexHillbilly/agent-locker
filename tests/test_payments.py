"""x402 Base USDC payment rail tests (mocked RPC, no network)."""
import sqlite3

import httpx
import pytest

from lockerd import config as cfg
from lockerd import payments
from lockerd.main import create_app

USDC_CONTRACT = cfg.DEFAULT_USDC_CONTRACT
WALLET = "0x" + "ab" * 20          # 40-hex recipient
PAYER = "0x" + "cd" * 20
TRANSFER_TOPIC = payments.TRANSFER_EVENT_TOPIC


def _topic_for(address: str) -> str:
    return "0x" + "0" * 24 + address[2:].lower()


def make_transfer_log(recipient, amount_units, contract=USDC_CONTRACT, payer=PAYER):
    return {
        "address": contract,
        "topics": [TRANSFER_TOPIC, _topic_for(payer), _topic_for(recipient)],
        "data": "0x" + format(amount_units, "064x"),
    }


def make_receipt(status="0x1", logs=None):
    return {"status": status, "logs": logs or []}


@pytest.fixture
async def x402_client(tmp_path, monkeypatch):
    app = create_app(cfg.Config(
        db_path=str(tmp_path / "pay.db"),
        auth_mode=cfg.AUTH_X402,
        payment_wallet_address=WALLET,
    ))
    receipts = {}

    async def fake_fetch(rpc_url, tx_hash):
        return receipts.get(tx_hash)

    monkeypatch.setattr(payments, "get_transaction_receipt", fake_fetch)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            yield c, receipts


# 1. Bypass: local mode never requires payment
async def test_local_bypasses_payment(tmp_path):
    app = create_app(cfg.Config(db_path=str(tmp_path / "l.db"), auth_mode=cfg.AUTH_LOCAL))
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            r = await c.post("/v1/pads", json={"ttl_seconds": 60, "max_blocks": 4})
            assert r.status_code == 201


# 2. Challenge: x402 without proof -> 402 + challenge + WWW-Authenticate
async def test_x402_challenge_without_proof(x402_client):
    client, _ = x402_client
    r = await client.post("/v1/pads", json={"ttl_seconds": 60, "max_blocks": 4})
    assert r.status_code == 402
    body = r.json()
    assert body["error"] == "payment_required"
    assert body["network"] == "base"
    assert body["chain_id"] == 8453
    assert body["currency"] == "USDC"
    assert body["token_contract"].lower() == USDC_CONTRACT.lower()
    assert body["amount_units"] == 2000
    assert body["amount"] == "0.002"
    assert body["recipient"].lower() == WALLET.lower()
    assert "instructions" in body
    www = r.headers["www-authenticate"]
    assert "X402" in www and WALLET in www and "USDC" in www


# 3. Success: valid receipt -> 201 + receipt recorded
async def test_x402_valid_payment(x402_client, tmp_path):
    client, receipts = x402_client
    tx = "0x" + "11" * 32
    receipts[tx] = make_receipt(logs=[make_transfer_log(WALLET, 2000)])
    r = await client.post("/v1/pads", json={"ttl_seconds": 60, "max_blocks": 4},
                          headers={"X-Payment-Proof": tx})
    assert r.status_code == 201
    conn = sqlite3.connect(str(tmp_path / "pay.db"))
    row = conn.execute(
        "SELECT tx_hash, amount_units, payer_address FROM payment_receipts WHERE tx_hash=?",
        (tx,),
    ).fetchone()
    conn.close()
    assert row is not None
    assert row[1] == 2000
    assert row[2] == PAYER.lower()


# 4. Replay: same tx_hash for a second pad -> rejected
async def test_x402_replay_rejected(x402_client):
    client, receipts = x402_client
    tx = "0x" + "22" * 32
    receipts[tx] = make_receipt(logs=[make_transfer_log(WALLET, 2000)])
    r1 = await client.post("/v1/pads", json={"ttl_seconds": 60, "max_blocks": 4},
                           headers={"X-Payment-Proof": tx})
    assert r1.status_code == 201
    r2 = await client.post("/v1/pads", json={"ttl_seconds": 60, "max_blocks": 4},
                           headers={"X-Payment-Proof": tx})
    assert r2.status_code == 409


# 5. Reverted TX -> 402
async def test_x402_reverted_tx_rejected(x402_client):
    client, receipts = x402_client
    tx = "0x" + "33" * 32
    receipts[tx] = make_receipt(status="0x0", logs=[make_transfer_log(WALLET, 2000)])
    r = await client.post("/v1/pads", json={"ttl_seconds": 60, "max_blocks": 4},
                          headers={"X-Payment-Proof": tx})
    assert r.status_code == 402


# 6a. Wrong recipient -> 402
async def test_x402_wrong_recipient_rejected(x402_client):
    client, receipts = x402_client
    tx = "0x" + "44" * 32
    receipts[tx] = make_receipt(logs=[make_transfer_log("0x" + "99" * 20, 2000)])
    r = await client.post("/v1/pads", json={"ttl_seconds": 60, "max_blocks": 4},
                          headers={"X-Payment-Proof": tx})
    assert r.status_code == 402


# 6b. Underpaid -> 402
async def test_x402_underpaid_rejected(x402_client):
    client, receipts = x402_client
    tx = "0x" + "55" * 32
    receipts[tx] = make_receipt(logs=[make_transfer_log(WALLET, 1999)])
    r = await client.post("/v1/pads", json={"ttl_seconds": 60, "max_blocks": 4},
                          headers={"X-Payment-Proof": tx})
    assert r.status_code == 402


# Config error: x402 mode with no wallet configured -> 500
async def test_x402_missing_wallet_config(tmp_path):
    app = create_app(cfg.Config(db_path=str(tmp_path / "w.db"), auth_mode=cfg.AUTH_X402))
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            r = await c.post("/v1/pads", json={"ttl_seconds": 60, "max_blocks": 4},
                             headers={"X-Payment-Proof": "0x1234"})
            assert r.status_code == 500
