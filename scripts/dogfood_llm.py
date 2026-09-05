#!/usr/bin/env python3
"""Live LLM dogfooding: two zero-context agent sessions over lockermcp.

A local LLM (Ollama by default) drives the lockermcp tools as a Planner, then a
fresh-context Worker, with an operator verification pass in between.

Run:  .venv/bin/python scripts/dogfood_llm.py [--model llama3.1:8b]
"""
import argparse
import asyncio
import json
import os
import subprocess
import sys

import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# --------------------------------------------------------------------------- #
# LLM client (Ollama /api/chat with tool calling)
# --------------------------------------------------------------------------- #
class OllamaClient:
    def __init__(self, base_url: str, model: str, temperature: float = 0.2):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.temperature = temperature

    def chat(self, messages, tools):
        r = httpx.post(
            f"{self.base_url}/api/chat",
            json={
                "model": self.model,
                "messages": messages,
                "tools": tools,
                "stream": False,
                "options": {"temperature": self.temperature},
            },
            timeout=600,
        )
        r.raise_for_status()
        return r.json()["message"]


# --------------------------------------------------------------------------- #
# MCP bridge
# --------------------------------------------------------------------------- #
def mcp_params(locker_url: str) -> StdioServerParameters:
    return StdioServerParameters(command=sys.executable, args=["-m", "lockermcp"],
                                 env={**os.environ, "LOCKER_URL": locker_url},
                                 cwd=REPO_ROOT)


def to_ollama_tools(tools):
    out = []
    for t in tools:
        out.append({
            "type": "function",
            "function": {
                "name": t.name,
                "description": t.description or "",
                "parameters": t.input_schema or {"type": "object", "properties": {}},
            },
        })
    return out


def coerce_args(args, schema):
    """LLMs often emit string-typed args; coerce per the tool's JSON schema."""
    if not isinstance(args, dict) or not isinstance(schema, dict):
        return args
    props = schema.get("properties", {})
    out = {}
    for k, v in args.items():
        typ = props.get(k, {}).get("type")
        if typ == "integer" and isinstance(v, str) and v.lstrip("-").isdigit():
            v = int(v)
        elif typ == "number" and isinstance(v, str):
            try:
                v = float(v)
            except ValueError:
                pass
        elif typ == "boolean" and isinstance(v, str):
            v = v.lower() in ("true", "1", "yes")
        elif typ in ("array", "object") and isinstance(v, str):
            try:
                v = json.loads(v)
            except json.JSONDecodeError:
                pass
        out[k] = v
    return out


async def call_mcp(session, name, args, schema):
    result = await session.call_tool(name, coerce_args(args, schema))
    if getattr(result, "structuredContent", None):
        return result.structuredContent
    for block in getattr(result, "content", []):
        if getattr(block, "text", None):
            try:
                return json.loads(block.text)
            except json.JSONDecodeError:
                return {"text": block.text}
    return {"text": str(result)}


async def run_agent(llm, session, schema_by_name, ollama_tools, system, user, label, max_iters=20):
    messages = [{"role": "system", "content": system},
                {"role": "user", "content": user}]
    log = []
    for i in range(max_iters):
        msg = await asyncio.to_thread(llm.chat, messages, ollama_tools)
        tool_calls = msg.get("tool_calls") or []
        if not tool_calls:
            print(f"[{label}] round {i}: final answer", flush=True)
            return msg.get("content", ""), log
        messages.append(msg)  # assistant message carrying the tool_calls
        for call in tool_calls:
            fn = call.get("function", {})
            name = fn.get("name", "")
            args = fn.get("arguments") or {}
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            print(f"[{label}] round {i}: {name} {json.dumps(args)[:160]}", flush=True)
            try:
                result = await call_mcp(session, name, args, schema_by_name.get(name, {}))
                status = "ok"
            except Exception as e:  # noqa: BLE001 — surface any transport error
                result = {"transport_error": str(e)}
                status = "error"
            print(f"[{label}] round {i}:   -> {json.dumps(result)[:160]}", flush=True)
            log.append({"name": name, "args": args, "status": status, "result": result})
            messages.append({"role": "tool", "content": json.dumps(result)})
    raise RuntimeError(f"{label}: exceeded {max_iters} tool-call rounds")


async def run_session(locker_url, llm, system, user, label):
    async with stdio_client(mcp_params(locker_url)) as (r, w):
        async with ClientSession(r, w) as session:
            await session.initialize()
            tools = (await session.list_tools()).tools
            schema_by_name = {t.name: t.input_schema for t in tools}
            final, log = await run_agent(llm, session, schema_by_name,
                                         to_ollama_tools(tools), system, user, label)
            return final, log, [t.name for t in tools]


# --------------------------------------------------------------------------- #
# Prompts
# --------------------------------------------------------------------------- #
PLANNER_SYSTEM = (
    "You are an orchestrator agent with access to lockermcp tools. Complete ALL "
    "FOUR steps, in order, without stopping early:\n"
    "1. Call locker_create with TTL 3600 seconds. Save the returned pad_id, "
    "write_key, and read_ticket.\n"
    "2. Call locker_append with Block 0: a locker.handoff.v1 envelope object with "
    "exactly these fields — schema='locker.handoff.v1', task_id (string), "
    "from_agent (string), to_agent (string), constraints (list of strings), "
    "artifacts (list of objects), budget_usd (number or null).\n"
    "3. Call locker_append AGAIN with Block 1: the concrete task artifact (a short "
    "Python utility specification).\n"
    "4. Call locker_seal.\n"
    "Do NOT stop until locker_seal has returned. Only then output the pad_id and "
    "read_ticket."
)

PLANNER_USER = (
    "Create a handoff. The task: specify a Python utility `topwords.py` that reads "
    "a text file and prints the 10 most frequent words (case-insensitive), skipping "
    "common stopwords. Put the complete specification in Block 1. Use the tools to "
    "create the pad, write both blocks, and seal it."
)

DEPOSIT_PLANNER_SYSTEM = (
    "You are an orchestrator agent with access to lockermcp tools. Use locker_deposit "
    "to create, write, and seal a pad in ONE atomic call. Then output ONLY the "
    "pad_id and read_ticket."
)

DEPOSIT_PLANNER_USER = (
    "Deposit a handoff. The task: specify a Python utility `topwords.py` that reads "
    "a text file and prints the 10 most frequent words (case-insensitive), skipping "
    "common stopwords. Build a valid locker.handoff.v1 envelope and pass the full "
    "specification as a single string in the artifacts list."
)

WORKER_SYSTEM = (
    "You are worker-agent with access to lockermcp tools. You are READ-ONLY: you "
    "may ONLY call locker_manifest and locker_read_blocks — NEVER locker_create, "
    "locker_append, or locker_seal. You have no prior context about the task. "
    "Steps:\n"
    "1. Call locker_manifest to read the pad state and confirm integrity.chain_valid "
    "is true.\n"
    "2. Call locker_read_blocks (defaults to Block 0) to read the envelope.\n"
    "3. Call locker_read_blocks with from_block=1 to read the task artifact (Block 1).\n"
    "4. Execute the task described in Block 1 and output the completed result as "
    "your final text answer. Do not call any write tools."
)


def summarize_result(r):
    if not isinstance(r, dict):
        return r
    if "error" in r:
        return f"ERROR({r['error'].get('status')}): {r['error'].get('detail')}"
    keys = [k for k in r if k in ("pad_id", "seq", "state", "block_count",
                                  "total_bytes", "integrity", "count", "head_hash")]
    return json.dumps({k: r[k] for k in keys}) if keys else json.dumps(r)[:200]


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
async def main() -> None:
    ap = argparse.ArgumentParser(description="LLM dogfooding of agent-locker")
    ap.add_argument("--model", default="llama3.1:8b")
    ap.add_argument("--ollama-url", default="http://localhost:11434")
    ap.add_argument("--locker-url", default="http://127.0.0.1:8000")
    ap.add_argument("--deposit", action="store_true",
                    help="planner uses the atomic locker_deposit tool instead of granular steps")
    ap.add_argument("--temperature", type=float, default=0.2)
    args = ap.parse_args()

    llm = OllamaClient(args.ollama_url, args.model, args.temperature)
    print(f"=== model={args.model} ollama={args.ollama_url} locker={args.locker_url} ===")

    # --- Session 1: Planner ---
    print("\n--- Session 1: Planner ---")
    psys, puser = (DEPOSIT_PLANNER_SYSTEM, DEPOSIT_PLANNER_USER) if args.deposit \
        else (PLANNER_SYSTEM, PLANNER_USER)
    final, log, tools = await run_session(args.locker_url, llm, psys, puser, "planner")
    print(f"tools available: {tools}")
    for t in log:
        print(f"  [{t['status']}] {t['name']}({json.dumps(t['args'])}) "
              f"-> {summarize_result(t['result'])}")
    print(f"planner final text: {final[:500]!r}")

    # map pad_id -> read_ticket from create/deposit results; find the sealed pad
    tickets = {}
    sealed_pad = None
    for t in log:
        r = t["result"]
        if t["status"] != "ok" or not isinstance(r, dict):
            continue
        if "pad_id" in r and "read_ticket" in r:
            tickets[r["pad_id"]] = r["read_ticket"]
            if r.get("status") == "sealed" and sealed_pad is None:
                sealed_pad = r["pad_id"]
        if t["name"] == "locker_seal" and "error" not in r:
            sealed_pad = t["args"].get("pad_id") or sealed_pad
    if sealed_pad and sealed_pad in tickets:
        pad_id, read_ticket = sealed_pad, tickets[sealed_pad]
    elif tickets:
        pad_id, read_ticket = next(iter(tickets.items()))
    else:
        print("\nFATAL: planner never successfully created a pad")
        sys.exit(1)
    print(f"\nhandoff pad: {pad_id} (sealed={bool(sealed_pad)})")

    # schema-compliance check: any 400 on append?
    validation_errors = [t for t in log
                         if isinstance(t["result"], dict) and "error" in t["result"]
                         and t["result"]["error"].get("status") == 400]
    print(f"\nplanner envelope validation errors: {len(validation_errors)}")
    for t in validation_errors:
        print(f"  -> {t['result']['error']['detail']}")

    # --- Operator verification ---
    print("\n--- Operator: inspect_pad.py ---")
    insp = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "scripts", "inspect_pad.py"),
         pad_id, "--ticket", read_ticket, "--url", args.locker_url],
        capture_output=True, text=True, timeout=60,
    )
    print(insp.stdout.strip() or insp.stderr.strip())

    # --- Session 2: Worker (zero-context) ---
    print("\n--- Session 2: Worker (zero context) ---")
    worker_user = f"pad_id: {pad_id}\nread_ticket: {read_ticket}"
    wfinal, wlog, wtools = await run_session(args.locker_url, llm, WORKER_SYSTEM,
                                             worker_user, "worker")
    for t in wlog:
        print(f"  [{t['status']}] {t['name']}({json.dumps(t['args'])}) "
              f"-> {summarize_result(t['result'])}")
    print(f"\nworker final result:\n{wfinal}")

    print("\n=== DOGFOOD RUN COMPLETE ===")


if __name__ == "__main__":
    asyncio.run(main())
