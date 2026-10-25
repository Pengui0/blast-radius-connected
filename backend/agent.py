"""Autonomous Blast Radius incident-commander triage agent.

Connects to backend/mcp_server.py via stdio FastMCP and drives multi-turn
tool-calling reasoning using Google GenAI with automatic replay fallback.
"""

import asyncio
from collections import defaultdict
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Any, AsyncGenerator, Optional

from google import genai
from google.genai import types
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from backend.config import BASE_DIR, GEMINI_API_KEY, GEMINI_MODEL
from backend import tools
from backend.db import active_engine

REPLAYS_DIR: Path = BASE_DIR / "replays"
REPLAYS_DIR.mkdir(parents=True, exist_ok=True)

SYSTEM_PROMPT = (
    "You are BLAST RADIUS, an incident-commander style supply-chain triage agent. "
    "Never answer from memory: call tools. Rank by severity x exposure x fix effort. "
    "Back every claim with attack_path or blast_radius. Max 6 tool calls. "
    "End with one concrete next action and exact fix ids. Terse."
)


def get_slug(question: str) -> str:
    """Generate a clean slug identifier from question text."""
    q_lower = question.lower()
    if any(k in q_lower for k in ["fix", "plan", "patch", "remediat", "upgrade", "what if", "replace"]):
        return "remediation"
    elif any(k in q_lower for k in ["path", "attack", "chain", "how", "ingress", "why is"]):
        return "attack_path"
    elif any(k in q_lower for k in ["top", "threat", "severe", "cve", "ghsa", "triage"]):
        return "triage"
    clean = re.sub(r"[^\w\s-]", "", q_lower).strip()
    slug = re.sub(r"[-\s]+", "_", clean)
    return slug[:40] if slug else "default"


def _make_tool_summary(tool_name: str, data: Any) -> str:
    """Produce a concise, user-friendly 1-line summary for tool execution."""
    if not isinstance(data, dict):
        return f"{tool_name} returned {len(data) if isinstance(data, list) else 1} items"

    if tool_name == "overview":
        return f"{data.get('packages', 0)} pkgs, {data.get('vulns', 0)} vulns, Blast Score: {data.get('blastScore', 0)}"
    elif tool_name == "top_threats":
        return f"Top threats retrieved (highest risk: {data[0].get('id') if isinstance(data, list) and data else 'None'})"
    elif tool_name == "attack_path":
        if data.get("error"):
            return data["error"]
        return f"Shortest path: {data.get('depth', 0)} hops from App to {data.get('package', data.get('target'))}"
    elif tool_name == "blast_radius":
        return f"Dependents: {data.get('dependentsCount', 0)}, direct roots affected: {len(data.get('affectedDirectRoots', []))}"
    elif tool_name == "chokepoints":
        return f"Identified {len(data) if isinstance(data, list) else 0} direct dependency bottlenecks"
    elif tool_name == "risk_clusters":
        return f"Partitioned {len(data) if isinstance(data, list) else 0} community clusters"
    elif tool_name == "fix_plan":
        actions = data.get("actions", [])
        return f"Synthesized {len(actions)} actions, residual Blast: {data.get('finalBlastScore', 0)}"
    elif tool_name == "simulate":
        return (f"Simulated: Blast Score {data.get('initialBlastScore')} -> {data.get('simulatedBlastScore')}, "
                f"{data.get('healedVulnsCount', 0)} advisories resolved")
    elif tool_name == "build_patch":
        return "Generated package.json overrides and shell remediation commands"
    elif tool_name == "cypher_ro":
        return f"Cypher returned {len(data) if isinstance(data, list) else 1} rows"
    return f"{tool_name} executed successfully"


async def stream_replay(slug: str) -> AsyncGenerator[dict[str, Any], None]:
    """Stream cached event sequence from replays directory with realistic delay."""
    replay_file = REPLAYS_DIR / f"{slug}.json"
    if not replay_file.exists():
        replay_file = REPLAYS_DIR / "default.json"
    if not replay_file.exists():
        # Fall back to any available replay file
        available = list(REPLAYS_DIR.glob("*.json"))
        if available:
            replay_file = available[0]

    yield {"type": "meta", "mode": "replay", "engine": "recorded"}
    if replay_file.exists():
        try:
            with open(replay_file, "r", encoding="utf-8") as f:
                events = json.load(f)
            for event in events:
                await asyncio.sleep(0.04)
                yield event
            return
        except Exception:
            pass

    # Dynamic fallback generator if replay file is somehow corrupted
    t_over = tools.overview()
    yield {"type": "step", "id": "call_1", "tool": "overview", "args": {}}
    yield {
        "type": "result",
        "id": "call_1",
        "tool": "overview",
        "ms": t_over["ms"],
        "engine": t_over.get("engine"),
        "cypher": t_over["cypher"],
        "summary": _make_tool_summary("overview", t_over["data"]),
        "highlight": t_over["highlight"],
    }
    plan = tools.fix_plan(3)
    yield {
        "type": "final",
        "markdown": "### Blast Radius triage\n\nGraph evaluated live. Apply the ranked fixes below.",
        "evidence": [],
        "actions": [
            {"label": f"{a['pkg']} -> {a['toVersion']} ({a['tier']})", "fix_ids": [a["fixId"]]}
            for a in plan["data"]["actions"]
        ],
    }


async def run_agent(question: str) -> AsyncGenerator[dict[str, Any], None]:
    """Execute the Blast Radius triage agent.

    Spawns backend/mcp_server.py once via stdio_client, converts inputSchemas into
    Gemini function declarations, runs up to 7 manual tool-loop rounds with google-genai,
    and yields SSE-ready dicts ({step, result, final}).
    """
    mode = os.getenv("AGENT_MODE", "").lower()
    slug = get_slug(question)

    if mode == "replay":
        async for event in stream_replay(slug):
            yield event
        return

    # Check for Gemini API key
    if not GEMINI_API_KEY:
        print("[Agent] GEMINI_API_KEY missing, using replay stream.")
        async for event in stream_replay(slug):
            yield event
        return

    recorded_events: list[dict[str, Any]] = []
    yield {"type": "meta", "mode": "live", "engine": active_engine()}

    # Attempt live execution with fallback to replay on error
    try:
        async for event in _run_live_agent(question):
            recorded_events.append(event)
            yield event
    except Exception as exc:
        print(f"[Agent] live run failed: {type(exc).__name__}: {exc}")
        # Nothing streamed yet: fall back to a recorded replay (clearly labelled by its meta event)
        if not recorded_events:
            async for event in stream_replay(slug):
                yield event
        else:
            yield {
                "type": "final",
                "markdown": f"### Agent stopped early\n\nThe live run failed after {len(recorded_events)} events "
                            f"({type(exc).__name__}). Tool results above are real; ask again to retry.",
                "evidence": [],
                "actions": [],
            }


async def _run_live_agent(question: str) -> AsyncGenerator[dict[str, Any], None]:
    """Internal generator driving MCP stdio and Google GenAI manual tool loop."""
    server_params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "backend.mcp_server"],
        env=os.environ.copy(),
    )

    candidate_models = [GEMINI_MODEL]
    for alt_model in ["gemini-flash-latest", "gemini-3.1-flash-lite"]:
        if alt_model not in candidate_models:
            candidate_models.append(alt_model)

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # 1. Fetch available tools and convert inputSchema to Gemini FunctionDeclarations
            tools_list = await session.list_tools()
            func_declarations: list[types.FunctionDeclaration] = []

            for t in tools_list.tools:
                schema = dict(t.inputSchema) if t.inputSchema else {"type": "object", "properties": {}}
                # Clean extraneous keys that Gemini schema parser rejects
                for drop_key in ["$schema", "title"]:
                    schema.pop(drop_key, None)

                fd = types.FunctionDeclaration(
                    name=t.name,
                    description=t.description or f"Graph tool {t.name}",
                    parameters_json_schema=schema,
                )
                func_declarations.append(fd)

            gemini_tools = [types.Tool(function_declarations=func_declarations)]

            # 2. Initialize Gemini Client
            client = genai.Client(api_key=GEMINI_API_KEY)

            # Build conversation history
            contents: list[types.Content] = [
                types.Content(
                    role="user",
                    parts=[types.Part.from_text(text=question)],
                )
            ]

            config = types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0.2,
                tools=gemini_tools,
            )

            evidence_items: list[dict[str, Any]] = []
            action_items: list[dict[str, Any]] = []

            def _generate_blocking(current_contents: list[types.Content]) -> Any:
                last_error = None
                for model_choice in candidate_models:
                    try:
                        return client.models.generate_content(
                            model=model_choice,
                            contents=current_contents,
                            config=config,
                        )
                    except Exception as err:
                        last_error = err
                        continue
                if last_error:
                    raise last_error
                raise RuntimeError("No candidate models responded")

            async def generate_with_fallback(current_contents: list[types.Content]) -> Any:
                # the SDK call is blocking: run it off the event loop so SSE keeps flushing
                return await asyncio.to_thread(_generate_blocking, current_contents)

            # 3. Manual tool loop (up to 7 rounds)
            for round_idx in range(7):
                resp = await generate_with_fallback(contents)

                candidate = resp.candidates[0] if resp.candidates else None
                if not candidate:
                    break

                parts = candidate.content.parts if candidate.content else []
                # Check for function calls
                fn_calls = [p.function_call for p in parts if p.function_call]

                if not fn_calls:
                    # Model provided text answer without calling more tools
                    final_markdown = resp.text or ""
                    yield {
                        "type": "final",
                        "markdown": final_markdown,
                        "evidence": evidence_items,
                        "actions": action_items,
                    }
                    return

                # Record model's assistant turn with the function calls
                contents.append(candidate.content)

                # Execute calls and build tool responses
                tool_response_parts: list[types.Part] = []

                for c_idx, fn in enumerate(fn_calls):
                    call_id = f"call_{round_idx}_{c_idx}"
                    tool_name = fn.name
                    tool_args = fn.args if fn.args else {}

                    # Yield step event
                    yield {
                        "type": "step",
                        "id": call_id,
                        "tool": tool_name,
                        "args": tool_args,
                    }

                    # Execute via MCP session
                    start_time = time.perf_counter()
                    mcp_res = await session.call_tool(tool_name, tool_args)
                    exec_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

                    # Parse output envelope
                    raw_text = mcp_res.content[0].text if mcp_res.content and hasattr(mcp_res.content[0], "text") else "{}"
                    try:
                        parsed_env = json.loads(raw_text)
                    except Exception:
                        parsed_env = {"data": raw_text, "cypher": "", "ms": exec_ms, "highlight": {"nodes": [], "edges": []}}

                    data = parsed_env.get("data")
                    cypher_str = parsed_env.get("cypher", "")
                    reported_ms = parsed_env.get("ms", exec_ms)
                    highlight = parsed_env.get("highlight", {"nodes": [], "edges": []})
                    summary = _make_tool_summary(tool_name, data)

                    # Collect evidence from attack_path and blast_radius
                    if tool_name == "attack_path" and highlight.get("nodes"):
                        label = f"Attack Path: App -> {tool_args.get('target', 'Target')}"
                        evidence_items.append({"label": label, "nodes": highlight["nodes"], "edges": highlight["edges"]})
                    elif tool_name == "blast_radius" and highlight.get("nodes"):
                        label = f"Blast Radius: {tool_args.get('package', 'Package')}"
                        evidence_items.append({"label": label, "nodes": highlight["nodes"], "edges": highlight["edges"]})

                    # Collect actions from fix_plan or simulate
                    if tool_name == "fix_plan" and isinstance(data, dict):
                        for a in data.get("actions", [])[:3]:
                            action_items.append({
                                "label": f"Upgrade {a.get('pkg')} to {a.get('toVersion')} (Tier: {a.get('tier')})",
                                "fix_ids": [a.get("fixId")],
                            })
                    elif tool_name == "simulate" and isinstance(data, dict):
                        if tool_args.get("fix_ids"):
                            action_items.append({
                                "label": f"Apply simulated fixes: {', '.join(tool_args.get('fix_ids', []))}",
                                "fix_ids": tool_args.get("fix_ids", []),
                            })

                    # Yield result event
                    yield {
                        "type": "result",
                        "id": call_id,
                        "tool": tool_name,
                        "ms": reported_ms,
                        "engine": parsed_env.get("engine"),
                        "cypher": cypher_str,
                        "summary": summary,
                        "highlight": highlight,
                    }

                    # Feed result back WITHOUT cypher and highlight to save tokens
                    tool_response_parts.append(
                        types.Part.from_function_response(
                            name=tool_name,
                            response={"data": data},
                        )
                    )

                # Append tool response turn to conversation history (Gemini requires role='user' for function responses)
                contents.append(
                    types.Content(
                        role="user",
                        parts=tool_response_parts,
                    )
                )

            # If max rounds reached, yield final with last text
            yield {
                "type": "final",
                "markdown": "### ⚠️ Maximum Triage Rounds Reached\n\nIncident triage concluded. Inspect identified attack paths and execute prioritized remediation.",
                "evidence": evidence_items,
                "actions": action_items,
            }


async def record_run(question: str) -> None:
    """Execute live run and record the event sequence into backend/replays/{slug}.json."""
    slug = get_slug(question)
    out_file = REPLAYS_DIR / f"{slug}.json"
    print(f"[Record] Recording triage run for: '{question}' -> {out_file}")

    events = []
    try:
        async for event in _run_live_agent(question):
            print(f"  Event: {event.get('type')} ({event.get('tool', '')})")
            events.append(event)
    except Exception as exc:
        print(f"[Record] Live execution error ({exc}). Recording from verified graph run.")
        async for event in stream_replay(slug):
            events.append(event)

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2)

    print(f"[Record] Saved {len(events)} events to {out_file}")


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "record":
        q = sys.argv[2]
        asyncio.run(record_run(q))
    elif len(sys.argv) > 1:
        q = sys.argv[1]

        async def _main():
            async for ev in run_agent(q):
                if ev.get("type") == "step":
                    print(f"\n[STEP] Tool: {ev.get('tool')} Args: {ev.get('args')}")
                elif ev.get("type") == "result":
                    print(f"[RESULT] {ev.get('summary')} (Time: {ev.get('ms')} ms)")
                elif ev.get("type") == "final":
                    print("\n[FINAL RESPONSE]")
                    print(ev.get("markdown"))
                    print(f"Evidence items: {len(ev.get('evidence', []))}")
                    print(f"Action items: {len(ev.get('actions', []))}")

        asyncio.run(_main())
    else:
        print("Usage: python -m backend.agent <question>")
        print("       python -m backend.agent record <question>")
