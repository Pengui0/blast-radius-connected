"""FastAPI REST & SSE API Server for Blast Radius.

Endpoints:
- POST /api/scan {roots} -> SSE ingest + analyze progress, then {type:'done',summary}
- GET /api/graph?mode=risk|full -> {nodes, links}
- GET /api/stats -> overview data
- GET /api/fixplan?max=5 -> fix plan data
- POST /api/simulate {fix_ids} -> simulation results
- GET /api/patch?fix_ids=a,b -> generated patch overrides, commands, and markdown
- GET /api/path?target= -> attack path hops
- POST /api/cypher {query} -> read-only Cypher results
- GET /api/presets -> preset definitions
- GET /api/agent/stream?q= -> SSE event stream from run_agent(q)
"""

import asyncio
import json
import math
import os
from typing import Any, AsyncGenerator, Literal

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from backend import tools
from backend.agent import run_agent
from backend.analyze import analyze
from backend.config import API_PORT, CACHE_DIR, GEMINI_API_KEY
from backend.db import active_engine, using_falkordb
from backend.ingest import (
    PRESETS,
    ingest,
    load_snapshot_into_falkor,
    read_cache,
    validate_roots,
    write_cache,
)

app = FastAPI(
    title="Blast Radius API",
    description="Supply-chain security triage with local SQLite and optional FalkorDB graph intelligence",
    version="1.0.0",
)

# CORS: explicit dev origins only (the UI normally goes through the same-origin proxy anyway)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Only one scan / preset switch may rewrite the graph at a time.
_graph_lock = asyncio.Lock()


# Request schemas
class ScanRequest(BaseModel):
    roots: list[str]


class SimulateRequest(BaseModel):
    fix_ids: list[str]


class CypherRequest(BaseModel):
    query: str


class ToolExecRequest(BaseModel):
    tool: str
    args: dict[str, Any] = {}


@app.get("/")
def health_check() -> dict[str, str]:
    return {"status": "ok", "app": "Blast Radius", "version": "1.0.0"}


@app.get("/api/health")
def health() -> dict[str, Any]:
    """Which engine is answering and whether the agent is live or replaying."""
    mode = os.getenv("AGENT_MODE", "").lower()
    agent = "replay" if (mode == "replay" or not GEMINI_API_KEY) else "live"
    return {"falkordb": using_falkordb(), "engine": active_engine(), "agent": agent}


def _preset_metrics(key: str) -> dict[str, Any]:
    snap = read_cache(f"snapshot_{key}.json") or {}
    vulns = snap.get("vulns", {})
    total = sum(float(v.get("risk", 0.0)) for v in vulns.values())
    return {
        "packages": len(snap.get("packages", {})),
        "vulns": len(vulns),
        "blastScore": round(100.0 * total / (total + 60.0)) if total > 0 else 0,
        "seeded": bool(snap),
    }


@app.get("/api/presets")
def get_presets() -> dict[str, Any]:
    """Seeded presets with real metrics computed from their saved snapshots."""
    descriptions = {
        "legacy_react": "React SPA toolchain with legacy build pipelines and an unpatched HTTP client.",
        "zombie_express": "Backend service using the abandoned request client and older Express middleware.",
        "kitchen_sink": "Combined frontend and backend legacy dependency trees.",
    }
    names = {
        "legacy_react": "Legacy React App",
        "zombie_express": "Zombie Express API",
        "kitchen_sink": "Kitchen Sink Full-Stack",
    }
    return {
        key: {"id": key, "name": names.get(key, key), "roots": roots,
              "description": descriptions.get(key, ""), **_preset_metrics(key)}
        for key, roots in PRESETS.items()
    }


@app.post("/api/scan")
async def scan_roots(req: ScanRequest) -> StreamingResponse:
    """Ingest + analyse custom roots, streaming progress as SSE."""
    try:
        roots = validate_roots(req.roots)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    if _graph_lock.locked():
        raise HTTPException(status_code=409, detail="Another scan is already running.")

    async def event_generator() -> AsyncGenerator[str, None]:
        async with _graph_lock:
            try:
                async for progress in ingest(roots):
                    yield f"data: {json.dumps(progress)}\n\n"
                yield f"data: {json.dumps({'stage': 'analyze', 'msg': 'Running PageRank, betweenness, community detection and fix synthesis'})}\n\n"
                summary = await asyncio.to_thread(analyze)
                yield f"data: {json.dumps({'type': 'done', 'summary': summary})}\n\n"
            except Exception as e:
                yield f"data: {json.dumps({'type': 'error', 'msg': str(e)})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/api/graph")
def get_graph_data(mode: Literal["risk", "full"] = Query("risk")) -> dict[str, Any]:
    """Nodes/links for the force graph (read from FalkorDB when online).

    'risk' = App + exposed packages + vulnerable packages; 'full' = the entire DAG.
    Advisories are attached to their package nodes as `vulns`.
    """
    return tools.graph_view(mode)


@app.get("/api/stats")
def get_stats() -> dict[str, Any]:
    """Retrieve repository security overview and Blast Score metrics."""
    res = tools.overview()
    return {**res["data"], "engine": res["engine"]}


@app.get("/api/fixplan")
def get_fix_plan(max: int = Query(5, ge=1, le=20)) -> dict[str, Any]:
    """Retrieve greedy set-cover prioritized fix plan."""
    return tools.fix_plan(max_actions=max)["data"]


@app.post("/api/simulate")
def simulate_fixes(req: SimulateRequest) -> dict[str, Any]:
    """Non-destructively simulate remediation impact of input fix IDs."""
    return tools.simulate(req.fix_ids)["data"]


@app.get("/api/patch")
def get_patch(fix_ids: str = Query("")) -> dict[str, Any]:
    """Generate package.json overrides, shell remediation commands, and PR markdown."""
    parsed_ids = [x.strip() for x in fix_ids.split(",") if x.strip()]
    return tools.build_patch(parsed_ids)["data"]


@app.get("/api/path")
def get_attack_path(target: str = Query(...)) -> dict[str, Any]:
    """Shortest App -> package/advisory chain, plus the advisory and its risk rank."""
    res = tools.attack_path(target)
    return {**res["data"], "engine": res["engine"], "ms": res["ms"]}


@app.post("/api/cypher")
def execute_cypher(req: CypherRequest) -> dict[str, Any]:
    """Read-only Cypher (LIMIT 200 enforced)."""
    return tools.cypher_ro(req.query)


@app.get("/api/agent/stream")
async def stream_agent(q: str = Query(...)) -> StreamingResponse:
    """Stream autonomous triage agent events via SSE."""
    async def sse_generator() -> AsyncGenerator[str, None]:
        try:
            async for event in run_agent(q):
                yield f"data: {json.dumps(event)}\n\n"
        except (asyncio.CancelledError, GeneratorExit):
            pass

    return StreamingResponse(sse_generator(), media_type="text/event-stream")


@app.post("/api/load-preset/{preset_name}")
async def load_preset(preset_name: str) -> dict[str, Any]:
    """Switch to a pre-seeded preset. Reloads FalkorDB too so graph and tools never disagree."""
    if preset_name not in PRESETS:
        raise HTTPException(status_code=404, detail=f"Unknown preset: {preset_name}")
    snap = read_cache(f"snapshot_{preset_name}.json")
    if not snap:
        raise HTTPException(status_code=404, detail=f"Preset '{preset_name}' is not seeded. Run: python -m backend.ingest seed")
    async with _graph_lock:
        write_cache("latest_graph_snapshot.json", snap)
        if using_falkordb():
            await asyncio.to_thread(load_snapshot_into_falkor, snap)
            await asyncio.to_thread(analyze)
    return tools.overview()


@app.post("/api/tools/execute")
def execute_tool_endpoint(req: ToolExecRequest) -> dict[str, Any]:
    """Execute any of the 10 FastMCP graph tools and return the full {data, cypher, ms, highlight} envelope."""
    t = req.tool
    a = req.args or {}
    if t == "overview":
        return tools.overview()
    elif t == "top_threats":
        return tools.top_threats(limit=int(a.get("limit", 5)))
    elif t == "attack_path":
        return tools.attack_path(target=str(a.get("target", "axios@0.21.1")))
    elif t == "blast_radius":
        return tools.blast_radius(package=str(a.get("package", "axios")))
    elif t == "chokepoints":
        return tools.chokepoints(limit=int(a.get("limit", 5)))
    elif t == "risk_clusters":
        return tools.risk_clusters()
    elif t == "fix_plan":
        return tools.fix_plan(max_actions=int(a.get("max_actions", 5)))
    elif t == "simulate":
        return tools.simulate(fix_ids=list(a.get("fix_ids", [])))
    elif t == "build_patch":
        return tools.build_patch(fix_ids=list(a.get("fix_ids", [])))
    elif t == "cypher_ro":
        return tools.cypher_ro(query=str(a.get("query", "")))
    else:
        return {"error": f"Unknown tool: {t}", "data": None, "cypher": "", "ms": 0.0, "highlight": {"nodes": [], "edges": []}}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=API_PORT, reload=False)
