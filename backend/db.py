"""FalkorDB connection, query helpers and JSON serialisation for Blast Radius."""

from typing import Any, Optional
import time

from falkordb import FalkorDB

from backend.config import (
    FALKOR_HOST,
    FALKOR_PASSWORD,
    FALKOR_PORT,
    FALKOR_QUERY_TIMEOUT_MS,
    FALKOR_SSL,
    FALKOR_USERNAME,
    GRAPH_BACKEND,
    GRAPH_NAME,
)

_client: Optional[FalkorDB] = None
_last_probe: tuple[float, bool] = (0.0, False)


def get_client() -> FalkorDB:
    """Return a singleton FalkorDB client instance."""
    global _client
    if _client is None:
        kwargs: dict[str, Any] = {"host": FALKOR_HOST, "port": FALKOR_PORT}
        if FALKOR_USERNAME:
            kwargs["username"] = FALKOR_USERNAME
        if FALKOR_PASSWORD:
            kwargs["password"] = FALKOR_PASSWORD
        if FALKOR_SSL:
            kwargs["ssl"] = True
        _client = FalkorDB(**kwargs)
    return _client


def reset_client() -> None:
    """Forget the cached client (used after a failed connection so the next call retries)."""
    global _client
    _client = None


def is_online(max_age: float = 2.0) -> bool:
    """True if FalkorDB answers a trivial query. Result is cached for `max_age` seconds."""
    global _last_probe
    now = time.monotonic()
    if now - _last_probe[0] < max_age:
        return _last_probe[1]
    ok = False
    try:
        # PING the server (not a graph query: the graph does not exist before the first scan)
        ok = bool(get_client().connection.ping())
    except Exception:
        reset_client()
    _last_probe = (now, ok)
    return ok


def using_falkordb() -> bool:
    """True only when FalkorDB is selected and reachable."""
    return GRAPH_BACKEND == "falkordb" and is_online()


def active_engine() -> str:
    """Return the engine currently serving graph operations."""
    return "falkordb" if using_falkordb() else "sqlite"


def get_graph(name: str = GRAPH_NAME):
    """Return a FalkorDB Graph object for the specified graph name."""
    return get_client().select_graph(name)


def _timed(fn, query: str, params: Optional[dict[str, Any]]):
    start = time.perf_counter()
    result = fn(query, params or {}, timeout=FALKOR_QUERY_TIMEOUT_MS)
    wall_ms = (time.perf_counter() - start) * 1000.0
    ms = getattr(result, "run_time_ms", None)
    ms = round(float(ms), 2) if ms is not None and ms >= 0 else round(wall_ms, 2)
    rows = result.result_set if getattr(result, "result_set", None) is not None else []
    header = [h[1] if isinstance(h, (list, tuple)) and len(h) > 1 else str(h) for h in (result.header or [])]
    return header, rows, ms


def run(query: str, params: Optional[dict[str, Any]] = None, graph_name: str = GRAPH_NAME) -> tuple[list[Any], float, str]:
    """Execute a read-write parameterised Cypher query. Returns (rows, ms, cypher)."""
    g = get_graph(graph_name)
    _, rows, ms = _timed(g.query, query, params)
    return rows, ms, query


def ro_run(query: str, params: Optional[dict[str, Any]] = None, graph_name: str = GRAPH_NAME) -> tuple[list[Any], float, str]:
    """Execute a read-only parameterised Cypher query (GRAPH.RO_QUERY). Returns (rows, ms, cypher)."""
    g = get_graph(graph_name)
    _, rows, ms = _timed(g.ro_query, query, params)
    return rows, ms, query


def ro_run_full(query: str, params: Optional[dict[str, Any]] = None, graph_name: str = GRAPH_NAME) -> tuple[list[str], list[Any], float]:
    """Like ro_run but also returns the column names: (columns, rows, ms)."""
    g = get_graph(graph_name)
    return _timed(g.ro_query, query, params)


def _call(v: Any) -> Any:
    return v() if callable(v) else v


def serialize(value: Any) -> Any:
    """Convert FalkorDB Node / Edge / Path objects (and containers) to JSON-safe values."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (list, tuple)):
        return [serialize(v) for v in value]
    if isinstance(value, dict):
        return {str(k): serialize(v) for k, v in value.items()}
    cls = type(value).__name__
    if cls == "Node":
        props = serialize(dict(getattr(value, "properties", {}) or {}))
        return {"_type": "node", "labels": list(getattr(value, "labels", []) or []), **props}
    if cls == "Edge":
        return {
            "_type": "edge",
            "relation": getattr(value, "relation", None),
            **serialize(dict(getattr(value, "properties", {}) or {})),
        }
    if cls == "Path":
        nodes = _call(getattr(value, "nodes", [])) or []
        return {
            "_type": "path",
            "nodes": [dict(getattr(n, "properties", {}) or {}).get("id", str(n)) for n in nodes],
            "length": max(0, len(nodes) - 1),
        }
    return str(value)
