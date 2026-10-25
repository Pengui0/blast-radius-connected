"""Graph tools for Blast Radius supply-chain triage.

Conventions
- Every tool returns {data, cypher, ms, engine, highlight:{nodes, edges}}.
- engine == "falkordb": every number came from Cypher/graph algorithms run in FalkorDB and
  `cypher` is exactly what was executed.
- engine == "sqlite": results came from the local SQLite snapshot and networkx.
"""

from collections import defaultdict, deque
import json
import math
import re
import time
from typing import Any, Optional

import networkx as nx

from backend.db import active_engine, ro_run, ro_run_full, serialize, using_falkordb
from backend.ingest import read_cache

EFFORT = {"refresh": 1.0, "override": 2.0, "breaking": 4.0}
SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1, "NONE": 0}


# ----------------------------------------------------------------------------- helpers
def _blast(total_risk: float) -> int:
    return round(100.0 * total_risk / (total_risk + 60.0)) if total_risk > 0 else 0


def _env(data: Any, cypher: str, ms: float, nodes: list, edges: list, engine: str, **extra: Any) -> dict[str, Any]:
    out = {
        "data": data,
        "cypher": cypher.strip(),
        "ms": round(ms, 2),
        "engine": engine,
        "highlight": {"nodes": list(dict.fromkeys(nodes)), "edges": edges},
    }
    out.update(extra)
    return out


def _snapshot() -> dict[str, Any]:
    return read_cache("latest_graph_snapshot.json") or read_cache("snapshot_kitchen_sink.json") or {}


def _falkor() -> bool:
    return using_falkordb()


def _ms(t0: float) -> float:
    return (time.perf_counter() - t0) * 1000.0


def _flatten_unique(lists: Any) -> list[str]:
    out: list[str] = []
    for l in lists or []:
        for x in l or []:
            if x not in out:
                out.append(x)
    return out


def _state(fix_ids: Optional[list[str]] = None) -> dict[str, Any]:
    """Unified view of vuln risks, package->vulns and Fix nodes from the active engine."""
    ids = None
    if fix_ids is not None:
        ids = [f if f.startswith("fix:") else f"fix:{f}" for f in fix_ids]
    if _falkor():
        try:
            t0 = time.perf_counter()
            q_v = "MATCH (v:Vuln) RETURN v.id, v.risk"
            q_h = "MATCH (p:Package)-[:HAS_VULN]->(v:Vuln) RETURN p.id, collect(v.id)"
            q_f = (
                "MATCH (f:Fix) " + ("WHERE f.id IN $ids " if ids is not None else "")
                + "OPTIONAL MATCH (f)-[:TARGETS]->(p:Package) OPTIONAL MATCH (f)-[:RESOLVES]->(v:Vuln) "
                "RETURN f.id, f.pkg, f.toVersion, f.tier, f.clears, f.unfixed, f.riskCleared, "
                "collect(DISTINCT p.id), collect(DISTINCT v.id)"
            )
            rows_v, _, _ = ro_run(q_v)
            rows_h, _, _ = ro_run(q_h)
            rows_f, _, _ = ro_run(q_f, {"ids": ids} if ids is not None else {})
            fixes = {
                fid: {"id": fid, "pkg": pkg, "toVersion": to, "tier": tier, "clears": cl or 0,
                      "unfixed": uf or 0, "riskCleared": float(rc or 0.0), "targets": t or [], "resolves": r or []}
                for fid, pkg, to, tier, cl, uf, rc, t, r in rows_f
            }
            return {
                "engine": "falkordb",
                "ms": _ms(t0),
                "cypher": ";\n".join(q.strip() for q in (q_v, q_h, q_f)),
                "vuln_risk": {vid: float(r or 0.0) for vid, r in rows_v},
                "pkg_vulns": {pid: set(v) for pid, v in rows_h},
                "fixes": fixes,
            }
        except Exception as exc:
            print(f"[tools] FalkorDB state load failed, using the local SQLite snapshot: {exc}")
    t0 = time.perf_counter()
    snap = _snapshot()
    pkg_vulns: dict[str, set[str]] = defaultdict(set)
    for h in snap.get("has_vuln", []):
        pkg_vulns[h["pkgId"]].add(h["vulnId"])
    raw = snap.get("fixes", {}) or {}
    raw = raw if isinstance(raw, dict) else {f["id"]: f for f in raw}
    fixes = {fid: f for fid, f in raw.items() if ids is None or fid in ids}
    return {
        "engine": active_engine(),
        "ms": _ms(t0),
        "cypher": "-- Answered from the local SQLite snapshot with networkx --",
        "vuln_risk": {vid: float(v.get("risk", 0.0)) for vid, v in snap.get("vulns", {}).items()},
        "pkg_vulns": dict(pkg_vulns),
        "fixes": fixes,
    }


# ----------------------------------------------------------------------------- overview
def overview() -> dict[str, Any]:
    """Retrieve high-level supply-chain security metrics and the repository Blast Score.

    WHEN TO USE: at the start of triage or for an executive summary.
    """
    if _falkor():
        try:
            q1 = (
                "MATCH (p:Package) WITH count(p) AS packages "
                "OPTIONAL MATCH (v:Vuln) WITH packages, count(v) AS vulns, sum(v.risk) AS totalRisk "
                "MATCH (d:Package {direct: true}) "
                "RETURN packages, vulns, count(d) AS directDependencies, totalRisk, collect(d.id) AS directIds"
            )
            q2 = "MATCH (v:Vuln) RETURN v.severity AS severity, count(v) AS n"
            rows, ms1, _ = ro_run(q1)
            sev_rows, ms2, _ = ro_run(q2)
            if rows:
                pk, vl, dc, tr, dids = rows[0]
                tr = float(tr or 0.0)
                return _env(
                    {"packages": pk, "vulns": vl, "directDependencies": dc, "totalRisk": round(tr, 2),
                     "blastScore": _blast(tr), "bySeverity": {str(r[0]).upper(): r[1] for r in sev_rows},
                     "falkorMs": round(ms1 + ms2, 2), "engine": "falkordb"},
                    q1 + ";\n" + q2, ms1 + ms2, ["app"] + list(dids or []), [["app", d] for d in (dids or [])],
                    "falkordb",
                )
        except Exception as exc:
            print(f"[tools.overview] FalkorDB failed: {exc}")
    t0 = time.perf_counter()
    snap = _snapshot()
    pk, vulns = snap.get("packages", {}), snap.get("vulns", {})
    dids = [pid for pid, p in pk.items() if p.get("direct") or p.get("depth") == 1]
    by_sev: dict[str, int] = defaultdict(int)
    tr = 0.0
    for v in vulns.values():
        by_sev[str(v.get("severity", "MODERATE")).upper()] += 1
        tr += float(v.get("risk", 0.0))
    return _env(
        {"packages": len(pk), "vulns": len(vulns), "directDependencies": len(dids), "totalRisk": round(tr, 2),
         "blastScore": _blast(tr), "bySeverity": dict(by_sev), "falkorMs": None, "engine": active_engine()},
        "-- Answered from the local SQLite snapshot with networkx --", _ms(t0),
        ["app"] + dids, [["app", d] for d in dids], active_engine(),
    )


# ----------------------------------------------------------------------------- top_threats
def top_threats(limit: int = 10) -> dict[str, Any]:
    """Rank vulnerabilities by Vuln.risk (severity x exposure x proximity).

    WHEN TO USE: to decide which advisories need urgent attention.
    """
    limit = max(1, min(int(limit), 50))
    q = (
        "MATCH (v:Vuln)<-[h:HAS_VULN]-(p:Package) "
        "WITH v, collect(DISTINCT p.id) AS affectedPackages, collect(h.fixed) AS fixedLists "
        "RETURN v.id, v.severity, v.cvss, v.risk, v.summary, v.url, affectedPackages, fixedLists "
        "ORDER BY v.risk DESC LIMIT $limit"
    )
    if _falkor():
        try:
            rows, ms, _ = ro_run(q, {"limit": limit})
            threats, nodes, edges = [], [], []
            for vid, sev, cvss, risk, summ, url, pkgs, fixed in rows:
                threats.append({"id": vid, "severity": sev, "cvss": float(cvss or 5.5), "risk": float(risk or 0.0),
                                "summary": summ, "url": url, "affectedPackages": pkgs or [],
                                "fixed": _flatten_unique(fixed)})
                nodes += [vid] + list(pkgs or [])
                edges += [[p, vid] for p in pkgs or []]
            return _env(threats, q, ms, nodes, edges, "falkordb")
        except Exception as exc:
            print(f"[tools.top_threats] FalkorDB failed: {exc}")
    t0 = time.perf_counter()
    snap = _snapshot()
    pk_by_v, fx_by_v = defaultdict(set), defaultdict(list)
    for h in snap.get("has_vuln", []):
        pk_by_v[h["vulnId"]].add(h["pkgId"])
        fx_by_v[h["vulnId"]].extend(h.get("fixed", []))
    top = sorted(snap.get("vulns", {}).values(), key=lambda v: float(v.get("risk", 0)), reverse=True)[:limit]
    threats, nodes, edges = [], [], []
    for v in top:
        pkgs = sorted(pk_by_v.get(v["id"], []))
        threats.append({"id": v["id"], "severity": v.get("severity"), "cvss": float(v.get("cvss", 5.5)),
                        "risk": float(v.get("risk", 0)), "summary": v.get("summary", ""), "url": v.get("url", ""),
                        "affectedPackages": pkgs, "fixed": list(dict.fromkeys(fx_by_v[v["id"]]))})
        nodes += [v["id"]] + pkgs
        edges += [[p, v["id"]] for p in pkgs]
    return _env(threats, q, _ms(t0), nodes, edges, active_engine())


# ----------------------------------------------------------------------------- attack_path
_PATH_Q = (
    "MATCH (a:App {id: 'app'}), (p:Package {id: $pkgId}) "
    "WITH shortestPath((a)-[:DEPENDS_ON*]->(p)) AS path "
    "RETURN path, length(path) AS depth"
)


def _rank_reason(v: dict[str, Any], depth: Any, dependents: Any) -> str:
    d = int(depth) if depth is not None else 99
    dep = int(dependents or 0)
    mult = 1.5 if d <= 2 else 1.0
    return (f"risk = CVSS {v.get('cvss')} x (1 + log2(1 + {dep} upstream dependents)) x {mult} "
            f"(depth {d}) = {v.get('risk')}")


def attack_path(target: str) -> dict[str, Any]:
    """Find the shortest dependency chain from the App to a vulnerability id or package.

    WHEN TO USE: to prove HOW a vulnerable package reaches the application.
    """
    target = target.strip()
    if _falkor():
        try:
            return _attack_path_falkor(target)
        except Exception as exc:
            print(f"[tools.attack_path] FalkorDB failed: {exc}")
    return _attack_path_memory(target)


def _attack_path_falkor(target: str) -> dict[str, Any]:
    ms_total = 0.0
    vuln: Optional[dict[str, Any]] = None
    depth_p = deps_p = None
    rows, ms, _ = ro_run(
        "MATCH (v:Vuln {id: $t})<-[h:HAS_VULN]-(p:Package) "
        "RETURN p.id, p.depth, p.dependents, v.id, v.severity, v.cvss, v.risk, v.summary, v.url, h.fixed "
        "ORDER BY p.depth ASC LIMIT 1", {"t": target})
    ms_total += ms
    if rows:
        pid, depth_p, deps_p, vid, sev, cvss, risk, summ, url, fixed = rows[0]
        vuln = {"id": vid, "severity": sev, "cvss": cvss, "risk": risk, "summary": summ, "url": url, "fixed": fixed or []}
    else:
        rows, ms, _ = ro_run("MATCH (p:Package) WHERE p.id = $t OR p.name = $t "
                             "RETURN p.id, p.depth, p.dependents ORDER BY p.depth ASC LIMIT 1", {"t": target})
        ms_total += ms
        if not rows:
            return _env({"target": target, "error": f"No package or advisory matches '{target}'", "hops": [],
                         "path": [], "requirements": []}, _PATH_Q, ms_total, [], [], "falkordb")
        pid, depth_p, deps_p = rows[0]
        r2, ms, _ = ro_run("MATCH (:Package {id: $id})-[h:HAS_VULN]->(v:Vuln) "
                           "RETURN v.id, v.severity, v.cvss, v.risk, v.summary, v.url, h.fixed "
                           "ORDER BY v.risk DESC LIMIT 1", {"id": pid})
        ms_total += ms
        if r2:
            vid, sev, cvss, risk, summ, url, fixed = r2[0]
            vuln = {"id": vid, "severity": sev, "cvss": cvss, "risk": risk, "summary": summ, "url": url, "fixed": fixed or []}

    path_rows, ms, _ = ro_run(_PATH_Q, {"pkgId": pid})
    ms_total += ms
    if not path_rows or path_rows[0][0] is None:
        return _env({"target": target, "package": pid, "error": f"No dependency path from App to {pid}", "hops": [],
                     "path": [], "requirements": []}, _PATH_Q, ms_total, [], [], "falkordb")
    path_obj = path_rows[0][0]
    nodes_l = path_obj.nodes() if callable(path_obj.nodes) else path_obj.nodes
    edges_l = path_obj.edges() if callable(path_obj.edges) else path_obj.edges
    ids = [n.properties.get("id") for n in nodes_l]
    reqs = ["entry"] + [e.properties.get("req", "") for e in edges_l]
    hops = [{"hop": i, "node": nid, "req": reqs[i]} for i, nid in enumerate(ids)]
    h_nodes, h_edges = list(ids), [[ids[i - 1], ids[i]] for i in range(1, len(ids))]

    rank = None
    if vuln:
        hops.append({"hop": len(hops), "node": vuln["id"], "req": "HAS_VULN", "advisory": vuln})
        h_nodes.append(vuln["id"])
        h_edges.append([pid, vuln["id"]])
        rk, ms, _ = ro_run("MATCH (v:Vuln) WHERE v.risk > $r RETURN count(v)", {"r": float(vuln["risk"] or 0)})
        ms_total += ms
        rank = (rk[0][0] if rk else 0) + 1
    data = {"target": target, "package": pid, "depth": len(ids) - 1, "hops": hops, "path": ids, "requirements": reqs,
            "vuln": vuln, "rank": rank,
            "rankReason": _rank_reason(vuln, depth_p, deps_p) if vuln else None}
    return _env(data, _PATH_Q, ms_total, h_nodes, h_edges, "falkordb")


def _attack_path_memory(target: str) -> dict[str, Any]:
    t0 = time.perf_counter()
    snap = _snapshot()
    pkgs, vulns, has_vuln = snap.get("packages", {}), snap.get("vulns", {}), snap.get("has_vuln", [])
    vuln: Optional[dict[str, Any]] = None
    pid = None
    if target in vulns:
        cands = [(pkgs.get(h["pkgId"], {}).get("depth", 99), h["pkgId"], h) for h in has_vuln if h["vulnId"] == target]
        if cands:
            _, pid, h = min(cands, key=lambda c: c[0])
            vuln = {**vulns[target], "fixed": h.get("fixed", [])}
    else:
        cands = [p for p in pkgs.values() if p["id"] == target or p.get("name") == target]
        if cands:
            pid = min(cands, key=lambda p: p.get("depth", 99))["id"]
            mine = [(vulns[h["vulnId"]], h) for h in has_vuln if h["pkgId"] == pid and h["vulnId"] in vulns]
            if mine:
                v, h = max(mine, key=lambda x: float(x[0].get("risk", 0)))
                vuln = {**v, "fixed": h.get("fixed", [])}
    if not pid:
        return _env({"target": target, "error": f"No package or advisory matches '{target}'", "hops": [], "path": [],
                     "requirements": []}, _PATH_Q, _ms(t0), [], [], active_engine())
    g = nx.DiGraph()
    for e in snap.get("edges", []):
        g.add_edge(e["fromId"], e["toId"], req=e.get("req", ""))
    try:
        ids = nx.shortest_path(g, "app", pid)
    except Exception:
        return _env({"target": target, "package": pid, "error": f"No dependency path from App to {pid}", "hops": [],
                     "path": [], "requirements": []}, _PATH_Q, _ms(t0), [], [], active_engine())
    reqs = ["entry"] + [g[ids[i - 1]][ids[i]].get("req", "") for i in range(1, len(ids))]
    hops = [{"hop": i, "node": n, "req": reqs[i]} for i, n in enumerate(ids)]
    h_nodes, h_edges = list(ids), [[ids[i - 1], ids[i]] for i in range(1, len(ids))]
    rank = None
    if vuln:
        hops.append({"hop": len(hops), "node": vuln["id"], "req": "HAS_VULN", "advisory": vuln})
        h_nodes.append(vuln["id"])
        h_edges.append([pid, vuln["id"]])
        rank = 1 + sum(1 for v in vulns.values() if float(v.get("risk", 0)) > float(vuln.get("risk", 0)))
    p = pkgs.get(pid, {})
    data = {"target": target, "package": pid, "depth": len(ids) - 1, "hops": hops, "path": ids, "requirements": reqs,
            "vuln": vuln, "rank": rank,
            "rankReason": _rank_reason(vuln, p.get("depth"), p.get("dependents")) if vuln else None}
    return _env(data, _PATH_Q, _ms(t0), h_nodes, h_edges, active_engine())


# ----------------------------------------------------------------------------- blast_radius
def blast_radius(package: str) -> dict[str, Any]:
    """Map every upstream dependent (and affected direct dependency) of a package.

    WHEN TO USE: to size the collateral damage of changing or replacing a dependency.
    """
    pkg = package.strip()
    q = (
        "MATCH (p:Package) WHERE p.id = $pkg OR p.name = $pkg "
        "MATCH (p)-[:REQUIRED_BY*0..64]->(u:Package) "
        "RETURN DISTINCT u.id, u.name, u.version, u.direct, u.depth"
    )
    if _falkor():
        try:
            rows, ms, _ = ro_run(q, {"pkg": pkg})
            deps = [{"id": i, "name": n, "version": v, "direct": bool(d), "depth": dp} for i, n, v, d, dp in rows]
            ids = [d["id"] for d in deps]
            e_rows, ms2, _ = ro_run("MATCH (a:Package)-[:REQUIRED_BY]->(b:Package) WHERE a.id IN $n AND b.id IN $n "
                                    "RETURN a.id, b.id", {"n": ids})
            return _env({"package": pkg, "dependentsCount": len(deps),
                         "affectedDirectRoots": [d["id"] for d in deps if d["direct"]], "dependents": deps},
                        q, ms + ms2, ids, [[a, b] for a, b in e_rows], "falkordb")
        except Exception as exc:
            print(f"[tools.blast_radius] FalkorDB failed: {exc}")
    t0 = time.perf_counter()
    snap = _snapshot()
    pkgs = snap.get("packages", {})
    start = [pid for pid, p in pkgs.items() if pid == pkg or p.get("name") == pkg]
    g = nx.DiGraph()
    for e in snap.get("edges", []):
        if e["fromId"] != "app":
            g.add_edge(e["toId"], e["fromId"])
    seen = set(start)
    queue = deque(start)
    while queue:
        cur = queue.popleft()
        for nxt in g.successors(cur) if cur in g else []:
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    deps = [{"id": i, "name": pkgs.get(i, {}).get("name", i), "version": pkgs.get(i, {}).get("version", ""),
             "direct": bool(pkgs.get(i, {}).get("direct")), "depth": pkgs.get(i, {}).get("depth", 99)} for i in seen]
    edges = [[u, v] for u in seen for v in (g.successors(u) if u in g else []) if v in seen]
    return _env({"package": pkg, "dependentsCount": len(deps),
                 "affectedDirectRoots": [d["id"] for d in deps if d["direct"]], "dependents": deps},
                q, _ms(t0), list(seen), edges, active_engine())


# ----------------------------------------------------------------------------- chokepoints
def chokepoints(limit: int = 5) -> dict[str, Any]:
    """Rank direct dependencies by the vulnerability risk that ONLY flows through them.

    WHEN TO USE: to find the root-cause dependency worth replacing or upgrading.
    """
    limit = max(1, min(int(limit), 25))
    q = (
        "MATCH (a:App)-[:DEPENDS_ON]->(d:Package) "
        "RETURN d.id, d.name, d.version, d.vulnFlow, d.exclusiveRisk, d.betweenness "
        "ORDER BY d.exclusiveRisk DESC, d.betweenness DESC LIMIT $limit"
    )
    if _falkor():
        try:
            rows, ms, _ = ro_run(q, {"limit": limit})
            cps = [{"id": i, "name": n, "version": v, "vulnFlow": fl or 0, "exclusiveRisk": float(ex or 0.0),
                    "betweenness": float(bw or 0.0), "chokepointScore": round(float(ex or 0.0), 2)}
                   for i, n, v, fl, ex, bw in rows]
            return _env(cps, q, ms, ["app"] + [c["id"] for c in cps], [["app", c["id"]] for c in cps], "falkordb")
        except Exception as exc:
            print(f"[tools.chokepoints] FalkorDB failed: {exc}")
    t0 = time.perf_counter()
    pk = _snapshot().get("packages", {})
    cps = [{"id": p["id"], "name": p["name"], "version": p["version"], "vulnFlow": int(p.get("vulnFlow", 0)),
            "exclusiveRisk": float(p.get("exclusiveRisk", 0.0)), "betweenness": float(p.get("betweenness", 0.0)),
            "chokepointScore": round(float(p.get("exclusiveRisk", 0.0)), 2)}
           for p in pk.values() if p.get("direct") or p.get("depth") == 1]
    cps.sort(key=lambda c: (c["exclusiveRisk"], c["betweenness"]), reverse=True)
    cps = cps[:limit]
    return _env(cps, q, _ms(t0), ["app"] + [c["id"] for c in cps], [["app", c["id"]] for c in cps], active_engine())


# ----------------------------------------------------------------------------- risk_clusters
def risk_clusters() -> dict[str, Any]:
    """Group packages into communities (label propagation) and show each one's share of risk.

    WHEN TO USE: to see which sub-ecosystem carries most of the risk.
    """
    q = (
        "MATCH (p:Package) OPTIONAL MATCH (p)-[:HAS_VULN]->(v:Vuln) "
        "WITH p.community AS communityId, count(DISTINCT p) AS packageCount, collect(DISTINCT v) AS vs, "
        "collect(DISTINCT p.name)[..5] AS samplePackages "
        "RETURN communityId, packageCount, size(vs) AS vulnCount, "
        "reduce(s = 0.0, x IN vs | s + x.risk) AS totalRisk, samplePackages ORDER BY totalRisk DESC"
    )
    if _falkor():
        try:
            rows, ms, _ = ro_run(q)
            grand = sum(float(r[3] or 0) for r in rows) or 1.0
            clusters = [{"communityId": c, "packageCount": pc, "vulnCount": vc, "totalRisk": round(float(tr or 0), 2),
                         "riskSharePercent": round(100.0 * float(tr or 0) / grand, 1), "samplePackages": sp or []}
                        for c, pc, vc, tr, sp in rows]
            nodes: list[str] = []
            if clusters and clusters[0]["totalRisk"] > 0:
                top, ms2, _ = ro_run("MATCH (p:Package {community: $c}) RETURN p.id LIMIT 60", {"c": clusters[0]["communityId"]})
                nodes = [r[0] for r in top]
                ms += ms2
            return _env(clusters, q, ms, nodes, [], "falkordb")
        except Exception as exc:
            print(f"[tools.risk_clusters] FalkorDB failed: {exc}")
    t0 = time.perf_counter()
    snap = _snapshot()
    pkgs, vulns = snap.get("packages", {}), snap.get("vulns", {})
    pv = defaultdict(set)
    for h in snap.get("has_vuln", []):
        pv[h["pkgId"]].add(h["vulnId"])
    comm_p, comm_v = defaultdict(list), defaultdict(set)
    for pid, p in pkgs.items():
        comm_p[p.get("community", 0)].append(p)
        comm_v[p.get("community", 0)].update(pv.get(pid, set()))
    grand = sum(float(v.get("risk", 0)) for v in vulns.values()) or 1.0
    clusters = []
    for cid, plist in comm_p.items():
        risk = sum(float(vulns[v].get("risk", 0)) for v in comm_v[cid] if v in vulns)
        clusters.append({"communityId": cid, "packageCount": len(plist), "vulnCount": len(comm_v[cid]),
                         "totalRisk": round(risk, 2), "riskSharePercent": round(100 * risk / grand, 1),
                         "samplePackages": list(dict.fromkeys(p["name"] for p in plist))[:5]})
    clusters.sort(key=lambda c: c["totalRisk"], reverse=True)
    nodes = [p["id"] for p in comm_p[clusters[0]["communityId"]][:60]] if clusters else []
    return _env(clusters, q, _ms(t0), nodes, [], active_engine())


# ----------------------------------------------------------------------------- fix_plan
def fix_plan(max_actions: int = 5) -> dict[str, Any]:
    """Greedy set cover over Fix nodes: maximise risk cleared per unit of effort.

    WHEN TO USE: to build the prioritised upgrade roadmap (refresh=1, override=2, breaking=4).
    """
    max_actions = max(1, min(int(max_actions), 20))
    st = _state()
    fixes = {fid: f for fid, f in st["fixes"].items() if f.get("toVersion") and f.get("resolves")}
    risks = st["vuln_risk"]
    uncovered = set(risks)
    initial_r = sum(risks.values())
    cur_r = initial_r
    actions: list[dict[str, Any]] = []
    h_nodes: list[str] = []
    h_edges: list[list[str]] = []
    for _ in range(max_actions):
        best, best_score, best_cleared = None, 0.0, set()
        for f in fixes.values():
            cleared = set(f["resolves"]) & uncovered
            gain = sum(risks.get(v, 0.0) for v in cleared)
            score = gain / EFFORT.get(f["tier"], 2.0)
            if gain > 0 and score > best_score:
                best, best_score, best_cleared = f, score, cleared
        if not best:
            break
        gain = sum(risks.get(v, 0.0) for v in best_cleared)
        uncovered -= best_cleared
        cur_r = max(0.0, cur_r - gain)
        actions.append({
            "action": len(actions) + 1, "fixId": best["id"], "pkg": best["pkg"], "toVersion": best["toVersion"],
            "tier": best["tier"], "effort": int(EFFORT.get(best["tier"], 2)), "clears": len(best_cleared),
            "unfixed": best.get("unfixed", 0), "riskCleared": round(gain, 2), "residualBlastScore": _blast(cur_r),
            "targets": best["targets"], "resolvedVulns": sorted(best_cleared),
        })
        for t in best["targets"]:
            h_nodes.append(t)
            h_edges += [[t, v] for v in best_cleared]
        h_nodes += list(best_cleared)
    data = {"initialBlastScore": _blast(initial_r),
            "finalBlastScore": actions[-1]["residualBlastScore"] if actions else _blast(initial_r),
            "totalRiskReduction": round(initial_r - cur_r, 2), "actions": actions}
    return _env(data, st["cypher"], st["ms"], h_nodes, h_edges, st["engine"])


# ----------------------------------------------------------------------------- simulate
def simulate(fix_ids: list[str]) -> dict[str, Any]:
    """Non-destructively compute the Blast Score after applying the given fixes.

    WHEN TO USE: to preview a plan before touching any lockfile.
    """
    ids = [f if f.startswith("fix:") else f"fix:{f}" for f in fix_ids]
    st = _state()
    risks = st["vuln_risk"]
    resolved: set[str] = set()
    for fid in ids:
        resolved.update(st["fixes"].get(fid, {}).get("resolves", []))
    resolved.intersection_update(risks)
    initial_r = sum(risks.values())
    remaining_r = sum(r for v, r in risks.items() if v not in resolved)
    healed_pkgs = sorted(p for p, vs in st["pkg_vulns"].items() if vs and vs <= resolved)
    h_edges = [[p, v] for p in healed_pkgs for v in st["pkg_vulns"][p]]
    init_b, sim_b = _blast(initial_r), _blast(remaining_r)
    data = {
        "initialBlastScore": init_b, "simulatedBlastScore": sim_b, "residualBlastScore": sim_b,
        "blastScoreReduction": init_b - sim_b, "riskReduced": round(initial_r - remaining_r, 2),
        "healedVulnsCount": len(resolved), "healedPackagesCount": len(healed_pkgs),
        "remainingVulnsCount": len(risks) - len(resolved), "healedPackages": healed_pkgs,
        "resolvedVulns": sorted(resolved),
    }
    return _env(data, st["cypher"], st["ms"], sorted(resolved) + healed_pkgs, h_edges, st["engine"])


# ----------------------------------------------------------------------------- build_patch
def build_patch(fix_ids: list[str]) -> dict[str, Any]:
    """Generate package.json overrides, shell steps and a PR/issue body for the chosen fixes.

    WHEN TO USE: when the user wants something they can commit.
    """
    ids = [f if f.startswith("fix:") else f"fix:{f}" for f in fix_ids]
    st = _state(ids)
    sel = [f for f in st["fixes"].values() if f.get("toVersion") and f["id"] in ids]
    sim = simulate(ids)["data"]
    overrides = {f["pkg"]: f"^{f['toVersion']}" for f in sel}
    ov_json = json.dumps({"overrides": overrides}, indent=2)
    names = " ".join(f["pkg"] for f in sel)
    commands = (["# 1) merge the overrides block above into package.json, then:", "npm install"]
                + ([f"npm ls {names}"] if names else []) + ["npm audit", "npm run lint", "npm run build"])
    engine_label = "FalkorDB" if st["engine"] == "falkordb" else "the local SQLite snapshot with NetworkX"
    lines = ["# Security remediation plan", "",
             f"Generated by **Blast Radius** from a dependency graph analysed with {engine_label}.", "",
             f"Blast Score: **{sim['initialBlastScore']} -> {sim['simulatedBlastScore']}** "
             f"({sim['healedVulnsCount']} advisories resolved, {sim['remainingVulnsCount']} remain)", "",
             "| Package | Target | Tier | Advisories fixed | No upstream fix | Risk cleared |",
             "| :-- | :-- | :-- | --: | --: | --: |"]
    for f in sel:
        tier = {"refresh": "refresh", "override": "override", "breaking": "BREAKING (major bump, test carefully)"}[f["tier"]]
        lines.append(f"| `{f['pkg']}` | `{f['toVersion']}` | {tier} | {f['clears']} | {f.get('unfixed', 0)} | {f['riskCleared']} |")
    lines += ["", "## Apply", "```json", ov_json, "```", "```bash", "\n".join(commands), "```", "",
              "Advisories with no published fix cannot be resolved by upgrading; track or replace those packages."]
    return _env({"overrides": overrides, "overrides_json": ov_json, "commands": commands,
                 "issue_markdown": "\n".join(lines)},
                st["cypher"], st["ms"], [t for f in sel for t in f["targets"]], [], st["engine"])


# ----------------------------------------------------------------------------- cypher_ro
_FORBIDDEN = ["CREATE", "MERGE", "SET", "DELETE", "REMOVE", "DROP", "LOAD", "FOREACH"]


def cypher_ro(query: str) -> dict[str, Any]:
    """Run a read-only Cypher query (GRAPH.RO_QUERY, LIMIT 200 enforced).

    WHEN TO USE: for bespoke questions the dedicated tools do not answer.
    """
    q = query.strip().rstrip(";").strip()
    err = lambda m, ms=0.0: _env({"error": m}, q, ms, [], [], "falkordb" if _falkor() else active_engine())
    if not q:
        return err("Empty query.")
    for word in _FORBIDDEN:
        if re.search(rf"\b{word}\b", q, re.IGNORECASE):
            return err(f"'{word}' is not allowed: this console is read-only.")
    if re.search(r"\bRETURN\b", q, re.IGNORECASE):
        if re.search(r"\bLIMIT\s+\d+", q, re.IGNORECASE):
            q = re.sub(r"\bLIMIT\s+(\d+)", lambda m: f"LIMIT {min(200, int(m.group(1)))}", q, flags=re.IGNORECASE)
        else:
            q += " LIMIT 200"
    if not _falkor():
        return _env({"error": "Cypher queries require FalkorDB. Set GRAPH_BACKEND=falkordb and start it with `docker compose up -d`."},
                    q, 0.0, [], [], active_engine())
    try:
        cols, rows, ms = ro_run_full(q)
    except Exception as exc:
        return _env({"error": str(exc)}, q, 0.0, [], [], "falkordb")
    rows = serialize(rows)
    nodes: list[str] = []
    edges: list[list[str]] = []

    def walk(x: Any) -> None:
        if isinstance(x, dict) and x.get("_type") == "path":
            ids = x["nodes"]
            nodes.extend(ids)
            edges.extend([[ids[i - 1], ids[i]] for i in range(1, len(ids))])
        elif isinstance(x, dict) and x.get("_type") == "node" and "id" in x:
            nodes.append(x["id"])
        elif isinstance(x, list):
            for y in x:
                walk(y)
        elif isinstance(x, str) and ("@" in x or x.startswith(("GHSA-", "CVE-")) or x == "app"):
            nodes.append(x)

    for r in rows[:40]:
        walk(r)
    return _env(rows, q, ms, nodes, edges, "falkordb", columns=cols)


# ----------------------------------------------------------------------------- graph view for the UI
def graph_view(mode: str = "risk") -> dict[str, Any]:
    """Nodes/links for the force graph. FalkorDB-backed when online."""
    full = mode == "full"
    if _falkor():
        try:
            t0 = time.perf_counter()
            rows, _, _ = ro_run(
                "MATCH (p:Package) OPTIONAL MATCH (p)-[h:HAS_VULN]->(v:Vuln) "
                "WITH p, collect(CASE WHEN v IS NULL THEN null ELSE {id: v.id, severity: v.severity, "
                "summary: v.summary, url: v.url, fixed: h.fixed} END) AS vulns "
                "WHERE $full OR p.exposed = true OR p.depth <= 2 OR size(vulns) > 0 "
                "RETURN p.id, p.name, p.depth, p.direct, p.pagerank, p.betweenness, p.community, p.dependents, "
                "p.exposed, vulns", {"full": full})
            nodes = [{"id": "app", "label": "App", "type": "app", "depth": 0, "direct": False, "severity": "NONE",
                      "pagerank": 0.0, "betweenness": 0.0, "community": 0, "dependents": 0, "exposed": True, "vulns": []}]
            for pid, name, depth, direct, pr, bw, com, dep, exp, vs in rows:
                vs = vs or []
                best = max((str(v["severity"]).upper() for v in vs), key=lambda s: SEV_RANK.get(s, 1), default="NONE")
                nodes.append({"id": pid, "label": name, "type": "package", "depth": depth, "direct": bool(direct),
                              "severity": best, "pagerank": float(pr or 0), "betweenness": float(bw or 0),
                              "community": int(com or 0), "dependents": int(dep or 0), "exposed": bool(exp), "vulns": vs})
            ids = [n["id"] for n in nodes if n["id"] != "app"]
            l_rows, _, _ = ro_run(
                "MATCH (a)-[r:DEPENDS_ON]->(b:Package) WHERE b.id IN $ids AND (a:App OR a.id IN $ids) "
                "RETURN a.id, b.id, r.req", {"ids": ids})
            return {"nodes": nodes, "links": [{"source": a, "target": b, "req": r} for a, b, r in l_rows],
                    "engine": "falkordb", "ms": round(_ms(t0), 2)}
        except Exception as exc:
            print(f"[tools.graph_view] FalkorDB failed: {exc}")
    snap = _snapshot()
    pkgs, edges, vulns = snap.get("packages", {}), snap.get("edges", []), snap.get("vulns", {})
    pv: dict[str, list] = defaultdict(list)
    for h in snap.get("has_vuln", []):
        v = vulns.get(h["vulnId"], {})
        pv[h["pkgId"]].append({"id": h["vulnId"], "severity": v.get("severity", "MODERATE"),
                               "summary": v.get("summary", ""), "url": v.get("url"), "fixed": h.get("fixed", [])})
    nodes = [{"id": "app", "label": "App", "type": "app", "depth": 0, "direct": False, "severity": "NONE",
              "pagerank": 0.0, "betweenness": 0.0, "community": 0, "dependents": 0, "exposed": True, "vulns": []}]
    keep = {"app"}
    for pid, p in pkgs.items():
        vs = pv.get(pid, [])
        exposed = bool(p.get("exposed") or p.get("depth", 99) <= 2)
        if not full and not exposed and not vs:
            continue
        best = max((str(v["severity"]).upper() for v in vs), key=lambda s: SEV_RANK.get(s, 1), default="NONE")
        nodes.append({"id": pid, "label": p.get("name", pid), "type": "package", "depth": p.get("depth", 99),
                      "direct": bool(p.get("direct") or p.get("depth") == 1), "severity": best,
                      "pagerank": float(p.get("pagerank", 0)), "betweenness": float(p.get("betweenness", 0)),
                      "community": int(p.get("community", 0)), "dependents": int(p.get("dependents", 0)),
                      "exposed": exposed, "vulns": vs})
        keep.add(pid)
    links = [{"source": e["fromId"], "target": e["toId"], "req": e.get("req", "")}
             for e in edges if e["fromId"] in keep and e["toId"] in keep]
    return {"nodes": nodes, "links": links, "engine": active_engine(), "ms": None}
