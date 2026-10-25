"""Graph analysis and vulnerability remediation engine for Blast Radius."""

from collections import defaultdict, deque
import math
import time
from typing import Any, Optional

import networkx as nx
import semantic_version

from backend.config import GRAPH_NAME
from backend.db import get_graph, ro_run, run
from backend.ingest import CVSS_FALLBACK, is_falkor_available, read_cache, write_cache


def _parse_version_safe(ver_str: str) -> Optional[semantic_version.Version]:
    """Safely parse a semver version string using coerce."""
    try:
        return semantic_version.Version.coerce(str(ver_str).strip())
    except Exception:
        return None


def _check_available_procedures() -> set[str]:
    """Check registered procedures in FalkorDB via dbms.procedures()."""
    procs: set[str] = set()
    try:
        rows, _, _ = ro_run("CALL dbms.procedures()")
        for row in rows:
            if row and len(row) > 0:
                procs.add(str(row[0]))
    except Exception:
        pass
    return procs


def _build_fixes(by_pkg_name: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Turn per-package-name vulnerability data into Fix records (shared by both engines).

    A vuln only counts as RESOLVED by a fix if an upstream release above the installed
    version actually fixes it. Advisories with no published fix stay in `unfixed`; they are
    never counted in `clears` / `riskCleared`, so the headline numbers cannot be overstated.
    """
    fixes: list[dict[str, Any]] = []
    for name, data in by_pkg_name.items():
        installed_versions = sorted(data["installed_versions"])
        parsed_installed = [v for v in map(_parse_version_safe, installed_versions) if v]

        # lowest fixed version above the installed one, per vuln
        min_fixed: dict[str, semantic_version.Version] = {}
        for vid in data["vuln_ids"]:
            above = []
            for f in data["fixed_per_vuln"].get(vid, []):
                pv = _parse_version_safe(f)
                if pv and all(pv > inst for inst in parsed_installed):
                    above.append(pv)
            if above:
                min_fixed[vid] = min(above)

        to_obj = max(min_fixed.values()) if min_fixed else None
        resolvable = set(min_fixed)

        if to_obj is None:
            tier = "breaking"
        elif any(to_obj.major != inst.major for inst in parsed_installed):
            tier = "breaking"
        else:
            tier = "refresh"  # fixed version satisfies every incoming requirement
            for req in data["reqs"]:
                if not req or req == "root":
                    continue
                try:
                    if not semantic_version.NpmSpec(req).match(to_obj):
                        tier = "override"
                        break
                except Exception:
                    tier = "override"
                    break

        fixes.append({
            "id": f"fix:{name}",
            "pkg": name,
            "toVersion": str(to_obj) if to_obj else None,
            "tier": tier,
            "clears": len(resolvable),
            "unfixed": len(data["vuln_ids"]) - len(resolvable),
            "riskCleared": round(sum(data["vuln_risks"].get(v, 0.0) for v in resolvable), 2),
            "installed": installed_versions,
            "targets": sorted(data["pkg_ids"]),
            "resolves": sorted(resolvable),
        })
    return fixes


def _export_snapshot_from_falkor() -> None:
    """Mirror FalkorDB analysis results into the local snapshot store."""
    snap = read_cache("latest_graph_snapshot.json") or {}
    packages = snap.get("packages", {})
    rows, _, _ = ro_run(
        "MATCH (p:Package) RETURN p.id, p.pagerank, p.betweenness, p.community, p.dependents, "
        "p.exposed, p.vulnFlow, p.exclusiveRisk"
    )
    for pid, pr, bw, com, dep, exp, flow, ex in rows:
        if pid in packages:
            packages[pid].update({
                "pagerank": pr or 0.0, "betweenness": bw or 0.0, "community": com or 0,
                "dependents": dep or 0, "exposed": bool(exp),
            })
            if flow is not None:
                packages[pid]["vulnFlow"] = flow
                packages[pid]["exclusiveRisk"] = ex or 0.0
    vulns = snap.get("vulns", {})
    rows, _, _ = ro_run("MATCH (v:Vuln) RETURN v.id, v.risk")
    for vid, risk in rows:
        if vid in vulns:
            vulns[vid]["risk"] = risk or 0.0
    rows, _, _ = ro_run(
        "MATCH (f:Fix) OPTIONAL MATCH (f)-[:TARGETS]->(p:Package) OPTIONAL MATCH (f)-[:RESOLVES]->(v:Vuln) "
        "RETURN f.id, f.pkg, f.toVersion, f.tier, f.clears, f.unfixed, f.riskCleared, "
        "collect(DISTINCT p.id), collect(DISTINCT v.id)"
    )
    snap["fixes"] = {
        fid: {"id": fid, "pkg": pkg, "toVersion": to, "tier": tier, "clears": cl or 0, "unfixed": uf or 0,
              "riskCleared": rc or 0.0, "targets": t or [], "resolves": r or []}
        for fid, pkg, to, tier, cl, uf, rc, t, r in rows
    }
    snap["packages"], snap["vulns"], snap["analyzed_at"] = packages, vulns, time.time()
    write_cache("latest_graph_snapshot.json", snap)


def analyze() -> dict[str, Any]:
    """Analyze the active graph using FalkorDB or local NetworkX algorithms.

    Steps:
    1 Create REQUIRED_BY for every DEPENDS_ON (incl. App).
    2 PageRank -> SET pagerank; betweenness (samplingSize 64) -> SET betweenness;
      labelPropagation (fallback WCC) -> SET community. If SET after CALL..YIELD fails,
      collect rows and write back via UNWIND.
    3 For each vulnerable Package: algo.BFS(p,64,'REQUIRED_BY') -> dependents (Packages only) + min depth;
      set p.dependents; mark every upstream Package exposed=true; compute Vuln.risk per SCORING.
    4 Chokepoints: per direct dep D, algo.BFS(D,64,'DEPENDS_ON') -> downstream vulnerable set;
      exclusive = vulns reachable from D and from no other direct dep (set math in Python);
      write D.vulnFlow, D.exclusiveRisk.
    5 Fix nodes per vulnerable package NAME: toVersion = for each vuln the lowest fixed version
      above the installed one, then the max across vulns and installed versions; tier per FIX TIERS
      using DEPENDS_ON.req of all installed versions (semantic_version.NpmSpec, try/except -> yellow).
      Create TARGETS + RESOLVES for every vuln that package name carries; set clears, riskCleared.

    Returns:
        {packages, vulns, bySeverity, blastScore, ms_per_step}
    """
    falkor_online = is_falkor_available()
    ms_per_step: dict[str, float] = {}

    if falkor_online:
        result = _analyze_falkordb(ms_per_step)
        result["engine"] = "falkordb"
    else:
        result = _analyze_in_memory(ms_per_step)
        result["engine"] = "sqlite"
    return result


def _analyze_falkordb(ms_per_step: dict[str, float]) -> dict[str, Any]:
    """Execute analysis directly on FalkorDB instance using Cypher and graph algorithms."""
    available_procs = _check_available_procedures()

    # Step 1: Create REQUIRED_BY for every DEPENDS_ON (incl. App)
    t0 = time.perf_counter()
    q1 = """
    MATCH (a)-[r:DEPENDS_ON]->(b)
    MERGE (b)-[:REQUIRED_BY]->(a)
    """
    _, ms1, _ = run(q1)
    ms_per_step["step1_required_by"] = ms1 if ms1 > 0 else round((time.perf_counter() - t0) * 1000.0, 2)

    # Step 2: PageRank -> SET pagerank; betweenness -> SET betweenness; labelPropagation (fallback WCC) -> SET community
    t0 = time.perf_counter()
    # 2a. PageRank
    try:
        pr_rows, _, _ = ro_run("CALL algo.pageRank('Package', 'DEPENDS_ON') YIELD node, score")
        if pr_rows:
            batch = [{"id": r[0].properties.get("id") if hasattr(r[0], "properties") else str(r[0]), "score": float(r[1])} for r in pr_rows]
            run("UNWIND $batch AS item MATCH (p:Package {id: item.id}) SET p.pagerank = item.score", {"batch": batch})
    except Exception as e:
        print(f"[FalkorDB] PageRank procedure call failed: {e}. Using fallback.")

    # 2b. Betweenness (samplingSize 64)
    try:
        bw_rows, _, _ = ro_run("CALL algo.betweenness({nodeLabels:['Package'], relationshipTypes:['DEPENDS_ON'], samplingSize:64, samplingSeed:42}) YIELD node, score")
        if bw_rows:
            batch = [{"id": r[0].properties.get("id") if hasattr(r[0], "properties") else str(r[0]), "score": float(r[1])} for r in bw_rows]
            run("UNWIND $batch AS item MATCH (p:Package {id: item.id}) SET p.betweenness = item.score", {"batch": batch})
    except Exception as e:
        print(f"[FalkorDB] Betweenness procedure call failed: {e}. Using fallback.")

    # 2c. LabelPropagation (fallback WCC)
    comm_written = False
    try:
        lp_rows, _, _ = ro_run("CALL algo.labelPropagation({nodeLabels:['Package'], relationshipTypes:['DEPENDS_ON']}) YIELD node, communityId")
        if lp_rows:
            batch = [{"id": r[0].properties.get("id") if hasattr(r[0], "properties") else str(r[0]), "community": int(r[1])} for r in lp_rows]
            run("UNWIND $batch AS item MATCH (p:Package {id: item.id}) SET p.community = item.community", {"batch": batch})
            comm_written = True
    except Exception as e:
        print(f"[FalkorDB] labelPropagation failed ({e}), falling back to WCC procedure as instructed.")

    if not comm_written:
        try:
            wcc_rows, _, _ = ro_run("CALL algo.WCC({nodeLabels:['Package'], relationshipTypes:['DEPENDS_ON']}) YIELD node, componentId")
            if wcc_rows:
                batch = [{"id": r[0].properties.get("id") if hasattr(r[0], "properties") else str(r[0]), "community": int(r[1])} for r in wcc_rows]
                run("UNWIND $batch AS item MATCH (p:Package {id: item.id}) SET p.community = item.community", {"batch": batch})
        except Exception as e:
            print(f"[FalkorDB] WCC procedure failed: {e}")

    ms_per_step["step2_centrality"] = round((time.perf_counter() - t0) * 1000.0, 2)

    # Step 3: For each vulnerable Package: algo.BFS(p,64,'REQUIRED_BY') -> dependents + min depth; set p.dependents; mark upstream exposed=true; compute Vuln.risk per SCORING
    t0 = time.perf_counter()
    # Fetch all vulnerable packages
    vuln_pkg_rows, _, _ = ro_run("""
    MATCH (p:Package)-[h:HAS_VULN]->(v:Vuln)
    RETURN p.id AS pkgId, p.depth AS depth, v.id AS vulnId, v.cvss AS cvss, v.severity AS severity, h.fixed AS fixed
    """)

    vuln_pkgs = list({r[0] for r in vuln_pkg_rows})
    pkg_upstream_map: dict[str, set[str]] = {}

    for p_id in vuln_pkgs:
        # Run BFS or reverse traversal along REQUIRED_BY
        try:
            bfs_rows, _, _ = ro_run("""
            MATCH (p:Package {id: $pkgId})
            MATCH (p)-[:REQUIRED_BY*1..64]->(upstream:Package)
            RETURN DISTINCT upstream.id AS id
            """, {"pkgId": p_id})
            upstream_set = {r[0] for r in bfs_rows if r[0] != "app"}
        except Exception:
            upstream_set = set()
        pkg_upstream_map[p_id] = upstream_set

    # Write dependents and mark exposed=true on all upstream
    batch_dependents = [{"id": pid, "dependents": len(up)} for pid, up in pkg_upstream_map.items()]
    if batch_dependents:
        run("""
        UNWIND $batch AS item
        MATCH (p:Package {id: item.id})
        SET p.dependents = item.dependents
        """, {"batch": batch_dependents})

    all_exposed_ids = set()
    for up_set in pkg_upstream_map.values():
        all_exposed_ids.update(up_set)

    if all_exposed_ids:
        batch_exp = [{"id": eid} for eid in all_exposed_ids]
        run("""
        UNWIND $batch AS item
        MATCH (p:Package {id: item.id})
        SET p.exposed = true
        """, {"batch": batch_exp})

    # Compute and set Vuln.risk
    # SCORING: cvss fallback {LOW:3,MODERATE:5.5,HIGH:7.5,CRITICAL:9.5};
    # vuln.risk = cvss*(1+log2(1+dependents))*(1.5 if min depth<=2 else 1)
    vuln_stats: dict[str, dict[str, Any]] = defaultdict(lambda: {"cvss": 5.5, "min_depth": 999, "max_dep": 0})
    for r in vuln_pkg_rows:
        pid, depth, vid, cvss, severity, _ = r
        cvss_val = float(cvss) if cvss is not None else CVSS_FALLBACK.get(str(severity).upper(), 5.5)
        d_val = int(depth) if depth is not None else 1
        dep_val = len(pkg_upstream_map.get(pid, set()))
        stats = vuln_stats[vid]
        stats["cvss"] = cvss_val
        stats["min_depth"] = min(stats["min_depth"], d_val)
        stats["max_dep"] = max(stats["max_dep"], dep_val)

    vuln_risk_batch = []
    for vid, stats in vuln_stats.items():
        mult = 1.5 if stats["min_depth"] <= 2 else 1.0
        risk = round(stats["cvss"] * (1.0 + math.log2(1.0 + stats["max_dep"])) * mult, 2)
        vuln_risk_batch.append({"id": vid, "risk": risk})

    if vuln_risk_batch:
        run("""
        UNWIND $batch AS item
        MATCH (v:Vuln {id: item.id})
        SET v.risk = item.risk
        """, {"batch": vuln_risk_batch})

    ms_per_step["step3_dependents_risk"] = round((time.perf_counter() - t0) * 1000.0, 2)

    # Step 4: Chokepoints: per direct dep D, algo.BFS(D,64,'DEPENDS_ON') -> downstream vulnerable set;
    # exclusive = vulns reachable from D and from no other direct dep (set math in Python);
    # write D.vulnFlow, D.exclusiveRisk
    t0 = time.perf_counter()
    direct_rows, _, _ = ro_run("""
    MATCH (a:App)-[:DEPENDS_ON]->(d:Package)
    RETURN DISTINCT d.id AS id
    """)
    direct_ids = [r[0] for r in direct_rows]

    vulns_per_direct: dict[str, set[str]] = {}
    for d_id in direct_ids:
        # Downstream reachable vulns
        v_rows, _, _ = ro_run("""
        MATCH (d:Package {id: $dId})-[:DEPENDS_ON*0..64]->(p:Package)-[:HAS_VULN]->(v:Vuln)
        RETURN DISTINCT v.id AS vid
        """, {"dId": d_id})
        vulns_per_direct[d_id] = {r[0] for r in v_rows}

    # Set math in Python
    vuln_risk_map = {item["id"]: item["risk"] for item in vuln_risk_batch}
    chokepoint_batch = []
    for d_id in direct_ids:
        d_vulns = vulns_per_direct.get(d_id, set())
        other_vulns = set().union(*(vulns_per_direct[other] for other in direct_ids if other != d_id))
        exclusive = d_vulns - other_vulns
        exclusive_risk = round(sum(vuln_risk_map.get(vid, 0.0) for vid in exclusive), 2)
        chokepoint_batch.append({
            "id": d_id,
            "vulnFlow": len(d_vulns),
            "exclusiveRisk": exclusive_risk,
        })

    if chokepoint_batch:
        run("""
        UNWIND $batch AS item
        MATCH (d:Package {id: item.id})
        SET d.vulnFlow = item.vulnFlow, d.exclusiveRisk = item.exclusiveRisk
        """, {"batch": chokepoint_batch})

    ms_per_step["step4_chokepoints"] = round((time.perf_counter() - t0) * 1000.0, 2)

    # Step 5: Fix nodes per vulnerable package NAME
    t0 = time.perf_counter()
    # Fetch vulnerable packages grouped by name
    pkg_rows, _, _ = ro_run("""
    MATCH (p:Package)-[h:HAS_VULN]->(v:Vuln)
    OPTIONAL MATCH ()-[r:DEPENDS_ON]->(p)
    RETURN p.name AS name, p.version AS version, p.id AS pkgId, v.id AS vulnId, v.risk AS risk, h.fixed AS fixed, collect(r.req) AS reqs
    """)

    # Group by package name
    by_pkg_name: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "installed_versions": set(),
        "pkg_ids": set(),
        "vuln_ids": set(),
        "fixed_per_vuln": defaultdict(list),
        "reqs": set(),
        "vuln_risks": {},
    })

    for r in pkg_rows:
        name, ver, pid, vid, risk, fixed_list, reqs = r
        entry = by_pkg_name[name]
        entry["installed_versions"].add(ver)
        entry["pkg_ids"].add(pid)
        entry["vuln_ids"].add(vid)
        entry["vuln_risks"][vid] = float(risk) if risk is not None else 0.0
        if fixed_list and isinstance(fixed_list, list):
            entry["fixed_per_vuln"][vid].extend(fixed_list)
        if reqs and isinstance(reqs, list):
            entry["reqs"].update(reqs)

    # Clean existing Fix nodes
    run("MATCH (f:Fix) DETACH DELETE f")

    fix_nodes = []
    targets_links = []
    resolves_links = []

    fix_records = _build_fixes(by_pkg_name)
    fix_nodes = [{k: f[k] for k in ("id", "pkg", "toVersion", "tier", "clears", "unfixed", "riskCleared")} for f in fix_records]
    targets_links = [{"fixId": f["id"], "pkgId": pid} for f in fix_records for pid in f["targets"]]
    resolves_links = [{"fixId": f["id"], "vulnId": vid} for f in fix_records for vid in f["resolves"]]

    # UNWIND Fix nodes and edges
    if fix_nodes:
        run("""
        UNWIND $batch AS f
        MERGE (fix:Fix {id: f.id})
        SET fix.pkg = f.pkg,
            fix.toVersion = f.toVersion,
            fix.tier = f.tier,
            fix.clears = f.clears,
            fix.unfixed = f.unfixed,
            fix.riskCleared = f.riskCleared
        """, {"batch": fix_nodes})

    if targets_links:
        run("""
        UNWIND $batch AS t
        MATCH (f:Fix {id: t.fixId}), (p:Package {id: t.pkgId})
        MERGE (f)-[:TARGETS]->(p)
        """, {"batch": targets_links})

    if resolves_links:
        run("""
        UNWIND $batch AS r
        MATCH (f:Fix {id: r.fixId}), (v:Vuln {id: r.vulnId})
        MERGE (f)-[:RESOLVES]->(v)
        """, {"batch": resolves_links})

    ms_per_step["step5_fixes"] = round((time.perf_counter() - t0) * 1000.0, 2)

    # Return summary stats
    p_count_rows, _, _ = ro_run("MATCH (p:Package) RETURN count(p) AS count")
    v_rows, _, _ = ro_run("MATCH (v:Vuln) RETURN v.id, v.severity, v.risk")

    packages_count = p_count_rows[0][0] if p_count_rows else 0
    vulns_count = len(v_rows)
    by_severity: dict[str, int] = defaultdict(int)
    total_risk = 0.0
    for r in v_rows:
        sev = str(r[1]).upper() if r[1] else "MODERATE"
        by_severity[sev] += 1
        total_risk += float(r[2]) if r[2] is not None else 0.0

    blast_score = round(100.0 * total_risk / (total_risk + 60.0)) if total_risk > 0 else 0

    try:
        _export_snapshot_from_falkor()
    except Exception as exc:  # snapshot is a convenience mirror; never fail the analysis for it
        print(f"[analyze] snapshot export failed: {exc}")

    return {
        "packages": packages_count,
        "vulns": vulns_count,
        "bySeverity": dict(by_severity),
        "blastScore": blast_score,
        "ms_per_step": ms_per_step,
    }


def _analyze_in_memory(ms_per_step: dict[str, float]) -> dict[str, Any]:
    """Execute graph analysis with networkx over the locally persisted SQLite snapshot."""
    snapshot = read_cache("latest_graph_snapshot.json") or {}
    packages: dict[str, dict[str, Any]] = snapshot.get("packages", {})
    edges: list[dict[str, str]] = snapshot.get("edges", [])
    vulns: dict[str, dict[str, Any]] = snapshot.get("vulns", {})
    has_vuln: list[dict[str, Any]] = snapshot.get("has_vuln", [])
    roots: list[str] = snapshot.get("roots", [])

    # Step 1: Create REQUIRED_BY for every DEPENDS_ON (incl. App)
    t0 = time.perf_counter()
    g_dep = nx.DiGraph()
    g_req_by = nx.DiGraph()

    for p_id in packages:
        g_dep.add_node(p_id)
        g_req_by.add_node(p_id)
    g_dep.add_node("app")
    g_req_by.add_node("app")

    for e in edges:
        u = e["fromId"]
        v = e["toId"]
        req = e.get("req", "")
        g_dep.add_edge(u, v, req=req)
        # REQUIRED_BY is reverse copy
        g_req_by.add_edge(v, u, req=req)

    ms_per_step["step1_required_by"] = round((time.perf_counter() - t0) * 1000.0, 2)

    # Step 2: PageRank, Betweenness, LabelPropagation (or WCC)
    t0 = time.perf_counter()
    # Graph of Packages only
    pkg_graph = g_dep.subgraph(packages.keys()).copy()

    # PageRank
    try:
        pr_scores = nx.pagerank(pkg_graph, alpha=0.85, max_iter=100) if len(pkg_graph) > 0 else {}
    except Exception:
        pr_scores = {p: 1.0 / max(1, len(pkg_graph)) for p in packages}

    for p_id, score in pr_scores.items():
        if p_id in packages:
            packages[p_id]["pagerank"] = round(float(score), 6)

    # Betweenness (samplingSize 64)
    k_sample = min(64, len(pkg_graph))
    try:
        bw_scores = nx.betweenness_centrality(pkg_graph, k=k_sample, seed=42) if k_sample > 0 else {}
    except Exception:
        bw_scores = {}

    for p_id, score in bw_scores.items():
        if p_id in packages:
            packages[p_id]["betweenness"] = round(float(score), 6)

    # Label propagation (fallback WCC)
    community_map: dict[str, int] = {}
    try:
        undirected_g = pkg_graph.to_undirected()
        communities = list(nx.community.label_propagation_communities(undirected_g))
        for c_id, comm in enumerate(communities):
            for node in comm:
                community_map[node] = c_id
    except Exception:
        # WCC fallback
        for c_id, comp in enumerate(nx.weakly_connected_components(pkg_graph)):
            for node in comp:
                community_map[node] = c_id

    for p_id, c_id in community_map.items():
        if p_id in packages:
            packages[p_id]["community"] = c_id

    ms_per_step["step2_centrality"] = round((time.perf_counter() - t0) * 1000.0, 2)

    # Step 3: For each vulnerable Package: algo.BFS(p,64,'REQUIRED_BY') -> dependents + min depth;
    # set p.dependents; mark upstream exposed=true; compute Vuln.risk per SCORING
    t0 = time.perf_counter()
    vuln_pkg_ids = {h["pkgId"] for h in has_vuln if h["pkgId"] in packages}

    pkg_upstream_map: dict[str, set[str]] = {}
    for p_id in vuln_pkg_ids:
        # BFS up to 64 hops along REQUIRED_BY
        visited = set()
        queue = deque([(p_id, 0)])
        while queue:
            curr, depth = queue.popleft()
            if depth >= 64:
                continue
            for parent in g_req_by.neighbors(curr):
                if parent != "app" and parent not in visited:
                    visited.add(parent)
                    queue.append((parent, depth + 1))
        pkg_upstream_map[p_id] = visited

    for p_id, upstream in pkg_upstream_map.items():
        packages[p_id]["dependents"] = len(upstream)
        for u in upstream:
            if u in packages:
                packages[u]["exposed"] = True

    # Compute Vuln.risk per SCORING
    # vuln.risk = cvss*(1+log2(1+dependents))*(1.5 if min depth<=2 else 1)
    vuln_stats: dict[str, dict[str, Any]] = defaultdict(lambda: {"cvss": 5.5, "min_depth": 999, "max_dep": 0})
    for h in has_vuln:
        pid = h["pkgId"]
        vid = h["vulnId"]
        p_info = packages.get(pid, {})
        v_info = vulns.get(vid, {})
        cvss = float(v_info.get("cvss", 5.5))
        depth = int(p_info.get("depth", 1))
        dep = len(pkg_upstream_map.get(pid, set()))

        stats = vuln_stats[vid]
        stats["cvss"] = cvss
        stats["min_depth"] = min(stats["min_depth"], depth)
        stats["max_dep"] = max(stats["max_dep"], dep)

    for vid, stats in vuln_stats.items():
        mult = 1.5 if stats["min_depth"] <= 2 else 1.0
        risk = round(stats["cvss"] * (1.0 + math.log2(1.0 + stats["max_dep"])) * mult, 2)
        if vid in vulns:
            vulns[vid]["risk"] = risk

    ms_per_step["step3_dependents_risk"] = round((time.perf_counter() - t0) * 1000.0, 2)

    # Step 4: Chokepoints: per direct dep D, algo.BFS(D,64,'DEPENDS_ON') -> downstream vulnerable set;
    # exclusive = vulns reachable from D and from no other direct dep (set math in Python);
    # write D.vulnFlow, D.exclusiveRisk
    t0 = time.perf_counter()
    direct_deps = [pid for pid, p in packages.items() if p.get("direct") or p.get("depth") == 1]
    if not direct_deps and "app" in g_dep:
        direct_deps = list(g_dep.neighbors("app"))

    # Map: pkgId -> list of vulnIds
    pkg_to_vulns: dict[str, set[str]] = defaultdict(set)
    for h in has_vuln:
        pkg_to_vulns[h["pkgId"]].add(h["vulnId"])

    vulns_per_direct: dict[str, set[str]] = {}
    for d_id in direct_deps:
        # BFS downstream up to 64 hops
        downstream_nodes = {d_id}
        queue = deque([(d_id, 0)])
        while queue:
            curr, hops = queue.popleft()
            if hops >= 64:
                continue
            for nxt in g_dep.neighbors(curr):
                if nxt not in downstream_nodes and nxt != "app":
                    downstream_nodes.add(nxt)
                    queue.append((nxt, hops + 1))

        d_vulns = set()
        for dn in downstream_nodes:
            d_vulns.update(pkg_to_vulns.get(dn, set()))
        vulns_per_direct[d_id] = d_vulns

    # Set math in Python
    for d_id in direct_deps:
        d_vulns = vulns_per_direct.get(d_id, set())
        other_vulns = set().union(*(vulns_per_direct[other] for other in direct_deps if other != d_id))
        exclusive = d_vulns - other_vulns
        exclusive_risk = round(sum(vulns[vid]["risk"] for vid in exclusive if vid in vulns), 2)
        if d_id in packages:
            packages[d_id]["vulnFlow"] = len(d_vulns)
            packages[d_id]["exclusiveRisk"] = exclusive_risk

    ms_per_step["step4_chokepoints"] = round((time.perf_counter() - t0) * 1000.0, 2)

    # Step 5: Fix nodes per vulnerable package NAME
    t0 = time.perf_counter()
    # Incoming requirements per package
    incoming_reqs: dict[str, set[str]] = defaultdict(set)
    for e in edges:
        incoming_reqs[e["toId"]].add(e.get("req", ""))

    # Group vulnerable packages by package name
    by_pkg_name: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "installed_versions": set(),
        "pkg_ids": set(),
        "vuln_ids": set(),
        "fixed_per_vuln": defaultdict(list),
        "reqs": set(),
        "vuln_risks": {},
    })

    for h in has_vuln:
        pid = h["pkgId"]
        vid = h["vulnId"]
        fixes = h.get("fixed", [])
        if pid in packages:
            p = packages[pid]
            pname = p["name"]
            pver = p["version"]
            entry = by_pkg_name[pname]
            entry["installed_versions"].add(pver)
            entry["pkg_ids"].add(pid)
            entry["vuln_ids"].add(vid)
            entry["vuln_risks"][vid] = vulns.get(vid, {}).get("risk", 0.0)
            entry["fixed_per_vuln"][vid].extend(fixes)
            entry["reqs"].update(incoming_reqs.get(pid, set()))

    fix_nodes: dict[str, dict[str, Any]] = {f["id"]: f for f in _build_fixes(by_pkg_name)}

    ms_per_step["step5_fixes"] = round((time.perf_counter() - t0) * 1000.0, 2)

    # Save updated snapshot
    snapshot["packages"] = packages
    snapshot["vulns"] = vulns
    snapshot["fixes"] = fix_nodes
    snapshot["analyzed_at"] = time.time()
    write_cache("latest_graph_snapshot.json", snapshot)

    # Calculate return values
    by_severity: dict[str, int] = defaultdict(int)
    total_risk = 0.0
    for v in vulns.values():
        sev = str(v.get("severity", "MODERATE")).upper()
        by_severity[sev] += 1
        total_risk += float(v.get("risk", 0.0))

    blast_score = round(100.0 * total_risk / (total_risk + 60.0)) if total_risk > 0 else 0

    return {
        "packages": len(packages),
        "vulns": len(vulns),
        "bySeverity": dict(by_severity),
        "blastScore": blast_score,
        "ms_per_step": ms_per_step,
    }


if __name__ == "__main__":
    print("Running analyze()...")
    res = analyze()
    print("Analysis Results:")
    print(f"  Packages: {res['packages']}")
    print(f"  Vulns: {res['vulns']}")
    print(f"  Blast Score: {res['blastScore']}")
    print(f"  By Severity: {res['bySeverity']}")
    print("  Time per step (ms):")
    for step, ms in res["ms_per_step"].items():
        print(f"    - {step}: {ms:.2f} ms")
