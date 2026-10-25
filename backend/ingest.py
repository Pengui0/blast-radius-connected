"""Supply-chain dependency and vulnerability ingestion module for Blast Radius."""

import asyncio
from collections import defaultdict, deque
import hashlib
import json
import math
from pathlib import Path
import re
import sys
from typing import Any, AsyncGenerator, Optional
import urllib.parse

import httpx

from backend.config import CACHE_DIR, GRAPH_NAME
from backend.db import active_engine, run, using_falkordb
from backend.snapshot_store import read_snapshot, write_snapshot

PRESETS: dict[str, list[str]] = {
    "legacy_react": ["react-scripts@5.0.1", "axios@0.21.1"],
    "zombie_express": ["express@4.17.1", "request@2.88.2", "jsonwebtoken@8.5.1"],
    "kitchen_sink": [
        "react-scripts@5.0.1",
        "axios@0.21.1",
        "express@4.17.1",
        "request@2.88.2",
        "jsonwebtoken@8.5.1",
        "lodash@4.17.15",
    ],
}

CVSS_FALLBACK: dict[str, float] = {
    "LOW": 3.0,
    "MODERATE": 5.5,
    "MEDIUM": 5.5,
    "HIGH": 7.5,
    "CRITICAL": 9.5,
}


def _cache_path(filename: str) -> Path:
    safe_name = "".join(c if (c.isalnum() or c in "._-") else "_" for c in filename)
    return CACHE_DIR / safe_name


def read_cache(filename: str) -> Optional[Any]:
    if filename == "latest_graph_snapshot.json" or (
        filename.startswith("snapshot_") and filename.endswith(".json")
    ):
        snapshot = read_snapshot(filename)
        if snapshot is not None:
            return snapshot
    path = _cache_path(filename)
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None
    return None


def write_cache(filename: str, data: Any) -> None:
    if filename == "latest_graph_snapshot.json" or (
        filename.startswith("snapshot_") and filename.endswith(".json")
    ):
        write_snapshot(filename, data)
        return
    path = _cache_path(filename)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


async def fetch_with_retry(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    json_data: Optional[Any] = None,
    cache_key: Optional[str] = None,
) -> Any:
    """Fetch HTTP endpoint with disk caching and 3x backoff retry."""
    if cache_key:
        cached = read_cache(cache_key)
        if cached is not None:
            return cached

    last_exc = None
    for attempt in range(3):
        try:
            if method.upper() == "GET":
                resp = await client.get(url, timeout=30.0)
            else:
                resp = await client.post(url, json=json_data, timeout=30.0)
            resp.raise_for_status()
            result = resp.json()
            if cache_key:
                write_cache(cache_key, result)
            return result
        except httpx.HTTPStatusError as exc:
            last_exc = exc
            code = exc.response.status_code
            if 400 <= code < 500 and code != 429:
                break  # client error: retrying will not help
            if attempt < 2:
                await asyncio.sleep(0.5 * (2**attempt))
        except Exception as exc:
            last_exc = exc
            if attempt < 2:
                await asyncio.sleep(0.5 * (2**attempt))
    if last_exc:
        raise last_exc
    return {}


def parse_pkg_spec(spec: str) -> tuple[str, str]:
    """Parse name and version from a spec string like 'react-scripts@5.0.1' or '@types/node@18.0.0'."""
    spec = spec.strip()
    if spec.startswith("@"):
        parts = spec[1:].split("@", 1)
        name = "@" + parts[0]
        version = parts[1] if len(parts) > 1 else ""
    else:
        parts = spec.split("@", 1)
        name = parts[0]
        version = parts[1] if len(parts) > 1 else ""
    return name, version


def is_falkor_available() -> bool:
    """True only when FalkorDB is selected and reachable."""
    return using_falkordb()


SPEC_RE = re.compile(r"^(@[a-z0-9][\w.\-]*/)?[a-z0-9][\w.\-]*@\d+\.\d+\.\d+([\-+][\w.\-]+)?$", re.IGNORECASE)
MAX_ROOTS = 12


def validate_roots(roots: list[str]) -> list[str]:
    """Normalise and validate npm 'name@x.y.z' specs; raises ValueError with a readable message."""
    cleaned = [r.strip() for r in roots if r and r.strip()]
    if not cleaned:
        raise ValueError("Provide at least one package as name@version (e.g. express@4.17.1).")
    if len(cleaned) > MAX_ROOTS:
        raise ValueError(f"At most {MAX_ROOTS} root packages per scan.")
    bad = [r for r in cleaned if not SPEC_RE.match(r)]
    if bad:
        raise ValueError(f"Invalid package spec(s): {', '.join(bad)}. Use exact versions like name@1.2.3.")
    return list(dict.fromkeys(cleaned))


def write_graph_to_falkor(
    packages: dict[str, dict[str, Any]],
    all_edges: list[dict[str, str]],
    vuln_nodes: dict[str, dict[str, Any]],
    has_vuln_links: list[dict[str, Any]],
    chunk_size: int = 500,
) -> None:
    """Wipe the graph and load packages, edges, vulns and HAS_VULN links (blocking)."""
    run("MATCH (n) DETACH DELETE n")
    for index_query in [
        "CREATE INDEX FOR (p:Package) ON (p.id)",
        "CREATE INDEX FOR (p:Package) ON (p.name)",
        "CREATE INDEX FOR (v:Vuln) ON (v.id)",
    ]:
        try:
            run(index_query)
        except Exception:
            pass  # index already exists

    run("MERGE (a:App {id: 'app', name: 'app'})")

    pkg_items = list(packages.values())
    for i in range(0, len(pkg_items), chunk_size):
        run(
            """
            UNWIND $batch AS p
            MERGE (pkg:Package {id: p.id})
            SET pkg.name = p.name, pkg.version = p.version, pkg.depth = p.depth,
                pkg.direct = p.direct, pkg.exposed = p.exposed, pkg.dependents = p.dependents,
                pkg.pagerank = p.pagerank, pkg.betweenness = p.betweenness, pkg.community = p.community
            """,
            {"batch": pkg_items[i : i + chunk_size]},
        )

    # Label-specific edge loads so the Package.id / App label indexes are used.
    app_edges = [e for e in all_edges if e["fromId"] == "app"]
    pkg_edges = [e for e in all_edges if e["fromId"] != "app"]
    for i in range(0, len(app_edges), chunk_size):
        run(
            """
            UNWIND $batch AS e
            MATCH (a:App {id: 'app'})
            MATCH (b:Package {id: e.toId})
            MERGE (a)-[:DEPENDS_ON {req: e.req}]->(b)
            MERGE (b)-[:REQUIRED_BY]->(a)
            """,
            {"batch": app_edges[i : i + chunk_size]},
        )
    for i in range(0, len(pkg_edges), chunk_size):
        run(
            """
            UNWIND $batch AS e
            MATCH (a:Package {id: e.fromId})
            MATCH (b:Package {id: e.toId})
            MERGE (a)-[:DEPENDS_ON {req: e.req}]->(b)
            MERGE (b)-[:REQUIRED_BY]->(a)
            """,
            {"batch": pkg_edges[i : i + chunk_size]},
        )

    vuln_items = list(vuln_nodes.values())
    for i in range(0, len(vuln_items), chunk_size):
        run(
            """
            UNWIND $batch AS v
            MERGE (vuln:Vuln {id: v.id})
            SET vuln.aliases = v.aliases, vuln.severity = v.severity, vuln.cvss = v.cvss,
                vuln.summary = v.summary, vuln.url = v.url, vuln.risk = v.risk
            """,
            {"batch": vuln_items[i : i + chunk_size]},
        )
    for i in range(0, len(has_vuln_links), chunk_size):
        run(
            """
            UNWIND $batch AS h
            MATCH (p:Package {id: h.pkgId})
            MATCH (v:Vuln {id: h.vulnId})
            MERGE (p)-[:HAS_VULN {fixed: h.fixed}]->(v)
            """,
            {"batch": has_vuln_links[i : i + chunk_size]},
        )


def load_snapshot_into_falkor(snapshot: dict[str, Any]) -> None:
    """Re-create the FalkorDB graph from a saved snapshot (used when switching presets)."""
    write_graph_to_falkor(
        snapshot.get("packages", {}),
        snapshot.get("edges", []),
        snapshot.get("vulns", {}),
        snapshot.get("has_vuln", []),
    )


async def ingest(roots: list[str]) -> AsyncGenerator[dict[str, Any], None]:
    """Ingest dependency graph and vulnerability data for given roots.

    Yields:
        Progress dictionary {stage, msg, n}
    """
    roots = validate_roots(roots)
    yield {
        "stage": "init",
        "msg": f"Starting ingestion for {len(roots)} roots: {', '.join(roots)}",
        "n": len(roots),
    }

    async with httpx.AsyncClient() as client:
        # Step (1): per root 'name@ver' call deps.dev :dependencies, merge by id name@ver
        packages: dict[str, dict[str, Any]] = {}
        # edges format: (from_id, to_id, req)
        raw_edges: set[tuple[str, str, str]] = set()

        root_ids: list[str] = []
        failed_roots: list[str] = []
        for root in roots:
            pkg_name, pkg_ver = parse_pkg_spec(root)
            root_id = f"{pkg_name}@{pkg_ver}"
            root_ids.append(root_id)
            packages[root_id] = {
                "id": root_id,
                "name": pkg_name,
                "version": pkg_ver,
            }

            yield {
                "stage": "deps_dev",
                "msg": f"Querying deps.dev for root {root_id}",
                "n": len(packages),
            }

            quoted_name = urllib.parse.quote(pkg_name, safe="")
            url = f"https://api.deps.dev/v3/systems/npm/packages/{quoted_name}/versions/{pkg_ver}:dependencies"
            cache_key = f"deps_{quoted_name}_{pkg_ver}.json"

            try:
                data = await fetch_with_retry(client, "GET", url, cache_key=cache_key)
            except Exception as e:
                failed_roots.append(root_id)
                packages.pop(root_id, None)
                root_ids.remove(root_id)
                yield {
                    "stage": "warn",
                    "msg": f"deps.dev could not resolve {root_id} ({type(e).__name__}); skipping it",
                    "n": len(packages),
                }
                continue

            nodes = data.get("nodes", [])
            node_map: dict[int, str] = {}

            for idx, node in enumerate(nodes):
                vkey = node.get("versionKey", {})
                n_name = vkey.get("name", "")
                n_ver = vkey.get("version", "")
                if not n_name:
                    continue
                node_id = f"{n_name}@{n_ver}"
                node_map[idx] = node_id
                if node_id not in packages:
                    packages[node_id] = {
                        "id": node_id,
                        "name": n_name,
                        "version": n_ver,
                    }

            for edge in data.get("edges", []):
                from_idx = edge.get("fromNode")
                to_idx = edge.get("toNode")
                req = edge.get("requirement", "")
                if from_idx in node_map and to_idx in node_map:
                    raw_edges.add((node_map[from_idx], node_map[to_idx], req))

        if not packages:
            raise RuntimeError(
                "deps.dev resolved none of the requested packages (check names/versions and network access)."
            )
        yield {
            "stage": "deps_resolved",
            "msg": f"Resolved {len(packages)} packages and {len(raw_edges)} dependency links",
            "n": len(packages),
        }

        # Step (2): create (:App{id:'app'}) with DEPENDS_ON{req:'root'} to the roots
        # Adjacency maps for BFS
        adj_out: dict[str, set[str]] = defaultdict(set)
        adj_in: dict[str, set[str]] = defaultdict(set)

        # Connect App -> roots
        all_edges: list[dict[str, str]] = []
        for r_id in root_ids:
            if r_id in packages:
                adj_out["app"].add(r_id)
                adj_in[r_id].add("app")
                all_edges.append({"fromId": "app", "toId": r_id, "req": "root"})

        for from_id, to_id, req in raw_edges:
            adj_out[from_id].add(to_id)
            adj_in[to_id].add(from_id)
            all_edges.append({"fromId": from_id, "toId": to_id, "req": req})

        # Step (3): compute depth + direct in Python BFS
        depth_map: dict[str, int] = {}
        queue: deque[tuple[str, int]] = deque()
        for r_id in root_ids:
            if r_id in packages:
                depth_map[r_id] = 1
                queue.append((r_id, 1))

        while queue:
            curr_id, d = queue.popleft()
            for child_id in adj_out.get(curr_id, set()):
                if child_id not in depth_map and child_id != "app":
                    depth_map[child_id] = d + 1
                    queue.append((child_id, d + 1))

        # Compute upstream dependents for each package (ancestors excluding 'app')
        dependents_map: dict[str, int] = {}
        for p_id in packages:
            ancestors: set[str] = set()
            rev_q: deque[str] = deque([p_id])
            rev_visited: set[str] = {p_id}
            while rev_q:
                u = rev_q.popleft()
                for parent in adj_in.get(u, set()):
                    if parent != "app" and parent not in rev_visited:
                        rev_visited.add(parent)
                        ancestors.add(parent)
                        rev_q.append(parent)
            dependents_map[p_id] = len(ancestors)

        # Update package records
        for p_id, p_dict in packages.items():
            depth = depth_map.get(p_id, 99)
            direct = depth == 1
            exposed = depth <= 2
            p_dict["depth"] = depth
            p_dict["direct"] = direct
            p_dict["exposed"] = exposed
            p_dict["dependents"] = dependents_map.get(p_id, 0)
            p_dict["pagerank"] = 0.0
            p_dict["betweenness"] = 0.0
            p_dict["community"] = 0

        yield {
            "stage": "bfs_computed",
            "msg": f"Computed BFS graph metrics (max depth: {max(depth_map.values()) if depth_map else 0})",
            "n": len(packages),
        }

        # Step (4): OSV querybatch in chunks of 500
        pkg_list = list(packages.values())
        unique_vuln_ids: set[str] = set()
        # Map: package_id -> list of vuln_ids
        pkg_vuln_ids: dict[str, list[str]] = defaultdict(list)

        chunk_size = 500
        osv_failed = False
        for i in range(0, len(pkg_list), chunk_size):
            chunk = pkg_list[i : i + chunk_size]
            queries = [
                {"package": {"name": p["name"], "ecosystem": "npm"}, "version": p["version"]}
                for p in chunk
            ]
            batch_hash = hashlib.md5(json.dumps(queries, sort_keys=True).encode()).hexdigest()
            cache_key = f"osv_batch_{batch_hash}.json"

            yield {
                "stage": "osv_query",
                "msg": f"Querying OSV batch {i // chunk_size + 1}/{(len(pkg_list) - 1) // chunk_size + 1}",
                "n": len(chunk),
            }

            try:
                osv_resp = await fetch_with_retry(
                    client,
                    "POST",
                    "https://api.osv.dev/v1/querybatch",
                    json_data={"queries": queries},
                    cache_key=cache_key,
                )
            except Exception as e:
                osv_failed = True
                yield {
                    "stage": "warn",
                    "msg": f"OSV batch failed ({type(e).__name__}); advisories for this batch are MISSING",
                    "n": len(chunk),
                }
                osv_resp = {"results": []}

            results = osv_resp.get("results", [])
            for idx, res in enumerate(results):
                if idx < len(chunk):
                    p_id = chunk[idx]["id"]
                    v_items = res.get("vulns", [])
                    for v in v_items:
                        v_id = v.get("id")
                        if v_id:
                            unique_vuln_ids.add(v_id)
                            pkg_vuln_ids[p_id].append(v_id)

        yield {
            "stage": "vulns_found",
            "msg": f"Found {len(unique_vuln_ids)} unique vulnerability advisories across packages",
            "n": len(unique_vuln_ids),
        }

        # Hydrate unique ids with 8 concurrent GETs
        sem = asyncio.Semaphore(8)
        hydrated_vulns: dict[str, dict[str, Any]] = {}

        async def hydrate_one(vuln_id: str) -> None:
            async with sem:
                cache_key = f"osv_vuln_{vuln_id}.json"
                url = f"https://api.osv.dev/v1/vulns/{vuln_id}"
                try:
                    data = await fetch_with_retry(client, "GET", url, cache_key=cache_key)
                    hydrated_vulns[vuln_id] = data
                except Exception:
                    hydrated_vulns[vuln_id] = {"id": vuln_id}

        tasks = [hydrate_one(vid) for vid in unique_vuln_ids]
        if tasks:
            await asyncio.gather(*tasks)

        # Parse vuln details, fixed versions, and compute risk
        # Map: vuln_id -> parsed Vuln dict
        vuln_nodes: dict[str, dict[str, Any]] = {}
        # List of HAS_VULN items: {pkgId, vulnId, fixed: list[str]}
        has_vuln_links: list[dict[str, Any]] = []

        for v_id in unique_vuln_ids:
            v_data = hydrated_vulns.get(v_id, {})
            db_spec = v_data.get("database_specific") or {}
            sev_str = db_spec.get("severity")

            # Extract numeric CVSS if present
            cvss_val: Optional[float] = None
            if not sev_str:
                sev_field = v_data.get("severity")
                if isinstance(sev_field, list) and sev_field:
                    for s in sev_field:
                        score_val = s.get("score")
                        if isinstance(score_val, (int, float)):
                            cvss_val = float(score_val)
                            break
                        elif isinstance(score_val, str) and score_val.replace(".", "", 1).isdigit():
                            cvss_val = float(score_val)
                            break
                        elif isinstance(s.get("type"), str) and "CVSS" in s.get("type", ""):
                            # score string like CVSS:3.1/...
                            pass

            if not sev_str:
                sev_str = "MODERATE"

            sev_upper = str(sev_str).upper()
            if sev_upper == "MEDIUM":
                sev_upper = "MODERATE"
            if sev_upper not in CVSS_FALLBACK:
                sev_upper = "MODERATE"

            if cvss_val is None:
                cvss_val = CVSS_FALLBACK.get(sev_upper, 5.5)

            # References and URL
            primary_url = f"https://osv.dev/vulnerability/{v_id}"
            for ref in v_data.get("references", []):
                ref_url = ref.get("url", "")
                if "advisories" in ref_url or "github.com/advisories" in ref_url:
                    primary_url = ref_url
                    break

            summary = v_data.get("summary") or ""
            if not summary:
                details = v_data.get("details") or ""
                summary = details[:140]

            # Fixed versions per package affected
            fixed_map: dict[str, list[str]] = defaultdict(list)
            for aff in v_data.get("affected", []):
                aff_pkg = aff.get("package", {})
                pname = aff_pkg.get("name", "").lower()
                ecosystem = aff_pkg.get("ecosystem", "").lower()
                if ecosystem and ecosystem != "npm":
                    continue
                for rng in aff.get("ranges", []):
                    for evt in rng.get("events", []):
                        if "fixed" in evt and evt["fixed"]:
                            fixed_map[pname].append(str(evt["fixed"]).strip())

            # Find all packages in this graph linked to this vuln
            linked_pkgs = [
                packages[pid]
                for pid, vids in pkg_vuln_ids.items()
                if v_id in vids and pid in packages
            ]

            min_depth = min((p["depth"] for p in linked_pkgs), default=1)
            max_dependents = max((p["dependents"] for p in linked_pkgs), default=0)

            # SCORING: vuln.risk = cvss*(1+log2(1+dependents))*(1.5 if min depth<=2 else 1)
            depth_multiplier = 1.5 if min_depth <= 2 else 1.0
            vuln_risk = round(cvss_val * (1.0 + math.log2(1.0 + max_dependents)) * depth_multiplier, 2)

            aliases = v_data.get("aliases") or []
            if not isinstance(aliases, list):
                aliases = [str(aliases)]

            vuln_nodes[v_id] = {
                "id": v_id,
                "aliases": aliases,
                "severity": sev_upper,
                "cvss": round(cvss_val, 1),
                "summary": summary,
                "url": primary_url,
                "risk": vuln_risk,
            }

            for p in linked_pkgs:
                pkg_name_lower = p["name"].lower()
                fixes = list(dict.fromkeys(fixed_map.get(pkg_name_lower, [])))
                has_vuln_links.append({
                    "pkgId": p["id"],
                    "vulnId": v_id,
                    "fixed": fixes,
                })

        yield {
            "stage": "vulns_hydrated",
            "msg": f"Hydrated {len(vuln_nodes)} vulnerabilities and {len(has_vuln_links)} package-vuln links",
            "n": len(vuln_nodes),
        }

        # Step (5): wipe graph, create indexes, load with UNWIND batches of 500
        engine = active_engine()
        if is_falkor_available():
            yield {
                "stage": "falkor_write",
                "msg": f"Loading data into FalkorDB graph '{GRAPH_NAME}'",
                "n": len(packages),
            }
            try:
                await asyncio.to_thread(
                    write_graph_to_falkor, packages, all_edges, vuln_nodes, has_vuln_links, chunk_size
                )
                engine = "falkordb"
                yield {
                    "stage": "falkor_complete",
                    "msg": f"Successfully wrote {len(packages)} packages and {len(vuln_nodes)} vulns to FalkorDB",
                    "n": len(packages),
                }
            except Exception as e:
                engine = "sqlite"
                yield {
                    "stage": "falkor_error",
                    "msg": f"FalkorDB write failed: {e}. Continuing with the SQLite snapshot engine.",
                    "n": 0,
                }
        else:
            yield {
                "stage": "sqlite_ready",
                "msg": "Using the local SQLite snapshot engine (no Docker required)",
                "n": len(packages),
            }

        # Save snapshot for analysis
        snapshot_data = {
            "roots": roots,
            "packages": packages,
            "edges": all_edges,
            "vulns": vuln_nodes,
            "has_vuln": has_vuln_links,
        }
        write_cache("latest_graph_snapshot.json", snapshot_data)

        # Calculate final blast score for summary
        # blastScore = round(100*R/(R+60)), R = sum of risk of unresolved vulns
        r_total = sum(v["risk"] for v in vuln_nodes.values())
        blast_score = round(100.0 * r_total / (r_total + 60.0)) if r_total > 0 else 0

        yield {
            "stage": "complete",
            "msg": f"Ingestion complete: {len(packages)} packages, {len(vuln_nodes)} vulnerabilities, Blast Score: {blast_score}",
            "n": len(packages),
            "packages_count": len(packages),
            "vulns_count": len(vuln_nodes),
            "blast_score": blast_score,
            "engine": engine,
            "partial": bool(osv_failed or failed_roots),
        }


async def seed_presets(only: Optional[list[str]] = None) -> None:
    """Prefetch presets, analyse them and save named snapshots for instant switching."""
    from backend.analyze import analyze

    print("==================================================")
    print("BLAST RADIUS: Seeding presets (deps.dev + OSV)")
    print("==================================================")

    for preset_name, roots in PRESETS.items():
        if only and preset_name not in only:
            continue
        print(f"\n[Preset: {preset_name}] Roots: {roots}")
        final_pkgs = final_vulns = 0
        async for progress in ingest(roots):
            if progress.get("stage") in ("deps_resolved", "vulns_hydrated", "warn", "complete"):
                print(f"  -> {progress.get('msg')}")
            final_pkgs = progress.get("packages_count", final_pkgs)
            final_vulns = progress.get("vulns_count", final_vulns)
        summary = await asyncio.to_thread(analyze)
        snapshot = read_cache("latest_graph_snapshot.json")
        if snapshot is None:
            raise RuntimeError(f"Analysis did not produce a snapshot for preset '{preset_name}'.")
        write_cache(f"snapshot_{preset_name}.json", snapshot)
        print(f"Summary for '{preset_name}': {final_pkgs} packages, {final_vulns} vulns, "
              f"Blast Score {summary['blastScore']} (engine: {summary['engine']})")

    print("\nPreset seeding completed.")


if __name__ == "__main__":
    args = sys.argv[1:]
    if args and args[0] == "seed":
        asyncio.run(seed_presets(args[1:] or None))
    elif args:
        # python -m backend.ingest express@4.17.1 lodash@4.17.15
        async def _custom() -> None:
            async for ev in ingest(args):
                print(f"[{ev['stage']}] {ev['msg']}")
        asyncio.run(_custom())
    else:
        print("Usage: python -m backend.ingest seed [preset ...] | python -m backend.ingest name@ver [name@ver ...]")
