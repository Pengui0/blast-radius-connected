# BLAST RADIUS: supply-chain triage agent on FalkorDB

Blast Radius is a supply-chain security triage workspace. It maps npm dependency trees and known advisories
into a graph, then helps prioritize **the fixes that clear the most risk**, trace their dependency paths,
simulate their impact, and generate a remediation patch (`overrides` JSON + issue text).

Dependency data comes from [deps.dev](https://deps.dev) and advisories from [OSV](https://osv.dev). Custom scans
send npm package names and versions to those public services; no private source code or repository files are uploaded.

## Run it

Prerequisites: Python 3.12, Node.js 22 with npm, and PowerShell. Docker Desktop is only needed for optional FalkorDB;
the default SQLite mode runs without Docker.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
Copy-Item .env.example .env
python -m pip install -r backend\requirements.txt
npm ci
npm run dev
```

Set `GEMINI_API_KEY` in `.env` to use the live agent. Without it, the agent replays recorded runs.
The SQLite database is created automatically at `backend/cache/blast_radius.sqlite3`.
If the built-in presets are missing, seed them with `python -m backend.ingest seed` from the activated environment.

### Optional: FalkorDB

To use FalkorDB and enable the Cypher console, start Docker Desktop and run:

```bash
docker compose up -d
```

Then, in the same PowerShell window you use to start the app, run:

```powershell
$env:GRAPH_BACKEND = "falkordb"
npm run dev
```

Leave `GRAPH_BACKEND` unset to use SQLite. If FalkorDB is unavailable, the app uses its local SQLite snapshot
instead. The SQLite mode uses NetworkX for graph analysis; Cypher queries require FalkorDB. To seed the three
built-in presets the first time, run
`python -m backend.ingest seed` in the activated virtual environment. Presets are loaded from cached data when
available; new scans may contact deps.dev and OSV.

## Verify a fresh checkout

In the activated Python environment, run the backend regression tests and frontend checks:

```powershell
python -m unittest discover -s backend\tests -v
npm run lint
npm run build
```

The GitHub Actions workflow runs these checks for pushes and pull requests.

## Hackathon demo checklist
`GRAPH_BACKEND=falkordb`, start the provided FalkorDB service, and show:

1. A seeded dependency graph and the selected graph engine in the status badge.
2. An AI analyst question with its graph-tool evidence and highlighted attack path.
3. The prioritized remediation plan, a non-destructive simulation, and the generated patch.
4. The Cypher console running a read-only query against FalkorDB.

Set `GEMINI_API_KEY` for a live analyst run. Without it, the interface explicitly labels recorded replay mode;
use replay for a deterministic backup demo. Do not present replay output as a live model response.


## Graph data model

```
(:App {id})
(:Package {id:'name@ver', name, version, depth, direct, exposed, dependents, pagerank, betweenness, community, vulnFlow, exclusiveRisk})
(:Vuln {id, aliases, severity, cvss, summary, url, risk})
(:Fix {id:'fix:<pkg>', pkg, toVersion, tier, clears, unfixed, riskCleared})

(App|Package)-[:DEPENDS_ON {req}]->(Package)      requirement string from deps.dev
(Package)-[:REQUIRED_BY]->(Package|App)           reverse copy, for blast-radius traversals
(Package)-[:HAS_VULN {fixed:[versions]}]->(Vuln)
(Fix)-[:TARGETS]->(Package)      (Fix)-[:RESOLVES]->(Vuln)   // only advisories the target version really fixes
```

## Cypher and graph algorithms the product depends on

| Question | FalkorDB feature | MCP tool |
| --- | --- | --- |
| How does vuln X reach my app? | `WITH shortestPath((a)-[:DEPENDS_ON*]->(p)) AS path RETURN path` | `attack_path` |
| Who is hurt if package P changes? | `(p)-[:REQUIRED_BY*0..64]->(u)` reachability | `blast_radius` |
| Which package is structurally critical? | `algo.pageRank('Package','DEPENDS_ON')` | `chokepoints` |
| Which package bridges ecosystems? | `algo.betweenness({samplingSize, samplingSeed})` | `chokepoints` |
| Which sub-ecosystem carries the risk? | `algo.labelPropagation` (fallback `algo.WCC`) | `risk_clusters` |
| Which direct dependency is the root cause? | per-root reachability + set difference -> `exclusiveRisk` | `chokepoints` |
| Fewest fixes for most risk | greedy set cover over `(:Fix)-[:RESOLVES]->(:Vuln)` | `fix_plan` |
| What if I apply these fixes? | non-destructive recompute over `RESOLVES` | `simulate` |
| Anything else | read-only `GRAPH.RO_QUERY`, LIMIT 200 | `cypher_ro` |

Risk model: `vuln.risk = cvss * (1 + log2(1 + dependents)) * (1.5 if depth <= 2 else 1)`;
`BlastScore = round(100*R/(R+60))`. When OSV gives only a severity label, CVSS falls back to LOW 3, MODERATE 5.5, HIGH 7.5, CRITICAL 9.5.
Fix tiers: **refresh** (fixed version satisfies every incoming requirement), **override** (same major, some parent pins it),
**breaking** (major bump or no fix). An advisory with no upstream fix is never counted as cleared.

## Layout

`backend/` ingest.py (deps.dev+OSV -> graph) · analyze.py (algorithms, fixes) · tools.py (10 graph tools) ·
mcp_server.py (FastMCP stdio) · agent.py (Gemini tool loop over MCP, replay fallback) · main.py (REST + SSE)
`src/` React UI (graph canvas, threat board, agent panel, patch drawer, Cypher console)  ·  `server.ts` dev server + `/api` proxy

## Deploy (one container: landing page + app + API)

Routes: `/` is the landing page (`landing/index.html`), `/app/` is the React app, `/api/*` is the FastAPI backend, `/healthz` is the host health check.

```
docker build -t blast-radius .
docker run -p 8080:8080 -e AGENT_MODE=replay blast-radius
```

On Render, push this repo and create a Blueprint from `render.yaml` (or a Docker web service). Set `GEMINI_API_KEY` in the dashboard and delete `AGENT_MODE=replay` to use the live analyst. `DISABLE_SCAN=1` keeps a public demo on the preset projects, because all visitors share one graph. Heavy endpoints are rate-limited per IP in `server.ts`.

Before deploying, edit the `CONFIG` block at the bottom of `landing/index.html` (video link, team, work done during the event).
