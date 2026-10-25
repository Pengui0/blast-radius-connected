# Audit: what was broken, what I changed, how I tested

Tested against a **real FalkorDB** (Redis + falkordb.so), not mocks: ingest + analyze on all 3 presets (1,278-package graph runs
analysis in about 1 s), all 10 tools directly and over MCP stdio, every REST endpoint, and the Express proxy including SSE.
Frontend: `tsc --noEmit` and `vite build` pass.

## Critical (the demo would have misled or failed)
| # | Problem | Fix |
|---|---|---|
| 1 | `npm install` failed out of the box (esbuild ^0.25 vs vite 8 peer range) | esbuild ^0.28 |
| 2 | `attack_path` used `MATCH path = shortestPath(...)`, which FalkorDB rejects, then iterated `Path.nodes` (a method), so it **always silently fell back to networkx** while still labelled FalkorDB | `WITH shortestPath(...) AS path`, call `nodes()`/`edges()`. 2 ms instead of 180 ms |
| 3 | In-memory fallbacks fabricated FalkorDB output: fake `cypher`/`ms`, and `cypher_ro` returned **canned rows unrelated to the user's query** | every result carries `engine`; `cypher_ro` returns a clear error when FalkorDB is offline |
| 4 | Two sources of truth: with FalkorDB online, `simulate` and `build_patch` read a JSON snapshot that never contained the fixes, so **Simulate healed 0 and the patch was empty** | state is loaded from FalkorDB; snapshot is mirrored after analysis |
| 5 | Over-claimed fixes: `fix:axios` claimed 24 advisories but 4 have no upstream fix, which inflated the headline Blast Score drop | RESOLVES only for advisories the target version fixes; `unfixed` reported separately |
| 6 | UI/API contract mismatches: simulate keys (`residualBlastScore`), `overrides` string vs object, `/api/graph` ignoring FalkorDB. These only looked right against the mock in `server.ts` | aligned both sides |
| 7 | "Custom scan" never scanned (it called the agent endpoint) | real `POST /api/scan` stream, validation, lock |
| 8 | Preset switch changed only the JSON, not FalkorDB, so graph and agent disagreed | reloads FalkorDB + re-analyzes |
| 9 | `server.ts` served invented numbers (1278 pkgs, 95 score, 14.8 ms) whenever the backend was down; so did the UI defaults, `'18.4 ms'`, a fake override list and a fake attack path | removed; UI shows real zeros/errors/banners |

## Important
- `asyncio` not imported in `main.py` (NameError on client disconnect); CORS `*` + credentials; relative paths in load-preset.
- Blocking calls (analyze, Gemini, DB writes) ran on the event loop and stalled SSE -> `asyncio.to_thread`.
- Silent failures: deps.dev/OSV errors were swallowed (a scan could "succeed" with 0 advisories) -> `warn` events + `partial` flag.
- `cypher_ro`: Node/Edge/Path objects were not JSON-serialisable; result columns were `Col_1..`; bad LIMIT handling.
- Port clash: FalkorDB Browser and the app both on :3000 -> browser on :3001. Express proxy re-serialised bodies with a stale Content-Length.
- Agent: live vs replay was invisible in the UI; replay run is now labelled REPLAY; errors no longer masquerade as "Triage complete".
- Unused heavy dependencies, stale generated README, and committed `__pycache__` -> cleaned; real README with data model + algorithm table.

## Not verified (be aware)
- The **live Gemini loop** (no key in my sandbox) and a **live deps.dev/OSV fetch for new packages** (network blocked): both paths are unchanged except the changes above.
- Live FalkorDB and the UI engine badge were verified; Gemini remains in replay mode until a valid API key is configured.
- Deployment. Needs FalkorDB Cloud or a VM for FalkorDB, plus any Node host. Otherwise record the demo from localhost.

## Earlier audit baseline (out of 10)

The following score and recommendations describe the state at the time of the original audit, not the current follow-up.

| Area | Before | After | Note |
|---|---:|---:|---|
| Idea & track fit | 9 | 9 | Strong. Triage + path proof + heal + MCP is a coherent story |
| Graph does real work | 4 | 8 | Was mostly decorative/fallback; now every tool runs Cypher/algorithms |
| Correctness & honesty | 3 | 8 | Fabricated outputs and over-claimed fixes removed |
| Agent / MCP | 7 | 8 | Real MCP server, 10 tools; live loop still untested here |
| UX / visuals | 7 | 7.5 | Good ops-console look; agent and board are on separate tabs |
| Runs on a fresh machine | 3 | 8 | npm install, ports, seed, offline presets all verified |
| Submission readiness | 3 | 7 | README done; still needs deploy/video/blog |
| **Overall** | **4.5** | **7.9** | |

## Follow-up readiness work

- On wide screens, the overview now puts the dependency graph, remediation board, and AI analyst in one triage workspace. Narrower screens retain the focused tabs and responsive layout.
- Added five Python regression tests for fix tiers, installed-version safety, greedy remediation ordering, simulation de-duplication, and generated patch provenance/commands.
- Added GitHub Actions checks for Python tests, TypeScript, production build, and production dependency advisories.
- The production Vite build is warning-free; `npm audit --omit=dev` reported zero vulnerabilities.
- Verified the local SQLite/replay API for graph, stats, plans, simulations, patches, and the analyst SSE stream; checked desktop and mobile layout for horizontal overflow.
- Started the local FalkorDB container and ran all 10 graph tools against it. Verified live stats, graph data, remediation actions, simulation, patch generation, attack path, and read-only Cypher through the FalkorDB engine.
- FalkorDB's default 1-second graph query timeout interrupted analysis on the full preset. Added an explicit configurable 20-second per-query timeout and restricted the unauthenticated local Docker ports to loopback.

## Still required before submission

- The current session has no deployment credentials, public host, or recording artifact. A live deployment or a working demo video still needs to be supplied and checked.
- Live Gemini analysis, fresh deps.dev/OSV scans, and FalkorDB-selected end-to-end behavior were not exercised in this follow-up session.
- The hackathon FAQ permits continuing an existing project, but requires the **submission and its main FalkorDB implementation to be new work completed during the event**. Verify the event dates against the actual implementation/commit history; the current workspace does not include usable Git tooling/history to certify compliance.
- Keep a deterministic replay demo as backup and clearly label it; show a live run separately only after verifying Gemini and FalkorDB are connected.
