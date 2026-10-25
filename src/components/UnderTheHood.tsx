import React from 'react';
import {
  Network,
  Cpu,
  Activity,
  Layers,
  ArrowRight,
  Database,
  Flame,
  CheckCircle2,
  GitBranch,
} from 'lucide-react';

const MCP_TOOLS = [
  {
    name: 'overview()',
    args: 'none',
    returns: '{packages, vulns, directDependencies, totalRisk, blastScore, bySeverity}',
    whenToUse: 'Initial triage, posture health checks, high-level KPI dashboard summaries.',
  },
  {
    name: 'top_threats(limit=5)',
    args: 'limit: int (default 5)',
    returns: 'list of [{id, severity, cvss, risk, summary, url, affectedPackages, fixed}]',
    whenToUse: 'Identifying most urgent CVE/GHSA advisories ranked by logarithmic blast risk.',
  },
  {
    name: 'attack_path(target)',
    args: 'target: package or vuln id (e.g. axios@0.21.1)',
    returns: '{depth, path: [ids], requirements: [req]}',
    whenToUse: 'Verifying ingress chains from root application down to vulnerable transitive dependencies.',
  },
  {
    name: 'blast_radius(package)',
    args: 'package: package name or id (e.g. axios)',
    returns: '{dependentsCount, directRootsAffected, dependents: [{id, direct, depth}]}',
    whenToUse: 'Calculating upstream collateral damage if a package is compromised or removed.',
  },
  {
    name: 'chokepoints(limit=5)',
    args: 'limit: int (default 5)',
    returns: 'list of direct dependencies [{id, vulnFlow, exclusiveRisk, uniqueVulns}]',
    whenToUse: 'Determining which direct root imports carry unique transitive vulnerability flows.',
  },
  {
    name: 'risk_clusters()',
    args: 'none',
    returns: 'list of community clusters [{communityId, packagesCount, vulnsCount, totalRisk}]',
    whenToUse: 'Evaluating architectural isolation boundaries using Label Propagation / WCC.',
  },
  {
    name: 'fix_plan(max_actions=5)',
    args: 'max_actions: int (default 5)',
    returns: '{initialBlastScore, finalBlastScore, totalRiskReduction, actions: [{action, fixId, pkg, toVersion, tier, effort, clears, riskCleared}]}',
    whenToUse: 'Generating an optimal greedy set-cover remediation roadmap maximizing risk reduction.',
  },
  {
    name: 'simulate(fix_ids)',
    args: 'fix_ids: list of strings (e.g. ["fix:axios"])',
    returns: '{healedVulnsCount, healedPackagesCount, residualBlastScore, riskReduced}',
    whenToUse: 'Non-destructively validating fix efficacy before touching lockfiles or deploying code.',
  },
  {
    name: 'build_patch(fix_ids)',
    args: 'fix_ids: list of strings (e.g. ["fix:axios"])',
    returns: '{overrides: json, commands: [str], issue_markdown: str}',
    whenToUse: 'Emitting deterministic package.json overrides, npm CLI commands, and PR descriptions.',
  },
  {
    name: 'cypher_ro(query)',
    args: 'query: Cypher string (LIMIT 200 enforced)',
    returns: 'rows: list of lists with execution ms and graph highlight payload',
    whenToUse: 'Answering investigative graph questions or running arbitrary custom Cypher queries.',
  },
];

const GRAPH_ALGORITHMS = [
  {
    name: "algo.pageRank('Package', 'DEPENDS_ON')",
    category: 'Topology Centrality',
    usedFor: 'Identifies structural linchpin packages that the entire dependency DAG relies upon. Scaled node radius in graph.',
    complexity: 'O(V + E) per iteration',
  },
  {
    name: "algo.betweenness({samplingSize: 64})",
    category: 'Bridge Detection',
    usedFor: 'Finds bottleneck dependencies that bridge multiple sub-ecosystems in the transitive tree.',
    complexity: 'O(k * (V + E)) with k=64 sampling',
  },
  {
    name: 'algo.labelPropagation (fallback WCC)',
    category: 'Community Partitioning',
    usedFor: 'Clusters nodes into modular isolation zones to contain supply-chain blast contagion.',
    complexity: 'Linear-time label diffusion',
  },
  {
    name: "algo.BFS(p, 64, 'REQUIRED_BY')",
    category: 'Upstream Blast Propagation',
    usedFor: 'Traverses reverse edges to determine dependents count, mark upstream packages exposed=true, and compute logarithmic Vuln.risk.',
    complexity: 'O(V + E) bounded to 64 hops',
  },
  {
    name: "algo.BFS(D, 64, 'DEPENDS_ON')",
    category: 'Direct Chokepoint Isolation',
    usedFor: 'Executes per direct dependency D to find downstream vulnerable set; applies Python set math to isolate exclusive vulnerability flows.',
    complexity: 'O(D * (V + E)) where D = direct roots',
  },
  {
    name: 'shortestPath((a:App)-[:DEPENDS_ON*]->(p))',
    category: 'Ingress Chain Proof',
    usedFor: 'Finds the exact minimum hop count and requirement constraints connecting the application runtime to an exploitable package.',
    complexity: 'O(V + E) via bidirectional search',
  },
];

export const UnderTheHood: React.FC<{ engine: string }> = ({ engine }) => {
  const usesFalkorDB = engine === 'falkordb';

  return (
    <div className="space-y-5">
      {/* 1. Header Banner */}
      <div className="rounded-2xl border border-slate-800 bg-gradient-to-r from-slate-900 via-slate-900/90 to-cyan-950/30 p-5 sm:p-6">
        <div className="mb-2 flex flex-wrap items-center gap-2">
          <span className="rounded-full border border-cyan-500/20 bg-cyan-500/10 px-2.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-cyan-300">
            Architecture
          </span>
          <span className="text-xs text-slate-400">{usesFalkorDB ? 'FalkorDB graph engine' : 'Local SQLite + NetworkX engine'}</span>
        </div>
        <h2 className="text-lg font-semibold text-white">How dependency risk is analyzed</h2>
        <p className="mt-1 max-w-3xl text-xs leading-5 text-slate-400">
          The same dependency and advisory model powers both engines. SQLite persists local snapshots and NetworkX analyzes them; FalkorDB is optional and adds direct Cypher queries.
        </p>
      </div>

      {/* 2. Visual Data Model Diagram */}
      <div className="space-y-5 rounded-2xl border border-slate-800 bg-slate-900/60 p-4 sm:p-5">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-white">
          <Network className="h-4 w-4 text-cyan-400" />
          Dependency graph schema
        </h3>

        {/* Node Types Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="p-4 rounded-xl bg-slate-950/90 border border-cyan-500/30 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs font-bold text-cyan-400">(:App)</span>
              <span className="text-[10px] text-slate-500 font-mono">1 per repo</span>
            </div>
            <div className="text-xs text-slate-300 font-mono space-y-1">
              <div>• id: <span className="text-slate-400">string ("app")</span></div>
              <div>• name: <span className="text-slate-400">string</span></div>
            </div>
            <p className="text-[11px] text-slate-400 pt-1 border-t border-slate-900">
              The root application entry point anchoring the dependency DAG.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-950/90 border border-sky-500/30 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs font-bold text-sky-400">(:Package)</span>
              <span className="text-[10px] text-slate-500 font-mono">V nodes</span>
            </div>
            <div className="text-xs text-slate-300 font-mono space-y-1">
              <div>• id: <span className="text-slate-400">"name@version"</span></div>
              <div>• depth, direct, exposed</div>
              <div>• pagerank, betweenness</div>
              <div>• community, dependents</div>
            </div>
            <p className="text-[11px] text-slate-400 pt-1 border-t border-slate-900">
              Direct and transitive npm libraries hydrated from deps.dev.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-950/90 border border-rose-500/30 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs font-bold text-rose-400">(:Vuln)</span>
              <span className="text-[10px] text-slate-500 font-mono">OSV advisories</span>
            </div>
            <div className="text-xs text-slate-300 font-mono space-y-1">
              <div>• id: <span className="text-slate-400">"GHSA-..."</span></div>
              <div>• severity: <span className="text-slate-400">CRITICAL|HIGH...</span></div>
              <div>• cvss: <span className="text-slate-400">float (0-10)</span></div>
              <div>• risk: <span className="text-slate-400">log2 scaled score</span></div>
            </div>
            <p className="text-[11px] text-slate-400 pt-1 border-t border-slate-900">
              Known CVEs/GHSAs hydrated positional batch from api.osv.dev.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-950/90 border border-emerald-500/30 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs font-bold text-emerald-400">(:Fix)</span>
              <span className="text-[10px] text-slate-500 font-mono">Synthesized</span>
            </div>
            <div className="text-xs text-slate-300 font-mono space-y-1">
              <div>• id: <span className="text-slate-400">"fix:name"</span></div>
              <div>• toVersion: <span className="text-slate-400">semver target</span></div>
              <div>• tier: <span className="text-slate-400">refresh|override|break</span></div>
              <div>• clears, riskCleared</div>
            </div>
            <p className="text-[11px] text-slate-400 pt-1 border-t border-slate-900">
              Candidate upgrade targets created per vulnerable package name.
            </p>
          </div>
        </div>

        {/* Edges Flowchart */}
        <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-3 font-mono text-xs">
          <div className="text-xs font-bold uppercase tracking-wider text-amber-400 font-sans">
            Directed Relationship Invariants
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-slate-300">
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="text-cyan-400">(:App|:Package)</span>
              <span className="text-amber-400 font-bold"> -[:DEPENDS_ON &#123;req&#125;]-&gt; </span>
              <span className="text-sky-400">(:Package)</span>
              <div className="text-[10px] text-slate-500 font-sans mt-1">Normal downstream import DAG</div>
            </div>

            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="text-sky-400">(:Package)</span>
              <span className="text-indigo-400 font-bold"> -[:REQUIRED_BY]-&gt; </span>
              <span className="text-cyan-400">(:Package|:App)</span>
              <div className="text-[10px] text-slate-500 font-sans mt-1">Reverse copy for instant upstream BFS</div>
            </div>

            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="text-sky-400">(:Package)</span>
              <span className="text-rose-400 font-bold"> -[:HAS_VULN &#123;fixed&#125;]-&gt; </span>
              <span className="text-rose-400">(:Vuln)</span>
              <div className="text-[10px] text-slate-500 font-sans mt-1">Carries fixed version array from OSV</div>
            </div>

            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="text-emerald-400">(:Fix)</span>
              <span className="text-emerald-400 font-bold"> -[:TARGETS]-&gt; </span>
              <span className="text-sky-400">(:Package)</span>
              <span className="text-emerald-400 font-bold">, -[:RESOLVES]-&gt; </span>
              <span className="text-rose-400">(:Vuln)</span>
              <div className="text-[10px] text-slate-500 font-sans mt-1">Connects upgrade actions to packages and vulns</div>
            </div>
          </div>
        </div>
      </div>

      {/* 3. The 10 MCP Tools Table */}
      <div className="space-y-4 rounded-2xl border border-slate-800 bg-slate-900/60 p-4 sm:p-5">
        <div className="flex items-center justify-between">
          <h3 className="text-base font-bold text-white flex items-center gap-2">
            <Cpu className="h-4 w-4 text-indigo-400" />
            The 10 Registered FastMCP Tools (Protocol: stdio FastMCP)
          </h3>
          <span className="text-xs font-mono text-emerald-400 bg-emerald-500/10 px-2.5 py-1 rounded-lg border border-emerald-500/20">
            Standard &#123;data, cypher, ms, highlight&#125; envelope
          </span>
        </div>

        <div className="overflow-x-auto rounded-xl border border-slate-800">
          <table className="w-full text-left font-mono text-xs">
            <thead className="bg-slate-950/90 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Tool Signature</th>
                <th className="py-3 px-4">Parameters</th>
                <th className="py-3 px-4">WHEN TO USE (Agent Triggers)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 bg-slate-950/40 text-slate-300">
              {MCP_TOOLS.map((t, idx) => (
                <tr key={idx} className="hover:bg-slate-900/60 transition-colors">
                  <td className="py-3 px-4 font-bold text-amber-300">{t.name}</td>
                  <td className="py-3 px-4 text-slate-400 text-[11px]">{t.args}</td>
                  <td className="py-3 px-4 font-sans text-slate-300 text-xs leading-relaxed">{t.whenToUse}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* 4. Graph Algorithm Reference */}
      <div className="space-y-4 rounded-2xl border border-slate-800 bg-slate-900/60 p-4 sm:p-5">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-white">
          <Activity className="h-4 w-4 text-amber-400" />
          Graph analyses and their purpose
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {GRAPH_ALGORITHMS.map((algo, idx) => (
            <div key={idx} className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-2 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between text-xs mb-1">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 font-bold">
                    {algo.category}
                  </span>
                  <span className="text-[10px] text-slate-500 font-mono">{algo.complexity}</span>
                </div>
                <h4 className="font-mono text-xs font-bold text-white mt-1.5 break-all">{algo.name}</h4>
                <p className="text-xs text-slate-400 mt-2 font-sans leading-relaxed">{algo.usedFor}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
