import React, { useState } from 'react';
import {
  Terminal,
  Play,
  Clock,
  Sparkles,
  Code2,
  Copy,
  Check,
  Table,
  CheckCircle2,
  AlertCircle,
} from 'lucide-react';

interface CypherTabProps {
  onHighlight: (highlight: { nodes: string[]; edges?: [string, string][] }) => void;
  engine: string;
}

const SAVED_QUERIES = [
  {
    name: 'PageRank Ranking (Top 10)',
    query: "CALL algo.pageRank('Package', 'DEPENDS_ON') YIELD node, score\nRETURN node.name, node.version, score ORDER BY score DESC LIMIT 10",
    description: 'Identifies the structural linchpin packages that the entire dependency graph relies upon.',
  },
  {
    name: 'Betweenness Centrality (Bridge Packages)',
    query: "CALL algo.betweenness({nodeLabels:['Package'], relationshipTypes:['DEPENDS_ON'], samplingSize:64}) YIELD node, score\nRETURN node.name, score ORDER BY score DESC LIMIT 10",
    description: 'Finds bottleneck dependencies that bridge multiple sub-ecosystems in the transitive tree.',
  },
  {
    name: 'Shortest Attack Path to axios',
    query: "MATCH (a:App {id: 'app'}), (p:Package {id: 'axios@0.21.1'})\nWITH shortestPath((a)-[:DEPENDS_ON*]->(p)) AS path\nRETURN path, length(path) AS depth",
    description: 'Pinpoints the exact import chain propagating a vulnerable library directly into your runtime.',
  },
  {
    name: 'BFS Upstream Blast Exposure',
    query: "MATCH (p:Package {name: 'axios'})\nMATCH (p)-[:REQUIRED_BY*1..64]->(upstream:Package)\nRETURN DISTINCT upstream.id AS id, upstream.direct AS direct, upstream.depth AS depth LIMIT 15",
    description: 'Calculates the upstream dependents that inherit security exposure and risk.',
  },
  {
    name: 'Top Blast Radius Vulnerabilities',
    query: "MATCH (v:Vuln)\nRETURN v.id, v.severity, v.cvss, v.risk, v.summary ORDER BY v.risk DESC LIMIT 10",
    description: 'Ranks all known CVE / GHSA advisories by scaled Blast Risk formula.',
  },
  {
    name: 'Packages with Direct Exposure',
    query: "MATCH (p:Package {direct: true})\nRETURN p.name, p.version, p.depth, p.pagerank ORDER BY p.pagerank DESC LIMIT 10",
    description: 'Inspects direct top-level dependencies declared in your package.json.',
  },
];

const renderCell = (cell: any): string =>
  cell && typeof cell === 'object'
    ? cell._type === 'path'
      ? cell.nodes.join(' → ')
      : JSON.stringify(cell)
    : String(cell);

export const CypherTab: React.FC<CypherTabProps> = ({ onHighlight, engine }) => {
  const [cypherQuery, setCypherQuery] = useState(SAVED_QUERIES[0].query);
  const [executing, setExecuting] = useState(false);
  const [resultRows, setResultRows] = useState<any[][] | null>(null);
  const [columns, setColumns] = useState<string[]>([]);
  const [elapsedMs, setElapsedMs] = useState<number | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [highlightPayload, setHighlightPayload] = useState<{ nodes: string[]; edges: [string, string][] } | null>(null);
  const [copied, setCopied] = useState(false);

  const handleRunQuery = async (customQ?: string) => {
    const q = (customQ || cypherQuery).trim();
    if (!q) return;

    setExecuting(true);
    setErrorMsg(null);
    setResultRows(null);

    try {
      const res = await fetch('/api/tools/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tool: 'cypher_ro', args: { query: q } }),
      });

      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: Failed to execute Cypher`);
      }

      const data = await res.json();
      setElapsedMs(data.ms ?? null);

      if (data.data?.error) {
        setErrorMsg(data.data.error);
        return;
      }

      if (Array.isArray(data.data)) {
        setResultRows(data.data);
        if (Array.isArray(data.columns) && data.columns.length > 0) {
          setColumns(data.columns);
        } else if (data.data.length > 0 && Array.isArray(data.data[0])) {
          setColumns(data.data[0].map((_: any, i: number) => `col ${i + 1}`));
        } else {
          setColumns(['Result']);
        }
      } else if (data.data?.notice) {
        setResultRows([['Notice', data.data.notice]]);
        setColumns(['Type', 'Message']);
      }

      if (data.highlight && (data.highlight.nodes?.length > 0 || data.highlight.edges?.length > 0)) {
        setHighlightPayload(data.highlight);
        onHighlight(data.highlight);
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Execution error');
    } finally {
      setExecuting(false);
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(cypherQuery);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (engine !== 'falkordb') {
    return (
      <section className="mx-auto max-w-3xl rounded-2xl border border-slate-700/70 bg-[#EEF1E7] p-5 shadow-xl sm:p-6">
        <div className="mb-4 flex h-9 w-9 items-center justify-center rounded-xl bg-cyan-400/10 text-cyan-300">
          <Terminal className="h-4 w-4" />
        </div>
        <h1 className="text-lg font-semibold text-white">Cypher console requires FalkorDB</h1>
        <p className="mt-2 text-sm leading-6 text-slate-400">
          This workspace is using SQLite with NetworkX. Graph analysis and remediation tools work locally;
          direct Cypher queries are available when FalkorDB is selected.
        </p>
        <div className="mt-5 rounded-xl border border-slate-800 bg-slate-950/70 p-4">
          <p className="text-xs font-semibold text-slate-300">To enable the query console</p>
          <ol className="mt-2 list-inside list-decimal space-y-1.5 text-xs leading-5 text-slate-400">
            <li>Start Docker Desktop and run <code className="text-cyan-200">docker compose up -d</code>.</li>
            <li>Set <code className="text-cyan-200">GRAPH_BACKEND=falkordb</code> in the terminal before starting the app.</li>
            <li>Restart the app so the backend connects to FalkorDB.</li>
          </ol>
        </div>
      </section>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold text-amber-400 uppercase tracking-wider bg-amber-500/10 border border-amber-500/20 px-2.5 py-0.5 rounded-full">
                FalkorDB Cypher Engine
              </span>
              <span className="text-xs text-slate-400 font-mono">Read-Only (LIMIT 200 enforced)</span>
            </div>
            <h2 className="text-xl font-bold text-white mt-1">Interactive Graph Algorithm Console</h2>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl">
              Directly query graph algorithms (`algo.pageRank`, `algo.betweenness`, `shortestPath`, `algo.BFS`) or write bespoke Cypher queries to interrogate the supply chain.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => handleRunQuery()}
              disabled={executing}
              className="px-5 py-2.5 rounded-xl bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs transition-all shadow-lg shadow-amber-500/20 disabled:opacity-50 flex items-center gap-2"
            >
              <Play className="w-4 h-4 fill-current" />
              {executing ? 'Executing...' : 'Run Cypher Query'}
            </button>
          </div>
        </div>

        {/* Saved Query Chips */}
        <div className="mt-5 pt-4 border-t border-slate-800 flex flex-wrap items-center gap-2">
          <span className="text-[10px] uppercase font-semibold text-slate-500">Saved Recipes:</span>
          {SAVED_QUERIES.map((sq, idx) => (
            <button
              key={idx}
              onClick={() => {
                setCypherQuery(sq.query);
                handleRunQuery(sq.query);
              }}
              className="text-xs px-2.5 py-1 rounded-lg bg-slate-950/70 border border-slate-800 text-slate-300 hover:text-white hover:border-amber-500/40 hover:bg-slate-900 transition-all font-mono"
            >
              {sq.name}
            </button>
          ))}
        </div>
      </div>

      {/* Query Editor & Controls */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-xs font-mono font-bold text-slate-400 flex items-center gap-1.5">
            <Code2 className="w-4 h-4 text-amber-400" />
            CYPHER EDITOR
          </span>
          <button
            onClick={handleCopy}
            className="text-xs text-slate-400 hover:text-white flex items-center gap-1 font-mono transition-colors"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            {copied ? 'Copied' : 'Copy Query'}
          </button>
        </div>

        <div className="relative">
          <textarea
            value={cypherQuery}
            onChange={(e) => setCypherQuery(e.target.value)}
            rows={4}
            className="w-full bg-slate-950 text-cyan-300 font-mono text-xs p-4 rounded-xl border border-slate-800 focus:border-amber-500/50 outline-none leading-relaxed"
            placeholder="MATCH (p:Package) RETURN p.name, p.version LIMIT 10"
          />
        </div>
      </div>

      {/* Results View */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Table className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-white">Execution Output</h3>
            {resultRows && (
              <span className="text-xs text-slate-400 font-mono">
                ({resultRows.length} {resultRows.length === 1 ? 'row' : 'rows'})
              </span>
            )}
          </div>

          <div className="flex items-center gap-3">
            {elapsedMs !== null && (
              <span className="text-xs font-mono text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-2.5 py-1 rounded-lg flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5" />
                {elapsedMs} ms
              </span>
            )}

            {highlightPayload && (
              <button
                onClick={() => onHighlight(highlightPayload)}
                className="text-xs font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 px-3 py-1 rounded-lg hover:bg-cyan-500/30 transition-all flex items-center gap-1.5"
              >
                <Sparkles className="w-3.5 h-3.5" />
                Highlight ({highlightPayload.nodes.length} nodes)
              </button>
            )}
          </div>
        </div>

        {/* Error notification */}
        {errorMsg && (
          <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800/40 text-xs text-rose-300 flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
            <span>{errorMsg}</span>
          </div>
        )}

        {/* Results Table */}
        {resultRows && resultRows.length > 0 ? (
          <div className="overflow-x-auto rounded-xl border border-slate-800 max-h-96">
            <table className="w-full text-left font-mono text-xs">
              <thead className="bg-slate-950/90 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800 sticky top-0">
                <tr>
                  <th className="py-2.5 px-4 w-12 text-slate-600">#</th>
                  {columns.map((c, i) => (
                    <th key={i} className="py-2.5 px-4">
                      {c}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 bg-slate-950/40 text-slate-300">
                {resultRows.map((row, rIdx) => (
                  <tr key={rIdx} className="hover:bg-slate-900/60 transition-colors">
                    <td className="py-2 px-4 text-slate-600 text-[11px]">{rIdx + 1}</td>
                    {Array.isArray(row) ? (
                      row.map((cell, cIdx) => (
                        <td key={cIdx} className="py-2 px-4 truncate max-w-xs">
                          {renderCell(cell)}
                        </td>
                      ))
                    ) : (
                      <td className="py-2 px-4">{String(row)}</td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          !executing &&
          !errorMsg && (
            <div className="text-center py-10 text-xs text-slate-500">
              Run a Cypher query or pick a saved recipe above to inspect rows.
            </div>
          )
        )}
      </div>
    </div>
  );
};
