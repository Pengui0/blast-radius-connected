import React, { useState, useEffect } from 'react';
import {
  X,
  ExternalLink,
  ShieldAlert,
  ArrowDown,
  Sparkles,
  HelpCircle,
  CheckCircle2,
  AlertTriangle,
  GitCommit,
  Network,
} from 'lucide-react';
import { GraphNode } from './GraphCanvas';

interface PathInspectorProps {
  node: GraphNode | null;
  onClose: () => void;
  onHighlightPath: (nodes: string[], edges: [string, string][]) => void;
}

interface AttackPathData {
  depth: number;
  path: string[];
  requirements: string[];
  vuln?: {
    id: string;
    severity: string;
    cvss: number;
    risk: number;
    summary: string;
    url: string;
    fixed: string[];
  };
  rank?: number;
  rankReason?: string;
}

export const PathInspector: React.FC<PathInspectorProps> = ({
  node,
  onClose,
  onHighlightPath,
}) => {
  const [pathData, setPathData] = useState<AttackPathData | null>(null);
  const [loading, setLoading] = useState(false);
  const [showRankExplanation, setShowRankExplanation] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!node || node.id === 'app') {
      setPathData(null);
      return;
    }

    setLoading(true);
    setError(null);
    setShowRankExplanation(false);

    // Call /api/path?target=nodeId
    fetch(`/api/path?target=${encodeURIComponent(node.id)}`)
      .then((res) => (res.ok ? res.json() : Promise.reject('Path failed')))
      .then((data) => {
        if (data.error) {
          setPathData(null);
          setError(data.error);
          return;
        }
        const hops = Array.isArray(data.hops) ? data.hops : [];
        const rawPath: string[] = Array.isArray(data.path)
          ? data.path
          : hops.map((h: any) => h.node).filter(Boolean);
        const rawReqs: string[] = Array.isArray(data.requirements)
          ? data.requirements
          : hops.map((h: any) => h.req || '');

        const safePath = rawPath.length > 0 ? rawPath : ['app', node.id];
        const safeReqs = rawReqs.length > 0 ? rawReqs : ['entry', 'target'];

        const topVuln =
          data.vuln || (node.vulns && node.vulns.length > 0 ? node.vulns[0] : undefined);

        setPathData({
          depth: data.depth ?? Math.max(1, safePath.length - 1),
          path: safePath,
          requirements: safeReqs,
          vuln: topVuln,
          rank: data.rank ?? undefined,
          rankReason: data.rankReason ?? undefined,
        });
      })
      .catch(() => {
        setPathData(null);
        setError('Could not load the attack path from the backend.');
      })
      .finally(() => setLoading(false));
  }, [node]);

  if (!node) return null;

  const handleHighlight = () => {
    const currentPath = pathData?.path || ['app', node.id];
    const pathNodes = [...currentPath];
    if (pathData?.vuln) pathNodes.push(pathData.vuln.id);

    const edges: [string, string][] = [];
    for (let i = 0; i < currentPath.length - 1; i++) {
      edges.push([currentPath[i], currentPath[i + 1]]);
    }
    if (pathData?.vuln && currentPath.length > 0) {
      edges.push([currentPath[currentPath.length - 1], pathData.vuln.id]);
    }
    onHighlightPath(pathNodes, edges);
  };

  const topAdvisory = pathData?.vuln || (node.vulns && node.vulns[0]);

  return (
    <div className="absolute inset-y-0 right-0 z-50 flex w-full max-w-sm animate-in flex-col justify-between overflow-y-auto border-l border-slate-700/80 bg-[#EEF1E7]/[0.98] p-4 shadow-2xl backdrop-blur-xl duration-300 sm:p-5">
      <div>
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <span className="p-1.5 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              <Network className="w-4 h-4" />
            </span>
            <div>
              <h3 className="text-sm font-bold text-white font-mono truncate max-w-[220px]">
                {node.label || node.id}
              </h3>
              <p className="text-[11px] text-slate-400">
                Depth {node.depth ?? 1} • {node.dependents ?? 0} dependents
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {error && (
          <div className="mt-4 p-3 rounded-xl bg-rose-950/40 border border-rose-800/40 text-xs text-rose-300">{error}</div>
        )}

        {/* 1. Vertical Attack Path Stepper */}
        <div className="mt-5">
          <div className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3 flex items-center justify-between">
            <span>Ingress Attack Stepper</span>
            <span className="text-[10px] font-mono text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded">
              {pathData?.depth ?? (node.depth || 1)} hops
            </span>
          </div>

          <div className="relative pl-6 space-y-4 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-gradient-to-b before:from-cyan-500 before:via-amber-500 before:to-rose-500">
            {/* Step: My App */}
            <div className="relative">
              <span className="absolute -left-6 top-1 w-3 h-3 rounded-full bg-cyan-400 ring-4 ring-slate-950" />
              <div className="text-xs font-mono font-bold text-cyan-300">My App</div>
              <div className="text-[10px] text-slate-500 font-sans">Root deployment entry point</div>
            </div>

            {/* Intermediate Hops */}
            {(pathData?.path || [])
              .filter((p) => p !== 'app' && p !== node.id)
              .map((hop, idx) => (
                <div key={hop} className="relative">
                  <span className="absolute -left-6 top-1 w-2.5 h-2.5 rounded-full bg-amber-400 ring-4 ring-slate-950" />
                  <div className="text-xs font-mono font-bold text-amber-200 truncate">{hop}</div>
                  <div className="text-[10px] text-slate-400 font-mono mt-0.5">
                    {pathData?.requirements?.[idx + 1] || 'dependency link'}
                  </div>
                </div>
              ))}

            {/* Target Package */}
            <div className="relative">
              <span className="absolute -left-6 top-1 w-3 h-3 rounded-full bg-rose-500 ring-4 ring-slate-950 shadow-sm shadow-rose-500" />
              <div className="text-xs font-mono font-bold text-rose-300">{node.id}</div>
              <div className="text-[10px] text-slate-400 font-mono mt-0.5">
                {pathData?.requirements && pathData.requirements.length > 0
                  ? pathData.requirements[pathData.requirements.length - 1]
                  : 'target library'}
              </div>
            </div>

            {/* Vulnerability Node (if present) */}
            {topAdvisory && (
              <div className="relative">
                <span className="absolute -left-6 top-1 w-2.5 h-2.5 rounded-full bg-rose-400 animate-ping ring-4 ring-slate-950" />
                <div className="text-xs font-mono font-bold text-rose-400 flex items-center gap-1.5">
                  <ShieldAlert className="w-3.5 h-3.5" />
                  {topAdvisory.id}
                </div>
                <div className="text-[10px] text-slate-400 font-sans">Remote code execution / exploit hook</div>
              </div>
            )}
          </div>
        </div>

        {/* 2. Advisory Card */}
        {topAdvisory && (
          <div className="mt-6 p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold text-amber-400">{topAdvisory.id}</span>
              <span
                className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                  topAdvisory.severity === 'CRITICAL'
                    ? 'bg-rose-500/10 text-rose-300 border-rose-500/30'
                    : topAdvisory.severity === 'HIGH'
                    ? 'bg-orange-500/10 text-orange-300 border-orange-500/30'
                    : 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                }`}
              >
                {topAdvisory.severity} (CVSS {(topAdvisory as any).cvss || 7.5})
              </span>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed font-sans">{topAdvisory.summary}</p>

            <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-xs">
              <span className="text-slate-400">Fixed in:</span>
              <span className="font-mono text-emerald-400 font-bold">
                {topAdvisory.fixed && topAdvisory.fixed.length > 0 ? topAdvisory.fixed.join(', ') : 'None'}
              </span>
            </div>

            {topAdvisory.url && (
              <a
                href={topAdvisory.url}
                target="_blank"
                rel="noreferrer"
                className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-mono transition-colors"
              >
                View OSV Advisory Details <ExternalLink className="w-3 h-3" />
              </a>
            )}
          </div>
        )}

        {/* 3. "Why is this ranked #N?" Explainer Card */}
        {showRankExplanation && (
          <div className="mt-4 p-4 rounded-xl bg-indigo-950/40 border border-indigo-800/40 text-xs space-y-2 animate-in fade-in duration-200">
            <div className="font-bold text-indigo-300 flex items-center gap-1.5">
              <HelpCircle className="w-4 h-4 text-indigo-400" />
              Scoring Rationale (FalkorDB Graph Algorithm)
            </div>
            <p className="text-slate-300 font-mono text-[11px]">
              vuln.risk = cvss * (1 + log2(1 + dependents)) * (1.5 if min depth &lt;= 2 else 1)
            </p>
            {pathData?.rankReason && (
              <p className="text-amber-300 font-mono text-[11px]">{pathData.rankReason}</p>
            )}
            <div className="space-y-1 text-slate-400 text-[11px]">
              <p>
                • <strong>Min Depth:</strong> {node.depth ?? 1} hops (
                {(node.depth || 1) <= 2 ? '1.5x entry multiplier applies' : '1.0x baseline'}
                )
              </p>
              <p>
                • <strong>Dependents:</strong> {node.dependents ?? 0} upstream packages inherit risk
              </p>
              <p>
                • <strong>PageRank:</strong> {((node.pagerank || 0.001) * 1000).toFixed(3)} (structural criticality)
              </p>
            </div>
          </div>
        )}
      </div>

      {/* Action Buttons */}
      <div className="mt-6 pt-4 border-t border-slate-800/80 space-y-2">
        <button
          onClick={handleHighlight}
          className="w-full py-2.5 px-4 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs transition-all shadow-lg shadow-cyan-500/20 flex items-center justify-center gap-2"
        >
          <Sparkles className="w-4 h-4" />
          Highlight on Graph
        </button>

        <button
          onClick={() => setShowRankExplanation(!showRankExplanation)}
          className="w-full py-2 px-4 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 text-xs transition-colors flex items-center justify-center gap-1.5 font-medium"
        >
          <HelpCircle className="w-3.5 h-3.5 text-slate-400" />
          {showRankExplanation ? 'Hide Ranking Math' : pathData?.rank ? `Why is this ranked #${pathData.rank}?` : 'How is risk scored?'}
        </button>
      </div>
    </div>
  );
};
