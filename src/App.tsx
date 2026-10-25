/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  Activity,
  AlertTriangle,
  Bot,
  CheckCircle2,
  ChevronDown,
  Flame,
  Info,
  Layers,
  Network,
  RefreshCw,
  ShieldAlert,
  Terminal,
} from 'lucide-react';

import { GraphCanvas, GraphCanvasHandle, GraphNode, GraphLink } from './components/GraphCanvas';
import { ThreatBoard, FixPlanData, StatsData } from './components/ThreatBoard';
import { PathInspector } from './components/PathInspector';
import { AgentPanel } from './components/AgentPanel';
import { PatchDrawer } from './components/PatchDrawer';
import { CypherTab } from './components/CypherTab';
import { UnderTheHood } from './components/UnderTheHood';

interface PresetItem {
  id: string;
  name: string;
  roots: string[];
  description: string;
  packages?: number;
  vulns?: number;
  blastScore?: number;
  seeded?: boolean;
}


export default function App() {
  const [activeTab, setActiveTab] = useState<'graph' | 'agent' | 'cypher' | 'hood'>('graph');
  const [selectedPreset, setSelectedPreset] = useState<string>('kitchen_sink');
  const [presets, setPresets] = useState<Record<string, PresetItem>>({});
  const [graphMode, setGraphMode] = useState<'risk' | 'full'>('risk');

  // Graph data & UI state
  const [graphNodes, setGraphNodes] = useState<GraphNode[]>([]);
  const [graphLinks, setGraphLinks] = useState<GraphLink[]>([]);
  const [inspectedNode, setInspectedNode] = useState<GraphNode | null>(null);
  const [isPatchDrawerOpen, setIsPatchDrawerOpen] = useState(false);
  const [selectedFixIdsForPatch, setSelectedFixIdsForPatch] = useState<string[]>([]);
  const [backendError, setBackendError] = useState<string | null>(null);
  const [health, setHealth] = useState<{ falkordb: boolean; engine: string; agent: string } | null>(null);
  const [simBanner, setSimBanner] = useState<string | null>(null);

  // Stats & FixPlan (zeros until the backend answers; never invented numbers)
  const [stats, setStats] = useState<StatsData>({
    packages: 0,
    vulns: 0,
    directDependencies: 0,
    totalRisk: 0,
    blastScore: 0,
    bySeverity: {},
  });
  const [fixPlan, setFixPlan] = useState<FixPlanData | null>(null);

  // Scanning / Progress state
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState<string | null>(null);
  const [customRootsInput, setCustomRootsInput] = useState('');
  const [showScanModal, setShowScanModal] = useState(false);

  // Canvas ref for imperative API
  const canvasRef = useRef<GraphCanvasHandle | null>(null);

  // Load presets + engine health on mount
  useEffect(() => {
    fetch('/api/presets')
      .then((res) => (res.ok ? res.json() : Promise.reject()))
      .then((data) => setPresets(data))
      .catch(() => setBackendError('Backend not reachable yet. It may still be starting; retrying…'));
    const pollHealth = () =>
      fetch('/api/health')
        .then((res) => (res.ok ? res.json() : Promise.reject()))
        .then((h) => setHealth(h))
        .catch(() => setHealth(null));
    pollHealth();
    const t = setInterval(pollHealth, 10000);
    return () => clearInterval(t);
  }, []);

  // Fetch graph & stats when preset or mode changes
  const loadGraphAndStats = useCallback(async (_presetKey: string, mode: 'risk' | 'full') => {
    try {
      const [gRes, sRes, fRes] = await Promise.all([
        fetch(`/api/graph?mode=${mode}`),
        fetch('/api/stats'),
        fetch('/api/fixplan?max=5'),
      ]);
      if (!gRes.ok || !sRes.ok || !fRes.ok) throw new Error('backend');
      const gData = await gRes.json();
      setGraphNodes(gData.nodes || []);
      setGraphLinks(gData.links || []);
      setStats(await sRes.json());
      setFixPlan(await fRes.json());
      setBackendError(null);
    } catch (err) {
      setBackendError('Backend not reachable. Start it with `npm run dev` (or `python -m backend.main`).');
    }
  }, []);

  useEffect(() => {
    loadGraphAndStats(selectedPreset, graphMode);
  }, [selectedPreset, graphMode, loadGraphAndStats]);

  // Keep retrying while the backend is booting
  useEffect(() => {
    if (!backendError) return;
    const t = setInterval(() => loadGraphAndStats(selectedPreset, graphMode), 3000);
    return () => clearInterval(t);
  }, [backendError, selectedPreset, graphMode, loadGraphAndStats]);

  // Switch preset handler: the backend reloads FalkorDB from the preset snapshot
  const handleSelectPreset = async (presetId: string) => {
    if (presetId === selectedPreset) return;
    setSelectedPreset(presetId);
    setInspectedNode(null);
    setSimBanner(null);
    canvasRef.current?.clearHighlight();
    setIsScanning(true);
    setScanProgress(`Loading preset into the graph engine…`);
    try {
      const res = await fetch(`/api/load-preset/${presetId}`, { method: 'POST' });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        setBackendError(err.detail || 'Could not load that preset.');
        return;
      }
    } catch {
      setBackendError('Backend not reachable.');
      return;
    } finally {
      setIsScanning(false);
      setScanProgress(null);
    }
    await loadGraphAndStats(presetId, graphMode);
  };

  // Run a custom scan: POST /api/scan streams SSE progress (EventSource cannot POST, so read the body)
  const handleRunCustomScan = async () => {
    const roots = customRootsInput
      .split(/[\s,]+/)
      .map((r) => r.trim())
      .filter(Boolean);
    if (roots.length === 0) return;

    setIsScanning(true);
    setScanProgress('Starting scan…');
    setShowScanModal(false);
    setSimBanner(null);
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ roots }),
      });
      if (!res.ok || !res.body) {
        const err = await res.json().catch(() => ({}));
        setBackendError(typeof err.detail === 'string' ? err.detail : 'Scan failed to start.');
        return;
      }
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = '';
      let failed: string | null = null;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const chunks = buf.split('\n\n');
        buf = chunks.pop() || '';
        for (const chunk of chunks) {
          const line = chunk.replace(/^data: /, '').trim();
          if (!line) continue;
          try {
            const ev = JSON.parse(line);
            if (ev.msg) setScanProgress(ev.msg);
            if (ev.type === 'error') failed = ev.msg || 'Scan failed.';
          } catch {
            /* ignore partial frames */
          }
        }
      }
      if (failed) {
        setBackendError(failed);
      } else {
        setBackendError(null);
        setSelectedPreset('custom');
        await loadGraphAndStats('custom', graphMode);
      }
    } catch {
      setBackendError('Scan interrupted: backend not reachable.');
    } finally {
      setIsScanning(false);
      setScanProgress(null);
    }
  };

  // Apply Plan: ask the backend (FalkorDB) exactly what would heal, then animate it
  const handleApplyPlan = async (selectedFixIds: string[]) => {
    if (selectedFixIds.length === 0) return;
    try {
      const res = await fetch('/api/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fix_ids: selectedFixIds }),
      });
      if (!res.ok) throw new Error('simulate failed');
      const sim = await res.json();
      canvasRef.current?.heal(sim.healedPackages || []);
      const before = stats.blastScore;
      setTimeout(() => {
        setStats((prev) => ({ ...prev, blastScore: sim.simulatedBlastScore, vulns: sim.remainingVulnsCount }));
        setSimBanner(
          `Simulated ${selectedFixIds.length} fix${selectedFixIds.length === 1 ? '' : 'es'}: Blast Score ${before} → ${sim.simulatedBlastScore}, ` +
            `${sim.healedVulnsCount} advisories resolved, ${sim.remainingVulnsCount} remain. Nothing was changed in your project.`
        );
      }, 600);
    } catch {
      setBackendError('Could not simulate the plan: backend not reachable.');
    }
  };

  return (
    <div className="app-shell min-h-screen text-slate-100 selection:bg-cyan-400/20 selection:text-cyan-100">
      <header className="sticky top-0 z-40 border-b-2 border-[#12211D] bg-[#EEF1E7]">
        <div className="mx-auto flex max-w-[1600px] flex-wrap items-center justify-between gap-x-6 gap-y-3 px-4 py-3 sm:px-6 lg:px-8">
          <a href="/" title="Back to the Blast Radius home page" className="flex min-w-0 items-center gap-3 no-underline">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-cyan-400 text-slate-950 shadow-lg shadow-cyan-950/50">
              <Flame className="h-5 w-5" />
            </div>
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
                <span className="text-sm font-bold tracking-[0.12em] text-white">BLAST RADIUS</span>
                <span
                  className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[10px] font-semibold ${
                    health?.engine === 'falkordb'
                      ? 'border-cyan-500/30 bg-cyan-500/10 text-cyan-300'
                      : 'border-emerald-500/25 bg-emerald-500/10 text-emerald-300'
                  }`}
                  title={health?.engine === 'falkordb' ? 'Queries run in FalkorDB' : 'Using the persistent local SQLite database'}
                >
                  <span className="h-1.5 w-1.5 rounded-full bg-current" />
                  {health == null ? 'Connecting' : health.engine === 'falkordb' ? 'FalkorDB' : 'SQLite · local'}
                </span>
              </div>
              <p className="mt-0.5 hidden text-xs text-slate-500 sm:block">Supply-chain security workspace</p>
            </div>
          </a>

          <div className="flex min-w-0 items-center gap-2">
            <label className="relative min-w-0">
              <span className="sr-only">Select dependency profile</span>
              <select
                value={selectedPreset}
                onChange={(e) => handleSelectPreset(e.target.value)}
                className="topbar-control h-9 w-full max-w-[min(62vw,340px)] appearance-none rounded-lg border border-slate-700/80 bg-slate-900 px-3 pr-9 font-medium text-slate-200 outline-none transition focus:border-cyan-400/60 focus:ring-2 focus:ring-cyan-400/10"
              >
                {Object.entries(presets).map(([k, p]) => (
                  <option key={k} value={k} disabled={p.seeded === false}>
                    {p.name}
                  </option>
                ))}
                {selectedPreset === 'custom' && <option value="custom">Custom scan</option>}
              </select>
              <ChevronDown className="pointer-events-none absolute right-3 top-3 h-4 w-4 text-slate-500" />
            </label>
            <button
              onClick={() => setShowScanModal(true)}
              className="topbar-control inline-flex h-9 shrink-0 items-center gap-2 rounded-lg border border-slate-700/80 bg-slate-900 px-3 font-semibold text-slate-300 transition hover:border-cyan-500/40 hover:text-white"
              title="Start a custom dependency scan"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${isScanning ? 'animate-spin text-cyan-300' : ''}`} />
              <span className="hidden sm:inline">New scan</span>
            </button>
          </div>
        </div>

        <nav aria-label="Main navigation" className="border-t border-slate-800/60">
          <div className="mx-auto flex max-w-[1600px] gap-1 overflow-x-auto px-4 py-1.5 sm:px-6 lg:px-8">
            {[
              { id: 'graph' as const, label: 'Overview', Icon: Network },
              { id: 'agent' as const, label: 'AI analyst', Icon: Bot },
              { id: 'cypher' as const, label: 'Query console', Icon: Terminal },
              { id: 'hood' as const, label: 'How it works', Icon: Info },
            ].map(({ id, label, Icon }) => (
              <button
                key={id}
                onClick={() => setActiveTab(id)}
                aria-current={activeTab === id ? 'page' : undefined}
                className={`main-nav-tab inline-flex shrink-0 items-center gap-1.5 rounded-md border-b-2 px-3 ${
                  activeTab === id
                    ? 'border-cyan-300/80 bg-slate-800/70 text-white'
                    : 'border-transparent text-slate-400 hover:bg-slate-800/40 hover:text-slate-200'
                }`}
              >
                <Icon className={`h-3.5 w-3.5 ${activeTab === id ? 'text-cyan-300' : ''}`} />
                {label}
              </button>
            ))}
          </div>
        </nav>

        {isScanning && (
          <div className="border-t border-cyan-500/15 bg-cyan-500/[0.06] px-4 py-2 sm:px-6 lg:px-8">
            <div className="mx-auto flex max-w-[1600px] items-center gap-2 text-xs text-cyan-100">
              <span className="h-1.5 w-1.5 shrink-0 animate-pulse rounded-full bg-cyan-300" />
              <span className="min-w-0 truncate">{scanProgress || 'Scanning dependencies…'}</span>
            </div>
          </div>
        )}
      </header>

      <main className="mx-auto flex w-full max-w-[1600px] min-w-0 flex-1 flex-col px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
        {(backendError || simBanner) && (
          <div
            role={backendError ? 'alert' : 'status'}
            className={`mb-5 flex items-start justify-between gap-4 rounded-xl border px-4 py-3 text-sm ${
              backendError
                ? 'border-rose-500/25 bg-rose-500/[0.07] text-rose-200'
                : 'border-emerald-500/25 bg-emerald-500/[0.07] text-emerald-200'
            }`}
          >
            <span className="min-w-0 break-words">{backendError || simBanner}</span>
            {simBanner && !backendError && (
              <button
                className="shrink-0 text-xs font-semibold text-emerald-300 underline-offset-4 hover:underline"
                onClick={() => { setSimBanner(null); loadGraphAndStats(selectedPreset, graphMode); }}
              >
                Reset
              </button>
            )}
          </div>
        )}

        {activeTab === 'graph' && (
          <div className="min-w-0 space-y-5">
            <section className="flex flex-col justify-between gap-3 sm:flex-row sm:items-end">
              <div>
                <div className="mb-1 flex items-center gap-2 text-[11px] font-bold uppercase tracking-[0.16em] text-cyan-300">
                  <Activity className="h-3.5 w-3.5" />
                  Security posture
                </div>
                <h1 className="text-xl font-semibold tracking-tight text-white sm:text-2xl">Dependency risk overview</h1>
                <p className="mt-1 max-w-2xl text-[13px] text-slate-400">
                  Map exposure across your dependency graph and prioritize the fixes with the greatest impact.
                </p>
              </div>
              <div className="text-xs text-slate-500">
                {presets[selectedPreset]?.description || 'Custom dependency scan'}
              </div>
            </section>

            <section aria-label="Security metrics" className="grid grid-cols-2 gap-3 md:grid-cols-4">
              <div className="metric-card">
                <div className="metric-label"><Flame className="text-rose-300" /> Blast score</div>
                <div className="metric-value text-rose-200">{stats.blastScore}<span className="ml-1 text-sm font-medium text-slate-500">/ 100</span></div>
                <div className="metric-note">Current repository risk</div>
              </div>
              <div className="metric-card">
                <div className="metric-label"><Layers className="text-cyan-300" /> Packages</div>
                <div className="metric-value">{stats.packages.toLocaleString()}</div>
                <div className="metric-note">{stats.directDependencies} direct dependencies</div>
              </div>
              <div className="metric-card">
                <div className="metric-label"><ShieldAlert className="text-amber-300" /> Advisories</div>
                <div className="metric-value text-amber-200">{stats.vulns.toLocaleString()}</div>
                <div className="metric-note">Known vulnerable packages</div>
              </div>
              <div className="metric-card">
                <div className="metric-label"><AlertTriangle className="text-orange-300" /> Critical / high</div>
                <div className="metric-value text-orange-200">
                  {((stats.bySeverity?.CRITICAL || 0) + (stats.bySeverity?.HIGH || 0)).toLocaleString()}
                </div>
                <div className="metric-note">Highest severity findings</div>
              </div>
            </section>

            <section className="grid min-w-0 grid-cols-1 gap-4 xl:h-[min(68vh,760px)] xl:min-h-[540px] xl:grid-cols-[minmax(0,1.55fr)_minmax(360px,0.9fr)] 2xl:grid-cols-[minmax(0,1.4fr)_minmax(300px,0.9fr)_minmax(320px,1fr)]">
              <div className="workspace-panel relative min-h-[480px] min-w-0 overflow-hidden xl:h-full">
                <GraphCanvas
                  ref={canvasRef}
                  nodes={graphNodes}
                  links={graphLinks}
                  mode={graphMode}
                  onModeChange={(m) => setGraphMode(m)}
                  onNodeClick={(node) => setInspectedNode(node)}
                />
                {inspectedNode && (
                  <PathInspector
                    node={inspectedNode}
                    onClose={() => setInspectedNode(null)}
                    onHighlightPath={(nodes, edges) => canvasRef.current?.highlight({ nodes, edges })}
                  />
                )}
              </div>
              <div className="min-h-[540px] min-w-0 xl:h-full xl:min-h-0">
                <ThreatBoard
                  stats={stats}
                  fixPlan={fixPlan}
                  onApplyPlan={handleApplyPlan}
                  onSelectFix={(fixId) => {
                    setSelectedFixIdsForPatch([fixId]);
                    setIsPatchDrawerOpen(true);
                  }}
                  onHighlightVuln={(pkgId) => canvasRef.current?.focusNode(pkgId)}
                />
              </div>
              <div className="hidden min-h-[540px] min-w-0 2xl:block 2xl:h-full 2xl:min-h-0">
                <AgentPanel
                  topPackageName={graphNodes.find((n) => n.severity === 'CRITICAL' || n.severity === 'HIGH')?.label || 'axios'}
                  topDirectDep={graphNodes.find((n) => n.direct)?.label || 'react-scripts'}
                  onHighlight={(h) => canvasRef.current?.highlight(h)}
                  onPulseApp={() => canvasRef.current?.pulseApp()}
                  onSimulatePlan={handleApplyPlan}
                  onOpenPatchDrawer={(fixIds) => {
                    setSelectedFixIdsForPatch(fixIds);
                    setIsPatchDrawerOpen(true);
                  }}
                  onOpenInspectorForNode={(nodeId) => {
                    const node = graphNodes.find((n) => n.id === nodeId);
                    if (node) setInspectedNode(node);
                  }}
                />
              </div>
            </section>
          </div>
        )}

        {activeTab === 'agent' && (
          <section className="grid min-w-0 grid-cols-1 gap-4 xl:h-[min(72vh,780px)] xl:min-h-[540px] xl:grid-cols-[minmax(0,1.15fr)_minmax(380px,0.85fr)]">
            <div className="workspace-panel relative min-h-[540px] min-w-0 overflow-hidden xl:h-full xl:min-h-0">
              <GraphCanvas
                ref={canvasRef}
                nodes={graphNodes}
                links={graphLinks}
                mode={graphMode}
                onModeChange={(m) => setGraphMode(m)}
                onNodeClick={(node) => setInspectedNode(node)}
              />
              {inspectedNode && (
                <PathInspector
                  node={inspectedNode}
                  onClose={() => setInspectedNode(null)}
                  onHighlightPath={(nodes, edges) => canvasRef.current?.highlight({ nodes, edges })}
                />
              )}
            </div>
            <div className="min-h-[540px] min-w-0 xl:h-full xl:min-h-0">
              <AgentPanel
                topPackageName={graphNodes.find((n) => n.severity === 'CRITICAL' || n.severity === 'HIGH')?.label || 'axios'}
                topDirectDep={graphNodes.find((n) => n.direct)?.label || 'react-scripts'}
                onHighlight={(h) => canvasRef.current?.highlight(h)}
                onPulseApp={() => canvasRef.current?.pulseApp()}
                onSimulatePlan={handleApplyPlan}
                onOpenPatchDrawer={(fixIds) => {
                  setSelectedFixIdsForPatch(fixIds);
                  setIsPatchDrawerOpen(true);
                }}
                onOpenInspectorForNode={(nodeId) => {
                  const node = graphNodes.find((n) => n.id === nodeId);
                  if (node) setInspectedNode(node);
                }}
              />
            </div>
          </section>
        )}

        {activeTab === 'cypher' && (
          <section className="min-w-0">
            <CypherTab
              engine={stats.engine || health?.engine || 'sqlite'}
              onHighlight={(h) => {
                setActiveTab('graph');
                setTimeout(() => canvasRef.current?.highlight(h), 100);
              }}
            />
          </section>
        )}

        {activeTab === 'hood' && (
          <section className="min-w-0">
            <UnderTheHood engine={stats.engine || health?.engine || 'sqlite'} />
          </section>
        )}
      </main>

      <footer className="mt-auto border-t border-slate-800/70 px-4 py-4 text-center text-[11px] text-slate-600">
        Blast Radius <span className="mx-1.5 text-slate-700">·</span> Supply-chain risk analysis
      </footer>

      <PatchDrawer
        isOpen={isPatchDrawerOpen}
        onClose={() => setIsPatchDrawerOpen(false)}
        fixIds={selectedFixIdsForPatch}
        initialBlastScore={stats.blastScore}
        residualBlastScore={fixPlan?.finalBlastScore ?? 0}
      />

      {showScanModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/75 p-4 backdrop-blur-sm">
          <div role="dialog" aria-modal="true" aria-labelledby="scan-title" className="w-full max-w-lg space-y-5 rounded-2xl border border-slate-700 bg-[#EEF1E7] p-5 shadow-2xl sm:p-6">
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="mb-2 inline-flex h-9 w-9 items-center justify-center rounded-xl bg-cyan-400/10 text-cyan-300">
                  <RefreshCw className="h-4 w-4" />
                </div>
                <h2 id="scan-title" className="text-lg font-semibold text-white">Scan dependencies</h2>
                <p className="mt-1 text-sm text-slate-400">Enter exact npm package versions to build a dependency risk graph.</p>
              </div>
              <button onClick={() => setShowScanModal(false)} aria-label="Close dialog" className="rounded-lg p-2 text-slate-500 transition hover:bg-slate-800 hover:text-white">
                <span aria-hidden="true">×</span>
              </button>
            </div>
            <label htmlFor="scan-roots" className="block text-xs font-semibold text-slate-300">Root packages</label>
            <textarea
              id="scan-roots"
              value={customRootsInput}
              onChange={(e) => setCustomRootsInput(e.target.value)}
              placeholder="express@4.17.1, axios@0.21.1"
              rows={4}
              className="w-full resize-y rounded-xl border border-slate-700 bg-slate-950/70 p-3 text-sm text-slate-100 outline-none placeholder:text-slate-600 focus:border-cyan-400/60 focus:ring-2 focus:ring-cyan-400/10"
            />
            <p className="text-xs text-slate-500">Separate packages with spaces or commas. Package data is resolved via deps.dev and OSV.</p>
            <div className="flex flex-col-reverse gap-2 border-t border-slate-800 pt-4 sm:flex-row sm:justify-end">
              <button onClick={() => setShowScanModal(false)} className="rounded-xl px-4 py-2.5 text-sm font-medium text-slate-400 transition hover:bg-slate-800 hover:text-white">Cancel</button>
              <button
                onClick={handleRunCustomScan}
                disabled={!customRootsInput.trim()}
                className="rounded-xl bg-cyan-300 px-4 py-2.5 text-sm font-semibold text-slate-950 transition hover:bg-cyan-200 disabled:cursor-not-allowed disabled:opacity-40"
              >
                Start scan
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
