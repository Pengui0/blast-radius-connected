import React, { useState, useEffect } from 'react';
import {
  X,
  Copy,
  Check,
  ExternalLink,
  FileCode,
  Terminal,
  FileText,
  Flame,
  ArrowRight,
  TrendingDown,
} from 'lucide-react';

interface PatchDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  fixIds: string[];
  initialBlastScore: number;
  residualBlastScore: number;
}

interface PatchData {
  overrides: Record<string, string>;
  overrides_json?: string;
  commands: string[];
  issue_markdown: string;
}

export const PatchDrawer: React.FC<PatchDrawerProps> = ({
  isOpen,
  onClose,
  fixIds,
  initialBlastScore,
  residualBlastScore,
}) => {
  const [activeTab, setActiveTab] = useState<'overrides' | 'shell' | 'github'>('overrides');
  const [patchData, setPatchData] = useState<PatchData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [repoInput, setRepoInput] = useState('');

  useEffect(() => {
    if (!isOpen || fixIds.length === 0) return;

    setLoading(true);
    setError(null);
    fetch(`/api/patch?fix_ids=${encodeURIComponent(fixIds.join(','))}`)
      .then((res) => (res.ok ? res.json() : Promise.reject('Patch failed')))
      .then((data) => setPatchData(data))
      .catch(() => {
        setPatchData(null);
        setError('Could not generate the patch: the backend did not respond.');
      })
      .finally(() => setLoading(false));
  }, [isOpen, fixIds, initialBlastScore, residualBlastScore]);

  if (!isOpen) return null;

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const overridesJson =
    patchData?.overrides_json ?? JSON.stringify({ overrides: patchData?.overrides || {} }, null, 2);
  const shellCommands = patchData?.commands?.join('\n') || '# No commands generated';
  const issueMarkdown = patchData?.issue_markdown || '';

  const repoValid = /^[\w.-]+\/[\w.-]+$/.test(repoInput.trim());
  const gitHubUrl = `https://github.com/${repoInput.trim()}/issues/new?title=${encodeURIComponent(
    '🛡️ Security Remediation: Blast Radius Triage Fix Plan'
  )}&body=${encodeURIComponent(issueMarkdown.slice(0, 5500))}`; // GitHub rejects very long URLs

  return (
    <div className="fixed inset-x-0 bottom-0 z-50 bg-slate-950/95 backdrop-blur-2xl border-t border-slate-800 shadow-2xl p-6 max-h-[85vh] overflow-y-auto animate-in slide-in-from-bottom duration-300">
      <div className="max-w-5xl mx-auto space-y-5">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-amber-400 bg-amber-500/10 border border-amber-500/20 px-2.5 py-0.5 rounded-full">
                Remediation Artifacts
              </span>
              <span className="text-xs text-slate-400 font-mono">
                {fixIds.length} {fixIds.length === 1 ? 'fix action' : 'fix actions'}
              </span>
            </div>
            <h2 className="text-lg font-bold text-white mt-1">Deterministic Remediation Patch Drawer</h2>
          </div>

          <div className="flex items-center gap-4">
            {/* Score Delta */}
            <div className="flex items-center gap-3 bg-slate-900/80 px-3.5 py-1.5 rounded-xl border border-slate-800">
              <div className="flex items-center gap-1.5 font-mono text-sm text-rose-400">
                <Flame className="w-4 h-4 text-rose-500" />
                {initialBlastScore}
              </div>
              <ArrowRight className="w-3.5 h-3.5 text-slate-600" />
              <div className="flex items-center gap-1.5 font-mono text-sm text-emerald-400 font-bold">
                <TrendingDown className="w-4 h-4 text-emerald-400" />
                {residualBlastScore}
              </div>
            </div>

            <button
              onClick={onClose}
              className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {loading && <div className="text-xs text-slate-400 font-mono animate-pulse">Generating patch from the graph…</div>}
        {error && (
          <div className="p-3 rounded-xl bg-rose-950/40 border border-rose-800/40 text-xs text-rose-300">{error}</div>
        )}

        {/* Tab Navigation */}
        <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
          <button
            onClick={() => setActiveTab('overrides')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all ${
              activeTab === 'overrides'
                ? 'bg-amber-500 text-slate-950 shadow-md'
                : 'text-slate-400 hover:text-white hover:bg-slate-900'
            }`}
          >
            <FileCode className="w-3.5 h-3.5" />
            package.json overrides
          </button>

          <button
            onClick={() => setActiveTab('shell')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all ${
              activeTab === 'shell'
                ? 'bg-amber-500 text-slate-950 shadow-md'
                : 'text-slate-400 hover:text-white hover:bg-slate-900'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            Shell Commands
          </button>

          <button
            onClick={() => setActiveTab('github')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all ${
              activeTab === 'github'
                ? 'bg-amber-500 text-slate-950 shadow-md'
                : 'text-slate-400 hover:text-white hover:bg-slate-900'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            GitHub Issue Markdown
          </button>
        </div>

        {/* Tab Content */}
        {activeTab === 'overrides' && (
          <div className="relative">
            <pre className="p-4 bg-slate-900/90 rounded-xl font-mono text-xs text-cyan-300 border border-slate-800 overflow-x-auto max-h-64">
              {overridesJson}
            </pre>
            <button
              onClick={() => handleCopy(overridesJson, 'overrides')}
              className="absolute top-3 right-3 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs rounded-lg flex items-center gap-1.5 font-medium transition-colors"
            >
              {copiedKey === 'overrides' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              {copiedKey === 'overrides' ? 'Copied!' : 'Copy JSON'}
            </button>
          </div>
        )}

        {activeTab === 'shell' && (
          <div className="relative">
            <pre className="p-4 bg-slate-900/90 rounded-xl font-mono text-xs text-emerald-300 border border-slate-800 overflow-x-auto max-h-64 whitespace-pre-wrap">
              {shellCommands}
            </pre>
            <button
              onClick={() => handleCopy(shellCommands, 'shell')}
              className="absolute top-3 right-3 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs rounded-lg flex items-center gap-1.5 font-medium transition-colors"
            >
              {copiedKey === 'shell' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              {copiedKey === 'shell' ? 'Copied!' : 'Copy Script'}
            </button>
          </div>
        )}

        {activeTab === 'github' && (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-900/50 p-3 rounded-xl border border-slate-800">
              <div className="flex items-center gap-2 text-xs">
                <span className="text-slate-400 font-medium">Target Repo:</span>
                <input
                  type="text"
                  value={repoInput}
                  onChange={(e) => setRepoInput(e.target.value)}
                  className="bg-slate-950 text-slate-200 px-2.5 py-1 rounded-lg border border-slate-700 font-mono text-xs outline-none w-48"
                  placeholder="owner/repo"
                />
              </div>

              <a
                href={repoValid ? gitHubUrl : undefined}
                aria-disabled={!repoValid}
                target="_blank"
                rel="noreferrer"
                title={repoValid ? 'Open a pre-filled issue' : 'Enter owner/repo first'}
                className={`px-3.5 py-1.5 bg-slate-800 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors ${
                  repoValid ? 'hover:bg-slate-700' : 'opacity-40 pointer-events-none'
                }`}
              >
                <ExternalLink className="w-3.5 h-3.5 text-cyan-400" />
                Open pre-filled GitHub issue
              </a>
            </div>

            <div className="relative">
              <pre className="p-4 bg-slate-900/90 rounded-xl font-mono text-xs text-slate-300 border border-slate-800 overflow-x-auto max-h-64 whitespace-pre-wrap">
                {issueMarkdown}
              </pre>
              <button
                onClick={() => handleCopy(issueMarkdown, 'github')}
                className="absolute top-3 right-3 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs rounded-lg flex items-center gap-1.5 font-medium transition-colors"
              >
                {copiedKey === 'github' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                {copiedKey === 'github' ? 'Copied!' : 'Copy Markdown'}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
