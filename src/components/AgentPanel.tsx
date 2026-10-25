import React, { useState, useRef, useEffect } from 'react';
import {
  Bot,
  Send,
  Cpu,
  Clock,
  Code2,
  ChevronDown,
  ChevronUp,
  CheckCircle2,
  Sparkles,
  FileCode,
  Flame,
  Wrench,
  Copy,
  Check,
} from 'lucide-react';

export interface AgentEvent {
  type: 'step' | 'result' | 'final' | 'meta';
  mode?: 'live' | 'replay';
  engine?: string;
  id?: string;
  tool?: string;
  args?: Record<string, any>;
  ms?: number;
  cypher?: string;
  summary?: string;
  highlight?: { nodes: string[]; edges?: [string, string][] };
  markdown?: string;
  evidence?: { label: string; nodes: string[]; edges: [string, string][] }[];
  actions?: { label: string; fix_ids: string[] }[];
}

interface AgentPanelProps {
  topPackageName?: string;
  topDirectDep?: string;
  onHighlight: (highlight: { nodes: string[]; edges?: [string, string][] }) => void;
  onPulseApp: () => void;
  onSimulatePlan: (fixIds: string[]) => void;
  onOpenPatchDrawer: (fixIds: string[]) => void;
  onOpenInspectorForNode: (nodeId: string) => void;
}

export const AgentPanel: React.FC<AgentPanelProps> = ({
  topPackageName = 'axios',
  topDirectDep = 'react-scripts',
  onHighlight,
  onPulseApp,
  onSimulatePlan,
  onOpenPatchDrawer,
  onOpenInspectorForNode,
}) => {
  const [query, setQuery] = useState('');
  const [isRunning, setIsRunning] = useState(false);
  const [events, setEvents] = useState<AgentEvent[]>([]);
  const [expandedCypher, setExpandedCypher] = useState<Record<string, boolean>>({});
  const [copiedCypher, setCopiedCypher] = useState<string | null>(null);
  const timelineEndRef = useRef<HTMLDivElement>(null);
  const eventSourceRef = useRef<EventSource | null>(null);
  const [runMode, setRunMode] = useState<{ mode?: string; engine?: string } | null>(null);

  const suggestionChips = [
    'What should I fix first?',
    `Why is ${topPackageName} in my app?`,
    `What if I replace ${topDirectDep}?`,
    'Show the worst attack path',
  ];

  // Auto scroll to latest event
  useEffect(() => {
    timelineEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [events]);

  const handleCopyCypher = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCypher(id);
    setTimeout(() => setCopiedCypher(null), 2000);
  };

  const handleSend = (userPrompt?: string) => {
    const q = (userPrompt || query).trim();
    if (!q || isRunning) return;

    setIsRunning(true);
    setEvents([]);
    setRunMode(null);
    onPulseApp();

    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }

    const sse = new EventSource(`/api/agent/stream?q=${encodeURIComponent(q)}`);
    eventSourceRef.current = sse;

    sse.onmessage = (msg) => {
      try {
        const ev: AgentEvent = JSON.parse(msg.data);
        if (ev.type === 'meta') {
          setRunMode({ mode: ev.mode, engine: ev.engine });
          return;
        }
        setEvents((prev) => [...prev, ev]);

        if (ev.type === 'step') {
          onPulseApp();
        } else if (ev.type === 'result' && ev.highlight) {
          onHighlight(ev.highlight);
        } else if (ev.type === 'final') {
          setIsRunning(false);
          sse.close();
        }
      } catch (err) {
        console.error('Error parsing agent SSE event:', err);
      }
    };

    sse.onerror = () => {
      // If server SSE stream closes or error, finalize cleanly
      setIsRunning(false);
      sse.close();
    };
  };

  return (
    <div className="flex h-full min-h-0 min-w-0 flex-col overflow-hidden rounded-2xl border border-slate-700/70 bg-[#EEF1E7] p-3 shadow-xl sm:p-4">
      {/* Header */}
      <div className="flex items-center justify-between pb-4 border-b border-slate-800">
        <div className="flex min-w-0 items-center gap-2">
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-cyan-400/10 text-cyan-300">
            <Bot className="h-4 w-4" />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="text-[11px] font-semibold tracking-wide text-slate-200">
                AI analyst
              </span>
              {runMode && (
                <span
                  className={`text-[10px] font-mono px-2 py-0.5 rounded-full border flex items-center gap-1 ${
                    runMode.mode === 'live'
                      ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                      : 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                  }`}
                >
                  <span className={`w-1.5 h-1.5 rounded-full ${runMode.mode === 'live' ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`} />
                  {runMode.mode === 'live' ? `Live agent · ${runMode.engine}` : 'REPLAY of a recorded run'}
                </span>
              )}
            </div>
            <p className="mt-0.5 text-[10px] leading-4 text-slate-500">
              Evidence-backed dependency risk analysis
            </p>
          </div>
        </div>

        <span className="shrink-0 rounded-lg border border-slate-800 bg-slate-950/80 px-2 py-1 text-[10px] text-slate-500">
          Up to 6 steps
        </span>
      </div>

      {/* Suggestion Chips */}
      <div className="mt-2.5 flex flex-wrap items-center gap-1.5 border-b border-slate-800/80 pb-3">
        <span className="text-[10px] uppercase font-semibold text-slate-500">Ask:</span>
        {suggestionChips.map((chip) => (
          <button
            key={chip}
            onClick={() => {
              setQuery(chip);
              handleSend(chip);
            }}
            disabled={isRunning}
            className="rounded-lg border border-slate-800 bg-slate-950/70 px-2 py-1 text-[11px] text-slate-400 transition hover:border-cyan-500/30 hover:bg-slate-900 hover:text-slate-100 disabled:opacity-40"
          >
            {chip}
          </button>
        ))}
      </div>

      {/* Timeline Stream Area */}
      <div className="min-h-0 flex-1 space-y-2 overflow-y-auto overscroll-contain py-2 pr-1">
        {events.length === 0 && !isRunning && (
          <div className="flex h-full min-h-[160px] flex-col items-center justify-center space-y-2 px-4 text-center text-slate-500">
            <Bot className="h-6 w-6 text-slate-600" />
            <p className="max-w-xs text-[11px] leading-5">
              Ask a question or choose a suggested analysis to get started.
            </p>
          </div>
        )}

        {events.map((ev, idx) => {
          // STEP CARD
          if (ev.type === 'step') {
            return (
              <div
                key={`step_${idx}`}
                className="space-y-2 rounded-xl border border-slate-800 bg-slate-950/70 p-3"
              >
                <div className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/20 flex items-center gap-1">
                      <Cpu className="w-3 h-3 text-amber-400" />
                      MCP Tool Call
                    </span>
                    <span className="font-mono font-bold text-cyan-300">{ev.tool}()</span>
                  </div>

                  <span className="flex items-center gap-1.5 text-[11px] text-slate-400 font-mono">
                    <span className="w-2 h-2 rounded-full bg-amber-400 animate-spin" />
                    Executing...
                  </span>
                </div>

                {ev.args && Object.keys(ev.args).length > 0 && (
                  <pre className="text-[11px] font-mono text-slate-400 bg-slate-900/90 p-2 rounded-lg border border-slate-850 overflow-x-auto">
                    {JSON.stringify(ev.args, null, 2)}
                  </pre>
                )}
              </div>
            );
          }

          // RESULT CARD
          if (ev.type === 'result') {
            const isCypherOpen = expandedCypher[ev.id || `res_${idx}`];
            const cypherKey = ev.id || `res_${idx}`;

            return (
              <div
                key={`result_${idx}`}
                className="min-w-0 space-y-2 rounded-xl border border-slate-800/90 bg-slate-950 p-3"
              >
                <div className="flex items-center justify-between text-xs">
                  <span className="min-w-0 break-words font-mono font-semibold text-emerald-400 [overflow-wrap:anywhere]">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    {ev.summary || `${ev.tool} executed successfully`}
                  </span>

                  <span className="flex shrink-0 items-center gap-1 rounded border border-emerald-500/20 bg-emerald-500/10 px-2 py-0.5 font-mono text-[10px] text-emerald-300">
                    <Clock className="w-3 h-3" />
                    {ev.ms != null ? `${ev.ms} ms` : '—'}{ev.engine ? ` · ${ev.engine}` : ''}
                  </span>
                </div>

                {/* Expandable Cypher Block */}
                {ev.cypher && (
                  <div className="border-t border-slate-900 pt-2">
                    <button
                      onClick={() =>
                        setExpandedCypher((prev) => ({ ...prev, [cypherKey]: !prev[cypherKey] }))
                      }
                      className="text-[11px] font-mono text-slate-400 hover:text-slate-200 flex items-center gap-1 transition-colors"
                    >
                      <Code2 className="w-3 h-3 text-cyan-400" />
                      <span>{isCypherOpen ? 'Hide Cypher Query' : 'View Generated Cypher'}</span>
                      {isCypherOpen ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                    </button>

                    {isCypherOpen && (
                      <div className="relative mt-2 p-2.5 rounded-lg bg-slate-900 font-mono text-[11px] text-cyan-300 border border-slate-800">
                        <pre className="overflow-x-auto whitespace-pre-wrap">{ev.cypher}</pre>
                        <button
                          onClick={() => handleCopyCypher(ev.cypher || '', cypherKey)}
                          className="absolute top-2 right-2 p-1 text-slate-400 hover:text-white bg-slate-800/80 rounded transition-colors"
                          title="Copy Cypher"
                        >
                          {copiedCypher === cypherKey ? (
                            <Check className="w-3 h-3 text-emerald-400" />
                          ) : (
                            <Copy className="w-3 h-3" />
                          )}
                        </button>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          }

          // FINAL BRIEFING CARD
          if (ev.type === 'final') {
            const fixIds =
              ev.actions && ev.actions.length > 0
                ? ev.actions.flatMap((a) => a.fix_ids)
                : [];

            return (
              <div
                key={`final_${idx}`}
                className="space-y-3 rounded-xl border border-slate-700 bg-slate-950 p-3.5"
              >
                <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                  <span className="flex items-center gap-2 text-[11px] font-semibold text-slate-200">
                    <Sparkles className="h-3.5 w-3.5 text-cyan-300" />
                    Analysis summary
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/20">
                    Incident-Commander Style
                  </span>
                </div>

                {/* Markdown text */}
                <div className="space-y-2 whitespace-pre-line break-words font-sans text-xs leading-relaxed text-slate-200 [overflow-wrap:anywhere]">
                  {ev.markdown}
                </div>

                {/* Evidence Chips */}
                {ev.evidence && ev.evidence.length > 0 && (
                  <div className="pt-2 border-t border-slate-900">
                    <div className="text-[10px] uppercase font-semibold text-slate-500 mb-2">
                      Supporting Evidence (click to highlight):
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {ev.evidence.map((evi, eIdx) => (
                        <button
                          key={eIdx}
                          onClick={() => {
                            onHighlight({ nodes: evi.nodes, edges: evi.edges });
                            if (evi.nodes.length > 0 && evi.nodes[evi.nodes.length - 1] !== 'app') {
                              onOpenInspectorForNode(evi.nodes[evi.nodes.length - 1]);
                            }
                          }}
                          className="px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800 hover:border-cyan-500/40 text-[11px] font-mono text-cyan-300 flex items-center gap-1.5 transition-colors"
                        >
                          <Sparkles className="w-3 h-3 text-cyan-400" />
                          {evi.label}
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                {/* Action Buttons: Simulate Plan & Get Patch */}
                <div className="pt-3 border-t border-slate-900 flex flex-wrap items-center justify-between gap-3">
                  <button
                    onClick={() => onSimulatePlan(fixIds)}
                    disabled={fixIds.length === 0}
                    className="disabled:opacity-40 px-4 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs transition-all flex items-center gap-1.5"
                  >
                    <Flame className="w-3.5 h-3.5 fill-slate-950 stroke-emerald-400" />
                    Simulate this plan (Heal)
                  </button>

                  <button
                    onClick={() => onOpenPatchDrawer(fixIds)}
                    disabled={fixIds.length === 0}
                    className="disabled:opacity-40 px-4 py-2 rounded-xl bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/30 font-bold text-xs transition-all flex items-center gap-1.5"
                  >
                    <FileCode className="w-3.5 h-3.5" />
                    Get Patch ({fixIds.length} fixes)
                  </button>
                </div>
              </div>
            );
          }

          return null;
        })}
        <div ref={timelineEndRef} />
      </div>

      {/* Input Box */}
      <div className="mt-4 pt-3 border-t border-slate-800 flex items-center gap-2">
        <input
          type="text"
          placeholder="Ask the triage agent..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') handleSend();
          }}
          disabled={isRunning}
          className="min-w-0 flex-1 rounded-xl border border-slate-800 bg-slate-950 px-3 py-2.5 text-xs text-white outline-none placeholder:text-slate-500 focus:border-cyan-400/50"
        />

        <button
          onClick={() => handleSend()}
          disabled={isRunning || !query.trim()}
          className="rounded-xl bg-cyan-300 p-2.5 text-slate-950 transition hover:bg-cyan-200 disabled:opacity-40"
          title="Send query"
        >
          <Send className="h-3.5 w-3.5 fill-current" />
        </button>
      </div>
    </div>
  );
};
