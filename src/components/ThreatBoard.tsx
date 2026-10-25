import React, { useState, useEffect, useRef } from 'react';
import {
  Flame,
  CheckCircle2,
  Wrench,
  ArrowRight,
  TrendingDown,
  Check,
} from 'lucide-react';

export interface FixAction {
  action: number;
  fixId: string;
  pkg: string;
  toVersion: string | null;
  tier: 'refresh' | 'override' | 'breaking';
  effort: number;
  clears: number;
  riskCleared: number;
  installed?: string;
  note?: string;
}

export interface FixPlanData {
  initialBlastScore: number;
  finalBlastScore: number;
  totalRiskReduction: number;
  actions: FixAction[];
}

export interface StatsData {
  packages: number;
  vulns: number;
  directDependencies: number;
  totalRisk: number;
  blastScore: number;
  bySeverity: Record<string, number>;
  falkorMs?: number | null;
  engine?: string;
}

interface ThreatBoardProps {
  stats: StatsData;
  fixPlan: FixPlanData | null;
  onApplyPlan: (selectedFixIds: string[]) => void;
  onSelectFix: (fixId: string) => void;
  onHighlightVuln?: (pkgId: string) => void;
}

const TIER_CONFIG = {
  refresh: {
    label: 'refresh',
    color: '#1b5e40',
    bg: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/20',
    icon: '🟢',
    effort: '1 pt',
  },
  override: {
    label: 'override',
    color: '#8a5700',
    bg: 'bg-amber-500/10 text-amber-300 border-amber-500/20',
    icon: '🟡',
    effort: '2 pts',
  },
  breaking: {
    label: 'breaking',
    color: '#b53a1c',
    bg: 'bg-rose-500/10 text-rose-300 border-rose-500/20',
    icon: '🔴',
    effort: '4 pts',
  },
};

export const ThreatBoard: React.FC<ThreatBoardProps> = ({
  stats,
  fixPlan,
  onApplyPlan,
  onSelectFix,
  onHighlightVuln,
}) => {
  const [selectedFixIds, setSelectedFixIds] = useState<Set<string>>(new Set());
  const [simulatedBlastScore, setSimulatedBlastScore] = useState<number>(stats.blastScore);
  const [simulatedResidualRisk, setSimulatedResidualRisk] = useState<number>(0);
  const [isSimulating, setIsSimulating] = useState(false);
  const debounceTimerRef = useRef<NodeJS.Timeout | null>(null);

  // Initialize selected fixes when fix plan arrives
  useEffect(() => {
    if (fixPlan && Array.isArray(fixPlan.actions) && fixPlan.actions.length > 0) {
      const allIds = new Set(fixPlan.actions.map((a) => a.fixId));
      setSelectedFixIds(allIds);
      setSimulatedBlastScore(fixPlan.finalBlastScore);
      setSimulatedResidualRisk(fixPlan.totalRiskReduction);
    }
  }, [fixPlan]);

  // Handle include checkbox toggle with 150ms debounced /api/simulate
  const handleToggleFix = (fixId: string) => {
    const nextSelected = new Set(selectedFixIds);
    if (nextSelected.has(fixId)) {
      nextSelected.delete(fixId);
    } else {
      nextSelected.add(fixId);
    }
    setSelectedFixIds(nextSelected);

    if (debounceTimerRef.current) {
      clearTimeout(debounceTimerRef.current);
    }

    setIsSimulating(true);
    debounceTimerRef.current = setTimeout(async () => {
      try {
        const res = await fetch('/api/simulate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ fix_ids: Array.from(nextSelected) }),
        });
        if (res.ok) {
          const data = await res.json();
          setSimulatedBlastScore(data.residualBlastScore ?? data.simulatedBlastScore ?? stats.blastScore);
          setSimulatedResidualRisk(data.riskReduced ?? 0);
        }
      } catch (e) {
        // Fallback simulation calculation
        let clearedRisk = 0;
        if (fixPlan && Array.isArray(fixPlan.actions)) {
          for (const a of fixPlan.actions) {
            if (nextSelected.has(a.fixId)) {
              clearedRisk += a.riskCleared;
            }
          }
        }
        const remainingR = Math.max(0, stats.totalRisk - clearedRisk);
        const score = Math.round((100 * remainingR) / (remainingR + 60));
        setSimulatedBlastScore(score);
        setSimulatedResidualRisk(clearedRisk);
      } finally {
        setIsSimulating(false);
      }
    }, 150);
  };

  const maxRisk = Math.max(...(fixPlan?.actions?.map((a) => a.riskCleared) || [100]));

  return (
    <div className="flex h-full min-h-[540px] min-w-0 flex-col rounded-2xl border border-slate-700/70 bg-[#EEF1E7] p-4 shadow-xl sm:p-5">
      <div className="mb-4 flex items-start justify-between gap-3 border-b border-slate-800 pb-4">
        <div>
          <h2 className="flex items-center gap-2 text-sm font-semibold text-white">
            <Wrench className="h-4 w-4 text-cyan-300" />
            Recommended fixes
          </h2>
          <p className="mt-1 text-xs text-slate-500">
            Highest risk reduction for the effort
          </p>
        </div>
        <div className="shrink-0 rounded-full border border-slate-700 bg-slate-900 px-2.5 py-1 text-[11px] font-medium text-slate-400">
          {selectedFixIds.size} of {fixPlan?.actions?.length || 0} selected
        </div>
      </div>

      <div className="min-h-0 flex-1 space-y-2.5 overflow-y-auto pr-1">
        {fixPlan && Array.isArray(fixPlan.actions) && fixPlan.actions.length > 0 ? (
          fixPlan.actions.map((action, idx) => {
            const isSelected = selectedFixIds.has(action.fixId);
            const tierConf = TIER_CONFIG[action.tier];
            const riskPercent = Math.min(100, Math.round((action.riskCleared / (maxRisk || 1)) * 100));

            return (
              <div
                key={action.fixId}
                className={`rounded-xl border p-3 transition-all ${
                  isSelected
                    ? 'border-slate-700/80 bg-slate-950/65'
                    : 'border-slate-800/70 bg-slate-950/25 opacity-60'
                }`}
              >
                <div className="flex items-start justify-between gap-3">
                  {/* Left: Checkbox + Action label */}
                  <div className="flex items-start gap-3">
                    <button
                      onClick={() => handleToggleFix(action.fixId)}
                      className={`mt-0.5 w-4 h-4 rounded flex items-center justify-center border transition-colors ${
                        isSelected
                          ? 'bg-emerald-500 border-emerald-400 text-slate-950'
                          : 'border-slate-700 hover:border-slate-500 bg-slate-900'
                      }`}
                    >
                      {isSelected && <Check className="w-3 h-3 stroke-[3]" />}
                    </button>

                    <div className="min-w-0 flex-1">
                      <div className="flex min-w-0 items-center gap-2">
                        <span className="shrink-0 font-mono text-[10px] font-bold text-slate-500">
                          {String(idx + 1).padStart(2, '0')}
                        </span>
                        <span className="min-w-0 truncate text-xs font-semibold text-white">
                          <span className="text-slate-400">{action.tier === 'refresh' ? 'Upgrade' : action.tier === 'override' ? 'Override' : 'Migrate'}</span>{' '}
                          <span className="text-cyan-200">{action.pkg}</span>
                          <span className="text-slate-500"> → </span>
                          <span className="text-emerald-300">{action.toVersion || 'None'}</span>
                        </span>
                      </div>

                      <div className="mt-2 flex flex-wrap items-center gap-x-2 gap-y-1">
                        <span className={`rounded-md border px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wide ${tierConf.bg}`}>
                          {tierConf.label}
                        </span>
                        <span className="text-[10px] text-slate-400">
                          Clears <strong className="font-mono text-slate-200">{action.clears}</strong> {action.clears === 1 ? 'advisory' : 'advisories'}
                        </span>
                        <span className="text-[10px] text-slate-500">Effort {tierConf.effort}</span>
                        {!!(action as any).unfixed && (
                          <span className="text-[10px] text-amber-300/80" title="Advisories on this package with no upstream fix yet">
                            +{(action as any).unfixed} unfixable
                          </span>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Right: Risk Cleared badge */}
                  <div className="text-right">
                    <span className="text-xs font-mono font-semibold text-emerald-300">
                      −{action.riskCleared.toFixed(1)}
                    </span>
                    <div className="text-[9px] uppercase tracking-wide text-slate-600">risk</div>
                  </div>
                </div>

                {/* Risk Bar */}
                <div className="mt-3 h-1 w-full overflow-hidden rounded-full bg-slate-800">
                  <div
                    className="h-full rounded-full transition-all duration-500"
                    style={{
                      width: `${riskPercent}%`,
                      backgroundColor: tierConf.color,
                    }}
                  />
                </div>
              </div>
            );
          })
        ) : (
          <div className="text-center py-8 text-xs text-slate-500">
            No remediation actions required. Repository is clean.
          </div>
        )}
      </div>

      <div className="mt-4 flex flex-col gap-4 border-t border-slate-800 pt-4">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-3">
          <div>
            <div className="text-[10px] font-semibold uppercase tracking-wide text-slate-500">Current score</div>
            <div className="mt-1 flex items-center gap-1.5 font-mono text-xl font-bold text-rose-300">
              <Flame className="h-4 w-4" />
              {stats.blastScore}
            </div>
          </div>

          <ArrowRight className="h-4 w-4 text-slate-600" />

          <div>
            <div className="text-[10px] font-semibold uppercase tracking-wide text-slate-500">After selected fixes</div>
            <div
              className={`mt-1 flex items-center gap-1.5 font-mono text-xl font-bold transition-all duration-300 ${
                simulatedBlastScore === 0 ? 'text-emerald-400' : 'text-amber-400'
              }`}
            >
              <TrendingDown className="h-4 w-4 text-emerald-400" />
              {simulatedBlastScore}
              {isSimulating && <span className="text-xs text-slate-500 animate-pulse">...</span>}
            </div>
          </div>

          <div className="border-l border-slate-800 pl-4">
            <div className="text-[10px] font-semibold uppercase tracking-wide text-slate-500">Risk reduced</div>
            <div className="mt-1 text-sm font-mono font-semibold text-emerald-300">
              -{simulatedResidualRisk.toFixed(1)} pts
            </div>
          </div>
        </div>

        <button
          onClick={() => onApplyPlan(Array.from(selectedFixIds))}
          disabled={selectedFixIds.size === 0}
          className="simulate-control flex w-full items-center justify-center gap-2 rounded-lg bg-cyan-300 px-4 py-2 font-bold text-slate-950 transition hover:bg-cyan-200 disabled:cursor-not-allowed disabled:opacity-40"
        >
          <CheckCircle2 className="h-3.5 w-3.5" />
          Simulate selected fixes ({selectedFixIds.size})
        </button>
      </div>
    </div>
  );
};
