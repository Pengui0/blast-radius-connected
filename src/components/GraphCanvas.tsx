import React, {
  useEffect,
  useRef,
  useImperativeHandle,
  forwardRef,
  useState,
  useCallback,
  useMemo,
} from 'react';
import ForceGraph2D, { ForceGraphMethods } from 'react-force-graph-2d';
import {
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Search,
  Filter,
  Eye,
  Sparkles,
  Layers,
  ShieldAlert,
} from 'lucide-react';

export interface GraphNode {
  id: string;
  label: string;
  type: 'app' | 'package';
  depth: number;
  direct?: boolean;
  severity?: 'CRITICAL' | 'HIGH' | 'MODERATE' | 'LOW' | 'NONE';
  pagerank?: number;
  betweenness?: number;
  community?: number;
  dependents?: number;
  exposed?: boolean;
  vulns?: {
    id: string;
    severity: string;
    summary: string;
    fixed: string[];
    url?: string;
  }[];
  // Internal animation state
  x?: number;
  y?: number;
  fx?: number;
  fy?: number;
  healed?: boolean;
  healProgress?: number;
  particles?: { x: number; y: number; vx: number; vy: number; life: number; color: string }[];
}

export interface GraphLink {
  source: string | GraphNode;
  target: string | GraphNode;
  req?: string;
  highlighted?: boolean;
}

export interface GraphCanvasHandle {
  highlight: (params: { nodes: string[]; edges?: [string, string][] }) => void;
  clearHighlight: () => void;
  heal: (nodeIds: string[]) => void;
  focusNode: (nodeId: string) => void;
  pulseApp: () => void;
}

interface GraphCanvasProps {
  nodes: GraphNode[];
  links: GraphLink[];
  mode: 'risk' | 'full';
  onModeChange: (mode: 'risk' | 'full') => void;
  onNodeClick: (node: GraphNode) => void;
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ff6a3d', // rose-500
  HIGH: '#f3a03a',     // orange-500
  MODERATE: '#e8c547', // amber-500
  LOW: '#7cc79b',      // emerald-500
  NONE: '#a9c7b9',     // sky-400
};

const COMMUNITY_COLORS = [
  'rgba(143, 163, 150, 0.28)',  // purple
  'rgba(229, 83, 45, 0.18)',  // blue
  'rgba(124, 199, 155, 0.2)',  // emerald
  'rgba(232, 197, 71, 0.2)',  // amber
  'rgba(169, 199, 185, 0.25)',  // pink
  'rgba(243, 160, 58, 0.2)',  // teal
];

export const GraphCanvas = forwardRef<GraphCanvasHandle, GraphCanvasProps>(
  ({ nodes, links, mode, onModeChange, onNodeClick }, ref) => {
    const fgRef = useRef<ForceGraphMethods<GraphNode, GraphLink> | undefined>(undefined);
    const containerRef = useRef<HTMLDivElement>(null);
    const [dimensions, setDimensions] = useState({ width: 800, height: 600 });
    const [showHalos, setShowHalos] = useState(true);
    const [searchQuery, setSearchQuery] = useState('');
    const [highlightedNodes, setHighlightedNodes] = useState<Set<string>>(new Set());
    const [highlightedEdges, setHighlightedEdges] = useState<Set<string>>(new Set());
    const [healedNodes, setHealedNodes] = useState<Set<string>>(new Set());
    const [appPulse, setAppPulse] = useState(0);

    // Particle bursts & edge animation
    const particlesRef = useRef<Map<string, { x: number; y: number; vx: number; vy: number; life: number; color: string }[]>>(new Map());
    const sweepAngleRef = useRef(0);
    const animFrameRef = useRef<number | null>(null);

    // Resize observer
    useEffect(() => {
      if (!containerRef.current) return;
      const obs = new ResizeObserver((entries) => {
        for (const entry of entries) {
          setDimensions({
            width: entry.contentRect.width || 800,
            height: entry.contentRect.height || 600,
          });
        }
      });
      obs.observe(containerRef.current);
      return () => obs.disconnect();
    }, []);

    // Animation ticker for reticle sweep & pulses
    useEffect(() => {
      const tick = () => {
        sweepAngleRef.current = (sweepAngleRef.current + 0.03) % (Math.PI * 2);
        animFrameRef.current = requestAnimationFrame(tick);
      };
      animFrameRef.current = requestAnimationFrame(tick);
      return () => {
        if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
      };
    }, []);

    // Imperative API
    useImperativeHandle(ref, () => ({
      highlight: ({ nodes: nIds, edges: ePairs }) => {
        const nSet = new Set(nIds);
        const eSet = new Set<string>();
        if (ePairs) {
          for (const [from, to] of ePairs) {
            eSet.add(`${from}->${to}`);
            eSet.add(`${to}->${from}`);
          }
        }
        setHighlightedNodes(nSet);
        setHighlightedEdges(eSet);

        // Zoom to fit highlighted nodes with 80px padding over 600ms
        setTimeout(() => {
          if (fgRef.current && nIds.length > 0) {
            fgRef.current.zoomToFit(600, 80);
          }
        }, 50);
      },

      clearHighlight: () => {
        setHighlightedNodes(new Set());
        setHighlightedEdges(new Set());
      },

      heal: (nodeIds: string[]) => {
        // Group nodes by depth for staggered 120ms tween
        const nodesByDepth = new Map<number, string[]>();
        for (const id of nodeIds) {
          const node = nodes.find((n) => n.id === id);
          const depth = node?.depth ?? 1;
          const list = nodesByDepth.get(depth) || [];
          list.push(id);
          nodesByDepth.set(depth, list);
        }

        const sortedDepths = Array.from(nodesByDepth.keys()).sort((a, b) => a - b);
        sortedDepths.forEach((depth, idx) => {
          setTimeout(() => {
            const batch = nodesByDepth.get(depth) || [];
            setHealedNodes((prev) => {
              const next = new Set(prev);
              for (const id of batch) next.add(id);
              return next;
            });

            // Trigger particle burst on healed nodes
            for (const id of batch) {
              const node = nodes.find((n) => n.id === id);
              if (node && node.x !== undefined && node.y !== undefined) {
                const burst: { x: number; y: number; vx: number; vy: number; life: number; color: string }[] = [];
                for (let i = 0; i < 18; i++) {
                  const angle = Math.random() * Math.PI * 2;
                  const speed = 1.5 + Math.random() * 3.5;
                  burst.push({
                    x: node.x,
                    y: node.y,
                    vx: Math.cos(angle) * speed,
                    vy: Math.sin(angle) * speed,
                    life: 1.0,
                    color: '#8fd3a8',
                  });
                }
                particlesRef.current.set(id, burst);
              }
            }
          }, idx * 120);
        });
      },

      focusNode: (nodeId: string) => {
        const target = nodes.find((n) => n.id === nodeId || n.id.includes(nodeId));
        if (target && target.x !== undefined && target.y !== undefined && fgRef.current) {
          fgRef.current.centerAt(target.x, target.y, 600);
          fgRef.current.zoom(2.5, 600);
          setHighlightedNodes(new Set([target.id]));
        }
      },

      pulseApp: () => {
        setAppPulse(Date.now());
      },
    }));

    // Process nodes with App fixed at (0, 0)
    const graphData = useMemo(() => {
      const processedNodes = nodes.map((n) => {
        if (n.id === 'app' || n.type === 'app') {
          return {
            ...n,
            fx: 0,
            fy: 0,
            x: 0,
            y: 0,
          };
        }
        return { ...n };
      });

      return {
        nodes: processedNodes,
        links: links.map((l) => ({ ...l })),
      };
    }, [nodes, links]);

    // Background rendering: concentric depth rings behind all nodes
    const drawBackground = useCallback(
      (ctx: CanvasRenderingContext2D) => {
        ctx.save();
        ctx.lineWidth = 1;
        ctx.strokeStyle = 'rgba(238, 241, 231, 0.06)';
        ctx.setLineDash([4, 6]);

        // Draw 6 concentric rings representing dependency depth 1 to 6
        const radii = [70, 140, 210, 280, 360, 440];
        for (let i = 0; i < radii.length; i++) {
          ctx.beginPath();
          ctx.arc(0, 0, radii[i], 0, Math.PI * 2);
          ctx.stroke();

          // Label depth
          ctx.fillStyle = 'rgba(238, 241, 231, 0.25)';
          ctx.font = '9px monospace';
          ctx.fillText(`depth ${i + 1}`, radii[i] + 4, -4);
        }
        ctx.restore();
      },
      []
    );

    // Custom node canvas drawing
    const drawNode = useCallback(
      (node: GraphNode, ctx: CanvasRenderingContext2D, globalScale: number) => {
        const isApp = node.id === 'app' || node.type === 'app';
        const isHighlighted = highlightedNodes.size === 0 || highlightedNodes.has(node.id);
        const isDimmed = highlightedNodes.size > 0 && !highlightedNodes.has(node.id);
        const isHealed = healedNodes.has(node.id);

        const x = node.x ?? 0;
        const y = node.y ?? 0;

        ctx.save();
        ctx.globalAlpha = isDimmed ? 0.07 : 1.0;

        // 1. Draw community halos if toggled
        if (showHalos && node.community !== undefined && !isApp) {
          const haloColor = COMMUNITY_COLORS[Math.abs(node.community) % COMMUNITY_COLORS.length];
          ctx.beginPath();
          ctx.arc(x, y, 14, 0, Math.PI * 2);
          ctx.fillStyle = haloColor;
          ctx.fill();
        }

        // 2. Draw App Node: Cyan reticle with rotating sweep & pulse
        if (isApp) {
          const reticleRadius = 16;

          // Pulse ring when appPulse is active
          const pulseElapsed = Date.now() - appPulse;
          if (pulseElapsed < 800) {
            const pulseProgress = pulseElapsed / 800;
            ctx.beginPath();
            ctx.arc(x, y, reticleRadius + pulseProgress * 24, 0, Math.PI * 2);
            ctx.strokeStyle = `rgba(238, 241, 231, ${1 - pulseProgress})`;
            ctx.lineWidth = 2;
            ctx.stroke();
          }

          // Concentric outer reticle
          ctx.beginPath();
          ctx.arc(x, y, reticleRadius, 0, Math.PI * 2);
          ctx.strokeStyle = '#eef1e7';
          ctx.lineWidth = 2;
          ctx.stroke();

          // Reticle crosshairs
          ctx.beginPath();
          ctx.moveTo(x - reticleRadius - 4, y);
          ctx.lineTo(x + reticleRadius + 4, y);
          ctx.moveTo(x, y - reticleRadius - 4);
          ctx.lineTo(x, y + reticleRadius + 4);
          ctx.strokeStyle = 'rgba(238, 241, 231, 0.4)';
          ctx.lineWidth = 1;
          ctx.stroke();

          // Rotating radar sweep
          ctx.save();
          ctx.beginPath();
          ctx.moveTo(x, y);
          ctx.arc(x, y, reticleRadius - 1, sweepAngleRef.current, sweepAngleRef.current + Math.PI / 3);
          ctx.closePath();
          const sweepGrad = ctx.createRadialGradient(x, y, 0, x, y, reticleRadius);
          sweepGrad.addColorStop(0, 'rgba(238, 241, 231, 0.6)');
          sweepGrad.addColorStop(1, 'rgba(238, 241, 231, 0.0)');
          ctx.fillStyle = sweepGrad;
          ctx.fill();
          ctx.restore();

          // Centre core
          ctx.beginPath();
          ctx.arc(x, y, 6, 0, Math.PI * 2);
          ctx.fillStyle = '#eef1e7';
          ctx.shadowColor = '#eef1e7';
          ctx.shadowBlur = 10;
          ctx.fill();

          // Label
          if (globalScale > 0.6) {
            ctx.fillStyle = '#e0f2fe';
            ctx.font = 'bold 10px sans-serif';
            ctx.textAlign = 'center';
            ctx.fillText('My App', x, y + reticleRadius + 12);
          }

          ctx.restore();
          return;
        }

        // 3. Regular Package node dot
        // Dot size scaled by PageRank (3px to 9px)
        const pr = node.pagerank || 0.001;
        const radius = Math.min(9, Math.max(3, 3 + pr * 3000));

        let baseColor = SEVERITY_COLORS[node.severity || 'NONE'];
        if (isHealed) {
          baseColor = '#8fd3a8'; // Healed green
        }

        // Pulse CRITICAL vulnerabilities
        let drawRadius = radius;
        if (node.severity === 'CRITICAL' && !isHealed) {
          const pulse = Math.sin(Date.now() / 180) * 2;
          drawRadius = Math.max(3, radius + pulse);

          // Outer shockwave glow
          ctx.beginPath();
          ctx.arc(x, y, drawRadius + 4, 0, Math.PI * 2);
          ctx.fillStyle = 'rgba(244, 63, 94, 0.25)';
          ctx.fill();
        }

        // Glow ring
        ctx.beginPath();
        ctx.arc(x, y, drawRadius, 0, Math.PI * 2);
        ctx.fillStyle = baseColor;
        ctx.shadowColor = baseColor;
        ctx.shadowBlur = isHealed ? 12 : node.severity && node.severity !== 'NONE' ? 8 : 2;
        ctx.fill();

        // White border if highlighted or direct
        if (isHighlighted && highlightedNodes.has(node.id)) {
          ctx.beginPath();
          ctx.arc(x, y, drawRadius + 2, 0, Math.PI * 2);
          ctx.strokeStyle = '#ffffff';
          ctx.lineWidth = 1.5;
          ctx.stroke();
        } else if (node.direct) {
          ctx.beginPath();
          ctx.arc(x, y, drawRadius + 1.5, 0, Math.PI * 2);
          ctx.strokeStyle = 'rgba(207, 224, 214, 0.7)';
          ctx.lineWidth = 1;
          ctx.stroke();
        }

        // Render particles for healed nodes
        const activeParticles = particlesRef.current.get(node.id);
        if (activeParticles && activeParticles.length > 0) {
          for (let pIdx = activeParticles.length - 1; pIdx >= 0; pIdx--) {
            const p = activeParticles[pIdx];
            p.x += p.vx;
            p.y += p.vy;
            p.life -= 0.025;
            if (p.life <= 0) {
              activeParticles.splice(pIdx, 1);
            } else {
              ctx.beginPath();
              ctx.arc(p.x, p.y, 2 * p.life, 0, Math.PI * 2);
              ctx.fillStyle = `rgba(143, 211, 168, ${p.life})`;
              ctx.fill();
            }
          }
        }

        // Label at sufficient zoom
        if (globalScale > 1.2 || isHighlighted && highlightedNodes.has(node.id)) {
          ctx.fillStyle = isHighlighted && highlightedNodes.has(node.id) ? '#ffffff' : '#94a3b8';
          ctx.font = isHighlighted && highlightedNodes.has(node.id) ? 'bold 9px monospace' : '8px monospace';
          ctx.textAlign = 'center';
          ctx.shadowBlur = 0;
          ctx.fillText(node.label || node.id, x, y + drawRadius + 9);
        }

        ctx.restore();
      },
      [highlightedNodes, healedNodes, showHalos, appPulse]
    );

    // Link Canvas Rendering
    const drawLink = useCallback(
      (link: any, ctx: CanvasRenderingContext2D) => {
        const srcId = typeof link.source === 'object' ? link.source.id : link.source;
        const tgtId = typeof link.target === 'object' ? link.target.id : link.target;
        const isLinkHighlighted =
          highlightedEdges.has(`${srcId}->${tgtId}`) || highlightedEdges.has(`${tgtId}->${srcId}`);
        const isDimmed = highlightedNodes.size > 0 && !isLinkHighlighted;

        const sx = link.source.x ?? 0;
        const sy = link.source.y ?? 0;
        const tx = link.target.x ?? 0;
        const ty = link.target.y ?? 0;

        ctx.save();
        if (isDimmed) {
          ctx.globalAlpha = 0.05;
          ctx.strokeStyle = '#eef1e7';
          ctx.lineWidth = 0.5;
          ctx.beginPath();
          ctx.moveTo(sx, sy);
          ctx.lineTo(tx, ty);
          ctx.stroke();
          ctx.restore();
          return;
        }

        if (isLinkHighlighted) {
          // Bright cyan/gold path
          ctx.globalAlpha = 0.9;
          ctx.strokeStyle = '#cfe0d6';
          ctx.lineWidth = 2.5;
          ctx.shadowColor = '#cfe0d6';
          ctx.shadowBlur = 6;
          ctx.beginPath();
          ctx.moveTo(sx, sy);
          ctx.lineTo(tx, ty);
          ctx.stroke();

          // 4 directional animated particles traveling along the edge
          const now = Date.now() / 1000;
          for (let i = 0; i < 4; i++) {
            const t = ((now * 1.2 + i * 0.25) % 1);
            const px = sx + (tx - sx) * t;
            const py = sy + (ty - sy) * t;

            ctx.beginPath();
            ctx.arc(px, py, 2.5, 0, Math.PI * 2);
            ctx.fillStyle = '#ffffff';
            ctx.shadowColor = '#cfe0d6';
            ctx.shadowBlur = 4;
            ctx.fill();
          }
        } else {
          // Normal 0.15 alpha cyan
          ctx.globalAlpha = 0.15;
          ctx.strokeStyle = '#eef1e7';
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(sx, sy);
          ctx.lineTo(tx, ty);
          ctx.stroke();
        }

        ctx.restore();
      },
      [highlightedEdges, highlightedNodes]
    );

    // Zoom Controls
    const handleZoomIn = () => {
      if (!fgRef.current) return;
      const cur = fgRef.current.zoom();
      fgRef.current.zoom(cur * 1.3, 300);
    };

    const handleZoomOut = () => {
      if (!fgRef.current) return;
      const cur = fgRef.current.zoom();
      fgRef.current.zoom(cur * 0.7, 300);
    };

    const handleResetZoom = () => {
      if (!fgRef.current) return;
      fgRef.current.zoomToFit(600, 80);
      setHighlightedNodes(new Set());
      setHighlightedEdges(new Set());
    };

    // Filtered search matches
    const searchMatches = useMemo(() => {
      if (!searchQuery.trim()) return [];
      const q = searchQuery.toLowerCase();
      return nodes.filter((n) => n.id.toLowerCase().includes(q) || n.label.toLowerCase().includes(q)).slice(0, 8);
    }, [searchQuery, nodes]);

    return (
      <div ref={containerRef} className="relative h-full w-full select-none overflow-hidden bg-[#1e3a33]">
        {/* ForceGraph2D Canvas */}
        <ForceGraph2D
          ref={fgRef as any}
          width={dimensions.width}
          height={dimensions.height}
          graphData={graphData}
          dagMode="radialout"
          onDagError={() => {
            // Ignored per spec
          }}
          nodeRelSize={4}
          nodeCanvasObject={(node, ctx, scale) => drawNode(node as GraphNode, ctx, scale)}
          nodeCanvasObjectMode={() => 'replace'}
          nodePointerAreaPaint={(node: any, color, ctx) => {
            ctx.fillStyle = color;
            ctx.beginPath();
            ctx.arc(node.x, node.y, 10, 0, 2 * Math.PI, false);
            ctx.fill();
          }}
          linkCanvasObject={(link, ctx) => drawLink(link, ctx)}
          linkCanvasObjectMode={() => 'replace'}
          onNodeClick={(n) => onNodeClick(n as GraphNode)}
          nodeLabel={(n: any) => {
            const vCount = n.vulns?.length || 0;
            const sev = n.severity || 'NONE';
            return `
              <div style="background:#12211d; border:1px solid #1e293b; padding:8px 12px; border-radius:8px; font-family:monospace; font-size:11px; box-shadow:0 8px 16px rgba(0,0,0,0.6);">
                <div style="font-weight:bold; color:#f8fafc; margin-bottom:4px;">${n.id}</div>
                <div style="color:#94a3b8;">Depth: <span style="color:#cfe0d6;">${n.depth ?? 0}</span> | Dependents: <span style="color:#e2e8f0;">${n.dependents ?? 0}</span></div>
                <div style="color:#94a3b8; margin-top:2px;">Severity: <span style="color:${SEVERITY_COLORS[sev]}; font-weight:bold;">${sev}</span> (${vCount} vulns)</div>
                ${n.pagerank ? `<div style="color:#64748b; font-size:10px; margin-top:2px;">PageRank: ${(n.pagerank * 1000).toFixed(3)}</div>` : ''}
              </div>
            `;
          }}
          onRenderFramePre={(ctx) => drawBackground(ctx)}
          cooldownTicks={120}
          enableNodeDrag={true}
          enableZoomInteraction={true}
        />

        {/* Top Control Toolbar */}
        <div className="pointer-events-none absolute inset-x-3 top-3 flex flex-col items-start gap-2 sm:inset-x-4 sm:flex-row sm:items-center sm:justify-between">
          {/* Left: Mode toggles */}
          <div className="flex items-center gap-1 bg-slate-900/80 backdrop-blur-md p-1 rounded-lg border border-slate-800 shadow-xl pointer-events-auto">
            <button
              onClick={() => onModeChange('risk')}
              aria-pressed={mode === 'risk'}
              className={`graph-toolbar-control px-2.5 py-1 rounded-md font-semibold transition-all flex items-center gap-1.5 ${
                mode === 'risk'
                  ? 'bg-cyan-300 text-slate-950 shadow-sm shadow-cyan-950/40'
                  : 'text-slate-400 hover:bg-slate-800 hover:text-slate-100'
              }`}
            >
              <Filter className="w-3.5 h-3.5" />
              Risk paths
            </button>
            <button
              onClick={() => onModeChange('full')}
              aria-pressed={mode === 'full'}
              className={`graph-toolbar-control px-2.5 py-1 rounded-md font-semibold transition-all flex items-center gap-1.5 ${
                mode === 'full'
                  ? 'bg-cyan-300 text-slate-950 shadow-sm shadow-cyan-950/40'
                  : 'text-slate-400 hover:bg-slate-800 hover:text-slate-100'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              Full graph
            </button>

            <div className="h-5 w-px bg-slate-800 mx-1" />

            <button
              onClick={() => setShowHalos(!showHalos)}
              aria-pressed={showHalos}
              className={`graph-toolbar-control px-2 py-1 rounded-md font-medium transition-all flex items-center gap-1.5 ${
                showHalos ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/30' : 'text-slate-400 hover:bg-slate-800'
              }`}
              title="Toggle Community Halos"
            >
              <Sparkles className="w-3.5 h-3.5" />
              Halos
            </button>
          </div>

          {/* Right: Search & Zoom Controls */}
          <div className="flex items-center gap-2 pointer-events-auto">
            {/* Search-to-focus */}
            <div className="relative">
              <div className="flex items-center bg-slate-900/90 backdrop-blur-md rounded-lg border border-slate-800 px-2.5 py-1 shadow-xl">
                <Search className="w-3.5 h-3.5 text-slate-400 mr-2" />
                <input
                  type="text"
                  placeholder="Focus package..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="graph-search-input w-28 bg-transparent font-mono text-slate-200 outline-none placeholder:text-slate-500 sm:w-36"
                />
              </div>

              {/* Dropdown search results */}
              {searchMatches.length > 0 && (
                <div className="absolute top-full mt-1.5 right-0 w-64 bg-slate-900/95 backdrop-blur-md border border-slate-800 rounded-xl shadow-2xl p-1.5 z-50">
                  {searchMatches.map((n) => (
                    <button
                      key={n.id}
                      onClick={() => {
                        onNodeClick(n);
                        setSearchQuery('');
                      }}
                      className="w-full text-left px-2.5 py-1.5 rounded-lg hover:bg-slate-800 text-xs flex items-center justify-between font-mono"
                    >
                      <span className="text-slate-200 truncate">{n.label || n.id}</span>
                      <span
                        className="text-[10px] font-bold px-1.5 py-0.5 rounded uppercase"
                        style={{ color: SEVERITY_COLORS[n.severity || 'NONE'] }}
                      >
                        {n.severity || 'OK'}
                      </span>
                    </button>
                  ))}
                </div>
              )}
            </div>

            {/* Zoom Controls */}
            <div className="flex items-center bg-slate-900/80 backdrop-blur-md rounded-lg border border-slate-800 p-0.5 shadow-xl">
              <button
                onClick={handleZoomIn}
                className="graph-icon-button text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-md transition-colors"
                title="Zoom in"
                aria-label="Zoom in"
              >
                <ZoomIn className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={handleZoomOut}
                className="graph-icon-button text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-md transition-colors"
                title="Zoom out"
                aria-label="Zoom out"
              >
                <ZoomOut className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={handleResetZoom}
                className="graph-icon-button text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-md transition-colors"
                title="Reset zoom"
                aria-label="Reset zoom"
              >
                <RotateCcw className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>

        {/* Legend Bottom-Left */}
        <div className="absolute bottom-4 left-4 bg-slate-900/85 backdrop-blur-md border border-slate-800/80 rounded-xl p-3 shadow-2xl pointer-events-auto text-[11px] font-sans">
          <div className="font-semibold text-slate-300 text-xs mb-2 flex items-center gap-1.5">
            <Eye className="w-3.5 h-3.5 text-cyan-400" />
            Graph Legend
          </div>
          <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-slate-400">
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full border border-cyan-400 bg-cyan-500/20 flex items-center justify-center">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
              </span>
              <span>App Core</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-[#ff6a3d] shadow-sm shadow-rose-500" />
              <span className="text-rose-400 font-medium">Critical</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-[#f3a03a]" />
              <span className="text-orange-400">High</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-[#e8c547]" />
              <span className="text-yellow-400">Moderate</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-[#cfe0d6]" />
              <span>Clean Pkg</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-[#8fd3a8] shadow-sm shadow-emerald-500" />
              <span className="text-emerald-400 font-medium">Healed</span>
            </div>
          </div>
          <div className="mt-2.5 pt-2 border-t border-slate-800 text-[10px] text-slate-500 flex items-center justify-between">
            <span>Dot Size: PageRank</span>
            <span>Rings: Radial Depth</span>
          </div>
        </div>
      </div>
    );
  }
);
