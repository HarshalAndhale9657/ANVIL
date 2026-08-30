import { useState, useEffect, useRef } from 'react';
import styles from './PetriNet.module.css';

/**
 * Maps backend ScanStage values (from SSE) to the node index to activate.
 * idle=0, trigger=1, recon=2, exploit=3, verify=4, patch=5, end=6, error=?
 */
const STAGE_INDEX = {
  idle: 0, trigger: 1, cloning: 1,
  recon: 2, exploit: 3, verify: 4,
  patch: 5, pushing: 5, end: 6,
  completed: 6, failed: 6, error: 6,
};

const NODES = [
  { id: 'idle',    label: 'IDLE',    x: 80,  y: 130, color: '#4a4a6a', desc: 'System ready' },
  { id: 'trigger', label: 'TRIGGER', x: 220, y: 130, color: '#00b4ff', desc: 'Webhook received' },
  { id: 'recon',   label: 'RECON',   x: 360, y: 55,  color: '#00ff9d', desc: 'Scanning source code' },
  { id: 'exploit', label: 'EXPLOIT', x: 500, y: 130, color: '#ff9f1c', desc: 'Generating payload' },
  { id: 'verify',  label: 'VERIFY',  x: 640, y: 55,  color: '#ffe34d', desc: 'Confirming exploit' },
  { id: 'patch',   label: 'PATCH',   x: 780, y: 130, color: '#00ff9d', desc: 'Opening Pull Request' },
  { id: 'end',     label: 'DONE',    x: 920, y: 130, color: '#00b4ff', desc: 'Scan complete' },
];

const EDGES = [
  { from: 0, to: 1 }, { from: 1, to: 2 }, { from: 2, to: 3 },
  { from: 3, to: 4 }, { from: 4, to: 5 }, { from: 5, to: 6 },
];

const ERROR_STAGES = new Set(['error', 'failed']);

export default function PetriNet({ currentStage }) {
  const [activeIndex, setActiveIndex] = useState(0);
  const [flowingEdge, setFlowingEdge] = useState(null);
  const [errored, setErrored] = useState(false);
  const prevIndex = useRef(0);

  useEffect(() => {
    if (!currentStage) return;

    // Pipeline failure: freeze at the last reached node and render it red.
    // (Previously 'error'/'failed' mapped to the same index as DONE, so a
    // failed scan animated all the way to a green "complete" state.)
    if (ERROR_STAGES.has(currentStage)) {
      setErrored(true);
      setFlowingEdge(null);
      return;
    }

    const idx = STAGE_INDEX[currentStage] ?? 0;

    if (idx < prevIndex.current) {
      // Reset (new scan)
      setErrored(false);
      setActiveIndex(0);
      prevIndex.current = 0;
      setFlowingEdge(null);
      return;
    }

    if (idx > prevIndex.current) {
      setErrored(false);
      setFlowingEdge(idx - 1);
      // Clean up the timer so rapid SSE events can't stack transitions or
      // fire state updates after the component unmounts.
      const timer = setTimeout(() => {
        setActiveIndex(idx);
        prevIndex.current = idx;
        setFlowingEdge(null);
      }, 500);
      return () => clearTimeout(timer);
    }
  }, [currentStage]);

  return (
    <div className={styles.petriWrap}>
      <div className={styles.header}>
        <span className={styles.headerTitle}>PETRI NET STATE MACHINE</span>
        <span className={styles.headerSub}>CPN — Colored Petri Net Orchestration</span>
      </div>

      <div className={styles.svgWrap}>
        <svg viewBox="0 0 1020 200" className={styles.svg} preserveAspectRatio="xMidYMid meet">
          <defs>
            <marker id="arr" markerWidth="8" markerHeight="6" refX="6" refY="3" orient="auto">
              <polygon points="0 0, 8 3, 0 6" fill="rgba(255,255,255,0.12)" />
            </marker>
            <marker id="arr-active" markerWidth="8" markerHeight="6" refX="6" refY="3" orient="auto">
              <polygon points="0 0, 8 3, 0 6" fill="#00ff9d" />
            </marker>
          </defs>

          {EDGES.map((edge, i) => {
            const from = NODES[edge.from];
            const to = NODES[edge.to];
            const isActive = i < activeIndex;
            const isFlowing = i === flowingEdge;
            const dx = to.x - from.x, dy = to.y - from.y;
            const len = Math.sqrt(dx*dx + dy*dy);
            const ux = dx/len, uy = dy/len;
            const r = 28;
            const x1 = from.x + ux*r, y1 = from.y + uy*r;
            const x2 = to.x - ux*r,   y2 = to.y - uy*r;
            return (
              <g key={i}>
                <line x1={x1} y1={y1} x2={x2} y2={y2}
                  stroke={isActive ? '#00ff9d' : 'rgba(255,255,255,0.08)'}
                  strokeWidth={isActive ? 2 : 1.5}
                  markerEnd={isActive ? 'url(#arr-active)' : 'url(#arr)'}
                  className={isFlowing ? styles.edgeFlowing : ''}
                />
                {isFlowing && (
                  <circle r="4" fill="#00ff9d">
                    <animateMotion dur="0.45s" fill="freeze" path={`M${x1},${y1} L${x2},${y2}`} />
                  </circle>
                )}
              </g>
            );
          })}

          {NODES.map((node, i) => {
            const isActive = i === activeIndex;
            const isDone = i < activeIndex;
            const activeColor = errored && isActive ? '#ff3b3b' : node.color;
            const color = isDone || isActive ? activeColor : '#1e1e30';
            const textColor = isDone || isActive ? '#06060b' : 'rgba(255,255,255,0.25)';
            return (
              <g key={node.id}>
                {isActive && (
                  <circle cx={node.x} cy={node.y} r="38" fill="none"
                    stroke={activeColor} strokeWidth="1" opacity="0.4"
                    className={styles.pulseRing} />
                )}
                <circle cx={node.x} cy={node.y} r="26"
                  fill={color}
                  stroke={isDone || isActive ? activeColor : 'rgba(255,255,255,0.12)'}
                  strokeWidth={isActive ? 2.5 : 1.5}
                  className={isActive ? styles.nodeActive : ''}
                />
                <text x={node.x} y={node.y + 4} textAnchor="middle"
                  fill={textColor} fontSize="8"
                  fontFamily="'Rajdhani', sans-serif" fontWeight="700" letterSpacing="1">
                  {node.label}
                </text>
                {isActive && (
                  <text x={node.x} y={node.y + 50} textAnchor="middle"
                    fill={activeColor} fontSize="8"
                    fontFamily="'Share Tech Mono', monospace" opacity="0.9">
                    {errored ? 'PIPELINE FAILED' : node.desc}
                  </text>
                )}
              </g>
            );
          })}
        </svg>
      </div>

      <div className={styles.footer}>
        <div className={styles.legend}>
          {[['#4a4a6a','Idle'], ['#00ff9d','Active'], ['#ff9f1c','Processing'], ['#ffe34d','Verifying']].map(([c,l]) => (
            <span key={l} className={styles.legItem}>
              <span className={styles.legDot} style={{background:c}}></span>{l}
            </span>
          ))}
        </div>
        <div className={styles.currentState}>
          CURRENT STATE:&nbsp;
          <span style={{color: errored ? '#ff3b3b' : (NODES[activeIndex]?.color || '#4a4a6a')}}>
            {errored ? 'FAILED' : (NODES[activeIndex]?.label || 'IDLE')}
          </span>
        </div>
      </div>
    </div>
  );
}
