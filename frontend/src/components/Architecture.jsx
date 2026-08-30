import styles from './Architecture.module.css';

const LAYERS = [
  {
    icon: '⚡',
    title: 'FastAPI + Pydantic v2',
    color: '#00b4ff',
    desc: 'ASGI webhook ingress with strict schema validation. Rejects malformed payloads in <10ms. Returns HTTP 202 instantly.'
  },
  {
    icon: '⚙',
    title: 'Async Pipeline + SSE',
    color: '#ff9f1c',
    desc: 'Each scan runs as a background asyncio task; live progress streams to the browser over Server-Sent Events through a per-scan in-process queue.'
  },
  {
    icon: '◈',
    title: 'SQLite WAL Checkpoint',
    color: '#ffe34d',
    desc: 'Crash-safe state persistence. Every Petri net transition is atomically committed. Full resume after failure.'
  },
  {
    icon: '◉',
    title: 'Colored Petri Net',
    color: '#00ff9d',
    desc: 'Deterministic routing via pure Python. LLM only evaluates conditions. Transitions are hardcoded if/else logic.'
  },
  {
    icon: '⬡',
    title: 'Fail-Closed Circuit Breakers',
    color: '#c8b9ff',
    desc: 'AST validation + retry limits + signature hashing. Infinite death-spirals are physically impossible.'
  },
  {
    icon: '◎',
    title: 'Omium SDK (OTLP)',
    color: '#00b4ff',
    desc: 'W3C Trace Context propagated across async boundaries. Every agent turn, token count and tool call causal-linked.'
  },
];

export default function Architecture() {
  return (
    <section className={styles.arch} id="architecture">
      <div className={styles.inner}>
        <div className={styles.sectionHeader}>
          <span className={styles.sectionTag}>SYSTEM DESIGN</span>
          <h2 className={styles.sectionTitle}>Production-Grade Architecture</h2>
          <p className={styles.sectionSub}>
            No LLM wrappers. No conversational loops. Pure mathematical orchestration.
          </p>
        </div>

        <div className={styles.grid}>
          {LAYERS.map((layer, i) => (
            <div key={i} className={styles.card} style={{'--accent': layer.color}}>
              <div className={styles.cardIcon}>{layer.icon}</div>
              <h3 className={styles.cardTitle}>{layer.title}</h3>
              <p className={styles.cardDesc}>{layer.desc}</p>
              <div className={styles.cardLine}></div>
            </div>
          ))}
        </div>

        {/* Stack diagram */}
        <div className={styles.stackDiagram}>
          <div className={styles.stackLabel}>REQUEST FLOW</div>
          <div className={styles.stackFlow}>
            {[
              { label: 'Webhook', sub: 'FastAPI\nPydantic v2' },
              { label: '→', arrow: true },
              { label: 'Runner', sub: 'asyncio task\nSSE stream' },
              { label: '→', arrow: true },
              { label: 'Orchestrator', sub: 'Petri Net\nGraph Engine' },
              { label: '→', arrow: true },
              { label: 'Agents', sub: 'Recon / Exploit\nVerify / Patch' },
              { label: '→', arrow: true },
              { label: 'State', sub: 'SQLite WAL\nCheckpoint' },
            ].map((item, i) => item.arrow ? (
              <span key={i} className={styles.flowArrow}>→</span>
            ) : (
              <div key={i} className={styles.flowBox}>
                <span className={styles.flowLabel}>{item.label}</span>
                <span className={styles.flowSub}>{item.sub}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
