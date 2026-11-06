import { useEffect, useRef } from 'react';
import styles from './Terminal.module.css';

const TYPE_CLASSES = {
  system:  styles.lineSystem,
  event:   styles.lineEvent,
  agent:   styles.lineAgent,
  data:    styles.lineData,
  warn:    styles.lineWarn,
  success: styles.lineSuccess,
  code:    styles.lineCode,
  flag:    styles.lineFlag,
  finish:  styles.lineFinish,
  error:   styles.lineWarn,
};

export default function Terminal({ logs, phase, repoUrl, retryInfo, scanId }) {
  const bottomRef = useRef(null);
  const outputRef = useRef(null);

  useEffect(() => {
    // Scroll within the terminal output container only, not the entire page
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight;
    }
  }, [logs]);

  const hasFlag = logs.some(l => l.type === 'flag');
  const isRunning = phase === 'scanning';
  const isDone = phase === 'complete';
  const isFailed = phase === 'failed';

  const shortPath = repoUrl
    ? repoUrl.replace('https://github.com/', '').replace('/', '_')
    : 'autonomous-engine';

  return (
    <div className={[styles.terminal, hasFlag ? styles.flagMode : ''].filter(Boolean).join(' ')}>
      <div className={styles.titleBar}>
        <div className={styles.dots}>
          <span className={styles.dot} style={{background:'#ff5f57'}}></span>
          <span className={styles.dot} style={{background:'#febc2e'}}></span>
          <span className={styles.dot} style={{background:'#28c840'}}></span>
        </div>
        <span className={styles.termTitle}>aegis@mission-control ~ /scan/{shortPath}</span>
        <div className={styles.termMeta}>
          <span className={styles.lineCounter}>{logs.length} events</span>
          {isRunning && !retryInfo && <span className={styles.runningBadge}>● RUNNING</span>}
          {isRunning && retryInfo && (
            <span className={styles.retryBadge}>↻ RETRYING {retryInfo.attempt}/{retryInfo.max}</span>
          )}
          {isDone && <span className={styles.doneBadge}>✓ COMPLETE</span>}
          {isFailed && <span className={styles.failedBadge}>✗ FAILED</span>}
        </div>
      </div>

      <div className={styles.output} ref={outputRef}>
        {logs.length === 0 && (
          <div className={styles.idle}>
            <span className={styles.idlePrompt}>$</span>
            <span className={styles.idleCursor}></span>
            <span className={styles.idleText}>&nbsp;Waiting for scan to start...</span>
          </div>
        )}
        {logs.map((line) => (
          <div key={line.id} className={[styles.line, TYPE_CLASSES[line.type] || '', styles.lineIn].join(' ')}>
            {line.type === 'flag' ? (
              <span className={styles.flagText}>{line.text}</span>
            ) : (
              <>
                <span className={styles.prompt}>
                  {['agent','system','event','finish'].includes(line.type) ? '>' : '\u00a0'}
                </span>
                {line.text}
              </>
            )}
          </div>
        ))}
        {isRunning && (
          <div className={styles.line}>
            <span className={styles.prompt}>$</span>
            <span className={styles.cursor}></span>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      <div className={styles.controls}>
        {scanId && (
          <span className={styles.scanIdBadge}>scan_id: {scanId.slice(0, 8)}…</span>
        )}
        <a
          href="https://github.com/HarshalAndhale9657/ANVIL/tree/main/backend/app"
          target="_blank" rel="noopener noreferrer"
          className={styles.viewScriptBtn}
        >
          <svg viewBox="0 0 24 24" fill="currentColor" width="14" height="14">
            <path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/>
          </svg>
          View A.E.G.I.S. Engine
        </a>
      </div>
    </div>
  );
}
