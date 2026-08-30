import { useState } from 'react';
import styles from './DiffViewer.module.css';

function parseDiff(diff) {
  if (!diff) return [];
  return diff.split('\n').map((line, i) => {
    let type = 'neutral';
    if (line.startsWith('---') || line.startsWith('+++')) type = 'header';
    else if (line.startsWith('@@')) type = 'hunk';
    else if (line.startsWith('-')) type = 'removed';
    else if (line.startsWith('+')) type = 'added';
    return { line, type, lineNum: i + 1 };
  });
}

function DiffLine({ line, type, lineNum }) {
  const cls = { removed: styles.lineRemoved, added: styles.lineAdded,
    hunk: styles.lineHunk, header: styles.lineHeader, neutral: styles.lineNeutral }[type] || styles.lineNeutral;
  return (
    <div className={[styles.codeLine, cls].join(' ')}>
      <span className={styles.lineNum}>{['removed','added','neutral'].includes(type) ? lineNum : ''}</span>
      <span className={styles.lineText}>{line || ' '}</span>
    </div>
  );
}

export default function DiffViewer({ patch, visible }) {
  const [merging, setMerging] = useState(false);
  const [merged, setMerged] = useState(false);

  if (!visible) {
    return (
      <div className={styles.pending}>
        <div className={styles.pendingIcon}>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" width="32" height="32">
            <circle cx="12" cy="12" r="10" strokeWidth="1.5"/>
            <path d="M12 8v4l3 3" strokeLinecap="round" strokeWidth="1.5"/>
          </svg>
        </div>
        <p>Patch will appear here after<br/>the PATCHER AGENT completes</p>
      </div>
    );
  }

  // Visible but no patch produced (clean repo / failed / partial result):
  // show an explicit "no patch" state instead of fabricated 97% + 0/0 counts.
  if (!patch || !patch.unified_diff) {
    return (
      <div className={styles.pending}>
        <div className={styles.pendingIcon}>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" width="32" height="32">
            <circle cx="12" cy="12" r="10" strokeWidth="1.5"/>
            <path d="M15 9l-6 6M9 9l6 6" strokeLinecap="round" strokeWidth="1.5"/>
          </svg>
        </div>
        <p>No patch was generated<br/>for this scan</p>
      </div>
    );
  }

  const diff = patch.unified_diff || '';
  const diffLines = parseDiff(diff);
  const confidence = patch.confidence_score != null ? Math.round(patch.confidence_score * 100) : 0;
  const prUrl = patch?.pr_url;
  const filename = patch?.file_modified || 'server.py';
  const prTitle = patch?.pull_request_title || 'fix(security): patch vulnerability';
  const addedCount = diffLines.filter(l => l.type === 'added').length;
  const removedCount = diffLines.filter(l => l.type === 'removed').length;

  const handleMerge = () => {
    if (prUrl) { window.open(prUrl, '_blank', 'noopener,noreferrer'); return; }
    setMerging(true);
    setTimeout(() => { setMerging(false); setMerged(true); }, 1600);
  };

  return (
    <div className={[styles.diffViewer, merged ? styles.mergedState : ''].filter(Boolean).join(' ')}>
      <div className={styles.header}>
        <div className={styles.fileInfo}>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" width="13" height="13">
            <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" strokeWidth="1.5"/>
            <path d="M14 2v6h6" strokeWidth="1.5"/>
          </svg>
          <span className={styles.filename}>{filename}</span>
          <span className={styles.cveBadge}>AI PATCH</span>
        </div>
        <div className={styles.changeStats}>
          <span className={styles.statAdded}>+{addedCount}</span>
          <span className={styles.statRemoved}>-{removedCount}</span>
        </div>
      </div>

      <div className={styles.codeBlock}>
        {diffLines.length > 0
          ? diffLines.map((l, i) => <DiffLine key={i} {...l} />)
          : <div className={styles.noDiff}>Patch content not available — check PR directly</div>}
      </div>

      <div className={styles.footer}>
        <div className={styles.prInfo}>
          <div className={styles.confidence}>
            <span className={styles.confLabel}>AI CONFIDENCE</span>
            <div className={styles.confBar}><div className={styles.confFill} style={{width:`${confidence}%`}}></div></div>
            <span className={styles.confValue}>{confidence}%</span>
          </div>
          <div className={styles.prTitle}>
            <svg viewBox="0 0 24 24" fill="currentColor" width="12" height="12" style={{flexShrink:0,opacity:0.6}}>
              <path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/>
            </svg>
            <span style={{overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{prTitle}</span>
          </div>
        </div>
        {!merged ? (
          <button className={[styles.mergeBtn, merging?styles.mergingBtn:'', prUrl?styles.prBtn:''].filter(Boolean).join(' ')}
            onClick={handleMerge} disabled={merging}>
            {merging ? (<><span className={styles.mergeSpinner}></span>MERGING...</>)
              : prUrl ? (<>
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" width="15" height="15">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
                      d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6M15 3h6m0 0v6m0-6L10 14"/>
                  </svg>VIEW PULL REQUEST</>)
              : (<>
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" width="15" height="15">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
                      d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                  </svg>APPROVE & MERGE FIX</>)}
          </button>
        ) : (
          <div className={styles.mergedBadge}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" width="15" height="15">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"/>
            </svg>MERGED TO MAIN
          </div>
        )}
      </div>
    </div>
  );
}
