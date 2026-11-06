import styles from './ScanComplete.module.css';

export default function ScanComplete({ result, scanId, onReset, telemetry = false }) {
  if (!result) return null;

  const secret = result.exploit?.exploit_evidence || null;
  const prUrl  = result.patch?.pr_url || null;
  const branch = result.patch?.pull_request_title
    ?.match(/\[([^\]]+)\]/)?.[1] || `fix/${scanId?.slice(0,8)}`;
  const repoUrl = result.repo_url;
  const repoShort = repoUrl?.replace('https://github.com/', '') || '';
  const vulnCount = result.vulnerabilities?.length || 0;
  const finding = result.exploited_finding || result.recon?.vulnerable_endpoints?.[0] || null;
  const framework = result.recon?.detected_framework || 'Unknown';
  const confidence = result.patch?.confidence_score != null
    ? Math.round(result.patch.confidence_score * 100) : null;

  const omiumUrl = 'https://app.omium.ai/overview';

  // Outcome drives the headline: never claim a fix that didn't happen.
  const outcome = prUrl ? 'patched' : (vulnCount === 0 && !result.partial) ? 'clean' : 'unpatched';
  const HEADLINES = {
    patched:   ['MISSION COMPLETE', 'Exploited, verified and patched'],
    clean:     ['SCAN COMPLETE', 'No exploitable vulnerability found'],
    unpatched: ['SCAN COMPLETE', 'Scan finished without a fix PR'],
  };
  const [headLabel, headTitle] = HEADLINES[outcome];
  // When the user can't push to the repo, the PR is opened inside their fork.
  const prOwner = prUrl?.replace('https://github.com/', '').split('/')[0];
  const repoOwner = repoShort.split('/')[0];
  const prInFork = !!(prOwner && repoOwner && prOwner.toLowerCase() !== repoOwner.toLowerCase());

  return (
    <div className={styles.card}>
      {/* Header */}
      <div className={styles.cardHeader}>
        <div className={styles.headerLeft}>
          <div className={styles.successRing}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" width="24" height="24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M5 13l4 4L19 7"/>
            </svg>
          </div>
          <div>
            <div className={styles.headerLabel}>{headLabel}</div>
            <div className={styles.headerTitle}>{headTitle}</div>
          </div>
        </div>
        <button className={styles.resetBtn} onClick={onReset}>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" width="14" height="14">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
              d="M4 4v5h5M20 20v-5h-5M4 9a9 9 0 0114.7-7"/>
          </svg>
          Scan Another Repo
        </button>
      </div>

      {/* Stats row */}
      <div className={styles.statsRow}>
        <div className={styles.stat}>
          <span className={styles.statVal} style={{color:'var(--accent-red)'}}>
            {vulnCount}
          </span>
          <span className={styles.statLabel}>Vulnerabilities Found</span>
        </div>
        <div className={styles.statDiv}></div>
        <div className={styles.stat}>
          <span className={styles.statVal} style={{color:'var(--accent-orange)'}}>
            {result.exploit?.vulnerability_confirmed ? 'YES' : 'NO'}
          </span>
          <span className={styles.statLabel}>Exploit Confirmed</span>
        </div>
        <div className={styles.statDiv}></div>
        <div className={styles.stat}>
          <span className={styles.statVal} style={{color:'var(--accent-green)'}}>
            {result.verification?.verified ? 'PASS' : 'FAIL'}
          </span>
          <span className={styles.statLabel}>Verifier Result</span>
        </div>
        <div className={styles.statDiv}></div>
        <div className={styles.stat}>
          <span className={styles.statVal} style={{color:'var(--accent-blue)'}}>
            {confidence != null ? `${confidence}%` : 'N/A'}
          </span>
          <span className={styles.statLabel}>Patch Confidence</span>
        </div>
      </div>

      {/* Key findings */}
      <div className={styles.findings}>

        {/* Secret captured */}
        {secret && (
          <div className={styles.finding} data-type="flag">
            <div className={styles.findingIcon} style={{background:'rgba(255,60,60,0.12)', borderColor:'rgba(255,60,60,0.3)', color:'var(--accent-red)'}}>
              💣
            </div>
            <div className={styles.findingBody}>
              <span className={styles.findingLabel}>SECRET RECOVERED</span>
              <code className={styles.findingCode} style={{color:'var(--accent-red)'}}>{secret}</code>
            </div>
          </div>
        )}

        {/* The finding the exploit proved (falls back to recon's top finding) */}
        {finding && (
          <div className={styles.finding}>
            <div className={styles.findingIcon} style={{background:'rgba(255,159,28,0.12)', borderColor:'rgba(255,159,28,0.3)', color:'var(--accent-orange)'}}>
              🔍
            </div>
            <div className={styles.findingBody}>
              <span className={styles.findingLabel}>
                {result.exploited_finding ? 'VULNERABILITY EXPLOITED' : 'TOP FINDING'}
              </span>
              <span className={styles.findingText}>
                {(finding.injection_vector || '').split('\n')[0]}
                {' on '}
                <code className={styles.findingCode}>{finding.path}</code>
              </span>
            </div>
          </div>
        )}

        {/* Patch branch */}
        <div className={styles.finding}>
          <div className={styles.findingIcon} style={{background:'rgba(0,255,157,0.1)', borderColor:'rgba(0,255,157,0.3)', color:'var(--accent-green)'}}>
            🩹
          </div>
          <div className={styles.findingBody}>
            <span className={styles.findingLabel}>PATCH STATUS</span>
            {prUrl ? (
              <a href={prUrl} target="_blank" rel="noopener noreferrer" className={styles.prLink}>
                {prInFork ? 'Pull Request opened in your fork →' : 'Pull Request opened →'}
                <span className={styles.prUrlText}>{prUrl.replace('https://github.com/', '')}</span>
              </a>
            ) : outcome === 'clean' ? (
              <span className={styles.findingText}>Nothing to patch: no vulnerability was found in the scanned source.</span>
            ) : (
              <span className={styles.findingText}>No pull request was opened for <code className={styles.findingCode}>{branch}</code>.</span>
            )}
          </div>
        </div>

        {/* Repo scanned */}
        <div className={styles.finding}>
          <div className={styles.findingIcon} style={{background:'rgba(0,180,255,0.1)', borderColor:'rgba(0,180,255,0.3)', color:'var(--accent-blue)'}}>
            📦
          </div>
          <div className={styles.findingBody}>
            <span className={styles.findingLabel}>TARGET REPOSITORY</span>
            <a href={repoUrl} target="_blank" rel="noopener noreferrer" className={styles.repoLink}>
              {repoShort}
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" width="10" height="10">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
                  d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6M15 3h6m0 0v6m0-6L10 14"/>
              </svg>
            </a>
          </div>
        </div>
      </div>

      {/* Footer actions */}
      <div className={styles.actions}>
        {prUrl && (
          <a href={prUrl} target="_blank" rel="noopener noreferrer" className={styles.actionPrimary}>
            <svg viewBox="0 0 24 24" fill="currentColor" width="16" height="16">
              <path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/>
            </svg>
            REVIEW PULL REQUEST
          </a>
        )}
        {telemetry && (
        <a href={omiumUrl} target="_blank" rel="noopener noreferrer" className={styles.actionSecondary}>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" width="15" height="15">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
              d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/>
          </svg>
          VIEW OMIUM TRACE
        </a>
        )}
      </div>
    </div>
  );
}
