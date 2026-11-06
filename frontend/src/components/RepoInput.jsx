import { useState } from 'react';
import styles from './RepoInput.module.css';

function isValidGithubUrl(url) {
  return /^https?:\/\/(www\.)?github\.com\/[^/]+\/[^/]+/.test(url.trim());
}

/** Human-readable summary of which repos this deployment will scan. */
function describeAllowed(owners) {
  if (!owners || owners.includes('*')) return null;
  const parts = owners.map(o => (o === '@self' ? 'your own repositories' : `${o}/*`));
  return parts.length ? `This deployment scans: ${parts.join(', ')}.` : null;
}

export default function RepoInput({ onStartScan, disabled, disabledReason, config }) {
  const demoRepo = config?.demo_repo_url || null;
  const allowedNote = describeAllowed(config?.allowed_owners);
  const [value, setValue] = useState('');
  const [error, setError] = useState('');
  const [focused, setFocused] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async () => {
    if (disabled || submitting) return;
    const trimmed = value.trim();
    if (!trimmed) { setError('Please enter a GitHub repository URL.'); return; }
    if (!isValidGithubUrl(trimmed)) {
      setError('Must be a valid GitHub URL — e.g. https://github.com/owner/repo');
      return;
    }
    setError('');
    setSubmitting(true);
    try {
      await onStartScan(trimmed);
    } finally {
      setSubmitting(false);
    }
  };

  const handleKey = (e) => { if (e.key === 'Enter') handleSubmit(); };

  return (
    <div className={styles.inputWrap}>
      <div className={styles.inputHeader}>
        <div className={styles.inputTitle}>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" width="14" height="14">
            <circle cx="11" cy="11" r="8" strokeWidth="1.5"/>
            <path d="M21 21l-4.35-4.35" strokeWidth="1.5" strokeLinecap="round"/>
          </svg>
          TARGET REPOSITORY
        </div>
        <span className={styles.inputHint}>
          {disabled && disabledReason
            ? <span style={{color:'rgba(255,159,28,0.7)'}}>{disabledReason}</span>
            : 'A.E.G.I.S. will clone, scan, exploit and patch this repo'}
        </span>
      </div>

      <div className={[
        styles.inputRow,
        focused ? styles.focused : '',
        error ? styles.hasError : '',
        disabled ? styles.disabledRow : '',
      ].filter(Boolean).join(' ')}>
        <div className={styles.inputPrefix}>
          <svg viewBox="0 0 24 24" fill="currentColor" width="16" height="16" className={styles.ghIcon}>
            <path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/>
          </svg>
          <span className={styles.inputPrefixSep}></span>
        </div>
        <input
          className={styles.input}
          type="url"
          placeholder="https://github.com/owner/repository"
          value={value}
          onChange={e => { setValue(e.target.value); setError(''); }}
          onFocus={() => setFocused(true)}
          onBlur={() => setFocused(false)}
          onKeyDown={handleKey}
          spellCheck={false}
          autoComplete="off"
          disabled={disabled}
        />
        <button className={[styles.submitBtn, (disabled || submitting) ? styles.submitBtnDisabled : ''].filter(Boolean).join(' ')}
          onClick={handleSubmit} disabled={disabled || submitting}>
          {submitting ? (
            <>
              <span style={{display:'inline-block',width:14,height:14,border:'2px solid rgba(255,255,255,0.3)',borderTopColor:'#00ff9d',borderRadius:'50%',animation:'spin 0.6s linear infinite'}}></span>
              STARTING...
            </>
          ) : (
            <>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" width="15" height="15">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5"
                  d="M13 10V3L4 14h7v7l9-11h-7z"/>
              </svg>
              START SCAN
            </>
          )}
        </button>
      </div>

      {error && (
        <div className={styles.error}>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" width="12" height="12">
            <circle cx="12" cy="12" r="10" strokeWidth="1.5"/>
            <path d="M12 8v4M12 16h.01" strokeWidth="1.5" strokeLinecap="round"/>
          </svg>
          {error}
        </div>
      )}

      {demoRepo && (
        <div className={styles.examples}>
          <span className={styles.exLabel}>Try the demo target:</span>
          <button className={styles.exBtn}
            onClick={() => { setValue(demoRepo); setError(''); }} disabled={disabled}>
            {demoRepo.replace('https://github.com/', '')}
          </button>
          <span className={styles.exLabel}>(a deliberately vulnerable Flask app)</span>
        </div>
      )}
      {config && (
        <p className={styles.policyNote}>
          {allowedNote && <>{allowedNote} </>}
          {config.upstream_prs
            ? 'If you can’t push to the repo, it is forked into your account and the fix PR is opened against the original.'
            : 'If you can’t push to the repo, it is forked into your account and the fix PR is opened in your fork.'}
        </p>
      )}
    </div>
  );
}
