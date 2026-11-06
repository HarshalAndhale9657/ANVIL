import styles from './GitHubConnect.module.css';

export default function GitHubConnect({
  user, loading, slow, authError, onDismissError, onLogin, onLogout,
}) {
  if (loading) {
    return (
      <div className={styles.wrap}>
        <div className={styles.checking}>
          <span className={styles.spinner}></span>
          <span>
            {slow ? 'Waking up the scan engine...' : 'Checking GitHub authentication...'}
            {slow && (
              <span className={styles.slowNote}>
                The backend sleeps when idle on its free hosting tier. First load can take up to a minute.
              </span>
            )}
          </span>
        </div>
      </div>
    );
  }

  if (user) {
    return (
      <div className={styles.connected}>
        <img
          src={user.avatar_url}
          alt={user.login}
          className={styles.avatar}
        />
        <div className={styles.userInfo}>
          <span className={styles.connectedLabel}>CONNECTED AS</span>
          <a
            href={`https://github.com/${user.login}`}
            target="_blank"
            rel="noopener noreferrer"
            className={styles.username}
          >
            @{user.login}
          </a>
        </div>
        <button className={styles.logoutBtn} onClick={onLogout}>
          Disconnect
        </button>
      </div>
    );
  }

  return (
    <div className={styles.wrap}>
      {authError && (
        <div className={styles.authError} role="alert">
          <span>{authError}</span>
          <button onClick={onDismissError} aria-label="Dismiss">×</button>
        </div>
      )}
      <div className={styles.notice}>
        <div className={styles.noticeIcon}>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" width="20" height="20">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5"
              d="M12 9v4M12 17h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
          </svg>
        </div>
        <div className={styles.noticeText}>
          <strong>GitHub Authentication Required</strong>
          <span>A.E.G.I.S. needs repo access to clone, scan, and open a Pull Request with the fix.</span>
        </div>
      </div>
      <button className={styles.connectBtn} onClick={onLogin}>
        <svg viewBox="0 0 24 24" fill="currentColor" width="18" height="18">
          <path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/>
        </svg>
        Connect GitHub to Start Scanning
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" width="14" height="14">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 18l6-6-6-6"/>
        </svg>
      </button>
      <p className={styles.scopeNote}>
        Requests the <code>repo</code> scope to clone the repository and open the fix
        Pull Request. Your token is kept in an encrypted, HttpOnly session cookie and
        is never stored server-side.
      </p>
    </div>
  );
}
