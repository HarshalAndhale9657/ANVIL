/**
 * A.E.G.I.S. API Client
 * All communication with the FastAPI backend lives here.
 *
 * Requests are SAME-ORIGIN (relative /api/...): locally the Vite dev server
 * proxies /api to :8000, and in production Vercel rewrites /api/* to the
 * backend (frontend/vercel.json). Same-origin keeps the session cookie
 * first-party, so login works in Safari/Firefox/Brave and private windows,
 * which all block third-party cookies.
 *
 * VITE_API_URL is only for split-origin setups (not recommended).
 */

const BASE = (import.meta.env.VITE_API_URL || '').replace(/\/+$/, '');

/** Build an Error carrying the server's human-readable `detail`. */
async function errorFrom(res) {
  const body = await res.json().catch(() => ({}));
  let msg = body.detail;
  if (Array.isArray(msg)) {
    // FastAPI 422: [{msg: "Value error, must be a GitHub repository URL ..."}]
    msg = msg.map(d => (d.msg || '').replace(/^Value error, /, '')).filter(Boolean).join('; ');
  }
  const err = new Error(msg || `HTTP ${res.status}`);
  err.code = res.status;
  return err;
}

// ── Deployment info ───────────────────────────────────────────────────────────

/**
 * Wake the backend early. Free-tier hosts sleep when idle and take up to a
 * minute to cold-start; firing this on page load means the engine is usually
 * awake by the time the visitor has read the hero and clicked Connect.
 */
export function warmUp() {
  fetch(`${BASE}/api/health`, { credentials: 'include' }).catch(() => {});
}

/** Public deployment policy: demo repo, allowed owners, limits. */
export async function getConfig() {
  try {
    const res = await fetch(`${BASE}/api/config`, { credentials: 'include' });
    return res.ok ? await res.json() : null;
  } catch {
    return null;
  }
}

// ── Auth ──────────────────────────────────────────────────────────────────────

/** Returns the GitHub user object or null if unauthenticated. */
export async function getMe() {
  try {
    const res = await fetch(`${BASE}/api/auth/me`, { credentials: 'include' });
    if (res.status === 401) return null;
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

/** Kick off GitHub OAuth — navigates the browser to /api/auth/github */
export function loginWithGitHub() {
  window.location.href = `${BASE}/api/auth/github`;
}

/** Clear the session cookie. */
export async function logout() {
  await fetch(`${BASE}/api/auth/logout`, { method: 'POST', credentials: 'include' });
}

// ── Scan ──────────────────────────────────────────────────────────────────────

/**
 * Start a new scan.
 * @param {string} repoUrl  - e.g. "https://github.com/owner/repo"
 * @param {string} baseBranch - default "main"
 * @returns {{ scan_id, stream_url, status }} or throws
 */
export async function startScan(repoUrl, baseBranch = 'main') {
  const res = await fetch(`${BASE}/api/scan`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ repo_url: repoUrl, base_branch: baseBranch }),
  });

  if (!res.ok) throw await errorFrom(res);
  return res.json();
}

/**
 * Subscribe to real-time SSE events for a scan.
 *
 * Uses manual reconnection with exponential backoff + jitter instead of
 * relying on the browser's native EventSource auto-reconnect, which fires
 * too rapidly and exhausts retry budgets.
 *
 * @param {string} scanId
 * @param {(event: ScanEvent) => void} onEvent  - called for every stage event
 * @param {(err: Error) => void}       onError  - called on fatal error
 * @returns {() => void}  call this to close the connection
 */
export function streamScan(scanId, onEvent, onError) {
  const url = `${BASE}/api/scan/${scanId}/stream`;

  // The backend sets `event:` to the stage name, `data:` to JSON
  const STAGES = ['queued','cloning','recon','exploit','verify','patch','pushing','completed','failed'];

  // ── Reconnection state ──
  let terminated = false;
  let retryCount = 0;
  const MAX_RETRIES = 15;             // generous budget for long-running scans
  const BASE_DELAY_MS = 1000;         // 1s initial backoff
  const MAX_DELAY_MS = 30000;         // cap at 30s
  let reconnectTimer = null;
  let es = null;

  function connect() {
    if (terminated) return;

    es = new EventSource(url, { withCredentials: true });

    // ── "connected" — server confirms stream is alive ──
    es.addEventListener('connected', () => {
      retryCount = 0;  // healthy connection — reset
    });

    // ── Stage events ──
    STAGES.forEach(stage => {
      es.addEventListener(stage, (e) => {
        try {
          retryCount = 0;  // any data event = healthy
          const data = JSON.parse(e.data);
          onEvent({ ...data, stage });

          if (stage === 'completed' || stage === 'failed') {
            terminated = true;
            es.close();
          }
        } catch (err) {
          console.warn('Failed to parse SSE data:', e.data);
        }
      });
    });

    // ── Keepalive ──
    es.addEventListener('keepalive', () => {
      retryCount = 0;
    });

    // ── Error handling with manual reconnection ──
    es.onerror = () => {
      // After a terminal event the server closes the stream — expected
      if (terminated) {
        es.close();
        return;
      }

      // Close the broken EventSource immediately so the browser doesn't
      // auto-reconnect underneath our manual backoff logic.
      es.close();

      retryCount++;

      if (retryCount > MAX_RETRIES) {
        onError(new Error(
          `SSE connection failed after ${MAX_RETRIES} retries — ` +
          `check that the backend is running and the scan is still active`
        ));
        return;
      }

      // Exponential backoff with jitter
      const delay = Math.min(
        BASE_DELAY_MS * Math.pow(2, retryCount - 1) + Math.random() * 500,
        MAX_DELAY_MS,
      );
      console.info(
        `[SSE] reconnecting in ${Math.round(delay)}ms (attempt ${retryCount}/${MAX_RETRIES})`
      );
      reconnectTimer = setTimeout(connect, delay);
    };
  }

  // Start the initial connection
  connect();

  // Return cleanup fn
  return () => {
    terminated = true;
    clearTimeout(reconnectTimer);
    es?.close();
  };
}

/**
 * Fetch the full ScanResult for a completed scan.
 * @param {string} scanId
 * @returns {ScanResult}
 */
export async function getScanResult(scanId) {
  const res = await fetch(`${BASE}/api/scan/${scanId}`, { credentials: 'include' });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}
