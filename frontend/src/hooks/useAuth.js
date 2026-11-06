import { useState, useEffect, useCallback } from 'react';
import { getMe, loginWithGitHub, logout as apiLogout } from '../api/client.js';

/** If the auth check takes longer than this, the backend is cold-starting. */
const SLOW_MS = 3500;

/**
 * Manages GitHub OAuth state.
 * Returns { user, loading, slow, authError, login, logout, clearAuthError }
 */
export function useAuth() {
  const [user, setUser] = useState(null);         // null = unauthenticated
  const [loading, setLoading] = useState(true);   // checking auth on mount
  const [slow, setSlow] = useState(false);        // backend waking up
  const [authError, setAuthError] = useState(null);

  useEffect(() => {
    // The OAuth callback bounces back with ?auth_error=... when the user
    // denies access or GitHub reports a problem. Surface it once, then strip
    // it from the URL so a refresh doesn't show it again.
    const params = new URLSearchParams(window.location.search);
    const err = params.get('auth_error');
    if (err) {
      const desc = params.get('auth_error_description');
      setAuthError(err === 'access_denied'
        ? 'GitHub authorization was cancelled.'
        : `GitHub sign-in failed: ${desc || err}`);
      params.delete('auth_error');
      params.delete('auth_error_description');
      const qs = params.toString();
      window.history.replaceState(null, '', window.location.pathname + (qs ? `?${qs}` : '') + window.location.hash);
    }

    let done = false;
    const timer = setTimeout(() => { if (!done) setSlow(true); }, SLOW_MS);
    getMe().then(u => {
      done = true;
      clearTimeout(timer);
      setUser(u);
      setSlow(false);
      setLoading(false);
    });
    return () => clearTimeout(timer);
  }, []);

  const login = useCallback(() => loginWithGitHub(), []);

  const logout = useCallback(async () => {
    await apiLogout().catch(() => {});
    setUser(null);
  }, []);

  const clearAuthError = useCallback(() => setAuthError(null), []);

  return { user, loading, slow, authError, login, logout, clearAuthError };
}
