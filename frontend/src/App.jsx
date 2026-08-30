import { useRef } from 'react';
import NavBar from './components/NavBar.jsx';
import HeroSection from './components/HeroSection.jsx';
import RepoInput from './components/RepoInput.jsx';
import GitHubConnect from './components/GitHubConnect.jsx';
import Terminal from './components/Terminal.jsx';
import PetriNet from './components/PetriNet.jsx';
import DiffViewer from './components/DiffViewer.jsx';
import ScanComplete from './components/ScanComplete.jsx';
import Architecture from './components/Architecture.jsx';
import Footer from './components/Footer.jsx';
import { useAuth } from './hooks/useAuth.js';
import { useScan } from './hooks/useScan.js';
import styles from './App.module.css';

export default function App() {
  const dashboardRef = useRef(null);
  const { user, loading: authLoading, login, logout } = useAuth();
  const {
    phase, scanId, petriStage, logs, progress,
    result, error, retryInfo, repoUrl, start, reset,
  } = useScan();

  const isAuthenticated = !!user;
  const isScanning = phase === 'scanning';
  const isComplete = phase === 'complete';
  const isFailed = phase === 'failed';
  const patchVisible = (isScanning && petriStage === 'patch') || isComplete || isFailed;

  // Display repo URL: from result (best), from scan hook (fallback)
  const displayRepoUrl = result?.repo_url || repoUrl || null;

  const handleStartScan = async (url) => {
    await start(url);
  };

  const scrollToDashboard = () => {
    dashboardRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  return (
    <div className={styles.app}>
      <NavBar user={user} onLogout={logout} />
      <HeroSection onScrollToDashboard={scrollToDashboard} />

      <section className={styles.dashboard} id="dashboard" ref={dashboardRef}>
        <div className={styles.dashInner}>

          {/* Header */}
          <div className={styles.dashHeader}>
            <div className={styles.dashTitleGroup}>
              <div className={styles.dashLive}>
                <span className={styles.liveDot}></span>
                MISSION CONTROL
              </div>
              <h2 className={styles.dashTitle}>Autonomous Red-Team Engine</h2>
              <p className={styles.dashSub}>
                Connect GitHub, submit a repo, and watch A.E.G.I.S. autonomously
                clone, exploit, verify, and patch — zero human intervention
              </p>
            </div>
            <a href="https://github.com/DevOpsDreamer/ANVIL" target="_blank"
              rel="noopener noreferrer" className={styles.dashGithubBtn}>
              <svg viewBox="0 0 24 24" fill="currentColor" width="16" height="16">
                <path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/>
              </svg>
              A.E.G.I.S. Engine on GitHub
            </a>
          </div>

          {/* ── Step 1: GitHub Auth ── */}
          <div className={styles.stepRow}>
            <div className={styles.stepBadge}
              style={{'--sc': isAuthenticated ? '#00ff9d' : '#ff9f1c'}}>
              <span className={styles.stepBadgeNum}>01</span>
              <span className={styles.stepBadgeLabel}>
                {isAuthenticated ? 'Authenticated' : 'Connect GitHub'}
              </span>
            </div>
            <div className={styles.stepContent}>
              <GitHubConnect
                user={user} loading={authLoading}
                onLogin={login} onLogout={logout}
              />
            </div>
          </div>

          {/* ── Step 2: Target Repo + Start Scan ── */}
          <div className={styles.stepRow}>
            <div className={styles.stepBadge}
              style={{'--sc': (isScanning || isComplete) ? '#00ff9d' : '#00b4ff'}}>
              <span className={styles.stepBadgeNum}>02</span>
              <span className={styles.stepBadgeLabel}>
                {isScanning ? 'Scanning' : isComplete ? 'Scan Done' : 'Target Repo'}
              </span>
            </div>
            <div className={styles.stepContent}>
              {/* Show repo input only when idle/failed */}
              {(phase === 'idle' || isFailed) && (
                <RepoInput
                  onStartScan={handleStartScan}
                  disabled={!isAuthenticated}
                  disabledReason={!isAuthenticated ? 'Connect GitHub first (Step 1)' : null}
                />
              )}
              {(isScanning || isComplete) && (
                <div className={styles.scanningBanner}>
                  <span className={styles.scanningDot}
                    style={{background: isComplete ? '#00ff9d' : '#ff9f1c'}}></span>
                  <span className={styles.scanningRepo}>{displayRepoUrl || '…'}</span>
                  <span className={styles.scanningStatus}>
                    {isComplete ? '✓ Scan Complete' : `${progress}%`}
                  </span>
                  {/* Progress bar */}
                  {!isComplete && (
                    <div className={styles.progressBar}>
                      <div className={styles.progressFill} style={{width:`${progress}%`}}></div>
                    </div>
                  )}
                </div>
              )}
              {isFailed && (
                <div className={styles.errorBanner}>
                  <span>✗ Scan failed: {error}</span>
                </div>
              )}
            </div>
          </div>

          {/* ── Step 3: Petri Net ── */}
          <div className={styles.stepRow}>
            <div className={styles.stepBadge} style={{'--sc': '#00ff9d'}}>
              <span className={styles.stepBadgeNum}>03</span>
              <span className={styles.stepBadgeLabel}>State Machine</span>
            </div>
            <div className={styles.stepContent}>
              <PetriNet currentStage={petriStage} />
            </div>
          </div>

          {/* ── Step 4: Terminal + Diff ── */}
          <div className={styles.stepRow}>
            <div className={styles.stepBadge} style={{'--sc': '#ff9f1c'}}>
              <span className={styles.stepBadgeNum}>04</span>
              <span className={styles.stepBadgeLabel}>Execute & Patch</span>
            </div>
            <div className={styles.stepContent}>
              <div className={styles.bottomGrid}>
                <div className={styles.terminalCol}>
                  <div className={styles.panelLabel}>
                    <span className={styles.labelDot} style={{background:'#00ff9d'}}></span>
                    LIVE AGENT TERMINAL
                    <span className={styles.labelHint}>— real-time SSE from backend</span>
                  </div>
                  <Terminal
                    logs={logs} phase={phase}
                    repoUrl={displayRepoUrl} retryInfo={retryInfo}
                    scanId={scanId}
                  />
                </div>
                <div className={styles.diffCol}>
                  <div className={styles.panelLabel}>
                    <span className={styles.labelDot} style={{background:'#00b4ff'}}></span>
                    CODE DIFF VIEWER
                    <span className={styles.labelHint}>— AI-generated patch from backend</span>
                  </div>
                  <DiffViewer patch={result?.patch} visible={patchVisible} />
                </div>
              </div>
            </div>
          </div>

          {/* ── Step 5: Final Result Card ── */}
          {isComplete && result && (
            <div className={styles.stepRow}>
              <div className={styles.stepBadge} style={{'--sc': '#00ff9d'}}>
                <span className={styles.stepBadgeNum}>05</span>
                <span className={styles.stepBadgeLabel}>Results</span>
              </div>
              <div className={styles.stepContent}>
                <ScanComplete result={result} scanId={scanId} onReset={reset} />
              </div>
            </div>
          )}

          {/* ── How it works ── */}
          <div className={styles.steps} id="how-it-works">
            <div className={styles.stepsHeader}>HOW IT WORKS</div>
            <div className={styles.stepsGrid}>
              {[
                { n:'01', color:'#00b4ff', title:'GitHub OAuth',
                  desc:'Authenticate with GitHub so A.E.G.I.S. can clone your repo and open a Pull Request with the fix using the repo scope.' },
                { n:'02', color:'#00ff9d', title:'Webhook Trigger',
                  desc:'POST /api/scan starts the pipeline. FastAPI validates the Pydantic schema, returns HTTP 202 instantly, and runs the scan as an async background task.' },
                { n:'03', color:'#00ff9d', title:'Reconnaissance',
                  desc:'Agent 1 reads source files via GPT-4o source analysis, identifies vulnerable endpoints. Strict ReconOutput JSON — no raw strings.' },
                { n:'04', color:'#ff9f1c', title:'Exploitation',
                  desc:'Agent 2 generates a targeted Python payload, executes it in an AST-validated subprocess sandbox with 5s timeout.' },
                { n:'05', color:'#ffe34d', title:'Verification',
                  desc:'The deterministic Verifier checks sandbox stdout for the exact flag. If it fails, the system retries the Exploiter (max 3×).' },
                { n:'06', color:'#00ff9d', title:'Patch + PR',
                  desc:'Agent 3 generates a fix with GPT-4o, statically validates it, opens a fix/ branch, and creates a GitHub Pull Request — all automatically.' },
              ].map((step) => (
                <div key={step.n} className={styles.step} style={{'--c': step.color}}>
                  <span className={styles.stepNum}>{step.n}</span>
                  <h3 className={styles.stepTitle}>{step.title}</h3>
                  <p className={styles.stepDesc}>{step.desc}</p>
                </div>
              ))}
            </div>
          </div>

        </div>
      </section>

      <Architecture />
      <Footer />
    </div>
  );
}
