import { useEffect, useRef } from 'react';
import styles from './HeroSection.module.css';

function MatrixRain() {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let animId;

    const resize = () => {
      canvas.width = canvas.offsetWidth;
      canvas.height = canvas.offsetHeight;
    };
    resize();
    window.addEventListener('resize', resize);

    const chars = '0123456789ABCDEF<>{}[]|/\\RECON EXPLOIT PATCH VERIFY';
    const fontSize = 13;
    const cols = Math.floor(canvas.width / fontSize);
    const drops = Array(cols).fill(0).map(() => Math.random() * -100);

    const draw = () => {
      ctx.fillStyle = 'rgba(6, 6, 11, 0.055)';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.font = `${fontSize}px 'Share Tech Mono', monospace`;

      for (let i = 0; i < drops.length; i++) {
        const char = chars[Math.floor(Math.random() * chars.length)];
        const progress = drops[i] / (canvas.height / fontSize);
        const alpha = Math.max(0.05, 0.6 - progress * 0.5);
        const isGreen = Math.random() > 0.9;
        ctx.fillStyle = isGreen
          ? `rgba(0, 255, 157, ${alpha})`
          : `rgba(0, 180, 255, ${alpha * 0.4})`;
        ctx.fillText(char, i * fontSize, drops[i] * fontSize);

        if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
          drops[i] = 0;
        }
        drops[i] += 0.5;
      }
    };

    const interval = setInterval(draw, 40);
    return () => {
      clearInterval(interval);
      cancelAnimationFrame(animId);
      window.removeEventListener('resize', resize);
    };
  }, []);

  return <canvas ref={canvasRef} className={styles.matrix} />;
}

export default function HeroSection({ onScrollToDashboard }) {
  return (
    <section className={styles.hero}>
      <MatrixRain />

      <div className={styles.grid}></div>

      <div className={styles.content}>
        <div className={styles.tag}>
          <span className={styles.tagDot}></span>
          PS3 AUTONOMY TRACK — MULTI-AGENT SECURITY
        </div>

        <h4 className={styles.title}>
          <span className={styles.titleLine1} data-text="AUTONOMOUS">AUTONOMOUS EXPLOIT</span>
          <span className={styles.titleLine2} data-text="SECURITY">GENERATION & INTELLIGENT</span>
          <span className={styles.titleAccent} data-text="ENGINE">SECURITY</span>
        </h4>

        <p className={styles.subtitle}>
          A self-directed AI system that finds vulnerabilities, proves they're real,
          <br />and generates the patch — without a human writing a single line of security code.
        </p>

        <div className={styles.stats}>
          <div className={styles.stat}>
            <span className={styles.statValue}>4</span>
            <span className={styles.statLabel}>Autonomous Agents</span>
          </div>
          <div className={styles.statDivider}></div>
          <div className={styles.stat}>
            <span className={styles.statValue}>0</span>
            <span className={styles.statLabel}>Human Interventions</span>
          </div>
          <div className={styles.statDivider}></div>
          <div className={styles.stat}>
            <span className={styles.statValue}>∞</span>
            <span className={styles.statLabel}>Petri Net States</span>
          </div>
          <div className={styles.statDivider}></div>
          <div className={styles.stat}>
            <span className={styles.statValue}>24s</span>
            <span className={styles.statLabel}>Avg Detection Time</span>
          </div>
        </div>

        <div className={styles.ctas}>
          <button className={styles.ctaPrimary} onClick={onScrollToDashboard}>
            <span>Launch Mission Control</span>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" width="18" height="18">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 7l5 5-5 5M6 12h12"/>
            </svg>
          </button>
        </div>

        <div className={styles.techStack}>
          {['FastAPI', 'asyncio + SSE', 'SQLite WAL', 'Colored Petri Net', 'AST Sandbox', 'GPT-4o', 'Omium SDK', 'Pydantic v2'].map(t => (
            <span key={t} className={styles.tech}>{t}</span>
          ))}
        </div>
      </div>

      <button
  className={styles.scrollIndicator}
  onClick={() => {
    if (onScrollToDashboard) {
      onScrollToDashboard();
    } else {
      window.scrollTo({
        top: window.innerHeight,
        behavior: 'smooth',
      });
    }
  }}
  aria-label="Scroll to dashboard"
>
  <span>SCROLL TO DASHBOARD</span>
  <div className={styles.scrollArrow}></div>
</button>
    </section>
  );
}
