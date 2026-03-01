import React, { useState } from 'react'

export default function URLScanner() {
  const [url, setUrl] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)

  const scan = async () => {
    if (!url.trim()) return
    setLoading(true)
    setResult(null)
    try {
      const res = await fetch('http://localhost:8001/scan_url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, src_ip: 'dashboard-user' }),
      })
      const data = await res.json()
      setResult(data)
    } catch (e) {
      setResult({ error: 'Could not reach URL scanner. Is it running on port 8001?' })
    }
    setLoading(false)
  }

  const isPhishing = result?.prediction === 'PHISHING'
  const color = !result ? 'var(--accent)'
    : isPhishing ? 'var(--danger)' : 'var(--accent)'

  return (
    <div style={styles.wrapper}>
      <div style={styles.header}>
        <span style={styles.title}>URL PHISHING SCANNER</span>
        <span style={styles.sub}>Powered by ML + Rule Engine</span>
      </div>

      <div style={styles.body}>
        <div style={styles.inputRow}>
          <input
            style={styles.input}
            placeholder="https://example.com/login?verify=true"
            value={url}
            onChange={e => setUrl(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && scan()}
          />
          <button
            style={{ ...styles.btn, ...(loading ? styles.btnScanning : {}) }}
            onClick={scan}
            disabled={loading}
          >
            {loading ? 'SCANNING...' : 'SCAN'}
          </button>
        </div>

        {result && !result.error && (
          <div style={{ ...styles.result, borderColor: color, background: isPhishing ? 'rgba(255,60,90,0.05)' : 'rgba(0,245,196,0.04)' }}>
            <div style={{ ...styles.verdict, color }}>
              {isPhishing ? '⚠ PHISHING DETECTED' : '✓ LEGITIMATE'}
            </div>
            <div style={styles.url}>{result.url}</div>
            <div style={styles.scores}>
              <div style={styles.scoreItem}>
                <span style={styles.scoreLabel}>RISK SCORE</span>
                <span style={{ ...styles.scoreVal, color }}>{(result.risk_score * 100).toFixed(0)}%</span>
              </div>
              <div style={styles.scoreItem}>
                <span style={styles.scoreLabel}>ML SCORE</span>
                <span style={styles.scoreVal}>{(result.ml_score * 100).toFixed(0)}%</span>
              </div>
              <div style={styles.scoreItem}>
                <span style={styles.scoreLabel}>RULE SCORE</span>
                <span style={styles.scoreVal}>{(result.rule_score * 100).toFixed(0)}%</span>
              </div>
            </div>
          </div>
        )}

        {result?.error && (
          <div style={styles.error}>{result.error}</div>
        )}

        {/* Quick test URLs */}
        <div style={styles.quickTests}>
          <span style={styles.quickLabel}>QUICK TEST:</span>
          {[
            'http://paypa1-secure.tk/login',
            'https://www.google.com',
            'http://free-iphone.xyz/claim',
          ].map(u => (
            <button key={u} style={styles.quickBtn} onClick={() => { setUrl(u); setResult(null) }}>
              {u.length > 35 ? u.slice(0, 35) + '...' : u}
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}

const styles = {
  wrapper: {
    background: 'var(--panel)',
    border: '1px solid var(--border)',
    borderRadius: 10,
    overflow: 'hidden',
  },
  header: {
    padding: '14px 20px',
    borderBottom: '1px solid var(--border)',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    background: 'rgba(0,245,196,0.03)',
  },
  title: {
    fontSize: 13, fontWeight: 700,
    letterSpacing: 2, color: 'var(--accent)',
  },
  sub: {
    fontSize: 11, color: 'var(--muted)',
    fontFamily: 'var(--mono)',
  },
  body: { padding: 20 },
  inputRow: {
    display: 'flex', gap: 10, marginBottom: 16,
  },
  input: {
    flex: 1,
    background: '#070c18',
    border: '1px solid var(--border)',
    borderRadius: 6,
    padding: '10px 14px',
    color: 'var(--text)',
    fontFamily: 'var(--mono)',
    fontSize: 13,
    outline: 'none',
  },
  btn: {
    background: 'transparent',
    border: '1px solid var(--accent)',
    borderRadius: 6,
    color: 'var(--accent)',
    padding: '10px 24px',
    fontFamily: 'var(--ui)',
    fontSize: 13,
    fontWeight: 700,
    letterSpacing: 2,
    cursor: 'pointer',
    whiteSpace: 'nowrap',
  },
  btnScanning: {
    borderColor: 'var(--warn)',
    color: 'var(--warn)',
    opacity: 0.7,
  },
  result: {
    border: '1px solid',
    borderRadius: 8,
    padding: 16,
    marginBottom: 16,
  },
  verdict: {
    fontSize: 18, fontWeight: 700,
    letterSpacing: 2, marginBottom: 6,
  },
  url: {
    fontFamily: 'var(--mono)', fontSize: 12,
    color: 'var(--muted)', marginBottom: 14,
    wordBreak: 'break-all',
  },
  scores: {
    display: 'flex', gap: 24,
  },
  scoreItem: {
    display: 'flex', flexDirection: 'column', gap: 4,
  },
  scoreLabel: {
    fontSize: 10, letterSpacing: 1.5,
    color: 'var(--muted)', textTransform: 'uppercase',
  },
  scoreVal: {
    fontFamily: 'var(--mono)', fontSize: 22,
    color: 'var(--text)',
  },
  error: {
    padding: 12, borderRadius: 6,
    background: 'rgba(255,60,90,0.08)',
    border: '1px solid var(--danger)',
    color: 'var(--danger)',
    fontFamily: 'var(--mono)', fontSize: 12,
    marginBottom: 16,
  },
  quickTests: {
    display: 'flex', alignItems: 'center',
    gap: 8, flexWrap: 'wrap',
  },
  quickLabel: {
    fontSize: 10, letterSpacing: 1.5,
    color: 'var(--muted)',
  },
  quickBtn: {
    background: 'transparent',
    border: '1px solid var(--border)',
    borderRadius: 4,
    color: 'var(--muted)',
    fontSize: 11,
    padding: '4px 10px',
    cursor: 'pointer',
    fontFamily: 'var(--mono)',
    transition: 'all 0.2s',
  },
}
