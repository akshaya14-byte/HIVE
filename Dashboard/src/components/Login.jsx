import React, { useState } from 'react'
import { auth } from '../firebase'
import { signInWithEmailAndPassword } from 'firebase/auth'

export default function Login() {
  const [email, setEmail]       = useState('')
  const [password, setPassword] = useState('')
  const [error, setError]       = useState('')
  const [loading, setLoading]   = useState(false)

  const login = async () => {
    if (!email || !password) return
    setLoading(true)
    setError('')
    try {
      await signInWithEmailAndPassword(auth, email, password)
    } catch (e) {
      setError('Invalid email or password.')
    }
    setLoading(false)
  }

  return (
    <div style={styles.root}>
      {/* Background grid */}
      <div style={styles.grid} />

      <div style={styles.card}>
        {/* Logo */}
        <div style={styles.logo}>
          <div style={styles.logoIcon}>🛡</div>
          <div style={styles.logoTitle}>SENTINEL</div>
          <div style={styles.logoSub}>SECURITY MONITORING PLATFORM</div>
        </div>

        {/* Form */}
        <div style={styles.form}>
          <div style={styles.field}>
            <label style={styles.label}>EMAIL</label>
            <input
              style={styles.input}
              type="email"
              placeholder="you@example.com"
              value={email}
              onChange={e => setEmail(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && login()}
              autoFocus
            />
          </div>

          <div style={styles.field}>
            <label style={styles.label}>PASSWORD</label>
            <input
              style={styles.input}
              type="password"
              placeholder="••••••••"
              value={password}
              onChange={e => setPassword(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && login()}
            />
          </div>

          {error && <div style={styles.error}>{error}</div>}

          <button
            style={{ ...styles.btn, ...(loading ? styles.btnLoading : {}) }}
            onClick={login}
            disabled={loading}
          >
            {loading ? 'AUTHENTICATING...' : 'LOGIN'}
          </button>
        </div>

        <div style={styles.footer}>
          Protected by Firebase Authentication
        </div>
      </div>
    </div>
  )
}

const styles = {
  root: {
    minHeight: '100vh',
    background: 'var(--bg)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    position: 'relative',
    overflow: 'hidden',
  },
  grid: {
    position: 'absolute', inset: 0,
    backgroundImage: `
      linear-gradient(rgba(0,245,196,0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,245,196,0.03) 1px, transparent 1px)
    `,
    backgroundSize: '40px 40px',
    pointerEvents: 'none',
  },
  card: {
    background: 'var(--panel)',
    border: '1px solid var(--border)',
    borderRadius: 16,
    padding: '48px 40px',
    width: 400,
    position: 'relative',
    boxShadow: '0 0 60px rgba(0,245,196,0.08)',
  },
  logo: {
    display: 'flex', flexDirection: 'column',
    alignItems: 'center', marginBottom: 40,
  },
  logoIcon: {
    width: 56, height: 56,
    border: '2px solid var(--accent)',
    borderRadius: 12,
    display: 'flex', alignItems: 'center', justifyContent: 'center',
    fontSize: 24, marginBottom: 16,
    boxShadow: '0 0 24px rgba(0,245,196,0.3)',
  },
  logoTitle: {
    fontSize: 28, fontWeight: 700,
    letterSpacing: 6, color: 'var(--accent)',
    marginBottom: 6,
  },
  logoSub: {
    fontFamily: 'var(--mono)', fontSize: 10,
    color: 'var(--muted)', letterSpacing: 2,
  },
  form: { display: 'flex', flexDirection: 'column', gap: 16 },
  field: {},
  label: {
    display: 'block', fontSize: 10,
    letterSpacing: 2, color: 'var(--muted)',
    textTransform: 'uppercase', marginBottom: 8,
  },
  input: {
    width: '100%', background: '#070c18',
    border: '1px solid var(--border)',
    borderRadius: 8, padding: '12px 16px',
    color: 'var(--text)', fontFamily: 'var(--mono)',
    fontSize: 14, outline: 'none',
    transition: 'border-color 0.2s',
    boxSizing: 'border-box',
  },
  error: {
    padding: '10px 14px', borderRadius: 6,
    background: 'rgba(255,60,90,0.08)',
    border: '1px solid var(--danger)',
    color: 'var(--danger)',
    fontFamily: 'var(--mono)', fontSize: 12,
  },
  btn: {
    width: '100%', padding: 14,
    background: 'transparent',
    border: '1px solid var(--accent)',
    borderRadius: 8, color: 'var(--accent)',
    fontFamily: 'var(--ui)', fontSize: 15,
    fontWeight: 700, letterSpacing: 4,
    cursor: 'pointer', marginTop: 8,
    transition: 'all 0.2s',
  },
  btnLoading: { opacity: 0.6, cursor: 'not-allowed' },
  footer: {
    marginTop: 32, textAlign: 'center',
    fontFamily: 'var(--mono)', fontSize: 11,
    color: 'var(--muted)',
  },
}
