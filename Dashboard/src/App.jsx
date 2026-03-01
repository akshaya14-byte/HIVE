import React, { useState, useEffect } from 'react'
import { auth } from './firebase'
import { onAuthStateChanged, signOut } from 'firebase/auth'
import Login from './components/Login'
import StatsCards from './components/StatsCards'
import LiveFeed from './components/LiveFeed'
import AttackChart from './components/AttackChart'
import BlocklistManager from './components/BlocklistManager'
import URLScanner from './components/URLScanner'
import TrafficScanner from './components/TrafficScanner'
import GeoMap from './components/GeoMap'

export default function App() {
  const [user, setUser] = useState(undefined)
  const [time, setTime] = useState(new Date())
  const [tab, setTab]   = useState('overview')

  useEffect(() => {
    const unsub = onAuthStateChanged(auth, u => setUser(u))
    return unsub
  }, [])

  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000)
    return () => clearInterval(t)
  }, [])

  if (user === undefined) {
    return <div style={styles.loading}><div style={styles.loadingText}>INITIALIZING...</div></div>
  }

  if (!user) return <Login />

  const tabs = ['overview', 'threat map', 'traffic scan', 'url scan', 'blocklist']

  return (
    <div style={styles.root}>
      <header style={styles.header}>
        <div style={styles.logo}>
          <div style={styles.logoIcon}>🛡</div>
          <div>
            <div style={styles.logoTitle}>SENTINEL</div>
            <div style={styles.logoSub}>REAL-TIME SECURITY MONITOR</div>
          </div>
        </div>

        <div style={styles.tabs}>
          {tabs.map(t => (
            <button key={t} style={{ ...styles.tab, ...(tab === t ? styles.tabActive : {}) }} onClick={() => setTab(t)}>
              {t.toUpperCase()}
            </button>
          ))}
        </div>

        <div style={styles.headerRight}>
          <div style={styles.userPill}>{user.email}</div>
          <div style={styles.statusPill}><span style={styles.dot} />MONITORING</div>
          <div style={styles.clock}>{time.toLocaleTimeString()}</div>
          <button style={styles.logoutBtn} onClick={() => signOut(auth)}>LOGOUT</button>
        </div>
      </header>

      <main style={styles.main}>
        <StatsCards />
        {tab === 'overview'      && <><LiveFeed /><AttackChart /></>}
        {tab === 'threat map'    && <GeoMap />}
        {tab === 'traffic scan'  && <TrafficScanner />}
        {tab === 'url scan'      && <URLScanner />}
        {tab === 'blocklist'     && <BlocklistManager />}
      </main>
    </div>
  )
}

const styles = {
  root: { minHeight: '100vh', background: '#050810' },
  loading: { minHeight: '100vh', background: '#050810', display: 'flex', alignItems: 'center', justifyContent: 'center' },
  loadingText: { fontFamily: 'monospace', fontSize: 14, color: '#00F5C4', letterSpacing: 4 },
  header: {
    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
    padding: '16px 32px', borderBottom: '1px solid #1a2540',
    background: 'linear-gradient(90deg, #050810 0%, #0a1530 50%, #050810 100%)',
    position: 'sticky', top: 0, zIndex: 100,
  },
  logo: { display: 'flex', alignItems: 'center', gap: 14 },
  logoIcon: { width: 42, height: 42, border: '2px solid #00F5C4', borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 18, boxShadow: '0 0 16px rgba(0,245,196,0.3)' },
  logoTitle: { fontSize: 20, fontWeight: 700, letterSpacing: 4, color: '#00F5C4' },
  logoSub: { fontFamily: 'monospace', fontSize: 10, color: '#4a6080', letterSpacing: 2 },
  tabs: { display: 'flex', gap: 4 },
  tab: { background: 'transparent', border: '1px solid transparent', borderRadius: 6, color: '#4a6080', padding: '7px 16px', fontSize: 11, fontWeight: 700, letterSpacing: 2, cursor: 'pointer', transition: 'all 0.2s' },
  tabActive: { border: '1px solid #00F5C4', color: '#00F5C4', background: 'rgba(0,245,196,0.06)' },
  headerRight: { display: 'flex', alignItems: 'center', gap: 16 },
  userPill: { fontFamily: 'monospace', fontSize: 11, color: '#4a6080', letterSpacing: 1 },
  statusPill: { display: 'flex', alignItems: 'center', gap: 8, padding: '6px 16px', border: '1px solid #00F5C4', borderRadius: 20, fontFamily: 'monospace', fontSize: 11, color: '#00F5C4', background: 'rgba(0,245,196,0.05)', letterSpacing: 1 },
  dot: { width: 7, height: 7, borderRadius: '50%', background: '#00F5C4', boxShadow: '0 0 6px #00F5C4' },
  clock: { fontFamily: 'monospace', fontSize: 13, color: '#4a6080', letterSpacing: 1 },
  logoutBtn: { background: 'transparent', border: '1px solid #4a6080', borderRadius: 6, color: '#4a6080', padding: '6px 14px', fontSize: 11, fontWeight: 700, letterSpacing: 2, cursor: 'pointer' },
  main: { padding: '28px 32px', display: 'flex', flexDirection: 'column', gap: 24 },
}
