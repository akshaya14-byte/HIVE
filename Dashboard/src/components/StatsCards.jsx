import React, { useEffect, useState } from 'react'
import { db } from '../firebase'
import { ref, onValue } from 'firebase/database'

export default function StatsCards() {
  const [stats, setStats] = useState({
    totalScans: 0, totalAttacks: 0,
    blockedIPs: 0, urlScans: 0,
  })
  const [prev, setPrev] = useState({})
  const [flash, setFlash] = useState({})

  useEffect(() => {
    const detRef = ref(db, 'detections')
    const blRef  = ref(db, 'blocklist')

    const unsubDet = onValue(detRef, snap => {
      const data = snap.val() || {}
      const entries = Object.values(data)
      const totalScans   = entries.length
      const totalAttacks = entries.filter(e => e.is_attack).length
      const urlScans     = entries.filter(e => e.type === 'url').length

      setStats(prev => {
        // Flash changed cards
        const changed = {}
        if (totalScans   !== prev.totalScans)   changed.totalScans = true
        if (totalAttacks !== prev.totalAttacks) changed.totalAttacks = true
        if (urlScans     !== prev.urlScans)     changed.urlScans = true
        if (Object.keys(changed).length) {
          setFlash(changed)
          setTimeout(() => setFlash({}), 600)
        }
        return { ...prev, totalScans, totalAttacks, urlScans }
      })
    })

    const unsubBl = onValue(blRef, snap => {
      const data = snap.val() || {}
      const blockedIPs = Object.keys(data).length
      setStats(prev => {
        if (blockedIPs !== prev.blockedIPs) {
          setFlash(f => ({ ...f, blockedIPs: true }))
          setTimeout(() => setFlash(f => ({ ...f, blockedIPs: false })), 600)
        }
        return { ...prev, blockedIPs }
      })
    })

    return () => { unsubDet(); unsubBl() }
  }, [])

  const cards = [
    { key: 'totalScans',   label: 'Total Scans',   value: stats.totalScans,   color: 'accent' },
    { key: 'totalAttacks', label: 'Attacks Found', value: stats.totalAttacks, color: 'danger' },
    { key: 'blockedIPs',   label: 'Blocked IPs',   value: stats.blockedIPs,   color: 'warn'   },
    { key: 'urlScans',     label: 'URL Scans',     value: stats.urlScans,     color: 'accent' },
  ]

  return (
    <div style={styles.grid}>
      {cards.map(c => (
        <div key={c.key} style={{
          ...styles.card,
          boxShadow: flash[c.key] ? `0 0 20px rgba(0,245,196,0.3)` : 'none',
          transition: 'box-shadow 0.3s',
        }}>
          <div style={{ ...styles.bar, background: `var(--${c.color})` }} />
          <div style={styles.label}>{c.label}</div>
          <div style={{ ...styles.value, color: `var(--${c.color})` }}>
            {c.value.toLocaleString()}
          </div>
          <div style={styles.sub}>
            {c.key === 'totalAttacks' && stats.totalScans > 0
              ? `${((stats.totalAttacks / stats.totalScans) * 100).toFixed(1)}% attack rate`
              : c.key === 'blockedIPs' && stats.blockedIPs > 0
              ? 'auto-blocked'
              : 'live count'}
          </div>
        </div>
      ))}
    </div>
  )
}

const styles = {
  grid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(4, 1fr)',
    gap: 16,
  },
  card: {
    background: 'var(--panel)',
    border: '1px solid var(--border)',
    borderRadius: 10,
    padding: '20px 24px',
    position: 'relative',
    overflow: 'hidden',
  },
  bar: {
    position: 'absolute',
    top: 0, left: 0, right: 0,
    height: 2, opacity: 0.7,
  },
  label: {
    fontSize: 11, letterSpacing: 2,
    textTransform: 'uppercase',
    color: 'var(--muted)', marginBottom: 10,
  },
  value: {
    fontFamily: 'var(--mono)',
    fontSize: 38, lineHeight: 1,
  },
  sub: {
    fontSize: 11, color: 'var(--muted)',
    marginTop: 6, fontFamily: 'var(--mono)',
  },
}
