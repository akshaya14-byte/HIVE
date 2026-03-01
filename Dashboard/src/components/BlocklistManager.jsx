import React, { useEffect, useState } from 'react'
import { db } from '../firebase'
import { ref, onValue, remove } from 'firebase/database'

export default function BlocklistManager() {
  const [blocked, setBlocked] = useState([])

  useEffect(() => {
    const unsub = onValue(ref(db, 'blocklist'), snap => {
      const data = snap.val() || {}
      const list = Object.entries(data).map(([key, v]) => ({ key, ...v }))
      setBlocked(list.sort((a, b) => (b.blocked_at || 0) - (a.blocked_at || 0)))
    })
    return unsub
  }, [])

  const unblock = async (key, ip) => {
    if (!window.confirm(`Unblock ${ip}?`)) return
    await remove(ref(db, `blocklist/${key}`))

    // Also call FastAPI to unblock
    try {
      await fetch(`http://localhost:8000/blocklist/${encodeURIComponent(ip)}`, {
        method: 'DELETE'
      })
    } catch (e) {
      console.warn('FastAPI unblock failed (server may be down)', e)
    }
  }

  const tagColor = (reason) => {
    if (!reason) return 'var(--danger)'
    if (reason.includes('SYN'))  return '#ff3c5a'
    if (reason.includes('UDP'))  return '#ffaa00'
    if (reason.includes('HTTP')) return '#7b6fff'
    if (reason.includes('ICMP')) return '#ff8c42'
    if (reason.includes('PHISHING')) return '#00b4d8'
    return 'var(--danger)'
  }

  return (
    <div style={styles.wrapper}>
      <div style={styles.header}>
        <span style={styles.title}>BLOCKLIST</span>
        <span style={styles.count}>{blocked.length} IPs BLOCKED</span>
      </div>

      {blocked.length === 0 ? (
        <div style={styles.empty}>No IPs blocked yet</div>
      ) : (
        <div style={styles.list}>
          {blocked.map(b => (
            <div key={b.key} style={styles.row}>
              <div style={styles.left}>
                <div style={styles.ip}>{b.ip || b.key}</div>
                <div style={styles.meta}>
                  <span style={{ ...styles.badge, borderColor: tagColor(b.reason), color: tagColor(b.reason) }}>
                    {b.reason || 'ATTACK'}
                  </span>
                  <span style={styles.metaText}>
                    {b.blocked_at ? new Date(b.blocked_at).toLocaleString() : ''}
                  </span>
                  {b.risk_score && (
                    <span style={styles.metaText}>
                      RISK {(b.risk_score * 100).toFixed(0)}%
                    </span>
                  )}
                </div>
              </div>
              <button
                style={styles.unblockBtn}
                onClick={() => unblock(b.key, b.ip || b.key)}
              >
                UNBLOCK
              </button>
            </div>
          ))}
        </div>
      )}
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
    background: 'rgba(255,60,90,0.04)',
  },
  title: {
    fontSize: 13,
    fontWeight: 700,
    letterSpacing: 2,
    color: 'var(--danger)',
  },
  count: {
    fontFamily: 'var(--mono)',
    fontSize: 11,
    color: 'var(--muted)',
  },
  empty: {
    padding: 40,
    textAlign: 'center',
    color: 'var(--muted)',
    fontFamily: 'var(--mono)',
    fontSize: 13,
  },
  list: {
    overflowY: 'auto',
    maxHeight: 320,
  },
  row: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '12px 20px',
    borderBottom: '1px solid var(--border)',
  },
  left: { flex: 1 },
  ip: {
    fontFamily: 'var(--mono)',
    fontSize: 15,
    color: 'var(--danger)',
    marginBottom: 4,
  },
  meta: {
    display: 'flex',
    alignItems: 'center',
    gap: 10,
  },
  badge: {
    border: '1px solid',
    borderRadius: 3,
    padding: '1px 6px',
    fontSize: 10,
    letterSpacing: 1,
  },
  metaText: {
    fontSize: 11,
    color: 'var(--muted)',
    fontFamily: 'var(--mono)',
  },
  unblockBtn: {
    background: 'transparent',
    border: '1px solid var(--muted)',
    borderRadius: 4,
    color: 'var(--muted)',
    fontSize: 11,
    padding: '4px 10px',
    cursor: 'pointer',
    fontFamily: 'var(--ui)',
    letterSpacing: 1,
    transition: 'all 0.2s',
  },
}
