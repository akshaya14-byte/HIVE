import React, { useEffect, useState, useRef } from 'react'
import { db } from '../firebase'
import { ref, onValue, query, limitToLast, orderByChild } from 'firebase/database'

export default function LiveFeed() {
  const [events, setEvents] = useState([])
  const bottomRef = useRef(null)

  useEffect(() => {
    const q = query(ref(db, 'detections'), limitToLast(50))
    const unsub = onValue(q, snap => {
      const data = snap.val() || {}
      const list = Object.entries(data)
        .map(([id, v]) => ({ id, ...v }))
        .sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0))
      setEvents(list)
    })
    return unsub
  }, [])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [events])

  const tagColor = (e) => {
    if (!e.is_attack) return 'var(--accent)'
    if (e.prediction === 'BLOCKED') return 'var(--warn)'
    return 'var(--danger)'
  }

  const tagLabel = (e) => {
    if (!e.is_attack) return e.type === 'url' ? 'LEGIT URL' : 'BENIGN'
    return e.prediction || 'ATTACK'
  }

  return (
    <div style={styles.wrapper}>
      <div style={styles.header}>
        <span style={styles.title}>LIVE FEED</span>
        <span style={styles.count}>{events.length} EVENTS</span>
      </div>
      <div style={styles.feed}>
        {events.length === 0 && (
          <div style={styles.empty}>Waiting for detections...</div>
        )}
        {events.map(e => (
          <div key={e.id} style={styles.row}>
            <span style={{ ...styles.tag, borderColor: tagColor(e), color: tagColor(e) }}>
              {tagLabel(e)}
            </span>
            <span style={styles.ip}>{e.src_ip || e.url || '—'}</span>
            <span style={styles.type}>{e.type === 'url' ? 'URL' : 'TRAFFIC'}</span>
            <span style={styles.score}>
              {e.risk_score != null ? `RISK ${(e.risk_score * 100).toFixed(0)}%` : ''}
            </span>
            <span style={styles.time}>
              {e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : ''}
            </span>
          </div>
        ))}
        <div ref={bottomRef} />
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
    display: 'flex',
    flexDirection: 'column',
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
    fontSize: 13,
    fontWeight: 700,
    letterSpacing: 2,
    color: 'var(--accent)',
  },
  count: {
    fontFamily: 'var(--mono)',
    fontSize: 11,
    color: 'var(--muted)',
  },
  feed: {
    overflowY: 'auto',
    maxHeight: 340,
    padding: '8px 0',
  },
  empty: {
    padding: '40px 20px',
    textAlign: 'center',
    color: 'var(--muted)',
    fontFamily: 'var(--mono)',
    fontSize: 13,
  },
  row: {
    display: 'flex',
    alignItems: 'center',
    gap: 12,
    padding: '8px 20px',
    borderBottom: '1px solid rgba(26,37,64,0.5)',
    fontSize: 13,
    fontFamily: 'var(--mono)',
    transition: 'background 0.15s',
  },
  tag: {
    border: '1px solid',
    borderRadius: 4,
    padding: '2px 8px',
    fontSize: 10,
    letterSpacing: 1,
    minWidth: 100,
    textAlign: 'center',
  },
  ip: {
    color: 'var(--text)',
    flex: 1,
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  type: {
    color: 'var(--muted)',
    fontSize: 11,
    letterSpacing: 1,
    minWidth: 60,
  },
  score: {
    color: 'var(--muted)',
    fontSize: 11,
    minWidth: 70,
    textAlign: 'right',
  },
  time: {
    color: 'var(--muted)',
    fontSize: 11,
    minWidth: 80,
    textAlign: 'right',
  },
}
