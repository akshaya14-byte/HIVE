import React, { useEffect, useState } from 'react'
import { db } from '../firebase'
import { ref, onValue } from 'firebase/database'
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
} from 'recharts'

const COLORS = ['#ff3c5a', '#00f5c4', '#ffaa00', '#7b6fff', '#ff8c42', '#00b4d8']

export default function AttackChart() {
  const [typeData, setTypeData]     = useState([])
  const [timelineData, setTimeline] = useState([])

  useEffect(() => {
    const unsub = onValue(ref(db, 'detections'), snap => {
      const data = snap.val() || {}
      const entries = Object.values(data)

      // Attack type breakdown
      const counts = {}
      entries.filter(e => e.is_attack).forEach(e => {
        const k = e.prediction || 'UNKNOWN'
        counts[k] = (counts[k] || 0) + 1
      })
      setTypeData(Object.entries(counts).map(([name, value]) => ({ name, value })))

      // Timeline — group by hour
      const hours = {}
      entries.forEach(e => {
        if (!e.timestamp) return
        const h = new Date(e.timestamp).getHours()
        const key = `${h}:00`
        if (!hours[key]) hours[key] = { time: key, attacks: 0, normal: 0 }
        e.is_attack ? hours[key].attacks++ : hours[key].normal++
      })
      setTimeline(Object.values(hours).sort((a,b) => parseInt(a.time) - parseInt(b.time)))
    })
    return unsub
  }, [])

  const CustomTooltip = ({ active, payload }) => {
    if (!active || !payload?.length) return null
    return (
      <div style={styles.tooltip}>
        <div style={{ color: 'var(--accent)', marginBottom: 4 }}>{payload[0]?.name}</div>
        {payload.map(p => (
          <div key={p.name} style={{ color: p.color }}>
            {p.name}: {p.value}
          </div>
        ))}
      </div>
    )
  }

  return (
    <div style={styles.grid}>
      {/* Pie — attack types */}
      <div style={styles.panel}>
        <div style={styles.header}>
          <span style={styles.title}>ATTACK TYPES</span>
        </div>
        <div style={{ padding: '16px 0' }}>
          {typeData.length === 0 ? (
            <div style={styles.empty}>No attacks yet</div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={typeData}
                  cx="50%" cy="50%"
                  innerRadius={55} outerRadius={85}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {typeData.map((_, i) => (
                    <Cell key={i} fill={COLORS[i % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
              </PieChart>
            </ResponsiveContainer>
          )}
          <div style={styles.legend}>
            {typeData.map((d, i) => (
              <div key={d.name} style={styles.legendItem}>
                <span style={{ ...styles.dot, background: COLORS[i % COLORS.length] }} />
                <span style={{ fontSize: 12 }}>{d.name}</span>
                <span style={{ ...styles.legendVal, color: COLORS[i % COLORS.length] }}>
                  {d.value}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Bar — timeline */}
      <div style={styles.panel}>
        <div style={styles.header}>
          <span style={styles.title}>ACTIVITY TIMELINE</span>
        </div>
        <div style={{ padding: '20px 8px 8px' }}>
          {timelineData.length === 0 ? (
            <div style={styles.empty}>No data yet</div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={timelineData} barGap={2}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1a2540" vertical={false} />
                <XAxis dataKey="time" tick={{ fill: '#4a5a7a', fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: '#4a5a7a', fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="attacks" fill="#ff3c5a" radius={[3,3,0,0]} name="Attacks" />
                <Bar dataKey="normal"  fill="#00f5c4" radius={[3,3,0,0]} name="Normal"  opacity={0.5} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>
    </div>
  )
}

const styles = {
  grid: {
    display: 'grid',
    gridTemplateColumns: '1fr 1.4fr',
    gap: 20,
  },
  panel: {
    background: 'var(--panel)',
    border: '1px solid var(--border)',
    borderRadius: 10,
    overflow: 'hidden',
  },
  header: {
    padding: '14px 20px',
    borderBottom: '1px solid var(--border)',
    background: 'rgba(0,245,196,0.03)',
  },
  title: {
    fontSize: 13,
    fontWeight: 700,
    letterSpacing: 2,
    color: 'var(--accent)',
  },
  empty: {
    padding: 40,
    textAlign: 'center',
    color: 'var(--muted)',
    fontFamily: 'var(--mono)',
    fontSize: 13,
  },
  tooltip: {
    background: '#0a0f1e',
    border: '1px solid #1a2540',
    borderRadius: 6,
    padding: '10px 14px',
    fontFamily: 'var(--mono)',
    fontSize: 12,
  },
  legend: {
    padding: '0 20px 8px',
    display: 'flex',
    flexDirection: 'column',
    gap: 6,
  },
  legendItem: {
    display: 'flex',
    alignItems: 'center',
    gap: 8,
    fontSize: 12,
    color: 'var(--text)',
  },
  dot: {
    width: 8, height: 8,
    borderRadius: '50%',
    flexShrink: 0,
  },
  legendVal: {
    marginLeft: 'auto',
    fontFamily: 'var(--mono)',
    fontSize: 12,
  },
}
