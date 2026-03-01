import React, { useState, useEffect } from 'react'

const PRESETS = {
  'SYN Flood':  { 'Flow Packets/s': 85000, 'Flow Bytes/s': 5440000, 'Min Packet Length': 64, 'Max Packet Length': 64, 'SYN Flag Count': 1, 'ACK Flag Count': 0, 'FIN Flag Count': 0, 'RST Flag Count': 0, 'PSH Flag Count': 0, 'Flow Duration': 50, 'Total Fwd Packets': 900, 'Total Backward Packets': 0, 'Destination Port': 80, 'Flow IAT Mean': 10, 'Flow IAT Std': 2, 'Flow IAT Max': 15, 'Fwd Packets/s': 85000, 'Bwd Packets/s': 0, 'Packet Length Mean': 64, 'Packet Length Std': 0, 'Average Packet Size': 64, 'Init_Win_bytes_forward': 0, 'Init_Win_bytes_backward': 0, 'act_data_pkt_fwd': 0, 'Active Mean': 0, 'Idle Mean': 0 },
  'UDP Flood':  { 'Flow Packets/s': 60000, 'Flow Bytes/s': 84000000, 'Min Packet Length': 1400, 'Max Packet Length': 1400, 'SYN Flag Count': 0, 'ACK Flag Count': 0, 'FIN Flag Count': 0, 'RST Flag Count': 0, 'PSH Flag Count': 0, 'Flow Duration': 100, 'Total Fwd Packets': 600, 'Total Backward Packets': 0, 'Destination Port': 53, 'Flow IAT Mean': 5, 'Flow IAT Std': 1, 'Flow IAT Max': 10, 'Fwd Packets/s': 60000, 'Bwd Packets/s': 0, 'Packet Length Mean': 1400, 'Packet Length Std': 0, 'Average Packet Size': 1400, 'Init_Win_bytes_forward': 0, 'Init_Win_bytes_backward': 0, 'act_data_pkt_fwd': 0, 'Active Mean': 0, 'Idle Mean': 0 },
  'HTTP Flood': { 'Flow Packets/s': 3000, 'Flow Bytes/s': 2400000, 'Min Packet Length': 200, 'Max Packet Length': 800, 'SYN Flag Count': 0, 'ACK Flag Count': 1, 'FIN Flag Count': 0, 'RST Flag Count': 0, 'PSH Flag Count': 1, 'Flow Duration': 2000, 'Total Fwd Packets': 300, 'Total Backward Packets': 200, 'Destination Port': 80, 'Flow IAT Mean': 50, 'Flow IAT Std': 10, 'Flow IAT Max': 100, 'Fwd Packets/s': 3000, 'Bwd Packets/s': 2000, 'Packet Length Mean': 500, 'Packet Length Std': 150, 'Average Packet Size': 500, 'Init_Win_bytes_forward': 65535, 'Init_Win_bytes_backward': 65535, 'act_data_pkt_fwd': 300, 'Active Mean': 0, 'Idle Mean': 0 },
  'Normal':     { 'Flow Packets/s': 50, 'Flow Bytes/s': 40000, 'Min Packet Length': 200, 'Max Packet Length': 800, 'SYN Flag Count': 0, 'ACK Flag Count': 1, 'FIN Flag Count': 0, 'RST Flag Count': 0, 'PSH Flag Count': 0, 'Flow Duration': 10000, 'Total Fwd Packets': 20, 'Total Backward Packets': 18, 'Destination Port': 443, 'Flow IAT Mean': 200, 'Flow IAT Std': 50, 'Flow IAT Max': 500, 'Fwd Packets/s': 25, 'Bwd Packets/s': 25, 'Packet Length Mean': 400, 'Packet Length Std': 150, 'Average Packet Size': 400, 'Init_Win_bytes_forward': 65535, 'Init_Win_bytes_backward': 65535, 'act_data_pkt_fwd': 15, 'Active Mean': 0, 'Idle Mean': 0 },
}

const INTENSITIES = {
  Low:    0.5,
  Medium: 1.0,
  High:   2.0,
}


export default function TrafficScanner() {
  const [srcIP, setSrcIP]         = useState('192.168.1.1')
  const [preset, setPreset]       = useState('SYN Flood')
  const [intensity, setIntensity] = useState('High')
  const [result, setResult]       = useState(null)
  const [loading, setLoading]     = useState(false)
  const [alerts, setAlerts] = useState([])
  useEffect(() => {

  const fetchAlerts = async () => {
    try {
      const res = await fetch('http://localhost:8000/alerts')
      const data = await res.json()
      setAlerts(data)
    } catch (err) {
      console.log('Alert fetch failed')
    }
  }

  fetchAlerts()

  const interval = setInterval(fetchAlerts, 3000)

  return () => clearInterval(interval)

}, [])

  const scan = async () => {
    setLoading(true)
    setResult(null)

    const base  = PRESETS[preset]
    const scale = INTENSITIES[intensity]

    const payload = {
      src_ip: srcIP || '192.168.1.1',
      ...base,
      'Flow Packets/s': base['Flow Packets/s'] * scale,
      'Flow Bytes/s':   base['Flow Bytes/s']   * scale,
      'Total Fwd Packets': base['Total Fwd Packets'] * scale,
    }

    try {
      const res  = await fetch('http://localhost:8000/scan_traffic', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
      const data = await res.json()
      setResult(data)
    } catch (e) {
      setResult({ error: 'Could not reach traffic scanner on port 8000.' })
    }
    setLoading(false)
  }

  const isAttack  = result?.is_attack
  const isBlocked = result?.prediction === 'BLOCKED'
  const color = !result ? 'var(--accent)'
    : isBlocked ? 'var(--warn)'
    : isAttack  ? 'var(--danger)'
    : 'var(--accent)'

  return (
    <div style={styles.wrapper}>
      <div style={styles.header}>
        <span style={styles.title}>TRAFFIC SCANNER</span>
        <span style={styles.sub}>DDoS / Anomaly Detection</span>
      </div>

      <div style={styles.body}>

        {/* Simple 3-field form */}
        <div style={styles.simpleForm}>

          {/* Source IP */}
          <div style={styles.field}>
            <label style={styles.label}>SOURCE IP</label>
            <input
              style={styles.input}
              value={srcIP}
              onChange={e => setSrcIP(e.target.value)}
              placeholder="192.168.1.1"
            />
          </div>

          {/* Attack Type */}
          <div style={styles.field}>
            <label style={styles.label}>ATTACK TYPE</label>
            <div style={styles.btnGroup}>
              {Object.keys(PRESETS).map(p => (
                <button
                  key={p}
                  style={{
                    ...styles.typeBtn,
                    ...(preset === p ? {
                      background: p === 'Normal' ? 'rgba(0,245,196,0.15)' : 'rgba(255,60,90,0.15)',
                      borderColor: p === 'Normal' ? 'var(--accent)' : 'var(--danger)',
                      color: p === 'Normal' ? 'var(--accent)' : 'var(--danger)',
                    } : {})
                  }}
                  onClick={() => { setPreset(p); setResult(null) }}
                >
                  {p}
                </button>
              ))}
            </div>
          </div>

          {/* Intensity */}
          <div style={styles.field}>
            <label style={styles.label}>INTENSITY</label>
            <div style={styles.btnGroup}>
              {Object.keys(INTENSITIES).map(i => (
                <button
                  key={i}
                  style={{
                    ...styles.typeBtn,
                    ...(intensity === i ? {
                      background: i === 'High' ? 'rgba(255,60,90,0.15)' : i === 'Medium' ? 'rgba(255,170,0,0.15)' : 'rgba(0,245,196,0.15)',
                      borderColor: i === 'High' ? 'var(--danger)' : i === 'Medium' ? 'var(--warn)' : 'var(--accent)',
                      color: i === 'High' ? 'var(--danger)' : i === 'Medium' ? 'var(--warn)' : 'var(--accent)',
                    } : {})
                  }}
                  onClick={() => { setIntensity(i); setResult(null) }}
                >
                  {i}
                </button>
              ))}
            </div>
          </div>

        </div>

        {/* Scan button */}
        <button
          style={{ ...styles.scanBtn, ...(loading ? styles.scanBtnLoading : {}) }}
          onClick={scan}
          disabled={loading}
        >
          {loading ? 'SCANNING...' : 'SCAN TRAFFIC'}
        </button>

        {/* Result */}
        {result && !result.error && (
          <div style={{ ...styles.result, borderColor: color,
            background: isBlocked ? 'rgba(255,170,0,0.05)'
              : isAttack ? 'rgba(255,60,90,0.05)'
              : 'rgba(0,245,196,0.04)' }}>
            <div style={{ ...styles.verdict, color }}>
              {isBlocked ? '⊘ IP ALREADY BLOCKED'
                : isAttack ? `⚠ ${result.prediction} DETECTED`
                : '✓ TRAFFIC IS NORMAL'}
            </div>
            <div style={styles.scores}>
              <div style={styles.scoreItem}>
                <span style={styles.scoreLabel}>RISK</span>
                <span style={{ ...styles.scoreVal, color }}>{(result.risk_score * 100).toFixed(0)}%</span>
              </div>
              <div style={styles.scoreItem}>
                <span style={styles.scoreLabel}>ML</span>
                <span style={styles.scoreVal}>{result.ml_score != null ? (result.ml_score * 100).toFixed(0) + '%' : '—'}</span>
              </div>
              <div style={styles.scoreItem}>
                <span style={styles.scoreLabel}>RULES</span>
                <span style={styles.scoreVal}>{result.rule_score != null ? (result.rule_score * 100).toFixed(0) + '%' : '—'}</span>
              </div>
              <div style={styles.scoreItem}>
                <span style={styles.scoreLabel}>AUTO-BLOCKED</span>
                <span style={{ ...styles.scoreVal, color: result.auto_blocked ? 'var(--danger)' : 'var(--muted)' }}>
                  {result.auto_blocked ? 'YES' : 'NO'}
                </span>
              </div>
            </div>
          </div>
        )}

        {result?.error && (
          <div style={styles.error}>{result.error}</div>
        )}

        {/* Live capture notice */}
        <div style={styles.notice}>
          <span style={styles.noticeIcon}>📡</span>
          <span>Live capture is running — real traffic from your network is being scanned automatically every 5 seconds</span>
        </div>

      </div>
      {/* Attack Timeline */}
<div style={styles.timeline}>
  <div style={styles.timelineTitle}>ATTACK TIMELINE</div>

  {alerts.length === 0 && (
    <div style={styles.timelineEmpty}>No recent alerts</div>
  )}

  {alerts.map((a, i) => (
    <div key={i} style={styles.timelineItem}>
      <span style={styles.timelineTime}>
        {new Date(a.time).toLocaleTimeString()}
      </span>
      <span style={styles.timelineText}>
        {a.type} from {a.ip}
      </span>
    </div>
  ))}
</div>
    </div>
  )
}

const styles = {
  wrapper: {
    background: 'var(--panel)',
    border: '1px solid var(--border)',
    borderRadius: 10, overflow: 'hidden',
  },
  header: {
    padding: '14px 20px', borderBottom: '1px solid var(--border)',
    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
    background: 'rgba(0,245,196,0.03)',
  },
  title: { fontSize: 13, fontWeight: 700, letterSpacing: 2, color: 'var(--accent)' },
  sub: { fontSize: 11, color: 'var(--muted)', fontFamily: 'var(--mono)' },
  body: { padding: 24 },
  simpleForm: { display: 'flex', flexDirection: 'column', gap: 20, marginBottom: 20 },
  field: {},
  label: {
    display: 'block', fontSize: 10, letterSpacing: 2,
    color: 'var(--muted)', textTransform: 'uppercase', marginBottom: 8,
  },
  input: {
    width: 280, background: '#070c18',
    border: '1px solid var(--border)', borderRadius: 6,
    padding: '10px 14px', color: 'var(--text)',
    fontFamily: 'var(--mono)', fontSize: 14, outline: 'none',
  },
  btnGroup: { display: 'flex', gap: 8, flexWrap: 'wrap' },
  typeBtn: {
    background: 'transparent',
    border: '1px solid var(--border)',
    borderRadius: 6, color: 'var(--muted)',
    padding: '8px 20px', fontSize: 13,
    fontWeight: 600, cursor: 'pointer',
    fontFamily: 'var(--ui)', letterSpacing: 1,
    transition: 'all 0.2s',
  },
  scanBtn: {
    width: '100%', padding: 14,
    background: 'transparent',
    border: '1px solid var(--accent)',
    borderRadius: 6, color: 'var(--accent)',
    fontFamily: 'var(--ui)', fontSize: 15,
    fontWeight: 700, letterSpacing: 3,
    cursor: 'pointer', marginBottom: 16,
    transition: 'all 0.2s',
  },
  scanBtnLoading: { borderColor: 'var(--warn)', color: 'var(--warn)', opacity: 0.7 },
  result: {
    border: '1px solid', borderRadius: 8,
    padding: 20, marginBottom: 16,
  },
  verdict: { fontSize: 20, fontWeight: 700, letterSpacing: 2, marginBottom: 16 },
  scores: { display: 'flex', gap: 32 },
  scoreItem: { display: 'flex', flexDirection: 'column', gap: 4 },
  scoreLabel: { fontSize: 10, letterSpacing: 1.5, color: 'var(--muted)', textTransform: 'uppercase' },
  scoreVal: { fontFamily: 'var(--mono)', fontSize: 28, color: 'var(--text)' },
  error: {
    padding: 12, borderRadius: 6,
    background: 'rgba(255,60,90,0.08)',
    border: '1px solid var(--danger)',
    color: 'var(--danger)',
    fontFamily: 'var(--mono)', fontSize: 12, marginBottom: 16,
  },
  notice: {
    display: 'flex', alignItems: 'center', gap: 10,
    padding: '10px 14px', borderRadius: 6,
    background: 'rgba(0,245,196,0.04)',
    border: '1px solid rgba(0,245,196,0.15)',
    fontSize: 12, color: 'var(--muted)',
  },
  noticeIcon: { fontSize: 16 },
  timeline: {
  marginTop: 20,
  padding: 16,
  border: '1px solid var(--border)',
  borderRadius: 8,
  background: '#070c18',
},

timelineTitle: {
  fontSize: 12,
  letterSpacing: 2,
  marginBottom: 10,
  color: 'var(--accent)',
},

timelineItem: {
  display: 'flex',
  gap: 10,
  fontFamily: 'var(--mono)',
  fontSize: 12,
  marginBottom: 6,
},

timelineTime: {
  color: 'var(--muted)',
},

timelineText: {
  color: 'var(--text)',
},

timelineEmpty: {
  color: 'var(--muted)',
  fontSize: 12,
},
}
