import React, { useEffect, useState, useRef } from 'react'
import { db } from '../firebase'
import { ref, onValue } from 'firebase/database'

const geoCache = {}

async function getGeo(ip) {
  if (!ip || ip === 'unknown' || ip === '-') return null
  if (ip.startsWith('192.168') || ip.startsWith('10.') || ip.startsWith('127.')) return null
  if (geoCache[ip]) return geoCache[ip]
  try {
    const res = await fetch(`https://ipapi.co/${ip}/json/`)
    const data = await res.json()
    if (data.latitude && data.longitude) {
      geoCache[ip] = { lat: data.latitude, lng: data.longitude, city: data.city || '', country: data.country_name || '' }
      return geoCache[ip]
    }
  } catch {}
  return null
}

export default function GeoMap() {
  const mapRef     = useRef(null)
  const mapObj     = useRef(null)
  const markersRef = useRef({})
  const [stats, setStats]     = useState({ total: 0, attacks: 0, countries: 0 })
  const [mapReady, setMapReady] = useState(false)
  const [status, setStatus]   = useState('Loading map...')

  // Step 1: inject Leaflet CSS + JS
  useEffect(() => {
    // CSS
    const link = document.createElement('link')
    link.rel  = 'stylesheet'
    link.href = 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.css'
    document.head.appendChild(link)

    // JS
    const script = document.createElement('script')
    script.src = 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.js'
    script.onload = () => setMapReady(true)
    script.onerror = () => setStatus('Failed to load Leaflet. Check internet connection.')
    document.head.appendChild(script)

    return () => {
      document.head.removeChild(link)
      document.head.removeChild(script)
    }
  }, [])

  // Step 2: init map once Leaflet loaded + div mounted
  useEffect(() => {
    if (!mapReady || !mapRef.current || mapObj.current) return
    const L = window.L
    if (!L) return

    const map = L.map(mapRef.current, {
      center: [20, 0],
      zoom: 2,
      zoomControl: true,
      attributionControl: false,
    })

    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      maxZoom: 19,
    }).addTo(map)

    mapObj.current = map
    setStatus('LIVE')
  }, [mapReady])

  // Step 3: Firebase listener → add markers
  useEffect(() => {
    if (!mapReady) return

    const detRef = ref(db, 'detections')
    const unsub  = onValue(detRef, async snap => {
      const data    = snap.val() || {}
      const entries = Object.values(data)

      let attacks = 0
      const countries = new Set()

      for (const entry of entries) {
        const ip = entry.src_ip || entry.ip
        if (entry.is_attack) attacks++

        if (!ip || markersRef.current[ip]) {
          if (entry.geo?.country) countries.add(entry.geo.country)
          continue
        }

        const geo = await getGeo(ip)
        if (!geo || !mapObj.current) continue

        const L = window.L
        if (!L) continue

        countries.add(geo.country)
        const isAtk = entry.is_attack
        const color = isAtk ? '#FF3C5A' : '#00F5C4'
        const size  = isAtk ? 16 : 10

        const icon = L.divIcon({
          className: '',
          html: `<div style="
            width:${size}px;height:${size}px;border-radius:50%;
            background:${color};border:2px solid ${color};
            box-shadow:0 0 ${isAtk ? 14 : 6}px ${color};
            cursor:pointer;
          "></div>`,
          iconSize: [size, size],
          iconAnchor: [size / 2, size / 2],
        })

        const marker = L.marker([geo.lat, geo.lng], { icon }).addTo(mapObj.current)
        marker.bindPopup(`
          <div style="font-family:monospace;font-size:12px;line-height:1.8">
            <b style="color:${isAtk ? '#FF3C5A' : '#009977'}">${isAtk ? '⚠ ' + (entry.prediction || 'ATTACK') : '✓ BENIGN'}</b><br>
            <b>IP:</b> ${ip}<br>
            ${geo.city ? `<b>City:</b> ${geo.city}<br>` : ''}
            <b>Country:</b> ${geo.country}<br>
            <b>Risk:</b> ${entry.risk_score ? (entry.risk_score * 100).toFixed(0) + '%' : '—'}
          </div>
        `)

        markersRef.current[ip] = marker
      }

      setStats({ total: entries.length, attacks, countries: countries.size })
    })

    return () => unsub()
  }, [mapReady])

  return (
    <div style={S.wrapper}>
      {/* Header */}
      <div style={S.header}>
        <span style={S.title}>🌍  GLOBAL THREAT MAP</span>
        <div style={S.legend}>
          <span style={S.legendItem}><span style={{ ...S.dot, background: '#FF3C5A', boxShadow: '0 0 6px #FF3C5A' }} /> ATTACK</span>
          <span style={S.legendItem}><span style={{ ...S.dot, background: '#00F5C4', boxShadow: '0 0 6px #00F5C4' }} /> BENIGN</span>
        </div>
      </div>

      {/* Stats bar */}
      <div style={S.statsBar}>
        {[
          { label: 'IPs MAPPED',  val: stats.total,     color: '#00F5C4' },
          { label: 'ATTACKS',     val: stats.attacks,   color: '#FF3C5A' },
          { label: 'COUNTRIES',   val: stats.countries, color: '#FFAA00' },
          { label: 'STATUS',      val: status,          color: status === 'LIVE' ? '#00F5C4' : '#FFAA00' },
        ].map((item, i) => (
          <div key={i} style={S.statItem}>
            <span style={S.statLabel}>{item.label}</span>
            <span style={{ ...S.statVal, color: item.color }}>{item.val}</span>
          </div>
        ))}
      </div>

      {/* Map container */}
      <div style={S.mapWrap}>
        <div ref={mapRef} style={S.map} />
        {status !== 'LIVE' && (
          <div style={S.overlay}>
            <div style={S.overlayText}>{status}</div>
          </div>
        )}
      </div>

      <div style={S.footer}>
        Click any dot for IP details  •  Private IPs not shown  •  Geo data: ipapi.co
      </div>
    </div>
  )
}

const S = {
  wrapper: { background: '#0a1128', border: '1px solid #1a2540', borderRadius: 10, overflow: 'hidden' },
  header: { padding: '14px 20px', borderBottom: '1px solid #1a2540', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'rgba(0,245,196,0.03)' },
  title: { fontSize: 13, fontWeight: 700, letterSpacing: 2, color: '#00F5C4', fontFamily: 'monospace' },
  legend: { display: 'flex', gap: 20 },
  legendItem: { display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: '#4a6080', fontFamily: 'monospace' },
  dot: { width: 10, height: 10, borderRadius: '50%', display: 'inline-block' },
  statsBar: { display: 'flex', borderBottom: '1px solid #1a2540' },
  statItem: { flex: 1, padding: '10px 20px', display: 'flex', flexDirection: 'column', gap: 3, borderRight: '1px solid #1a2540' },
  statLabel: { fontSize: 10, letterSpacing: 1.5, color: '#4a6080', fontFamily: 'monospace' },
  statVal: { fontFamily: 'monospace', fontSize: 20, fontWeight: 700 },
  mapWrap: { position: 'relative', height: 450 },
  map: { height: '100%', width: '100%' },
  overlay: { position: 'absolute', inset: 0, background: 'rgba(5,8,16,0.85)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 999 },
  overlayText: { fontFamily: 'monospace', fontSize: 14, color: '#FFAA00', letterSpacing: 3 },
  footer: { padding: '8px 20px', fontSize: 10, color: '#4a6080', fontFamily: 'monospace', borderTop: '1px solid #1a2540' },
}
