import React, { useEffect, useMemo, useState } from 'react';
import { MapContainer, TileLayer, Marker, Polyline, Popup, Circle, useMap } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import {
  MapPin,
  Navigation,
  AlertTriangle,
  ShieldAlert,
  Clock,
  Activity,
  X,
  Flame,
  User,
  Eye
} from 'lucide-react';

// Fix leaflet default marker icons
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon-2x.png',
  iconUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png',
  shadowUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png',
});

// ============================================================
// Indian office/city location pool for realistic simulation
// ============================================================
const INDIA_LOCATIONS = [
  { city: 'Mumbai HQ',     lat: 19.0760, lng: 72.8777, type: 'office' },
  { city: 'Delhi Office',  lat: 28.7041, lng: 77.1025, type: 'office' },
  { city: 'Bengaluru DC',  lat: 12.9716, lng: 77.5946, type: 'datacenter' },
  { city: 'Chennai',       lat: 13.0827, lng: 80.2707, type: 'office' },
  { city: 'Pune',          lat: 18.5204, lng: 73.8567, type: 'office' },
  { city: 'Hyderabad',     lat: 17.3850, lng: 78.4867, type: 'office' },
  { city: 'Kolkata',       lat: 22.5726, lng: 88.3639, type: 'remote' },
  { city: 'Ahmedabad',     lat: 23.0225, lng: 72.5714, type: 'remote' },
  { city: 'Jaipur',        lat: 26.9124, lng: 75.7873, type: 'remote' },
  { city: 'Lucknow',       lat: 26.8467, lng: 80.9462, type: 'remote' },
  { city: 'Surat',         lat: 21.1702, lng: 72.8311, type: 'remote' },
  { city: 'Noida',         lat: 28.5355, lng: 77.3910, type: 'office' },
  // Suspicious foreign locations
  { city: 'Singapore',     lat: 1.3521,  lng: 103.8198, type: 'suspicious' },
  { city: 'Dubai',         lat: 25.2048, lng: 55.2708,  type: 'suspicious' },
  { city: 'London',        lat: 51.5074, lng: -0.1278,  type: 'suspicious' },
  { city: 'Frankfurt',     lat: 50.1109, lng: 8.6821,   type: 'suspicious' },
];

// Seeded pseudo-random for consistency per employee
function seededRand(seed, min, max) {
  const x = Math.sin(seed) * 10000;
  return min + (x - Math.floor(x)) * (max - min);
}

// Generate location track for an employee based on their ID
function generateEmployeeTrack(employee, alerts = [], riskEvents = []) {
  const seed = employee.id?.charCodeAt(0) + (employee.id?.charCodeAt(4) || 0) + (employee.id?.charCodeAt(8) || 0) || 42;

  // Pick 3–6 locations, mostly normal, possibly suspicious for high-risk
  const riskScore = employee.latestRiskScore || 0;
  const numPoints = 3 + Math.floor(seededRand(seed * 1.5, 0, 4));
  const includesSuspicious = riskScore >= 70;

  const normalPool = INDIA_LOCATIONS.filter(l => l.type !== 'suspicious');
  const suspiciousPool = INDIA_LOCATIONS.filter(l => l.type === 'suspicious');

  const points = [];

  // First location: main office (seeded)
  const mainIdx = Math.floor(seededRand(seed, 0, normalPool.length));
  const main = normalPool[mainIdx];

  // Add slight jitter to make each track look unique
  const jitter = () => (seededRand(seed * Math.random() * 100, -0.05, 0.05));

  points.push({
    ...main,
    lat: main.lat + seededRand(seed * 2, -0.02, 0.02),
    lng: main.lng + seededRand(seed * 3, -0.02, 0.02),
    timestamp: new Date(Date.now() - 8 * 3600000).toISOString(),
    event: 'Login from primary office',
    riskLevel: 'normal',
    riskScore: Math.floor(seededRand(seed, 5, 25))
  });

  // Intermediate stops
  for (let i = 1; i < numPoints - 1; i++) {
    const idx = Math.floor(seededRand(seed * (i + 7), 0, normalPool.length));
    const loc = normalPool[idx];
    const hrOffset = i * 2;
    const events = ['API Access', 'Database Query', 'File Download', 'Session Active', 'VPN Connected'];
    points.push({
      ...loc,
      lat: loc.lat + seededRand(seed * i * 13, -0.03, 0.03),
      lng: loc.lng + seededRand(seed * i * 17, -0.03, 0.03),
      timestamp: new Date(Date.now() - (8 - hrOffset) * 3600000).toISOString(),
      event: events[Math.floor(seededRand(seed * i, 0, events.length))],
      riskLevel: riskScore >= 40 ? 'unusual' : 'normal',
      riskScore: Math.floor(seededRand(seed * i, 15, 50))
    });
  }

  // Last location: suspicious if high risk
  if (includesSuspicious && suspiciousPool.length > 0) {
    const suspIdx = Math.floor(seededRand(seed * 9, 0, suspiciousPool.length));
    const susp = suspiciousPool[suspIdx];
    const suspEvents = ['Unauthorized API Call', 'Exfiltration Attempt', 'Suspicious Login', 'Data Export'];
    points.push({
      ...susp,
      timestamp: new Date(Date.now() - 30 * 60000).toISOString(),
      event: suspEvents[Math.floor(seededRand(seed * 5, 0, suspEvents.length))],
      riskLevel: riskScore >= 85 ? 'high-risk' : 'suspicious',
      riskScore: riskScore
    });
  } else {
    const lastIdx = Math.floor(seededRand(seed * 11, 0, normalPool.length));
    const loc = normalPool[lastIdx];
    points.push({
      ...loc,
      lat: loc.lat + seededRand(seed * 4, -0.01, 0.01),
      lng: loc.lng + seededRand(seed * 5, -0.01, 0.01),
      timestamp: new Date().toISOString(),
      event: 'Current session',
      riskLevel: 'normal',
      riskScore: Math.floor(seededRand(seed * 6, 5, 30))
    });
  }

  return points;
}

// Custom colored circle marker icon
function makeIcon(riskLevel) {
  const colors = {
    'normal': '#10b981',
    'unusual': '#0ea5e9',
    'suspicious': '#f59e0b',
    'high-risk': '#f43f5e',
    'contained': '#6366f1'
  };
  const color = colors[riskLevel] || '#94a3b8';
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="32" height="32">
    <circle cx="16" cy="16" r="10" fill="${color}" fill-opacity="0.25" stroke="${color}" stroke-width="2"/>
    <circle cx="16" cy="16" r="5" fill="${color}"/>
  </svg>`;
  return L.divIcon({
    html: svg,
    className: '',
    iconSize: [32, 32],
    iconAnchor: [16, 16],
    popupAnchor: [0, -16]
  });
}

function makeLastIcon(riskLevel) {
  const colors = {
    'normal': '#10b981',
    'unusual': '#0ea5e9',
    'suspicious': '#f59e0b',
    'high-risk': '#f43f5e',
  };
  const color = colors[riskLevel] || '#94a3b8';
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 40 40" width="40" height="40">
    <circle cx="20" cy="20" r="15" fill="${color}" fill-opacity="0.2" stroke="${color}" stroke-width="2.5"/>
    <circle cx="20" cy="20" r="8" fill="${color}" fill-opacity="0.8"/>
    <circle cx="20" cy="20" r="4" fill="white"/>
  </svg>`;
  return L.divIcon({
    html: `<div style="animation: mapPulse 1.5s infinite;">${svg}</div>`,
    className: '',
    iconSize: [40, 40],
    iconAnchor: [20, 20],
    popupAnchor: [0, -20]
  });
}

// Auto-fit map bounds to track
function FitBounds({ positions }) {
  const map = useMap();
  useEffect(() => {
    if (positions && positions.length >= 2) {
      const bounds = L.latLngBounds(positions.map(p => [p[0], p[1]]));
      map.fitBounds(bounds, { padding: [50, 50], maxZoom: 6 });
    } else if (positions && positions.length === 1) {
      map.setView(positions[0], 8);
    }
  }, [positions, map]);
  return null;
}

const RISK_COLORS = {
  'normal': '#10b981',
  'unusual': '#0ea5e9',
  'suspicious': '#f59e0b',
  'high-risk': '#f43f5e',
};

const RISK_LABELS = {
  'normal': 'Normal',
  'unusual': 'Unusual',
  'suspicious': 'Suspicious',
  'high-risk': 'HIGH RISK',
};

// ============================================================
// MAIN COMPONENT
// ============================================================
export function EmployeeMapView({ employee, alerts = [], riskEvents = [], onClose }) {
  const [selectedPoint, setSelectedPoint] = useState(null);

  const track = useMemo(() => {
    if (!employee) return [];
    return generateEmployeeTrack(employee, alerts, riskEvents);
  }, [employee, alerts, riskEvents]);

  const positions = useMemo(() => track.map(p => [p.lat, p.lng]), [track]);

  const polylineSegments = useMemo(() => {
    const segments = [];
    for (let i = 0; i < track.length - 1; i++) {
      segments.push({
        from: track[i],
        to: track[i + 1],
        riskLevel: track[i + 1].riskLevel,
        color: RISK_COLORS[track[i + 1].riskLevel] || '#64748b'
      });
    }
    return segments;
  }, [track]);

  const lastPoint = track[track.length - 1];
  const riskScore = employee?.latestRiskScore || 0;
  const riskColor = RISK_COLORS[lastPoint?.riskLevel] || '#64748b';

  return (
    <div className="fixed inset-0 z-[9999] bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="w-full max-w-6xl bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl overflow-hidden flex flex-col"
        style={{ height: '90vh', animation: 'mapSlideIn 0.3s ease-out' }}
      >
        {/* Header */}
        <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/80">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-gradient-to-br from-cyan-600 to-blue-700 shadow-md shadow-cyan-900/40">
              <Navigation size={18} className="text-white" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-white flex items-center gap-2">
                <span>Location Track —</span>
                <span className="text-cyan-300">{employee?.name}</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 border border-slate-700 text-slate-300">
                  {employee?.employee_code || employee?.id?.substring(0, 8)}
                </span>
              </h2>
              <p className="text-[11px] text-slate-400 mt-0.5">{employee?.role} • {employee?.department}</p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {/* Risk badge */}
            <div className="px-3 py-1.5 rounded-xl border text-xs font-bold font-mono"
              style={{
                backgroundColor: `${riskColor}15`,
                borderColor: `${riskColor}40`,
                color: riskColor
              }}
            >
              Risk: {riskScore}/100
            </div>

            {/* Track points count */}
            <div className="px-2.5 py-1.5 rounded-xl bg-slate-800 border border-slate-700 text-[11px] font-mono text-slate-300">
              {track.length} tracked points
            </div>

            <button onClick={onClose}
              className="p-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors cursor-pointer"
            >
              <X size={18} />
            </button>
          </div>
        </div>

        {/* Body: Map + Sidebar */}
        <div className="flex flex-1 overflow-hidden">
          {/* MAP */}
          <div className="flex-1 relative">
            <MapContainer
              center={[20.5937, 78.9629]}
              zoom={5}
              style={{ height: '100%', width: '100%', background: '#0f172a' }}
              zoomControl={true}
            >
              <TileLayer
                url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
                attribution='&copy; <a href="https://carto.com/">CARTO</a>'
              />

              <FitBounds positions={positions} />

              {/* Polyline segments (color-coded by risk) */}
              {polylineSegments.map((seg, i) => (
                <Polyline
                  key={i}
                  positions={[[seg.from.lat, seg.from.lng], [seg.to.lat, seg.to.lng]]}
                  color={seg.color}
                  weight={3}
                  opacity={0.8}
                  dashArray={seg.riskLevel === 'suspicious' || seg.riskLevel === 'high-risk' ? '8 5' : undefined}
                />
              ))}

              {/* Track points */}
              {track.map((point, i) => {
                const isLast = i === track.length - 1;
                const icon = isLast ? makeLastIcon(point.riskLevel) : makeIcon(point.riskLevel);
                return (
                  <Marker
                    key={i}
                    position={[point.lat, point.lng]}
                    icon={icon}
                    eventHandlers={{
                      click: () => setSelectedPoint(point)
                    }}
                  >
                    <Popup className="custom-map-popup">
                      <div className="p-2 min-w-[200px] bg-slate-900 text-slate-200 rounded-lg text-xs font-mono">
                        <div className="font-bold text-white mb-1">📍 {point.city}</div>
                        <div className="text-slate-400 mb-1">{new Date(point.timestamp).toLocaleString()}</div>
                        <div className="font-semibold" style={{ color: RISK_COLORS[point.riskLevel] || '#94a3b8' }}>
                          {RISK_LABELS[point.riskLevel]}
                        </div>
                        <div className="text-slate-300 mt-1">{point.event}</div>
                        <div className="text-slate-400 mt-0.5">Risk: {point.riskScore}</div>
                      </div>
                    </Popup>
                  </Marker>
                );
              })}

              {/* Pulse circle on last point */}
              {lastPoint && (
                <Circle
                  center={[lastPoint.lat, lastPoint.lng]}
                  radius={80000}
                  color={riskColor}
                  fillColor={riskColor}
                  fillOpacity={0.08}
                  weight={1}
                />
              )}
            </MapContainer>

            {/* Map overlay — legend */}
            <div className="absolute bottom-4 left-4 z-[1000] p-3 rounded-xl bg-slate-900/90 border border-slate-800 backdrop-blur-sm text-[10px] font-mono space-y-1.5">
              <div className="text-slate-400 font-bold uppercase tracking-wider mb-2">Risk Legend</div>
              {Object.entries(RISK_LABELS).map(([key, label]) => (
                <div key={key} className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: RISK_COLORS[key] }} />
                  <span className="text-slate-300">{label}</span>
                </div>
              ))}
              <div className="pt-1 border-t border-slate-800 text-slate-500">
                Dashed line = suspicious path
              </div>
            </div>
          </div>

          {/* SIDEBAR: Track Timeline */}
          <div className="w-80 border-l border-slate-800 flex flex-col bg-slate-950/60 overflow-hidden">
            <div className="px-4 py-3 border-b border-slate-800">
              <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                <Activity size={13} className="text-cyan-400" />
                Location Timeline
              </h3>
            </div>

            <div className="flex-1 overflow-y-auto px-3 py-3 space-y-2">
              {track.map((point, i) => {
                const isLast = i === track.length - 1;
                const isFirst = i === 0;
                const color = RISK_COLORS[point.riskLevel] || '#64748b';
                const isSelected = selectedPoint === point;

                return (
                  <div
                    key={i}
                    onClick={() => setSelectedPoint(point)}
                    className={`p-3 rounded-xl border cursor-pointer transition-all ${
                      isSelected
                        ? 'border-cyan-500/70 bg-cyan-950/20 shadow-md'
                        : 'border-slate-800/80 bg-slate-900/50 hover:border-slate-700 hover:bg-slate-900'
                    }`}
                  >
                    <div className="flex items-start gap-2.5">
                      {/* Timeline dot */}
                      <div className="flex flex-col items-center shrink-0 pt-0.5">
                        <div className="w-3 h-3 rounded-full border-2 flex items-center justify-center"
                          style={{ borderColor: color, backgroundColor: `${color}30` }}
                        >
                          {isLast && <div className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: color }} />}
                        </div>
                        {!isLast && (
                          <div className="w-px flex-1 mt-1" style={{ backgroundColor: `${color}40`, minHeight: '20px' }} />
                        )}
                      </div>

                      <div className="flex-1 min-w-0 space-y-0.5">
                        <div className="flex items-center justify-between gap-1">
                          <span className="text-[11px] font-bold text-slate-200 font-mono truncate">
                            {isFirst ? '🏢' : isLast ? '📍' : '•'} {point.city}
                          </span>
                          <span
                            className="text-[9px] px-1.5 py-0.5 rounded font-mono font-bold shrink-0"
                            style={{ backgroundColor: `${color}20`, color }}
                          >
                            {RISK_LABELS[point.riskLevel]}
                          </span>
                        </div>

                        <p className="text-[10px] text-slate-400 truncate">{point.event}</p>

                        <div className="flex items-center gap-2 text-[9px] font-mono text-slate-500">
                          <Clock size={9} />
                          {new Date(point.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                          <span className="ml-auto" style={{ color }}>Score: {point.riskScore}</span>
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Bottom: selected point detail */}
            {selectedPoint && (
              <div className="border-t border-slate-800 p-4 space-y-2 bg-slate-950/80">
                <div className="flex items-center gap-2 text-xs font-bold text-slate-300">
                  <Eye size={12} className="text-cyan-400" />
                  <span>Point Detail</span>
                </div>
                <div className="space-y-1.5 text-[11px] font-mono">
                  <div className="flex justify-between">
                    <span className="text-slate-500">Location</span>
                    <span className="text-slate-200 font-bold">{selectedPoint.city}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Coordinates</span>
                    <span className="text-slate-400">
                      {selectedPoint.lat.toFixed(4)}, {selectedPoint.lng.toFixed(4)}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Event</span>
                    <span className="text-slate-200 text-right max-w-[55%]">{selectedPoint.event}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Risk</span>
                    <span className="font-bold" style={{ color: RISK_COLORS[selectedPoint.riskLevel] }}>
                      {RISK_LABELS[selectedPoint.riskLevel]} ({selectedPoint.riskScore})
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Time</span>
                    <span className="text-slate-400">{new Date(selectedPoint.timestamp).toLocaleString()}</span>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      <style>{`
        @keyframes mapSlideIn {
          from { opacity: 0; transform: scale(0.97) translateY(12px); }
          to   { opacity: 1; transform: scale(1) translateY(0); }
        }
        @keyframes mapPulse {
          0%, 100% { transform: scale(1); opacity: 1; }
          50%       { transform: scale(1.15); opacity: 0.8; }
        }
        .leaflet-popup-content-wrapper {
          background: #0f172a !important;
          border: 1px solid #334155 !important;
          border-radius: 12px !important;
          box-shadow: 0 8px 32px rgba(0,0,0,0.5) !important;
        }
        .leaflet-popup-tip {
          background: #0f172a !important;
        }
        .leaflet-popup-content {
          margin: 0 !important;
        }
      `}</style>
    </div>
  );
}
