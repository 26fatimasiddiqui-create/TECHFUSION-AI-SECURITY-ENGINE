import React, { useState } from 'react';
import { 
  ShieldAlert, 
  Activity, 
  Flame, 
  AlertTriangle, 
  ChevronRight, 
  User, 
  Laptop, 
  Globe, 
  Database,
  ArrowRight,
  Filter,
  CheckCircle2,
  RefreshCw
} from 'lucide-react';
import { Card } from '../components/common/Card';
import { RiskBadge, StatusBadge } from '../components/common/Badge';
import { LoadingSpinner } from '../components/common/LoadingSpinner';
import { ErrorBanner } from '../components/common/ErrorBanner';

export function InternalThreatsPage({
  incidents = [],
  events = [],
  isLoading = false,
  error = null,
  onRefresh,
  onSelectIncident,
  setTab,
  onRunNormal,
  onRunSuspicious,
}) {
  const [filterSignal, setFilterSignal] = useState('ALL');

  // Derive all signals
  const allSignals = incidents.flatMap(i => i.signals_detected || []);
  const threatSignalsCatalog = [
    { key: 'new_device', label: 'NEW DEVICE', count: allSignals.filter(s => s === 'new_device' || s === 'unknown_device').length, desc: 'Unseen hardware' },
    { key: 'new_ip', label: 'NEW IP', count: allSignals.filter(s => s === 'new_ip').length, desc: 'Unfamiliar IP' },
    { key: 'impossible_travel', label: 'IMPOSSIBLE TRAVEL', count: allSignals.filter(s => s === 'impossible_travel').length, desc: 'Speed > 850 km/h' },
    { key: 'abnormal_login_time', label: 'ABNORMAL TIME', count: allSignals.filter(s => s === 'abnormal_login_time').length, desc: 'Off-hours login' },
    { key: 'device_anomaly', label: 'DEVICE ANOMALY', count: allSignals.filter(s => s === 'device_anomaly').length, desc: 'OS / fingerprint shift' },
    { key: 'abnormal_resource_access', label: 'ROLE DEVIATION', count: allSignals.filter(s => s === 'abnormal_resource_access').length, desc: 'Atypical resource' },
    { key: 'bulk_data_access', label: 'BULK ACCESS', count: allSignals.filter(s => s === 'bulk_data_access').length, desc: '>=1k records export' },
    { key: 'privilege_escalation', label: 'PRIVILEGE ESCALATION', count: allSignals.filter(s => s === 'privilege_escalation').length, desc: 'Role transition' },
  ];

  // Internal threat incidents
  const internalIncidents = incidents.filter(i => 
    (i.signals_detected || []).some(s => [
      'new_device', 'unknown_device', 'new_ip', 'impossible_travel', 
      'abnormal_login_time', 'device_anomaly', 'abnormal_resource_access', 
      'bulk_data_access', 'privilege_escalation'
    ].includes(s))
  );

  const filteredIncidents = filterSignal === 'ALL'
    ? internalIncidents
    : internalIncidents.filter(i => (i.signals_detected || []).includes(filterSignal));

  const featuredIncident = internalIncidents[0] || incidents[0];

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-900/95 to-red-950/30 border border-slate-800 rounded-2xl p-6 shadow-xl relative overflow-hidden">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="p-1.5 rounded-lg bg-red-950/80 border border-red-800/50 text-red-400">
                <ShieldAlert size={20} />
              </span>
              <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
                Internal Threats & Behavioral Anomaly Detection
              </h1>
              <span className="px-2.5 py-0.5 rounded text-[10px] font-mono uppercase tracking-wider bg-cyan-950/80 text-cyan-300 border border-cyan-800/50">
                Active Defense
              </span>
            </div>
            <p className="text-xs sm:text-sm text-slate-400 max-w-3xl leading-relaxed">
              Detects insider risks by combining multiple behavioral signals (New Device + New IP + Unusual Time + Sensitive API + Bulk Data) rather than treating isolated unfamiliar actions as automatic threats.
            </p>
          </div>

          {/* Interactive Simulation Triggers */}
          <div className="flex items-center gap-2 shrink-0">
            {onRunNormal && (
              <button
                onClick={onRunNormal}
                className="flex items-center gap-1.5 px-3.5 py-2 bg-emerald-950/60 hover:bg-emerald-900/60 border border-emerald-700/50 text-emerald-300 rounded-xl text-xs font-semibold transition-all cursor-pointer shadow-lg shadow-emerald-950/30"
                title="Simulate A. Verma routine access (Known device, known IP, low risk)"
              >
                <Activity size={14} className="text-emerald-400" />
                <span>Test Normal Flow</span>
              </button>
            )}
            {onRunSuspicious && (
              <button
                onClick={onRunSuspicious}
                className="flex items-center gap-1.5 px-3.5 py-2 bg-gradient-to-r from-red-950 to-orange-950 hover:from-red-900 hover:to-orange-900 border border-red-700/60 text-red-200 rounded-xl text-xs font-semibold shadow-lg shadow-red-950/50 transition-all cursor-pointer"
                title="Simulate J. Singh multi-signal attack chain (Critical risk incident)"
              >
                <Flame size={14} className="text-red-400 fill-red-400" />
                <span>Test Threat Chain</span>
              </button>
            )}
          </div>
        </div>
      </div>

      {error && <ErrorBanner title="Telemetry Error" message={error} onRetry={onRefresh} />}

      {/* Behavioral Signals Matrix */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Behavioral Threat Signal Indicators
          </div>
          <span className="text-xs font-mono text-slate-500">
            Active Signals Tracked: {threatSignalsCatalog.filter(s => s.count > 0).length} of {threatSignalsCatalog.length}
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2.5">
          {threatSignalsCatalog.map((sig) => {
            const isActive = sig.count > 0;
            const isSelected = filterSignal === sig.key;
            return (
              <button
                key={sig.key}
                onClick={() => setFilterSignal(isSelected ? 'ALL' : sig.key)}
                className={`p-3 rounded-xl border flex flex-col justify-between text-left transition-all cursor-pointer ${
                  isSelected
                    ? 'bg-red-950/80 border-red-500 text-white ring-2 ring-red-500/30 shadow-lg shadow-red-950/50'
                    : isActive
                    ? 'bg-amber-950/40 border-amber-700/60 text-amber-200 hover:border-amber-500 shadow-sm shadow-amber-950/30'
                    : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] font-mono font-bold tracking-wider">{sig.label}</span>
                  <span className={`text-[10px] font-bold font-mono px-1.5 py-0.5 rounded ${
                    isActive ? 'bg-amber-900/80 text-amber-300' : 'bg-slate-800 text-slate-500'
                  }`}>
                    {sig.count}
                  </span>
                </div>
                <span className="text-[10px] text-slate-400 line-clamp-1">{sig.desc}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Featured Internal Threat Incident & Attack Chain Analysis */}
      {featuredIncident ? (
        <Card className="p-6 bg-gradient-to-br from-slate-900 via-slate-900/95 to-red-950/20 border border-slate-800 shadow-xl space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
            <div className="flex items-center gap-3">
              <span className="font-mono text-base font-bold text-white">
                Incident: {featuredIncident.id}
              </span>
              <span className="text-xs text-slate-400">
                Affected User: <strong className="text-cyan-300">{featuredIncident.primary_entity}</strong>
              </span>
              <RiskBadge
                level={featuredIncident.risk_assessment?.risk_level || 'LOW'}
                score={featuredIncident.risk_assessment?.risk_score}
              />
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setTab('graph')}
                className="px-3 py-1.5 text-xs font-medium text-cyan-400 hover:text-cyan-300 bg-cyan-950/40 hover:bg-cyan-950/80 border border-cyan-800/50 rounded-lg transition-colors cursor-pointer flex items-center gap-1"
              >
                <span>Open User Graph</span>
                <ChevronRight size={13} />
              </button>
              <button
                onClick={() => {
                  if (onSelectIncident) onSelectIncident(featuredIncident);
                  setTab('incidents');
                }}
                className="px-3 py-1.5 text-xs font-medium text-amber-300 hover:text-amber-200 bg-amber-950/40 hover:bg-amber-950/80 border border-amber-800/50 rounded-lg transition-colors cursor-pointer flex items-center gap-1"
              >
                <span>Investigate Incident</span>
                <ChevronRight size={13} />
              </button>
            </div>
          </div>

          {/* Attack / Activity Chain Progression */}
          <div>
            <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-2.5">
              Correlated Multi-Step Activity Chain (Unified Behavioral Session)
            </div>
            <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
              <span className="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-200 border border-slate-700 flex items-center gap-1.5">
                <User size={13} className="text-cyan-400" />
                USER ({featuredIncident.primary_entity})
              </span>
              <ChevronRight size={14} className="text-slate-600 shrink-0" />
              <span className="px-3 py-1.5 rounded-lg bg-blue-950/60 text-blue-300 border border-blue-800/60">
                LOGIN
              </span>
              <ChevronRight size={14} className="text-slate-600 shrink-0" />
              <span className="px-3 py-1.5 rounded-lg bg-amber-950/70 text-amber-300 border border-amber-800/60">
                NEW DEVICE
              </span>
              <ChevronRight size={14} className="text-slate-600 shrink-0" />
              <span className="px-3 py-1.5 rounded-lg bg-amber-950/70 text-amber-300 border border-amber-800/60">
                NEW IP
              </span>
              <ChevronRight size={14} className="text-slate-600 shrink-0" />
              <span className="px-3 py-1.5 rounded-lg bg-orange-950/70 text-orange-300 border border-orange-800/60">
                SENSITIVE API
              </span>
              <ChevronRight size={14} className="text-slate-600 shrink-0" />
              <span className="px-3 py-1.5 rounded-lg bg-red-950/80 text-red-300 border border-red-800/70 font-bold">
                BULK DATA ACCESS
              </span>
            </div>
          </div>

          {/* Plain-English Explanation: WHY is this sequence risky? */}
          <div className="p-4 rounded-xl bg-red-950/20 border border-red-900/40 text-xs space-y-2">
            <div className="font-semibold text-red-400 flex items-center gap-1.5">
              <AlertTriangle size={14} />
              <span>Correlation Engine Rationales (WHY is this sequence risky?):</span>
            </div>
            <div className="text-slate-300 leading-relaxed space-y-1.5">
              {featuredIncident.risk_assessment?.reasons?.map((reason, idx) => (
                <div key={idx} className="flex items-start gap-2">
                  <span className="text-red-400 font-bold">•</span>
                  <span>{reason}</span>
                </div>
              )) || (
                <p>
                  New IP and New Device alone remain contextual (LOW risk). When combined with off-hours authentication, high-sensitivity API invocation, and bulk database queries, the multi-signal correlation engine escalates to High/Critical risk.
                </p>
              )}
            </div>
            {featuredIncident.risk_assessment?.recommended_action && (
              <div className="mt-3 pt-2.5 border-t border-red-900/30 text-amber-300 font-medium flex items-center gap-1.5">
                <CheckCircle2 size={13} className="text-amber-400" />
                <span>Recommended Action: {featuredIncident.risk_assessment.recommended_action}</span>
              </div>
            )}
          </div>
        </Card>
      ) : (
        <Card className="p-8 text-center bg-slate-900/50 border border-slate-800">
          <p className="text-slate-400 text-sm">No internal threat incidents detected yet.</p>
          <p className="text-slate-500 text-xs mt-1">Use the "Test Threat Chain" button above to simulate multi-signal insider activity.</p>
        </Card>
      )}

      {/* Filterable Table of Correlated Internal Incidents */}
      <Card className="p-6 bg-slate-900/90 border border-slate-800 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <Filter size={15} className="text-cyan-400" />
            <h3 className="text-sm font-bold text-white tracking-wide">
              Correlated Internal Threat Sessions ({filteredIncidents.length})
            </h3>
          </div>
          {filterSignal !== 'ALL' && (
            <button
              onClick={() => setFilterSignal('ALL')}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-mono underline cursor-pointer"
            >
              Reset Filter
            </button>
          )}
        </div>

        {filteredIncidents.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="text-[11px] text-slate-400 uppercase font-mono border-b border-slate-800">
                <tr>
                  <th className="pb-2.5">Incident ID</th>
                  <th className="pb-2.5">User / Entity</th>
                  <th className="pb-2.5">Risk Score</th>
                  <th className="pb-2.5">Signals Detected</th>
                  <th className="pb-2.5">Status</th>
                  <th className="pb-2.5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {filteredIncidents.map((inc) => (
                  <tr key={inc.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3 font-semibold text-white">{inc.id}</td>
                    <td className="py-3 text-cyan-300 font-sans font-medium">{inc.primary_entity}</td>
                    <td className="py-3">
                      <RiskBadge
                        level={inc.risk_assessment?.risk_level || 'LOW'}
                        score={inc.risk_assessment?.risk_score}
                      />
                    </td>
                    <td className="py-3 font-sans">
                      <div className="flex flex-wrap gap-1">
                        {(inc.signals_detected || []).map((s, i) => (
                          <span key={i} className="px-1.5 py-0.5 text-[10px] rounded bg-slate-800 text-slate-300 border border-slate-700">
                            {s}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="py-3">
                      <StatusBadge status={inc.status || 'ACTIVE'} />
                    </td>
                    <td className="py-3 text-right font-sans">
                      <button
                        onClick={() => {
                          if (onSelectIncident) onSelectIncident(inc);
                          setTab('incidents');
                        }}
                        className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs transition-colors cursor-pointer"
                      >
                        Investigate
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-6 text-center text-slate-500 text-xs">
            No incidents matching the active filter.
          </div>
        )}
      </Card>
    </div>
  );
}
