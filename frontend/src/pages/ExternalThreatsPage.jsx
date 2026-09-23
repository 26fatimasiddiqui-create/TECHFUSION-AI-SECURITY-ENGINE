import React, { useState } from 'react';
import { 
  Globe, 
  Activity, 
  Flame, 
  AlertTriangle, 
  ChevronRight, 
  ShieldCheck, 
  Terminal, 
  Bot, 
  Database,
  Filter,
  CheckCircle2,
  Server,
  Lock
} from 'lucide-react';
import { Card } from '../components/common/Card';
import { RiskBadge, StatusBadge } from '../components/common/Badge';
import { LoadingSpinner } from '../components/common/LoadingSpinner';
import { ErrorBanner } from '../components/common/ErrorBanner';

export function ExternalThreatsPage({
  incidents = [],
  events = [],
  isLoading = false,
  error = null,
  onRefresh,
  onSelectIncident,
  setTab,
  onRunExternalNormal,
  onRunExternalAttack,
}) {
  const [filterSignal, setFilterSignal] = useState('ALL');

  // Derive all signals
  const allSignals = incidents.flatMap(i => i.signals_detected || []);
  const externalSignalsCatalog = [
    { key: 'brute_force_login', label: 'BRUTE FORCE', count: allSignals.filter(s => s === 'brute_force_login').length, desc: 'Repeated auth failures' },
    { key: 'credential_stuffing', label: 'CRED STUFFING', count: allSignals.filter(s => s === 'credential_stuffing').length, desc: 'Automated list test' },
    { key: 'password_spraying', label: 'PWD SPRAYING', count: allSignals.filter(s => s === 'password_spraying').length, desc: 'Single IP -> multi-user' },
    { key: 'distributed_attack', label: 'DISTRIBUTED', count: allSignals.filter(s => s === 'distributed_attack').length, desc: 'Multi-IP coordination' },
    { key: 'suspicious_external_ip', label: 'THREAT INTEL IP', count: allSignals.filter(s => s === 'suspicious_external_ip').length, desc: 'Tor / malicious proxy' },
    { key: 'api_abuse', label: 'API ABUSE', count: allSignals.filter(s => s === 'api_abuse').length, desc: 'Rate-limit / 403 bursts' },
    { key: 'prompt_injection', label: 'PROMPT INJECTION', count: allSignals.filter(s => s === 'prompt_injection').length, desc: 'System override / DAN' },
    { key: 'indirect_prompt_injection', label: 'INDIRECT INJECTION', count: allSignals.filter(s => s === 'indirect_prompt_injection').length, desc: 'Tainted doc payload' },
    { key: 'agent_privilege_abuse', label: 'AGENT PRIV ABUSE', count: allSignals.filter(s => s === 'agent_privilege_abuse').length, desc: 'Restricted system tool' },
    { key: 'data_exfiltration', label: 'DATA EXFILTRATION', count: allSignals.filter(s => s === 'data_exfiltration').length, desc: 'Outbound transfer' },
  ];

  // External threat incidents
  const externalIncidents = incidents.filter(i => 
    (i.signals_detected || []).some(s => [
      'brute_force_login', 'credential_stuffing', 'password_spraying', 'distributed_attack',
      'suspicious_external_ip', 'api_abuse', 'prompt_injection', 'indirect_prompt_injection',
      'agent_privilege_abuse', 'data_exfiltration', 'external_attack_chain'
    ].includes(s))
  );

  const filteredIncidents = filterSignal === 'ALL'
    ? externalIncidents
    : externalIncidents.filter(i => (i.signals_detected || []).includes(filterSignal));

  const featuredIncident = externalIncidents[0] || incidents[0];

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-900/95 to-purple-950/30 border border-slate-800 rounded-2xl p-6 shadow-xl relative overflow-hidden">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="p-1.5 rounded-lg bg-purple-950/80 border border-purple-800/50 text-purple-400">
                <Globe size={20} />
              </span>
              <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
                External Threats & Perimeter Attack Detection
              </h1>
              <span className="px-2.5 py-0.5 rounded text-[10px] font-mono uppercase tracking-wider bg-purple-950/80 text-purple-300 border border-purple-800/50">
                Perimeter Defense
              </span>
            </div>
            <p className="text-xs sm:text-sm text-slate-400 max-w-3xl leading-relaxed">
              Detects attacks originating from external/untrusted sources (Brute Force, Credential Stuffing, API Abuse, Prompt Injection, Exfiltration) and correlates them with internal users, AI agents, tools, and databases into a unified incident.
            </p>
          </div>

          {/* Interactive Simulation Triggers */}
          <div className="flex items-center gap-2 shrink-0">
            {onRunExternalNormal && (
              <button
                onClick={onRunExternalNormal}
                className="flex items-center gap-1.5 px-3.5 py-2 bg-emerald-950/60 hover:bg-emerald-900/60 border border-emerald-700/50 text-emerald-300 rounded-xl text-xs font-semibold transition-all cursor-pointer shadow-lg shadow-emerald-950/30"
                title="Simulate David Miller benign external access (Valid login, legitimate prompt, low risk)"
              >
                <Activity size={14} className="text-emerald-400" />
                <span>Test External Benign</span>
              </button>
            )}
            {onRunExternalAttack && (
              <button
                onClick={onRunExternalAttack}
                className="flex items-center gap-1.5 px-3.5 py-2 bg-gradient-to-r from-purple-950 to-pink-950 hover:from-purple-900 hover:to-pink-900 border border-purple-700/60 text-purple-200 rounded-xl text-xs font-semibold shadow-lg shadow-purple-950/50 transition-all cursor-pointer"
                title="Simulate coordinated external attack chain (Critical risk incident)"
              >
                <Flame size={14} className="text-purple-400 fill-purple-400" />
                <span>Test External Attack Chain</span>
              </button>
            )}
          </div>
        </div>
      </div>

      {error && <ErrorBanner title="Telemetry Error" message={error} onRetry={onRefresh} />}

      {/* External Signals Matrix */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            External Threat Signal Indicators
          </div>
          <span className="text-xs font-mono text-slate-500">
            Active Signals Tracked: {externalSignalsCatalog.filter(s => s.count > 0).length} of {externalSignalsCatalog.length}
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5">
          {externalSignalsCatalog.map((sig) => {
            const isActive = sig.count > 0;
            const isSelected = filterSignal === sig.key;
            return (
              <button
                key={sig.key}
                onClick={() => setFilterSignal(isSelected ? 'ALL' : sig.key)}
                className={`p-3 rounded-xl border flex flex-col justify-between text-left transition-all cursor-pointer ${
                  isSelected
                    ? 'bg-purple-950/80 border-purple-500 text-white ring-2 ring-purple-500/30 shadow-lg shadow-purple-950/50'
                    : isActive
                    ? 'bg-purple-950/40 border-purple-700/60 text-purple-200 hover:border-purple-500 shadow-sm shadow-purple-950/30'
                    : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] font-mono font-bold tracking-wider">{sig.label}</span>
                  <span className={`text-[10px] font-bold font-mono px-1.5 py-0.5 rounded ${
                    isActive ? 'bg-purple-900/80 text-purple-300' : 'bg-slate-800 text-slate-500'
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

      {/* Featured External Threat Incident & Coordinated Attack Chain */}
      {featuredIncident ? (
        <Card className="p-6 bg-gradient-to-br from-slate-900 via-slate-900/95 to-purple-950/20 border border-slate-800 shadow-xl space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/60 pb-4">
            <div className="flex items-center gap-3">
              <span className="font-mono text-base font-bold text-white">
                Incident: {featuredIncident.id}
              </span>
              <span className="text-xs text-slate-400">
                Targeted Entity: <strong className="text-purple-300">{featuredIncident.primary_entity}</strong>
              </span>
              <RiskBadge
                level={featuredIncident.risk_assessment?.risk_level || 'LOW'}
                score={featuredIncident.risk_assessment?.risk_score}
              />
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => {
                  if (onSelectIncident) onSelectIncident(featuredIncident);
                  setTab('incidents');
                }}
                className="px-3 py-1.5 text-xs font-medium text-purple-300 hover:text-purple-200 bg-purple-950/40 hover:bg-purple-950/80 border border-purple-800/50 rounded-lg transition-colors cursor-pointer flex items-center gap-1"
              >
                <span>Investigate Incident</span>
                <ChevronRight size={13} />
              </button>
            </div>
          </div>

          {/* External Attack Chain Progression */}
          <div>
            <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-2.5">
              Coordinated Attack Progression (Unified Incident Correlation)
            </div>
            <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
              <span className="px-3 py-1.5 rounded-lg bg-purple-950/70 text-purple-300 border border-purple-800/60 flex items-center gap-1.5">
                <Globe size={13} className="text-purple-400" />
                EXTERNAL IP
              </span>
              <ChevronRight size={14} className="text-slate-600 shrink-0" />
              <span className="px-3 py-1.5 rounded-lg bg-red-950/60 text-red-300 border border-red-800/60">
                LOGIN ATTACK
              </span>
              <ChevronRight size={14} className="text-slate-600 shrink-0" />
              <span className="px-3 py-1.5 rounded-lg bg-blue-950/60 text-blue-300 border border-blue-800/60">
                SESSION TAKEOVER
              </span>
              <ChevronRight size={14} className="text-slate-600 shrink-0" />
              <span className="px-3 py-1.5 rounded-lg bg-amber-950/70 text-amber-300 border border-amber-800/60 flex items-center gap-1.5">
                <Bot size={13} className="text-amber-400" />
                PROMPT INJECTION
              </span>
              <ChevronRight size={14} className="text-slate-600 shrink-0" />
              <span className="px-3 py-1.5 rounded-lg bg-orange-950/70 text-orange-300 border border-orange-800/60">
                AGENT PRIV PRIVILEGE
              </span>
              <ChevronRight size={14} className="text-slate-600 shrink-0" />
              <span className="px-3 py-1.5 rounded-lg bg-red-950/80 text-red-300 border border-red-800/70 font-bold flex items-center gap-1.5">
                <Database size={13} className="text-red-400" />
                DATA EXFILTRATION
              </span>
            </div>
          </div>

          {/* Plain-English Explanation: WHY is this sequence risky? */}
          <div className="p-4 rounded-xl bg-purple-950/20 border border-purple-900/40 text-xs space-y-2">
            <div className="font-semibold text-purple-400 flex items-center gap-1.5">
              <AlertTriangle size={14} />
              <span>Perimeter & Agent Intelligence Rationales:</span>
            </div>
            <div className="text-slate-300 leading-relaxed space-y-1.5">
              {featuredIncident.risk_assessment?.reasons?.map((reason, idx) => (
                <div key={idx} className="flex items-start gap-2">
                  <span className="text-purple-400 font-bold">•</span>
                  <span>{reason}</span>
                </div>
              )) || (
                <p>
                  Single failed logins or external IPs alone remain contextual (LOW risk). When correlated with automated brute-force attacks, AI agent prompt injection, restricted tool execution, and outbound data transfer, the system classifies the sequence as a Critical coordinated attack chain.
                </p>
              )}
            </div>
            {featuredIncident.risk_assessment?.recommended_action && (
              <div className="mt-3 pt-2.5 border-t border-purple-900/30 text-amber-300 font-medium flex items-center gap-1.5">
                <CheckCircle2 size={13} className="text-amber-400" />
                <span>Recommended Action: {featuredIncident.risk_assessment.recommended_action}</span>
              </div>
            )}
          </div>
        </Card>
      ) : (
        <Card className="p-8 text-center bg-slate-900/50 border border-slate-800">
          <p className="text-slate-400 text-sm">No external threat incidents detected yet.</p>
          <p className="text-slate-500 text-xs mt-1">Use the "Test External Attack Chain" button above to simulate a multi-step external perimeter attack.</p>
        </Card>
      )}

      {/* Filterable Table of Correlated External Incidents */}
      <Card className="p-6 bg-slate-900/90 border border-slate-800 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <Filter size={15} className="text-purple-400" />
            <h3 className="text-sm font-bold text-white tracking-wide">
              Correlated External Threat Sessions ({filteredIncidents.length})
            </h3>
          </div>
          {filterSignal !== 'ALL' && (
            <button
              onClick={() => setFilterSignal('ALL')}
              className="text-xs text-purple-400 hover:text-purple-300 font-mono underline cursor-pointer"
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
                  <th className="pb-2.5">Target Entity</th>
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
                    <td className="py-3 text-purple-300 font-sans font-medium">{inc.primary_entity}</td>
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
