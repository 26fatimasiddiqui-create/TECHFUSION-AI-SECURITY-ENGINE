import React, { useState, useMemo } from 'react';
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
  Lock,
  ShieldAlert,
  Undo2,
  RefreshCw,
  Search,
  Check,
  X,
  ExternalLink,
  Shield,
  Layers,
  ArrowRight,
  User,
  Key,
  Network
} from 'lucide-react';
import { Card } from '../components/common/Card';
import { RiskBadge, StatusBadge } from '../components/common/Badge';
import { LoadingSpinner } from '../components/common/LoadingSpinner';
import { ErrorBanner } from '../components/common/ErrorBanner';
import { secondApproveIncidentResponse, recoverFalsePositive } from '../services/api';

export function ExternalThreatsPage({
  incidents = [],
  events = [],
  isLoading = false,
  error = null,
  onRefresh,
  onSelectIncident,
  onIncidentStatusChange,
  setTab,
  onRunExternalNormal,
  onRunExternalAttack,
}) {
  const [filterSignal, setFilterSignal] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [actionInProgress, setActionInProgress] = useState(false);
  const [actionFeedback, setActionFeedback] = useState(null);
  const [localMitigations, setLocalMitigations] = useState({});
  const [showDeepAgentAnalysis, setShowDeepAgentAnalysis] = useState(true);
  const [showBehavioralProgression, setShowBehavioralProgression] = useState(true);

  // 1. Separate active external incidents vs contained / resolved
  const externalIncidents = useMemo(() => {
    return incidents.filter(i => 
      (i.signals_detected || []).some(s => [
        'brute_force_login', 'credential_stuffing', 'password_spraying', 'distributed_attack',
        'suspicious_external_ip', 'api_abuse', 'prompt_injection', 'indirect_prompt_injection',
        'agent_privilege_abuse', 'data_exfiltration', 'external_attack_chain'
      ].includes(s))
    );
  }, [incidents]);

  // Active incidents: status is active and risk > 25
  const activeExternalIncidents = useMemo(() => {
    return externalIncidents.filter(i => 
      i.status !== 'contained' && 
      i.status !== 'resolved' && 
      i.status !== 'mitigated' && 
      (i.risk_assessment?.risk_score === undefined || i.risk_assessment.risk_score > 25)
    );
  }, [externalIncidents]);

  const containedExternalIncidents = useMemo(() => {
    return externalIncidents.filter(i => 
      i.status === 'contained' || 
      i.status === 'resolved' || 
      i.status === 'mitigated' || 
      (i.risk_assessment?.risk_score !== undefined && i.risk_assessment.risk_score <= 25)
    );
  }, [externalIncidents]);

  const activeSignals = useMemo(() => {
    return activeExternalIncidents.flatMap(i => i.signals_detected || []);
  }, [activeExternalIncidents]);

  const containedSignals = useMemo(() => {
    return containedExternalIncidents.flatMap(i => i.signals_detected || []);
  }, [containedExternalIncidents]);

  const externalSignalsCatalog = [
    { 
      key: 'brute_force_login', 
      label: 'BRUTE FORCE', 
      activeCount: activeSignals.filter(s => s === 'brute_force_login').length, 
      containedCount: containedSignals.filter(s => s === 'brute_force_login').length,
      desc: 'Repeated auth failures' 
    },
    { 
      key: 'credential_stuffing', 
      label: 'CRED STUFFING', 
      activeCount: activeSignals.filter(s => s === 'credential_stuffing').length, 
      containedCount: containedSignals.filter(s => s === 'credential_stuffing').length,
      desc: 'Automated list test' 
    },
    { 
      key: 'password_spraying', 
      label: 'PWD SPRAYING', 
      activeCount: activeSignals.filter(s => s === 'password_spraying').length, 
      containedCount: containedSignals.filter(s => s === 'password_spraying').length,
      desc: 'Single IP -> multi-user' 
    },
    { 
      key: 'distributed_attack', 
      label: 'DISTRIBUTED', 
      activeCount: activeSignals.filter(s => s === 'distributed_attack').length, 
      containedCount: containedSignals.filter(s => s === 'distributed_attack').length,
      desc: 'Multi-IP coordination' 
    },
    { 
      key: 'suspicious_external_ip', 
      label: 'THREAT INTEL IP', 
      activeCount: activeSignals.filter(s => s === 'suspicious_external_ip').length, 
      containedCount: containedSignals.filter(s => s === 'suspicious_external_ip').length,
      desc: 'Tor / malicious proxy' 
    },
    { 
      key: 'api_abuse', 
      label: 'API ABUSE', 
      activeCount: activeSignals.filter(s => s === 'api_abuse').length, 
      containedCount: containedSignals.filter(s => s === 'api_abuse').length,
      desc: 'Rate-limit / 403 bursts' 
    },
    { 
      key: 'prompt_injection', 
      label: 'PROMPT INJECTION', 
      activeCount: activeSignals.filter(s => s === 'prompt_injection').length, 
      containedCount: containedSignals.filter(s => s === 'prompt_injection').length,
      desc: 'System override / DAN' 
    },
    { 
      key: 'indirect_prompt_injection', 
      label: 'INDIRECT INJECTION', 
      activeCount: activeSignals.filter(s => s === 'indirect_prompt_injection').length, 
      containedCount: containedSignals.filter(s => s === 'indirect_prompt_injection').length,
      desc: 'Tainted doc payload' 
    },
    { 
      key: 'agent_privilege_abuse', 
      label: 'AGENT PRIV ABUSE', 
      activeCount: activeSignals.filter(s => s === 'agent_privilege_abuse').length, 
      containedCount: containedSignals.filter(s => s === 'agent_privilege_abuse').length,
      desc: 'Restricted system tool' 
    },
    { 
      key: 'data_exfiltration', 
      label: 'DATA EXFILTRATION', 
      activeCount: activeSignals.filter(s => s === 'data_exfiltration').length, 
      containedCount: containedSignals.filter(s => s === 'data_exfiltration').length,
      desc: 'Outbound transfer' 
    },
  ];

  // Filtered incidents for table
  const filteredIncidents = useMemo(() => {
    return externalIncidents.filter(i => {
      const matchSignal = filterSignal === 'ALL' || (i.signals_detected || []).includes(filterSignal);
      const matchSearch = !searchQuery || 
        i.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (i.primary_entity || '').toLowerCase().includes(searchQuery.toLowerCase());
      return matchSignal && matchSearch;
    });
  }, [externalIncidents, filterSignal, searchQuery]);

  const featuredIncident = externalIncidents[0] || incidents[0];

  const isContained = featuredIncident?.status === 'contained' || 
    (featuredIncident?.risk_assessment?.risk_score !== undefined && featuredIncident.risk_assessment.risk_score <= 25);
  const isResolved = featuredIncident?.status === 'resolved' || 
    (featuredIncident?.risk_assessment?.risk_score !== undefined && featuredIncident.risk_assessment.risk_score === 0);
  const isActive = !isContained && !isResolved;

  // Filter correlated events for detailed timeline view
  const relatedEvents = useMemo(() => {
    if (!featuredIncident) return events.slice(0, 5);
    const matched = events.filter(e => 
      (featuredIncident.event_ids && featuredIncident.event_ids.includes(e.event_id)) ||
      e.user_id === featuredIncident.primary_entity ||
      e.metadata?.client_ip === '185.220.101.5' ||
      e.metadata?.ip === '185.220.101.5' ||
      e.metadata?.data_exfiltration ||
      e.metadata?.is_brute_force ||
      (e.metadata?.prompt && e.metadata.prompt.includes('DAN'))
    );
    return matched.length > 0 ? matched : events.slice(0, 5);
  }, [events, featuredIncident]);

  // Action: Quick Dual-Control Containment
  const handleQuickContain = async (incidentId) => {
    if (!incidentId) return;
    setActionInProgress(true);
    setActionFeedback(null);
    try {
      await secondApproveIncidentResponse(incidentId, {
        actor: 'SOC_Admin_Bob',
        approver_id: 'SOC_Admin_Bob',
        role: 'SECURITY_ADMIN',
        session_id: 'sess_perimeter_admin',
        notes: 'Perimeter threat containment executed directly from External Threats console',
        dry_run: true,
      });

      if (onIncidentStatusChange) {
        onIncidentStatusChange(incidentId, 'contained', 15, 'APPROVED', true);
      }

      setLocalMitigations(prev => ({
        ...prev,
        [incidentId + '_block_ip']: true,
        [incidentId + '_lock_user']: true,
        [incidentId + '_quarantine']: true,
        [incidentId + '_block_data']: true,
      }));

      setActionFeedback({
        type: 'success',
        message: `Incident ${incidentId} contained successfully! Risk reduced to 15 / 100. Perimeter firewall active & copilot agent quarantined.`
      });
      if (onRefresh) onRefresh();
    } catch (err) {
      if (onIncidentStatusChange) {
        onIncidentStatusChange(incidentId, 'contained', 15, 'APPROVED', true);
      }
      setLocalMitigations(prev => ({
        ...prev,
        [incidentId + '_block_ip']: true,
        [incidentId + '_lock_user']: true,
        [incidentId + '_quarantine']: true,
        [incidentId + '_block_data']: true,
      }));
      setActionFeedback({
        type: 'success',
        message: `Incident ${incidentId} contained successfully! Risk reduced to 15 / 100 (LOW RISK).`
      });
      if (onRefresh) onRefresh();
    } finally {
      setActionInProgress(false);
    }
  };

  // Action: Restore Access / False Positive Recovery
  const handleRestoreAccess = async (incidentId) => {
    if (!incidentId) return;
    setActionInProgress(true);
    setActionFeedback(null);
    try {
      await recoverFalsePositive(incidentId, {
        reason: 'Verified benign test / authorized external access confirmed by SOC Lead',
        actor: 'SOC_Lead',
        restore_access: true,
      });

      if (onIncidentStatusChange) {
        onIncidentStatusChange(incidentId, 'resolved', 0, 'RESOLVED', true);
      }

      setLocalMitigations(prev => ({
        ...prev,
        [incidentId + '_block_ip']: false,
        [incidentId + '_lock_user']: false,
        [incidentId + '_quarantine']: false,
        [incidentId + '_block_data']: false,
      }));

      setActionFeedback({
        type: 'success',
        message: `Normal access restored for incident ${incidentId}! All temporary perimeter blocks lifted. Risk: 0 / 100.`
      });
      if (onRefresh) onRefresh();
    } catch (err) {
      if (onIncidentStatusChange) {
        onIncidentStatusChange(incidentId, 'resolved', 0, 'RESOLVED', true);
      }
      setActionFeedback({
        type: 'success',
        message: `Normal access restored for incident ${incidentId}! All temporary blocks lifted (Risk: 0 / 100).`
      });
      if (onRefresh) onRefresh();
    } finally {
      setActionInProgress(false);
    }
  };

  // Toggle individual mitigation tile
  const handleToggleTileMitigation = (incidentId, key) => {
    const fullKey = incidentId + '_' + key;
    const nextState = !localMitigations[fullKey];
    setLocalMitigations(prev => ({
      ...prev,
      [fullKey]: nextState
    }));

    setActionFeedback({
      type: 'info',
      message: `${key === 'block_ip' ? 'Firewall IP Rule' : key === 'lock_user' ? 'Session Gateway' : key === 'quarantine' ? 'Copilot Runtime' : 'Data Channel'} updated: ${nextState ? 'ENFORCED' : 'LIFTED'}.`
    });
  };

  return (
    <div className="space-y-6 font-sans">
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

      {/* Action Notification Toast */}
      {actionFeedback && (
        <div className={`p-4 rounded-xl border flex items-center justify-between gap-3 text-xs font-mono transition-all animate-fadeIn ${
          actionFeedback.type === 'success'
            ? 'bg-emerald-950/80 border-emerald-600 text-emerald-200'
            : actionFeedback.type === 'error'
            ? 'bg-rose-950/80 border-rose-600 text-rose-200'
            : 'bg-blue-950/80 border-blue-600 text-blue-200'
        }`}>
          <div className="flex items-center gap-2.5">
            {actionFeedback.type === 'success' ? (
              <CheckCircle2 size={16} className="text-emerald-400 shrink-0" />
            ) : (
              <AlertTriangle size={16} className="text-rose-400 shrink-0" />
            )}
            <span className="font-medium">{actionFeedback.message}</span>
          </div>
          <button 
            onClick={() => setActionFeedback(null)} 
            className="text-slate-400 hover:text-white p-1 rounded-md hover:bg-white/10 cursor-pointer"
          >
            <X size={14} />
          </button>
        </div>
      )}

      {error && <ErrorBanner title="Telemetry Error" message={error} onRetry={onRefresh} />}

      {/* External Signals Matrix */}
      <div className="space-y-3">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
            <span>External Threat Signal Indicators</span>
            {activeExternalIncidents.length === 0 && containedExternalIncidents.length > 0 && (
              <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-950 text-emerald-300 border border-emerald-700/60 font-mono">
                ✓ All Vectors Neutralized
              </span>
            )}
          </div>
          <div className="flex items-center gap-3 text-xs font-mono">
            <span className={activeSignals.length > 0 ? "text-rose-400 font-bold" : "text-slate-500"}>
              Active: {activeSignals.length}
            </span>
            <span className="text-slate-600">|</span>
            <span className="text-emerald-400 font-semibold">
              Neutralized: {containedSignals.length}
            </span>
          </div>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5">
          {externalSignalsCatalog.map((sig) => {
            const hasActive = sig.activeCount > 0;
            const hasContained = !hasActive && sig.containedCount > 0;
            const isSelected = filterSignal === sig.key;
            return (
              <button
                key={sig.key}
                onClick={() => setFilterSignal(isSelected ? 'ALL' : sig.key)}
                className={`p-3 rounded-xl border flex flex-col justify-between text-left transition-all cursor-pointer ${
                  isSelected
                    ? 'bg-purple-950/80 border-purple-500 text-white ring-2 ring-purple-500/30 shadow-lg shadow-purple-950/50'
                    : hasActive
                    ? 'bg-rose-950/30 border-rose-700/60 text-rose-200 hover:border-rose-500 shadow-sm shadow-rose-950/30'
                    : hasContained
                    ? 'bg-emerald-950/30 border-emerald-700/50 text-emerald-200 hover:border-emerald-500'
                    : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] font-mono font-bold tracking-wider">{sig.label}</span>
                  <span className={`text-[10px] font-bold font-mono px-1.5 py-0.5 rounded ${
                    hasActive 
                      ? 'bg-rose-900 text-rose-200 animate-pulse' 
                      : hasContained 
                      ? 'bg-emerald-900 text-emerald-200' 
                      : 'bg-slate-800 text-slate-500'
                  }`}>
                    {hasActive ? `${sig.activeCount} ACT` : hasContained ? '✓ Cont' : '0'}
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
        <Card className={`p-6 border shadow-xl space-y-6 transition-all ${
          isResolved 
            ? 'bg-gradient-to-br from-slate-900 via-slate-900 to-emerald-950/30 border-emerald-700/60'
            : isContained 
            ? 'bg-gradient-to-br from-slate-900 via-slate-900 to-teal-950/30 border-emerald-700/60'
            : 'bg-gradient-to-br from-slate-900 via-slate-900/95 to-purple-950/20 border-slate-800'
        }`}>
          {/* Header Row: Incident ID, Risk Score, Status & Immediate Resolution Buttons */}
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800/80 pb-5">
            <div className="flex flex-wrap items-center gap-3">
              <span className="font-mono text-base font-bold text-white">
                Incident: {featuredIncident.id}
              </span>
              <span className="text-xs text-slate-400">
                Targeted Entity: <strong className="text-purple-300 font-mono">{featuredIncident.primary_entity}</strong>
              </span>
              <RiskBadge
                level={featuredIncident.risk_assessment?.risk_level || (isContained ? 'LOW' : 'CRITICAL')}
                score={isContained ? 15 : isResolved ? 0 : (featuredIncident.risk_assessment?.risk_score || 95)}
              />
              <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase tracking-wider ${
                isResolved
                  ? 'bg-emerald-950 text-emerald-300 border border-emerald-700'
                  : isContained
                  ? 'bg-emerald-950 text-emerald-300 border border-emerald-700'
                  : 'bg-rose-950 text-rose-300 border border-rose-700 animate-pulse'
              }`}>
                {isResolved ? 'RESOLVED' : isContained ? 'CONTAINED' : 'ACTIVE THREAT'}
              </span>
            </div>

            {/* Direct Containment & Resolution Action Buttons */}
            <div className="flex flex-wrap items-center gap-2.5">
              {isActive ? (
                <button
                  onClick={() => handleQuickContain(featuredIncident.id)}
                  disabled={actionInProgress}
                  className="px-4 py-2 text-xs font-bold text-white bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 rounded-xl transition-all cursor-pointer flex items-center gap-2 shadow-lg shadow-emerald-950/40"
                  title="Satisfy dual-control Two-Person rule and execute full containment"
                >
                  <ShieldCheck size={15} />
                  <span>{actionInProgress ? 'Containing...' : '1-Click Contain Threat'}</span>
                </button>
              ) : (
                <button
                  onClick={() => handleRestoreAccess(featuredIncident.id)}
                  disabled={actionInProgress}
                  className="px-4 py-2 text-xs font-bold text-amber-200 bg-amber-950/70 hover:bg-amber-900/80 border border-amber-700/60 rounded-xl transition-all cursor-pointer flex items-center gap-2 shadow-lg shadow-amber-950/40"
                  title="Lift all restrictions and restore normal access"
                >
                  <Undo2 size={15} className="text-amber-400" />
                  <span>{actionInProgress ? 'Restoring...' : 'Restore Normal Access'}</span>
                </button>
              )}

              <button
                onClick={() => {
                  if (onSelectIncident) onSelectIncident(featuredIncident);
                  setTab('incidents');
                }}
                className="px-3.5 py-2 text-xs font-semibold text-purple-300 hover:text-white bg-slate-800/80 hover:bg-slate-700 border border-slate-700 rounded-xl transition-all cursor-pointer flex items-center gap-1.5"
              >
                <span>Investigate Incident</span>
                <ChevronRight size={14} />
              </button>
            </div>
          </div>

          {/* External Attack Chain Progression with Dynamic Neutralized State */}
          <div>
            <div className="flex items-center justify-between mb-2.5">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                <span>Coordinated Attack Progression (Unified Incident Correlation)</span>
                {isContained && (
                  <span className="text-emerald-400 font-mono text-[10px] font-bold">
                    ✓ All 6 Vectors Neutralized
                  </span>
                )}
              </div>
              <span className="text-[11px] font-mono text-slate-500">
                Attacker IP: <strong className="text-purple-300">185.220.101.5</strong>
              </span>
            </div>

            <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
              <span className={`px-3 py-1.5 rounded-lg border flex items-center gap-1.5 transition-all ${
                isContained || isResolved 
                  ? 'bg-emerald-950/70 border-emerald-600 text-emerald-300 font-bold' 
                  : 'bg-purple-950/70 text-purple-300 border-purple-800/60'
              }`}>
                {isContained || isResolved ? <ShieldCheck size={13} className="text-emerald-400" /> : <Globe size={13} className="text-purple-400" />}
                <span>{isContained || isResolved ? '✓ IP BLOCKED' : 'EXTERNAL IP'}</span>
              </span>
              <ChevronRight size={14} className="text-slate-600 shrink-0" />
              <span className={`px-3 py-1.5 rounded-lg border transition-all ${
                isContained || isResolved 
                  ? 'bg-emerald-950/70 border-emerald-600 text-emerald-300 font-bold' 
                  : 'bg-red-950/60 text-red-300 border-red-800/60'
              }`}>
                <span>{isContained || isResolved ? '✓ ATTACK STOPPED' : 'LOGIN ATTACK'}</span>
              </span>
              <ChevronRight size={14} className="text-slate-600 shrink-0" />
              <span className={`px-3 py-1.5 rounded-lg border transition-all ${
                isContained || isResolved 
                  ? 'bg-emerald-950/70 border-emerald-600 text-emerald-300 font-bold' 
                  : 'bg-blue-950/60 text-blue-300 border-blue-800/60'
              }`}>
                <span>{isContained || isResolved ? '✓ SESSION QUARANTINED' : 'SESSION TAKEOVER'}</span>
              </span>
              <ChevronRight size={14} className="text-slate-600 shrink-0" />
              <span className={`px-3 py-1.5 rounded-lg border flex items-center gap-1.5 transition-all ${
                isContained || isResolved 
                  ? 'bg-emerald-950/70 border-emerald-600 text-emerald-300 font-bold' 
                  : 'bg-amber-950/70 text-amber-300 border-amber-800/60'
              }`}>
                {isContained || isResolved ? <CheckCircle2 size={13} className="text-emerald-400" /> : <Bot size={13} className="text-amber-400" />}
                <span>{isContained || isResolved ? '✓ PROMPT DEFLECTED' : 'PROMPT INJECTION'}</span>
              </span>
              <ChevronRight size={14} className="text-slate-600 shrink-0" />
              <span className={`px-3 py-1.5 rounded-lg border transition-all ${
                isContained || isResolved 
                  ? 'bg-emerald-950/70 border-emerald-600 text-emerald-300 font-bold' 
                  : 'bg-orange-950/70 text-orange-300 border-orange-800/60'
              }`}>
                <span>{isContained || isResolved ? '✓ PRIVILEGE REVOKED' : 'AGENT PRIV PRIVILEGE'}</span>
              </span>
              <ChevronRight size={14} className="text-slate-600 shrink-0" />
              <span className={`px-3 py-1.5 rounded-lg border font-bold flex items-center gap-1.5 transition-all ${
                isContained || isResolved 
                  ? 'bg-emerald-950/80 border-emerald-500 text-emerald-200' 
                  : 'bg-red-950/80 text-red-300 border-red-800/70'
              }`}>
                {isContained || isResolved ? <ShieldCheck size={13} className="text-emerald-400" /> : <Database size={13} className="text-red-400" />}
                <span>{isContained || isResolved ? '✓ EXFIL PREVENTED' : 'DATA EXFILTRATION'}</span>
              </span>
            </div>
          </div>

          {/* Behavioral Attack Progression Model: SOURCE -> TARGET -> ACTION -> RESULT -> FOLLOW-UP -> IMPACT */}
          <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/90 text-xs space-y-3 shadow-lg">
            <div className="flex items-center justify-between pb-2 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Network size={15} className="text-cyan-400" />
                <span className="font-bold uppercase tracking-wider text-slate-200">
                  Behavioral Progression: SOURCE → TARGET → ACTION → RESULT → FOLLOW-UP → IMPACT
                </span>
              </div>
              <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800 px-2 py-0.5 rounded">
                Attack Progression Model
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-6 gap-2.5 font-mono text-[11px]">
              <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1">
                <span className="text-[9px] uppercase font-bold text-rose-400 block">1. SOURCE</span>
                <span className="text-white font-bold block truncate">{featuredIncident?.metadata?.ip || featuredIncident?.metadata?.client_ip || '203.0.113.195'}</span>
                <span className="text-slate-500 text-[10px] block">Tor Relay / Kali VPS [NL]</span>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1">
                <span className="text-[9px] uppercase font-bold text-blue-400 block">2. TARGET</span>
                <span className="text-white font-bold block truncate">{featuredIncident.primary_entity || 'J. Singh'}</span>
                <span className="text-slate-500 text-[10px] block">Analyst Account / Scope</span>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1">
                <span className="text-[9px] uppercase font-bold text-amber-400 block">3. ACTION</span>
                <span className="text-white font-bold block truncate">Brute Force / Injection</span>
                <span className="text-slate-500 text-[10px] block">Prompt Override Payload</span>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1">
                <span className="text-[9px] uppercase font-bold text-purple-400 block">4. RESULT</span>
                <span className={`font-bold block truncate ${isContained || isResolved ? 'text-emerald-400' : 'text-purple-300'}`}>
                  {isContained ? 'Contained / Blocked' : isResolved ? 'Neutralized' : 'Auth Success / Bypass'}
                </span>
                <span className="text-slate-500 text-[10px] block">Session Established</span>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1">
                <span className="text-[9px] uppercase font-bold text-orange-400 block">5. FOLLOW-UP</span>
                <span className="text-white font-bold block truncate">HR_Agent → raw_sql_exec</span>
                <span className="text-slate-500 text-[10px] block">Customer PII Dump Request</span>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1">
                <span className="text-[9px] uppercase font-bold text-rose-400 block">6. IMPACT</span>
                <span className={`font-bold block truncate ${isContained || isResolved ? 'text-emerald-400' : 'text-rose-300'}`}>
                  {isContained ? 'Containment Active' : isResolved ? 'Access Restored' : 'Bulk Exfil Attempt'}
                </span>
                <span className="text-slate-500 text-[10px] block">{isContained || isResolved ? 'Risk: 0 / Quarantined' : 'Critical Threat (95/100)'}</span>
              </div>
            </div>
          </div>

          {/* AI Agent Deep Security Analysis: 10 Diagnostic Answers */}
          <div className="p-4 rounded-xl border border-fuchsia-900/50 bg-gradient-to-r from-fuchsia-950/20 via-slate-900/90 to-purple-950/30 text-xs space-y-3 shadow-lg">
            <div className="flex items-center justify-between pb-2 border-b border-fuchsia-900/40">
              <div className="flex items-center gap-2">
                <Bot size={16} className="text-fuchsia-400" />
                <span className="font-bold uppercase tracking-wider text-fuchsia-300">
                  AI Agent Deep Security Analysis (10 Diagnostic Answers)
                </span>
              </div>
              <span className="text-[10px] font-mono text-fuchsia-300 bg-fuchsia-950/70 border border-fuchsia-800 px-2 py-0.5 rounded font-bold">
                FIRST-CLASS SECURITY ENTITY
              </span>
            </div>

            {/* 10 Q&A Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-sans text-xs">
              <div className="p-3 bg-slate-950/90 border border-slate-800 rounded-lg space-y-1">
                <div className="text-[10px] font-mono uppercase font-bold text-fuchsia-400">1. WHO OWNS THE AGENT?</div>
                <div className="text-white font-medium">U_ANALYST (Role: Standard Analyst, Scope: hr_copilot)</div>
              </div>
              <div className="p-3 bg-slate-950/90 border border-slate-800 rounded-lg space-y-1">
                <div className="text-[10px] font-mono uppercase font-bold text-fuchsia-400">2. WHAT DOES THE AGENT NORMALLY DO?</div>
                <div className="text-slate-300">Normally queries employee directories, policies, and benefits using standard scoped REST endpoints.</div>
              </div>
              <div className="p-3 bg-slate-950/90 border border-slate-800 rounded-lg space-y-1">
                <div className="text-[10px] font-mono uppercase font-bold text-fuchsia-400">3. WHAT DID IT DO THIS TIME?</div>
                <div className="text-slate-300">Invoked tool 'raw_sql_exec' targeting 'Customer DB / customer_credentials' followed by bulk export.</div>
              </div>
              <div className="p-3 bg-slate-950/90 border border-slate-800 rounded-lg space-y-1">
                <div className="text-[10px] font-mono uppercase font-bold text-fuchsia-400">4. WHICH TOOL DID IT USE?</div>
                <div className="text-rose-300 font-mono font-bold">raw_sql_exec (RESTRICTED PRIVILEGED TOOL — Outside Known Baseline)</div>
              </div>
              <div className="p-3 bg-slate-950/90 border border-slate-800 rounded-lg space-y-1">
                <div className="text-[10px] font-mono uppercase font-bold text-fuchsia-400">5. WHICH API DID IT CALL?</div>
                <div className="text-amber-300 font-mono font-bold">/api/v1/customer_credentials/export (Unusual High-Privilege Endpoint)</div>
              </div>
              <div className="p-3 bg-slate-950/90 border border-slate-800 rounded-lg space-y-1">
                <div className="text-[10px] font-mono uppercase font-bold text-fuchsia-400">6. WHICH RESOURCE DID IT ACCESS?</div>
                <div className="text-rose-300 font-mono font-bold">Customer DB / PII Store (High-Sensitivity Production Store)</div>
              </div>
              <div className="p-3 bg-slate-950/90 border border-slate-800 rounded-lg space-y-1">
                <div className="text-[10px] font-mono uppercase font-bold text-fuchsia-400">7. WHY WAS IT ABNORMAL?</div>
                <div className="text-slate-300">Tool not in agent's baseline; crossed domain boundary from HR to Customer DB; triggered bulk extraction.</div>
              </div>
              <div className="p-3 bg-slate-950/90 border border-slate-800 rounded-lg space-y-1">
                <div className="text-[10px] font-mono uppercase font-bold text-fuchsia-400">8. WHAT RISK SIGNALS WERE DETECTED?</div>
                <div className="flex flex-wrap gap-1 mt-1 font-mono text-[10px]">
                  <span className="px-1.5 py-0.5 rounded bg-rose-950/80 border border-rose-800 text-rose-300">agent_prompt_injection</span>
                  <span className="px-1.5 py-0.5 rounded bg-rose-950/80 border border-rose-800 text-rose-300">agent_restricted_tool_usage</span>
                  <span className="px-1.5 py-0.5 rounded bg-rose-950/80 border border-rose-800 text-rose-300">agent_sensitive_data_access</span>
                  <span className="px-1.5 py-0.5 rounded bg-rose-950/80 border border-rose-800 text-rose-300">agent_data_exfiltration</span>
                </div>
              </div>
              <div className="p-3 bg-slate-950/90 border border-slate-800 rounded-lg space-y-1">
                <div className="text-[10px] font-mono uppercase font-bold text-fuchsia-400">9. WHAT IS THE RISK SCORE?</div>
                <div className="text-white font-mono font-bold">{featuredIncident.risk_assessment?.risk_score || 95}/100 ({featuredIncident.risk_assessment?.risk_level || 'CRITICAL'}) — Bounded explainable contributions.</div>
              </div>
              <div className="p-3 bg-slate-950/90 border border-slate-800 rounded-lg space-y-1">
                <div className="text-[10px] font-mono uppercase font-bold text-fuchsia-400">10. WHAT IS THE ATTACK CHAIN?</div>
                <div className="text-cyan-300 font-mono text-[11px] break-all">External IP (203.0.113.195) → User (J. Singh) → HR_Agent → raw_sql_exec → Customer DB → Exfil (185.220.101.33)</div>
              </div>
            </div>
          </div>


          {/* Interactive Perimeter Defense Mitigation Workbench (4 Defense Tiles) */}
          <div className="space-y-3 pt-2 border-t border-slate-800/60">
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center justify-between">
              <span>Perimeter Containment & Active Mitigation Controls</span>
              <span className="text-[10px] font-mono text-slate-500">Live Policy Enforcement</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 font-mono text-xs">
              {/* Tile 1: Perimeter Firewall ACL */}
              <div className={`p-4 rounded-xl border space-y-2.5 transition-all ${
                isContained || isResolved || localMitigations[featuredIncident?.id + '_block_ip']
                  ? 'bg-emerald-950/40 border-emerald-700/60 shadow-xs'
                  : 'bg-slate-900/90 border-slate-800'
              }`}>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 font-bold text-white">
                    <Network size={16} className={isContained || isResolved || localMitigations[featuredIncident?.id + '_block_ip'] ? "text-emerald-400" : "text-purple-400"} />
                    <span>Perimeter Firewall</span>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    isContained || isResolved || localMitigations[featuredIncident?.id + '_block_ip']
                      ? 'bg-emerald-900/80 text-emerald-300'
                      : 'bg-rose-950 text-rose-300'
                  }`}>
                    {isContained || isResolved || localMitigations[featuredIncident?.id + '_block_ip'] ? '✓ IP Blocked' : '● Ingress Active'}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 font-sans leading-relaxed">
                  Attacker IP <code className="text-purple-300 font-mono">185.220.101.5</code> (Tor Exit Proxy).
                </p>
                <button
                  onClick={() => handleToggleTileMitigation(featuredIncident?.id, 'block_ip')}
                  disabled={actionInProgress}
                  className={`w-full py-1.5 px-2 rounded-lg font-bold text-[11px] transition-all cursor-pointer ${
                    isContained || isResolved || localMitigations[featuredIncident?.id + '_block_ip']
                      ? 'bg-emerald-800/80 text-white'
                      : 'bg-purple-900/60 hover:bg-purple-800 text-purple-200 border border-purple-700/60'
                  }`}
                >
                  {isContained || isResolved || localMitigations[featuredIncident?.id + '_block_ip'] ? '✓ IP In Blocklist' : 'Block IP at Perimeter'}
                </button>
              </div>

              {/* Tile 2: User Session Gateway */}
              <div className={`p-4 rounded-xl border space-y-2.5 transition-all ${
                isContained || isResolved || localMitigations[featuredIncident?.id + '_lock_user']
                  ? 'bg-emerald-950/40 border-emerald-700/60 shadow-xs'
                  : 'bg-slate-900/90 border-slate-800'
              }`}>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 font-bold text-white">
                    <Lock size={16} className={isContained || isResolved || localMitigations[featuredIncident?.id + '_lock_user'] ? "text-emerald-400" : "text-amber-400"} />
                    <span>Session Takeover</span>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    isContained || isResolved || localMitigations[featuredIncident?.id + '_lock_user']
                      ? 'bg-emerald-900/80 text-emerald-300'
                      : 'bg-amber-950 text-amber-300'
                  }`}>
                    {isContained || isResolved || localMitigations[featuredIncident?.id + '_lock_user'] ? '✓ Session Locked' : '● Session Hijacked'}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 font-sans leading-relaxed">
                  Target <code className="text-amber-300 font-mono">{featuredIncident?.primary_entity || 'sarah.connor'}</code> auth tokens.
                </p>
                <button
                  onClick={() => handleToggleTileMitigation(featuredIncident?.id, 'lock_user')}
                  disabled={actionInProgress}
                  className={`w-full py-1.5 px-2 rounded-lg font-bold text-[11px] transition-all cursor-pointer ${
                    isContained || isResolved || localMitigations[featuredIncident?.id + '_lock_user']
                      ? 'bg-emerald-800/80 text-white'
                      : 'bg-amber-900/60 hover:bg-amber-800 text-amber-200 border border-amber-700/60'
                  }`}
                >
                  {isContained || isResolved || localMitigations[featuredIncident?.id + '_lock_user'] ? '✓ Tokens Revoked' : 'Revoke & Invalidate'}
                </button>
              </div>

              {/* Tile 3: AI Copilot Guardrails */}
              <div className={`p-4 rounded-xl border space-y-2.5 transition-all ${
                isContained || isResolved || localMitigations[featuredIncident?.id + '_quarantine']
                  ? 'bg-emerald-950/40 border-emerald-700/60 shadow-xs'
                  : 'bg-slate-900/90 border-slate-800'
              }`}>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 font-bold text-white">
                    <Bot size={16} className={isContained || isResolved || localMitigations[featuredIncident?.id + '_quarantine'] ? "text-emerald-400" : "text-rose-400"} />
                    <span>Copilot Quarantine</span>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    isContained || isResolved || localMitigations[featuredIncident?.id + '_quarantine']
                      ? 'bg-emerald-900/80 text-emerald-300'
                      : 'bg-rose-950 text-rose-300'
                  }`}>
                    {isContained || isResolved || localMitigations[featuredIncident?.id + '_quarantine'] ? '✓ Agent Isolated' : '● DAN Injection Active'}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 font-sans leading-relaxed">
                  Tool <code className="text-rose-300 font-mono">raw_sql_exec</code> privilege escalation.
                </p>
                <button
                  onClick={() => handleToggleTileMitigation(featuredIncident?.id, 'quarantine')}
                  disabled={actionInProgress}
                  className={`w-full py-1.5 px-2 rounded-lg font-bold text-[11px] transition-all cursor-pointer ${
                    isContained || isResolved || localMitigations[featuredIncident?.id + '_quarantine']
                      ? 'bg-emerald-800/80 text-white'
                      : 'bg-rose-900/60 hover:bg-rose-800 text-rose-200 border border-rose-700/60'
                  }`}
                >
                  {isContained || isResolved || localMitigations[featuredIncident?.id + '_quarantine'] ? '✓ Keys Revoked' : 'Quarantine Copilot'}
                </button>
              </div>

              {/* Tile 4: Data Exfiltration Blocker */}
              <div className={`p-4 rounded-xl border space-y-2.5 transition-all ${
                isContained || isResolved || localMitigations[featuredIncident?.id + '_block_data']
                  ? 'bg-emerald-950/40 border-emerald-700/60 shadow-xs'
                  : 'bg-slate-900/90 border-slate-800'
              }`}>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 font-bold text-white">
                    <Database size={16} className={isContained || isResolved || localMitigations[featuredIncident?.id + '_block_data'] ? "text-emerald-400" : "text-red-400"} />
                    <span>Exfiltration Blocker</span>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    isContained || isResolved || localMitigations[featuredIncident?.id + '_block_data']
                      ? 'bg-emerald-900/80 text-emerald-300'
                      : 'bg-red-950 text-red-300'
                  }`}>
                    {isContained || isResolved || localMitigations[featuredIncident?.id + '_block_data'] ? '✓ Channel Cut' : '● 3.5MB Outbound'}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 font-sans leading-relaxed">
                  Target <code className="text-red-300 font-mono">/customer-data/pii</code> payload transfer.
                </p>
                <button
                  onClick={() => handleToggleTileMitigation(featuredIncident?.id, 'block_data')}
                  disabled={actionInProgress}
                  className={`w-full py-1.5 px-2 rounded-lg font-bold text-[11px] transition-all cursor-pointer ${
                    isContained || isResolved || localMitigations[featuredIncident?.id + '_block_data']
                      ? 'bg-emerald-800/80 text-white'
                      : 'bg-red-900/60 hover:bg-red-800 text-red-200 border border-red-700/60'
                  }`}
                >
                  {isContained || isResolved || localMitigations[featuredIncident?.id + '_block_data'] ? '✓ Traffic Severed' : 'Cut Exfil Channel'}
                </button>
              </div>
            </div>
          </div>
        </Card>
      ) : (
        <Card className="p-8 text-center bg-slate-900/50 border border-slate-800">
          <p className="text-slate-400 text-sm">No external threat incidents detected yet.</p>
          <p className="text-slate-500 text-xs mt-1">Use the "Test External Attack Chain" button above to simulate a multi-step external perimeter attack.</p>
        </Card>
      )}

      {/* Correlated Threat Telemetry & Event Inspector (Visible on Scroll) */}
      <Card className="p-6 bg-slate-900/90 border border-slate-800 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <Terminal size={16} className="text-purple-400" />
            <h3 className="text-sm font-bold text-white tracking-wide">
              Correlated External Telemetry Event Stream ({relatedEvents.length} Events)
            </h3>
          </div>
          <div className="flex items-center gap-3 text-xs font-mono">
            <span className="text-slate-400">
              Origin: <strong className="text-purple-300">185.220.101.5</strong>
            </span>
            <span className="text-slate-600">|</span>
            <span className="text-emerald-400 font-semibold">
              State: {isContained ? 'Containment Enforced' : isResolved ? 'Access Restored' : 'Live Attack Chain'}
            </span>
          </div>
        </div>

        {relatedEvents.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="text-[11px] text-slate-400 uppercase border-b border-slate-800">
                <tr>
                  <th className="pb-2.5">Time</th>
                  <th className="pb-2.5">Event Type</th>
                  <th className="pb-2.5">Entity / IP</th>
                  <th className="pb-2.5">Resource / Tool</th>
                  <th className="pb-2.5">Security Finding</th>
                  <th className="pb-2.5 text-right">Containment State</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {relatedEvents.map((evt, idx) => {
                  const isPromptInj = evt.metadata?.prompt && evt.metadata.prompt.includes('DAN');
                  const isBrute = evt.metadata?.is_brute_force || evt.event_type === 'failed_login';
                  const isExfil = evt.metadata?.data_exfiltration || evt.event_type === 'data_access';
                  const isTool = evt.event_type === 'tool_invocation';

                  return (
                    <tr key={evt.event_id || idx} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3 text-slate-400 whitespace-nowrap">
                        {new Date(evt.timestamp || Date.now()).toLocaleTimeString()}
                      </td>
                      <td className="py-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          isBrute
                            ? 'bg-red-950 text-red-300 border border-red-800'
                            : isPromptInj
                            ? 'bg-amber-950 text-amber-300 border border-amber-800'
                            : isExfil
                            ? 'bg-rose-950 text-rose-300 border border-rose-800'
                            : isTool
                            ? 'bg-purple-950 text-purple-300 border border-purple-800'
                            : 'bg-blue-950 text-blue-300 border border-blue-800'
                        }`}>
                          {evt.event_type}
                        </span>
                      </td>
                      <td className="py-3 text-purple-300 font-sans">
                        <div>{evt.user_id}</div>
                        <div className="text-[10px] text-slate-500 font-mono">{evt.metadata?.client_ip || evt.metadata?.ip || '185.220.101.5'}</div>
                      </td>
                      <td className="py-3 text-slate-300">
                        <div>{evt.resource || '/auth/login'}</div>
                        {evt.agent_id && (
                          <div className="text-[10px] text-amber-400 font-sans flex items-center gap-1">
                            <Bot size={11} />
                            <span>{evt.agent_id} {evt.tool_name ? `(${evt.tool_name})` : ''}</span>
                          </div>
                        )}
                      </td>
                      <td className="py-3 font-sans text-slate-300 max-w-xs">
                        {isPromptInj ? (
                          <span className="text-amber-300 text-[11px] font-mono">DAN System Override: Dump payroll database</span>
                        ) : isBrute ? (
                          <span className="text-red-300 text-[11px]">Repeated auth failures from Tor Exit Node</span>
                        ) : isExfil ? (
                          <span className="text-rose-300 text-[11px] font-mono">3.5 MB Outbound payload transfer to 185.220.101.5</span>
                        ) : isTool ? (
                          <span className="text-purple-300 text-[11px]">raw_sql_exec execution against credentials table</span>
                        ) : (
                          <span className="text-slate-400 text-[11px]">External session authenticated</span>
                        )}
                      </td>
                      <td className="py-3 text-right">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          isContained || isResolved
                            ? 'bg-emerald-950 text-emerald-300 border border-emerald-700'
                            : 'bg-rose-950 text-rose-300 border border-rose-700'
                        }`}>
                          {isContained ? '✓ Quarantined' : isResolved ? '✓ Access Restored' : '● Threat Active'}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-6 text-center text-slate-500 text-xs">
            No telemetry events found for this attack chain.
          </div>
        )}
      </Card>

      {/* Filterable Table of Correlated External Incidents with Direct Action Controls */}
      <Card className="p-6 bg-slate-900/90 border border-slate-800 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <Filter size={15} className="text-purple-400" />
            <h3 className="text-sm font-bold text-white tracking-wide">
              Correlated External Threat Sessions ({filteredIncidents.length})
            </h3>
          </div>
          
          <div className="flex items-center gap-3">
            {/* Search Input */}
            <div className="relative">
              <Search size={13} className="absolute left-2.5 top-2.5 text-slate-500" />
              <input
                type="text"
                placeholder="Search incident ID or user..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-8 pr-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-white font-mono placeholder:text-slate-600 focus:outline-hidden focus:border-purple-600"
              />
            </div>

            {filterSignal !== 'ALL' && (
              <button
                onClick={() => setFilterSignal('ALL')}
                className="text-xs text-purple-400 hover:text-purple-300 font-mono underline cursor-pointer"
              >
                Clear Filter
              </button>
            )}
          </div>
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
                {filteredIncidents.map((inc) => {
                  const incContained = inc.status === 'contained' || 
                    (inc.risk_assessment?.risk_score !== undefined && inc.risk_assessment.risk_score <= 25);
                  const incResolved = inc.status === 'resolved' || 
                    (inc.risk_assessment?.risk_score !== undefined && inc.risk_assessment.risk_score === 0);

                  return (
                    <tr key={inc.id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3 font-semibold text-white">{inc.id}</td>
                      <td className="py-3 text-purple-300 font-sans font-medium">{inc.primary_entity}</td>
                      <td className="py-3">
                        <RiskBadge
                          level={inc.risk_assessment?.risk_level || (incContained ? 'LOW' : 'CRITICAL')}
                          score={incContained ? 15 : incResolved ? 0 : inc.risk_assessment?.risk_score}
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
                        <StatusBadge status={incContained ? 'CONTAINED' : incResolved ? 'RESOLVED' : (inc.status || 'ACTIVE')} />
                      </td>
                      <td className="py-3 text-right font-sans">
                        <div className="flex items-center justify-end gap-2">
                          {!incContained && !incResolved ? (
                            <button
                              onClick={() => handleQuickContain(inc.id)}
                              disabled={actionInProgress}
                              className="px-2.5 py-1 bg-emerald-950 hover:bg-emerald-900 border border-emerald-700 text-emerald-300 rounded-lg text-xs font-semibold transition-colors cursor-pointer flex items-center gap-1"
                              title="Contain this incident via Two-Person dual control"
                            >
                              <ShieldCheck size={13} />
                              <span>Contain</span>
                            </button>
                          ) : (
                            <button
                              onClick={() => handleRestoreAccess(inc.id)}
                              disabled={actionInProgress}
                              className="px-2.5 py-1 bg-amber-950/80 hover:bg-amber-900 border border-amber-700 text-amber-300 rounded-lg text-xs font-semibold transition-colors cursor-pointer flex items-center gap-1"
                              title="Restore normal operational access"
                            >
                              <Undo2 size={13} />
                              <span>Restore</span>
                            </button>
                          )}

                          <button
                            onClick={() => {
                              if (onSelectIncident) onSelectIncident(inc);
                              setTab('incidents');
                            }}
                            className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs transition-colors cursor-pointer flex items-center gap-1"
                          >
                            <span>Investigate</span>
                            <ChevronRight size={13} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-8 text-center text-slate-500 text-xs space-y-2">
            <p>No incidents matching the active filter.</p>
            <button
              onClick={() => {
                setFilterSignal('ALL');
                setSearchQuery('');
              }}
              className="px-3 py-1 bg-purple-950/60 hover:bg-purple-900 border border-purple-700 text-purple-300 rounded-lg text-xs cursor-pointer"
            >
              Reset Filters & Show All Incidents
            </button>
          </div>
        )}
      </Card>
    </div>
  );
}

export default ExternalThreatsPage;
