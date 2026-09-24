import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  Volume2, 
  CheckCircle2, 
  Flame, 
  ArrowRight, 
  Radio, 
  ShieldCheck, 
  UserCheck, 
  Cpu, 
  Server,
  X,
  Sparkles
} from 'lucide-react';
import { RiskBadge } from '../common/Badge';

export function CriticalIncidentBanner({ 
  alert, 
  queueCount = 1,
  onSelectIncident, 
  onAcknowledge, 
  onResolveAlert,
  onReplayVoice, 
  onOpenActionCenter,
  onDismiss 
}) {
  const [isAcknowledging, setIsAcknowledging] = useState(false);
  const [isResolving, setIsResolving] = useState(false);
  const [isReplaying, setIsReplaying] = useState(false);
  const [isDismissing, setIsDismissing] = useState(false);
  const [acknowledgedLocally, setAcknowledgedLocally] = useState(false);
  const [countdown, setCountdown] = useState(5);

  const isContained = alert?.status === 'contained' || 
                      alert?.approval_state === 'APPROVED' || 
                      (alert?.risk_score !== undefined && alert.risk_score <= 25) ||
                      alert?.response_state === 'CONTAINMENT_ACTIVE';

  const isResolved = alert?.status === 'resolved' || 
                     (alert?.risk_score !== undefined && alert.risk_score === 0);

  const isCritical = !isContained && !isResolved && ((alert?.risk_level || alert?.severity || '').toUpperCase() === 'CRITICAL' || (alert?.risk_score || 0) >= 80);
  const isHigh = !isContained && !isResolved && ((alert?.risk_level || alert?.severity || '').toUpperCase() === 'HIGH' || (alert?.risk_score || 0) >= 60);

  const handleClose = () => {
    setIsDismissing(true);
    setTimeout(() => {
      if (onDismiss && alert?.alert_id) {
        onDismiss(alert.alert_id);
      }
    }, 300);
  };

  // Auto-dismiss immediately when contained or resolved
  useEffect(() => {
    if (alert && (isContained || isResolved)) {
      handleClose();
    }
  }, [isContained, isResolved, alert?.alert_id]);

  if (!alert) return null;

  const handleAckClick = async () => {
    if (!onAcknowledge || isAcknowledging) return;
    setIsAcknowledging(true);
    try {
      await onAcknowledge(alert.alert_id);
      setAcknowledgedLocally(true);
      setTimeout(() => {
        handleClose();
      }, 1500);
    } finally {
      setIsAcknowledging(false);
    }
  };

  const handleReplayClick = async () => {
    if (!onReplayVoice || isReplaying) return;
    setIsReplaying(true);
    try {
      await onReplayVoice(alert);
    } finally {
      setIsReplaying(false);
    }
  };

  const handleResolveClick = async () => {
    if (!onResolveAlert || isResolving) return;
    setIsResolving(true);
    try {
      await onResolveAlert(alert.alert_id);
    } finally {
      setIsResolving(false);
    }
  };

  const threatType = alert.threat_type || 'EXTERNAL_THREAT';
  const affectedEntity = alert.affected_entity || alert.agent_id || alert.user_id || 'System Asset';
  const approvalState = isContained ? 'APPROVED' : alert.approval_state || 'NOT_REQUIRED';
  const containmentState = isResolved ? 'RESTORED' : isContained ? 'CONTAINMENT_ACTIVE' : alert.response_state || 'CONTAINMENT_SIMULATED';
  const isAcknowledged = !!alert.acknowledged || acknowledgedLocally;

  return (
    <div className={`mb-6 p-4 sm:p-5 rounded-2xl border transition-all duration-500 shadow-sm dark:shadow-2xl relative overflow-hidden backdrop-blur-md ${
      isDismissing ? 'opacity-0 -translate-y-4 scale-95' : 'opacity-100 translate-y-0 scale-100'
    } ${
      isResolved || isContained
        ? 'bg-emerald-50 dark:bg-gradient-to-r dark:from-emerald-950/80 dark:via-slate-950/90 dark:to-teal-950/60 border-emerald-300 dark:border-emerald-500/50'
        : isCritical 
        ? 'bg-rose-50 dark:bg-gradient-to-r dark:from-red-950/80 dark:via-slate-950/90 dark:to-red-950/60 border-rose-300 dark:border-red-500/50' 
        : 'bg-amber-50 dark:bg-gradient-to-r dark:from-amber-950/80 dark:via-slate-950/90 dark:to-amber-950/60 border-amber-300 dark:border-amber-500/50'
    }`}>
      {/* Decorative ambient background pulses */}
      <div className={`absolute -top-12 -right-12 w-48 h-48 rounded-full blur-3xl pointer-events-none ${
        isResolved || isContained ? 'bg-emerald-600/10' : 'bg-red-600/10 animate-pulse'
      }`} />
      <div className={`absolute -bottom-12 -left-12 w-48 h-48 rounded-full blur-3xl pointer-events-none ${
        isResolved || isContained ? 'bg-teal-600/10' : 'bg-amber-600/10'
      }`} />

      {/* Auto-dismiss progress bar if contained / resolved */}
      {(isContained || isResolved) && (
        <div className="absolute top-0 left-0 right-0 h-1 bg-emerald-100 dark:bg-emerald-950 overflow-hidden">
          <div 
            className="h-full bg-emerald-500 transition-all duration-1000 ease-linear"
            style={{ width: `${(countdown / 5) * 100}%` }}
          />
        </div>
      )}

      {/* Top Right Quick Dismiss Button */}
      <button
        onClick={handleClose}
        className="absolute top-3 right-3 p-1.5 rounded-lg text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-black/5 dark:hover:bg-white/10 transition-colors cursor-pointer z-20"
        title="Dismiss banner"
      >
        <X size={16} />
      </button>

      <div className="relative z-10 flex flex-col lg:flex-row lg:items-center justify-between gap-4 pr-6 sm:pr-8">
        {/* Left Side: Header, Severity, and Telemetry Badges */}
        <div className="space-y-3 flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2.5">
            {isResolved ? (
              <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-100 dark:bg-emerald-900/60 border border-emerald-300 dark:border-emerald-500/40 text-emerald-800 dark:text-emerald-200 text-[11px] font-mono font-bold tracking-wide uppercase shadow-xs">
                <CheckCircle2 size={12} className="text-emerald-600 dark:text-emerald-400" />
                <span>INCIDENT RESOLVED (RISK: 0)</span>
              </div>
            ) : isContained ? (
              <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-100 dark:bg-emerald-900/60 border border-emerald-300 dark:border-emerald-500/40 text-emerald-800 dark:text-emerald-200 text-[11px] font-mono font-bold tracking-wide uppercase shadow-xs">
                <ShieldCheck size={12} className="text-emerald-600 dark:text-emerald-400" />
                <span>THREAT NEUTRALIZED & QUARANTINED</span>
              </div>
            ) : (
              <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-rose-100 dark:bg-red-900/60 border border-rose-300 dark:border-red-500/40 text-rose-800 dark:text-red-200 text-[11px] font-mono font-bold tracking-wide uppercase shadow-xs">
                <Radio size={12} className="text-rose-600 dark:text-red-400 animate-ping" />
                <span>{isCritical ? 'CRITICAL SECURITY ALERT' : 'HIGH SECURITY ESCALATION'}</span>
              </div>
            )}

            <RiskBadge 
              level={isResolved ? 'RESOLVED' : isContained ? 'LOW' : alert.risk_level || 'CRITICAL'} 
              score={isResolved ? 0 : isContained ? 15 : alert.risk_score || (isCritical ? 100 : 75)} 
            />

            {/* Threat Type Badge */}
            <span className="px-2.5 py-1 bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-700/70 rounded-md text-[11px] font-mono text-cyan-700 dark:text-cyan-300 font-semibold uppercase tracking-wider">
              {threatType.replace(/_/g, ' ')}
            </span>

            {/* Affected User / Agent Badge */}
            <span className="px-2.5 py-1 bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-700/70 rounded-md text-[11px] font-mono text-purple-700 dark:text-purple-300 flex items-center gap-1.5">
              <Cpu size={12} className="text-purple-600 dark:text-purple-400" />
              <span className="truncate max-w-[180px]">{affectedEntity}</span>
            </span>

            {/* Approval State Badge */}
            {approvalState !== 'NOT_REQUIRED' && (
              <span className={`px-2.5 py-1 rounded-md text-[11px] font-mono font-semibold flex items-center gap-1.5 border ${
                approvalState === 'APPROVED' 
                  ? 'bg-emerald-100 dark:bg-emerald-950/70 border-emerald-300 dark:border-emerald-500/50 text-emerald-800 dark:text-emerald-300' 
                  : 'bg-amber-100 dark:bg-amber-950/70 border-amber-300 dark:border-amber-500/50 text-amber-800 dark:text-amber-300'
              }`}>
                <UserCheck size={12} />
                <span>APPROVAL: {approvalState.replace(/_/g, ' ')}</span>
              </span>
            )}
            {/* Queue Position Badge */}
            {queueCount > 1 && (
              <span className="px-2.5 py-1 bg-amber-100 dark:bg-amber-950/80 text-amber-800 dark:text-amber-300 border border-amber-300 dark:border-amber-700/60 rounded-md text-[11px] font-mono font-bold tracking-wide">
                Queue: 1 of {queueCount}
              </span>
            )}
          </div>

          {/* Alert Main Headline and Rationale */}
          <div className="space-y-1">
            <h3 className="text-base sm:text-lg font-bold text-slate-900 dark:text-white tracking-tight flex items-center gap-2">
              {isResolved || isContained ? (
                <ShieldCheck size={18} className="text-emerald-600 dark:text-emerald-400 shrink-0" />
              ) : (
                <Flame size={18} className="text-rose-600 dark:text-red-400 shrink-0" />
              )}
              <span>
                {isResolved 
                  ? 'Incident Resolved (False Positive Verified & Access Restored)'
                  : isContained 
                  ? 'Threat Neutralized & Quarantined (Risk: 15 / 100)'
                  : alert.title || alert.message || 'Correlated Multi-Step Attack Chain Detected'}
              </span>
            </h3>
            <p className="text-xs sm:text-sm text-slate-700 dark:text-slate-300 line-clamp-2 leading-relaxed font-sans">
              {isResolved
                ? 'All temporary security controls and tool quarantine restrictions lifted. Audit history preserved.'
                : isContained
                ? 'Dual-control Two-Person Rule satisfied. AI agent quarantined and session privileges revoked. Auto-dismissing in ' + countdown + 's...'
                : acknowledgedLocally
                ? 'Alert acknowledged by SOC Operator. Auto-dismissing...'
                : alert.voice_message || alert.reasons?.[0] || 'Multi-event correlation linked unauthorized tool execution with sensitive data access.'}
            </p>
          </div>

          {/* Containment Simulation State */}
          <div className="flex flex-wrap items-center gap-3 pt-1 text-xs font-mono text-slate-600 dark:text-slate-400">
            <div className="flex items-center gap-1.5">
              <ShieldCheck size={14} className={isContained || isResolved ? "text-emerald-600 dark:text-emerald-400" : "text-cyan-600 dark:text-cyan-400"} />
              <span>Response: <strong className="text-slate-900 dark:text-slate-200">{containmentState}</strong></span>
            </div>
            <span>•</span>
            <div className="flex items-center gap-1.5">
              <Server size={14} className="text-purple-600 dark:text-purple-400" />
              <span>Pipeline: <strong className="text-slate-900 dark:text-slate-200">ThreatFusion AI Engine</strong></span>
            </div>
          </div>
        </div>

        {/* Right Side: Action Buttons & Voice Trigger */}
        <div className="flex flex-wrap lg:flex-col items-center lg:items-end justify-between lg:justify-center gap-2.5 shrink-0 border-t lg:border-t-0 pt-3 lg:pt-0 border-slate-200 dark:border-slate-800/80">
          
          <div className="flex items-center gap-2">
            {/* Voice Replay Button */}
            <button
              onClick={handleReplayClick}
              disabled={isReplaying}
              className="p-2.5 bg-purple-100 dark:bg-purple-950/80 hover:bg-purple-200 dark:hover:bg-purple-900 text-purple-800 dark:text-purple-200 border border-purple-300 dark:border-purple-700/60 rounded-xl transition-all cursor-pointer shadow-xs"
              title="Speak alert synthesis"
            >
              <Volume2 size={16} className={isReplaying ? 'animate-bounce text-purple-600 dark:text-purple-300' : ''} />
            </button>

            {/* Acknowledge / Dismiss Button */}
            {isContained || isResolved ? (
              <button
                onClick={handleClose}
                className="px-3.5 py-2 bg-emerald-100 dark:bg-emerald-950 hover:bg-emerald-200 dark:hover:bg-emerald-900 text-emerald-800 dark:text-emerald-200 border border-emerald-300 dark:border-emerald-700/80 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer shadow-xs"
              >
                <CheckCircle2 size={14} className="text-emerald-600 dark:text-emerald-400" />
                <span>Dismiss ({countdown}s)</span>
              </button>
            ) : !isAcknowledged ? (
              <button
                onClick={handleAckClick}
                disabled={isAcknowledging}
                className="px-3.5 py-2 bg-white dark:bg-slate-900/90 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-200 border border-slate-200 dark:border-slate-700/80 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer shadow-xs"
              >
                <CheckCircle2 size={14} className="text-emerald-600 dark:text-emerald-400" />
                <span>{isAcknowledging ? 'Saving...' : 'Acknowledge'}</span>
              </button>
            ) : (
              <span className="px-3 py-1.5 rounded-xl bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300 text-xs font-mono font-medium flex items-center gap-1">
                <CheckCircle2 size={13} />
                <span>Acknowledged</span>
              </span>
            )}

            {/* 1-Click Resolve Alert Button (Resolves this alert in isolation & advances queue) */}
            {!isResolved && !isContained && onResolveAlert && (
              <button
                onClick={handleResolveClick}
                disabled={isResolving}
                className="px-3.5 py-2 bg-emerald-100 dark:bg-emerald-950/80 hover:bg-emerald-200 dark:hover:bg-emerald-900 text-emerald-800 dark:text-emerald-200 border border-emerald-300 dark:border-emerald-700/80 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer shadow-xs"
                title="Resolve this alert and advance to next in queue"
              >
                <CheckCircle2 size={14} className="text-emerald-600 dark:text-emerald-400" />
                <span>{isResolving ? 'Resolving...' : 'Resolve Alert'}</span>
              </button>
            )}
          </div>

          {/* Action Center Primary Trigger */}
          <button
            onClick={() => onOpenActionCenter ? onOpenActionCenter(alert) : onSelectIncident && onSelectIncident({ id: alert.incident_id })}
            className={`px-4 py-2.5 rounded-xl text-xs font-bold flex items-center gap-2 shadow-md transition-all cursor-pointer text-white ${
              isContained || isResolved
                ? 'bg-emerald-600 hover:bg-emerald-500 shadow-emerald-600/30'
                : 'bg-gradient-to-r from-red-600 to-rose-700 hover:from-red-500 hover:to-rose-600 shadow-red-600/30'
            }`}
          >
            <span>{isContained || isResolved ? 'View Incident Report' : 'Open Action Center'}</span>
            <ArrowRight size={14} />
          </button>
        </div>
      </div>
    </div>
  );
}

export default CriticalIncidentBanner;
