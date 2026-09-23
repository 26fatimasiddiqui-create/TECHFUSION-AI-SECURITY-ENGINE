import React, { useState } from 'react';
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
  Server
} from 'lucide-react';
import { RiskBadge } from '../common/Badge';

export function CriticalIncidentBanner({ 
  alert, 
  onSelectIncident, 
  onAcknowledge, 
  onReplayVoice, 
  onOpenActionCenter 
}) {
  const [isAcknowledging, setIsAcknowledging] = useState(false);
  const [isReplaying, setIsReplaying] = useState(false);

  if (!alert) return null;

  const isCritical = (alert.risk_level || alert.severity || '').toUpperCase() === 'CRITICAL';
  const isHigh = (alert.risk_level || alert.severity || '').toUpperCase() === 'HIGH';
  if (!isCritical && !isHigh) return null;

  const handleAckClick = async () => {
    if (!onAcknowledge || isAcknowledging) return;
    setIsAcknowledging(true);
    try {
      await onAcknowledge(alert.alert_id);
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

  const threatType = alert.threat_type || 'EXTERNAL_THREAT';
  const affectedEntity = alert.affected_entity || alert.agent_id || alert.user_id || 'System Asset';
  const approvalState = alert.approval_state || 'NOT_REQUIRED';
  const containmentState = alert.response_state || 'CONTAINMENT_SIMULATED';
  const isAcknowledged = !!alert.acknowledged;

  return (
    <div className={`mb-6 p-4 sm:p-5 rounded-2xl border transition-all duration-300 shadow-sm dark:shadow-2xl relative overflow-hidden backdrop-blur-md ${
      isCritical 
        ? 'bg-rose-50 dark:bg-gradient-to-r dark:from-red-950/80 dark:via-slate-950/90 dark:to-red-950/60 border-rose-300 dark:border-red-500/50' 
        : 'bg-amber-50 dark:bg-gradient-to-r dark:from-amber-950/80 dark:via-slate-950/90 dark:to-amber-950/60 border-amber-300 dark:border-amber-500/50'
    }`}>
      {/* Decorative ambient background pulses */}
      <div className="absolute -top-12 -right-12 w-48 h-48 bg-red-600/10 rounded-full blur-3xl pointer-events-none animate-pulse" />
      <div className="absolute -bottom-12 -left-12 w-48 h-48 bg-amber-600/10 rounded-full blur-3xl pointer-events-none" />

      <div className="relative z-10 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        {/* Left Side: Header, Severity, and Telemetry Badges */}
        <div className="space-y-3 flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2.5">
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-rose-100 dark:bg-red-900/60 border border-rose-300 dark:border-red-500/40 text-rose-800 dark:text-red-200 text-[11px] font-mono font-bold tracking-wide uppercase shadow-xs">
              <Radio size={12} className="text-rose-600 dark:text-red-400 animate-ping" />
              <span>{isCritical ? 'CRITICAL SECURITY ALERT' : 'HIGH SECURITY ESCALATION'}</span>
            </div>

            <RiskBadge level={alert.risk_level || 'CRITICAL'} score={alert.risk_score || (isCritical ? 100 : 75)} />

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
          </div>

          {/* Alert Main Headline and Rationale */}
          <div className="space-y-1">
            <h3 className="text-base sm:text-lg font-bold text-slate-900 dark:text-white tracking-tight flex items-center gap-2">
              <Flame size={18} className="text-rose-600 dark:text-red-400 shrink-0" />
              <span>{alert.title || alert.message || 'Correlated Multi-Step Attack Chain Detected'}</span>
            </h3>
            <p className="text-xs sm:text-sm text-slate-700 dark:text-slate-300 line-clamp-2 leading-relaxed font-sans">
              {alert.voice_message || alert.reasons?.[0] || 'Multi-event correlation linked unauthorized tool execution with sensitive data access.'}
            </p>
          </div>

          {/* Containment Simulation State */}
          <div className="flex flex-wrap items-center gap-3 pt-1 text-xs font-mono text-slate-600 dark:text-slate-400">
            <div className="flex items-center gap-1.5">
              <ShieldCheck size={14} className="text-cyan-600 dark:text-cyan-400" />
              <span>Response: <strong className="text-slate-900 dark:text-slate-200">{containmentState}</strong></span>
            </div>
            <span>•</span>
            <div className="flex items-center gap-1.5">
              <Server size={14} className="text-purple-600 dark:text-purple-400" />
              <span>Pipeline: <strong className="text-slate-900 dark:text-slate-200">TechFusion AI Engine</strong></span>
            </div>
          </div>
        </div>

        {/* Right Side: Action Buttons & Voice Trigger */}
        <div className="flex flex-wrap lg:flex-col items-center lg:items-end justify-between lg:justify-center gap-2.5 shrink-0 border-t lg:border-t-0 pt-3 lg:pt-0 border-rose-200 dark:border-slate-800/80">
          
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

            {/* Acknowledge Button */}
            {!isAcknowledged && (
              <button
                onClick={handleAckClick}
                disabled={isAcknowledging}
                className="px-3.5 py-2 bg-white dark:bg-slate-900/90 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-200 border border-slate-200 dark:border-slate-700/80 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer shadow-xs"
              >
                <CheckCircle2 size={14} className="text-emerald-600 dark:text-emerald-400" />
                <span>{isAcknowledging ? 'Saving...' : 'Acknowledge'}</span>
              </button>
            )}
          </div>

          {/* Action Center Primary Trigger */}
          <button
            onClick={() => onOpenActionCenter ? onOpenActionCenter(alert) : onSelectIncident && onSelectIncident({ id: alert.incident_id })}
            className="px-4 py-2.5 bg-gradient-to-r from-red-600 to-rose-700 hover:from-red-500 hover:to-rose-600 text-white rounded-xl text-xs font-bold flex items-center gap-2 shadow-md shadow-red-600/30 transition-all cursor-pointer"
          >
            <span>Open Action Center</span>
            <ArrowRight size={14} />
          </button>
        </div>
      </div>
    </div>
  );
}

export default CriticalIncidentBanner;
