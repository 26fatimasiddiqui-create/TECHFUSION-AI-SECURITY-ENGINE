import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  X, 
  User, 
  Clock, 
  CheckCircle2, 
  AlertTriangle, 
  Terminal, 
  Database,
  ArrowRight,
  Shield,
  Layers,
  RefreshCw,
  Activity,
  Check,
  ShieldCheck
} from 'lucide-react';
import { 
  supabase, 
  isSupabaseConfigured,
  updateAlertStatusInSupabase,
  approveAlertInSupabase,
  resolveAlertInSupabase,
  isAlertActive
} from '../../services/insightSupabase';

export function InsightAlertModal({ 
  alert: initialAlert, 
  onClose, 
  onSelectEmployee,
  onStatusUpdated
}) {
  const [alert, setAlert] = useState(initialAlert);
  const [linkedRiskEvent, setLinkedRiskEvent] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isUpdatingStatus, setIsUpdatingStatus] = useState(false);
  const [updateError, setUpdateError] = useState(null);

  useEffect(() => {
    if (!initialAlert?.id) return;
    setAlert(initialAlert);

    // Fetch fresh record from Supabase table to ensure single source of truth
    if (isSupabaseConfigured && supabase) {
      setIsLoading(true);
      supabase
        .from('alerts')
        .select('*')
        .eq('id', initialAlert.id)
        .maybeSingle()
        .then(async ({ data: freshAlert }) => {
          if (freshAlert) {
            setAlert(prev => ({ ...prev, ...freshAlert }));
            // If alert has a linked risk_event_id, fetch the corresponding risk_event
            if (freshAlert.risk_event_id) {
              const { data: revt } = await supabase
                .from('risk_events')
                .select('*')
                .eq('id', freshAlert.risk_event_id)
                .maybeSingle();
              if (revt) {
                setLinkedRiskEvent(revt);
              }
            }
          }
          setIsLoading(false);
        })
        .catch(err => {
          console.warn('Error fetching fresh alert from Supabase:', err);
          setIsLoading(false);
        });
    }
  }, [initialAlert?.id]);

  if (!alert) return null;

  const score = Number(alert.risk_score || 0);
  const isCritical = alert.severity === 'CRITICAL' || score >= 85 || alert.alert_type === 'CRITICAL';
  const isHigh = alert.severity === 'HIGH' || score >= 70;
  
  const statusStr = String(alert.status || 'NEW').toLowerCase().trim();
  const isApproved = statusStr === 'approved';
  const isResolved = statusStr === 'resolved';
  const isActive = isAlertActive(statusStr);

  const triggeringEvent = alert.message || alert.event || 'Unusual sensitive-data access';
  const timestampStr = alert.created_at || alert.timestamp || new Date().toISOString();

  const recommendedAction = score >= 85 || alert.severity === 'CRITICAL'
    ? 'Immediately isolate employee active session, revoke database tokens, and require Two-Person manager verification.'
    : score >= 70 || alert.severity === 'HIGH'
    ? 'Flag account for credential review, restrict off-hours access, and notify direct supervisor.'
    : 'Log telemetry anomaly and continue baseline behavioral monitoring.';

  // Handle Approve action: updates Supabase status to 'approved'
  const handleApprove = async () => {
    setIsUpdatingStatus(true);
    setUpdateError(null);
    try {
      const { data, error } = await approveAlertInSupabase(alert.id);
      if (error) {
        setUpdateError(`Failed to approve: ${error}`);
      } else {
        setAlert(prev => ({
          ...prev,
          status: 'approved',
          resolved_at: new Date().toISOString()
        }));
        if (onStatusUpdated) {
          onStatusUpdated(alert.id, 'approved');
        }
      }
    } catch (err) {
      setUpdateError(err.message || 'Error updating status in Supabase');
    } finally {
      setIsUpdatingStatus(false);
    }
  };

  // Handle Resolve action: updates Supabase status to 'resolved'
  const handleResolve = async () => {
    setIsUpdatingStatus(true);
    setUpdateError(null);
    try {
      const { data, error } = await resolveAlertInSupabase(alert.id);
      if (error) {
        setUpdateError(`Failed to resolve: ${error}`);
      } else {
        setAlert(prev => ({
          ...prev,
          status: 'resolved',
          resolved_at: new Date().toISOString()
        }));
        if (onStatusUpdated) {
          onStatusUpdated(alert.id, 'resolved');
        }
      }
    } catch (err) {
      setUpdateError(err.message || 'Error updating status in Supabase');
    } finally {
      setIsUpdatingStatus(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4 overflow-y-auto animate-in fade-in duration-200">
      <div 
        className="w-full max-w-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-2xl overflow-hidden my-8 max-h-[90vh] flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className={`p-5 border-b flex items-center justify-between ${
          isCritical 
            ? 'bg-rose-50 dark:bg-rose-950/40 border-rose-200 dark:border-rose-900/60' 
            : 'bg-slate-50 dark:bg-slate-950/60 border-slate-200 dark:border-slate-800'
        }`}>
          <div className="flex items-center gap-3">
            <div className={`p-2.5 rounded-xl border ${
              isCritical 
                ? 'bg-rose-100 dark:bg-rose-950 border-rose-300 dark:border-rose-700 text-rose-700 dark:text-rose-400' 
                : 'bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-cyan-700 dark:text-cyan-400'
            }`}>
              <ShieldAlert size={20} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-slate-900 dark:text-white font-mono">{alert.id}</h3>
                <span className={`px-2.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${
                  isCritical 
                    ? 'bg-rose-50 dark:bg-rose-950 text-rose-700 dark:text-rose-300 border-rose-200 dark:border-rose-700' 
                    : 'bg-orange-50 dark:bg-orange-950 text-orange-700 dark:text-orange-300 border-orange-200 dark:border-orange-700'
                }`}>
                  {alert.alert_type || alert.severity} SEVERITY
                </span>
                {isLoading && (
                  <RefreshCw size={12} className="animate-spin text-cyan-600 dark:text-cyan-400" />
                )}
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 font-sans">
                Supabase alerts table • Created by n8n workflow
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-xl bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors cursor-pointer"
          >
            <X size={16} />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 space-y-5 overflow-y-auto flex-1 font-mono text-xs">
          
          {/* Key Metric Blocks */}
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
            <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1">
              <span className="text-slate-500 dark:text-slate-400 text-[10px] uppercase block">RISK SCORE</span>
              <div className="text-2xl font-black text-rose-600 dark:text-rose-400">
                {score} <span className="text-xs text-slate-400 dark:text-slate-500 font-normal">/ 100</span>
              </div>
            </div>

            <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1">
              <span className="text-slate-500 dark:text-slate-400 text-[10px] uppercase block">EMPLOYEE</span>
              <div className="text-sm font-bold text-slate-900 dark:text-white truncate font-sans">
                {alert.employee_name || 'N/A'}
              </div>
              <span className="text-[10px] text-cyan-700 dark:text-cyan-400">
                Code: {alert.employee_code || 'N/A'}
              </span>
            </div>

            <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1 col-span-2 sm:col-span-1">
              <span className="text-slate-500 dark:text-slate-400 text-[10px] uppercase block">STATUS</span>
              <span className={`inline-block px-2.5 py-0.5 rounded text-[10px] font-bold uppercase border ${
                isApproved 
                  ? 'bg-emerald-50 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-700' 
                  : isResolved 
                  ? 'bg-blue-50 dark:bg-blue-950 text-blue-700 dark:text-blue-300 border-blue-200 dark:border-blue-700'
                  : 'bg-rose-50 dark:bg-rose-950 text-rose-700 dark:text-rose-300 border-rose-200 dark:border-rose-700'
              }`}>
                {alert.status || 'NEW'}
              </span>
              <span className="text-[10px] text-slate-500 block truncate" title={alert.employee_id}>
                UUID: {alert.employee_id}
              </span>
            </div>
          </div>

          {/* Status Alert notice if approved/resolved */}
          {(isApproved || isResolved) && (
            <div className="p-3.5 rounded-xl bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800/80 flex items-center justify-between text-xs font-mono">
              <div className="flex items-center gap-2 text-emerald-800 dark:text-emerald-300">
                <CheckCircle2 size={16} className="text-emerald-600 dark:text-emerald-400" />
                <span>Threat {isApproved ? 'Approved by SOC Analyst' : 'Resolved'} in Supabase</span>
              </div>
              <span className="text-[10px] text-slate-500 dark:text-slate-400">
                Removed from Active Threat Overview
              </span>
            </div>
          )}

          {updateError && (
            <div className="p-3 rounded-xl bg-rose-50 dark:bg-rose-950/80 border border-rose-200 dark:border-rose-700 text-rose-800 dark:text-rose-300 text-xs font-mono">
              {updateError}
            </div>
          )}

          {/* Triggering Event Box */}
          <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-2">
            <span className="text-slate-500 dark:text-slate-400 text-[10px] uppercase font-bold tracking-wider block">
              TRIGGERING SECURITY EVENT / MESSAGE
            </span>
            <p className="text-sm font-sans text-slate-900 dark:text-slate-100 font-medium leading-relaxed">
              "{triggeringEvent}"
            </p>
            <div className="flex items-center gap-2 text-slate-500 text-[10px] pt-1 border-t border-slate-200 dark:border-slate-900">
              <Clock size={12} />
              <span>Timestamp: {new Date(timestampStr).toUTCString()} ({new Date(timestampStr).toLocaleString()})</span>
            </div>
          </div>

          {/* Linked Risk Event (if exists) */}
          {linkedRiskEvent && (
            <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1.5">
              <div className="flex items-center gap-1.5 text-cyan-600 dark:text-cyan-400 font-bold text-[11px]">
                <Activity size={13} />
                <span>LINKED SUPABASE RISK EVENT</span>
              </div>
              <div className="text-[11px] text-slate-700 dark:text-slate-300">
                Type: <strong className="text-slate-900 dark:text-white">{linkedRiskEvent.event_type}</strong> • Severity: <strong className="text-slate-900 dark:text-white">{linkedRiskEvent.severity}</strong> • Score: <strong className="text-slate-900 dark:text-white">{linkedRiskEvent.risk_score}</strong>
              </div>
              <p className="text-[11px] text-slate-600 dark:text-slate-400 font-sans">
                {linkedRiskEvent.description}
              </p>
            </div>
          )}

          {/* Recommended Action */}
          <div className="p-4 rounded-xl bg-amber-50/70 dark:bg-gradient-to-r dark:from-amber-950/40 dark:to-slate-950 border border-amber-200 dark:border-amber-800/80 space-y-2">
            <div className="flex items-center gap-2 text-amber-800 dark:text-amber-300 font-bold text-xs">
              <CheckCircle2 size={15} className="text-amber-600 dark:text-amber-400" />
              <span>RECOMMENDED MITIGATION ACTION</span>
            </div>
            <p className="text-xs font-sans text-amber-900 dark:text-slate-200 leading-relaxed">
              {recommendedAction}
            </p>
          </div>

          {/* Technical Payload / Supabase Row Viewer */}
          <div className="space-y-2">
            <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 text-[10px] uppercase font-bold">
              <span>Actual Supabase Record Data (JSON)</span>
              <span className="text-cyan-600 dark:text-cyan-400 font-mono">Table: public.alerts</span>
            </div>
            <pre className="p-3 rounded-xl bg-slate-900 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-cyan-300 text-[11px] overflow-x-auto">
{JSON.stringify(alert.raw_record || {
  id: alert.id,
  employee_id: alert.employee_id,
  employee_code: alert.employee_code,
  risk_score: alert.risk_score,
  alert_type: alert.alert_type,
  message: alert.message,
  status: alert.status,
  created_at: alert.created_at,
  resolved_at: alert.resolved_at,
  risk_event_id: alert.risk_event_id
}, null, 2)}
            </pre>
          </div>

        </div>

        {/* Footer with Action Controls */}
        <div className="p-4 border-t border-slate-100 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/80 flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
          <div className="flex items-center gap-2">
            <span className="text-slate-500">Security Engine: INSIGHT</span>
            {isApproved ? (
              <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-emerald-50 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800 flex items-center gap-1">
                <Check size={11} />
                <span>APPROVED</span>
              </span>
            ) : isResolved ? (
              <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-blue-50 dark:bg-blue-950 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-800 flex items-center gap-1">
                <Check size={11} />
                <span>RESOLVED</span>
              </span>
            ) : (
              <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-rose-50 dark:bg-rose-950/80 text-rose-700 dark:text-rose-300 border border-rose-200 dark:border-rose-800 animate-pulse">
                ACTIVE THREAT
              </span>
            )}
          </div>

          <div className="flex items-center gap-2">
            {isActive && (
              <>
                <button
                  onClick={handleApprove}
                  disabled={isUpdatingStatus}
                  className="px-3.5 py-2 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-bold rounded-xl transition-all cursor-pointer flex items-center gap-1.5 shadow-md shadow-emerald-600/20 dark:shadow-emerald-950/40 disabled:opacity-50"
                  title="Approve alert in Supabase and remove from Active Threat Overview"
                >
                  {isUpdatingStatus ? (
                    <RefreshCw size={13} className="animate-spin" />
                  ) : (
                    <CheckCircle2 size={14} />
                  )}
                  <span>Approve Threat</span>
                </button>

                <button
                  onClick={handleResolve}
                  disabled={isUpdatingStatus}
                  className="px-3.5 py-2 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 hover:text-slate-900 dark:hover:text-white font-bold rounded-xl transition-all cursor-pointer flex items-center gap-1.5 disabled:opacity-50"
                  title="Mark alert as resolved in Supabase"
                >
                  {isUpdatingStatus ? (
                    <RefreshCw size={13} className="animate-spin" />
                  ) : (
                    <ShieldCheck size={14} />
                  )}
                  <span>Resolve Alert</span>
                </button>
              </>
            )}

            <button
              onClick={onClose}
              className="px-4 py-2 bg-slate-200 hover:bg-slate-300 dark:bg-slate-900 dark:hover:bg-slate-800 border border-slate-300 dark:border-slate-800 text-slate-800 dark:text-slate-300 hover:text-slate-950 dark:hover:text-white rounded-xl transition-colors cursor-pointer font-semibold"
            >
              Close
            </button>
          </div>
        </div>

      </div>
    </div>
  );
}
