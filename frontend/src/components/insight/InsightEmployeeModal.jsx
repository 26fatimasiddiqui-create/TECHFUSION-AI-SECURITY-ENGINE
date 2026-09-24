import React, { useState, useEffect } from 'react';
import { 
  User, 
  X, 
  Mail, 
  MapPin, 
  Briefcase, 
  ShieldAlert, 
  Activity, 
  Clock, 
  Play, 
  CheckCircle2, 
  AlertTriangle,
  History,
  TrendingUp,
  FileText,
  Lock,
  RefreshCw
} from 'lucide-react';
import { 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  Tooltip, 
  ResponsiveContainer 
} from 'recharts';
import { fetchEmployeeDetailFromSupabase, calculateRiskLevel } from '../../services/insightSupabase';

export function InsightEmployeeModal({ 
  employee, 
  onClose, 
  onSimulateThreat 
}) {
  const [details, setDetails] = useState({
    accessLogs: [],
    riskEvents: [],
    alerts: [],
    incidents: [],
    approvals: []
  });
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    if (!employee?.id) return;
    let isMounted = true;
    setIsLoading(true);

    fetchEmployeeDetailFromSupabase(employee.id)
      .then((res) => {
        if (isMounted) {
          setDetails(res);
          setIsLoading(false);
        }
      })
      .catch((err) => {
        console.error('Error fetching employee relations:', err);
        if (isMounted) setIsLoading(false);
      });

    return () => {
      isMounted = false;
    };
  }, [employee?.id]);

  if (!employee) return null;

  const currentRiskScore = employee.latestRiskScore || 0;
  const currentRiskLevel = calculateRiskLevel(currentRiskScore);

  const getRiskColor = (score) => {
    if (score >= 85) return 'text-rose-500';
    if (score >= 70) return 'text-orange-500';
    if (score >= 40) return 'text-amber-500';
    return 'text-emerald-500';
  };

  // Build risk history strictly from real risk_events (ordered by detected_at ASC)
  const chartData = (details.riskEvents || []).map((evt) => ({
    detected_at: evt.detected_at 
      ? new Date(evt.detected_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) 
      : '--:--',
    risk_score: Number(evt.risk_score || 0),
    description: evt.description
  }));

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4 overflow-y-auto animate-in fade-in duration-200">
      <div 
        className="w-full max-w-4xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-2xl overflow-hidden my-6 max-h-[90vh] flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Modal Header */}
        <div className="p-5 border-b border-slate-100 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/70 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-cyan-50 dark:bg-cyan-950 border border-cyan-200 dark:border-cyan-800 text-cyan-700 dark:text-cyan-400 flex items-center justify-center font-bold font-mono">
              <User size={20} />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="text-base font-bold text-slate-900 dark:text-white font-mono">{employee.name}</h3>
                <span className="px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-cyan-700 dark:text-cyan-300 font-mono text-xs border border-slate-200 dark:border-slate-700">
                  {employee.employee_code || employee.id}
                </span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${
                  currentRiskLevel === 'CRITICAL'
                    ? 'bg-rose-50 dark:bg-rose-950/90 text-rose-700 dark:text-rose-300 border-rose-200 dark:border-rose-700'
                    : currentRiskLevel === 'HIGH'
                    ? 'bg-orange-50 dark:bg-orange-950/90 text-orange-700 dark:text-orange-300 border-orange-200 dark:border-orange-700'
                    : currentRiskLevel === 'MODERATE'
                    ? 'bg-amber-50 dark:bg-amber-950/90 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-700'
                    : 'bg-emerald-50 dark:bg-emerald-950/90 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-700'
                }`}>
                  {currentRiskLevel} RISK
                </span>
                <span className="text-[10px] text-slate-500 font-mono">
                  Status: {employee.status || 'ACTIVE'}
                </span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 font-sans mt-0.5">
                {employee.role} • {employee.department}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {onSimulateThreat && (
              <button
                onClick={() => onSimulateThreat(employee)}
                className="px-3 py-1.5 rounded-xl bg-rose-50 hover:bg-rose-100 dark:bg-rose-950 dark:hover:bg-rose-900 border border-rose-200 dark:border-rose-700 text-rose-700 dark:text-rose-200 text-xs font-mono font-bold flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                <Play size={12} />
                <span>Simulate Threat</span>
              </button>
            )}

            <button
              onClick={onClose}
              className="p-1.5 rounded-xl bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors cursor-pointer"
            >
              <X size={16} />
            </button>
          </div>
        </div>

        {/* Modal Scrollable Body */}
        <div className="p-6 space-y-6 overflow-y-auto flex-1 font-mono text-xs">
          
          {/* Top Info Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3">
            <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1">
              <span className="text-slate-500 dark:text-slate-400 text-[10px] uppercase block">LATEST RISK SCORE</span>
              <div className={`text-2xl font-black ${getRiskColor(currentRiskScore)}`}>
                {currentRiskScore} <span className="text-xs text-slate-400 dark:text-slate-500 font-normal">/ 100</span>
              </div>
            </div>

            <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1">
              <span className="text-slate-500 dark:text-slate-400 text-[10px] uppercase block">SUPABASE UUID</span>
              <div className="text-[11px] text-cyan-700 dark:text-cyan-300 truncate" title={employee.id}>
                {employee.id}
              </div>
            </div>

            <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1">
              <span className="text-slate-500 dark:text-slate-400 text-[10px] uppercase block">EMAIL</span>
              <div className="text-[11px] text-slate-800 dark:text-slate-300 truncate font-sans" title={employee.email}>
                {employee.email || 'N/A'}
              </div>
            </div>

            <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1">
              <span className="text-slate-500 dark:text-slate-400 text-[10px] uppercase block">DATABASE CREATED</span>
              <div className="text-[11px] text-slate-800 dark:text-slate-300 truncate font-sans">
                {employee.created_at ? new Date(employee.created_at).toLocaleDateString() : 'N/A'}
              </div>
            </div>
          </div>

          {/* Loading Indicator */}
          {isLoading && (
            <div className="p-4 text-center text-slate-500 dark:text-slate-400 flex items-center justify-center gap-2">
              <RefreshCw size={14} className="animate-spin text-cyan-600 dark:text-cyan-400" />
              <span>Fetching employee records from Supabase...</span>
            </div>
          )}

          {/* 1. Risk History Recharts Line Chart (Pure risk_events from Supabase) */}
          <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-3">
            <div className="flex items-center justify-between text-xs">
              <div className="flex items-center gap-2 font-bold text-slate-800 dark:text-slate-200">
                <TrendingUp size={15} className="text-cyan-600 dark:text-cyan-400" />
                <span>Risk History (From Supabase risk_events: {details.riskEvents.length})</span>
              </div>
              <span className="text-[10px] text-slate-500 dark:text-slate-400">Ordered by detected_at</span>
            </div>

            {chartData.length === 0 ? (
              <div className="h-28 flex items-center justify-center text-slate-500 text-[11px]">
                No risk history available
              </div>
            ) : (
              <div className="h-36 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={chartData}>
                    <XAxis dataKey="detected_at" stroke="#94a3b8" fontSize={10} />
                    <YAxis domain={[0, 100]} stroke="#94a3b8" fontSize={10} />
                    <Tooltip 
                      contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '11px', color: '#f8fafc' }}
                    />
                    <Line 
                      type="monotone" 
                      dataKey="risk_score" 
                      stroke="#f43f5e" 
                      strokeWidth={2.5} 
                      dot={{ fill: '#f43f5e', r: 3 }}
                      activeDot={{ r: 5 }}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            )}
          </div>

          {/* 2. Real Risk Events List */}
          <div className="space-y-2">
            <div className="text-[11px] uppercase tracking-wider text-slate-600 dark:text-slate-400 font-bold flex items-center gap-1.5">
              <AlertTriangle size={13} className="text-amber-500" />
              <span>Supabase Risk Events ({details.riskEvents.length})</span>
            </div>
            {details.riskEvents.length === 0 ? (
              <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-slate-500">
                No risk data available.
              </div>
            ) : (
              <div className="space-y-2 max-h-48 overflow-y-auto">
                {details.riskEvents.map((evt) => (
                  <div key={evt.id} className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 flex items-center justify-between gap-3">
                    <div className="space-y-0.5 font-sans">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-slate-900 dark:text-white text-xs">{evt.event_type}</span>
                        <span className={`px-1.5 py-0.2 rounded text-[9px] font-mono border ${
                          evt.severity === 'CRITICAL' ? 'bg-rose-50 dark:bg-rose-950 text-rose-700 dark:text-rose-300 border-rose-200 dark:border-rose-800' :
                          evt.severity === 'HIGH' ? 'bg-orange-50 dark:bg-orange-950 text-orange-700 dark:text-orange-300 border-orange-200 dark:border-orange-800' :
                          'bg-slate-100 dark:bg-slate-900 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-800'
                        }`}>
                          Score: {evt.risk_score} • {evt.severity}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-600 dark:text-slate-400">{evt.description}</p>
                    </div>
                    <span className="text-[10px] text-slate-500 shrink-0 font-mono">
                      {evt.detected_at ? new Date(evt.detected_at).toLocaleString() : '--'}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* 3. Real Supabase Access Logs */}
          <div className="space-y-2">
            <div className="text-[11px] uppercase tracking-wider text-slate-600 dark:text-slate-400 font-bold flex items-center gap-1.5">
              <History size={13} className="text-cyan-600 dark:text-cyan-400" />
              <span>Supabase Access Logs ({details.accessLogs.length})</span>
            </div>
            {details.accessLogs.length === 0 ? (
              <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-slate-500">
                No access logs recorded for this employee.
              </div>
            ) : (
              <div className="space-y-2 max-h-48 overflow-y-auto">
                {details.accessLogs.map((log) => (
                  <div key={log.id} className="p-2.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 flex items-center justify-between gap-2 text-xs">
                    <div className="flex items-center gap-2 font-mono">
                      <span className={`w-2 h-2 rounded-full ${log.success ? 'bg-emerald-500' : 'bg-rose-500'}`} />
                      <span className="font-bold text-slate-800 dark:text-slate-200">{log.action}</span>
                      <span className="text-slate-600 dark:text-slate-400">{log.resource_name}</span>
                      <span className="text-slate-400 dark:text-slate-600 text-[10px]">({log.resource_type})</span>
                    </div>
                    <span className="text-[10px] text-slate-500 font-mono">
                      {log.access_time ? new Date(log.access_time).toLocaleTimeString() : '--'}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* 4. Real Associated Supabase Alerts */}
          <div className="space-y-2">
            <div className="text-[11px] uppercase tracking-wider text-slate-600 dark:text-slate-400 font-bold flex items-center gap-1.5">
              <ShieldAlert size={13} className="text-rose-500" />
              <span>Supabase Alerts ({details.alerts.length})</span>
            </div>
            {details.alerts.length === 0 ? (
              <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-slate-500">
                No active alerts.
              </div>
            ) : (
              <div className="space-y-2 max-h-48 overflow-y-auto">
                {details.alerts.map((alt) => (
                  <div key={alt.id} className="p-3 rounded-xl bg-rose-50/50 dark:bg-rose-950/20 border border-rose-200 dark:border-rose-800/80 flex items-center justify-between gap-2">
                    <div className="space-y-0.5 font-sans">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold text-rose-700 dark:text-rose-300 font-mono">{alt.id}</span>
                        <span className="text-[10px] px-2 py-0.5 rounded bg-rose-50 dark:bg-rose-950 border border-rose-200 dark:border-rose-700 text-rose-700 dark:text-rose-300 font-mono">
                          Score: {alt.risk_score} • {alt.alert_type}
                        </span>
                        <span className="text-[10px] text-slate-500 dark:text-slate-400">Status: {alt.status}</span>
                      </div>
                      <p className="text-xs text-slate-700 dark:text-slate-200">{alt.message}</p>
                    </div>
                    <span className="text-[10px] text-slate-500 dark:text-slate-400 font-mono">
                      {alt.created_at ? new Date(alt.created_at).toLocaleTimeString() : '--'}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* 5. Real Supabase Incidents */}
          {details.incidents.length > 0 && (
            <div className="space-y-2">
              <div className="text-[11px] uppercase tracking-wider text-slate-600 dark:text-slate-400 font-bold flex items-center gap-1.5">
                <FileText size={13} className="text-amber-500" />
                <span>Supabase Incidents ({details.incidents.length})</span>
              </div>
              <div className="space-y-2">
                {details.incidents.map((inc) => (
                  <div key={inc.id} className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 flex items-center justify-between gap-2">
                    <div className="space-y-0.5 font-sans">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold text-slate-900 dark:text-white font-mono">{inc.title}</span>
                        <span className="text-[10px] px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 text-amber-700 dark:text-amber-300 font-mono">
                          {inc.severity}
                        </span>
                      </div>
                      <p className="text-xs text-slate-600 dark:text-slate-400">{inc.description}</p>
                    </div>
                    <span className="text-[10px] text-slate-500 font-mono">
                      {inc.created_at ? new Date(inc.created_at).toLocaleDateString() : '--'}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 6. Real Supabase Approvals */}
          {details.approvals.length > 0 && (
            <div className="space-y-2">
              <div className="text-[11px] uppercase tracking-wider text-slate-600 dark:text-slate-400 font-bold flex items-center gap-1.5">
                <Lock size={13} className="text-purple-500" />
                <span>Supabase Approvals ({details.approvals.length})</span>
              </div>
              <div className="space-y-2">
                {details.approvals.map((app) => (
                  <div key={app.id} className="p-2.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 flex items-center justify-between gap-2">
                    <div className="font-sans">
                      <span className="font-bold text-slate-900 dark:text-white text-xs">{app.requested_action} on {app.resource_name}</span>
                      <p className="text-[11px] text-slate-600 dark:text-slate-400">Reason: {app.reason}</p>
                    </div>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 text-purple-700 dark:text-purple-300 font-mono">
                      {app.status}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

        </div>

        {/* Modal Footer */}
        <div className="p-4 border-t border-slate-100 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/80 flex items-center justify-between text-xs font-mono">
          <span className="text-slate-500">Employee ID: {employee.employee_code || employee.id}</span>
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-200 dark:bg-slate-800 hover:bg-slate-300 dark:hover:bg-slate-700 text-slate-800 dark:text-white rounded-xl transition-colors cursor-pointer font-semibold"
          >
            Close Detail
          </button>
        </div>

      </div>
    </div>
  );
}
