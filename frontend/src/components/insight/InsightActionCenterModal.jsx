import React, { useState, useEffect, useMemo } from 'react';
import { 
  X, 
  ShieldAlert, 
  Activity, 
  Clock, 
  CheckCircle2, 
  AlertTriangle,
  TrendingUp,
  History,
  FileText,
  Lock,
  RefreshCw,
  Shield,
  Zap,
  BarChart3,
  Eye,
  ChevronDown,
  ChevronUp,
  Check,
  XCircle,
  Flame,
  User,
  MapPin,
  Briefcase,
  Mail
} from 'lucide-react';
import { 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  Tooltip, 
  ResponsiveContainer,
  AreaChart,
  Area 
} from 'recharts';
import { 
  fetchEmployeeDetailFromSupabase, 
  calculateRiskLevel,
  approveAlertInSupabase,
  resolveAlertInSupabase
} from '../../services/insightSupabase';

export function InsightActionCenterModal({ 
  employee, 
  onClose, 
  onApproveComplete,
  onResolveComplete
}) {
  const [details, setDetails] = useState({
    accessLogs: [],
    riskEvents: [],
    alerts: [],
    incidents: [],
    approvals: []
  });
  const [isLoading, setIsLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('analysis');
  const [actionInProgress, setActionInProgress] = useState(null); // 'approve' | 'resolve' | null
  const [actionResult, setActionResult] = useState(null); // { type, message }
  const [expandedSections, setExpandedSections] = useState({
    riskEvents: true,
    accessLogs: false,
    alerts: true,
    incidents: false
  });

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
        console.error('Error fetching employee details:', err);
        if (isMounted) setIsLoading(false);
      });

    return () => { isMounted = false; };
  }, [employee?.id]);

  if (!employee) return null;

  const currentRiskScore = employee.latestRiskScore || 0;
  const currentRiskLevel = calculateRiskLevel(currentRiskScore);

  const getRiskColor = (score) => {
    if (score >= 85) return '#f43f5e';
    if (score >= 70) return '#f97316';
    if (score >= 40) return '#f59e0b';
    return '#10b981';
  };

  const getRiskBgClass = (score) => {
    if (score >= 85) return 'from-rose-600 to-red-700';
    if (score >= 70) return 'from-orange-500 to-amber-600';
    if (score >= 40) return 'from-amber-500 to-yellow-600';
    return 'from-emerald-500 to-green-600';
  };

  const getRiskTextClass = (level) => {
    const l = (level || '').toUpperCase();
    if (l === 'CRITICAL') return 'text-rose-500';
    if (l === 'HIGH') return 'text-orange-500';
    if (l === 'MODERATE') return 'text-amber-500';
    return 'text-emerald-500';
  };

  // Build chart data from risk events
  const chartData = useMemo(() => {
    return (details.riskEvents || []).map((evt) => ({
      time: evt.detected_at 
        ? new Date(evt.detected_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) 
        : '--:--',
      risk_score: Number(evt.risk_score || 0),
      description: evt.description,
      event_type: evt.event_type
    }));
  }, [details.riskEvents]);

  // Active (non-approved/resolved) alerts for this employee
  const activeAlerts = useMemo(() => {
    return (details.alerts || []).filter(a => {
      const s = (a.status || '').toLowerCase();
      return !['approved', 'resolved', 'dismissed', 'closed'].includes(s);
    });
  }, [details.alerts]);

  // Risk analysis summary
  const analysisMetrics = useMemo(() => {
    const events = details.riskEvents || [];
    const logs = details.accessLogs || [];
    const alerts = details.alerts || [];

    const avgScore = events.length > 0
      ? Math.round(events.reduce((sum, e) => sum + Number(e.risk_score || 0), 0) / events.length)
      : 0;
    
    const maxScore = events.length > 0
      ? Math.max(...events.map(e => Number(e.risk_score || 0)))
      : 0;

    const failedAccess = logs.filter(l => l.success === false).length;
    const criticalEvents = events.filter(e => Number(e.risk_score || 0) >= 85).length;

    return { avgScore, maxScore, failedAccess, criticalEvents, totalEvents: events.length, totalLogs: logs.length, totalAlerts: alerts.length };
  }, [details]);

  const toggleSection = (key) => {
    setExpandedSections(prev => ({ ...prev, [key]: !prev[key] }));
  };

  // Handle approve all active alerts for this employee
  // Also fires even with 0 active alerts — so SOC analyst can mark employee as cleared
  const handleApproveAll = async () => {
    setActionInProgress('approve');
    setActionResult(null);

    try {
      // Approve any remaining active alerts
      if (activeAlerts.length > 0) {
        const results = await Promise.all(
          activeAlerts.map(alt => approveAlertInSupabase(alt.id))
        );
        const errors = results.filter(r => r.error);
        if (errors.length > 0) {
          setActionResult({ 
            type: 'warning', 
            message: `${activeAlerts.length - errors.length}/${activeAlerts.length} alerts approved. Some failed.` 
          });
        } else {
          setActionResult({ 
            type: 'success', 
            message: `${employee.name} approved & marked as cleared.` 
          });
        }
      } else {
        setActionResult({ 
          type: 'success', 
          message: `${employee.name} marked as cleared. Risk lowered to LOW.` 
        });
      }

      // Always notify parent — this is what lowers the risk in the table
      if (onApproveComplete) {
        onApproveComplete(employee.id, activeAlerts.map(a => a.id));
      }

    } catch (err) {
      console.error('Approve all failed:', err);
      setActionResult({ type: 'error', message: `Failed: ${err.message}` });
    } finally {
      setActionInProgress(null);
    }
  };

  // Handle resolve all active alerts
  // Also fires even with 0 active alerts — so SOC analyst can mark employee as cleared
  const handleResolveAll = async () => {
    setActionInProgress('resolve');
    setActionResult(null);

    try {
      if (activeAlerts.length > 0) {
        const results = await Promise.all(
          activeAlerts.map(alt => resolveAlertInSupabase(alt.id))
        );
        const errors = results.filter(r => r.error);
        if (errors.length > 0) {
          setActionResult({ 
            type: 'warning', 
            message: `${activeAlerts.length - errors.length}/${activeAlerts.length} alerts resolved. Some failed.` 
          });
        } else {
          setActionResult({ 
            type: 'success', 
            message: `${employee.name} resolved & marked as cleared.` 
          });
        }
      } else {
        setActionResult({ 
          type: 'success', 
          message: `${employee.name} marked as cleared. Risk lowered to LOW.` 
        });
      }

      // Always notify parent
      if (onResolveComplete) {
        onResolveComplete(employee.id, activeAlerts.map(a => a.id));
      }

    } catch (err) {
      console.error('Resolve all failed:', err);
      setActionResult({ type: 'error', message: `Failed: ${err.message}` });
    } finally {
      setActionInProgress(null);
    }
  };

  const tabs = [
    { id: 'analysis', label: 'Threat Analysis', icon: BarChart3 },
    { id: 'timeline', label: 'Activity Timeline', icon: History },
    { id: 'action', label: 'Take Action', icon: Zap }
  ];

  return (
    <div 
      className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto"
      onClick={onClose}
    >
      <div 
        className="w-full max-w-5xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700/80 rounded-2xl shadow-2xl overflow-hidden my-4 max-h-[92vh] flex flex-col"
        onClick={(e) => e.stopPropagation()}
        style={{ animation: 'actionCenterSlideIn 0.3s ease-out' }}
      >
        {/* ================================================================ */}
        {/* HEADER — Employee Info + Risk Score Gauge                        */}
        {/* ================================================================ */}
        <div className="relative overflow-hidden">
          {/* Background gradient based on risk */}
          <div className={`absolute inset-0 bg-gradient-to-r ${getRiskBgClass(currentRiskScore)} opacity-10 dark:opacity-20`} />
          
          <div className="relative p-5 flex items-start justify-between gap-4 border-b border-slate-200 dark:border-slate-800">
            <div className="flex items-start gap-4 flex-1 min-w-0">
              {/* Risk Score Ring */}
              <div className="relative shrink-0">
                <div className="w-16 h-16 rounded-2xl flex items-center justify-center"
                  style={{ 
                    background: `conic-gradient(${getRiskColor(currentRiskScore)} ${currentRiskScore}%, #1e293b ${currentRiskScore}%)`,
                    padding: '3px'
                  }}
                >
                  <div className="w-full h-full rounded-xl bg-white dark:bg-slate-900 flex items-center justify-center">
                    <span className="text-lg font-black font-mono" style={{ color: getRiskColor(currentRiskScore) }}>
                      {currentRiskScore}
                    </span>
                  </div>
                </div>
                <div className="absolute -bottom-1 -right-1 px-1.5 py-0.5 rounded text-[8px] font-black uppercase tracking-wider"
                  style={{ 
                    backgroundColor: getRiskColor(currentRiskScore) + '20',
                    color: getRiskColor(currentRiskScore),
                    border: `1px solid ${getRiskColor(currentRiskScore)}40`
                  }}
                >
                  {currentRiskLevel}
                </div>
              </div>

              {/* Employee Info */}
              <div className="min-w-0 flex-1 space-y-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <h2 className="text-lg font-bold text-slate-900 dark:text-white truncate">
                    {employee.name}
                  </h2>
                  <span className="px-2 py-0.5 rounded-lg bg-slate-100 dark:bg-slate-800 text-cyan-700 dark:text-cyan-300 font-mono text-xs border border-slate-200 dark:border-slate-700 font-bold">
                    {employee.employee_code || employee.id?.substring(0, 8)}
                  </span>
                </div>
                <div className="flex items-center gap-4 text-xs text-slate-500 dark:text-slate-400 font-sans flex-wrap">
                  <span className="flex items-center gap-1">
                    <Briefcase size={12} /> {employee.role}
                  </span>
                  <span className="flex items-center gap-1">
                    <MapPin size={12} /> {employee.department}
                  </span>
                  {employee.email && (
                    <span className="flex items-center gap-1">
                      <Mail size={12} /> {employee.email}
                    </span>
                  )}
                </div>
                {/* Quick Stats */}
                <div className="flex items-center gap-3 pt-1 flex-wrap">
                  <span className="px-2 py-0.5 rounded-lg text-[10px] font-mono font-bold bg-rose-50 dark:bg-rose-950/60 text-rose-600 dark:text-rose-400 border border-rose-200 dark:border-rose-800">
                    {activeAlerts.length} Active Alert{activeAlerts.length !== 1 ? 's' : ''}
                  </span>
                  <span className="px-2 py-0.5 rounded-lg text-[10px] font-mono font-bold bg-amber-50 dark:bg-amber-950/60 text-amber-600 dark:text-amber-400 border border-amber-200 dark:border-amber-800">
                    {analysisMetrics.totalEvents} Risk Event{analysisMetrics.totalEvents !== 1 ? 's' : ''}
                  </span>
                  <span className="px-2 py-0.5 rounded-lg text-[10px] font-mono font-bold bg-cyan-50 dark:bg-cyan-950/60 text-cyan-600 dark:text-cyan-400 border border-cyan-200 dark:border-cyan-800">
                    {analysisMetrics.totalLogs} Access Log{analysisMetrics.totalLogs !== 1 ? 's' : ''}
                  </span>
                </div>
              </div>
            </div>

            {/* Close button */}
            <button
              onClick={onClose}
              className="p-2 rounded-xl bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors cursor-pointer shrink-0"
            >
              <X size={18} />
            </button>
          </div>
        </div>

        {/* ================================================================ */}
        {/* TAB NAVIGATION                                                   */}
        {/* ================================================================ */}
        <div className="px-5 pt-3 border-b border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950/50">
          <div className="flex items-center gap-1">
            {tabs.map(tab => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`px-4 py-2.5 rounded-t-xl text-xs font-bold flex items-center gap-2 transition-all cursor-pointer border-b-2 ${
                    isActive
                      ? 'bg-white dark:bg-slate-900 text-cyan-700 dark:text-cyan-400 border-cyan-500 shadow-xs'
                      : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white border-transparent hover:bg-white/50 dark:hover:bg-slate-800/50'
                  }`}
                >
                  <Icon size={14} />
                  <span>{tab.label}</span>
                  {tab.id === 'action' && activeAlerts.length > 0 && (
                    <span className="px-1.5 py-0.5 rounded-full bg-rose-500 text-white text-[9px] font-black min-w-[18px] text-center">
                      {activeAlerts.length}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* ================================================================ */}
        {/* TAB CONTENT                                                      */}
        {/* ================================================================ */}
        <div className="flex-1 overflow-y-auto p-5 space-y-5">

          {isLoading && (
            <div className="p-8 text-center text-slate-500 dark:text-slate-400 flex items-center justify-center gap-2">
              <RefreshCw size={16} className="animate-spin text-cyan-600 dark:text-cyan-400" />
              <span className="text-sm font-medium">Loading threat analysis from Supabase...</span>
            </div>
          )}

          {/* ============================================================== */}
          {/* TAB: THREAT ANALYSIS                                           */}
          {/* ============================================================== */}
          {!isLoading && activeTab === 'analysis' && (
            <>
              {/* Analysis Summary Cards */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="p-3.5 rounded-xl bg-gradient-to-br from-slate-50 to-white dark:from-slate-900 dark:to-slate-800 border border-slate-200 dark:border-slate-700 space-y-1">
                  <span className="text-[10px] text-slate-500 dark:text-slate-400 uppercase font-bold tracking-wider block">Current Score</span>
                  <div className="text-2xl font-black" style={{ color: getRiskColor(currentRiskScore) }}>
                    {currentRiskScore}<span className="text-xs text-slate-400 font-normal">/100</span>
                  </div>
                </div>
                <div className="p-3.5 rounded-xl bg-gradient-to-br from-slate-50 to-white dark:from-slate-900 dark:to-slate-800 border border-slate-200 dark:border-slate-700 space-y-1">
                  <span className="text-[10px] text-slate-500 dark:text-slate-400 uppercase font-bold tracking-wider block">Peak Score</span>
                  <div className="text-2xl font-black text-rose-500">
                    {analysisMetrics.maxScore}<span className="text-xs text-slate-400 font-normal">/100</span>
                  </div>
                </div>
                <div className="p-3.5 rounded-xl bg-gradient-to-br from-slate-50 to-white dark:from-slate-900 dark:to-slate-800 border border-slate-200 dark:border-slate-700 space-y-1">
                  <span className="text-[10px] text-slate-500 dark:text-slate-400 uppercase font-bold tracking-wider block">Critical Events</span>
                  <div className="text-2xl font-black text-amber-500">
                    {analysisMetrics.criticalEvents}
                  </div>
                </div>
                <div className="p-3.5 rounded-xl bg-gradient-to-br from-slate-50 to-white dark:from-slate-900 dark:to-slate-800 border border-slate-200 dark:border-slate-700 space-y-1">
                  <span className="text-[10px] text-slate-500 dark:text-slate-400 uppercase font-bold tracking-wider block">Failed Access</span>
                  <div className="text-2xl font-black text-orange-500">
                    {analysisMetrics.failedAccess}
                  </div>
                </div>
              </div>

              {/* Risk Trend Chart */}
              <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-xs font-bold text-slate-800 dark:text-slate-200">
                    <TrendingUp size={14} className="text-cyan-600 dark:text-cyan-400" />
                    <span>Risk Trend Analysis</span>
                    <span className="text-[10px] text-slate-400 font-normal">({chartData.length} data points)</span>
                  </div>
                </div>

                {chartData.length === 0 ? (
                  <div className="h-28 flex items-center justify-center text-slate-500 text-xs">
                    No risk history data available
                  </div>
                ) : (
                  <div className="h-40 w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={chartData}>
                        <defs>
                          <linearGradient id="riskGradient" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor={getRiskColor(currentRiskScore)} stopOpacity={0.3}/>
                            <stop offset="95%" stopColor={getRiskColor(currentRiskScore)} stopOpacity={0}/>
                          </linearGradient>
                        </defs>
                        <XAxis dataKey="time" stroke="#64748b" fontSize={10} />
                        <YAxis domain={[0, 100]} stroke="#64748b" fontSize={10} />
                        <Tooltip 
                          contentStyle={{ 
                            backgroundColor: '#0f172a', 
                            borderColor: '#334155', 
                            borderRadius: '12px', 
                            fontSize: '11px', 
                            color: '#f8fafc',
                            boxShadow: '0 8px 32px rgba(0,0,0,0.3)'
                          }}
                          formatter={(value, name) => [value, 'Risk Score']}
                          labelFormatter={(label) => `Time: ${label}`}
                        />
                        <Area 
                          type="monotone" 
                          dataKey="risk_score" 
                          stroke={getRiskColor(currentRiskScore)} 
                          strokeWidth={2.5} 
                          fill="url(#riskGradient)"
                          dot={{ fill: getRiskColor(currentRiskScore), r: 3, strokeWidth: 0 }}
                          activeDot={{ r: 5, strokeWidth: 0 }}
                        />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </div>

              {/* Collapsible: Risk Events */}
              <CollapsibleSection
                title={`Risk Events (${details.riskEvents.length})`}
                icon={<AlertTriangle size={13} className="text-amber-500" />}
                isOpen={expandedSections.riskEvents}
                onToggle={() => toggleSection('riskEvents')}
              >
                {details.riskEvents.length === 0 ? (
                  <EmptyState message="No risk events recorded" />
                ) : (
                  <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
                    {details.riskEvents.map((evt) => (
                      <div key={evt.id} className="p-3 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 flex items-center justify-between gap-3 hover:border-slate-300 dark:hover:border-slate-700 transition-colors">
                        <div className="space-y-0.5 font-sans min-w-0 flex-1">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-bold text-slate-900 dark:text-white text-xs">{evt.event_type}</span>
                            <span className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-bold border ${
                              evt.severity === 'CRITICAL' ? 'bg-rose-50 dark:bg-rose-950 text-rose-600 dark:text-rose-400 border-rose-200 dark:border-rose-800' :
                              evt.severity === 'HIGH' ? 'bg-orange-50 dark:bg-orange-950 text-orange-600 dark:text-orange-400 border-orange-200 dark:border-orange-800' :
                              'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-700'
                            }`}>
                              {evt.risk_score} • {evt.severity}
                            </span>
                          </div>
                          <p className="text-[11px] text-slate-600 dark:text-slate-400 truncate">{evt.description}</p>
                        </div>
                        <span className="text-[10px] text-slate-500 shrink-0 font-mono">
                          {evt.detected_at ? new Date(evt.detected_at).toLocaleString() : '--'}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </CollapsibleSection>

              {/* Collapsible: Active Alerts */}
              <CollapsibleSection
                title={`Active Alerts (${activeAlerts.length})`}
                icon={<ShieldAlert size={13} className="text-rose-500" />}
                isOpen={expandedSections.alerts}
                onToggle={() => toggleSection('alerts')}
                highlight={activeAlerts.length > 0}
              >
                {activeAlerts.length === 0 ? (
                  <div className="p-4 rounded-xl bg-emerald-50 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-800 text-center">
                    <CheckCircle2 size={24} className="mx-auto text-emerald-500 mb-1" />
                    <p className="text-xs font-semibold text-emerald-700 dark:text-emerald-300">No Active Alerts</p>
                    <p className="text-[10px] text-slate-500">All threats have been approved or resolved.</p>
                  </div>
                ) : (
                  <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
                    {activeAlerts.map((alt) => (
                      <div key={alt.id} className="p-3 rounded-xl bg-rose-50/50 dark:bg-rose-950/20 border border-rose-200 dark:border-rose-800/80 flex items-center justify-between gap-2 hover:border-rose-300 dark:hover:border-rose-700 transition-colors">
                        <div className="space-y-0.5 font-sans min-w-0 flex-1">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-xs font-bold text-rose-700 dark:text-rose-300 font-mono">
                              {alt.alert_type || 'ALERT'}
                            </span>
                            <span className="text-[10px] px-2 py-0.5 rounded bg-rose-50 dark:bg-rose-950 border border-rose-200 dark:border-rose-700 text-rose-700 dark:text-rose-300 font-mono font-bold">
                              Score: {alt.risk_score}
                            </span>
                            <span className="text-[10px] text-slate-500">Status: {alt.status}</span>
                          </div>
                          <p className="text-xs text-slate-700 dark:text-slate-300 truncate">{alt.message}</p>
                        </div>
                        <span className="text-[10px] text-slate-500 font-mono shrink-0">
                          {alt.created_at ? new Date(alt.created_at).toLocaleTimeString() : '--'}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </CollapsibleSection>
            </>
          )}

          {/* ============================================================== */}
          {/* TAB: ACTIVITY TIMELINE                                         */}
          {/* ============================================================== */}
          {!isLoading && activeTab === 'timeline' && (
            <>
              {/* Access Logs */}
              <CollapsibleSection
                title={`Access Logs (${details.accessLogs.length})`}
                icon={<History size={13} className="text-cyan-600 dark:text-cyan-400" />}
                isOpen={true}
                onToggle={() => {}}
              >
                {details.accessLogs.length === 0 ? (
                  <EmptyState message="No access logs recorded" />
                ) : (
                  <div className="space-y-1.5 max-h-64 overflow-y-auto pr-1">
                    {details.accessLogs.map((log) => (
                      <div key={log.id} className="p-2.5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 flex items-center justify-between gap-2 text-xs hover:border-slate-300 dark:hover:border-slate-700 transition-colors">
                        <div className="flex items-center gap-2 font-mono min-w-0">
                          <span className={`w-2 h-2 rounded-full shrink-0 ${log.success === false ? 'bg-rose-500' : 'bg-emerald-500'}`} />
                          <span className="font-bold text-slate-800 dark:text-slate-200">{log.action}</span>
                          <span className="text-slate-600 dark:text-slate-400 truncate">{log.resource_name}</span>
                          <span className="text-slate-400 dark:text-slate-600 text-[10px] shrink-0">({log.resource_type})</span>
                        </div>
                        <span className="text-[10px] text-slate-500 font-mono shrink-0">
                          {log.access_time ? new Date(log.access_time).toLocaleString() : '--'}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </CollapsibleSection>

              {/* Incidents */}
              {details.incidents.length > 0 && (
                <CollapsibleSection
                  title={`Incidents (${details.incidents.length})`}
                  icon={<FileText size={13} className="text-amber-500" />}
                  isOpen={true}
                  onToggle={() => {}}
                >
                  <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                    {details.incidents.map((inc) => (
                      <div key={inc.id} className="p-3 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 flex items-center justify-between gap-2">
                        <div className="space-y-0.5 font-sans">
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-bold text-slate-900 dark:text-white font-mono">{inc.title}</span>
                            <span className="text-[10px] px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-amber-700 dark:text-amber-300 font-mono">
                              {inc.severity}
                            </span>
                          </div>
                          <p className="text-xs text-slate-600 dark:text-slate-400">{inc.description}</p>
                        </div>
                        <span className="text-[10px] text-slate-500 font-mono shrink-0">
                          {inc.created_at ? new Date(inc.created_at).toLocaleDateString() : '--'}
                        </span>
                      </div>
                    ))}
                  </div>
                </CollapsibleSection>
              )}

              {/* Approvals */}
              {details.approvals.length > 0 && (
                <CollapsibleSection
                  title={`Approval History (${details.approvals.length})`}
                  icon={<Lock size={13} className="text-purple-500" />}
                  isOpen={true}
                  onToggle={() => {}}
                >
                  <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                    {details.approvals.map((app) => (
                      <div key={app.id} className="p-2.5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 flex items-center justify-between gap-2">
                        <div className="font-sans">
                          <span className="font-bold text-slate-900 dark:text-white text-xs">{app.requested_action} on {app.resource_name}</span>
                          <p className="text-[11px] text-slate-600 dark:text-slate-400">Reason: {app.reason}</p>
                        </div>
                        <span className="text-[10px] px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-purple-700 dark:text-purple-300 font-mono font-bold shrink-0">
                          {app.status}
                        </span>
                      </div>
                    ))}
                  </div>
                </CollapsibleSection>
              )}
            </>
          )}

          {/* ============================================================== */}
          {/* TAB: TAKE ACTION                                               */}
          {/* ============================================================== */}
          {!isLoading && activeTab === 'action' && (
            <div className="space-y-5">
              {/* Action Result Toast */}
              {actionResult && (
                <div className={`p-4 rounded-xl border flex items-center gap-3 ${
                  actionResult.type === 'success' 
                    ? 'bg-emerald-50 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-800 text-emerald-800 dark:text-emerald-200'
                    : actionResult.type === 'warning'
                    ? 'bg-amber-50 dark:bg-amber-950/40 border-amber-300 dark:border-amber-800 text-amber-800 dark:text-amber-200'
                    : 'bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-800 text-rose-800 dark:text-rose-200'
                }`}
                  style={{ animation: 'actionCenterSlideIn 0.3s ease-out' }}
                >
                  {actionResult.type === 'success' ? <CheckCircle2 size={18} /> : <AlertTriangle size={18} />}
                  <span className="text-sm font-semibold">{actionResult.message}</span>
                </div>
              )}

              {/* Summary before action */}
              <div className="p-5 rounded-2xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-4">
                <div className="flex items-center gap-2 text-sm font-bold text-slate-800 dark:text-slate-200">
                  <Eye size={16} className="text-cyan-600 dark:text-cyan-400" />
                  <span>Action Summary for {employee.name}</span>
                </div>
                
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                  <div className="p-3 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 space-y-1">
                    <span className="text-[10px] text-slate-500 uppercase font-bold block">Risk Level</span>
                    <span className={`text-base font-black ${getRiskTextClass(currentRiskLevel)}`}>
                      {currentRiskLevel}
                    </span>
                  </div>
                  <div className="p-3 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 space-y-1">
                    <span className="text-[10px] text-slate-500 uppercase font-bold block">Pending Alerts</span>
                    <span className="text-base font-black text-rose-500">
                      {activeAlerts.length}
                    </span>
                  </div>
                  <div className="p-3 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 space-y-1">
                    <span className="text-[10px] text-slate-500 uppercase font-bold block">Total Events</span>
                    <span className="text-base font-black text-slate-700 dark:text-slate-300">
                      {analysisMetrics.totalEvents}
                    </span>
                  </div>
                </div>

                {/* Active alerts list */}
                {activeAlerts.length > 0 && (
                  <div className="space-y-2">
                    <span className="text-[10px] text-slate-500 uppercase font-bold tracking-wider">Alerts to be actioned:</span>
                    {activeAlerts.map(alt => (
                      <div key={alt.id} className="p-2.5 rounded-xl bg-rose-50/60 dark:bg-rose-950/20 border border-rose-200 dark:border-rose-800/80 text-xs flex items-center gap-2">
                        <Flame size={12} className="text-rose-500 shrink-0" />
                        <span className="font-bold text-rose-700 dark:text-rose-300 font-mono">{alt.alert_type}</span>
                        <span className="text-slate-600 dark:text-slate-400 truncate flex-1">{alt.message}</span>
                        <span className="text-[10px] font-mono text-slate-500 shrink-0">Score: {alt.risk_score}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Action Buttons */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {/* Approve All */}
                <button
                  onClick={handleApproveAll}
                  disabled={actionInProgress !== null}
                  className="p-5 rounded-2xl bg-gradient-to-br from-emerald-500 to-emerald-600 hover:from-emerald-400 hover:to-emerald-500 disabled:from-slate-400 disabled:to-slate-500 text-white shadow-lg shadow-emerald-500/25 hover:shadow-emerald-500/40 disabled:shadow-none transition-all cursor-pointer disabled:cursor-not-allowed group"
                >
                  <div className="flex items-center gap-3">
                    {actionInProgress === 'approve' ? (
                      <RefreshCw size={22} className="animate-spin" />
                    ) : (
                      <Check size={22} />
                    )}
                    <div className="text-left">
                      <div className="font-bold text-sm">
                        {activeAlerts.length === 0 ? 'Mark as Cleared' : 'Approve & Clear'}
                      </div>
                      <div className="text-xs text-emerald-100 group-disabled:text-slate-300">
                        {activeAlerts.length === 0 
                          ? 'Manually clear this employee — lower risk to LOW' 
                          : `Approve all ${activeAlerts.length} alert(s) and remove from monitoring`
                        }
                      </div>
                    </div>
                  </div>
                </button>

                {/* Resolve All */}
                <button
                  onClick={handleResolveAll}
                  disabled={actionInProgress !== null}
                  className="p-5 rounded-2xl bg-gradient-to-br from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:from-slate-400 disabled:to-slate-500 text-white shadow-lg shadow-cyan-500/25 hover:shadow-cyan-500/40 disabled:shadow-none transition-all cursor-pointer disabled:cursor-not-allowed group"
                >
                  <div className="flex items-center gap-3">
                    {actionInProgress === 'resolve' ? (
                      <RefreshCw size={22} className="animate-spin" />
                    ) : (
                      <CheckCircle2 size={22} />
                    )}
                    <div className="text-left">
                      <div className="font-bold text-sm">
                        {activeAlerts.length === 0 ? 'Mark as Resolved' : 'Resolve & Close'}
                      </div>
                      <div className="text-xs text-cyan-100 group-disabled:text-slate-300">
                        {activeAlerts.length === 0 
                          ? 'Manually resolve this employee — lower risk to LOW' 
                          : `Mark all ${activeAlerts.length} alert(s) as resolved and archive`
                        }
                      </div>
                    </div>
                  </div>
                </button>
              </div>
            </div>
          )}
        </div>

        {/* ================================================================ */}
        {/* FOOTER                                                           */}
        {/* ================================================================ */}
        <div className="p-4 border-t border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/80 flex items-center justify-between text-xs font-mono">
          <span className="text-slate-500 dark:text-slate-400">
            Action Center • {employee.employee_code || employee.id}
          </span>
          <div className="flex items-center gap-2">
            {activeTab !== 'action' && activeAlerts.length > 0 && (
              <button
                onClick={() => setActiveTab('action')}
                className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-xl transition-colors cursor-pointer font-bold flex items-center gap-1.5 shadow-md shadow-rose-500/20"
              >
                <Zap size={13} />
                <span>Take Action ({activeAlerts.length})</span>
              </button>
            )}
            <button
              onClick={onClose}
              className="px-4 py-2 bg-slate-200 dark:bg-slate-800 hover:bg-slate-300 dark:hover:bg-slate-700 text-slate-800 dark:text-white rounded-xl transition-colors cursor-pointer font-semibold"
            >
              Close
            </button>
          </div>
        </div>

      </div>

      {/* Inline animation keyframes */}
      <style>{`
        @keyframes actionCenterSlideIn {
          from { opacity: 0; transform: translateY(16px) scale(0.98); }
          to { opacity: 1; transform: translateY(0) scale(1); }
        }
      `}</style>
    </div>
  );
}

// ========================================================================
// SUB-COMPONENTS
// ========================================================================

function CollapsibleSection({ title, icon, isOpen, onToggle, highlight, children }) {
  return (
    <div className={`rounded-xl border transition-colors ${
      highlight 
        ? 'bg-rose-50/30 dark:bg-rose-950/10 border-rose-200 dark:border-rose-800/60' 
        : 'bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-800'
    }`}>
      <button
        onClick={onToggle}
        className="w-full px-4 py-3 flex items-center justify-between cursor-pointer hover:bg-slate-100/50 dark:hover:bg-slate-800/30 rounded-xl transition-colors"
      >
        <div className="flex items-center gap-2 text-[11px] uppercase tracking-wider font-bold text-slate-600 dark:text-slate-400">
          {icon}
          <span>{title}</span>
        </div>
        {isOpen ? <ChevronUp size={14} className="text-slate-400" /> : <ChevronDown size={14} className="text-slate-400" />}
      </button>
      {isOpen && (
        <div className="px-4 pb-4">
          {children}
        </div>
      )}
    </div>
  );
}

function EmptyState({ message }) {
  return (
    <div className="p-4 text-center text-slate-500 dark:text-slate-400 text-xs">
      {message}
    </div>
  );
}
