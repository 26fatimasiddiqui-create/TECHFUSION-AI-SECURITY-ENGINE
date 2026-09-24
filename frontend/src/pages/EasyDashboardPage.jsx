import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { 
  Users, 
  ShieldAlert, 
  AlertTriangle, 
  CheckCircle2, 
  ShieldCheck, 
  Clock, 
  ArrowRight, 
  RefreshCw, 
  Sun, 
  Moon, 
  Check, 
  X,
  ExternalLink, 
  Activity,
  Layers,
  ChevronRight,
  Shield,
  Flame
} from 'lucide-react';
import { 
  fetchEmployeesFromSupabase,
  fetchRiskEventsFromSupabase,
  fetchAlertsFromSupabase,
  getAllAccessLogs,
  getApprovals,
  approveAlertInSupabase,
  resolveAlertInSupabase,
  deriveDashboardState,
  supabase,
  isSupabaseConfigured,
  isAlertActive,
  calculateRiskLevel
} from '../services/insightSupabase';
import { useTheme } from '../context/ThemeContext';

export function EasyDashboardPage({ setTab, onActiveAlertCountChange }) {
  const { theme, toggleTheme, isDark } = useTheme();

  // Supabase Data State
  const [employees, setEmployees] = useState([]);
  const [riskEvents, setRiskEvents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [accessLogs, setAccessLogs] = useState([]);
  const [approvals, setApprovals] = useState([]);

  // UI state
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [actionInProgressId, setActionInProgressId] = useState(null);
  const [actionToast, setActionToast] = useState(null);
  const [lastRefreshed, setLastRefreshed] = useState(new Date());
  const [hiddenAlertIds, setHiddenAlertIds] = useState(() => new Set());

  const channelRef = useRef(null);

  // ============================================================================
  // 1. DATA FETCHING: Pure Supabase Single Source of Truth
  // ============================================================================
  const loadSupabaseData = useCallback(async (isSilent = false) => {
    if (!isSilent) setIsLoading(true);
    setIsRefreshing(true);

    if (!isSupabaseConfigured || !supabase) {
      setEmployees([]);
      setRiskEvents([]);
      setAlerts([]);
      setAccessLogs([]);
      setApprovals([]);
      setIsLoading(false);
      setIsRefreshing(false);
      return;
    }

    try {
      const [empRes, riskRes, altRes, logRes, appRes] = await Promise.all([
        fetchEmployeesFromSupabase(),
        fetchRiskEventsFromSupabase(),
        fetchAlertsFromSupabase(),
        getAllAccessLogs(),
        getApprovals()
      ]);

      const empData = empRes.data || [];
      const riskData = riskRes.data || [];
      const altData = altRes.data || [];
      const logData = logRes.data || [];
      const appData = appRes.data || [];

      setEmployees(empData);
      setRiskEvents(riskData);
      setAlerts(altData);
      setAccessLogs(logData);
      setApprovals(appData);
      setLastRefreshed(new Date());
    } catch (err) {
      console.error('EasyDashboard load error:', err);
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  }, []);

  // ============================================================================
  // 2. REALTIME & POLLING
  // ============================================================================
  useEffect(() => {
    loadSupabaseData(false);

    // Supabase Realtime listener
    if (isSupabaseConfigured && supabase) {
      try {
        const channel = supabase
          .channel('public:easy_dashboard_realtime')
          .on(
            'postgres_changes',
            { event: '*', schema: 'public', table: 'alerts' },
            () => loadSupabaseData(true)
          )
          .on(
            'postgres_changes',
            { event: '*', schema: 'public', table: 'risk_events' },
            () => loadSupabaseData(true)
          )
          .on(
            'postgres_changes',
            { event: '*', schema: 'public', table: 'approvals' },
            () => loadSupabaseData(true)
          )
          .subscribe();

        channelRef.current = channel;
      } catch (e) {
        console.warn('Realtime subscription notice:', e);
      }
    }

    // Polling fallback every 8 seconds
    const interval = setInterval(() => {
      loadSupabaseData(true);
    }, 8000);

    return () => {
      clearInterval(interval);
      if (channelRef.current && supabase) {
        supabase.removeChannel(channelRef.current);
      }
    };
  }, [loadSupabaseData]);

  // Unified derived dashboard state
  const dashboardState = useMemo(() => {
    return deriveDashboardState(employees, riskEvents, alerts, accessLogs);
  }, [employees, riskEvents, alerts, accessLogs]);

  // Synchronize layout active badge count
  useEffect(() => {
    if (onActiveAlertCountChange && typeof dashboardState.activeAlertsCount === 'number') {
      onActiveAlertCountChange(dashboardState.activeAlertsCount);
    }
  }, [dashboardState.activeAlertsCount, onActiveAlertCountChange]);

  // ============================================================================
  // 3. DERIVED METRICS FOR NON-TECHNICAL EXECUTIVE VIEW
  // ============================================================================
  const totalEmployees = employees.length || 0;
  
  // High risk employees: score >= 70
  const highRiskEmployees = useMemo(() => {
    return dashboardState.employees.filter(e => (e.latestRiskScore || 0) >= 70);
  }, [dashboardState.employees]);

  // Active alerts
  const activeAlerts = useMemo(() => {
    return (dashboardState.alerts || []).filter(a => !hiddenAlertIds.has(String(a.id)));
  }, [dashboardState.alerts, hiddenAlertIds]);

  // Critical alerts: active and (score >= 85 or severity === CRITICAL)
  const criticalAlerts = useMemo(() => {
    return activeAlerts.filter(a => {
      const score = Number(a.risk_score || 0);
      const sev = String(a.severity || a.alert_type || '').toUpperCase();
      return score >= 85 || sev === 'CRITICAL';
    });
  }, [activeAlerts]);

  // Pending Approvals count (from approvals table or active threats needing sign-off)
  const pendingApprovalsCount = useMemo(() => {
    const rawPending = (approvals || []).filter(a => 
      a.approved === false || a.approved === null || a.status === 'pending' || a.status === 'requested'
    ).length;
    // If approvals table is empty or has zero, fallback to active high/critical alerts requiring action
    if (rawPending > 0) return rawPending;
    return activeAlerts.filter(a => (a.risk_score || 0) >= 70).length;
  }, [approvals, activeAlerts]);

  // Overall Security Status: SAFE | ATTENTION NEEDED | CRITICAL
  const securityStatus = useMemo(() => {
    if (criticalAlerts.length > 0) {
      return {
        level: 'CRITICAL',
        title: 'Critical Threat Alert',
        message: `${criticalAlerts.length} high-severity threat incident${criticalAlerts.length > 1 ? 's' : ''} detected that require immediate containment.`,
        bgClass: 'bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-800/80',
        badgeClass: 'bg-rose-600 text-white shadow-rose-600/30',
        iconColor: 'text-rose-600 dark:text-rose-400',
        glowColor: 'shadow-rose-500/20'
      };
    }
    if (highRiskEmployees.length > 0 || activeAlerts.length > 0) {
      return {
        level: 'ATTENTION NEEDED',
        title: 'Attention Needed',
        message: `${highRiskEmployees.length} employee profile${highRiskEmployees.length > 1 ? 's' : ''} and ${activeAlerts.length} active event${activeAlerts.length > 1 ? 's' : ''} require management review.`,
        bgClass: 'bg-amber-50 dark:bg-amber-950/40 border-amber-300 dark:border-amber-800/80',
        badgeClass: 'bg-amber-500 text-white shadow-amber-500/30',
        iconColor: 'text-amber-600 dark:text-amber-400',
        glowColor: 'shadow-amber-500/20'
      };
    }
    return {
      level: 'SAFE',
      title: 'Systems Secure & Normal',
      message: `All systems nominal. Zero active critical security anomalies detected across ${totalEmployees.toLocaleString()} monitored identities.`,
      bgClass: 'bg-emerald-50 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-800/80',
      badgeClass: 'bg-emerald-600 text-white shadow-emerald-600/30',
      iconColor: 'text-emerald-600 dark:text-emerald-400',
      glowColor: 'shadow-emerald-500/20'
    };
  }, [criticalAlerts.length, highRiskEmployees.length, activeAlerts.length, totalEmployees]);

  // Top 5 Threats Needing Attention
  const topThreats = useMemo(() => {
    return [...activeAlerts]
      .sort((a, b) => (Number(b.risk_score || 0)) - (Number(a.risk_score || 0)))
      .slice(0, 5);
  }, [activeAlerts]);

  // Top 5 Recent Activities (Clean, non-technical format)
  const recentActivities = useMemo(() => {
    const list = [];

    // From access logs
    accessLogs.slice(0, 10).forEach(log => {
      const emp = employees.find(e => e.id === log.employee_id);
      list.push({
        id: `log-${log.id}`,
        userName: emp ? `${emp.name} (${emp.employee_code})` : 'Employee',
        action: log.action ? `${log.action.replace('_', ' ')}: ${log.resource_name || 'System'}` : 'System Access',
        timestamp: log.access_time,
        status: log.success === false ? 'Denied' : 'Normal',
        type: 'log'
      });
    });

    // From risk events
    riskEvents.slice(0, 5).forEach(evt => {
      const emp = employees.find(e => e.id === evt.employee_id);
      list.push({
        id: `evt-${evt.id}`,
        userName: emp ? `${emp.name} (${emp.employee_code})` : 'Employee',
        action: evt.description || evt.event_type || 'Unusual Activity',
        timestamp: evt.detected_at,
        status: 'Flagged',
        type: 'event'
      });
    });

    // Sort chronologically DESC and take top 5
    return list
      .sort((a, b) => new Date(b.timestamp || 0) - new Date(a.timestamp || 0))
      .slice(0, 5);
  }, [accessLogs, riskEvents, employees]);

  // Risk Distribution Summary (LOW / MODERATE / HIGH / CRITICAL)
  const riskDistribution = useMemo(() => {
    return dashboardState.riskDistribution || { LOW: 0, MODERATE: 0, HIGH: 0, CRITICAL: 0 };
  }, [dashboardState.riskDistribution]);

  // ============================================================================
  // 4. ACTION HANDLERS: Approve & Resolve
  // Updates Supabase status, removes threat from active view, preserves history
  // ============================================================================
  const handleApproveThreat = async (alertId, employeeName) => {
    setActionInProgressId(alertId);

    // Hide immediately from UI for instant feedback
    setHiddenAlertIds(prev => new Set([...prev, String(alertId)]));
    // Local optimistic update
    setAlerts(prev => prev.map(a => a.id === alertId ? { ...a, status: 'approved', resolved_at: new Date().toISOString() } : a));

    try {
      const { error } = await approveAlertInSupabase(alertId);
      if (error) throw new Error(error);

      setActionToast({
        type: 'success',
        message: `Threat for ${employeeName || 'employee'} approved & removed from active monitoring.`
      });

      // Refetch to ensure database consistency
      await loadSupabaseData(true);
    } catch (err) {
      console.error('Approve threat notice:', err);
      // Rollback: unhide the alert since the API call failed
      setHiddenAlertIds(prev => {
        const next = new Set(prev);
        next.delete(String(alertId));
        return next;
      });
      setAlerts(prev => prev.map(a => a.id === alertId ? { ...a, status: 'new', resolved_at: null } : a));
      setActionToast({
        type: 'error',
        message: `Failed to approve threat: ${err.message || 'Error updating status'}`
      });
    } finally {
      setActionInProgressId(null);
      setTimeout(() => setActionToast(null), 4000);
    }
  };

  const handleResolveThreat = async (alertId, employeeName) => {
    setActionInProgressId(alertId);

    // Hide immediately from UI for instant feedback
    setHiddenAlertIds(prev => new Set([...prev, String(alertId)]));
    // Local optimistic update
    setAlerts(prev => prev.map(a => a.id === alertId ? { ...a, status: 'resolved', resolved_at: new Date().toISOString() } : a));

    try {
      const { error } = await resolveAlertInSupabase(alertId);
      if (error) throw new Error(error);

      setActionToast({
        type: 'success',
        message: `Threat for ${employeeName || 'employee'} resolved & cleared.`
      });

      // Refetch to ensure database consistency
      await loadSupabaseData(true);
    } catch (err) {
      console.error('Resolve threat notice:', err);
      // Rollback: unhide the alert since the API call failed
      setHiddenAlertIds(prev => {
        const next = new Set(prev);
        next.delete(String(alertId));
        return next;
      });
      setAlerts(prev => prev.map(a => a.id === alertId ? { ...a, status: 'new', resolved_at: null } : a));
      setActionToast({
        type: 'error',
        message: `Failed to resolve threat: ${err.message || 'Error updating status'}`
      });
    } finally {
      setActionInProgressId(null);
      setTimeout(() => setActionToast(null), 4000);
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-800 dark:text-slate-100 font-sans pb-16 transition-colors duration-200">
      
      {/* Toast Notification */}
      {actionToast && (
        <div className={`fixed bottom-6 right-6 z-50 p-4 rounded-xl shadow-xl border flex items-center gap-3 animate-fade-in ${
          actionToast.type === 'success' 
            ? 'bg-emerald-900/90 text-white border-emerald-600' 
            : 'bg-rose-900/90 text-white border-rose-600'
        }`}>
          {actionToast.type === 'success' ? <CheckCircle2 size={18} /> : <AlertTriangle size={18} />}
          <span className="text-xs font-semibold">{actionToast.message}</span>
          <button onClick={() => setActionToast(null)} className="ml-2 hover:opacity-80 text-white">
            <X size={14} />
          </button>
        </div>
      )}

      {/* Top Header Bar */}
      <header className="bg-white/95 dark:bg-slate-900/95 border-b border-slate-200 dark:border-slate-800 backdrop-blur-md px-4 sm:px-8 py-4 sticky top-0 z-30 shadow-xs transition-colors">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          
          <div className="flex items-center gap-3.5">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-600 to-blue-600 flex items-center justify-center text-white shadow-md shadow-cyan-500/20 shrink-0">
              <ShieldCheck size={22} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl sm:text-2xl font-black text-slate-900 dark:text-white tracking-tight">
                  Easy Dashboard
                </h1>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-cyan-100 dark:bg-cyan-950 text-cyan-700 dark:text-cyan-300 border border-cyan-300 dark:border-cyan-800">
                  Non-Technical View
                </span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Executive Security Overview & Decision Workbench
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2.5">
            {/* Last refreshed pill */}
            <span className="text-[11px] text-slate-400 dark:text-slate-500 hidden md:inline">
              Synced {lastRefreshed.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
            </span>

            {/* Refresh Button */}
            <button
              onClick={() => loadSupabaseData(false)}
              disabled={isRefreshing}
              className="p-2 sm:px-3 sm:py-2 rounded-xl bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700 text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer shadow-xs"
              title="Refresh all data directly from Supabase"
            >
              <RefreshCw size={14} className={isRefreshing ? 'animate-spin text-cyan-600' : ''} />
              <span className="hidden sm:inline">Refresh</span>
            </button>

            {/* Switch to Technical Dashboard Link */}
            <button
              onClick={() => setTab ? setTab('technical') : null}
              className="px-3.5 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 text-xs font-bold flex items-center gap-1.5 transition-all cursor-pointer shadow-xs"
              title="Open full SOC Technical Dashboard"
            >
              <Layers size={14} />
              <span>Technical SOC View</span>
              <ArrowRight size={13} />
            </button>

            {/* Theme Toggle */}
            <button
              onClick={toggleTheme}
              className="p-2 rounded-xl bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700 transition-all cursor-pointer"
              title={isDark ? "Switch to Light Mode" : "Switch to Dark Mode"}
            >
              {isDark ? <Sun size={15} className="text-amber-400" /> : <Moon size={15} className="text-slate-600" />}
            </button>
          </div>

        </div>
      </header>

      {/* Main Container */}
      <main className="max-w-7xl mx-auto px-4 sm:px-8 pt-6 space-y-6">

        {/* ================================================================== */}
        {/* 1. KPI CARDS                                                       */}
        {/* ================================================================== */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          
          {/* Card 1: Total Employees */}
          <div className="p-5 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800/80 shadow-xs hover:shadow-md transition-all">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                Total Employees
              </span>
              <div className="p-2 rounded-xl bg-blue-50 dark:bg-blue-950/60 text-blue-600 dark:text-blue-400">
                <Users size={18} />
              </div>
            </div>
            <div className="text-2xl sm:text-3xl font-black text-slate-900 dark:text-white">
              {totalEmployees.toLocaleString()}
            </div>
            <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
              Active monitored corporate identities
            </p>
          </div>

          {/* Card 2: High Risk Employees */}
          <div className="p-5 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800/80 shadow-xs hover:shadow-md transition-all">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                High Risk Employees
              </span>
              <div className="p-2 rounded-xl bg-amber-50 dark:bg-amber-950/60 text-amber-600 dark:text-amber-400">
                <AlertTriangle size={18} />
              </div>
            </div>
            <div className={`text-2xl sm:text-3xl font-black ${
              highRiskEmployees.length > 0 ? 'text-amber-600 dark:text-amber-400' : 'text-slate-900 dark:text-white'
            }`}>
              {highRiskEmployees.length}
            </div>
            <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
              Score ≥ 70 requiring review
            </p>
          </div>

          {/* Card 3: Critical Alerts */}
          <div className="p-5 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800/80 shadow-xs hover:shadow-md transition-all">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                Critical Alerts
              </span>
              <div className="p-2 rounded-xl bg-rose-50 dark:bg-rose-950/60 text-rose-600 dark:text-rose-400">
                <ShieldAlert size={18} />
              </div>
            </div>
            <div className={`text-2xl sm:text-3xl font-black ${
              criticalAlerts.length > 0 ? 'text-rose-600 dark:text-rose-400' : 'text-slate-900 dark:text-white'
            }`}>
              {criticalAlerts.length}
            </div>
            <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
              Unresolved severe threats
            </p>
          </div>

          {/* Card 4: Pending Approvals */}
          <div className="p-5 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800/80 shadow-xs hover:shadow-md transition-all">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                Pending Approvals
              </span>
              <div className="p-2 rounded-xl bg-purple-50 dark:bg-purple-950/60 text-purple-600 dark:text-purple-400">
                <Clock size={18} />
              </div>
            </div>
            <div className={`text-2xl sm:text-3xl font-black ${
              pendingApprovalsCount > 0 ? 'text-purple-600 dark:text-purple-400' : 'text-slate-900 dark:text-white'
            }`}>
              {pendingApprovalsCount}
            </div>
            <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
              Awaiting supervisor authorization
            </p>
          </div>

        </div>

        {/* ================================================================== */}
        {/* 2. MAIN SECTION: "Security Status"                                 */}
        {/* ================================================================== */}
        <div className={`p-6 rounded-3xl border shadow-sm transition-all ${securityStatus.bgClass}`}>
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            
            <div className="flex items-center gap-4">
              <div className={`w-14 h-14 rounded-2xl flex items-center justify-center shadow-lg shrink-0 ${
                securityStatus.level === 'SAFE' 
                  ? 'bg-emerald-600 text-white shadow-emerald-600/30' 
                  : securityStatus.level === 'ATTENTION NEEDED'
                  ? 'bg-amber-500 text-white shadow-amber-500/30'
                  : 'bg-rose-600 text-white shadow-rose-600/30 animate-pulse'
              }`}>
                {securityStatus.level === 'SAFE' ? (
                  <ShieldCheck size={32} />
                ) : securityStatus.level === 'ATTENTION NEEDED' ? (
                  <AlertTriangle size={30} />
                ) : (
                  <ShieldAlert size={30} />
                )}
              </div>

              <div>
                <div className="flex items-center gap-2.5 flex-wrap">
                  <span className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 font-mono">
                    Security Status
                  </span>
                  <span className={`px-3 py-0.5 rounded-full text-xs font-black tracking-wide uppercase ${securityStatus.badgeClass}`}>
                    {securityStatus.level}
                  </span>
                </div>
                <h2 className="text-xl sm:text-2xl font-black text-slate-900 dark:text-white mt-0.5">
                  {securityStatus.title}
                </h2>
                <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-300 max-w-2xl mt-1">
                  {securityStatus.message}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-3 shrink-0 w-full md:w-auto">
              <button
                onClick={() => setTab ? setTab('threats') : null}
                className="w-full md:w-auto px-5 py-2.5 rounded-xl bg-white dark:bg-slate-900 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-900 dark:text-white border border-slate-300 dark:border-slate-700 text-xs font-bold transition-all shadow-xs flex items-center justify-center gap-2 cursor-pointer"
              >
                <span>View Full Threat Feed</span>
                <ChevronRight size={14} />
              </button>
            </div>

          </div>
        </div>

        {/* ================================================================== */}
        {/* 3. THREATS NEEDING ATTENTION (Max 5) & RISK SUMMARY               */}
        {/* ================================================================== */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          
          {/* Threats Needing Attention (2 Columns) */}
          <div className="lg:col-span-2 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
                  <Flame size={18} className="text-rose-600 dark:text-rose-400" />
                  <span>Threats Needing Attention</span>
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Most important active threats requiring immediate action
                </p>
              </div>

              <button
                onClick={() => setTab ? setTab('threats') : null}
                className="text-xs font-bold text-cyan-600 dark:text-cyan-400 hover:underline flex items-center gap-1 cursor-pointer"
              >
                <span>View All Threats</span>
                <ArrowRight size={12} />
              </button>
            </div>

            {/* Threat List */}
            {topThreats.length === 0 ? (
              <div className="p-8 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-center space-y-2">
                <CheckCircle2 size={32} className="mx-auto text-emerald-500" />
                <h4 className="text-sm font-bold text-slate-900 dark:text-white">
                  No Active Threats
                </h4>
                <p className="text-xs text-slate-500 dark:text-slate-400 max-w-sm mx-auto">
                  All security threats have been resolved or approved. The environment is currently operating within safe parameters.
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                {topThreats.map((threat) => {
                  const score = Number(threat.risk_score || 0);
                  const isCritical = score >= 85 || threat.severity === 'CRITICAL';
                  const isHigh = !isCritical && (score >= 70 || threat.severity === 'HIGH');
                  const isActionLoading = actionInProgressId === threat.id;

                  return (
                    <div 
                      key={threat.id}
                      className="p-4 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs hover:border-slate-300 dark:hover:border-slate-700 transition-all flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4"
                    >
                      <div className="space-y-1.5 min-w-0 flex-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-bold text-sm text-slate-900 dark:text-white truncate">
                            {threat.employee_name || 'Employee'}
                          </span>
                          <span className="text-[11px] font-mono text-slate-400">
                            ({threat.employee_code || 'EMP'})
                          </span>
                          
                          {/* Risk Level Badge */}
                          <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${
                            isCritical 
                              ? 'bg-rose-100 dark:bg-rose-950 text-rose-700 dark:text-rose-300 border border-rose-300 dark:border-rose-800'
                              : isHigh 
                              ? 'bg-amber-100 dark:bg-amber-950 text-amber-700 dark:text-amber-300 border border-amber-300 dark:border-amber-800'
                              : 'bg-blue-100 dark:bg-blue-950 text-blue-700 dark:text-blue-300 border border-blue-300 dark:border-blue-800'
                          }`}>
                            {threat.severity || calculateRiskLevel(score)}
                          </span>

                          {/* Risk Score */}
                          <span className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold ${
                            score >= 70 ? 'bg-rose-50 dark:bg-rose-950/60 text-rose-600 dark:text-rose-400' : 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300'
                          }`}>
                            Score: {score}/100
                          </span>
                        </div>

                        {/* Short Description */}
                        <p className="text-xs text-slate-600 dark:text-slate-300 line-clamp-2">
                          {threat.message || 'Suspicious access pattern detected'}
                        </p>

                        <div className="text-[10px] text-slate-400 flex items-center gap-1 font-mono">
                          <Clock size={11} />
                          <span>{threat.created_at ? new Date(threat.created_at).toLocaleString() : 'Recently'}</span>
                        </div>
                      </div>

                      {/* Action Buttons: Approve & Resolve */}
                      <div className="flex items-center gap-2 shrink-0 w-full sm:w-auto pt-2 sm:pt-0 border-t sm:border-t-0 border-slate-100 dark:border-slate-800">
                        <button
                          onClick={() => handleApproveThreat(threat.id, threat.employee_name)}
                          disabled={isActionLoading}
                          className="flex-1 sm:flex-initial px-3.5 py-1.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold transition-all shadow-xs flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-50"
                          title="Authorize activity and remove from active threat feed"
                        >
                          <Check size={13} />
                          <span>Approve</span>
                        </button>

                        <button
                          onClick={() => handleResolveThreat(threat.id, threat.employee_name)}
                          disabled={isActionLoading}
                          className="flex-1 sm:flex-initial px-3.5 py-1.5 rounded-xl bg-white dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 border border-slate-300 dark:border-slate-700 text-xs font-bold transition-all shadow-xs flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-50"
                          title="Mark incident as resolved"
                        >
                          <CheckCircle2 size={13} className="text-cyan-600 dark:text-cyan-400" />
                          <span>Resolve</span>
                        </button>
                      </div>

                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Right Column: RISK SUMMARY & STATUS */}
          <div className="space-y-4">
            <div>
              <h3 className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <Shield size={18} className="text-cyan-600 dark:text-cyan-400" />
                <span>Risk Summary</span>
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Workforce risk distribution tier counts
              </p>
            </div>

            {/* Risk Breakdown Cards */}
            <div className="p-5 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 space-y-4 shadow-xs">
              
              {/* Progress bar visual */}
              <div className="h-3.5 rounded-full bg-slate-100 dark:bg-slate-800 overflow-hidden flex shadow-inner">
                <div 
                  style={{ width: `${totalEmployees > 0 ? (riskDistribution.LOW / totalEmployees) * 100 : 90}%` }} 
                  className="bg-emerald-500 transition-all duration-500" 
                  title={`LOW: ${riskDistribution.LOW}`}
                />
                <div 
                  style={{ width: `${totalEmployees > 0 ? (riskDistribution.MODERATE / totalEmployees) * 100 : 7}%` }} 
                  className="bg-amber-500 transition-all duration-500" 
                  title={`MODERATE: ${riskDistribution.MODERATE}`}
                />
                <div 
                  style={{ width: `${totalEmployees > 0 ? (riskDistribution.HIGH / totalEmployees) * 100 : 2}%` }} 
                  className="bg-orange-500 transition-all duration-500" 
                  title={`HIGH: ${riskDistribution.HIGH}`}
                />
                <div 
                  style={{ width: `${totalEmployees > 0 ? (riskDistribution.CRITICAL / totalEmployees) * 100 : 1}%` }} 
                  className="bg-rose-600 transition-all duration-500" 
                  title={`CRITICAL: ${riskDistribution.CRITICAL}`}
                />
              </div>

              {/* Counts Breakdown List */}
              <div className="space-y-2.5 pt-1 text-xs">
                
                {/* Low Risk */}
                <div className="flex items-center justify-between p-2 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-100 dark:border-slate-800/80">
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
                    <span className="font-semibold text-slate-700 dark:text-slate-300">LOW RISK</span>
                  </div>
                  <span className="font-mono font-bold text-slate-900 dark:text-white">
                    {riskDistribution.LOW.toLocaleString()}
                  </span>
                </div>

                {/* Moderate Risk */}
                <div className="flex items-center justify-between p-2 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-100 dark:border-slate-800/80">
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span>
                    <span className="font-semibold text-slate-700 dark:text-slate-300">MODERATE RISK</span>
                  </div>
                  <span className="font-mono font-bold text-slate-900 dark:text-white">
                    {riskDistribution.MODERATE.toLocaleString()}
                  </span>
                </div>

                {/* High Risk */}
                <div className="flex items-center justify-between p-2 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-100 dark:border-slate-800/80">
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-orange-500"></span>
                    <span className="font-semibold text-slate-700 dark:text-slate-300">HIGH RISK</span>
                  </div>
                  <span className="font-mono font-bold text-orange-600 dark:text-orange-400">
                    {riskDistribution.HIGH.toLocaleString()}
                  </span>
                </div>

                {/* Critical Risk */}
                <div className="flex items-center justify-between p-2 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-100 dark:border-slate-800/80">
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-rose-600"></span>
                    <span className="font-semibold text-slate-700 dark:text-slate-300">CRITICAL RISK</span>
                  </div>
                  <span className="font-mono font-bold text-rose-600 dark:text-rose-400">
                    {riskDistribution.CRITICAL.toLocaleString()}
                  </span>
                </div>

              </div>

              {/* View all employees link */}
              <button
                onClick={() => setTab ? setTab('employees') : null}
                className="w-full py-2.5 rounded-xl bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 text-xs font-bold transition-all text-center flex items-center justify-center gap-1.5 cursor-pointer"
              >
                <Users size={14} />
                <span>View All Employees Directory</span>
              </button>

            </div>

          </div>

        </div>

        {/* ================================================================== */}
        {/* 4. RECENT ACTIVITY (Latest 5 Relevant Activities)                  */}
        {/* ================================================================== */}
        <div className="space-y-4 pt-2">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <Activity size={18} className="text-blue-600 dark:text-blue-400" />
                <span>Recent Activity</span>
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Latest 5 relevant security events logged from actual operations
              </p>
            </div>

            <button
              onClick={() => setTab ? setTab('activity') : null}
              className="text-xs font-bold text-cyan-600 dark:text-cyan-400 hover:underline flex items-center gap-1 cursor-pointer"
            >
              <span>View All Activity</span>
              <ArrowRight size={12} />
            </button>
          </div>

          <div className="p-4 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs divide-y divide-slate-100 dark:divide-slate-800/80">
            {recentActivities.length === 0 ? (
              <div className="py-6 text-center text-xs text-slate-400">
                No recent activity records available.
              </div>
            ) : (
              recentActivities.map((act) => (
                <div key={act.id} className="py-3 first:pt-1 last:pb-1 flex items-center justify-between gap-4">
                  <div className="flex items-center gap-3 min-w-0">
                    <div className={`p-2 rounded-xl shrink-0 ${
                      act.type === 'event' 
                        ? 'bg-rose-50 dark:bg-rose-950/60 text-rose-600 dark:text-rose-400' 
                        : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300'
                    }`}>
                      {act.type === 'event' ? <AlertTriangle size={15} /> : <Activity size={15} />}
                    </div>
                    <div className="min-w-0">
                      <div className="text-xs font-bold text-slate-900 dark:text-white truncate">
                        {act.userName}
                      </div>
                      <p className="text-[11px] text-slate-600 dark:text-slate-400 truncate">
                        {act.action}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 shrink-0 text-right">
                    <span className="text-[10px] text-slate-400 font-mono">
                      {act.timestamp ? new Date(act.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Recently'}
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      act.status === 'Denied' || act.status === 'Flagged'
                        ? 'bg-rose-100 dark:bg-rose-950 text-rose-700 dark:text-rose-300'
                        : 'bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300'
                    }`}>
                      {act.status}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

      </main>

    </div>
  );
}

export default EasyDashboardPage;
