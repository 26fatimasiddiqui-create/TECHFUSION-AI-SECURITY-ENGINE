import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { 
  Bell, 
  ShieldAlert, 
  Clock, 
  Check, 
  ShieldCheck, 
  Flame, 
  Filter, 
  Search,
  ChevronDown,
  ChevronUp,
  RefreshCw,
  AlertCircle,
  Volume2,
  VolumeX,
  Radio,
  CheckCircle2,
  Play,
  RotateCcw,
  Cpu,
  UserCheck,
  User,
  ArrowRight,
  BookOpen,
  Sparkles,
  ExternalLink,
  Shield
} from 'lucide-react';
import { Card } from '../components/common/Card';
import { RiskBadge, StatusBadge } from '../components/common/Badge';
import { LoadingSpinner } from '../components/common/LoadingSpinner';
import { ErrorBanner } from '../components/common/ErrorBanner';
import { updateAlertStatus, acknowledgeAlert, replayAlertVoice, resolveAlert } from '../services/api';
import { 
  approveAlertInSupabase, 
  fetchAlertsFromSupabase, 
  fetchEmployeesFromSupabase,
  isSupabaseConfigured,
  calculateRiskLevel,
  isAlertActive,
  supabase 
} from '../services/insightSupabase';
import { voiceAlertService } from '../services/voiceAlertService';
import { useMode } from '../context/ModeContext';
import { translateTechnicalTerm, getEasyRiskDisplay } from '../utils/easyLanguage';

export function AlertsPage({ 
  alerts = [], 
  isLoading = false, 
  error = null, 
  onRefresh, 
  onResolveAlert,
  onSelectAlert, 
  onSelectIncident, 
  onActiveAlertCountChange,
  setTab 
}) {
  const { isEasyMode } = useMode();

  const [filterStatus, setFilterStatus] = useState('all');
  const [filterLevel, setFilterLevel] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [updatingId, setUpdatingId] = useState(null);
  const [actionError, setActionError] = useState(null);
  const [expandedAlertId, setExpandedAlertId] = useState(null);
  const [voiceEnabled, setVoiceEnabled] = useState(voiceAlertService.isEnabled());
  const [replayingId, setReplayingId] = useState(null);

  // Supabase state
  const [supabaseAlerts, setSupabaseAlerts] = useState([]);
  const [isSupabaseLoading, setIsSupabaseLoading] = useState(false);
  const [employeeMap, setEmployeeMap] = useState(new Map());

  // Unified data fetcher for Supabase alerts & employee metadata
  const loadSupabaseData = useCallback(async (silent = false) => {
    if (!isSupabaseConfigured) return;
    if (!silent) setIsSupabaseLoading(true);

    try {
      const [empRes, altRes] = await Promise.all([
        fetchEmployeesFromSupabase(),
        fetchAlertsFromSupabase()
      ]);

      const rawEmployees = empRes.data || [];
      const rawAlerts = altRes.data || [];

      // Build employee lookup map (both id and employee_code)
      const empMap = new Map();
      rawEmployees.forEach(emp => {
        empMap.set(String(emp.id), emp);
        if (emp.employee_code) empMap.set(String(emp.employee_code), emp);
      });
      setEmployeeMap(empMap);

      // Normalize Supabase alerts into unified format
      const normalized = rawAlerts.map(a => {
        const emp = empMap.get(String(a.employee_id));
        const score = Number(a.risk_score || 0);
        const level = calculateRiskLevel(score);
        const employeeName = emp ? emp.name : 'Unknown Employee';
        const employeeCode = emp ? emp.employee_code : (a.employee_id ? String(a.employee_id).slice(0, 8) : 'EMP');
        const defaultMsg = a.message || `Suspicious insider activity detected for ${employeeName}`;
        const isAcked = ['approved', 'resolved', 'acknowledged'].includes((a.status || '').toLowerCase());

        return {
          alert_id: a.id,
          id: a.id,
          _source: 'supabase',
          employee_id: a.employee_id,
          employee_name: employeeName,
          employee_code: employeeCode,
          department: emp ? emp.department : 'General',
          incident_id: a.incident_id || null,
          threat_type: a.alert_type || (level === 'CRITICAL' ? 'DATA_EXFILTRATION' : 'POLICY_VIOLATION'),
          title: `[${level}] ${a.alert_type || 'Security Alert'} - ${employeeName}`,
          message: defaultMsg,
          description: a.description || defaultMsg,
          voice_message: defaultMsg,
          risk_level: level,
          risk_score: score,
          severity: level,
          status: a.status || 'new',
          acknowledged: isAcked,
          timestamp: a.created_at || a.detected_at || new Date().toISOString(),
          reasons: a.description ? [a.description] : [defaultMsg],
          recommended_action: a.recommended_action || (level === 'CRITICAL' ? 'Immediate SOC lockdown & manager approval required' : 'Review employee access and audit telemetry'),
          primary_entity: `${employeeName} (${employeeCode})`,
        };
      });

      setSupabaseAlerts(normalized);

      // Sync active alert count to parent badge
      const activeCount = normalized.filter(a => isAlertActive(a.status)).length;
      if (onActiveAlertCountChange) {
        onActiveAlertCountChange(activeCount);
      }
    } catch (err) {
      console.warn('Failed loading Supabase alerts:', err);
    } finally {
      if (!silent) setIsSupabaseLoading(false);
    }
  }, [onActiveAlertCountChange]);

  // Initial load
  useEffect(() => {
    loadSupabaseData();
  }, [loadSupabaseData]);

  // Supabase Realtime subscription for live alert updates
  useEffect(() => {
    if (isSupabaseConfigured && supabase) {
      const channel = supabase
        .channel('public:alerts_page_realtime')
        .on(
          'postgres_changes',
          { event: '*', schema: 'public', table: 'alerts' },
          () => {
            loadSupabaseData(true);
          }
        )
        .subscribe();

      return () => {
        supabase.removeChannel(channel);
      };
    }
  }, [loadSupabaseData]);

  // Merge Supabase alerts with backend alerts (Supabase takes precedence)
  const allAlerts = useMemo(() => {
    const backendOnly = alerts.filter(a => 
      !supabaseAlerts.some(s => s.alert_id === a.alert_id || (s.incident_id && s.incident_id === a.incident_id))
    );
    return [...supabaseAlerts, ...backendOnly];
  }, [supabaseAlerts, alerts]);

  // Computed summary counts for quick reference
  const counts = useMemo(() => {
    const total = allAlerts.length;
    const active = allAlerts.filter(a => isAlertActive(a.status)).length;
    const critical = allAlerts.filter(a => (a.risk_level || '').toUpperCase() === 'CRITICAL').length;
    const unacked = allAlerts.filter(a => !a.acknowledged && isAlertActive(a.status)).length;
    const acked = allAlerts.filter(a => !!a.acknowledged).length;
    const approved = allAlerts.filter(a => (a.status || '').toLowerCase() === 'approved').length;
    const resolved = allAlerts.filter(a => (a.status || '').toLowerCase() === 'resolved').length;
    return { total, active, critical, unacked, acked, approved, resolved };
  }, [allAlerts]);

  // Filtered alerts
  const filteredAlerts = useMemo(() => {
    return allAlerts.filter((a) => {
      let matchesStatus = true;
      const statusLower = (a.status || '').toLowerCase();

      if (filterStatus === 'active') {
        matchesStatus = isAlertActive(a.status);
      } else if (filterStatus === 'unacknowledged') {
        matchesStatus = !a.acknowledged && isAlertActive(a.status);
      } else if (filterStatus === 'acknowledged') {
        matchesStatus = !!a.acknowledged;
      } else if (filterStatus === 'critical') {
        matchesStatus = (a.risk_level || '').toUpperCase() === 'CRITICAL';
      } else if (filterStatus === 'approved') {
        matchesStatus = statusLower === 'approved';
      } else if (filterStatus === 'resolved') {
        matchesStatus = statusLower === 'resolved';
      } else if (filterStatus !== 'all') {
        matchesStatus = statusLower === filterStatus.toLowerCase();
      }

      const matchesLevel = filterLevel === 'all' || (a.risk_level || '').toUpperCase() === filterLevel.toUpperCase();
      const searchLower = searchTerm.toLowerCase();
      const matchesSearch =
        !searchTerm ||
        a.alert_id?.toLowerCase().includes(searchLower) ||
        a.employee_name?.toLowerCase().includes(searchLower) ||
        a.employee_code?.toLowerCase().includes(searchLower) ||
        a.department?.toLowerCase().includes(searchLower) ||
        a.incident_id?.toLowerCase().includes(searchLower) ||
        a.threat_type?.toLowerCase().includes(searchLower) ||
        a.message?.toLowerCase().includes(searchLower) ||
        a.voice_message?.toLowerCase().includes(searchLower) ||
        a.recommended_action?.toLowerCase().includes(searchLower) ||
        a.reasons?.some(r => r.toLowerCase().includes(searchLower));

      return matchesStatus && matchesLevel && matchesSearch;
    });
  }, [allAlerts, filterStatus, filterLevel, searchTerm]);

  const toggleVoice = () => {
    const nextVal = !voiceEnabled;
    voiceAlertService.setEnabled(nextVal);
    setVoiceEnabled(nextVal);
  };

  const handleTestSpeech = () => {
    voiceAlertService.testSpeech();
  };

  const handleAcknowledge = async (alertId) => {
    setUpdatingId(alertId);
    setActionError(null);
    try {
      await acknowledgeAlert(alertId, {
        acknowledged_by: 'soc_analyst',
        note: 'Operator acknowledged alert receipt from SOC Alerts Console'
      });
      setSupabaseAlerts(prev => prev.map(a => a.alert_id === alertId ? { ...a, acknowledged: true } : a));
      if (onRefresh) onRefresh();
    } catch (err) {
      // If it's a Supabase-only alert, mark acknowledged locally
      setSupabaseAlerts(prev => prev.map(a => a.alert_id === alertId ? { ...a, acknowledged: true } : a));
    } finally {
      setUpdatingId(null);
    }
  };

  const handleReplayVoice = async (alert) => {
    setReplayingId(alert.alert_id);
    try {
      voiceAlertService.replayAlert(alert);
      await replayAlertVoice(alert.alert_id, { requested_by: 'soc_operator' }).catch(() => {});
    } catch (err) {
      console.warn('Replay audio error:', err);
    } finally {
      setTimeout(() => setReplayingId(null), 1000);
    }
  };

  const handleResolveAlert = async (alertId) => {
    setUpdatingId(alertId);
    setActionError(null);
    try {
      if (onResolveAlert) {
        await onResolveAlert(alertId);
      } else {
        await resolveAlert(alertId, {
          resolution_reason: 'Resolved via SOC Alerts Console',
          actor: 'soc_analyst'
        });
      }
      setSupabaseAlerts(prev => prev.map(a => a.alert_id === alertId ? { ...a, status: 'resolved', acknowledged: true } : a));
      loadSupabaseData(true);
      if (onRefresh) onRefresh();
    } catch (err) {
      setActionError(`Failed to resolve alert ${alertId}: ${err.message || 'Server error'}`);
    } finally {
      setUpdatingId(null);
    }
  };

  // Approve alert (sets status to 'approved' in Supabase, marks acknowledged, decrements badge)
  const handleApproveAlert = async (alertId) => {
    setUpdatingId(alertId);
    setActionError(null);
    try {
      const { error } = await approveAlertInSupabase(alertId);
      if (error) throw new Error(error);
      
      // Optimistically update local alert state
      setSupabaseAlerts(prev => {
        const updated = prev.map(a => a.alert_id === alertId ? { ...a, status: 'approved', acknowledged: true } : a);
        const newActiveCount = updated.filter(a => isAlertActive(a.status)).length;
        if (onActiveAlertCountChange) onActiveAlertCountChange(newActiveCount);
        return updated;
      });

      // Refetch from Supabase to guarantee consistency
      setTimeout(() => loadSupabaseData(true), 500);
      if (onRefresh) onRefresh();
    } catch (err) {
      setActionError(`Failed to approve alert ${alertId}: ${err.message || 'Server error'}`);
    } finally {
      setUpdatingId(null);
    }
  };

  const isDataLoading = (isLoading || isSupabaseLoading) && allAlerts.length === 0;

  return (
    <div className="space-y-6 font-sans">
      {/* Header with Voice Alert Controls & Refresh */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-900 dark:text-white tracking-tight flex items-center gap-2">
            <Bell className="text-red-500 animate-pulse" size={22} />
            <span>Security Alerts & Notifications</span>
            <span className="text-xs px-2.5 py-0.5 rounded-full bg-red-100 dark:bg-red-950/80 text-red-700 dark:text-red-300 font-mono font-bold border border-red-200 dark:border-red-900">
              {counts.active} Active
            </span>
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            Real-time security telemetry with live Supabase database sync, voice synthesis, and one-click analyst approvals.
          </p>
        </div>

        {/* Controls */}
        <div className="flex items-center gap-2 bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 p-1.5 rounded-2xl shrink-0 shadow-xs">
          <button
            onClick={() => loadSupabaseData(false)}
            disabled={isSupabaseLoading}
            className="px-2.5 py-1.5 rounded-xl bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 text-xs font-medium flex items-center gap-1.5 transition-colors cursor-pointer border border-slate-200 dark:border-slate-700"
            title="Refresh alerts from Supabase"
          >
            <RefreshCw size={12} className={isSupabaseLoading ? 'animate-spin text-cyan-500' : 'text-slate-400'} />
            <span>Refresh</span>
          </button>

          <button
            onClick={toggleVoice}
            className={`px-3 py-1.5 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer ${
              voiceEnabled
                ? 'bg-purple-100 dark:bg-purple-950 text-purple-800 dark:text-purple-300 border border-purple-300 dark:border-purple-800/80'
                : 'bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border border-transparent'
            }`}
            title="Toggle autonomous speech synthesis alerts"
          >
            {voiceEnabled ? <Volume2 size={14} className="text-purple-600 dark:text-purple-400" /> : <VolumeX size={14} />}
            <span>{voiceEnabled ? 'Voice Active' : 'Voice Muted'}</span>
          </button>

          <button
            onClick={handleTestSpeech}
            className="px-2.5 py-1.5 rounded-xl bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 text-xs font-medium flex items-center gap-1 transition-colors cursor-pointer border border-slate-200 dark:border-slate-700"
            title="Test synthetic TTS speech audio output"
          >
            <Play size={12} className="text-cyan-600 dark:text-cyan-400" />
            <span>Test Audio</span>
          </button>
        </div>
      </div>

      {/* KPI Overview Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2.5">
        {[
          { label: 'Total Ingested', count: counts.total, color: 'text-slate-300', bg: 'bg-slate-900/40 border-slate-800' },
          { label: 'Active Alerts', count: counts.active, color: 'text-red-400 font-bold', bg: 'bg-red-950/20 border-red-900/50' },
          { label: 'Critical Risk', count: counts.critical, color: 'text-rose-400 font-bold', bg: 'bg-rose-950/20 border-rose-900/50' },
          { label: 'Unacknowledged', count: counts.unacked, color: 'text-amber-400 font-semibold', bg: 'bg-amber-950/20 border-amber-900/50' },
          { label: 'Acknowledged', count: counts.acked, color: 'text-cyan-400', bg: 'bg-cyan-950/20 border-cyan-900/50' },
          { label: 'Approved (Cleared)', count: counts.approved, color: 'text-purple-400 font-semibold', bg: 'bg-purple-950/20 border-purple-900/50' },
          { label: 'Resolved', count: counts.resolved, color: 'text-emerald-400', bg: 'bg-emerald-950/20 border-emerald-900/50' },
        ].map((card, idx) => (
          <div key={idx} className={`p-3 rounded-xl border ${card.bg} text-center`}>
            <div className="text-[10px] uppercase font-mono tracking-wider text-slate-400">{card.label}</div>
            <div className={`text-lg font-mono tracking-tight mt-0.5 ${card.color}`}>{card.count}</div>
          </div>
        ))}
      </div>

      {/* Global Error Banner */}
      {error && (
        <ErrorBanner
          title="Alerts Stream Notice"
          message={error}
          onRetry={loadSupabaseData}
        />
      )}

      {/* Action Error Banner */}
      {actionError && (
        <ErrorBanner
          title="Alert Action Notice"
          message={actionError}
        />
      )}

      {/* Filters Bar */}
      <Card className="p-4 bg-white dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" size={14} />
            <input
              type="text"
              placeholder="Search by Employee, ID, threat, or reason..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-4 py-2 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl text-xs text-slate-900 dark:text-slate-200 focus:outline-none focus:border-cyan-500/50 font-mono"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="flex flex-wrap items-center p-1 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl">
              {[
                { id: 'all', label: `ALL (${counts.total})` },
                { id: 'active', label: `ACTIVE (${counts.active})` },
                { id: 'critical', label: `CRITICAL (${counts.critical})` },
                { id: 'unacknowledged', label: `UNACKED (${counts.unacked})` },
                { id: 'approved', label: `APPROVED (${counts.approved})` },
                { id: 'resolved', label: `RESOLVED (${counts.resolved})` },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setFilterStatus(tab.id)}
                  className={`px-2.5 py-1 rounded-lg text-[11px] font-mono uppercase tracking-wider transition-colors cursor-pointer ${
                    filterStatus === tab.id
                      ? 'bg-cyan-100 dark:bg-cyan-950 text-cyan-800 dark:text-cyan-300 font-semibold border border-cyan-300 dark:border-cyan-800/60'
                      : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            <select
              value={filterLevel}
              onChange={(e) => setFilterLevel(e.target.value)}
              className="px-3 py-1.5 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl text-xs text-slate-700 dark:text-slate-300 focus:outline-none focus:border-cyan-500/50 cursor-pointer font-mono"
            >
              <option value="all">ALL LEVELS</option>
              <option value="CRITICAL">CRITICAL (85+)</option>
              <option value="HIGH">HIGH (70-84)</option>
              <option value="MODERATE">MODERATE (40-69)</option>
              <option value="LOW">LOW (0-39)</option>
            </select>
          </div>
        </div>
      </Card>

      {/* EASY MODE ALERTS LIST (Clean human wording cards) */}
      {isEasyMode ? (
        <div className="space-y-4">
          {isDataLoading ? (
            <div className="py-12">
              <LoadingSpinner text="Loading security notifications from Supabase..." />
            </div>
          ) : filteredAlerts.length === 0 ? (
            <Card className="text-center py-12 text-slate-500 dark:text-slate-400 text-xs">
              No security alerts currently match your filters.
            </Card>
          ) : (
            filteredAlerts.map((alert) => {
              const isCritical = (alert.risk_level || '').toUpperCase() === 'CRITICAL';
              const isApproved = (alert.status || '').toLowerCase() === 'approved';
              const easySummary = isCritical
                ? `AI detected critical risk pattern for ${alert.employee_name}.`
                : alert.message || 'Suspicious activity identified by defense engine.';

              return (
                <Card
                  key={alert.alert_id}
                  className={`p-5 transition-all ${
                    isApproved 
                      ? 'border-purple-800/40 bg-purple-950/10'
                      : isCritical 
                      ? 'border-rose-300 dark:border-rose-800/80 bg-rose-50/50 dark:bg-rose-950/20 shadow-xs' 
                      : ''
                  }`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <div className="space-y-1.5">
                      <div className="flex flex-wrap items-center gap-2">
                        <RiskBadge level={alert.risk_level} score={alert.risk_score} />
                        <span className="text-xs font-mono font-bold text-slate-900 dark:text-white flex items-center gap-1">
                          <User size={12} className="text-cyan-400" />
                          <span>{alert.employee_name}</span>
                          <span className="text-slate-500 text-[10px]">({alert.employee_code})</span>
                        </span>
                        {isApproved && (
                          <span className="px-2 py-0.5 rounded text-[10px] bg-purple-100 dark:bg-purple-950 text-purple-700 dark:text-purple-300 font-semibold border border-purple-300 dark:border-purple-800 flex items-center gap-1">
                            <ShieldCheck size={11} /> Approved
                          </span>
                        )}
                        {alert.acknowledged && !isApproved && (
                          <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-100 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-300 font-medium">
                            Acknowledged
                          </span>
                        )}
                      </div>

                      <h3 className="text-base font-extrabold text-slate-900 dark:text-white">
                        {easySummary}
                      </h3>

                      <p className="text-xs text-slate-600 dark:text-slate-300">
                        {translateTechnicalTerm(alert.threat_type || 'SECURITY_ANOMALY')} • {alert.department}
                      </p>
                    </div>

                    <div className="flex flex-wrap items-center gap-2 shrink-0">
                      {/* Replay Voice button */}
                      <button
                        onClick={() => handleReplayVoice(alert)}
                        disabled={replayingId === alert.alert_id}
                        className="p-2 rounded-xl bg-purple-100 dark:bg-purple-950/70 hover:bg-purple-200 dark:hover:bg-purple-900 text-purple-800 dark:text-purple-300 border border-purple-200 dark:border-purple-800/60 transition-colors cursor-pointer text-xs flex items-center gap-1.5"
                        title="Listen to audio alert"
                      >
                        <Volume2 size={14} className={replayingId === alert.alert_id ? 'animate-bounce' : ''} />
                        <span className="hidden sm:inline">Listen</span>
                      </button>

                      {/* Approve alert button */}
                      {!isApproved && (
                        <button
                          onClick={() => handleApproveAlert(alert.alert_id)}
                          disabled={updatingId === alert.alert_id}
                          className="px-3.5 py-1.5 rounded-xl bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white text-xs font-bold transition-all cursor-pointer shadow-md shadow-purple-600/30 flex items-center gap-1.5"
                        >
                          <ShieldCheck size={13} />
                          <span>Approve</span>
                        </button>
                      )}

                      {/* Resolve alert button */}
                      {alert.status !== 'resolved' && (
                        <button
                          onClick={() => handleResolveAlert(alert.alert_id)}
                          disabled={updatingId === alert.alert_id}
                          className="px-3 py-1.5 rounded-xl bg-emerald-100 dark:bg-emerald-950/80 hover:bg-emerald-200 dark:hover:bg-emerald-900 text-emerald-800 dark:text-emerald-300 text-xs font-medium transition-colors cursor-pointer border border-emerald-300 dark:border-emerald-700/80 flex items-center gap-1"
                        >
                          <CheckCircle2 size={13} className="text-emerald-600 dark:text-emerald-400" />
                          <span>Resolve</span>
                        </button>
                      )}

                      {/* View What Happened button */}
                      <button
                        onClick={() => {
                          if (onSelectAlert) onSelectAlert(alert);
                        }}
                        className="px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold flex items-center gap-1.5 shadow-md shadow-cyan-600/30 transition-all cursor-pointer"
                      >
                        <span>View Details</span>
                        <ArrowRight size={13} />
                      </button>
                    </div>
                  </div>
                </Card>
              );
            })
          )}
        </div>
      ) : (
        /* PRO MODE ALERTS TABLE (Detailed SOC Table) */
        <div className="bg-white dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden shadow-sm dark:shadow-xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-700 dark:text-slate-300">
              <thead className="bg-slate-50 dark:bg-slate-950/90 text-[11px] uppercase tracking-wider text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-800">
                <tr>
                  <th className="py-3.5 px-4 font-semibold">Alert ID</th>
                  <th className="py-3.5 px-4 font-semibold">Monitored Employee</th>
                  <th className="py-3.5 px-4 font-semibold">Risk Level</th>
                  <th className="py-3.5 px-4 font-semibold">Threat Type</th>
                  <th className="py-3.5 px-4 font-semibold">Message & Reason</th>
                  <th className="py-3.5 px-4 font-semibold">Status / Voice</th>
                  <th className="py-3.5 px-4 font-semibold">Timestamp</th>
                  <th className="py-3.5 px-4 font-semibold text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60">
                {isDataLoading ? (
                  <tr>
                    <td colSpan={8} className="text-center py-16">
                      <LoadingSpinner text="Fetching security alerts from Supabase (1000 monitored employees)..." />
                    </td>
                  </tr>
                ) : filteredAlerts.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="text-center py-16 text-slate-500 dark:text-slate-400 font-medium">
                      No security alerts match the selected filters.
                    </td>
                  </tr>
                ) : (
                  filteredAlerts.map((alert) => {
                    const isExpanded = expandedAlertId === alert.alert_id;
                    const isCritical = (alert.risk_level || '').toUpperCase() === 'CRITICAL';
                    const isHigh = (alert.risk_level || '').toUpperCase() === 'HIGH';
                    const isApproved = (alert.status || '').toLowerCase() === 'approved';
                    const primaryReason = alert.message || alert.reasons?.[0] || alert.title || 'Security Anomaly Detected';
                    const threatType = alert.threat_type || 'SUSPICIOUS_ACTIVITY';
                    const isAcked = !!alert.acknowledged;

                    return (
                      <React.Fragment key={alert.alert_id}>
                        <tr className={`hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors ${
                          isApproved
                            ? 'bg-purple-950/10'
                            : isCritical 
                            ? 'bg-red-50/40 dark:bg-red-950/20' 
                            : isHigh 
                            ? 'bg-amber-50/40 dark:bg-amber-950/10' 
                            : ''
                        }`}>
                          {/* 1. Alert ID */}
                          <td className="py-3.5 px-4 font-mono text-slate-900 dark:text-white font-bold whitespace-nowrap">
                            <div className="flex items-center gap-1.5">
                              {isCritical && !isApproved && <Radio size={12} className="text-red-500 animate-pulse shrink-0" />}
                              {isApproved && <ShieldCheck size={13} className="text-purple-400 shrink-0" />}
                              <span title={alert.alert_id} className="cursor-pointer hover:text-cyan-400" onClick={() => setExpandedAlertId(isExpanded ? null : alert.alert_id)}>
                                {alert.alert_id ? String(alert.alert_id).slice(0, 8) : 'ALERT'}
                              </span>
                            </div>
                          </td>

                          {/* 2. Monitored Employee */}
                          <td className="py-3.5 px-4 whitespace-nowrap">
                            <div className="flex items-center gap-2">
                              <div className="w-6 h-6 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-300 font-bold text-[10px]">
                                {alert.employee_name ? alert.employee_name.charAt(0) : 'U'}
                              </div>
                              <div>
                                <div className="font-semibold text-slate-900 dark:text-white flex items-center gap-1.5">
                                  <span>{alert.employee_name}</span>
                                  {alert.employee_code && (
                                    <span className="text-[10px] font-mono text-slate-500">{alert.employee_code}</span>
                                  )}
                                </div>
                                <div className="text-[10px] text-slate-500">{alert.department || 'Employee'}</div>
                              </div>
                            </div>
                          </td>

                          {/* 3. Risk Level */}
                          <td className="py-3.5 px-4 whitespace-nowrap">
                            <RiskBadge level={alert.risk_level} score={alert.risk_score} />
                          </td>

                          {/* 4. Threat Type */}
                          <td className="py-3.5 px-4 whitespace-nowrap">
                            <span className="px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-700 font-mono text-[10px] text-cyan-700 dark:text-cyan-300 uppercase tracking-wide">
                              {threatType.replace(/_/g, ' ')}
                            </span>
                          </td>

                          {/* 5. Message & Reason */}
                          <td className="py-3.5 px-4 max-w-xs truncate text-slate-700 dark:text-slate-300">
                            <span title={primaryReason} className="cursor-pointer hover:underline" onClick={() => setExpandedAlertId(isExpanded ? null : alert.alert_id)}>
                              {primaryReason}
                            </span>
                          </td>

                          {/* 6. Voice Status & Status Badge */}
                          <td className="py-3.5 px-4 whitespace-nowrap">
                            <div className="flex items-center gap-2">
                              {(isCritical || isHigh) && (
                                <button
                                  onClick={() => handleReplayVoice(alert)}
                                  disabled={replayingId === alert.alert_id}
                                  className="p-1 rounded bg-purple-100 dark:bg-purple-950/70 hover:bg-purple-200 dark:hover:bg-purple-900 text-purple-800 dark:text-purple-300 border border-purple-200 dark:border-purple-800/60 transition-colors cursor-pointer"
                                  title="Replay voice alert audio"
                                >
                                  <Volume2 size={12} className={replayingId === alert.alert_id ? 'animate-bounce' : ''} />
                                </button>
                              )}
                              {isApproved ? (
                                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-100 dark:bg-purple-950 text-purple-800 dark:text-purple-300 border border-purple-300 dark:border-purple-800 flex items-center gap-1 font-bold">
                                  <ShieldCheck size={11} /> APPROVED
                                </span>
                              ) : (
                                <span className={`px-2 py-0.5 rounded text-[10px] font-mono ${
                                  isAcked
                                    ? 'bg-emerald-100 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800'
                                    : 'bg-amber-100 dark:bg-amber-950 text-amber-800 dark:text-amber-300 border border-amber-200 dark:border-amber-800'
                                }`}>
                                  {isAcked ? 'ACKED' : 'PENDING'}
                                </span>
                              )}
                            </div>
                          </td>

                          {/* 7. Timestamp */}
                          <td className="py-3.5 px-4 whitespace-nowrap text-slate-500 dark:text-slate-400 font-mono text-[11px]">
                            {new Date(alert.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                          </td>

                          {/* 8. Actions */}
                          <td className="py-3.5 px-4 text-right whitespace-nowrap">
                            <div className="flex items-center justify-end gap-1.5">
                              {/* Approve Button */}
                              {!isApproved && (
                                <button
                                  onClick={() => handleApproveAlert(alert.alert_id)}
                                  disabled={updatingId === alert.alert_id}
                                  className="px-2.5 py-1 rounded bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white text-[11px] font-bold transition-all cursor-pointer shadow-xs flex items-center gap-1"
                                  title="Approve employee threat & clear critical risk"
                                >
                                  <ShieldCheck size={11} />
                                  <span>Approve</span>
                                </button>
                              )}

                              {/* Resolve Button */}
                              {alert.status !== 'resolved' && !isApproved && (
                                <button
                                  onClick={() => handleResolveAlert(alert.alert_id)}
                                  disabled={updatingId === alert.alert_id}
                                  className="px-2 py-1 rounded bg-emerald-50 dark:bg-emerald-950/60 hover:bg-emerald-100 dark:hover:bg-emerald-900 text-emerald-700 dark:text-emerald-300 text-[11px] font-medium transition-colors cursor-pointer border border-emerald-200 dark:border-emerald-800"
                                  title="Resolve single alert"
                                >
                                  Resolve
                                </button>
                              )}

                              {/* Ack Button */}
                              {!isAcked && !isApproved && (
                                <button
                                  onClick={() => handleAcknowledge(alert.alert_id)}
                                  disabled={updatingId === alert.alert_id}
                                  className="px-2 py-1 rounded bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-[11px] transition-colors cursor-pointer border border-slate-200 dark:border-slate-700"
                                >
                                  Ack
                                </button>
                              )}

                              {/* Details / Investigate */}
                              <button
                                onClick={() => {
                                  if (onSelectAlert) onSelectAlert(alert);
                                }}
                                className="px-2 py-1 rounded bg-cyan-50 dark:bg-cyan-950/60 hover:bg-cyan-100 dark:hover:bg-cyan-900 text-cyan-700 dark:text-cyan-300 text-[11px] font-medium transition-colors cursor-pointer border border-cyan-200 dark:border-cyan-800"
                                title="Open full alert inspection"
                              >
                                Details
                              </button>
                            </div>
                          </td>
                        </tr>

                        {/* Accordion row for expanded details */}
                        {isExpanded && (
                          <tr className="bg-slate-950/60 border-b border-slate-800">
                            <td colSpan={8} className="p-4 space-y-3 font-mono text-xs">
                              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 p-3 bg-slate-900 rounded-xl border border-slate-800">
                                <div>
                                  <span className="text-slate-500">Employee ID:</span>{' '}
                                  <span className="text-cyan-400 font-bold">{alert.employee_id}</span>
                                </div>
                                <div>
                                  <span className="text-slate-500">Full Alert ID:</span>{' '}
                                  <span className="text-slate-300">{alert.alert_id}</span>
                                </div>
                                <div>
                                  <span className="text-slate-500">Detected At:</span>{' '}
                                  <span className="text-slate-300">{new Date(alert.timestamp).toLocaleString()}</span>
                                </div>
                              </div>
                              <div className="p-3 bg-slate-900 rounded-xl border border-slate-800">
                                <div className="text-[10px] uppercase font-bold text-cyan-400 mb-1">Recommended Response</div>
                                <div className="text-slate-200">{alert.recommended_action}</div>
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

export default AlertsPage;
