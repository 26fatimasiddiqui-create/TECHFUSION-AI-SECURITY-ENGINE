import React, { useState, useEffect } from 'react';
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
  ArrowRight,
  BookOpen
} from 'lucide-react';
import { Card } from '../components/common/Card';
import { RiskBadge, StatusBadge } from '../components/common/Badge';
import { LoadingSpinner } from '../components/common/LoadingSpinner';
import { ErrorBanner } from '../components/common/ErrorBanner';
import { updateAlertStatus, acknowledgeAlert, replayAlertVoice } from '../services/api';
import { voiceAlertService } from '../services/voiceAlertService';
import { useMode } from '../context/ModeContext';
import { translateTechnicalTerm, getEasyRiskDisplay } from '../utils/easyLanguage';

export function AlertsPage({ 
  alerts = [], 
  isLoading = false, 
  error = null, 
  onRefresh, 
  onSelectAlert, 
  onSelectIncident, 
  setTab 
}) {
  const { isEasyMode, setMode } = useMode();

  const [filterStatus, setFilterStatus] = useState('all');
  const [filterLevel, setFilterLevel] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [updatingId, setUpdatingId] = useState(null);
  const [actionError, setActionError] = useState(null);
  const [expandedAlertId, setExpandedAlertId] = useState(null);
  const [voiceEnabled, setVoiceEnabled] = useState(voiceAlertService.isEnabled());
  const [replayingId, setReplayingId] = useState(null);

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
      if (onRefresh) onRefresh();
    } catch (err) {
      setActionError(`Failed to acknowledge alert ${alertId}: ${err.message || 'Server error'}`);
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

  const handleStatusChange = async (alertId, newStatus) => {
    setUpdatingId(alertId);
    setActionError(null);
    try {
      await updateAlertStatus(alertId, newStatus);
      if (onRefresh) onRefresh();
    } catch (err) {
      setActionError(`Failed to update alert ${alertId}: ${err.message || 'Server error'}`);
    } finally {
      setUpdatingId(null);
    }
  };

  const filteredAlerts = alerts.filter((a) => {
    let matchesStatus = true;
    if (filterStatus === 'unacknowledged') {
      matchesStatus = !a.acknowledged && a.status !== 'resolved';
    } else if (filterStatus === 'acknowledged') {
      matchesStatus = !!a.acknowledged;
    } else if (filterStatus === 'critical') {
      matchesStatus = (a.risk_level || '').toUpperCase() === 'CRITICAL';
    } else if (filterStatus !== 'all') {
      matchesStatus = a.status?.toLowerCase() === filterStatus.toLowerCase();
    }

    const matchesLevel = filterLevel === 'all' || a.risk_level?.toUpperCase() === filterLevel.toUpperCase();
    const searchLower = searchTerm.toLowerCase();
    const matchesSearch =
      !searchTerm ||
      a.alert_id?.toLowerCase().includes(searchLower) ||
      a.incident_id?.toLowerCase().includes(searchLower) ||
      a.threat_type?.toLowerCase().includes(searchLower) ||
      a.message?.toLowerCase().includes(searchLower) ||
      a.voice_message?.toLowerCase().includes(searchLower) ||
      a.recommended_action?.toLowerCase().includes(searchLower) ||
      a.reasons?.some(r => r.toLowerCase().includes(searchLower));

    return matchesStatus && matchesLevel && matchesSearch;
  });

  return (
    <div className="space-y-6 font-sans">
      {/* Header with Voice Alert Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-900 dark:text-white tracking-tight flex items-center gap-2">
            <Bell className="text-red-500" size={22} />
            <span>Security Alerts & Notifications</span>
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            Real-time security telemetry with automated voice synthesis, Two-Person Rule awareness, and incident acknowledgement.
          </p>
        </div>

        {/* Step 6 Voice Synthesis Control Widget */}
        <div className="flex items-center gap-2 bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 p-1.5 rounded-2xl shrink-0 shadow-xs">
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
            <span>{voiceEnabled ? 'Voice Alerts Active' : 'Voice Muted'}</span>
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

      {/* Global Error Banner */}
      {error && (
        <ErrorBanner
          title="Alerts Stream Notice"
          message={error}
          onRetry={onRefresh}
        />
      )}

      {/* Action Error Banner */}
      {actionError && (
        <ErrorBanner
          title="Alert Action Failed"
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
              placeholder="Search by ID, keyword, user, or threat..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-4 py-2 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl text-xs text-slate-900 dark:text-slate-200 focus:outline-none focus:border-cyan-500/50 font-mono"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="flex items-center p-1 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl">
              {[
                { id: 'all', label: 'ALL' },
                { id: 'unacknowledged', label: 'UNACKED' },
                { id: 'acknowledged', label: 'ACKED' },
                { id: 'critical', label: 'CRITICAL' },
                { id: 'resolved', label: 'RESOLVED' },
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
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MODERATE">MODERATE</option>
              <option value="LOW">LOW</option>
            </select>
          </div>
        </div>
      </Card>

      {/* EASY MODE ALERTS LIST (Clean human wording cards) */}
      {isEasyMode ? (
        <div className="space-y-4">
          {isLoading && alerts.length === 0 ? (
            <div className="py-12">
              <LoadingSpinner text="Loading security notifications..." />
            </div>
          ) : filteredAlerts.length === 0 ? (
            <Card className="text-center py-12 text-slate-500 dark:text-slate-400 text-xs">
              No security alerts currently match your filters.
            </Card>
          ) : (
            filteredAlerts.map((alert) => {
              const isCritical = (alert.risk_level || '').toUpperCase() === 'CRITICAL';
              const riskDisplay = getEasyRiskDisplay(alert.risk_level, alert.risk_score);
              const easySummary = isCritical
                ? 'AI detected suspicious access to customer data.'
                : alert.message || 'Suspicious activity was identified by the defense system.';

              return (
                <Card
                  key={alert.alert_id}
                  className={`p-5 transition-all ${
                    isCritical 
                      ? 'border-rose-300 dark:border-rose-800/80 bg-rose-50/50 dark:bg-rose-950/20 shadow-xs' 
                      : ''
                  }`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <div className="space-y-1.5">
                      <div className="flex flex-wrap items-center gap-2">
                        <RiskBadge level={alert.risk_level} score={alert.risk_score} />
                        <span className="text-xs font-mono text-slate-500 dark:text-slate-400">
                          {alert.alert_id}
                        </span>
                        {alert.acknowledged && (
                          <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-100 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-300 font-medium">
                            Acknowledged
                          </span>
                        )}
                      </div>

                      <h3 className="text-base font-extrabold text-slate-900 dark:text-white">
                        {easySummary}
                      </h3>

                      <p className="text-xs text-slate-600 dark:text-slate-300">
                        {translateTechnicalTerm(alert.threat_type || 'EXTERNAL_THREAT')}
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

                      {/* Acknowledge button */}
                      {!alert.acknowledged && (
                        <button
                          onClick={() => handleAcknowledge(alert.alert_id)}
                          disabled={updatingId === alert.alert_id}
                          className="px-3 py-1.5 rounded-xl bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-medium transition-colors cursor-pointer border border-slate-200 dark:border-slate-700"
                        >
                          Acknowledge
                        </button>
                      )}

                      {/* View What Happened button */}
                      <button
                        onClick={() => {
                          if (alert.incident_id && onSelectIncident) {
                            onSelectIncident({ id: alert.incident_id });
                          }
                          if (setTab) setTab('incidents');
                        }}
                        className="px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold flex items-center gap-1.5 shadow-md shadow-blue-600/30 transition-all cursor-pointer"
                      >
                        <span>View What Happened</span>
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
                  <th className="py-3.5 px-4 font-semibold">Incident</th>
                  <th className="py-3.5 px-4 font-semibold">Risk Level</th>
                  <th className="py-3.5 px-4 font-semibold">Threat Type</th>
                  <th className="py-3.5 px-4 font-semibold">Message & Reason</th>
                  <th className="py-3.5 px-4 font-semibold">Voice / Ack</th>
                  <th className="py-3.5 px-4 font-semibold">Timestamp</th>
                  <th className="py-3.5 px-4 font-semibold text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60">
                {isLoading && alerts.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="text-center py-16">
                      <LoadingSpinner text="Fetching security alerts from GET /api/alerts..." />
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
                    const primaryReason = alert.message || alert.reasons?.[0] || alert.title || 'Security Anomaly Detected';
                    const threatType = alert.threat_type || 'EXTERNAL_THREAT';
                    const isAcked = !!alert.acknowledged;

                    return (
                      <tr key={alert.alert_id} className={`hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors ${
                        isCritical ? 'bg-red-50/40 dark:bg-red-950/10' : isHigh ? 'bg-amber-50/40 dark:bg-amber-950/10' : ''
                      }`}>
                        {/* 1. Alert ID */}
                        <td className="py-3.5 px-4 font-mono text-slate-900 dark:text-white font-bold whitespace-nowrap">
                          <span className="flex items-center gap-1.5">
                            {isCritical && <Radio size={12} className="text-red-500 animate-pulse" />}
                            <span>{alert.alert_id}</span>
                          </span>
                        </td>

                        {/* 2. Incident Link */}
                        <td className="py-3.5 px-4 font-mono whitespace-nowrap">
                          {alert.incident_id ? (
                            <button
                              onClick={() => {
                                if (onSelectIncident) onSelectIncident({ id: alert.incident_id });
                                if (setTab) setTab('incidents');
                              }}
                              className="text-cyan-600 dark:text-cyan-400 hover:text-cyan-500 dark:hover:text-cyan-300 hover:underline flex items-center gap-1 font-semibold cursor-pointer"
                              title="Jump to Incident"
                            >
                              <Flame size={12} className="text-amber-500" />
                              <span>{alert.incident_id}</span>
                            </button>
                          ) : (
                            <span className="text-slate-400">-</span>
                          )}
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
                          <span title={primaryReason}>
                            {primaryReason}
                          </span>
                        </td>

                        {/* 6. Voice Status & Ack State */}
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
                            <span className={`px-2 py-0.5 rounded text-[10px] font-mono ${
                              isAcked
                                ? 'bg-emerald-100 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800'
                                : 'bg-amber-100 dark:bg-amber-950 text-amber-800 dark:text-amber-300 border border-amber-200 dark:border-amber-800'
                            }`}>
                              {isAcked ? 'ACKED' : 'PENDING'}
                            </span>
                          </div>
                        </td>

                        {/* 7. Timestamp */}
                        <td className="py-3.5 px-4 whitespace-nowrap text-slate-500 dark:text-slate-400 font-mono text-[11px]">
                          {new Date(alert.timestamp).toLocaleTimeString()}
                        </td>

                        {/* 8. Actions */}
                        <td className="py-3.5 px-4 text-right whitespace-nowrap">
                          <div className="flex items-center justify-end gap-1.5">
                            {!isAcked && (
                              <button
                                onClick={() => handleAcknowledge(alert.alert_id)}
                                disabled={updatingId === alert.alert_id}
                                className="px-2 py-1 rounded bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-[11px] transition-colors cursor-pointer border border-slate-200 dark:border-slate-700"
                              >
                                Ack
                              </button>
                            )}
                            <button
                              onClick={() => {
                                if (alert.incident_id && onSelectIncident) {
                                  onSelectIncident({ id: alert.incident_id });
                                }
                                if (setTab) setTab('incidents');
                              }}
                              className="px-2 py-1 rounded bg-blue-50 dark:bg-blue-950/60 hover:bg-blue-100 dark:hover:bg-blue-900 text-blue-700 dark:text-blue-300 text-[11px] font-medium transition-colors cursor-pointer border border-blue-200 dark:border-blue-800"
                            >
                              Investigate
                            </button>
                          </div>
                        </td>
                      </tr>
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
