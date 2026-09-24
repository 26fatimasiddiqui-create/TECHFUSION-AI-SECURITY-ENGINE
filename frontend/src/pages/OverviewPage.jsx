import React, { useMemo } from 'react';
import { 
  ShieldAlert, 
  Activity, 
  Flame, 
  AlertTriangle, 
  ChevronRight, 
  Clock, 
  AlertOctagon, 
  Radio,
  Globe,
  ShieldCheck,
  Zap,
  CheckCircle2,
  BookOpen,
  ArrowRight,
  Gauge
} from 'lucide-react';
import { Card, MetricCard } from '../components/common/Card';
import { RiskBadge, StatusBadge, SignalPill } from '../components/common/Badge';
import { LoadingSpinner } from '../components/common/LoadingSpinner';
import { ErrorBanner } from '../components/common/ErrorBanner';
import { LiveSecurityGraph } from '../components/common/LiveSecurityGraph';
import { EasyIncidentStory } from '../components/easy/EasyIncidentStory';
import { useMode } from '../context/ModeContext';

export function OverviewPage({ 
  events = [], 
  incidents = [], 
  alerts = [], 
  isLoading = false,
  error = null,
  onRetry,
  onSelectIncident, 
  onSelectAlert, 
  setTab,
}) {
  const { isEasyMode, setMode } = useMode();

  // Derive active incidents count directly from authoritative incidents
  const activeIncidents = incidents.filter(i => (i.status === 'active' || !i.status)).length;

  // Synchronize alerts with authoritative incidents to ensure UI consistency
  const synchronizedAlerts = useMemo(() => {
    const incMap = new Map();
    incidents.forEach(inc => {
      incMap.set(inc.id, inc);
      if (inc.primary_entity) incMap.set(`user:${inc.primary_entity}`, inc);
    });

    return alerts.map(alert => {
      let linkedInc = null;
      if (alert.incident_id && incMap.has(alert.incident_id)) {
        linkedInc = incMap.get(alert.incident_id);
      } else {
        linkedInc = incidents.find(i => 
          (i.id === alert.incident_id) ||
          (alert.event_id && i.event_ids && i.event_ids.includes(alert.event_id)) ||
          (alert.primary_entity && i.primary_entity === alert.primary_entity) ||
          (alert.target_entity && i.primary_entity === alert.target_entity)
        );
      }

      if (!linkedInc) return alert;

      const incStatus = (linkedInc.status || 'active').toLowerCase();
      const incScore = linkedInc.risk_assessment?.risk_score ?? linkedInc.risk_score;

      let syncStatus = alert.status;
      let syncScore = alert.risk_score;
      let syncLevel = alert.risk_level || alert.severity;
      let syncTitle = alert.title;

      if (incStatus === 'contained') {
        syncStatus = 'contained';
        syncScore = Math.min(syncScore ?? 15, incScore ?? 15, 15);
        syncLevel = 'LOW';
        if (!syncTitle || syncTitle.includes('CRITICAL')) {
          syncTitle = `[Contained] ${linkedInc.threat_type || alert.threat_type || 'Threat Contained'}`;
        }
      } else if (incStatus === 'resolved' || incStatus === 'mitigated' || incStatus === 'recovered') {
        syncStatus = incStatus;
        syncScore = 0;
        syncLevel = 'LOW';
        if (!syncTitle || syncTitle.includes('CRITICAL')) {
          syncTitle = `[Resolved] ${linkedInc.threat_type || alert.threat_type || 'Threat Resolved'}`;
        }
      } else if (incStatus === 'acknowledged') {
        syncStatus = 'acknowledged';
      }

      return {
        ...alert,
        status: syncStatus,
        risk_score: syncScore,
        risk_level: syncLevel,
        severity: syncLevel,
        title: syncTitle,
        incident_status: incStatus
      };
    });
  }, [alerts, incidents]);

  // Derive current severity breakdown from authoritative incidents (status != severity)
  const incidentSeverities = useMemo(() => {
    return incidents.map(inc => {
      const status = (inc.status || 'active').toLowerCase();
      if (['resolved', 'mitigated', 'recovered'].includes(status)) return 'LOW';
      if (status === 'contained') return 'LOW';
      const score = inc.risk_assessment?.risk_score ?? inc.risk_score ?? 0;
      const level = (inc.risk_assessment?.risk_level || inc.risk_level || '').toUpperCase();
      if (level === 'CRITICAL' || score >= 80) return 'CRITICAL';
      if (level === 'HIGH' || (score >= 60 && score < 80)) return 'HIGH';
      if (level === 'MODERATE' || (score >= 30 && score < 60)) return 'MODERATE';
      return 'LOW';
    });
  }, [incidents]);

  const criticalIncidents = incidentSeverities.filter(s => s === 'CRITICAL').length;
  const highRiskIncidents = incidentSeverities.filter(s => s === 'HIGH').length;
  const moderateRiskIncidents = incidentSeverities.filter(s => s === 'MODERATE').length;
  const lowRiskIncidents = incidentSeverities.filter(s => s === 'LOW').length;
  
  // Sort alerts descending by timestamp so latest alerts are always at the top
  const sortedAlerts = useMemo(() => {
    return [...synchronizedAlerts].sort((a, b) => new Date(b.timestamp || b.created_at || 0) - new Date(a.timestamp || a.created_at || 0));
  }, [synchronizedAlerts]);

  // Calculate Events Today from real event timestamps
  const now = new Date();
  const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
  const eventsTodayCount = events.filter(e => new Date(e.timestamp).getTime() >= startOfToday).length || events.length;
  const recentAlertsCount = alerts.length;

  // Prioritize active or uncontained incident as the primary featured incident
  const primaryIncident = useMemo(() => {
    return incidents.find(i => i.status === 'active' || !i.status) || (incidents.length > 0 ? incidents[0] : null);
  }, [incidents]);

  // Render Easy Mode Overview
  if (isEasyMode) {
    return (
      <div className="space-y-6">
        {/* Error state */}
        {error && (
          <ErrorBanner
            title="Telemetry Notice"
            message={error}
            onRetry={onRetry}
          />
        )}

        {/* Loading state indicator */}
        {isLoading && events.length === 0 && incidents.length === 0 && (
          <div className="py-12">
            <LoadingSpinner text="Checking security status..." />
          </div>
        )}

        {/* Easy Mode Top Status Summary */}
        <div className="p-5 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4 shadow-sm">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-emerald-100 dark:bg-emerald-950 text-emerald-600 dark:text-emerald-400 flex items-center justify-center font-bold">
              <ShieldCheck size={22} />
            </div>
            <div>
              <div className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                System Status
              </div>
              <div className="text-base sm:text-lg font-extrabold text-slate-900 dark:text-white">
                {activeIncidents > 0 ? `${activeIncidents} Active Threat Needs Review` : 'All Security Systems Operational'}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setMode('pro')}
              className="px-3 py-1.5 rounded-xl bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-medium flex items-center gap-1.5 transition-colors cursor-pointer"
            >
              <Gauge size={13} className="text-cyan-500" />
              <span>Switch to Pro Mode for detailed graphs</span>
            </button>
          </div>
        </div>

        {/* Simplified 3-Metric Overview Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <Card className="p-5 flex items-center justify-between">
            <div>
              <div className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                Active Threats
              </div>
              <div className="text-2xl sm:text-3xl font-black text-rose-600 dark:text-rose-400 mt-1">
                {activeIncidents}
              </div>
              <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                {criticalIncidents > 0 ? `${criticalIncidents} Critical Severity` : 'Monitoring telemetry'}
              </div>
            </div>
            <div className="w-12 h-12 rounded-2xl bg-rose-50 dark:bg-rose-950/80 text-rose-600 dark:text-rose-400 flex items-center justify-center border border-rose-200 dark:border-rose-800">
              <AlertOctagon size={24} />
            </div>
          </Card>

          <Card className="p-5 flex items-center justify-between">
            <div>
              <div className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                AI Defense Engine
              </div>
              <div className="text-2xl sm:text-3xl font-black text-emerald-600 dark:text-emerald-400 mt-1">
                Online
              </div>
              <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                Autonomous multi-signal correlation active
              </div>
            </div>
            <div className="w-12 h-12 rounded-2xl bg-emerald-50 dark:bg-emerald-950/80 text-emerald-600 dark:text-emerald-400 flex items-center justify-center border border-emerald-200 dark:border-emerald-800">
              <ShieldCheck size={24} />
            </div>
          </Card>

          <Card className="p-5 flex items-center justify-between">
            <div>
              <div className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                Action Required
              </div>
              <div className="text-2xl sm:text-3xl font-black text-amber-600 dark:text-amber-400 mt-1">
                1 Pending
              </div>
              <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                Two-person containment approval
              </div>
            </div>
            <div className="w-12 h-12 rounded-2xl bg-amber-50 dark:bg-amber-950/80 text-amber-600 dark:text-amber-400 flex items-center justify-center border border-amber-200 dark:border-amber-800">
              <Clock size={24} />
            </div>
          </Card>
        </div>

        {/* Featured Easy Mode Incident Story Visualizer */}
        <EasyIncidentStory
          incident={primaryIncident}
          onOpenActionCenter={() => {
            if (primaryIncident && onSelectIncident) onSelectIncident(primaryIncident);
            if (setTab) setTab('incidents');
          }}
          onViewProDetails={() => setMode('pro')}
        />
      </div>
    );
  }

  // Render Pro Mode Overview (Detailed SOC experience)
  return (
    <div className="space-y-6">
      {/* Top Welcome & Posture Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-900/90 to-cyan-950/40 border border-slate-800 rounded-2xl p-6 relative overflow-hidden shadow-xl">
        <div className="max-w-3xl">
          <div className="inline-flex items-center gap-2 px-2.5 py-1 bg-cyan-950/80 border border-cyan-800/50 rounded-md text-xs font-mono text-cyan-400 mb-3">
            <Radio size={13} className="text-cyan-400" />
            THREATFUSION AI SECURITY ENGINE ACTIVE • PRO SOC MODE
          </div>
          <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
            Security Monitoring & Multi-Step Risk Assessment
          </h1>
          <p className="text-sm text-slate-400 mt-2 leading-relaxed">
            Correlating isolated user logins, device anomalies, AI agent invocations, and database queries into unified security incidents with explainable rationales.
          </p>
        </div>
      </div>

      {/* Error state if overview fetch failed */}
      {error && (
        <ErrorBanner
          title="Telemetry Synchronization Warning"
          message={error}
          onRetry={onRetry}
        />
      )}

      {/* Loading state indicator if initial fetch */}
      {isLoading && events.length === 0 && incidents.length === 0 && (
        <div className="py-12">
          <LoadingSpinner text="Connecting to backend and aggregating security statistics..." />
        </div>
      )}

      {/* Featured Live Security Graph (Matching Exact User Architecture) */}
      <LiveSecurityGraph
        events={events}
        incidents={incidents}
        alerts={alerts}
        onInvestigate={() => {
          if (incidents.length > 0 && onSelectIncident) {
            const target = incidents.find(i => i.status === 'active' || !i.status) || incidents[0];
            onSelectIncident(target);
          } else if (setTab) {
            setTab('incidents');
          }
        }}
        onSelectNode={(node) => {
          if (setTab) setTab('graph');
        }}
      />

      {/* 6 Primary Overview Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        <MetricCard
          title="Active Incidents"
          value={activeIncidents}
          subtitle="Correlated attack sessions"
          icon={Flame}
          color="amber"
        />
        <MetricCard
          title="Critical Incidents"
          value={criticalIncidents}
          subtitle="Score >= 80 (Immediate)"
          icon={AlertOctagon}
          color="red"
        />
        <MetricCard
          title="High Risk Incidents"
          value={highRiskIncidents}
          subtitle="Score 60 - 79 (Verification)"
          icon={AlertTriangle}
          color="amber"
        />
        <MetricCard
          title="Moderate Risk"
          value={moderateRiskIncidents}
          subtitle="Score 30 - 59 (Monitored)"
          icon={Activity}
          color="cyan"
        />
        <MetricCard
          title="Events Today"
          value={eventsTodayCount}
          subtitle="Normalized telemetry"
          icon={Activity}
          color="cyan"
        />
        <MetricCard
          title="Recent Alerts"
          value={recentAlertsCount}
          subtitle="Escalation & n8n hooks"
          icon={ShieldAlert}
          color="purple"
        />
      </div>

      {/* Two Column Layout: Correlated Incidents & Recent Alerts (Elevated to top priority) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left 7 cols: Active Correlated Incidents */}
        <div className="lg:col-span-7 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Flame className="w-4 h-4 text-amber-500 dark:text-amber-400" />
              <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-900 dark:text-slate-300">
                Correlated Incidents ({incidents.length})
              </h2>
            </div>
            <button
              onClick={() => setTab('incidents')}
              className="text-xs text-cyan-600 dark:text-cyan-400 hover:text-cyan-500 dark:hover:text-cyan-300 font-mono flex items-center gap-1 cursor-pointer"
            >
              <span>View Detailed Chains</span>
              <ChevronRight size={14} />
            </button>
          </div>

          {incidents.length === 0 ? (
            <Card className="text-center py-8 text-slate-500 dark:text-slate-400 text-xs">
              No active security incidents detected.
            </Card>
          ) : (
            <div className="space-y-3">
              {incidents.slice(0, 5).map((incident) => {
                const risk = incident.risk_assessment;
                const eventCount = incident.events?.length || incident.event_ids?.length || 1;
                const primaryUser = incident.primary_entity || 'N/A';
                
                return (
                  <div
                    key={incident.id}
                    onClick={() => {
                      if (onSelectIncident) onSelectIncident(incident);
                      if (setTab) setTab('incidents');
                    }}
                    className="p-4 rounded-xl bg-white dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 hover:border-cyan-500/50 hover:bg-slate-50 dark:hover:bg-slate-900 transition-all cursor-pointer shadow-xs"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-bold text-slate-900 dark:text-white">
                            {incident.id}
                          </span>
                          <RiskBadge level={risk?.risk_level || incident.risk_level || 'LOW'} score={risk?.risk_score !== undefined ? risk.risk_score : incident.risk_score} />
                        </div>
                        <p className="text-xs text-slate-600 dark:text-slate-300 font-medium line-clamp-1">
                          {risk?.reasons?.[0] || 'Multi-event correlation detected anomalies'}
                        </p>
                      </div>
                      <StatusBadge status={incident.status || 'active'} />
                    </div>

                    <div className="mt-3 pt-3 border-t border-slate-100 dark:border-slate-800/80 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500 dark:text-slate-400 font-mono">
                      <div className="flex items-center gap-4">
                        <span>User: <strong className="text-slate-700 dark:text-slate-200">{primaryUser}</strong></span>
                        <span>Events: <strong className="text-cyan-600 dark:text-cyan-400">{eventCount}</strong></span>
                      </div>
                      <div className="flex items-center gap-1 text-[11px]">
                        <Clock size={12} />
                        <span>{new Date(incident.created_at || Date.now()).toLocaleTimeString()}</span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Right 5 cols: High Priority Recent Alerts Queue */}
        <div className="lg:col-span-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
              <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-900 dark:text-slate-300">
                Recent Alerts ({sortedAlerts.length})
              </h2>
            </div>
            <button
              onClick={() => setTab('alerts')}
              className="text-xs text-cyan-600 dark:text-cyan-400 hover:text-cyan-500 dark:hover:text-cyan-300 font-mono flex items-center gap-1 cursor-pointer"
            >
              <span>Alerts Center</span>
              <ChevronRight size={14} />
            </button>
          </div>

          {sortedAlerts.length === 0 ? (
            <Card className="text-center py-8 text-slate-500 dark:text-slate-400 text-xs">
              No recent alerts triggered.
            </Card>
          ) : (
            <div className="space-y-3">
              {sortedAlerts.slice(0, 5).map((alert) => {
                const isContained = alert.status === 'contained' || alert.incident_status === 'contained';
                const isResolved = alert.status === 'resolved' || alert.status === 'mitigated' || alert.status === 'recovered' || alert.incident_status === 'resolved';
                const isCrit = !isContained && !isResolved && (((alert.risk_level || alert.severity || '').toUpperCase() === 'CRITICAL') || (alert.risk_score >= 80));
                const isHigh = !isContained && !isResolved && (((alert.risk_level || alert.severity || '').toUpperCase() === 'HIGH') || (alert.risk_score >= 60 && alert.risk_score < 80));
                const alertTitle = alert.title || alert.threat_type || alert.message || alert.reasons?.[0] || 'Security Anomaly Detected';
                const alertTarget = alert.primary_entity || alert.affected_entity || alert.target_entity || 'Network/Host';
                const alertLevel = isContained ? 'LOW' : isResolved ? 'RESOLVED' : (alert.risk_level || alert.severity || (alert.risk_score >= 80 ? 'CRITICAL' : alert.risk_score >= 60 ? 'HIGH' : alert.risk_score >= 30 ? 'MODERATE' : 'LOW'));

                return (
                  <div
                    key={alert.alert_id || alert.id}
                    onClick={() => {
                      if (onSelectAlert) onSelectAlert(alert);
                      if (setTab) setTab('alerts');
                    }}
                    className={`p-3.5 rounded-xl bg-white dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 transition-all cursor-pointer shadow-xs ${
                      isCrit 
                        ? 'border-l-4 border-l-rose-500 shadow-rose-950/20' 
                        : isHigh 
                        ? 'border-l-4 border-l-amber-500 shadow-amber-950/20' 
                        : isContained
                        ? 'border-l-4 border-l-indigo-500 shadow-indigo-950/20'
                        : isResolved
                        ? 'border-l-4 border-l-emerald-500 shadow-emerald-950/20'
                        : 'border-l-4 border-l-cyan-500'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex items-center gap-1.5 flex-1 min-w-0">
                        {isContained && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-950/80 text-indigo-300 border border-indigo-700 shrink-0">
                            CONTAINED
                          </span>
                        )}
                        {isResolved && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950/80 text-emerald-300 border border-emerald-700 shrink-0">
                            RESOLVED
                          </span>
                        )}
                        <span className="text-xs font-bold text-slate-900 dark:text-slate-200 line-clamp-1">
                          {alertTitle}
                        </span>
                      </div>
                      <RiskBadge level={alertLevel} score={alert.risk_score} />
                    </div>
                    <div className="mt-2 flex items-center justify-between text-[11px] text-slate-500 dark:text-slate-400 font-mono">
                      <span>Target: <strong className="text-slate-700 dark:text-slate-300">{alertTarget}</strong></span>
                      <span>{new Date(alert.timestamp || alert.created_at || Date.now()).toLocaleTimeString()}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Clear Risk Indicators: LOW, MODERATE, HIGH, CRITICAL */}
      <Card className="p-4 bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-3">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
            Threat Distribution by Severity
          </span>
          <span className="text-xs font-mono text-slate-500 dark:text-slate-400">
            Total Correlated Incidents: {incidents.length}
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="p-3 rounded-xl bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800/40 flex items-center justify-between">
            <div>
              <div className="text-[11px] font-semibold text-emerald-700 dark:text-emerald-400 tracking-wider">LOW RISK</div>
              <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 font-mono">Routine Baseline</div>
            </div>
            <span className="text-xl font-bold font-mono text-emerald-700 dark:text-emerald-400">{lowRiskIncidents}</span>
          </div>

          <div className="p-3 rounded-xl bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800/40 flex items-center justify-between">
            <div>
              <div className="text-[11px] font-semibold text-amber-700 dark:text-amber-400 tracking-wider">MODERATE RISK</div>
              <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 font-mono">Anomalous Activity</div>
            </div>
            <span className="text-xl font-bold font-mono text-amber-700 dark:text-amber-400">{moderateRiskIncidents}</span>
          </div>

          <div className="p-3 rounded-xl bg-orange-50 dark:bg-orange-950/40 border border-orange-200 dark:border-orange-800/40 flex items-center justify-between">
            <div>
              <div className="text-[11px] font-semibold text-orange-700 dark:text-orange-400 tracking-wider">HIGH RISK</div>
              <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 font-mono">Step-up Auth Req.</div>
            </div>
            <span className="text-xl font-bold font-mono text-orange-700 dark:text-orange-400">{highRiskIncidents}</span>
          </div>

          <div className="p-3 rounded-xl bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-800/40 flex items-center justify-between">
            <div>
              <div className="text-[11px] font-semibold text-red-700 dark:text-red-400 tracking-wider">CRITICAL RISK</div>
              <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 font-mono">Containment Trigger</div>
            </div>
            <span className="text-xl font-bold font-mono text-red-700 dark:text-red-400">{criticalIncidents}</span>
          </div>
        </div>
      </Card>
    </div>
  );
}

export default OverviewPage;
