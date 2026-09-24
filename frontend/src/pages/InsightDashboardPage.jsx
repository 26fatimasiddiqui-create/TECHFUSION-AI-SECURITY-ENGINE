import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { InsightHeader } from '../components/insight/InsightHeader';
import { InsightKpiCards } from '../components/insight/InsightKpiCards';
import { InsightRiskOverview } from '../components/insight/InsightRiskOverview';
import { InsightSimulationPanel } from '../components/insight/InsightSimulationPanel';
import { InsightEmployeeTable } from '../components/insight/InsightEmployeeTable';
import { InsightAlertPanel } from '../components/insight/InsightAlertPanel';
import { InsightApiTestPanel } from '../components/insight/InsightApiTestPanel';
import { InsightEmployeeModal } from '../components/insight/InsightEmployeeModal';
import { InsightAlertModal } from '../components/insight/InsightAlertModal';
import { InsightN8nHealthModal } from '../components/insight/InsightN8nHealthModal';
import { InsightActionCenterModal } from '../components/insight/InsightActionCenterModal';
import { EmployeeMapView } from '../components/insight/EmployeeMapView';

import { 
  fetchEmployeesFromSupabase,
  fetchRiskEventsFromSupabase,
  fetchAlertsFromSupabase,
  getAllAccessLogs,
  approveAlertInSupabase,
  resolveAlertInSupabase,
  deriveDashboardState,
  supabase,
  isSupabaseConfigured,
  calculateRiskLevel
} from '../services/insightSupabase';
import { testN8nConnection } from '../services/n8nService';
import { AlertCircle, Database, RefreshCw, KeyRound, Copy, Check } from 'lucide-react';

export function InsightDashboardPage({ onActiveAlertCountChange }) {
  // Raw Supabase states
  const [rawEmployees, setRawEmployees] = useState([]);
  const [rawRiskEvents, setRawRiskEvents] = useState([]);
  const [rawAlerts, setRawAlerts] = useState([]);
  const [rawAccessLogs, setRawAccessLogs] = useState([]);

  // UI state
  const [lastUpdated, setLastUpdated] = useState(new Date().toISOString());
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [loadError, setLoadError] = useState(null);
  
  // Navigation section: 'dashboard' | 'api-test'
  const [activeSection, setActiveSection] = useState('dashboard');

  // Modals & detail views
  const [selectedEmployee, setSelectedEmployee] = useState(null);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [healthModalOpen, setHealthModalOpen] = useState(false);
  const [healthResult, setHealthResult] = useState(null);
  const [isTestingHealth, setIsTestingHealth] = useState(false);
  const [n8nStatus, setN8nStatus] = useState('idle'); // 'idle' | 'connected' | 'failed'
  const [copiedSql, setCopiedSql] = useState(false);
  const [actionCenterEmployee, setActionCenterEmployee] = useState(null);
  const [approvedEmployeeIds, setApprovedEmployeeIds] = useState(() => new Set());
  const [mapViewEmployee, setMapViewEmployee] = useState(null);

  const channelRef = useRef(null);

  // ==========================================================================
  // 1. DATA REFETCH: Purely from Supabase tables
  // ==========================================================================
  const loadAllData = useCallback(async (silent = false) => {
    if (!silent) setIsRefreshing(true);
    setLoadError(null);

    if (!isSupabaseConfigured || !supabase) {
      setRawEmployees([]);
      setRawRiskEvents([]);
      setRawAlerts([]);
      setRawAccessLogs([]);
      if (!silent) setIsRefreshing(false);
      return;
    }

    try {
      const [empRes, riskRes, altRes, logRes] = await Promise.all([
        fetchEmployeesFromSupabase(),
        fetchRiskEventsFromSupabase(),
        fetchAlertsFromSupabase(),
        getAllAccessLogs()
      ]);

      if (empRes.error) {
        console.warn('Employees fetch notice:', empRes.error);
      }
      if (riskRes.error) {
        console.warn('Risk events fetch notice:', riskRes.error);
      }
      if (altRes.error) {
        console.warn('Alerts fetch notice:', altRes.error);
      }
      if (logRes.error) {
        console.warn('Access logs fetch notice:', logRes.error);
      }

      setRawEmployees(empRes.data || []);
      setRawRiskEvents(riskRes.data || []);
      setRawAlerts(altRes.data || []);
      setRawAccessLogs(logRes.data || []);
      setLastUpdated(new Date().toISOString());
    } catch (err) {
      console.error('Failed loading Supabase data:', err);
      setLoadError(err.message || 'Error querying Supabase records');
    } finally {
      if (!silent) setIsRefreshing(false);
    }
  }, []);

  // ==========================================================================
  // 2. SUBSCRIPTIONS & POLLING (Every 6 seconds)
  // ==========================================================================
  useEffect(() => {
    // Initial fetch
    loadAllData(false);

    // Initial silent n8n health probe
    testN8nConnection().then(res => {
      setHealthResult(res);
      setN8nStatus(res.connected ? 'connected' : 'failed');
    });

    // Supabase Realtime Subscription to: alerts, risk_events, incidents
    if (isSupabaseConfigured && supabase) {
      try {
        const channel = supabase
          .channel('public:insight_threat_realtime')
          .on(
            'postgres_changes',
            { event: '*', schema: 'public', table: 'alerts' },
            (payload) => {
              console.log('Realtime alert event:', payload);
              loadAllData(true);
            }
          )
          .on(
            'postgres_changes',
            { event: '*', schema: 'public', table: 'risk_events' },
            (payload) => {
              console.log('Realtime risk_event event:', payload);
              loadAllData(true);
            }
          )
          .on(
            'postgres_changes',
            { event: '*', schema: 'public', table: 'incidents' },
            (payload) => {
              console.log('Realtime incident event:', payload);
              loadAllData(true);
            }
          )
          .subscribe();

        channelRef.current = channel;
      } catch (e) {
        console.warn('Supabase realtime subscription failed, using polling:', e);
      }
    }

    // Polling fallback every 6 seconds as required by specification
    const pollTimer = setInterval(() => {
      loadAllData(true);
    }, 6000);

    return () => {
      clearInterval(pollTimer);
      if (channelRef.current && supabase) {
        supabase.removeChannel(channelRef.current);
      }
    };
  }, [loadAllData]);

  // ==========================================================================
  // 3. TEST N8N CONNECTION ACTION
  // ==========================================================================
  const handleTestConnection = async () => {
    setIsTestingHealth(true);
    setHealthModalOpen(true);
    const result = await testN8nConnection();
    setHealthResult(result);
    setN8nStatus(result.connected ? 'connected' : 'failed');
    setIsTestingHealth(false);
  };

  // ==========================================================================
  // 4. WORKFLOW / SIMULATION COMPLETION
  // STRICT RULE: No local fake alert injection! Refetch directly from Supabase!
  // ==========================================================================
  const handleSimulationComplete = (result) => {
    // Immediate refetch
    loadAllData(true);

    // Staggered refetch to catch n8n automation -> Supabase insertion
    setTimeout(() => {
      loadAllData(true);
    }, 1500);

    setTimeout(() => {
      loadAllData(true);
    }, 3500);
  };

  // ==========================================================================
  // 5. DERIVE UNIFIED DASHBOARD STATE FROM SUPABASE
  // ==========================================================================
  const dashboardState = deriveDashboardState(rawEmployees, rawRiskEvents, rawAlerts, rawAccessLogs);

  // For approved employees: lower risk score to LOW so they stay in the table
  // but are no longer shown as CRITICAL/HIGH risk
  const visibleEmployees = useMemo(() => {
    if (approvedEmployeeIds.size === 0) return dashboardState.employees;
    return dashboardState.employees.map(emp => {
      if (approvedEmployeeIds.has(String(emp.id))) {
        const lowScore = 15; // LOW risk
        return {
          ...emp,
          latestRiskScore: lowScore,
          riskLevel: calculateRiskLevel(lowScore),
          status: 'CLEARED'
        };
      }
      return emp;
    });
  }, [dashboardState.employees, approvedEmployeeIds]);

  // Sync active alert count with layout and sidebar badge
  useEffect(() => {
    if (onActiveAlertCountChange && typeof dashboardState.activeAlertsCount === 'number') {
      onActiveAlertCountChange(dashboardState.activeAlertsCount);
    }
  }, [dashboardState.activeAlertsCount, onActiveAlertCountChange]);

  // Handler: Human/SOC Analyst Approves a Threat
  const handleApproveAlert = async (alertId) => {
    try {
      const { error } = await approveAlertInSupabase(alertId);
      if (error) {
        console.error('Failed to approve alert in Supabase:', error);
      }
      // Re-fetch from Supabase immediately to ensure Supabase remains single source of truth
      await loadAllData(true);
    } catch (err) {
      console.error('Error approving alert:', err);
    }
  };

  // Handler: Human/SOC Analyst Resolves a Threat
  const handleResolveAlert = async (alertId) => {
    try {
      const { error } = await resolveAlertInSupabase(alertId);
      if (error) {
        console.error('Failed to resolve alert in Supabase:', error);
      }
      // Re-fetch from Supabase immediately
      await loadAllData(true);
    } catch (err) {
      console.error('Error resolving alert:', err);
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 flex flex-col font-sans selection:bg-rose-500 selection:text-white transition-colors duration-200">
      
      {/* 1. HEADER */}
      <InsightHeader
        lastUpdated={lastUpdated}
        isRefreshing={isRefreshing}
        onRefresh={() => loadAllData(false)}
        onTestConnection={handleTestConnection}
        isTestingConnection={isTestingHealth}
        n8nStatus={n8nStatus}
        activeSection={activeSection}
        setActiveSection={setActiveSection}
      />

      {/* Main Content View Container */}
      <main className="flex-1 p-4 sm:p-6 lg:p-8 max-w-7xl mx-auto w-full space-y-6">
        
        {/* Supabase Connection Setup Notice if not configured */}
        {!isSupabaseConfigured && (
          <div className="p-4 rounded-2xl bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-800/80 text-amber-900 dark:text-amber-200 text-xs font-mono space-y-2">
            <div className="flex items-center gap-2 font-bold text-amber-800 dark:text-amber-300">
              <Database size={16} />
              <span>Supabase Database Connection Required</span>
            </div>
            <p className="font-sans text-slate-700 dark:text-slate-300 leading-relaxed">
              To view real-time security alerts and live employee risk metrics, enter your Supabase project credentials in <code className="text-amber-800 dark:text-amber-300 font-mono font-bold">frontend/.env</code>:
            </p>
            <pre className="p-3 rounded-xl bg-slate-900 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-amber-300 text-[11px] overflow-x-auto">
              VITE_SUPABASE_URL=https://your-project.supabase.co
              <br />
              VITE_SUPABASE_ANON_KEY=eyJhbGciOi...
            </pre>
            <p className="text-[11px] text-slate-500 dark:text-slate-400 font-sans">
              All tables are defined in <code className="text-cyan-600 dark:text-cyan-400 font-mono font-bold">supabase_insider_threat_schema.sql</code>. All metrics will be calculated strictly from your Supabase records with zero mock data.
            </p>
          </div>
        )}

        {loadError && (
          <div className="p-3.5 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-300 dark:border-rose-800 text-rose-800 dark:text-rose-300 text-xs font-mono flex items-center justify-between">
            <span>Supabase Query Notice: {loadError}</span>
            <button
              onClick={() => loadAllData(false)}
              className="px-2.5 py-1 rounded bg-rose-600 hover:bg-rose-700 dark:bg-rose-900/60 dark:hover:bg-rose-900 text-white cursor-pointer font-bold"
            >
              Retry Query
            </button>
          </div>
        )}

        {/* Row Level Security (RLS) Advisory Banner when database returns 0 records */}
        {isSupabaseConfigured && !isRefreshing && rawEmployees.length === 0 && (
          <div className="p-4 rounded-2xl bg-amber-50/80 dark:bg-amber-950/30 border border-amber-300 dark:border-amber-700/80 text-amber-900 dark:text-amber-200 text-xs font-mono space-y-3 shadow-xs dark:shadow-lg dark:shadow-black/30">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <div className="flex items-center gap-2 font-bold text-amber-800 dark:text-amber-300">
                <AlertCircle size={16} />
                <span>Supabase Row-Level Security (RLS) Active — 0 Records Returned</span>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => {
                    const sql = `ALTER TABLE employees DISABLE ROW LEVEL SECURITY;\nALTER TABLE access_logs DISABLE ROW LEVEL SECURITY;\nALTER TABLE risk_events DISABLE ROW LEVEL SECURITY;\nALTER TABLE alerts DISABLE ROW LEVEL SECURITY;\nALTER TABLE incidents DISABLE ROW LEVEL SECURITY;\nALTER TABLE approvals DISABLE ROW LEVEL SECURITY;`;
                    navigator.clipboard?.writeText(sql);
                    setCopiedSql(true);
                    setTimeout(() => setCopiedSql(false), 2000);
                  }}
                  className="px-3 py-1 rounded-xl bg-white dark:bg-slate-900 hover:bg-slate-100 dark:hover:bg-slate-800 text-cyan-700 dark:text-cyan-300 border border-slate-300 dark:border-slate-700 cursor-pointer flex items-center gap-1.5 transition-colors font-bold shadow-xs"
                >
                  {copiedSql ? <Check size={12} className="text-emerald-500" /> : <Copy size={12} />}
                  <span>{copiedSql ? 'Copied SQL!' : 'Copy SQL'}</span>
                </button>
                <button
                  onClick={() => loadAllData(false)}
                  className="px-3 py-1 rounded-xl bg-amber-100 hover:bg-amber-200 dark:bg-amber-900/60 dark:hover:bg-amber-900 text-amber-900 dark:text-amber-200 border border-amber-300 dark:border-amber-700 cursor-pointer flex items-center gap-1.5 transition-colors font-bold shadow-xs"
                >
                  <RefreshCw size={12} className={isRefreshing ? 'animate-spin' : ''} />
                  <span>Recheck Supabase</span>
                </button>
              </div>
            </div>
            <p className="font-sans text-slate-700 dark:text-slate-300 leading-relaxed text-xs">
              The application is successfully connected to your Supabase project (<code className="text-cyan-700 dark:text-cyan-400 font-mono font-bold">frdxnrwcvbksmfocsvqu</code>), but PostgreSQL returned 0 rows because <strong>Row Level Security (RLS)</strong> is enabled on your tables without an anonymous <code className="text-amber-800 dark:text-amber-300 font-bold">SELECT</code> read policy.
            </p>
            <div className="space-y-1">
              <span className="text-[10px] text-slate-500 dark:text-slate-400 font-bold uppercase tracking-wider block">
                To allow the frontend to display your 1,000 employees and data, run this SQL in Supabase Dashboard → SQL Editor:
              </span>
              <pre className="p-3 rounded-xl bg-slate-900 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-emerald-400 text-[11px] overflow-x-auto leading-relaxed select-all">
{`ALTER TABLE employees DISABLE ROW LEVEL SECURITY;
ALTER TABLE access_logs DISABLE ROW LEVEL SECURITY;
ALTER TABLE risk_events DISABLE ROW LEVEL SECURITY;
ALTER TABLE alerts DISABLE ROW LEVEL SECURITY;
ALTER TABLE incidents DISABLE ROW LEVEL SECURITY;
ALTER TABLE approvals DISABLE ROW LEVEL SECURITY;`}
              </pre>
            </div>
          </div>
        )}

        {activeSection === 'dashboard' ? (
          <>
            {/* 2. KPI CARDS */}
            <InsightKpiCards
              totalEmployees={dashboardState.totalEmployees}
              highRiskEmployees={dashboardState.highRiskEmployees}
              criticalAlerts={dashboardState.criticalAlerts}
              alertsToday={dashboardState.alertsToday}
            />

            {/* 3. Middle Section: Risk Overview Chart (Left) & Predefined Scenarios (Right) */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              
              {/* Risk Overview with Recharts (5 cols) */}
              <div className="lg:col-span-5">
                <InsightRiskOverview employees={dashboardState.employees} />
              </div>

              {/* Demo / Simulation Panel (7 cols) */}
              <div className="lg:col-span-7">
                <InsightSimulationPanel 
                  employees={dashboardState.employees}
                  onSimulationComplete={handleSimulationComplete}
                />
              </div>

            </div>

            {/* 4. EMPLOYEE RISK TABLE */}
            <InsightEmployeeTable
              employees={visibleEmployees}
              onSelectEmployee={(emp) => setSelectedEmployee(emp)}
              onOpenActionCenter={(emp) => setActionCenterEmployee(emp)}
              onOpenMapView={(emp) => setMapViewEmployee(emp)}
              onQuickSimulate={(emp) => {
                setActiveSection('api-test');
              }}
            />

            {/* 5. ALERT FEED PANEL */}
            <InsightAlertPanel
              alerts={dashboardState.alerts}
              allAlerts={dashboardState.allAlerts}
              onSelectAlert={(alt) => setSelectedAlert(alt)}
              onApproveAlert={handleApproveAlert}
              onResolveAlert={handleResolveAlert}
            />
          </>
        ) : (
          /* DEDICATED API TEST SECTION */
          <InsightApiTestPanel 
            employees={dashboardState.employees}
            onTestComplete={handleSimulationComplete}
          />
        )}

      </main>

      {/* 6. EMPLOYEE DETAIL VIEW MODAL */}
      {selectedEmployee && (
        <InsightEmployeeModal
          employee={selectedEmployee}
          onClose={() => setSelectedEmployee(null)}
          onSimulateThreat={(emp) => {
            setSelectedEmployee(null);
            setActiveSection('api-test');
          }}
        />
      )}

      {/* 7. ALERT DETAIL MODAL */}
      {selectedAlert && (
        <InsightAlertModal
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
          onStatusUpdated={(alertId, newStatus) => {
            loadAllData(true);
          }}
        />
      )}

      {/* 8. N8N CONNECTION HEALTH MODAL */}
      {healthModalOpen && (
        <InsightN8nHealthModal
          healthResult={healthResult}
          isLoading={isTestingHealth}
          onRetest={handleTestConnection}
          onClose={() => setHealthModalOpen(false)}
        />
      )}

      {/* 9. ACTION CENTER MODAL */}
      {actionCenterEmployee && (
        <InsightActionCenterModal
          employee={actionCenterEmployee}
          onClose={() => setActionCenterEmployee(null)}
          onApproveComplete={(employeeId, alertIds) => {
            // Lower employee risk to LOW immediately
            setApprovedEmployeeIds(prev => new Set([...prev, String(employeeId)]));
            // Refetch data from Supabase
            loadAllData(true);
            // Close modal after a short delay for success animation
            setTimeout(() => setActionCenterEmployee(null), 1200);
          }}
          onResolveComplete={(employeeId, alertIds) => {
            // Lower employee risk to LOW immediately
            setApprovedEmployeeIds(prev => new Set([...prev, String(employeeId)]));
            // Refetch data
            loadAllData(true);
            setTimeout(() => setActionCenterEmployee(null), 1200);
          }}
        />
      )}

      {/* 10. MAP VIEW MODAL */}
      {mapViewEmployee && (
        <EmployeeMapView
          employee={mapViewEmployee}
          alerts={rawAlerts.filter(a => a.employee_id === mapViewEmployee.id)}
          riskEvents={rawRiskEvents.filter(e => e.employee_id === mapViewEmployee.id)}
          onClose={() => setMapViewEmployee(null)}
        />
      )}

    </div>
  );
}

export default InsightDashboardPage;
