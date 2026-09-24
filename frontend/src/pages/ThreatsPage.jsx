import React, { useState, useEffect, useCallback } from 'react';
import { 
  Flame, 
  ShieldAlert, 
  CheckCircle2, 
  Check, 
  Clock, 
  RefreshCw, 
  Filter, 
  Search,
  ExternalLink,
  Shield,
  AlertTriangle
} from 'lucide-react';
import { 
  fetchAlertsFromSupabase,
  fetchEmployeesFromSupabase,
  approveAlertInSupabase,
  resolveAlertInSupabase,
  deriveDashboardState,
  isAlertActive,
  calculateRiskLevel,
  isSupabaseConfigured,
  supabase
} from '../services/insightSupabase';
import { InsightAlertModal } from '../components/insight/InsightAlertModal';

export function ThreatsPage({ setTab, onSelectIncident }) {
  const [alerts, setAlerts] = useState([]);
  const [employees, setEmployees] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [filterSeverity, setFilterSeverity] = useState('ALL'); // ALL | CRITICAL | HIGH | MODERATE | LOW
  const [search, setSearch] = useState('');
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [actionFeedback, setActionFeedback] = useState(null);

  const loadData = useCallback(async (silent = false) => {
    if (!silent) setIsLoading(true);
    setIsRefreshing(true);
    try {
      const [altRes, empRes] = await Promise.all([
        fetchAlertsFromSupabase(),
        fetchEmployeesFromSupabase()
      ]);
      setAlerts(altRes.data || []);
      setEmployees(empRes.data || []);
    } catch (err) {
      console.error('ThreatsPage load error:', err);
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadData(false);
  }, [loadData]);

  const dashboardState = deriveDashboardState(employees, [], alerts, []);

  // Filter only ACTIVE threats
  const activeThreats = dashboardState.alerts.filter(t => {
    if (filterSeverity !== 'ALL' && t.severity !== filterSeverity) return false;
    if (search.trim()) {
      const q = search.toLowerCase();
      const matchName = (t.employee_name || '').toLowerCase().includes(q);
      const matchCode = (t.employee_code || '').toLowerCase().includes(q);
      const matchMsg = (t.message || '').toLowerCase().includes(q);
      const matchType = (t.alert_type || '').toLowerCase().includes(q);
      if (!matchName && !matchCode && !matchMsg && !matchType) return false;
    }
    return true;
  });

  const handleApprove = async (alertId, empName) => {
    try {
      await approveAlertInSupabase(alertId);
      setAlerts(prev => prev.map(a => a.id === alertId ? { ...a, status: 'approved', resolved_at: new Date().toISOString() } : a));
      setActionFeedback({ type: 'success', message: `Threat approved for ${empName || 'employee'}. Removed from active monitoring.` });
      await loadData(true);
    } catch (err) {
      setActionFeedback({ type: 'error', message: err.message || 'Error approving threat' });
    } finally {
      setTimeout(() => setActionFeedback(null), 4000);
    }
  };

  const handleResolve = async (alertId, empName) => {
    try {
      await resolveAlertInSupabase(alertId);
      setAlerts(prev => prev.map(a => a.id === alertId ? { ...a, status: 'resolved', resolved_at: new Date().toISOString() } : a));
      setActionFeedback({ type: 'success', message: `Threat resolved for ${empName || 'employee'}.` });
      await loadData(true);
    } catch (err) {
      setActionFeedback({ type: 'error', message: err.message || 'Error resolving threat' });
    } finally {
      setTimeout(() => setActionFeedback(null), 4000);
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-800 dark:text-slate-100 font-sans pb-16 transition-colors">
      
      {/* Toast */}
      {actionFeedback && (
        <div className={`fixed bottom-6 right-6 z-50 p-4 rounded-xl shadow-xl border flex items-center gap-2 text-xs font-semibold ${
          actionFeedback.type === 'success' ? 'bg-emerald-900 text-white border-emerald-600' : 'bg-rose-900 text-white border-rose-600'
        }`}>
          {actionFeedback.type === 'success' ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}
          <span>{actionFeedback.message}</span>
        </div>
      )}

      {/* Header */}
      <header className="bg-white/95 dark:bg-slate-900/95 border-b border-slate-200 dark:border-slate-800 backdrop-blur-md px-4 sm:px-8 py-4 sticky top-0 z-30 shadow-xs">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-rose-600 text-white flex items-center justify-center shadow-md shadow-rose-500/20">
              <Flame size={22} />
            </div>
            <div>
              <h1 className="text-xl sm:text-2xl font-black text-slate-900 dark:text-white">
                Active Threats
              </h1>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Live threat incidents requiring investigation, approval, or containment
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2.5">
            <button
              onClick={() => loadData(false)}
              disabled={isRefreshing}
              className="p-2 sm:px-3 sm:py-2 rounded-xl bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700 text-xs font-semibold flex items-center gap-1.5 cursor-pointer shadow-xs"
            >
              <RefreshCw size={14} className={isRefreshing ? 'animate-spin' : ''} />
              <span className="hidden sm:inline">Refresh</span>
            </button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-8 pt-6 space-y-6">
        
        {/* Controls: Search & Filter */}
        <div className="p-4 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3 shadow-xs">
          
          <div className="relative w-full sm:w-80">
            <Search size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search threat by employee, type..."
              className="w-full pl-9 pr-4 py-2 rounded-xl text-xs bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-white outline-none focus:border-cyan-500"
            />
          </div>

          <div className="flex items-center gap-1.5 overflow-x-auto w-full sm:w-auto">
            {['ALL', 'CRITICAL', 'HIGH', 'MODERATE', 'LOW'].map((lvl) => (
              <button
                key={lvl}
                onClick={() => setFilterSeverity(lvl)}
                className={`px-3 py-1.5 rounded-xl text-xs font-bold transition-all cursor-pointer ${
                  filterSeverity === lvl
                    ? 'bg-slate-900 dark:bg-white text-white dark:text-slate-900 shadow-xs'
                    : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-700'
                }`}
              >
                {lvl}
              </button>
            ))}
          </div>

        </div>

        {/* Threats List */}
        {activeThreats.length === 0 ? (
          <div className="p-12 rounded-3xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-center space-y-3">
            <CheckCircle2 size={40} className="mx-auto text-emerald-500" />
            <h3 className="text-base font-bold text-slate-900 dark:text-white">
              No Active Threats Found
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 max-w-md mx-auto">
              There are no active security threats matching the selected filter criteria. All threats have been reviewed or resolved.
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {activeThreats.map((threat) => {
              const score = Number(threat.risk_score || 0);
              const isCrit = threat.severity === 'CRITICAL' || score >= 85;
              const isHigh = !isCrit && (threat.severity === 'HIGH' || score >= 70);

              return (
                <div
                  key={threat.id}
                  className="p-5 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs hover:border-slate-300 dark:hover:border-slate-700 transition-all flex flex-col md:flex-row items-start md:items-center justify-between gap-4"
                >
                  <div className="space-y-1.5 flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-bold text-sm text-slate-900 dark:text-white">
                        {threat.employee_name}
                      </span>
                      <span className="text-xs font-mono text-slate-400">
                        ({threat.employee_code})
                      </span>
                      <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase ${
                        isCrit 
                          ? 'bg-rose-100 dark:bg-rose-950 text-rose-700 dark:text-rose-300 border border-rose-300 dark:border-rose-800'
                          : isHigh
                          ? 'bg-amber-100 dark:bg-amber-950 text-amber-700 dark:text-amber-300 border border-amber-300 dark:border-amber-800'
                          : 'bg-blue-100 dark:bg-blue-950 text-blue-700 dark:text-blue-300 border border-blue-300 dark:border-blue-800'
                      }`}>
                        {threat.severity}
                      </span>
                      <span className="text-xs font-mono font-bold text-slate-700 dark:text-slate-300">
                        Score: {score}/100
                      </span>
                    </div>

                    <p className="text-xs text-slate-600 dark:text-slate-300">
                      {threat.message}
                    </p>

                    <div className="flex items-center gap-4 text-[11px] text-slate-400 font-mono pt-0.5">
                      <span className="flex items-center gap-1">
                        <Clock size={12} />
                        {threat.created_at ? new Date(threat.created_at).toLocaleString() : 'Recent'}
                      </span>
                      {threat.alert_type && (
                        <span>Type: {threat.alert_type}</span>
                      )}
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-2 shrink-0 w-full md:w-auto pt-2 md:pt-0 border-t md:border-t-0 border-slate-100 dark:border-slate-800">
                    <button
                      onClick={() => setSelectedAlert(threat)}
                      className="px-3.5 py-2 rounded-xl bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 text-xs font-bold transition-all cursor-pointer"
                    >
                      Details
                    </button>

                    <button
                      onClick={() => handleApprove(threat.id, threat.employee_name)}
                      className="px-4 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold transition-all shadow-xs flex items-center gap-1.5 cursor-pointer"
                    >
                      <Check size={14} />
                      <span>Approve</span>
                    </button>

                    <button
                      onClick={() => handleResolve(threat.id, threat.employee_name)}
                      className="px-4 py-2 rounded-xl bg-white dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 border border-slate-300 dark:border-slate-700 text-xs font-bold transition-all shadow-xs flex items-center gap-1.5 cursor-pointer"
                    >
                      <CheckCircle2 size={14} className="text-cyan-600" />
                      <span>Resolve</span>
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}

      </main>

      {/* Alert Detail Modal */}
      {selectedAlert && (
        <InsightAlertModal
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
          onStatusUpdated={(alertId) => {
            loadData(true);
            setSelectedAlert(null);
          }}
        />
      )}

    </div>
  );
}

export default ThreatsPage;
