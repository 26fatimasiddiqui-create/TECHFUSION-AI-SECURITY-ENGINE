import React, { useState, useEffect, useCallback } from 'react';
import { InsightEmployeeTable } from '../components/insight/InsightEmployeeTable';
import { InsightEmployeeModal } from '../components/insight/InsightEmployeeModal';
import { 
  fetchEmployeesFromSupabase,
  fetchRiskEventsFromSupabase,
  fetchAlertsFromSupabase,
  getAllAccessLogs,
  deriveDashboardState,
  supabase,
  isSupabaseConfigured
} from '../services/insightSupabase';
import { Users, RefreshCw } from 'lucide-react';

export function EmployeesPage({ setTab }) {
  const [employees, setEmployees] = useState([]);
  const [riskEvents, setRiskEvents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [accessLogs, setAccessLogs] = useState([]);
  const [selectedEmployee, setSelectedEmployee] = useState(null);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const loadData = useCallback(async () => {
    setIsRefreshing(true);
    if (!isSupabaseConfigured || !supabase) {
      setIsRefreshing(false);
      return;
    }
    try {
      const [empRes, riskRes, altRes, logRes] = await Promise.all([
        fetchEmployeesFromSupabase(),
        fetchRiskEventsFromSupabase(),
        fetchAlertsFromSupabase(),
        getAllAccessLogs()
      ]);

      setEmployees(empRes.data || []);
      setRiskEvents(riskRes.data || []);
      setAlerts(altRes.data || []);
      setAccessLogs(logData || []);
    } catch (err) {
      console.error('EmployeesPage fetch error:', err);
    } finally {
      setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const dashboardState = deriveDashboardState(employees, riskEvents, alerts, accessLogs);

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-800 dark:text-slate-100 font-sans pb-16 transition-colors">
      <header className="bg-white/95 dark:bg-slate-900/95 border-b border-slate-200 dark:border-slate-800 backdrop-blur-md px-4 sm:px-8 py-4 sticky top-0 z-30 shadow-xs">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-blue-600 text-white flex items-center justify-center shadow-md shadow-blue-500/20">
              <Users size={20} />
            </div>
            <div>
              <h1 className="text-xl sm:text-2xl font-black text-slate-900 dark:text-white">
                Employees Directory
              </h1>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Monitored Workforce Identities & Relational Risk History ({employees.length.toLocaleString()} total)
              </p>
            </div>
          </div>

          <button
            onClick={loadData}
            disabled={isRefreshing}
            className="p-2 sm:px-3 sm:py-2 rounded-xl bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700 text-xs font-semibold flex items-center gap-1.5 cursor-pointer shadow-xs"
          >
            <RefreshCw size={14} className={isRefreshing ? 'animate-spin' : ''} />
            <span className="hidden sm:inline">Refresh</span>
          </button>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-8 pt-6">
        <InsightEmployeeTable
          employees={dashboardState.employees}
          onSelectEmployee={(emp) => setSelectedEmployee(emp)}
          onQuickSimulate={(emp) => {
            if (setTab) setTab('technical');
          }}
        />
      </main>

      {selectedEmployee && (
        <InsightEmployeeModal
          employee={selectedEmployee}
          onClose={() => setSelectedEmployee(null)}
          onSimulateThreat={(emp) => {
            setSelectedEmployee(null);
            if (setTab) setTab('technical');
          }}
        />
      )}
    </div>
  );
}

export default EmployeesPage;
