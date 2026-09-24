import React, { useState } from 'react';
import { 
  Play, 
  ShieldAlert, 
  AlertTriangle, 
  Activity, 
  CheckCircle2, 
  XCircle, 
  RefreshCw, 
  ArrowRight,
  Database,
  Sparkles,
  ExternalLink
} from 'lucide-react';
import { sendThreatAlert, N8N_PRODUCTION_WEBHOOK } from '../../services/n8nService';
import { insertRiskEventToSupabase } from '../../services/insightSupabase';

export function InsightSimulationPanel({ employees = [], onSimulationComplete }) {
  const [isLoading, setIsLoading] = useState(false);
  const [activeScenarioId, setActiveScenarioId] = useState('critical');
  const [lastResult, setLastResult] = useState(null);

  const scenarios = [
    {
      id: 'normal',
      name: 'NORMAL',
      title: 'A. Verma (Routine Engineering)',
      defaultCode: 'EMP001',
      risk_score: 25,
      severity: 'LOW',
      event: 'Standard employee authentication from verified corporate hardware',
      badgeColor: 'bg-emerald-50 dark:bg-emerald-950/80 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-700',
      buttonColor: 'bg-emerald-50 hover:bg-emerald-100 dark:bg-emerald-950 dark:hover:bg-emerald-900 border-emerald-300 dark:border-emerald-700 text-emerald-700 dark:text-emerald-300',
      border: 'border-slate-200 dark:border-slate-800 hover:border-emerald-400 dark:hover:border-emerald-800/60',
      n8nOutcome: 'Ignored by IF node (risk_score < 70) — Normal baseline profile'
    },
    {
      id: 'suspicious',
      name: 'SUSPICIOUS',
      title: 'R. Khan (Contractor Deviation)',
      defaultCode: 'EMP003',
      risk_score: 65,
      severity: 'HIGH',
      event: 'Unusual file access from Unknown Device (Linux)',
      badgeColor: 'bg-amber-50 dark:bg-amber-950/80 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-700',
      buttonColor: 'bg-amber-50 hover:bg-amber-100 dark:bg-amber-950 dark:hover:bg-amber-900 border-amber-300 dark:border-amber-700 text-amber-700 dark:text-amber-300',
      border: 'border-slate-200 dark:border-slate-800 hover:border-amber-400 dark:hover:border-amber-800/60',
      n8nOutcome: 'Below IF node threshold (risk_score < 70) — Flagged for review'
    },
    {
      id: 'critical',
      name: 'CRITICAL',
      title: 'J. Singh (Exfiltration Threat)',
      defaultCode: 'EMP001',
      risk_score: 87,
      severity: 'CRITICAL',
      event: 'Unusual sensitive-data access (/database/customer_credentials/dump)',
      badgeColor: 'bg-rose-50 dark:bg-rose-950/90 text-rose-700 dark:text-rose-300 border-rose-200 dark:border-rose-700',
      buttonColor: 'bg-gradient-to-r from-red-600 via-rose-600 to-rose-700 hover:from-red-500 hover:to-rose-600 text-white border-rose-600',
      border: 'border-rose-200 dark:border-rose-900/60 hover:border-rose-400 dark:hover:border-rose-700',
      n8nOutcome: 'Triggers IF node (risk_score >= 70) → Edit Fields → Supabase Create Row'
    }
  ];

  const handleSimulate = async (scenario) => {
    setIsLoading(true);
    setActiveScenarioId(scenario.id);
    setLastResult(null);

    // 1. Select a REAL employee from employees table
    const targetEmp = employees.find(e => e.employee_code === scenario.defaultCode) || employees[0];
    const employeeCode = targetEmp?.employee_code || scenario.defaultCode || 'EMP001';

    // 2. Create a risk event in Supabase using that employee's REAL UUID (if available)
    if (targetEmp?.id) {
      try {
        await insertRiskEventToSupabase({
          employee_id: targetEmp.id,
          event_type: scenario.id === 'critical' ? 'UNUSUAL_DATA_ACCESS' : scenario.id === 'suspicious' ? 'UNUSUAL_FILE_ACCESS' : 'NORMAL_ACTIVITY',
          description: scenario.event,
          risk_score: scenario.risk_score,
          severity: scenario.severity
        });
      } catch (err) {
        console.warn('Could not insert risk_event prior to webhook dispatch:', err);
      }
    }

    // 3. Dispatch payload to n8n webhook using employee_code
    const payload = {
      employee_id: employeeCode,
      risk_score: scenario.risk_score,
      severity: scenario.severity,
      event: scenario.event
    };

    const result = await sendThreatAlert(payload);
    setLastResult(result);
    setIsLoading(false);

    // 4. Notify parent to refetch Supabase (single source of truth)
    if (onSimulationComplete) {
      onSimulationComplete(result);
    }
  };

  const criticalScenario = scenarios.find(s => s.id === 'critical');

  return (
    <div className="p-5 rounded-2xl bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 shadow-xs dark:shadow-lg dark:shadow-black/20 space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 dark:border-slate-800/80 pb-3">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-xl bg-rose-50 dark:bg-rose-950/80 border border-rose-200 dark:border-rose-800/60 text-rose-600 dark:text-rose-400">
            <Play size={16} />
          </div>
          <div>
            <h3 className="text-xs font-bold uppercase font-mono tracking-wider text-slate-800 dark:text-slate-200">
              Threat Simulation Workbench
            </h3>
            <p className="text-[11px] text-slate-500 dark:text-slate-400 font-sans">
              Sends real event to n8n webhook • IF <code className="text-cyan-600 dark:text-cyan-400 font-mono font-bold">risk_score ≥ 70</code> → creates Supabase alert
            </p>
          </div>
        </div>

        {/* Hero Critical Action Button */}
        <button
          onClick={() => handleSimulate(criticalScenario)}
          disabled={isLoading}
          className="px-4 py-2 rounded-xl bg-gradient-to-r from-red-600 via-rose-600 to-rose-700 hover:from-red-500 hover:to-rose-600 text-white font-mono text-xs font-bold shadow-md shadow-rose-500/20 dark:shadow-rose-950/50 flex items-center gap-2 border border-rose-500 transition-all cursor-pointer active:scale-95 disabled:opacity-50"
        >
          {isLoading && activeScenarioId === 'critical' ? (
            <RefreshCw size={14} className="animate-spin" />
          ) : (
            <ShieldAlert size={14} />
          )}
          <span>Simulate Critical Threat</span>
        </button>
      </div>

      {/* Predefined Scenarios Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {scenarios.map((scenario) => {
          const isCurrentLoading = isLoading && activeScenarioId === scenario.id;
          return (
            <div
              key={scenario.id}
              className={`p-3.5 rounded-xl bg-slate-50/70 dark:bg-slate-950/70 border transition-all flex flex-col justify-between space-y-3 ${scenario.border}`}
            >
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${scenario.badgeColor}`}>
                    {scenario.name}
                  </span>
                  <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400">
                    Score: <strong className="text-slate-900 dark:text-white">{scenario.risk_score}</strong>
                  </span>
                </div>

                <div>
                  <h4 className="text-xs font-bold text-slate-800 dark:text-slate-200 font-mono">{scenario.title}</h4>
                  <p className="text-[11px] text-slate-600 dark:text-slate-400 font-sans mt-0.5 line-clamp-2">
                    "{scenario.event}"
                  </p>
                </div>

                <div className="p-2 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-[10px] text-slate-600 dark:text-slate-400 font-mono">
                  {scenario.n8nOutcome}
                </div>
              </div>

              <button
                onClick={() => handleSimulate(scenario)}
                disabled={isLoading}
                className={`w-full py-2 px-3 rounded-lg text-xs font-mono font-bold border flex items-center justify-center gap-1.5 transition-all cursor-pointer disabled:opacity-50 ${scenario.buttonColor}`}
              >
                {isCurrentLoading ? (
                  <>
                    <RefreshCw size={13} className="animate-spin" />
                    <span>Dispatching...</span>
                  </>
                ) : (
                  <>
                    <Play size={12} />
                    <span>Run {scenario.name}</span>
                  </>
                )}
              </button>
            </div>
          );
        })}
      </div>

      {/* Live Response Result Status Box */}
      {lastResult && (
        <div className={`p-3.5 rounded-xl border text-xs font-mono space-y-2 animate-in fade-in duration-200 ${
          lastResult.ok 
            ? 'bg-emerald-50/50 dark:bg-slate-950 border-emerald-300 dark:border-emerald-800/80 text-emerald-800 dark:text-emerald-300' 
            : 'bg-rose-50/50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-800 text-rose-800 dark:text-rose-300'
        }`}>
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center gap-2">
              {lastResult.ok ? (
                <CheckCircle2 size={16} className="text-emerald-600 dark:text-emerald-400" />
              ) : (
                <XCircle size={16} className="text-rose-600 dark:text-rose-400" />
              )}
              <span className="font-bold">
                HTTP {lastResult.status} {lastResult.statusText || (lastResult.ok ? 'OK' : 'Error')}
              </span>
              <span className="text-slate-500 dark:text-slate-400 text-[11px]">({lastResult.timeMs} ms)</span>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-[10px] px-2 py-0.5 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 text-cyan-700 dark:text-cyan-300 font-mono">
                {lastResult.isHighRiskWorkflowTriggered ? 'Triggered n8n IF Node (Score ≥ 70)' : 'Sub-Threshold (Score < 70)'}
              </span>
            </div>
          </div>

          <div className="text-[11px] text-slate-600 dark:text-slate-400 truncate">
            Workflow Response: <code className="text-slate-900 dark:text-white font-mono">{JSON.stringify(lastResult.data)}</code>
          </div>
        </div>
      )}
    </div>
  );
}
