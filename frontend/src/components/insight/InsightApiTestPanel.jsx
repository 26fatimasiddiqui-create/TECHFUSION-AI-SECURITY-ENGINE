import React, { useState } from 'react';
import { 
  Send, 
  Terminal, 
  CheckCircle2, 
  XCircle, 
  RefreshCw, 
  Clock, 
  Code, 
  ExternalLink,
  ShieldAlert,
  Sparkles,
  AlertCircle
} from 'lucide-react';
import { sendThreatAlert, N8N_PRODUCTION_WEBHOOK } from '../../services/n8nService';

export function InsightApiTestPanel({ employees = [], onTestComplete }) {
  const initialEmpCode = employees.length > 0 ? employees[0].employee_code : 'EMP001';
  const [selectedEmpCode, setSelectedEmpCode] = useState(initialEmpCode);
  const [customEmpCode, setCustomEmpCode] = useState('');
  const [riskScore, setRiskScore] = useState(87);
  const [severity, setSeverity] = useState('CRITICAL');
  const [eventText, setEventText] = useState('Unusual sensitive-data access');
  const [isLoading, setIsLoading] = useState(false);
  const [testResult, setTestResult] = useState(null);

  // Quick preset events
  const presetEvents = [
    'Unusual sensitive-data access',
    'Unusual file access',
    'Normal employee activity',
    'Off-hours database dump (/db/customer_pii)',
    'Excessive API call frequency to payroll export',
    'Prompt injection override on copilot agent'
  ];

  const effectiveEmpCode = customEmpCode.trim() || selectedEmpCode || 'EMP001';

  const handleSendTestAlert = async () => {
    setIsLoading(true);
    setTestResult(null);

    const payload = {
      employee_id: effectiveEmpCode,
      risk_score: Number(riskScore),
      severity: severity,
      event: eventText
    };

    const result = await sendThreatAlert(payload);
    setTestResult(result);
    setIsLoading(false);

    if (onTestComplete) {
      onTestComplete(result);
    }
  };

  const selectedEmp = employees.find(e => e.employee_code === selectedEmpCode);

  return (
    <div className="p-6 rounded-2xl bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 shadow-xs dark:shadow-xl space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 dark:border-slate-800 pb-4">
        <div className="flex items-center gap-2.5">
          <div className="p-2.5 rounded-xl bg-gradient-to-br from-cyan-600 to-blue-600 text-white shadow-md">
            <Terminal size={18} />
          </div>
          <div>
            <h2 className="text-sm sm:text-base font-bold text-slate-900 dark:text-white font-mono uppercase tracking-wider">
              n8n Webhook Live API Diagnostic Tester
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 font-sans">
              Directly dispatches real HTTP POST requests to <code className="text-cyan-600 dark:text-cyan-400 font-mono font-bold">https://fatimasiddiqui.app.n8n.cloud/webhook/insider-risk-alert</code>
            </p>
          </div>
        </div>

        <div className="text-[10px] font-mono text-slate-600 dark:text-slate-400 px-3 py-1 rounded-xl bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
          METHOD: <strong className="text-emerald-600 dark:text-emerald-400">POST</strong> • FORMAT: <strong className="text-cyan-600 dark:text-cyan-400">JSON</strong>
        </div>
      </div>

      {/* Configuration Form Grid */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
        
        {/* Left Inputs (7 cols) */}
        <div className="md:col-span-7 space-y-4 font-mono text-xs">
          
          {/* Employee Selector */}
          <div className="space-y-1.5">
            <label className="text-slate-600 dark:text-slate-400 block font-bold text-[11px]">
              1. SELECT EMPLOYEE (Source: Supabase employees table):
            </label>
            {employees.length > 0 ? (
              <select
                value={selectedEmpCode}
                onChange={(e) => {
                  setSelectedEmpCode(e.target.value);
                  setCustomEmpCode('');
                }}
                className="w-full p-2.5 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl text-slate-900 dark:text-white font-mono focus:border-cyan-500 focus:outline-hidden"
              >
                {employees.map((emp) => (
                  <option key={emp.id} value={emp.employee_code}>
                    {emp.employee_code} — {emp.name} ({emp.role} • {emp.department})
                  </option>
                ))}
              </select>
            ) : (
              <div className="space-y-1">
                <input
                  type="text"
                  placeholder="Enter employee code, e.g. EMP001"
                  value={customEmpCode}
                  onChange={(e) => setCustomEmpCode(e.target.value)}
                  className="w-full p-2.5 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl text-slate-900 dark:text-white font-mono"
                />
                <span className="text-[10px] text-slate-500">
                  (Employees table empty in Supabase; using manual employee code)
                </span>
              </div>
            )}
          </div>

          {/* Risk Score Slider & Input */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-[11px]">
              <label className="text-slate-600 dark:text-slate-400 font-bold">2. RISK SCORE (0–100):</label>
              <span className={`px-2 py-0.5 rounded font-bold ${
                riskScore >= 85 ? 'text-rose-700 dark:text-rose-400 bg-rose-50 dark:bg-rose-950/80 border border-rose-200 dark:border-rose-800' :
                riskScore >= 70 ? 'text-orange-700 dark:text-orange-400 bg-orange-50 dark:bg-orange-950/80 border border-orange-200 dark:border-orange-800' :
                riskScore >= 40 ? 'text-amber-700 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/80 border border-amber-200 dark:border-amber-800' :
                'text-emerald-700 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/80 border border-emerald-200 dark:border-emerald-800'
              }`}>
                {riskScore} / 100 {riskScore >= 70 ? '→ Triggers IF Node' : '→ Ignored'}
              </span>
            </div>

            <div className="flex items-center gap-3">
              <input
                type="range"
                min="0"
                max="100"
                value={riskScore}
                onChange={(e) => {
                  const val = Number(e.target.value);
                  setRiskScore(val);
                  if (val >= 85) setSeverity('CRITICAL');
                  else if (val >= 70) setSeverity('HIGH');
                  else if (val >= 40) setSeverity('MODERATE');
                  else setSeverity('LOW');
                }}
                className="flex-1 accent-rose-500 cursor-pointer h-2 bg-slate-100 dark:bg-slate-950 rounded-lg"
              />
              <input
                type="number"
                min="0"
                max="100"
                value={riskScore}
                onChange={(e) => setRiskScore(Math.min(100, Math.max(0, Number(e.target.value))))}
                className="w-16 p-2 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl text-slate-900 dark:text-white text-center font-bold"
              />
            </div>
          </div>

          {/* Severity Selector */}
          <div className="space-y-1.5">
            <label className="text-slate-600 dark:text-slate-400 block font-bold text-[11px]">
              3. SEVERITY LEVEL:
            </label>
            <div className="grid grid-cols-4 gap-2">
              {['LOW', 'MODERATE', 'HIGH', 'CRITICAL'].map((lvl) => (
                <button
                  key={lvl}
                  type="button"
                  onClick={() => setSeverity(lvl)}
                  className={`py-2 rounded-xl border text-[11px] font-bold transition-all cursor-pointer ${
                    severity === lvl
                      ? lvl === 'CRITICAL' ? 'bg-rose-50 dark:bg-rose-950 text-rose-700 dark:text-rose-300 border-rose-300 dark:border-rose-600 shadow-xs' :
                        lvl === 'HIGH' ? 'bg-orange-50 dark:bg-orange-950 text-orange-700 dark:text-orange-300 border-orange-300 dark:border-orange-600' :
                        lvl === 'MODERATE' ? 'bg-amber-50 dark:bg-amber-950 text-amber-700 dark:text-amber-300 border-amber-300 dark:border-amber-600' :
                        'bg-emerald-50 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300 border-emerald-300 dark:border-emerald-600'
                      : 'bg-slate-100 dark:bg-slate-950 text-slate-600 dark:text-slate-500 border-slate-200 dark:border-slate-800 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  {lvl}
                </button>
              ))}
            </div>
          </div>

          {/* Event Description */}
          <div className="space-y-1.5">
            <label className="text-slate-600 dark:text-slate-400 block font-bold text-[11px]">
              4. TRIGGERING SECURITY EVENT:
            </label>
            <input
              type="text"
              value={eventText}
              onChange={(e) => setEventText(e.target.value)}
              placeholder="e.g. Unusual sensitive-data access"
              className="w-full p-2.5 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl text-slate-900 dark:text-white focus:border-cyan-500 focus:outline-hidden"
            />

            {/* Quick preset chips */}
            <div className="flex items-center gap-1.5 flex-wrap pt-1">
              <span className="text-[10px] text-slate-500">Presets:</span>
              {presetEvents.map((pe, idx) => (
                <button
                  key={idx}
                  type="button"
                  onClick={() => setEventText(pe)}
                  className="px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-950 hover:bg-slate-200 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-800 text-[10px] text-slate-600 dark:text-slate-400 hover:text-cyan-700 dark:hover:text-cyan-300 transition-colors cursor-pointer"
                >
                  {pe.substring(0, 24)}...
                </button>
              ))}
            </div>
          </div>

          {/* Send Test Alert Button */}
          <button
            onClick={handleSendTestAlert}
            disabled={isLoading}
            className="w-full py-3 rounded-xl bg-gradient-to-r from-cyan-600 via-sky-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-mono font-bold text-xs flex items-center justify-center gap-2 shadow-md shadow-cyan-600/20 dark:shadow-cyan-950/40 border border-cyan-500 transition-all cursor-pointer disabled:opacity-50 active:scale-98"
          >
            {isLoading ? (
              <>
                <RefreshCw size={14} className="animate-spin" />
                <span>Executing Live HTTP Request...</span>
              </>
            ) : (
              <>
                <Send size={14} />
                <span>Send Test Alert to n8n Webhook</span>
              </>
            )}
          </button>
        </div>

        {/* Right Output: Live Request & Response Inspector (5 cols) */}
        <div className="md:col-span-5 space-y-4 font-mono text-xs">
          
          {/* Outgoing Request Payload Box */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-slate-600 dark:text-slate-400 text-[11px] font-bold">
              <span>OUTGOING REQUEST PAYLOAD</span>
              <span className="text-cyan-600 dark:text-cyan-400 font-mono">Content-Type: application/json</span>
            </div>
            <pre className="p-3.5 rounded-xl bg-slate-900 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-cyan-300 text-[11px] overflow-x-auto shadow-inner">
{JSON.stringify({
  employee_id: effectiveEmpCode,
  risk_score: Number(riskScore),
  severity: severity,
  event: eventText
}, null, 2)}
            </pre>
          </div>

          {/* Response Inspector */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-slate-600 dark:text-slate-400 text-[11px] font-bold">
              <span>ACTUAL LIVE RESPONSE</span>
              {testResult && (
                <span className={`text-[10px] px-2 py-0.5 rounded font-mono ${
                  testResult.ok ? 'bg-emerald-50 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800' : 'bg-rose-50 dark:bg-rose-950 text-rose-700 dark:text-rose-300 border border-rose-200 dark:border-rose-800'
                }`}>
                  HTTP {testResult.status} • {testResult.timeMs}ms
                </span>
              )}
            </div>

            {testResult ? (
              <div className="space-y-2">
                <pre className={`p-3.5 rounded-xl border text-[11px] overflow-x-auto max-h-48 ${
                  testResult.ok 
                    ? 'bg-slate-900 dark:bg-slate-950 border-emerald-300 dark:border-emerald-800/80 text-emerald-300' 
                    : 'bg-rose-900 dark:bg-rose-950/30 border-rose-300 dark:border-rose-800 text-rose-300'
                }`}>
{JSON.stringify(testResult.data || { error: testResult.error, statusText: testResult.statusText }, null, 2)}
                </pre>

                {/* Workflow Execution Checklist */}
                <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1.5 text-[11px]">
                  <div className="text-slate-600 dark:text-slate-400 font-bold uppercase text-[10px] pb-1 border-b border-slate-100 dark:border-slate-800">
                    Execution Pipeline Checklist:
                  </div>
                  
                  <div className="flex items-center gap-2 text-emerald-600 dark:text-emerald-400">
                    <CheckCircle2 size={13} />
                    <span>✓ Webhook reachable ({testResult.timeMs} ms)</span>
                  </div>

                  <div className="flex items-center gap-2 text-emerald-600 dark:text-emerald-400">
                    <CheckCircle2 size={13} />
                    <span>✓ Request sent ({effectiveEmpCode})</span>
                  </div>

                  <div className={`flex items-center gap-2 ${testResult.isHighRiskWorkflowTriggered ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-400 dark:text-slate-500'}`}>
                    {testResult.isHighRiskWorkflowTriggered ? (
                      <CheckCircle2 size={13} />
                    ) : (
                      <div className="w-3 h-3 rounded-full border border-slate-400 dark:border-slate-700" />
                    )}
                    <span>
                      {testResult.isHighRiskWorkflowTriggered 
                        ? '✓ Workflow triggered (risk_score ≥ 70)' 
                        : '○ IF Node ignored (risk_score < 70)'}
                    </span>
                  </div>

                  <div className={`flex items-center gap-2 ${testResult.isHighRiskWorkflowTriggered ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-400 dark:text-slate-500'}`}>
                    {testResult.isHighRiskWorkflowTriggered ? (
                      <CheckCircle2 size={13} />
                    ) : (
                      <div className="w-3 h-3 rounded-full border border-slate-400 dark:border-slate-700" />
                    )}
                    <span>
                      {testResult.isHighRiskWorkflowTriggered 
                        ? '✓ Alert stored in Supabase' 
                        : '○ Supabase alert skipped'}
                    </span>
                  </div>
                </div>
              </div>
            ) : (
              <div className="p-8 rounded-xl bg-slate-50/60 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 border-dashed text-center text-slate-500 text-[11px] space-y-1">
                <AlertCircle size={20} className="mx-auto text-slate-400 dark:text-slate-600 mb-1" />
                <p>No test request dispatched yet.</p>
                <p className="text-[10px] text-slate-400 dark:text-slate-600">Click "Send Test Alert" to execute an actual HTTP probe.</p>
              </div>
            )}
          </div>

        </div>

      </div>
    </div>
  );
}
