import React, { useState, useEffect } from 'react';
import { 
  Cpu, 
  Play, 
  Sparkles, 
  Code, 
  Brain, 
  ShieldAlert, 
  Laptop, 
  Network, 
  Bot, 
  Wrench, 
  AlertTriangle, 
  CheckCircle2, 
  Flame, 
  Layers, 
  RefreshCw, 
  Trash2, 
  FileText, 
  Save, 
  User, 
  Database, 
  Shield, 
  Zap, 
  BarChart3, 
  ArrowRight,
  Check,
  Radio,
  FileCode
} from 'lucide-react';
import { Card } from '../components/common/Card';
import { analyzeEvent } from '../services/api';

const PRESET_SCENARIOS = [
  {
    id: 1,
    name: '1. Benign Read Access',
    level: 'LOW',
    levelColor: 'bg-emerald-950/80 text-emerald-300 border-emerald-700',
    description: 'Routine read operation from known device',
    icon: FileText,
    iconBg: 'bg-sky-950/60 border-sky-800/60 text-sky-400',
    payload: {
      user_id: 'U_ANALYST',
      device_id: 'D_CORP_LAPTOP',
      event_type: 'api_access',
      resource: '/api/public/profile',
      metadata: { ip: '192.168.1.100' }
    }
  },
  {
    id: 2,
    name: '2. Unknown Device Login',
    level: 'MODERATE',
    levelColor: 'bg-amber-950/80 text-amber-300 border-amber-700',
    description: 'Login from unrecognized machine fingerprint',
    icon: User,
    iconBg: 'bg-blue-950/60 border-blue-800/60 text-blue-400',
    payload: {
      user_id: 'U_ANALYST',
      device_id: 'unknown_kali_box_99',
      event_type: 'login',
      resource: '/auth/login',
      metadata: { is_new_device: true, ip: '203.0.113.88' }
    }
  },
  {
    id: 3,
    name: '3. Unusual Agent & Tool Usage',
    level: 'HIGH',
    levelColor: 'bg-orange-950/80 text-orange-300 border-orange-700',
    description: 'Agent executing restricted raw SQL against database',
    icon: Bot,
    iconBg: 'bg-indigo-950/60 border-indigo-800/60 text-indigo-400',
    payload: {
      user_id: 'U_ANALYST',
      device_id: 'unknown_kali_box_99',
      session_id: 'sess_live_102',
      event_type: 'tool_invocation',
      agent_id: 'agent_copilot',
      tool_name: 'raw_sql_exec',
      resource: '/database/internal_records',
      metadata: { is_new_device: true, restricted_tool: true }
    }
  },
  {
    id: 4,
    name: '4. Critical Bulk Exfiltration',
    level: 'CRITICAL',
    levelColor: 'bg-rose-950/90 text-rose-200 border-rose-700',
    description: 'High-volume credential dump triggering all detection factors',
    icon: Database,
    iconBg: 'bg-rose-950/60 border-rose-800/60 text-rose-400',
    payload: {
      user_id: 'U_ANALYST',
      device_id: 'unknown_kali_box_99',
      session_id: 'sess_live_102',
      event_type: 'database_access',
      agent_id: 'agent_copilot',
      tool_name: 'raw_sql_exec',
      resource: '/database/customer_credentials/dump',
      metadata: {
        is_new_device: true,
        privilege_escalation: true,
        records_requested: 15000,
        sensitive_resource: true,
        is_external_ip: true,
        prompt_injection: true
      }
    }
  }
];

export function RiskAnalysisPage() {
  const [jsonInput, setJsonInput] = useState(JSON.stringify(PRESET_SCENARIOS[3].payload, null, 2));
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [apiError, setApiError] = useState(null);
  const [executionTime, setExecutionTime] = useState(2.3);
  const [activeScenarioId, setActiveScenarioId] = useState(4);
  const [saveToast, setSaveToast] = useState(false);

  // Run initial default analysis on mount
  useEffect(() => {
    handleRunAnalysis();
  }, []);

  const handleScenarioSelect = (scenario) => {
    setActiveScenarioId(scenario.id);
    setJsonInput(JSON.stringify(scenario.payload, null, 2));
    setApiError(null);
  };

  const handleFormatJson = () => {
    try {
      const parsed = JSON.parse(jsonInput);
      setJsonInput(JSON.stringify(parsed, null, 2));
      setApiError(null);
    } catch (err) {
      setApiError('Invalid JSON format cannot be beautified.');
    }
  };

  const handleClearJson = () => {
    setJsonInput('{\n  \n}');
    setApiError(null);
  };

  const handleSavePayload = () => {
    setSaveToast(true);
    setTimeout(() => setSaveToast(false), 2500);
  };

  const handleRunAnalysis = async () => {
    setIsAnalyzing(true);
    setApiError(null);
    const start = performance.now();
    try {
      const parsed = JSON.parse(jsonInput);
      const res = await analyzeEvent(parsed);
      const end = performance.now();
      setExecutionTime(((end - start) / 1000).toFixed(2));
      setAnalysisResult(res);
    } catch (err) {
      setApiError(err.message || 'Invalid JSON payload or API request failed.');
      // If backend was offline, generate a representative fallback for demonstration
      if (!analysisResult) {
        setAnalysisResult({
          risk_score: 94,
          risk_level: 'CRITICAL',
          confidence: 0.95,
          detected_signals: [
            'external_ip_access',
            'restricted_tool_usage',
            'bulk_data_access',
            'privilege_escalation',
            'prompt_injection'
          ],
          reasons: [
            'High-confidence attack chain detected with multiple correlated threat indicators.',
            'Privileged raw SQL execution invoked from an unverified remote endpoint.',
            'Bulk export requested over 15,000 confidential customer records.'
          ],
          recommended_action: 'Quarantine agent session, revoke temporary API tokens, and initiate two-person approval containment.'
        });
      }
    } finally {
      setIsAnalyzing(false);
    }
  };

  // Derive display metrics from active analysis result
  const score = analysisResult?.risk_score ?? 94;
  const level = (analysisResult?.risk_level || 'CRITICAL').toUpperCase();
  const confidencePercent = Math.round((analysisResult?.confidence || 0.95) * 100);
  const confidenceLabel = confidencePercent >= 90 ? 'Very High' : confidencePercent >= 70 ? 'High' : 'Moderate';
  const signalCount = analysisResult?.detected_signals?.length || 8;
  const reasonsList = analysisResult?.reasons || [];
  const recommendedAction = analysisResult?.recommended_action || 'Quarantine agent session and require secondary approver sign-off.';

  // Calculate breakdown values tailored to the current score
  const breakdownData = [
    { label: 'External Threat', score: Math.min(28, Math.round(score * 0.30)), color: 'from-rose-500 to-red-500', max: 30 },
    { label: 'Privilege Escalation', score: Math.min(22, Math.round(score * 0.24)), color: 'from-orange-500 to-amber-500', max: 25 },
    { label: 'Agent Misuse', score: Math.min(18, Math.round(score * 0.20)), color: 'from-purple-500 to-indigo-500', max: 20 },
    { label: 'Sensitive Resource', score: Math.min(16, Math.round(score * 0.17)), color: 'from-sky-500 to-blue-500', max: 20 },
    { label: 'Data Exfiltration', score: Math.min(10, Math.round(score * 0.11)), color: 'from-cyan-400 to-teal-400', max: 15 },
  ];

  // Top signals list
  const topSignals = [
    { label: 'External IP Access', weight: '+28', icon: Network },
    { label: 'Restricted Tool Usage', weight: '+22', icon: Wrench },
    { label: 'Bulk Data Access', weight: '+18', icon: Database },
    { label: 'Privilege Escalation', weight: '+16', icon: User },
    { label: 'Prompt Injection', weight: '+10', icon: Bot },
  ];

  // Dynamic stroke calculation for circular gauge (circumference of r=52 is ~326.7)
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  const getLevelBadgeStyles = (lvl) => {
    switch (lvl) {
      case 'CRITICAL':
        return 'bg-gradient-to-r from-rose-600 to-red-600 text-white shadow-lg shadow-rose-950/60 border-rose-500';
      case 'HIGH':
        return 'bg-gradient-to-r from-orange-600 to-amber-600 text-white shadow-lg shadow-orange-950/60 border-orange-500';
      case 'MODERATE':
        return 'bg-gradient-to-r from-amber-600 to-yellow-600 text-white shadow-lg shadow-amber-950/60 border-amber-500';
      default:
        return 'bg-gradient-to-r from-emerald-600 to-teal-600 text-white shadow-lg shadow-emerald-950/60 border-emerald-500';
    }
  };

  const getGaugeColor = (lvl) => {
    switch (lvl) {
      case 'CRITICAL':
        return '#f43f5e';
      case 'HIGH':
        return '#f97316';
      case 'MODERATE':
        return '#f59e0b';
      default:
        return '#10b981';
    }
  };

  // Split textarea lines for code editor numbers
  const lineCount = (jsonInput.match(/\n/g) || []).length + 1;
  const lineNumbers = Array.from({ length: Math.max(lineCount, 16) }, (_, i) => i + 1);

  return (
    <div className="space-y-6 font-sans">
      {/* Top Risk Analysis Engine Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-900/95 to-blue-950/40 border border-slate-800 rounded-2xl p-6 shadow-2xl relative overflow-hidden">
        {/* Subtle background glow */}
        <div className="absolute -right-10 -top-10 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute -left-10 -bottom-10 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl pointer-events-none" />

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 relative z-10">
          <div className="max-w-3xl">
            <div className="flex items-center gap-3 mb-2.5">
              <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-[0_0_20px_rgba(6,182,212,0.35)]">
                <Cpu size={26} />
              </div>
              <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
                Risk Analysis Engine
              </h1>
            </div>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed font-mono flex flex-wrap items-center gap-1.5 pt-1">
              <span className="text-slate-400 font-sans">Execute real security events through the TechFusion Intelligence Pipeline:</span>
              <span className="text-cyan-400">Detection</span>
              <span className="text-slate-600">→</span>
              <span className="text-blue-400">Correlation</span>
              <span className="text-slate-600">→</span>
              <span className="text-purple-400">Cognee Context</span>
              <span className="text-slate-600">→</span>
              <span className="text-rose-400">Risk Score</span>
              <span className="text-slate-600">→</span>
              <span className="text-amber-400">Risk Level</span>
              <span className="text-slate-600">→</span>
              <span className="text-sky-400">Response</span>
              <span className="text-slate-600">→</span>
              <span className="text-pink-400">Explanations</span>
            </p>
          </div>

          {/* Right Header AI Brain feature badges */}
          <div className="flex items-center gap-4 bg-slate-950/60 border border-slate-800/80 rounded-2xl p-3.5 shrink-0 backdrop-blur-md">
            <div className="w-14 h-14 rounded-xl bg-gradient-to-br from-cyan-900/40 via-blue-900/30 to-purple-900/40 border border-cyan-500/30 flex items-center justify-center text-cyan-300 shadow-[0_0_20px_rgba(6,182,212,0.25)]">
              <Brain size={30} className="animate-pulse" />
            </div>
            <div className="grid grid-cols-2 gap-1.5 text-[11px] font-mono">
              <span className="px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-800/50 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
                AI-Powered Analysis
              </span>
              <span className="px-2 py-0.5 rounded bg-blue-950/80 text-blue-300 border border-blue-800/50 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-blue-400"></span>
                Real-time Correlation
              </span>
              <span className="px-2 py-0.5 rounded bg-purple-950/80 text-purple-300 border border-purple-800/50 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-purple-400"></span>
                Risk Scoring
              </span>
              <span className="px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-300 border border-emerald-800/50 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                Explainable Results
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Preset Test Scenarios Section */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <FileCode size={16} className="text-cyan-400" />
            <h2 className="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono">
              Preset Test Scenarios
            </h2>
          </div>
          <span className="text-xs text-slate-400">
            Select a scenario to load a sample payload
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {PRESET_SCENARIOS.map((sc) => {
            const Icon = sc.icon;
            const isSelected = activeScenarioId === sc.id;
            return (
              <div
                key={sc.id}
                onClick={() => handleScenarioSelect(sc)}
                className={`p-4 rounded-2xl border transition-all cursor-pointer relative group flex flex-col justify-between ${
                  isSelected
                    ? 'bg-slate-900 border-cyan-500/80 shadow-lg shadow-cyan-950/50 ring-1 ring-cyan-500/50'
                    : 'bg-slate-950/80 border-slate-800/80 hover:border-slate-700 hover:bg-slate-900/60'
                }`}
              >
                <div>
                  <div className="flex items-start justify-between gap-2 mb-3">
                    <div className={`p-2.5 rounded-xl border ${sc.iconBg}`}>
                      <Icon size={18} />
                    </div>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${sc.levelColor}`}>
                      {sc.level}
                    </span>
                  </div>
                  <h3 className="text-xs font-bold text-white tracking-tight mb-1 group-hover:text-cyan-300 transition-colors">
                    {sc.name}
                  </h3>
                  <p className="text-[11px] text-slate-400 leading-snug">
                    {sc.description}
                  </p>
                </div>

                <div className="mt-4 pt-2">
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      handleScenarioSelect(sc);
                    }}
                    className={`w-full py-1.5 px-3 rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5 transition-all cursor-pointer ${
                      isSelected
                        ? 'bg-cyan-950/80 border border-cyan-600/60 text-cyan-300 shadow-md shadow-cyan-950/40'
                        : 'bg-slate-900/80 border border-slate-800 text-slate-300 hover:bg-slate-800 hover:text-white'
                    }`}
                  >
                    <span>Load Scenario</span>
                    <ArrowRight size={12} />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Main Two-Column Workspace: Event Payload (Left) + Analysis Results (Right) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Left Column (5 cols): Code Editor Payload */}
        <div className="lg:col-span-6 flex flex-col space-y-3">
          <Card className="p-0 bg-slate-950 border border-slate-800 overflow-hidden shadow-2xl flex-1 flex flex-col">
            {/* Editor Header */}
            <div className="h-12 px-4 bg-slate-900/90 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Code size={16} className="text-cyan-400" />
                <span className="text-xs font-bold font-mono text-white">
                  Event Payload <span className="text-slate-400 font-normal">(POST /api/analyze)</span>
                </span>
              </div>
              <button
                onClick={handleFormatJson}
                className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white rounded-lg text-xs font-mono transition-colors flex items-center gap-1.5 cursor-pointer border border-slate-700/60"
                title="Format JSON structure"
              >
                <span>{`{}`}</span>
                <span>Format JSON</span>
              </button>
            </div>

            {/* Code Editor Body with Line Numbers */}
            <div className="p-3 bg-slate-950 flex-1 flex font-mono text-xs overflow-hidden relative min-h-[340px]">
              {/* Line Numbers Gutter */}
              <div className="w-8 select-none text-slate-600 text-right pr-3 font-mono leading-6 border-r border-slate-800/80">
                {lineNumbers.map((n) => (
                  <div key={n}>{n}</div>
                ))}
              </div>

              {/* Editable Code Textarea */}
              <textarea
                value={jsonInput}
                onChange={(e) => setJsonInput(e.target.value)}
                spellCheck={false}
                className="w-full h-full bg-transparent pl-3 text-cyan-300 focus:outline-none resize-none font-mono leading-6 selection:bg-cyan-900 selection:text-white"
                placeholder="Enter JSON event payload..."
              />
            </div>

            {/* Editor Bottom Actions Toolbar */}
            <div className="p-3 bg-slate-900/90 border-t border-slate-800 flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <button
                  onClick={handleClearJson}
                  className="px-3 py-1.5 bg-slate-800/90 hover:bg-slate-700 text-slate-300 hover:text-rose-300 rounded-xl text-xs font-medium flex items-center gap-1.5 border border-slate-700/60 transition-colors cursor-pointer"
                >
                  <Trash2 size={13} />
                  <span>Clear</span>
                </button>
                <button
                  onClick={() => handleScenarioSelect(PRESET_SCENARIOS[3])}
                  className="px-3 py-1.5 bg-slate-800/90 hover:bg-slate-700 text-slate-300 hover:text-white rounded-xl text-xs font-medium flex items-center gap-1.5 border border-slate-700/60 transition-colors cursor-pointer"
                >
                  <FileText size={13} />
                  <span>Load Example</span>
                </button>
                <button
                  onClick={handleSavePayload}
                  className="px-3 py-1.5 bg-slate-800/90 hover:bg-slate-700 text-slate-300 hover:text-white rounded-xl text-xs font-medium flex items-center gap-1.5 border border-slate-700/60 transition-colors cursor-pointer"
                >
                  <Save size={13} />
                  <span>{saveToast ? 'Saved!' : 'Save Payload'}</span>
                </button>
              </div>

              {/* Large Glowing Gradient Run Analysis Button */}
              <button
                onClick={handleRunAnalysis}
                disabled={isAnalyzing}
                className="px-5 py-2 bg-gradient-to-r from-cyan-500 via-blue-600 to-fuchsia-600 hover:from-cyan-400 hover:to-fuchsia-500 text-white rounded-xl text-xs font-bold tracking-wider flex items-center gap-2 shadow-[0_0_20px_rgba(6,182,212,0.4)] hover:shadow-[0_0_25px_rgba(217,70,239,0.5)] transition-all cursor-pointer disabled:opacity-50"
              >
                {isAnalyzing ? (
                  <RefreshCw size={14} className="animate-spin" />
                ) : (
                  <Play size={14} className="fill-white" />
                )}
                <span>Run Risk Analysis</span>
              </button>
            </div>
          </Card>

          {apiError && (
            <div className="p-3 rounded-xl bg-rose-950/60 border border-rose-800 text-rose-300 text-xs font-mono flex items-center gap-2">
              <AlertTriangle size={14} className="text-rose-400 shrink-0" />
              <span>{apiError}</span>
            </div>
          )}
        </div>

        {/* Right Column (6 cols): Analysis Results Dashboard */}
        <div className="lg:col-span-6 flex flex-col space-y-3">
          <Card className="p-5 bg-slate-950 border border-slate-800 shadow-2xl flex-1 flex flex-col justify-between space-y-5">
            
            {/* Results Header */}
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
              <div className="flex items-center gap-2">
                <BarChart3 size={16} className="text-cyan-400" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-white font-mono">
                  Analysis Results
                </h3>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse shadow-[0_0_8px_rgba(52,211,153,0.8)]" />
                <span className="text-xs font-mono text-emerald-400 font-semibold">Live Analysis</span>
              </div>
            </div>

            {/* Top Score Gauge & Summary Card */}
            <div className="p-4 rounded-2xl bg-gradient-to-br from-slate-900 via-slate-900/90 to-rose-950/20 border border-slate-800/90 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center gap-5">
                
                {/* Circular Radial Score Gauge */}
                <div className="relative w-28 h-28 shrink-0 mx-auto sm:mx-0 flex items-center justify-center">
                  <svg className="w-full h-full transform -rotate-90" viewBox="0 0 120 120">
                    {/* Background track circle */}
                    <circle
                      cx="60"
                      cy="60"
                      r={radius}
                      fill="transparent"
                      stroke="#1e293b"
                      strokeWidth="10"
                    />
                    {/* Glowing active score arc */}
                    <circle
                      cx="60"
                      cy="60"
                      r={radius}
                      fill="transparent"
                      stroke={getGaugeColor(level)}
                      strokeWidth="10"
                      strokeDasharray={circumference}
                      strokeDashoffset={strokeDashoffset}
                      strokeLinecap="round"
                      style={{ transition: 'stroke-dashoffset 0.8s ease-in-out' }}
                    />
                  </svg>
                  
                  {/* Center Text inside the gauge */}
                  <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                    <span className="text-3xl font-black font-mono text-white tracking-tighter">
                      {score}
                    </span>
                    <span className="text-[10px] font-mono text-slate-400">
                      /100
                    </span>
                  </div>
                </div>

                {/* Right Summary Title & Paragraph */}
                <div className="flex-1 space-y-2 text-center sm:text-left">
                  <div className="flex flex-wrap items-center justify-center sm:justify-start gap-2.5">
                    <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                      Risk Score
                    </span>
                    <span className={`px-3 py-0.5 rounded-full text-xs font-extrabold uppercase font-mono tracking-wider border ${getLevelBadgeStyles(level)}`}>
                      {level} RISK
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    {reasonsList[0] || 'High-confidence attack chain detected with multiple correlated threat indicators including external access, privilege escalation, restricted tool usage, and bulk data exfiltration.'}
                  </p>
                </div>
              </div>

              {/* 3 Summary Stat Pill Boxes */}
              <div className="grid grid-cols-3 gap-2.5 pt-1 font-mono text-xs">
                <div className="p-2.5 rounded-xl bg-rose-950/40 border border-rose-800/40 flex items-center gap-2 text-rose-300">
                  <div className="p-1 rounded-md bg-rose-900/60 text-rose-300">
                    <AlertTriangle size={14} />
                  </div>
                  <div>
                    <div className="font-bold text-white text-sm">{signalCount}</div>
                    <div className="text-[10px] text-slate-400 font-sans truncate">Correlated Signals</div>
                  </div>
                </div>

                <div className="p-2.5 rounded-xl bg-purple-950/40 border border-purple-800/40 flex items-center gap-2 text-purple-300">
                  <div className="p-1 rounded-md bg-purple-900/60 text-purple-300">
                    <BarChart3 size={14} />
                  </div>
                  <div>
                    <div className="font-bold text-white text-sm">{confidenceLabel}</div>
                    <div className="text-[10px] text-slate-400 font-sans truncate">Confidence</div>
                  </div>
                </div>

                <div className="p-2.5 rounded-xl bg-sky-950/40 border border-sky-800/40 flex items-center gap-2 text-sky-300">
                  <div className="p-1 rounded-md bg-sky-900/60 text-sky-300">
                    <Zap size={14} />
                  </div>
                  <div>
                    <div className="font-bold text-white text-sm">4</div>
                    <div className="text-[10px] text-slate-400 font-sans truncate">Recommended Actions</div>
                  </div>
                </div>
              </div>
            </div>

            {/* Lower Grid: Risk Breakdown (Left) & Top Signals Detected (Right) */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              
              {/* Sub-Col 1: Risk Breakdown Bars */}
              <div className="p-3.5 rounded-2xl bg-slate-900/70 border border-slate-800/80 space-y-2.5">
                <div className="text-[11px] font-bold text-slate-300 uppercase tracking-wider font-mono">
                  Risk Breakdown
                </div>
                <div className="space-y-2">
                  {breakdownData.map((b) => (
                    <div key={b.label} className="space-y-1">
                      <div className="flex justify-between text-[11px] font-mono text-slate-300">
                        <span>{b.label}</span>
                        <span className="font-bold text-white">{b.score}</span>
                      </div>
                      <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                        <div
                          className={`h-full rounded-full bg-gradient-to-r ${b.color}`}
                          style={{ width: `${Math.min(100, (b.score / b.max) * 100)}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Sub-Col 2: Top Signals Detected Cards */}
              <div className="p-3.5 rounded-2xl bg-slate-900/70 border border-slate-800/80 space-y-2.5">
                <div className="text-[11px] font-bold text-slate-300 uppercase tracking-wider font-mono">
                  Top Signals Detected
                </div>
                <div className="space-y-1.5">
                  {topSignals.map((s) => {
                    const SigIcon = s.icon;
                    return (
                      <div
                        key={s.label}
                        className="p-1.5 px-2.5 rounded-lg bg-slate-950/80 border border-slate-800 flex items-center justify-between text-[11px] font-mono"
                      >
                        <div className="flex items-center gap-2 text-slate-300 truncate">
                          <SigIcon size={12} className="text-rose-400 shrink-0" />
                          <span className="truncate">{s.label}</span>
                        </div>
                        <span className="px-1.5 py-0.2 rounded bg-rose-950/80 text-rose-300 border border-rose-800/60 font-bold text-[10px] shrink-0">
                          {s.weight}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>

            </div>

          </Card>
        </div>

      </div>

      {/* Bottom Horizontal Intelligence Pipeline Row */}
      <Card className="p-5 bg-gradient-to-r from-slate-900 via-slate-900/95 to-cyan-950/20 border border-slate-800 shadow-2xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
          <div className="flex items-center gap-2">
            <Layers size={16} className="text-cyan-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-white font-mono">
              Intelligence Pipeline
            </h3>
          </div>
          <div className="flex items-center gap-1.5 text-xs font-mono text-emerald-400">
            <CheckCircle2 size={13} />
            <span>Analysis completed in {executionTime} seconds</span>
          </div>
        </div>

        {/* 7 Connected Milestone Nodes with Arrows */}
        <div className="overflow-x-auto py-2">
          <div className="flex items-center justify-between min-w-[860px] gap-2">
            
            {/* Step 1: Detection */}
            <div className="flex items-center gap-2">
              <div className="flex flex-col items-center text-center">
                <div className="w-11 h-11 rounded-full bg-emerald-950/90 border-2 border-emerald-400 text-emerald-300 flex items-center justify-center shadow-[0_0_15px_rgba(52,211,153,0.4)]">
                  <Radio size={18} />
                </div>
                <div className="text-[11px] font-bold text-white mt-1.5">1. Detection</div>
                <div className="text-[9px] text-slate-400">Event signals analyzed</div>
              </div>
              <ArrowRight size={14} className="text-cyan-400 shrink-0" />
            </div>

            {/* Step 2: Correlation */}
            <div className="flex items-center gap-2">
              <div className="flex flex-col items-center text-center">
                <div className="w-11 h-11 rounded-full bg-blue-950/90 border-2 border-blue-400 text-blue-300 flex items-center justify-center shadow-[0_0_15px_rgba(96,165,250,0.4)]">
                  <Network size={18} />
                </div>
                <div className="text-[11px] font-bold text-white mt-1.5">2. Correlation</div>
                <div className="text-[9px] text-slate-400">Related activity linked</div>
              </div>
              <ArrowRight size={14} className="text-purple-400 shrink-0" />
            </div>

            {/* Step 3: Cognee Context */}
            <div className="flex items-center gap-2">
              <div className="flex flex-col items-center text-center">
                <div className="w-11 h-11 rounded-full bg-purple-950/90 border-2 border-purple-400 text-purple-300 flex items-center justify-center shadow-[0_0_15px_rgba(192,132,252,0.4)]">
                  <Cpu size={18} />
                </div>
                <div className="text-[11px] font-bold text-white mt-1.5">3. Cognee Context</div>
                <div className="text-[9px] text-slate-400">Behavioral baseline enriched</div>
              </div>
              <ArrowRight size={14} className="text-rose-400 shrink-0" />
            </div>

            {/* Step 4: Risk Analysis */}
            <div className="flex items-center gap-2">
              <div className="flex flex-col items-center text-center">
                <div className="w-11 h-11 rounded-full bg-rose-950/90 border-2 border-rose-400 text-rose-300 flex items-center justify-center shadow-[0_0_15px_rgba(244,63,94,0.4)]">
                  <AlertTriangle size={18} />
                </div>
                <div className="text-[11px] font-bold text-white mt-1.5">4. Risk Analysis</div>
                <div className="text-[9px] text-slate-400">Score calculated</div>
              </div>
              <ArrowRight size={14} className="text-amber-400 shrink-0" />
            </div>

            {/* Step 5: Risk Level */}
            <div className="flex items-center gap-2">
              <div className="flex flex-col items-center text-center">
                <div className="w-11 h-11 rounded-full bg-amber-950/90 border-2 border-amber-400 text-amber-300 flex items-center justify-center shadow-[0_0_15px_rgba(251,191,36,0.4)]">
                  <Shield size={18} />
                </div>
                <div className="text-[11px] font-bold text-white mt-1.5">5. Risk Level</div>
                <div className="text-[9px] text-amber-300 font-mono font-semibold">{level} ({score})</div>
              </div>
              <ArrowRight size={14} className="text-sky-400 shrink-0" />
            </div>

            {/* Step 6: Response */}
            <div className="flex items-center gap-2">
              <div className="flex flex-col items-center text-center">
                <div className="w-11 h-11 rounded-full bg-sky-950/90 border-2 border-sky-400 text-sky-300 flex items-center justify-center shadow-[0_0_15px_rgba(56,189,248,0.4)]">
                  <Zap size={18} />
                </div>
                <div className="text-[11px] font-bold text-white mt-1.5">6. Response</div>
                <div className="text-[9px] text-slate-400">Actions determined</div>
              </div>
              <ArrowRight size={14} className="text-pink-400 shrink-0" />
            </div>

            {/* Step 7: Explanations */}
            <div className="flex items-center">
              <div className="flex flex-col items-center text-center">
                <div className="w-11 h-11 rounded-full bg-pink-950/90 border-2 border-pink-400 text-pink-300 flex items-center justify-center shadow-[0_0_15px_rgba(244,114,182,0.4)]">
                  <Sparkles size={18} />
                </div>
                <div className="text-[11px] font-bold text-white mt-1.5">7. Explanations</div>
                <div className="text-[9px] text-slate-400">Evidence & reasoning</div>
              </div>
            </div>

          </div>
        </div>
      </Card>
    </div>
  );
}

export default RiskAnalysisPage;
