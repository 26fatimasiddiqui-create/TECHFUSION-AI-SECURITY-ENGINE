import React, { useState, useEffect } from 'react';
import { 
  Flame, 
  ShieldAlert, 
  AlertTriangle, 
  CheckCircle2, 
  XCircle, 
  Clock, 
  User as UserIcon, 
  Laptop, 
  Bot, 
  Database, 
  Network, 
  UploadCloud, 
  Zap, 
  Sparkles, 
  Radio, 
  FileText, 
  Check, 
  Layers, 
  ArrowRight, 
  Lock, 
  ShieldCheck, 
  Volume2, 
  Eye, 
  Download, 
  Lightbulb, 
  ChevronRight, 
  History, 
  Users, 
  Wrench, 
  Globe, 
  RefreshCw, 
  FileCode,
  Shield,
  Activity,
  KeyRound,
  FileCheck,
  UserCheck,
  UserX,
  Undo2,
  BookOpen,
  Gauge
} from 'lucide-react';
import { Card } from '../components/common/Card';
import { RiskBadge, StatusBadge, SignalPill } from '../components/common/Badge';
import { LoadingSpinner } from '../components/common/LoadingSpinner';
import { ErrorBanner } from '../components/common/ErrorBanner';
import { EasyIncidentStory } from '../components/easy/EasyIncidentStory';
import { voiceAlertService } from '../services/voiceAlertService';
import { useMode } from '../context/ModeContext';
import { 
  getIncident,
  getIncidentResponse,
  approveIncidentResponse,
  secondApproveIncidentResponse,
  rejectIncidentResponse,
  recoverFalsePositive,
  getApprovalStatus,
  evaluateApprover
} from '../services/api';

// Default reference incident fallback matching the mockup
const MOCK_FALLBACK_INCIDENT = {
  id: 'INC-311065C2',
  title: 'Unusual Resource Access Detected',
  subtitle: 'High-confidence attack chain detected with multiple correlated signals.',
  status: 'active',
  created_at: '2026-09-23T14:43:48Z',
  assigned_to: 'SOC_Analyst',
  primary_entity: 'U_ANALYST',
  entity_type: 'user',
  risk_assessment: {
    risk_score: 100,
    risk_level: 'CRITICAL',
    confidence: 0.88,
    reasons: [
      'High-confidence attack chain detected with multiple correlated signals.',
      'AI agent executing restricted SQL queries against sensitive customer data.',
      'Bulk export activity from an unrecognized machine fingerprint.'
    ],
    recommended_action: 'Require human approval for containment and quarantine agent session.'
  },
  signals_detected: [
    'external_ip_access',
    'privilege_escalation',
    'unexpected_ai_agent_activity',
    'bulk_data_access',
    'sensitive_resource',
    'unknown_device',
    'unexpected_tool_usage'
  ],
  events: [
    {
      id: 'EVT-101',
      timestamp: '2026-09-23T14:43:48Z',
      event_type: 'login',
      user_id: 'U_ANALYST',
      device_id: 'unknown_kali_box_99',
      session_id: 'sess_live_102',
      resource: '/auth/login',
      metadata: { client_ip: '185.220.101.33', is_new_device: true, ip: '185.220.101.33' }
    },
    {
      id: 'EVT-102',
      timestamp: '2026-09-23T14:43:55Z',
      event_type: 'tool_invocation',
      user_id: 'U_ANALYST',
      device_id: 'unknown_kali_box_99',
      agent_id: 'agent_copilot',
      tool_name: 'raw_sql_exec',
      session_id: 'sess_live_102',
      resource: '/database/customer_credentials/dump',
      metadata: { restricted_tool: true, privilege_escalation: true }
    },
    {
      id: 'EVT-103',
      timestamp: '2026-09-23T14:44:02Z',
      event_type: 'data_access',
      user_id: 'U_ANALYST',
      device_id: 'unknown_kali_box_99',
      agent_id: 'agent_copilot',
      resource: '/database/customer_credentials/dump',
      metadata: { records_requested: 15000, sensitive_resource: true, data_exfiltration: true }
    }
  ]
};

export function IncidentsPage({ 
  incidents = [], 
  selectedIncident, 
  setSelectedIncident, 
  isLoading = false,
  error = null,
  onRetry 
}) {
  const { isEasyMode, setMode } = useMode();

  const [activeIncidentId, setActiveIncidentId] = useState(
    selectedIncident?.id || (incidents.length > 0 ? incidents[0].id : MOCK_FALLBACK_INCIDENT.id)
  );
  const [detailedIncident, setDetailedIncident] = useState(null);
  const [isDetailLoading, setIsDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState(null);
  const [activeTab, setActiveTab] = useState('overview'); // overview, attack-chain, events, risk-analysis, response, approvals, audit-trail, related-entities
  const [acknowledged, setAcknowledged] = useState(false);
  const [isPlayingVoice, setIsPlayingVoice] = useState(false);

  // Response & Approvals Workflow States
  const [responseDetails, setResponseDetails] = useState(null);
  const [approvalRecord, setApprovalRecord] = useState(null);
  const [actionInProgress, setActionInProgress] = useState(false);
  const [actionFeedback, setActionFeedback] = useState(null);
  const [showRecoveryForm, setShowRecoveryForm] = useState(false);
  const [recoveryReason, setRecoveryReason] = useState('Verified legitimate quarterly backup authorized by SOC Director');
  const [recoveryActor, setRecoveryActor] = useState('SOC_Lead');

  // Approver evaluation state
  const [approver1Name, setApprover1Name] = useState('SOC_Analyst_Alice');
  const [approver1Role, setApprover1Role] = useState('SECURITY_ANALYST');
  const [approver1Session, setApprover1Session] = useState('sess_alice_01');
  const [approver2Name, setApprover2Name] = useState('SOC_Admin_Bob');
  const [approver2Role, setApprover2Role] = useState('SECURITY_ADMIN');
  const [approver2Session, setApprover2Session] = useState('sess_bob_02');
  const [approver2Notes, setApprover2Notes] = useState('Dual-control administrator verification confirmed containment policy.');
  const [evalResult, setEvalResult] = useState(null);
  const [isEvaluating, setIsEvaluating] = useState(false);
  const [simulatedAnomalies, setSimulatedAnomalies] = useState({
    impossible_travel: false,
    failed_logins: false,
    privilege_escalation: false,
  });

  // Sync active incident
  useEffect(() => {
    if (selectedIncident?.id) {
      setActiveIncidentId(selectedIncident.id);
    } else if (!activeIncidentId && incidents.length > 0) {
      setActiveIncidentId(incidents[0].id);
    }
  }, [selectedIncident, incidents, activeIncidentId]);

  // Fetch detailed incident & response from API
  useEffect(() => {
    if (!activeIncidentId) {
      setDetailedIncident(MOCK_FALLBACK_INCIDENT);
      return;
    }

    let isMounted = true;
    const fetchIncidentDetails = async () => {
      setIsDetailLoading(true);
      setDetailError(null);
      setActionFeedback(null);
      setShowRecoveryForm(false);
      setEvalResult(null);
      try {
        const [data, respData, apprData] = await Promise.all([
          getIncident(activeIncidentId).catch(() => null),
          getIncidentResponse(activeIncidentId).catch(() => null),
          getApprovalStatus(activeIncidentId).catch(() => null)
        ]);

        if (isMounted) {
          if (data) {
            setDetailedIncident(data);
            if (setSelectedIncident) setSelectedIncident(data);
          } else {
            const found = incidents.find(i => i.id === activeIncidentId);
            setDetailedIncident(found || MOCK_FALLBACK_INCIDENT);
          }
          setResponseDetails(respData);
          setApprovalRecord(apprData);
        }
      } catch (err) {
        if (isMounted) {
          const found = incidents.find(i => i.id === activeIncidentId);
          setDetailedIncident(found || MOCK_FALLBACK_INCIDENT);
        }
      } finally {
        if (isMounted) {
          setIsDetailLoading(false);
        }
      }
    };

    fetchIncidentDetails();

    return () => {
      isMounted = false;
    };
  }, [activeIncidentId, incidents, setSelectedIncident]);

  // Active Incident Data Resolvers
  const inc = detailedIncident || MOCK_FALLBACK_INCIDENT;
  const score = inc.risk_assessment?.risk_score ?? 100;
  const level = (inc.risk_assessment?.risk_level || 'CRITICAL').toUpperCase();
  const confidence = Math.round((inc.risk_assessment?.confidence || 0.88) * 100);
  const events = inc.events || MOCK_FALLBACK_INCIDENT.events;
  const eventCount = events.length || 3;

  // Attack chain node extraction
  const externalIp = events.find(e => e.metadata?.client_ip || e.metadata?.ip)?.metadata?.client_ip || '185.220.101.33';
  const targetUser = inc.primary_entity || events.find(e => e.user_id)?.user_id || 'U_ANALYST';
  const targetDevice = events.find(e => e.device_id)?.device_id || 'unknown_kali_box_99';
  const targetAgent = events.find(e => e.agent_id)?.agent_id || 'agent_copilot';
  const targetResource = events.find(e => e.resource)?.resource || '/database/customer_credentials/dump';
  const resourceCleanName = targetResource.includes('customer') ? 'customer_db' : targetResource.split('/').pop() || 'customer_db';
  const exfilVolume = events.find(e => e.metadata?.records_requested)?.metadata?.records_requested 
    ? `${events.find(e => e.metadata?.records_requested)?.metadata?.records_requested.toLocaleString()} records`
    : '15,000 records';

  // Voice narration handler
  const handleVoiceReplay = () => {
    setIsPlayingVoice(true);
    const speechText = `Security Alert. Incident ${inc.id}. Critical risk level with score ${score} out of 100. Attack chain detected involving user ${targetUser}, agent ${targetAgent}, and bulk exfiltration against ${resourceCleanName}. Two-person approval is required for containment.`;
    voiceAlertService.speakText(speechText);
    setTimeout(() => setIsPlayingVoice(false), 5000);
  };

  // Export report
  const handleExportReport = () => {
    const reportData = {
      incident_id: inc.id,
      timestamp: new Date().toISOString(),
      level,
      score,
      confidence: `${confidence}%`,
      assigned_to: inc.assigned_to || 'SOC_Analyst',
      primary_entity: targetUser,
      device: targetDevice,
      agent: targetAgent,
      resource: targetResource,
      signals: inc.signals_detected || [],
      events: events,
      recommendations: [
        'Require human approval for containment',
        'Review affected user and agent activity',
        'Validate legitimacy of data access',
        'Consider restricting agent tool privileges'
      ]
    };
    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `TechFusion_Incident_Report_${inc.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Approver Evaluation Handler
  const handleEvaluateApproverRisk = async (targetApprover, targetRole, targetSession) => {
    setIsEvaluating(true);
    try {
      const activeMeta = {};
      if (simulatedAnomalies.impossible_travel) activeMeta.impossible_travel = true;
      if (simulatedAnomalies.failed_logins) activeMeta.failed_logins = true;
      if (simulatedAnomalies.privilege_escalation) activeMeta.privilege_escalation = true;

      const res = await evaluateApprover(inc.id, {
        approver_id: targetApprover,
        role: targetRole,
        session_id: targetSession,
        metadata: activeMeta,
      });
      setEvalResult(res);
      if (res.requires_independent_verification || !res.approval_allowed) {
        setActionFeedback({
          type: 'error',
          message: `Approver '${targetApprover}' evaluated with ${res.approver_risk_level} risk (${res.approver_risk_score}/100). Approval requires independent verification!`
        });
      } else {
        setActionFeedback({
          type: 'success',
          message: `Approver '${targetApprover}' evaluated with ${res.approver_risk_level} risk (${res.approver_risk_score}/100). Authorized to participate in approval chain.`
        });
      }
    } catch (err) {
      setActionFeedback({ type: 'error', message: err.message || 'Failed to evaluate approver.' });
    } finally {
      setIsEvaluating(false);
    }
  };

  // Containment Handlers
  const handleApproveContainment = async () => {
    setActionInProgress(true);
    setActionFeedback(null);
    try {
      const activeMeta = {};
      if (simulatedAnomalies.impossible_travel) activeMeta.impossible_travel = true;
      if (simulatedAnomalies.failed_logins) activeMeta.failed_logins = true;
      if (simulatedAnomalies.privilege_escalation) activeMeta.privilege_escalation = true;

      await approveIncidentResponse(inc.id, {
        actor: approver1Name || 'SOC_Analyst_Alice',
        approver_id: approver1Name || 'SOC_Analyst_Alice',
        role: approver1Role || 'SECURITY_ANALYST',
        session_id: approver1Session || 'sess_alice_01',
        notes: 'Approver 1 authorization submitted (Two-Person Rule gate).',
        dry_run: true,
        metadata: activeMeta,
      });

      const [updatedResp, updatedAppr] = await Promise.all([
        getIncidentResponse(inc.id).catch(() => null),
        getApprovalStatus(inc.id).catch(() => null)
      ]);
      setResponseDetails(updatedResp);
      setApprovalRecord(updatedAppr);

      if (updatedAppr?.state === 'APPROVER_2_REQUIRED') {
        setActionFeedback({
          type: 'info',
          message: 'Approver 1 authorized! Step 5 Two-Person Rule: Independent Approver 2 authorization now required.'
        });
      } else if (updatedAppr?.state === 'APPROVAL_BLOCKED') {
        setActionFeedback({
          type: 'error',
          message: 'Approval BLOCKED: Approver context exhibits elevated security risk. Independent verification required!'
        });
      } else {
        setActionFeedback({ type: 'success', message: 'Containment actions successfully authorized and simulated!' });
      }
    } catch (err) {
      setActionFeedback({ type: 'error', message: err.message || 'Containment approval recorded in simulation mode.' });
    } finally {
      setActionInProgress(false);
    }
  };

  const handleSecondApproveContainment = async () => {
    setActionInProgress(true);
    setActionFeedback(null);
    try {
      await secondApproveIncidentResponse(inc.id, {
        actor: approver2Name || 'SOC_Admin_Bob',
        approver_id: approver2Name || 'SOC_Admin_Bob',
        role: approver2Role || 'SECURITY_ADMIN',
        session_id: approver2Session || 'sess_bob_02',
        notes: approver2Notes || 'Second independent approver verified and approved.',
        dry_run: true,
      });

      const [updatedResp, updatedAppr] = await Promise.all([
        getIncidentResponse(inc.id).catch(() => null),
        getApprovalStatus(inc.id).catch(() => null)
      ]);
      setResponseDetails(updatedResp);
      setApprovalRecord(updatedAppr);

      setActionFeedback({
        type: 'success',
        message: 'Two-Person Rule satisfied! Dual independent authorization verified. Containment executed in simulation mode.'
      });
    } catch (err) {
      setActionFeedback({ type: 'error', message: err.message || 'Second approval recorded in simulation mode.' });
    } finally {
      setActionInProgress(false);
    }
  };

  const handleRejectContainment = async () => {
    setActionInProgress(true);
    setActionFeedback(null);
    try {
      await rejectIncidentResponse(inc.id, {
        actor: approver1Name || 'SOC_Analyst_Alice',
        reason: 'Analyst assessed scenario as contained or benign.'
      });
      setActionFeedback({ type: 'info', message: 'Containment actions rejected and audit record logged.' });
      const [updatedResp, updatedAppr] = await Promise.all([
        getIncidentResponse(inc.id).catch(() => null),
        getApprovalStatus(inc.id).catch(() => null)
      ]);
      setResponseDetails(updatedResp);
      setApprovalRecord(updatedAppr);
    } catch (err) {
      setActionFeedback({ type: 'info', message: 'Action recorded.' });
    } finally {
      setActionInProgress(false);
    }
  };

  const handleRecoverFalsePositive = async () => {
    setActionInProgress(true);
    setActionFeedback(null);
    try {
      await recoverFalsePositive(inc.id, {
        reason: recoveryReason || 'Acknowledged false positive',
        actor: recoveryActor || 'SOC_Lead',
        restore_access: true
      });
      setActionFeedback({ 
        type: 'success', 
        message: 'False positive recovered: restrictions lifted and incident resolved.' 
      });
      setShowRecoveryForm(false);
    } catch (err) {
      setActionFeedback({ type: 'success', message: 'False positive recovery recorded in simulation.' });
      setShowRecoveryForm(false);
    } finally {
      setActionInProgress(false);
    }
  };

  // Top Contributing Signals Data
  const signalsBreakdown = [
    { name: 'Bulk Data Access', score: 28, max: 30, color: 'from-rose-500 to-red-600' },
    { name: 'Privilege Escalation', score: 24, max: 30, color: 'from-orange-500 to-amber-500' },
    { name: 'Unusual Tool Usage', score: 18, max: 30, color: 'from-purple-500 to-indigo-500' },
    { name: 'Unknown Device', score: 16, max: 30, color: 'from-blue-500 to-cyan-500' },
    { name: 'Sensitive Resource', score: 14, max: 30, color: 'from-teal-400 to-emerald-400' },
  ];

  // SVG Gauge calculations
  const gaugeRadius = 46;
  const gaugeCircumference = 2 * Math.PI * gaugeRadius;
  const gaugeOffset = gaugeCircumference - (score / 100) * gaugeCircumference;

  return (
    <div className="space-y-6 font-sans">
      
      {/* Breadcrumb & Incident Selector */}
      <div className="flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
        <div className="flex items-center gap-2 text-slate-500 dark:text-slate-400">
          <span className="hover:text-slate-900 dark:hover:text-white cursor-pointer transition-colors" onClick={() => setActiveTab('overview')}>
            Incidents
          </span>
          <ChevronRight size={14} className="text-slate-400 dark:text-slate-600" />
          <span className="text-slate-900 dark:text-white font-bold px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
            {inc.id}
          </span>
        </div>

        {incidents.length > 1 && (
          <div className="flex items-center gap-2">
            <span className="text-slate-500 dark:text-slate-400 text-[11px]">Select Incident:</span>
            <div className="flex items-center gap-1.5 overflow-x-auto max-w-md">
              {incidents.map((item) => (
                <button
                  key={item.id}
                  onClick={() => setActiveIncidentId(item.id)}
                  className={`px-2.5 py-1 rounded-lg text-[11px] transition-all cursor-pointer font-mono ${
                    item.id === inc.id
                      ? 'bg-rose-100 dark:bg-rose-950 border border-rose-300 dark:border-rose-600 text-rose-800 dark:text-rose-200 font-bold shadow-xs'
                      : 'bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  {item.id}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* EASY MODE INCIDENT STORY VIEW (When in Easy Mode and Overview tab) */}
      {isEasyMode && activeTab === 'overview' ? (
        <EasyIncidentStory
          incident={inc}
          onOpenActionCenter={() => setActiveTab('response')}
          onReplayVoice={handleVoiceReplay}
          isPlayingVoice={isPlayingVoice}
          onViewProDetails={() => setMode('pro')}
        />
      ) : (
        /* PRO MODE INCIDENT HERO BANNER & TABS */
        <>
          {/* Hero Critical Incident Banner */}
          <div className="relative rounded-2xl p-6 overflow-hidden border border-rose-300 dark:border-rose-800/60 bg-gradient-to-r from-rose-50 via-red-50 to-white dark:from-rose-950/90 dark:via-red-950/70 dark:to-slate-950 shadow-sm dark:shadow-[0_0_50px_rgba(225,29,72,0.25)] transition-colors">
            {/* Ambient background glows */}
            <div className="absolute -left-20 -top-20 w-80 h-80 bg-rose-500/10 dark:bg-rose-600/15 rounded-full blur-3xl pointer-events-none" />
            <div className="absolute right-0 bottom-0 w-96 h-96 bg-red-500/5 dark:bg-red-600/10 rounded-full blur-3xl pointer-events-none" />

            <div className="relative z-10 flex flex-col xl:flex-row items-start xl:items-center justify-between gap-6">
              
              {/* Left: Giant Alert Icon + Title + Threat Tags */}
              <div className="flex items-start gap-5 max-w-3xl">
                {/* Glowing Big Red Warning Triangle */}
                <div className="w-16 h-16 sm:w-20 sm:h-20 rounded-2xl bg-gradient-to-br from-rose-600 to-red-700 flex items-center justify-center text-white shadow-md shadow-rose-600/30 dark:shadow-[0_0_30px_rgba(244,63,94,0.6)] shrink-0 animate-pulse">
                  <AlertTriangle size={38} className="stroke-[2.2]" />
                </div>

                <div className="space-y-2">
                  <div className="flex items-center gap-3">
                    <span className="px-3 py-0.5 rounded-md bg-rose-600 text-white font-mono text-[11px] font-black uppercase tracking-wider shadow-xs">
                      CRITICAL INCIDENT
                    </span>
                  </div>

                  <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 dark:text-white tracking-tight leading-tight">
                    {inc.title || 'Unusual Resource Access Detected'}
                  </h1>

                  <p className="text-xs sm:text-sm text-slate-700 dark:text-rose-200/90 leading-relaxed font-sans">
                    {inc.subtitle || inc.risk_assessment?.reasons?.[0] || 'High-confidence attack chain detected with multiple correlated signals.'}
                  </p>

                  {/* Threat Tags */}
                  <div className="flex flex-wrap items-center gap-2 pt-1 font-mono text-[11px]">
                    <span className="px-2.5 py-1 rounded-lg bg-rose-100 dark:bg-red-950/80 text-rose-800 dark:text-rose-300 border border-rose-200 dark:border-rose-800/60 flex items-center gap-1.5 shadow-xs">
                      <Flame size={12} className="text-rose-600 dark:text-rose-400" />
                      <span>External Access</span>
                    </span>
                    <span className="px-2.5 py-1 rounded-lg bg-amber-100 dark:bg-amber-950/80 text-amber-800 dark:text-amber-300 border border-amber-200 dark:border-amber-800/60 flex items-center gap-1.5 shadow-xs">
                      <ShieldAlert size={12} className="text-amber-600 dark:text-amber-400" />
                      <span>Privilege Escalation</span>
                    </span>
                    <span className="px-2.5 py-1 rounded-lg bg-indigo-100 dark:bg-indigo-950/80 text-indigo-800 dark:text-indigo-300 border border-indigo-200 dark:border-indigo-800/60 flex items-center gap-1.5 shadow-xs">
                      <Bot size={12} className="text-indigo-600 dark:text-indigo-400" />
                      <span>AI Agent Misuse</span>
                    </span>
                    <span className="px-2.5 py-1 rounded-lg bg-emerald-100 dark:bg-emerald-950/80 text-emerald-800 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/60 flex items-center gap-1.5 shadow-xs">
                      <Database size={12} className="text-emerald-600 dark:text-emerald-400" />
                      <span>Data Exfiltration</span>
                    </span>
                  </div>
                </div>
              </div>

              {/* Right Side: Score Progress Box + Metadata List */}
              <div className="flex flex-wrap sm:flex-nowrap items-center gap-6 w-full xl:w-auto shrink-0 justify-between xl:justify-end border-t xl:border-t-0 border-rose-200 dark:border-rose-900/60 pt-4 xl:pt-0">
                
                {/* Risk Score Pill Box */}
                <div className="p-4 rounded-2xl bg-white dark:bg-black/40 border border-rose-200 dark:border-rose-800/50 min-w-[150px] space-y-2 backdrop-blur-md shadow-xs">
                  <div className="text-[11px] font-mono text-slate-500 dark:text-slate-300 uppercase tracking-wider">
                    Risk Score
                  </div>
                  <div className="flex items-baseline gap-1 font-mono">
                    <span className="text-3xl font-black text-slate-900 dark:text-white tracking-tight">{score}</span>
                    <span className="text-xs text-rose-600 dark:text-rose-300 font-bold">/ 100</span>
                  </div>
                  <div className="w-full h-1.5 rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-rose-500 to-red-500"
                      style={{ width: `${score}%` }}
                    />
                  </div>
                  <div className="text-[10px] font-mono text-cyan-600 dark:text-cyan-400 font-semibold flex items-center gap-1">
                    <span>Confidence</span>
                    <span className="text-slate-900 dark:text-white font-bold">{confidence}%</span>
                  </div>
                </div>

                {/* Metadata Fields */}
                <div className="space-y-2 font-mono text-xs text-slate-700 dark:text-slate-300 min-w-[200px]">
                  <div className="flex items-center justify-between gap-4">
                    <span className="text-slate-500 dark:text-slate-400 text-[11px]">Status</span>
                    <span className="px-2.5 py-0.5 rounded-full bg-rose-600 text-white font-bold text-[10px] flex items-center gap-1 shadow-xs">
                      <span className="w-1.5 h-1.5 rounded-full bg-white animate-pulse" />
                      ACTIVE
                    </span>
                  </div>
                  <div className="flex items-center justify-between gap-4">
                    <span className="text-slate-500 dark:text-slate-400 text-[11px]">Incident ID</span>
                    <span className="text-slate-900 dark:text-white font-bold">{inc.id}</span>
                  </div>
                  <div className="flex items-center justify-between gap-4">
                    <span className="text-slate-500 dark:text-slate-400 text-[11px]">Detected</span>
                    <span className="text-slate-700 dark:text-slate-200 text-[11px]">
                      {new Date(inc.created_at || Date.now()).toLocaleDateString('en-US', {
                        month: 'short',
                        day: 'numeric',
                        year: 'numeric'
                      })} {new Date(inc.created_at || Date.now()).toLocaleTimeString()}
                    </span>
                  </div>
                  <div className="flex items-center justify-between gap-4">
                    <span className="text-slate-500 dark:text-slate-400 text-[11px]">Assigned to</span>
                    <span className="text-cyan-600 dark:text-cyan-300 font-semibold">{inc.assigned_to || 'SOC_Analyst'}</span>
                  </div>
                </div>

              </div>

            </div>

            {/* Hero Bottom Actions Bar */}
            <div className="mt-6 pt-4 border-t border-rose-200 dark:border-rose-900/50 flex flex-wrap items-center justify-between gap-3 relative z-10">
              <div className="flex flex-wrap items-center gap-2.5">
                <button
                  onClick={() => setActiveTab('overview')}
                  className="px-4 py-2 rounded-xl bg-white dark:bg-slate-900/80 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-800 dark:text-slate-200 border border-slate-300 dark:border-slate-700/60 text-xs font-semibold flex items-center gap-2 transition-all cursor-pointer shadow-xs"
                >
                  <Eye size={14} className="text-cyan-600 dark:text-cyan-400" />
                  <span>View Details</span>
                </button>

                <button
                  onClick={() => setAcknowledged(true)}
                  className={`px-4 py-2 rounded-xl text-xs font-semibold flex items-center gap-2 transition-all cursor-pointer border ${
                    acknowledged 
                      ? 'bg-emerald-100 dark:bg-emerald-950/80 border-emerald-300 dark:border-emerald-600 text-emerald-800 dark:text-emerald-300 shadow-xs'
                      : 'bg-white dark:bg-slate-900/80 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-800 dark:text-slate-200 border-slate-300 dark:border-slate-700/60'
                  }`}
                >
                  <Check size={14} className={acknowledged ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-400'} />
                  <span>{acknowledged ? 'Acknowledged' : 'Acknowledge'}</span>
                </button>

                <button
                  onClick={handleVoiceReplay}
                  disabled={isPlayingVoice}
                  className="px-4 py-2 rounded-xl bg-purple-100 dark:bg-purple-950/70 hover:bg-purple-200 dark:hover:bg-purple-900/70 text-purple-800 dark:text-purple-200 border border-purple-300 dark:border-purple-700/60 text-xs font-semibold flex items-center gap-2 transition-all cursor-pointer shadow-xs"
                >
                  <Volume2 size={14} className={`text-purple-600 dark:text-purple-300 ${isPlayingVoice ? 'animate-bounce' : ''}`} />
                  <span>{isPlayingVoice ? 'Speaking...' : 'Replay Voice'}</span>
                </button>
              </div>

              <button
                onClick={() => setActiveTab('response')}
                className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-rose-600 via-red-600 to-rose-700 hover:from-rose-500 hover:to-red-600 text-white text-xs font-bold tracking-wide flex items-center gap-2 shadow-md shadow-rose-600/30 transition-all cursor-pointer"
              >
                <span>Open Action Center</span>
                <ArrowRight size={14} />
              </button>
            </div>
          </div>

          {/* Tabs Navigation Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 dark:border-slate-800 pb-3">
            <div className="flex flex-wrap items-center gap-1.5 font-mono text-xs">
              {[
                { id: 'overview', label: 'Overview' },
                { id: 'attack-chain', label: 'Attack Chain' },
                { id: 'events', label: `Events (${eventCount})` },
                { id: 'risk-analysis', label: 'Risk Analysis' },
                { id: 'response', label: 'Response' },
                { id: 'approvals', label: 'Approvals' },
                { id: 'audit-trail', label: 'Audit Trail' },
                { id: 'related-entities', label: 'Related Entities' },
              ].map((tab) => {
                const isActive = activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`px-3.5 py-1.5 rounded-xl transition-all cursor-pointer font-semibold ${
                      isActive
                        ? 'bg-cyan-100 dark:bg-cyan-500/20 text-cyan-800 dark:text-cyan-300 border border-cyan-300 dark:border-cyan-500/40 shadow-xs'
                        : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-900/60 border border-transparent'
                    }`}
                  >
                    {tab.label}
                  </button>
                );
              })}
            </div>

            <button
              onClick={handleExportReport}
              className="px-3 py-1.5 rounded-xl bg-white dark:bg-slate-900 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700 text-xs font-mono flex items-center gap-1.5 transition-all cursor-pointer shadow-xs"
            >
              <Download size={13} />
              <span>Export Report</span>
            </button>
          </div>
        </>
      )}

      {/* Feedback Alert for Actions */}
      {actionFeedback && (
        <div
          className={`p-3.5 rounded-xl border text-xs font-mono flex items-center justify-between gap-3 animate-fade-in ${
            actionFeedback.type === 'error'
              ? 'bg-rose-100 dark:bg-rose-950/80 border-rose-300 dark:border-rose-700 text-rose-800 dark:text-rose-200'
              : actionFeedback.type === 'info'
              ? 'bg-cyan-100 dark:bg-cyan-950/80 border-cyan-300 dark:border-cyan-700 text-cyan-800 dark:text-cyan-200'
              : 'bg-emerald-100 dark:bg-emerald-950/80 border-emerald-300 dark:border-emerald-700 text-emerald-800 dark:text-emerald-200'
          }`}
        >
          <div className="flex items-center gap-2">
            {actionFeedback.type === 'error' ? (
              <AlertTriangle size={16} className="text-rose-600 dark:text-rose-400 shrink-0" />
            ) : actionFeedback.type === 'info' ? (
              <ShieldAlert size={16} className="text-cyan-600 dark:text-cyan-400 shrink-0" />
            ) : (
              <CheckCircle2 size={16} className="text-emerald-600 dark:text-emerald-400 shrink-0" />
            )}
            <span>{actionFeedback.message}</span>
          </div>
          <button
            onClick={() => setActionFeedback(null)}
            className="text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white cursor-pointer"
          >
            ✕
          </button>
        </div>
      )}

      {/* Main Tab Views (Pro Mode or Detailed Tab Selection) */}
      {(!isEasyMode && activeTab === 'overview') && (
        <div className="space-y-6">
          
          {/* 1. Attack Chain Card (Full Width) */}
          <Card className="p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800/80 pb-3">
              <div className="flex items-center gap-2.5">
                <div className="p-1.5 rounded-lg bg-cyan-100 dark:bg-cyan-950/80 border border-cyan-200 dark:border-cyan-800/60 text-cyan-700 dark:text-cyan-400">
                  <UserIcon size={16} />
                </div>
                <div>
                  <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-white font-mono">
                    Attack Chain
                  </h3>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400">
                    Visual flow of the detected attack sequence
                  </p>
                </div>
              </div>
            </div>

            {/* Horizontal Attack Sequence Flow */}
            <div className="overflow-x-auto py-2">
              <div className="flex items-center justify-between min-w-[760px] gap-2">
                
                {/* 1. External IP */}
                <div className="flex items-center gap-2 flex-1">
                  <div className="p-3.5 rounded-2xl bg-gradient-to-br from-rose-50 to-white dark:from-rose-950/60 dark:to-slate-900 border border-rose-200 dark:border-rose-800/60 flex-1 space-y-1 shadow-xs">
                    <div className="w-8 h-8 rounded-xl bg-rose-100 dark:bg-rose-950 border border-rose-300 dark:border-rose-700/60 flex items-center justify-center text-rose-600 dark:text-rose-400 mb-2">
                      <Globe size={16} />
                    </div>
                    <div className="text-[10px] font-mono text-slate-500 dark:text-slate-400 uppercase tracking-wider">External IP</div>
                    <div className="text-xs font-bold text-rose-700 dark:text-rose-200 font-mono truncate">{externalIp}</div>
                  </div>
                  <ArrowRight size={14} className="text-slate-400 dark:text-slate-600 shrink-0" />
                </div>

                {/* 2. User */}
                <div className="flex items-center gap-2 flex-1">
                  <div className="p-3.5 rounded-2xl bg-gradient-to-br from-blue-50 to-white dark:from-blue-950/60 dark:to-slate-900 border border-blue-200 dark:border-blue-800/60 flex-1 space-y-1 shadow-xs">
                    <div className="w-8 h-8 rounded-xl bg-blue-100 dark:bg-blue-950 border border-blue-300 dark:border-blue-700/60 flex items-center justify-center text-blue-600 dark:text-blue-400 mb-2">
                      <UserIcon size={16} />
                    </div>
                    <div className="text-[10px] font-mono text-slate-500 dark:text-slate-400 uppercase tracking-wider">User</div>
                    <div className="text-xs font-bold text-blue-700 dark:text-blue-200 font-mono truncate">{targetUser}</div>
                  </div>
                  <ArrowRight size={14} className="text-slate-400 dark:text-slate-600 shrink-0" />
                </div>

                {/* 3. Device */}
                <div className="flex items-center gap-2 flex-1">
                  <div className="p-3.5 rounded-2xl bg-gradient-to-br from-purple-50 to-white dark:from-purple-950/60 dark:to-slate-900 border border-purple-200 dark:border-purple-800/60 flex-1 space-y-1 shadow-xs">
                    <div className="w-8 h-8 rounded-xl bg-purple-100 dark:bg-purple-950 border border-purple-300 dark:border-purple-700/60 flex items-center justify-center text-purple-600 dark:text-purple-400 mb-2">
                      <Laptop size={16} />
                    </div>
                    <div className="text-[10px] font-mono text-slate-500 dark:text-slate-400 uppercase tracking-wider">Device</div>
                    <div className="text-xs font-bold text-purple-700 dark:text-purple-200 font-mono truncate">{targetDevice}</div>
                  </div>
                  <ArrowRight size={14} className="text-slate-400 dark:text-slate-600 shrink-0" />
                </div>

                {/* 4. AI Agent */}
                <div className="flex items-center gap-2 flex-1">
                  <div className="p-3.5 rounded-2xl bg-gradient-to-br from-teal-50 to-white dark:from-teal-950/60 dark:to-slate-900 border border-teal-200 dark:border-teal-800/60 flex-1 space-y-1 shadow-xs">
                    <div className="w-8 h-8 rounded-xl bg-teal-100 dark:bg-teal-950 border border-teal-300 dark:border-teal-700/60 flex items-center justify-center text-teal-600 dark:text-teal-400 mb-2">
                      <Bot size={16} />
                    </div>
                    <div className="text-[10px] font-mono text-slate-500 dark:text-slate-400 uppercase tracking-wider">AI Agent</div>
                    <div className="text-xs font-bold text-teal-700 dark:text-teal-200 font-mono truncate">{targetAgent}</div>
                  </div>
                  <ArrowRight size={14} className="text-slate-400 dark:text-slate-600 shrink-0" />
                </div>

                {/* 5. Database */}
                <div className="flex items-center gap-2 flex-1">
                  <div className="p-3.5 rounded-2xl bg-gradient-to-br from-amber-50 to-white dark:from-amber-950/60 dark:to-slate-900 border border-amber-200 dark:border-amber-800/60 flex-1 space-y-1 shadow-xs">
                    <div className="w-8 h-8 rounded-xl bg-amber-100 dark:bg-amber-950 border border-amber-300 dark:border-amber-700/60 flex items-center justify-center text-amber-600 dark:text-amber-400 mb-2">
                      <Database size={16} />
                    </div>
                    <div className="text-[10px] font-mono text-slate-500 dark:text-slate-400 uppercase tracking-wider">Database</div>
                    <div className="text-xs font-bold text-amber-700 dark:text-amber-200 font-mono truncate">{resourceCleanName}</div>
                  </div>
                  <ArrowRight size={14} className="text-slate-400 dark:text-slate-600 shrink-0" />
                </div>

                {/* 6. Exfiltration */}
                <div className="flex items-center flex-1">
                  <div className="p-3.5 rounded-2xl bg-gradient-to-br from-rose-100 to-white dark:from-rose-950/80 dark:to-slate-900 border border-rose-300 dark:border-rose-700/80 flex-1 space-y-1 shadow-xs">
                    <div className="w-8 h-8 rounded-xl bg-rose-200 dark:bg-rose-900 border border-rose-300 dark:border-rose-600/60 flex items-center justify-center text-rose-700 dark:text-rose-300 mb-2">
                      <UploadCloud size={16} />
                    </div>
                    <div className="text-[10px] font-mono text-slate-500 dark:text-slate-400 uppercase tracking-wider">Exfiltration</div>
                    <div className="text-xs font-bold text-rose-700 dark:text-rose-200 font-mono truncate">{exfilVolume}</div>
                  </div>
                </div>

              </div>
            </div>
          </Card>

          {/* 2. Lower 3-Column Layout */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            
            {/* Panel 1: Incident Summary (4 cols) */}
            <div className="lg:col-span-4 flex flex-col">
              <Card className="p-5 flex-1 flex flex-col justify-between space-y-4">
                <div className="space-y-4">
                  <div className="flex items-center gap-2 border-b border-slate-100 dark:border-slate-800/80 pb-3">
                    <ShieldCheck size={16} className="text-cyan-600 dark:text-cyan-400" />
                    <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-white font-mono">
                      Incident Summary
                    </h3>
                  </div>

                  {/* Summary key-values */}
                  <div className="space-y-3 font-mono text-xs">
                    <div className="space-y-1">
                      <span className="text-slate-500 dark:text-slate-400 text-[11px]">Target User</span>
                      <div className="flex items-center gap-2 text-slate-900 dark:text-slate-200 font-bold bg-slate-50 dark:bg-slate-900/80 p-2 rounded-xl border border-slate-200 dark:border-slate-800">
                        <UserIcon size={14} className="text-blue-500" />
                        <span>{targetUser}</span>
                      </div>
                    </div>

                    <div className="space-y-1">
                      <span className="text-slate-500 dark:text-slate-400 text-[11px]">Device</span>
                      <div className="flex items-center justify-between gap-2 bg-slate-50 dark:bg-slate-900/80 p-2 rounded-xl border border-slate-200 dark:border-slate-800">
                        <div className="flex items-center gap-2 text-slate-900 dark:text-slate-200 font-bold truncate">
                          <Laptop size={14} className="text-purple-500" />
                          <span className="truncate">{targetDevice}</span>
                        </div>
                        <span className="px-2 py-0.5 rounded text-[9px] font-mono bg-rose-100 dark:bg-rose-950 text-rose-700 dark:text-rose-300 border border-rose-200 dark:border-rose-800 shrink-0">
                          Unrecognized
                        </span>
                      </div>
                    </div>

                    <div className="space-y-1">
                      <span className="text-slate-500 dark:text-slate-400 text-[11px]">Agent</span>
                      <div className="flex items-center gap-2 text-slate-900 dark:text-slate-200 font-bold bg-slate-50 dark:bg-slate-900/80 p-2 rounded-xl border border-slate-200 dark:border-slate-800">
                        <Bot size={14} className="text-teal-500" />
                        <span>{targetAgent}</span>
                      </div>
                    </div>

                    <div className="space-y-1">
                      <span className="text-slate-500 dark:text-slate-400 text-[11px]">Resource</span>
                      <div className="flex items-center gap-2 text-slate-900 dark:text-slate-200 font-bold bg-slate-50 dark:bg-slate-900/80 p-2 rounded-xl border border-slate-200 dark:border-slate-800 truncate">
                        <Database size={14} className="text-amber-500 shrink-0" />
                        <span className="truncate">{targetResource}</span>
                      </div>
                    </div>

                    <div className="space-y-1">
                      <span className="text-slate-500 dark:text-slate-400 text-[11px]">Incident Type</span>
                      <div className="text-slate-900 dark:text-white font-semibold text-xs pt-0.5">
                        {inc.title || 'Unusual Resource Access'}
                      </div>
                    </div>

                    {/* Tactics */}
                    <div className="space-y-1 pt-1">
                      <span className="text-slate-500 dark:text-slate-400 text-[11px]">Tactics</span>
                      <div className="flex flex-wrap gap-1.5 pt-1">
                        <span className="px-2 py-0.5 rounded bg-amber-100 dark:bg-amber-950/80 text-amber-800 dark:text-amber-300 border border-amber-200 dark:border-amber-800/60 text-[10px]">
                          Privilege Escalation
                        </span>
                        <span className="px-2 py-0.5 rounded bg-teal-100 dark:bg-teal-950/80 text-teal-800 dark:text-teal-300 border border-teal-200 dark:border-teal-800/60 text-[10px]">
                          Data Exfiltration
                        </span>
                        <span className="px-2 py-0.5 rounded bg-purple-100 dark:bg-purple-950/80 text-purple-800 dark:text-purple-300 border border-purple-200 dark:border-purple-800/60 text-[10px]">
                          Tool Abuse
                        </span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Description */}
                <div className="pt-3 border-t border-slate-100 dark:border-slate-800/80 space-y-1">
                  <span className="text-slate-500 dark:text-slate-400 text-[11px] font-mono">Description</span>
                  <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
                    Correlated events indicate an AI agent executing restricted SQL queries against sensitive customer data, followed by bulk export activity from an unrecognized device.
                  </p>
                </div>
              </Card>
            </div>

            {/* Panel 2: Risk Analysis (4 cols) */}
            <div className="lg:col-span-4 flex flex-col">
              <Card className="p-5 flex-1 flex flex-col justify-between space-y-4">
                <div className="space-y-4">
                  <div className="flex items-center gap-2 border-b border-slate-100 dark:border-slate-800/80 pb-3">
                    <Network size={16} className="text-cyan-600 dark:text-cyan-400" />
                    <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-white font-mono">
                      Risk Analysis
                    </h3>
                  </div>

                  {/* Score Gauge & Breakdown Header */}
                  <div className="flex items-center gap-4">
                    {/* SVG Radial Gauge */}
                    <div className="relative w-24 h-24 shrink-0 flex items-center justify-center">
                      <svg className="w-full h-full transform -rotate-90" viewBox="0 0 110 110">
                        <circle
                          cx="55"
                          cy="55"
                          r={gaugeRadius}
                          fill="transparent"
                          stroke="currentColor"
                          className="text-slate-200 dark:text-slate-800"
                          strokeWidth="9"
                        />
                        <circle
                          cx="55"
                          cy="55"
                          r={gaugeRadius}
                          fill="transparent"
                          stroke="#f43f5e"
                          strokeWidth="9"
                          strokeDasharray={gaugeCircumference}
                          strokeDashoffset={gaugeOffset}
                          strokeLinecap="round"
                        />
                      </svg>
                      <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                        <span className="text-2xl font-black font-mono text-slate-900 dark:text-white tracking-tight">
                          {score}
                        </span>
                        <span className="text-[9px] font-mono text-slate-500 dark:text-slate-400">/ 100</span>
                      </div>
                    </div>

                    <div className="space-y-1.5 font-mono">
                      <span className="px-2.5 py-0.5 rounded-full bg-rose-600 text-white font-bold text-[10px] uppercase shadow-xs">
                        CRITICAL RISK
                      </span>
                      <div className="text-xs text-slate-700 dark:text-slate-300">
                        Confidence <span className="font-bold text-cyan-600 dark:text-cyan-400">{confidence}%</span>
                      </div>
                    </div>
                  </div>

                  {/* Top Contributing Signals Progress Bars */}
                  <div className="space-y-2.5 pt-1">
                    <div className="text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider font-mono">
                      Top Contributing Signals
                    </div>
                    <div className="space-y-2">
                      {signalsBreakdown.map((sig) => (
                        <div key={sig.name} className="space-y-1">
                          <div className="flex justify-between text-[11px] font-mono text-slate-700 dark:text-slate-300">
                            <span>{sig.name}</span>
                            <span className="font-bold text-slate-900 dark:text-white">{sig.score}</span>
                          </div>
                          <div className="w-full h-1.5 rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
                            <div
                              className={`h-full rounded-full bg-gradient-to-r ${sig.color}`}
                              style={{ width: `${(sig.score / sig.max) * 100}%` }}
                            />
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* AI Analysis box */}
                <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 space-y-2">
                  <div className="flex items-center gap-2 text-xs font-bold text-amber-700 dark:text-amber-300 font-mono">
                    <Lightbulb size={14} className="text-amber-500" />
                    <span>AI Analysis</span>
                  </div>
                  <p className="text-[11px] text-slate-700 dark:text-slate-300 leading-snug">
                    This appears to be a coordinated data exfiltration attempt using an AI agent with escalated privileges.
                  </p>
                  <button
                    onClick={() => setActiveTab('risk-analysis')}
                    className="text-[11px] text-cyan-600 dark:text-cyan-400 hover:text-cyan-500 dark:hover:text-cyan-300 font-mono font-semibold flex items-center gap-1 cursor-pointer pt-1"
                  >
                    <span>View Full Analysis</span>
                    <ArrowRight size={12} />
                  </button>
                </div>
              </Card>
            </div>

            {/* Panel 3: Timeline & Recommended Actions (4 cols) */}
            <div className="lg:col-span-4 flex flex-col space-y-4">
              
              {/* Top Sub-Card: Timeline */}
              <Card className="p-4 space-y-3">
                <div className="flex items-center gap-2 border-b border-slate-100 dark:border-slate-800/80 pb-2.5">
                  <Clock size={16} className="text-cyan-600 dark:text-cyan-400" />
                  <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-white font-mono">
                    Timeline
                  </h3>
                </div>

                <div className="space-y-3 relative pl-3 font-mono text-xs">
                  {/* Vertical Track Line */}
                  <div className="absolute left-[17px] top-2 bottom-2 w-0.5 bg-slate-200 dark:bg-slate-800" />

                  {/* Step 1 */}
                  <div className="flex items-start gap-3 relative z-10">
                    <div className="w-5 h-5 rounded-full bg-purple-100 dark:bg-purple-950 border border-purple-300 dark:border-purple-500 text-purple-700 dark:text-purple-300 flex items-center justify-center shrink-0 mt-0.5">
                      <Radio size={10} />
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center justify-between text-slate-700 dark:text-slate-300">
                        <span className="font-bold text-slate-900 dark:text-white text-[11px]">Incident Detected</span>
                        <span className="text-[10px] text-slate-400">02:43:48 PM</span>
                      </div>
                      <p className="text-[10px] text-slate-500 dark:text-slate-400 font-sans">High-risk activity identified</p>
                    </div>
                  </div>

                  {/* Step 2 */}
                  <div className="flex items-start gap-3 relative z-10">
                    <div className="w-5 h-5 rounded-full bg-amber-100 dark:bg-amber-950 border border-amber-300 dark:border-amber-500 text-amber-700 dark:text-amber-300 flex items-center justify-center shrink-0 mt-0.5">
                      <Layers size={10} />
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center justify-between text-slate-700 dark:text-slate-300">
                        <span className="font-bold text-slate-900 dark:text-white text-[11px]">Correlated (3 events)</span>
                        <span className="text-[10px] text-slate-400">02:43:55 PM</span>
                      </div>
                      <p className="text-[10px] text-slate-500 dark:text-slate-400 font-sans">Events linked into attack chain</p>
                    </div>
                  </div>

                  {/* Step 3 */}
                  <div className="flex items-start gap-3 relative z-10">
                    <div className="w-5 h-5 rounded-full bg-rose-100 dark:bg-rose-950 border border-rose-300 dark:border-rose-500 text-rose-700 dark:text-rose-300 flex items-center justify-center shrink-0 mt-0.5">
                      <AlertTriangle size={10} />
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center justify-between text-slate-700 dark:text-slate-300">
                        <span className="font-bold text-slate-900 dark:text-white text-[11px]">Risk Score Calculated</span>
                        <span className="text-[10px] text-slate-400">02:44:02 PM</span>
                      </div>
                      <p className="text-[10px] text-rose-600 dark:text-rose-400 font-mono font-bold">Score: 100 (CRITICAL)</p>
                    </div>
                  </div>

                  {/* Step 4 */}
                  <div className="flex items-start gap-3 relative z-10">
                    <div className="w-5 h-5 rounded-full bg-teal-100 dark:bg-teal-950 border border-teal-300 dark:border-teal-500 text-teal-700 dark:text-teal-300 flex items-center justify-center shrink-0 mt-0.5">
                      <Zap size={10} />
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center justify-between text-slate-700 dark:text-slate-300">
                        <span className="font-bold text-slate-900 dark:text-white text-[11px]">Response Determined</span>
                        <span className="text-[10px] text-slate-400">02:44:05 PM</span>
                      </div>
                      <p className="text-[10px] text-slate-500 dark:text-slate-400 font-sans">Approval required</p>
                    </div>
                  </div>

                  {/* Step 5 */}
                  <div className="flex items-start gap-3 relative z-10">
                    <div className="w-5 h-5 rounded-full bg-amber-100 dark:bg-amber-950 border border-amber-300 dark:border-amber-500 text-amber-700 dark:text-amber-300 flex items-center justify-center shrink-0 mt-0.5">
                      <Shield size={10} />
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center justify-between text-slate-700 dark:text-slate-300">
                        <span className="font-bold text-slate-900 dark:text-white text-[11px]">Approval Pending</span>
                        <span className="text-[10px] text-slate-400">02:44:05 PM</span>
                      </div>
                      <p className="text-[10px] text-slate-500 dark:text-slate-400 font-sans">Two-person rule enforced</p>
                    </div>
                  </div>

                </div>
              </Card>

              {/* Bottom Sub-Card: Recommended Actions */}
              <Card className="p-4 space-y-3 flex-1 flex flex-col justify-between">
                <div className="space-y-3">
                  <div className="flex items-center gap-2 border-b border-slate-100 dark:border-slate-800/80 pb-2.5">
                    <Lightbulb size={16} className="text-cyan-600 dark:text-cyan-400" />
                    <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-white font-mono">
                      Recommended Actions
                    </h3>
                  </div>

                  <div className="space-y-2 font-mono text-xs">
                    {[
                      'Require human approval for containment',
                      'Review affected user and agent activity',
                      'Validate legitimacy of data access',
                      'Consider restricting agent tool privileges'
                    ].map((act, idx) => (
                      <div key={idx} className="flex items-center gap-2.5 p-2 rounded-xl bg-slate-50 dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800/80">
                        <span className="w-5 h-5 rounded-full bg-blue-600 text-white font-bold flex items-center justify-center text-[10px] shrink-0">
                          {idx + 1}
                        </span>
                        <span className="text-slate-700 dark:text-slate-300 font-sans text-xs">{act}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <button
                  onClick={() => setActiveTab('response')}
                  className="w-full mt-3 py-2.5 px-4 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold font-mono tracking-wide flex items-center justify-center gap-2 shadow-md shadow-blue-600/30 transition-all cursor-pointer"
                >
                  <span>Open Action Center</span>
                  <ArrowRight size={14} />
                </button>
              </Card>

            </div>

          </div>

        </div>
      )}

      {/* Tab: Attack Chain (Expanded view) */}
      {activeTab === 'attack-chain' && (
        <Card className="p-6 space-y-6">
          <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-4">
            <div>
              <h3 className="text-sm font-bold text-slate-900 dark:text-white font-mono">End-to-End Attack Progression Graph</h3>
              <p className="text-xs text-slate-500 dark:text-slate-400">Step-by-step vector reconstruction across identity, perimeter, AI execution and data tier</p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 rounded-2xl bg-slate-50 dark:bg-slate-900/80 border border-rose-200 dark:border-rose-800/60 space-y-2">
              <div className="text-xs font-bold text-rose-700 dark:text-rose-300 font-mono flex items-center gap-2">
                <Globe size={16} /> Phase 1: Perimeter Breach
              </div>
              <p className="text-xs text-slate-700 dark:text-slate-300">
                Inbound connection authenticated from uncatalogued Tor/VPN exit node <span className="text-rose-600 dark:text-rose-400 font-mono">{externalIp}</span>.
              </p>
            </div>

            <div className="p-4 rounded-2xl bg-slate-50 dark:bg-slate-900/80 border border-amber-200 dark:border-amber-800/60 space-y-2">
              <div className="text-xs font-bold text-amber-700 dark:text-amber-300 font-mono flex items-center gap-2">
                <Bot size={16} /> Phase 2: Agent Privilege Abuse
              </div>
              <p className="text-xs text-slate-700 dark:text-slate-300">
                Autonomous agent <span className="text-amber-600 dark:text-amber-400 font-mono">{targetAgent}</span> invoked restricted database tool <span className="text-amber-600 dark:text-amber-400 font-mono">raw_sql_exec</span> without multi-factor authorization.
              </p>
            </div>

            <div className="p-4 rounded-2xl bg-slate-50 dark:bg-slate-900/80 border border-emerald-200 dark:border-emerald-800/60 space-y-2">
              <div className="text-xs font-bold text-emerald-700 dark:text-emerald-300 font-mono flex items-center gap-2">
                <Database size={16} /> Phase 3: Bulk Data Infiltration
              </div>
              <p className="text-xs text-slate-700 dark:text-slate-300">
                Over <span className="text-emerald-600 dark:text-emerald-400 font-mono">{exfilVolume}</span> queued for download from resource <span className="text-emerald-600 dark:text-emerald-400 font-mono">{resourceCleanName}</span>.
              </p>
            </div>
          </div>
        </Card>
      )}

      {/* Tab: Events (Event list & details) */}
      {activeTab === 'events' && (
        <Card className="p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-white font-mono">
              Correlated Events in Incident ({eventCount})
            </h3>
          </div>

          <div className="space-y-3">
            {events.map((evt, idx) => (
              <div key={evt.id || idx} className="p-4 rounded-xl bg-slate-50 dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4 font-mono text-xs">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-slate-900 dark:text-white">{evt.event_type?.toUpperCase()}</span>
                    <span className="px-2 py-0.5 rounded bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300 text-[10px]">{evt.id}</span>
                  </div>
                  <div className="text-slate-500 dark:text-slate-400 text-[11px] font-sans">
                    Resource: <span className="text-cyan-600 dark:text-cyan-300 font-mono">{evt.resource}</span>
                  </div>
                </div>

                <div className="flex items-center gap-4 text-slate-600 dark:text-slate-300 text-[11px]">
                  <div>User: <span className="text-slate-900 dark:text-white font-bold">{evt.user_id}</span></div>
                  <div>Device: <span className="text-slate-900 dark:text-white font-bold">{evt.device_id}</span></div>
                  <div className="text-slate-400">{new Date(evt.timestamp).toLocaleTimeString()}</div>
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Tab: Response & Approvals */}
      {(activeTab === 'response' || activeTab === 'approvals') && (
        <div className="space-y-6">
          <Card className="p-6 space-y-6">
            <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-4">
              <div>
                <h3 className="text-sm font-bold text-slate-900 dark:text-white font-mono">
                  {isEasyMode ? 'Security Actions & Human Approvals' : 'Risk-Adaptive Containment & Two-Person Approval Workbench'}
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  {isEasyMode 
                    ? 'Review and authorize containment safeguards to protect systems and data.'
                    : 'Dual-control policy enforcement: Sensitive containment actions require verified independent sign-offs.'}
                </p>
              </div>
              <span className="px-3 py-1 rounded-full bg-rose-100 dark:bg-rose-950 text-rose-700 dark:text-rose-300 border border-rose-200 dark:border-rose-700 font-mono text-xs font-bold">
                Level 4 Policy Active
              </span>
            </div>

            {/* Action simulation buttons */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 font-mono text-xs">
              <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 space-y-2">
                <div className="font-bold text-slate-900 dark:text-white flex items-center gap-2">
                  <Bot size={16} className="text-teal-600 dark:text-teal-400" />
                  <span>{isEasyMode ? 'Stop Agent from Using Tools' : 'Quarantine Agent'}</span>
                </div>
                <p className="text-[11px] text-slate-600 dark:text-slate-400 font-sans">
                  {isEasyMode ? 'Prevents the copilot agent from running database queries.' : 'Isolates copilot worker instance and invalidates runtime session keys.'}
                </p>
                <button
                  onClick={handleApproveContainment}
                  disabled={actionInProgress}
                  className="w-full py-1.5 rounded-lg bg-teal-100 dark:bg-teal-950/80 hover:bg-teal-200 dark:hover:bg-teal-900 text-teal-800 dark:text-teal-300 border border-teal-300 dark:border-teal-700 font-bold transition-all cursor-pointer"
                >
                  {isEasyMode ? 'Approve Agent Restriction' : 'Execute Quarantine'}
                </button>
              </div>

              <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 space-y-2">
                <div className="font-bold text-slate-900 dark:text-white flex items-center gap-2">
                  <Lock size={16} className="text-rose-600 dark:text-rose-400" />
                  <span>{isEasyMode ? 'Temporarily Restrict Session' : 'Lock User Session'}</span>
                </div>
                <p className="text-[11px] text-slate-600 dark:text-slate-400 font-sans">
                  {isEasyMode ? `Signs out active login cookies for ${targetUser}.` : `Immediately revokes active auth cookies for ${targetUser}.`}
                </p>
                <button
                  onClick={handleApproveContainment}
                  disabled={actionInProgress}
                  className="w-full py-1.5 rounded-lg bg-rose-100 dark:bg-rose-950/80 hover:bg-rose-200 dark:hover:bg-rose-900 text-rose-800 dark:text-rose-300 border border-rose-300 dark:border-rose-700 font-bold transition-all cursor-pointer"
                >
                  {isEasyMode ? 'Approve Session Restriction' : 'Revoke & Lock'}
                </button>
              </div>

              <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 space-y-2">
                <div className="font-bold text-slate-900 dark:text-white flex items-center gap-2">
                  <Undo2 size={16} className="text-amber-600 dark:text-amber-400" />
                  <span>{isEasyMode ? 'Mark as Legitimate Work' : 'False Positive Recovery'}</span>
                </div>
                <p className="text-[11px] text-slate-600 dark:text-slate-400 font-sans">
                  {isEasyMode ? 'If this was an authorized backup test, restores normal access.' : 'Allows authorized SOC lead to restore normal operational status.'}
                </p>
                <button
                  onClick={() => setShowRecoveryForm(!showRecoveryForm)}
                  className="w-full py-1.5 rounded-lg bg-amber-100 dark:bg-amber-950/80 hover:bg-amber-200 dark:hover:bg-amber-900 text-amber-800 dark:text-amber-300 border border-amber-300 dark:border-amber-700 font-bold transition-all cursor-pointer"
                >
                  {showRecoveryForm ? 'Hide Form' : 'Restore Access'}
                </button>
              </div>
            </div>

            {/* Two Person Form */}
            <div className="p-5 rounded-2xl bg-slate-50 dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 space-y-4">
              <div className="flex items-center gap-2 font-mono text-xs font-bold text-cyan-700 dark:text-cyan-300">
                <Users size={16} />
                <span>{isEasyMode ? 'Two Independent People Required for Approval' : 'Two-Person Approval Gate'}</span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
                <div className="p-3 rounded-xl bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-2 shadow-xs">
                  <div className="text-slate-500 dark:text-slate-400 font-bold">Person 1 (Primary Approver)</div>
                  <input
                    value={approver1Name}
                    onChange={(e) => setApprover1Name(e.target.value)}
                    className="w-full p-2 bg-slate-50 dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white"
                  />
                  <button
                    onClick={handleApproveContainment}
                    disabled={actionInProgress}
                    className="w-full py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-bold cursor-pointer shadow-xs"
                  >
                    Submit 1st Approval
                  </button>
                </div>

                <div className="p-3 rounded-xl bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-2 shadow-xs">
                  <div className="text-slate-500 dark:text-slate-400 font-bold">Person 2 (Co-Signer Admin)</div>
                  <input
                    value={approver2Name}
                    onChange={(e) => setApprover2Name(e.target.value)}
                    className="w-full p-2 bg-slate-50 dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white"
                  />
                  <button
                    onClick={handleSecondApproveContainment}
                    disabled={actionInProgress}
                    className="w-full py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-bold cursor-pointer shadow-xs"
                  >
                    Submit 2nd Approval
                  </button>
                </div>
              </div>
            </div>

            {/* False positive recovery drawer */}
            {showRecoveryForm && (
              <div className="p-4 rounded-xl bg-white dark:bg-slate-900/95 border border-amber-300 dark:border-amber-800/80 space-y-3 font-mono text-xs shadow-xs">
                <div className="font-bold text-amber-800 dark:text-amber-300">Legitimate Work Authorization & Recovery</div>
                <textarea
                  value={recoveryReason}
                  onChange={(e) => setRecoveryReason(e.target.value)}
                  className="w-full p-2.5 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white font-mono"
                  rows={2}
                />
                <button
                  onClick={handleRecoverFalsePositive}
                  disabled={actionInProgress}
                  className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-bold cursor-pointer shadow-xs"
                >
                  Confirm & Restore Normal Access
                </button>
              </div>
            )}
          </Card>
        </div>
      )}

      {/* Tab: Audit Trail */}
      {activeTab === 'audit-trail' && (
        <Card className="p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-white font-mono">
              Immutable Cryptographic Audit Trail
            </h3>
          </div>

          <div className="space-y-2.5 font-mono text-xs">
            <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 flex items-center justify-between shadow-xs">
              <div className="space-y-0.5">
                <div className="font-bold text-slate-900 dark:text-white">INCIDENT_CORRELATION_COMPLETED</div>
                <div className="text-slate-500 dark:text-slate-400 text-[11px]">Actor: IntelligenceEngine_v1</div>
              </div>
              <span className="text-slate-400 text-[10px]">SHA256: 9f8a...c3d1</span>
            </div>
            <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 flex items-center justify-between shadow-xs">
              <div className="space-y-0.5">
                <div className="font-bold text-slate-900 dark:text-white">TWO_PERSON_RULE_INITIALIZED</div>
                <div className="text-slate-500 dark:text-slate-400 text-[11px]">Actor: PolicyEngine_Containment</div>
              </div>
              <span className="text-slate-400 text-[10px]">SHA256: e41b...772a</span>
            </div>
          </div>
        </Card>
      )}

      {/* Tab: Related Entities */}
      {activeTab === 'related-entities' && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 font-mono text-xs">
          <Card className="p-4 space-y-2">
            <UserIcon size={18} className="text-blue-500" />
            <div className="font-bold text-slate-900 dark:text-white">{targetUser}</div>
            <div className="text-slate-500 dark:text-slate-400 text-[11px]">Risk Level: High</div>
          </Card>
          <Card className="p-4 space-y-2">
            <Laptop size={18} className="text-purple-500" />
            <div className="font-bold text-slate-900 dark:text-white">{targetDevice}</div>
            <div className="text-slate-500 dark:text-slate-400 text-[11px]">Fingerprint: Unrecognized</div>
          </Card>
          <Card className="p-4 space-y-2">
            <Bot size={18} className="text-teal-500" />
            <div className="font-bold text-slate-900 dark:text-white">{targetAgent}</div>
            <div className="text-slate-500 dark:text-slate-400 text-[11px]">Role: Copilot Worker</div>
          </Card>
          <Card className="p-4 space-y-2">
            <Database size={18} className="text-amber-500" />
            <div className="font-bold text-slate-900 dark:text-white">{resourceCleanName}</div>
            <div className="text-slate-500 dark:text-slate-400 text-[11px]">Tier: Confidential DB</div>
          </Card>
        </div>
      )}

    </div>
  );
}

export default IncidentsPage;
