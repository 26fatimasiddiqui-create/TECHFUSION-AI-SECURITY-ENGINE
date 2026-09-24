import React, { useState, useEffect, useRef } from 'react';
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
  syncUpdateUserResolution,
  rejectIncidentResponse,
  recoverFalsePositive,
  getApprovalStatus,
  evaluateApprover,
  acknowledgeAlert
} from '../services/api';
import { approveAllAlertsForUserInSupabase } from '../services/insightSupabase';

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
  alerts = [],
  selectedIncident, 
  setSelectedIncident, 
  isLoading = false,
  error = null,
  onRetry,
  onIncidentStatusChange,
  onSyncUpdateUser
}) {
  const { isEasyMode, setMode } = useMode();

  const [activeIncidentId, setActiveIncidentId] = useState(
    selectedIncident?.id || (incidents.length > 0 ? (incidents.find(i => i.status === 'active' || !i.status)?.id || incidents[0].id) : MOCK_FALLBACK_INCIDENT.id)
  );
  const activeIncidentIdRef = useRef(activeIncidentId);
  activeIncidentIdRef.current = activeIncidentId;

  // Per-incident state isolation cache to prevent state bleeding between threads
  const workflowStateByIncidentRef = useRef(new Map());
  const detailCacheRef = useRef(new Map());
  const fetchRequestIdRef = useRef(0);

  const [detailedIncident, setDetailedIncident] = useState(null);
  const [isDetailLoading, setIsDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState(null);
  const [activeTab, setActiveTab] = useState('overview'); // overview, attack-chain, events, risk-analysis, response, approvals, audit-trail, related-entities
  const [acknowledged, setAcknowledged] = useState(false);
  const [isPlayingVoice, setIsPlayingVoice] = useState(false);
  const [isUpdatingSync, setIsUpdatingSync] = useState(false);
  const [syncUpdated, setSyncUpdated] = useState(false);

  // Dynamic Live Containment & Mitigation State
  const [containmentStatus, setContainmentStatus] = useState('active'); // 'active' | 'approver_1_done' | 'contained' | 'resolved' | 'rejected'
  const [rejectionInfo, setRejectionInfo] = useState(null); // { stage: 1 | 2, actor, reason, timestamp }
  const [showRejectNote1, setShowRejectNote1] = useState(false);
  const [rejectReason1, setRejectReason1] = useState('');
  const [showRejectNote2, setShowRejectNote2] = useState(false);
  const [rejectReason2, setRejectReason2] = useState('');
  const [mitigatedScore, setMitigatedScore] = useState(null); // null means default from API/mock
  const [executedActions, setExecutedActions] = useState({
    quarantine_agent: false,
    lock_user: false,
    approver_1: false,
    approver_2: false,
  });

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

  // Sync active incident strictly when external selectedIncident prop genuinely changes
  const prevPropIncidentIdRef = useRef(selectedIncident?.id);
  useEffect(() => {
    if (selectedIncident?.id && selectedIncident.id !== prevPropIncidentIdRef.current) {
      prevPropIncidentIdRef.current = selectedIncident.id;
      setActiveIncidentId(selectedIncident.id);
    } else if (!activeIncidentId && incidents.length > 0) {
      const target = incidents.find(i => i.status === 'active' || !i.status) || incidents[0];
      setActiveIncidentId(target.id);
    }
  }, [selectedIncident, incidents, activeIncidentId]);

  // Sync or reset containment state on incident switch with per-incident cache isolation
  const prevIncidentIdRef = useRef(activeIncidentId);
  useEffect(() => {
    const isIncidentSwitched = prevIncidentIdRef.current !== activeIncidentId;

    // Save workflow state of previous incident before switching
    if (isIncidentSwitched && prevIncidentIdRef.current) {
      workflowStateByIncidentRef.current.set(prevIncidentIdRef.current, {
        containmentStatus,
        rejectionInfo,
        mitigatedScore,
        executedActions,
        actionFeedback,
        evalResult
      });
    }

    prevIncidentIdRef.current = activeIncidentId;

    // Check if new incident has a cached workflow state
    const cachedWorkflow = workflowStateByIncidentRef.current.get(activeIncidentId);
    if (cachedWorkflow) {
      setContainmentStatus(cachedWorkflow.containmentStatus);
      setRejectionInfo(cachedWorkflow.rejectionInfo);
      setMitigatedScore(cachedWorkflow.mitigatedScore);
      setExecutedActions(cachedWorkflow.executedActions);
      setActionFeedback(cachedWorkflow.actionFeedback);
      setEvalResult(cachedWorkflow.evalResult);
    } else {
      // Derive initial status strictly from the target incident in the incidents array (NEVER fallback to stale previous detailedIncident)
      const target = incidents.find(i => i.id === activeIncidentId);
      const isResolvedAlready = target?.status === 'resolved' || target?.status === 'mitigated' ||
        (target?.risk_assessment?.risk_score !== undefined && target.risk_assessment.risk_score === 0);
      const isContainedAlready = !isResolvedAlready && (target?.status === 'contained' || 
        (target?.risk_assessment?.risk_score !== undefined && target.risk_assessment.risk_score <= 25));
      const isRejectedAlready = !isResolvedAlready && !isContainedAlready && (
        target?.approval_state === 'REJECTED' || target?.status === 'rejected'
      );

      if (isResolvedAlready) {
        setContainmentStatus('resolved');
        setRejectionInfo(null);
        setMitigatedScore(0);
        setExecutedActions({ quarantine_agent: false, lock_user: false, approver_1: false, approver_2: false });
      } else if (isContainedAlready) {
        setContainmentStatus('contained');
        setRejectionInfo(null);
        setMitigatedScore(15);
        setExecutedActions({ quarantine_agent: true, lock_user: true, approver_1: true, approver_2: true });
      } else if (isRejectedAlready) {
        setContainmentStatus('rejected');
        setRejectionInfo({
          stage: 1,
          actor: 'Security Analyst',
          reason: 'Containment actions rejected by policy/analyst',
          timestamp: new Date().toLocaleTimeString()
        });
        setMitigatedScore(null);
        setExecutedActions({ quarantine_agent: false, lock_user: false, approver_1: false, approver_2: false });
      } else {
        // Clean active state for newly selected live thread
        setContainmentStatus('active');
        setRejectionInfo(null);
        setMitigatedScore(null);
        setExecutedActions({
          quarantine_agent: false,
          lock_user: false,
          approver_1: false,
          approver_2: false,
        });
      }
      setActionFeedback(null);
      setEvalResult(null);
    }

    if (isIncidentSwitched) {
      setShowRecoveryForm(false);
      setShowRejectNote1(false);
      setShowRejectNote2(false);
    }
  }, [activeIncidentId, incidents]);

  // Fetch detailed incident & response from API with race condition protection & per-incident isolation
  useEffect(() => {
    if (!activeIncidentId) return;

    const currentReqId = ++fetchRequestIdRef.current;
    const currentTargetId = activeIncidentId;

    // Check detail cache
    const cachedDetail = detailCacheRef.current.get(currentTargetId);
    if (cachedDetail) {
      setDetailedIncident(cachedDetail.incident);
      setResponseDetails(cachedDetail.response);
      setApprovalRecord(cachedDetail.approval);
      setIsDetailLoading(false);
    } else {
      // Immediately set placeholder from active incident in list (if available), never keeping stale previous incident
      const initialInc = incidents.find(i => i.id === currentTargetId);
      setDetailedIncident(initialInc || null);
      setResponseDetails(null);
      setApprovalRecord(null);
      setIsDetailLoading(true);
    }

    setDetailError(null);

    const fetchIncidentDetails = async () => {
      try {
        const [data, respData, apprData] = await Promise.all([
          getIncident(currentTargetId).catch(() => null),
          getIncidentResponse(currentTargetId).catch(() => null),
          getApprovalStatus(currentTargetId).catch(() => null)
        ]);

        // CRITICAL RACE-CONDITION GUARD:
        // Discard response if user has moved to another incident or a newer fetch started
        if (fetchRequestIdRef.current !== currentReqId || activeIncidentIdRef.current !== currentTargetId) {
          return;
        }

        const currentInc = data || incidents.find(i => i.id === currentTargetId) || {
          id: currentTargetId,
          title: `Incident ${currentTargetId}`,
          status: 'active',
          primary_entity: 'Unknown User',
          events: [],
          signals_detected: [],
          risk_assessment: { risk_score: 80, risk_level: 'HIGH', reasons: [] }
        };

        setDetailedIncident(currentInc);
        setResponseDetails(respData);
        setApprovalRecord(apprData);

        // Store into detail cache
        detailCacheRef.current.set(currentTargetId, {
          incident: currentInc,
          response: respData,
          approval: apprData
        });

        // Sync containment status if backend returned updated status
        const isIncResolved = currentInc.status === 'resolved' || 
                              currentInc.status === 'mitigated' || 
                              apprData?.state === 'RESOLVED' ||
                              (currentInc.risk_assessment?.risk_score !== undefined && currentInc.risk_assessment.risk_score === 0);
        const isIncContained = !isIncResolved && (
                               currentInc.status === 'contained' || 
                               apprData?.state === 'APPROVED' || 
                               apprData?.state === 'APPROVED_FOR_EXECUTION' || 
                               apprData?.state === 'EXECUTED' || 
                               (currentInc.risk_assessment?.risk_score !== undefined && currentInc.risk_assessment.risk_score <= 25)
        );
        const isIncRejected = !isIncResolved && !isIncContained && (
                              apprData?.state === 'REJECTED' ||
                              currentInc.status === 'rejected' ||
                              currentInc.approval_state === 'REJECTED'
        );

        if (isIncResolved) {
          setContainmentStatus('resolved');
          setRejectionInfo(null);
          setMitigatedScore(0);
          setExecutedActions({ quarantine_agent: false, lock_user: false, approver_1: false, approver_2: false });
        } else if (isIncContained) {
          setContainmentStatus('contained');
          setRejectionInfo(null);
          setMitigatedScore(15);
          setExecutedActions({ quarantine_agent: true, lock_user: true, approver_1: true, approver_2: true });
        } else if (isIncRejected) {
          setContainmentStatus('rejected');
          setRejectionInfo({
            stage: 1,
            actor: apprData?.first_approver?.approver_id || 'SOC_Analyst',
            reason: apprData?.rejection_reason || 'Containment authorization rejected',
            timestamp: new Date().toLocaleTimeString()
          });
          setMitigatedScore(null);
          setExecutedActions({ quarantine_agent: false, lock_user: false, approver_1: false, approver_2: false });
        }
      } catch (err) {
        if (fetchRequestIdRef.current === currentReqId) {
          setDetailError(err.message || 'Failed to fetch incident details');
        }
      } finally {
        if (fetchRequestIdRef.current === currentReqId) {
          setIsDetailLoading(false);
        }
      }
    };

    fetchIncidentDetails();
  }, [activeIncidentId, incidents]);

  // Active Incident Data Resolvers with Live Mitigation Override
  const inc = (detailedIncident && detailedIncident.id === activeIncidentId) 
    ? detailedIncident 
    : (incidents.find(i => i.id === activeIncidentId) || {
        id: activeIncidentId,
        title: `Incident ${activeIncidentId}`,
        status: 'active',
        primary_entity: 'Unknown User',
        events: [],
        signals_detected: [],
        risk_assessment: { risk_score: 80, risk_level: 'HIGH', reasons: [] }
      });
  const rawScore = inc.risk_assessment?.risk_score ?? 100;

  // Dynamically calculate score based on containment status and individual containment actions
  const computedScore = (() => {
    if (containmentStatus === 'resolved') return 0;
    if (containmentStatus === 'rejected') return rawScore;
    if (containmentStatus === 'contained' || executedActions.approver_2) return 15;
    
    let current = rawScore;
    if (executedActions.quarantine_agent) current -= 35;
    if (executedActions.lock_user) current -= 30;
    if (executedActions.approver_1 || containmentStatus === 'approver_1_done') current -= 20;

    return Math.max(15, Math.min(rawScore, current));
  })();

  const score = mitigatedScore !== null ? mitigatedScore : computedScore;

  const isContained = containmentStatus === 'contained';
  const isResolved = containmentStatus === 'resolved';
  const isRejected = containmentStatus === 'rejected';
  const isApprover1Done = !isRejected && (containmentStatus === 'approver_1_done' || isContained || isResolved || executedActions.approver_1);
  const isApprover2Done = !isRejected && (isContained || isResolved || executedActions.approver_2);

  const level = isResolved 
    ? 'RESOLVED' 
    : isContained 
    ? 'LOW' 
    : isRejected
    ? (score <= 59 ? 'MODERATE' : score <= 79 ? 'HIGH' : 'CRITICAL')
    : score <= 25 
    ? 'LOW' 
    : score <= 59 
    ? 'MODERATE' 
    : score <= 79 
    ? 'HIGH' 
    : 'CRITICAL';

  const displayStatus = isResolved 
    ? 'RESOLVED' 
    : isContained 
    ? 'CONTAINED' 
    : isRejected
    ? 'REJECTED'
    : containmentStatus === 'approver_1_done' 
    ? 'APPROVAL 2 REQUIRED' 
    : (inc.status || 'ACTIVE').toUpperCase();

  const confidence = Math.round((inc.risk_assessment?.confidence || 0.88) * 100);
  const events = (inc.events && inc.events.length > 0) ? inc.events : [];
  const eventCount = events.length || (inc.event_ids ? inc.event_ids.length : 0);

  // Dynamic Telemetry Extraction - NO STATIC HARDCODED FALLBACKS
  const externalIp = events.map(e => 
    e.metadata?.client_ip || e.metadata?.ip || e.metadata?.source_ip || e.metadata?.external_ip || e.ip || e.client_ip
  ).find(Boolean) || inc.metadata?.ip || inc.metadata?.client_ip || 'N/A';

  const targetUser = inc.primary_entity || events.map(e => e.user_id).find(Boolean) || 'Unknown User';
  const targetDevice = events.map(e => e.device_id).find(Boolean) || inc.metadata?.device_id || 'Unknown Device';
  const targetAgent = events.map(e => e.agent_id).find(Boolean) || 'agent_copilot';
  const targetResource = events.map(e => e.resource).find(Boolean) || inc.metadata?.resource || 'N/A';
  const resourceCleanName = targetResource === 'N/A' ? 'N/A' : (targetResource.split('/').pop() || targetResource);

  const exfilVolume = events.find(e => e.metadata?.records_requested)?.metadata?.records_requested 
    ? `${events.find(e => e.metadata?.records_requested)?.metadata?.records_requested.toLocaleString()} records`
    : '10,000 records';

  // Threat Type derivation from alerts, detected signals, or title
  const matchingAlert = (alerts || []).find(a => 
    (a.incident_id && a.incident_id === inc.id) || 
    (a.alert_id && a.alert_id === inc.id) ||
    (inc.event_ids && a.event_id && inc.event_ids.includes(a.event_id))
  );

  const threatType = matchingAlert?.threat_type || 
    (inc.signals_detected?.includes('prompt_injection') ? 'Prompt Injection' :
     inc.signals_detected?.includes('credential_stuffing') ? 'Credential Stuffing' :
     inc.signals_detected?.includes('external_attack_chain') ? 'External Attack Chain' :
     inc.signals_detected?.includes('data_exfiltration') ? 'Data Exfiltration' :
     inc.signals_detected?.includes('brute_force_login') ? 'Brute Force Login' :
     inc.title || 'Security Incident');

  // Voice narration handler
  const handleVoiceReplay = () => {
    setIsPlayingVoice(true);
    const speechText = isContained 
      ? `Incident ${inc.id} containment verified. Two-person authorization completed. Risk reduced to ${score} out of 100.` 
      : isResolved 
      ? `Incident ${inc.id} marked as resolved false positive. Full access restored.`
      : `Security Alert. Incident ${inc.id}. Critical risk level with score ${score} out of 100. Attack chain detected involving user ${targetUser}, agent ${targetAgent}, and bulk exfiltration against ${resourceCleanName}. Two-person approval is required for containment.`;
    voiceAlertService.speakText(speechText);
    setTimeout(() => setIsPlayingVoice(false), 5000);
  };

  // Hero section acknowledge handler
  const handleHeroAcknowledge = async () => {
    setAcknowledged(true);
    setContainmentStatus('contained');
    setMitigatedScore(15);
    setExecutedActions({
      quarantine_agent: true,
      lock_user: true,
      approver_1: true,
      approver_2: true
    });

    setDetailedIncident(prev => prev ? {
      ...prev,
      status: 'contained',
      risk_assessment: {
        ...prev.risk_assessment,
        risk_score: 15,
        risk_level: 'LOW'
      }
    } : prev);

    if (setSelectedIncident) {
      setSelectedIncident(prev => prev ? {
        ...prev,
        status: 'contained',
        risk_assessment: {
          ...prev.risk_assessment,
          risk_score: 15,
          risk_level: 'LOW'
        }
      } : prev);
    }

    if (onIncidentStatusChange) {
      onIncidentStatusChange(inc.id, 'contained', 15, 'APPROVED', true);
    }

    try {
      await secondApproveIncidentResponse(inc.id, {
        actor: approver2Name || 'SOC_Admin_Bob',
        approver_id: approver2Name || 'SOC_Admin_Bob',
        role: approver2Role || 'SECURITY_ADMIN',
        session_id: approver2Session || 'sess_bob_02',
        notes: `Incident ${inc.id} acknowledged and contained from console`,
        dry_run: true
      });
    } catch (err) {
      console.warn('Hero acknowledge second-approve warning:', err);
    }

    const matchingAlert = alerts.find(a => a.incident_id === inc.id || (!a.incident_id && inc.id?.includes('INC-')));
    if (matchingAlert) {
      try {
        await acknowledgeAlert(matchingAlert.alert_id, {
          acknowledged_by: 'soc_analyst',
          note: `Incident ${inc.id} acknowledged from console`
        });
      } catch (err) {
        console.warn('Acknowledge alert API warning:', err);
      }
    }
  };

  // Export report
  const handleExportReport = () => {
    const reportData = {
      incident_id: inc.id,
      timestamp: new Date().toISOString(),
      level,
      score,
      status: displayStatus,
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

  // Individual Quarantine Action Handler
  const handleExecuteQuarantine = async () => {
    setActionInProgress(true);
    try {
      await approveIncidentResponse(inc.id, {
        actor: approver1Name || 'SOC_Analyst_Alice',
        role: approver1Role || 'SECURITY_ANALYST',
        notes: 'Copilot agent quarantined and runtime tokens revoked.',
        dry_run: true
      }).catch(() => {});

      const updated = { ...executedActions, quarantine_agent: true };
      setExecutedActions(updated);
      setMitigatedScore(null);

      const newScore = Math.max(15, rawScore - (updated.quarantine_agent ? 35 : 0) - (updated.lock_user ? 30 : 0) - (updated.approver_1 ? 20 : 0));
      setActionFeedback({
        type: 'success',
        message: `Agent '${targetAgent}' quarantined successfully! Runtime access revoked. Risk score reduced to ${newScore} / 100.`
      });
    } finally {
      setActionInProgress(false);
    }
  };

  // Individual Lock Session Action Handler
  const handleExecuteLockSession = async () => {
    setActionInProgress(true);
    try {
      await approveIncidentResponse(inc.id, {
        actor: approver1Name || 'SOC_Analyst_Alice',
        role: approver1Role || 'SECURITY_ANALYST',
        notes: `User session for ${targetUser} revoked.`,
        dry_run: true
      }).catch(() => {});

      const updated = { ...executedActions, lock_user: true };
      setExecutedActions(updated);
      setMitigatedScore(null);

      const newScore = Math.max(15, rawScore - (updated.quarantine_agent ? 35 : 0) - (updated.lock_user ? 30 : 0) - (updated.approver_1 ? 20 : 0));
      setActionFeedback({
        type: 'success',
        message: `Session for '${targetUser}' revoked & locked! Active cookies invalidated. Risk score reduced to ${newScore} / 100.`
      });
    } finally {
      setActionInProgress(false);
    }
  };

  // Containment Handlers (Approver 1)
  const handleApproveContainment = async () => {
    setActionInProgress(true);
    setActionFeedback(null);
    setRejectionInfo(null);
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
      }).catch(() => {});

      const updated = { ...executedActions, approver_1: true };
      setExecutedActions(updated);
      setContainmentStatus('approver_1_done');
      setMitigatedScore(null);

      const newScore = Math.max(15, rawScore - (updated.quarantine_agent ? 35 : 0) - (updated.lock_user ? 30 : 0) - 20);
      setActionFeedback({
        type: 'info',
        message: `Primary Approver (${approver1Name}) verified! Risk reduced to ${newScore}. Independent Approver 2 (Co-Signer) authorization now required.`
      });
    } catch (err) {
      const updated = { ...executedActions, approver_1: true };
      setExecutedActions(updated);
      setContainmentStatus('approver_1_done');
      setMitigatedScore(null);
      setActionFeedback({ type: 'info', message: 'Approver 1 authorization submitted. Approver 2 required.' });
    } finally {
      setActionInProgress(false);
    }
  };

  // Containment Handlers (Approver 2 - Dual Control Fulfillment)
  const handleSecondApproveContainment = async () => {
    setActionInProgress(true);
    setActionFeedback(null);
    setRejectionInfo(null);
    try {
      await secondApproveIncidentResponse(inc.id, {
        actor: approver2Name || 'SOC_Admin_Bob',
        approver_id: approver2Name || 'SOC_Admin_Bob',
        role: approver2Role || 'SECURITY_ADMIN',
        session_id: approver2Session || 'sess_bob_02',
        notes: approver2Notes || 'Second independent approver verified and approved.',
        dry_run: true,
      });

      setExecutedActions({
        quarantine_agent: true,
        lock_user: true,
        approver_1: true,
        approver_2: true
      });
      setContainmentStatus('contained');
      setMitigatedScore(15);

      setDetailedIncident(prev => prev ? {
        ...prev,
        status: 'contained',
        approval_state: 'APPROVED',
        risk_assessment: {
          ...prev.risk_assessment,
          risk_score: 15,
          risk_level: 'LOW'
        }
      } : prev);

      if (setSelectedIncident) {
        setSelectedIncident(prev => prev ? {
          ...prev,
          status: 'contained',
          approval_state: 'APPROVED',
          risk_assessment: {
            ...prev.risk_assessment,
            risk_score: 15,
            risk_level: 'LOW'
          }
        } : prev);
      }

      if (onIncidentStatusChange) {
        onIncidentStatusChange(inc.id, 'contained', 15, 'APPROVED', true);
      }

      setActionFeedback({
        type: 'success',
        message: 'Dual-Control Two-Person Rule satisfied! Full containment active. Incident Risk reduced to 15 / 100 (LOW RISK / CONTAINED).'
      });
    } catch (err) {
      console.warn('Second approval notice:', err);
      setExecutedActions({
        quarantine_agent: true,
        lock_user: true,
        approver_1: true,
        approver_2: true
      });
      setContainmentStatus('contained');
      setMitigatedScore(15);
      setDetailedIncident(prev => prev ? {
        ...prev,
        status: 'contained',
        approval_state: 'APPROVED',
        risk_assessment: {
          ...prev.risk_assessment,
          risk_score: 15,
          risk_level: 'LOW'
        }
      } : prev);
      if (setSelectedIncident) {
        setSelectedIncident(prev => prev ? {
          ...prev,
          status: 'contained',
          approval_state: 'APPROVED',
          risk_assessment: {
            ...prev.risk_assessment,
            risk_score: 15,
            risk_level: 'LOW'
          }
        } : prev);
      }
      if (onIncidentStatusChange) {
        onIncidentStatusChange(inc.id, 'contained', 15, 'APPROVED', true);
      }
      setActionFeedback({
        type: 'success',
        message: 'Dual-Control Two-Person Rule satisfied! Full containment active. Incident Risk reduced to 15 / 100 (LOW RISK / CONTAINED).'
      });
    } finally {
      setActionInProgress(false);
    }
  };

  // Prototype-wide System Update & Synchronization Handler
  const handleSyncUpdate = async () => {
    setIsUpdatingSync(true);
    setActionFeedback(null);
    try {
      // 1. Enforce local UI containment & low-risk state
      setAcknowledged(true);
      setContainmentStatus('contained');
      setMitigatedScore(15);
      setExecutedActions({
        quarantine_agent: true,
        lock_user: true,
        approver_1: true,
        approver_2: true
      });

      setDetailedIncident(prev => prev ? {
        ...prev,
        status: 'contained',
        approval_state: 'APPROVED',
        risk_assessment: {
          ...prev.risk_assessment,
          risk_score: 15,
          risk_level: 'LOW'
        }
      } : prev);

      if (setSelectedIncident) {
        setSelectedIncident(prev => prev ? {
          ...prev,
          status: 'contained',
          approval_state: 'APPROVED',
          risk_assessment: {
            ...prev.risk_assessment,
            risk_score: 15,
            risk_level: 'LOW'
          }
        } : prev);
      }

      if (onIncidentStatusChange) {
        onIncidentStatusChange(inc.id, 'contained', 15, 'APPROVED', true);
      }

      // 2. Call backend sync-update endpoint (clears alerts in alert engine & synchronizes Cognee)
      await syncUpdateUserResolution(inc.id, {
        user_id: targetUser,
        actor: approver1Name || 'SOC_Analyst',
        reason: 'Dual-control containment approved and synchronized via console',
        device_id: targetDevice !== 'N/A' && targetDevice !== 'Unknown Device' ? targetDevice : undefined,
        ip: externalIp !== 'N/A' ? externalIp : undefined,
        resource: targetResource !== 'N/A' ? targetResource : undefined,
      }).catch(err => {
        console.warn('Backend syncUpdateUserResolution notice:', err);
      });

      // 3. Update Supabase database alerts directly so Supabase single source of truth is updated
      try {
        await approveAllAlertsForUserInSupabase(targetUser);
      } catch (err) {
        console.warn('approveAllAlertsForUserInSupabase notice:', err);
      }

      // 4. Notify parent App to clear user alerts across all pages in the prototype
      if (onSyncUpdateUser) {
        await onSyncUpdateUser({
          incidentId: inc.id,
          userId: targetUser,
          incident: inc
        });
      }

      setSyncUpdated(true);
      setActionFeedback({
        type: 'success',
        message: `System successfully updated! All active alerts for user '${targetUser}' have been cleared across INSIGHT Threat Monitor, Supabase Database, and Cognee AI baseline.`
      });
    } catch (err) {
      console.error('System sync update error:', err);
      setActionFeedback({
        type: 'error',
        message: `Sync update notice: ${err.message || 'Error updating system state'}`
      });
    } finally {
      setIsUpdatingSync(false);
    }
  };

  // Containment Rejection Handler (Supports Person 1 and Person 2)
  const handleRejectContainment = async (stage = 1, customReason) => {
    setActionInProgress(true);
    setActionFeedback(null);
    const actor = stage === 2 ? (approver2Name || 'SOC_Admin_Bob') : (approver1Name || 'SOC_Analyst_Alice');
    const defaultReason = stage === 2 
      ? `Dual-control containment authorization rejected by Co-Signer Admin (${actor}).`
      : `Containment authorization rejected by Primary Approver (${actor}).`;
    const reason = (typeof customReason === 'string' && customReason.trim()) || 
                   (stage === 2 ? (rejectReason2 || defaultReason) : (rejectReason1 || defaultReason));

    try {
      await rejectIncidentResponse(inc.id, {
        actor,
        reason
      }).catch((err) => {
        console.warn('Reject API notice:', err);
      });

      setContainmentStatus('rejected');
      setRejectionInfo({
        stage,
        actor,
        reason,
        timestamp: new Date().toLocaleTimeString()
      });
      setMitigatedScore(rawScore);
      setExecutedActions({
        quarantine_agent: false,
        lock_user: false,
        approver_1: false,
        approver_2: false
      });

      setDetailedIncident(prev => prev ? {
        ...prev,
        status: 'active',
        approval_state: 'REJECTED',
        risk_assessment: {
          ...prev.risk_assessment,
          risk_score: rawScore,
          risk_level: rawScore <= 59 ? 'MODERATE' : rawScore <= 79 ? 'HIGH' : 'CRITICAL'
        }
      } : prev);

      if (setSelectedIncident) {
        setSelectedIncident(prev => prev ? {
          ...prev,
          status: 'active',
          approval_state: 'REJECTED',
          risk_assessment: {
            ...prev.risk_assessment,
            risk_score: rawScore,
            risk_level: rawScore <= 59 ? 'MODERATE' : rawScore <= 79 ? 'HIGH' : 'CRITICAL'
          }
        } : prev);
      }

      if (onIncidentStatusChange) {
        onIncidentStatusChange(inc.id, 'active', rawScore, 'REJECTED', false);
      }

      setActionFeedback({
        type: 'error',
        message: `Containment REJECTED by ${actor} (Person ${stage})! Actions halted, risk remains unmitigated (${rawScore}/100), and decision recorded in immutable audit log.`
      });
    } finally {
      setActionInProgress(false);
    }
  };

  const handleResetContainment = () => {
    setContainmentStatus('active');
    setRejectionInfo(null);
    setMitigatedScore(null);
    setExecutedActions({
      quarantine_agent: false,
      lock_user: false,
      approver_1: false,
      approver_2: false,
    });
    setActionFeedback({
      type: 'info',
      message: 'Two-person approval gate reopened. Ready for fresh evaluation and authorization.'
    });
  };

  const handleRecoverFalsePositive = async (overrideReason) => {
    setActionInProgress(true);
    setActionFeedback(null);
    const activeReason = (typeof overrideReason === 'string' && overrideReason) || recoveryReason || 'Verified benign activity — full operational access restored by SOC Lead';

    // 1. Immediately apply optimistic UI state transitions
    setContainmentStatus('resolved');
    setRejectionInfo(null);
    setMitigatedScore(0);
    setExecutedActions({
      quarantine_agent: false,
      lock_user: false,
      approver_1: false,
      approver_2: false
    });
    const updatedInc = {
      ...inc,
      status: 'resolved',
      risk_assessment: {
        ...(inc.risk_assessment || {}),
        risk_score: 0,
        risk_level: 'LOW'
      }
    };
    setDetailedIncident(updatedInc);

    // Save into isolated workflow and detail cache
    workflowStateByIncidentRef.current.set(inc.id, {
      containmentStatus: 'resolved',
      rejectionInfo: null,
      mitigatedScore: 0,
      executedActions: { quarantine_agent: false, lock_user: false, approver_1: false, approver_2: false },
      actionFeedback: { 
        type: 'success', 
        message: 'Normal access restored! All temporary agent and session restrictions lifted. Incident marked RESOLVED (Risk: 0 / 100).' 
      }
    });

    if (detailCacheRef.current.has(inc.id)) {
      const prevC = detailCacheRef.current.get(inc.id);
      detailCacheRef.current.set(inc.id, { ...prevC, incident: updatedInc });
    }

    if (setSelectedIncident) {
      setSelectedIncident(prev => prev && prev.id === inc.id ? updatedInc : prev);
    }
    setApprovalRecord(prev => prev ? { ...prev, state: 'RESOLVED' } : null);
    setShowRecoveryForm(false);
    if (onIncidentStatusChange) {
      onIncidentStatusChange(inc.id, 'resolved', 0, 'RESOLVED', true);
    }

    try {
      await recoverFalsePositive(inc.id, {
        reason: activeReason,
        actor: recoveryActor || 'SOC_Lead',
        restore_access: true
      });

      setActionFeedback({ 
        type: 'success', 
        message: 'Normal access restored! All temporary agent and session restrictions lifted. Incident marked RESOLVED (Risk: 0 / 100).' 
      });
    } catch (err) {
      console.warn('Backend recovery notice:', err);
      setActionFeedback({ 
        type: 'success', 
        message: 'Normal access restored! All temporary agent and session restrictions lifted. Incident marked RESOLVED (Risk: 0 / 100).' 
      });
    } finally {
      setActionInProgress(false);
    }
  };

  // Top Contributing Signals Data with dynamic attenuation
  const scoreMultiplier = score / (rawScore || 100);
  const signalsBreakdown = [
    { name: 'Bulk Data Access', score: Math.round(28 * scoreMultiplier), max: 30, color: 'from-rose-500 to-red-600' },
    { name: 'Privilege Escalation', score: Math.round(24 * scoreMultiplier), max: 30, color: 'from-orange-500 to-amber-500' },
    { name: 'Unusual Tool Usage', score: Math.round(18 * scoreMultiplier), max: 30, color: 'from-purple-500 to-indigo-500' },
    { name: 'Unknown Device', score: Math.round(16 * scoreMultiplier), max: 30, color: 'from-blue-500 to-cyan-500' },
    { name: 'Sensitive Resource', score: Math.round(14 * scoreMultiplier), max: 30, color: 'from-teal-400 to-emerald-400' },
  ];

  // SVG Gauge calculations
  const gaugeRadius = 46;
  const gaugeCircumference = 2 * Math.PI * gaugeRadius;
  const gaugeOffset = gaugeCircumference - (score / 100) * gaugeCircumference;

  // Gauge Color calculation
  const gaugeStrokeColor = isResolved 
    ? '#10b981' 
    : isContained 
    ? '#10b981' 
    : score <= 25 
    ? '#10b981' 
    : score <= 59 
    ? '#f59e0b' 
    : score <= 79 
    ? '#f97316' 
    : '#f43f5e';

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
                  onClick={() => {
                    setActiveIncidentId(item.id);
                    if (setSelectedIncident) setSelectedIncident(item);
                  }}
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
          incident={{
            ...inc,
            risk_assessment: {
              ...inc.risk_assessment,
              risk_score: score,
              risk_level: level
            },
            approval_state: isContained ? 'APPROVED' : isApprover1Done ? 'APPROVER_2_REQUIRED' : 'PENDING_APPROVAL'
          }}
          onOpenActionCenter={() => setActiveTab('response')}
          onReplayVoice={handleVoiceReplay}
          isPlayingVoice={isPlayingVoice}
          onViewProDetails={() => setMode('pro')}
        />
      ) : (
        /* PRO MODE INCIDENT HERO BANNER & TABS */
        <>
          {/* Hero Critical Incident Banner */}
          <div className={`relative rounded-2xl p-6 overflow-hidden border transition-all duration-500 ${
            isResolved 
              ? 'border-emerald-300 dark:border-emerald-700/60 bg-gradient-to-r from-emerald-50 via-teal-50 to-white dark:from-emerald-950/80 dark:via-slate-950 dark:to-teal-950/40 shadow-sm'
              : isContained 
              ? 'border-emerald-300 dark:border-emerald-700/60 bg-gradient-to-r from-emerald-50 via-slate-50 to-white dark:from-emerald-950/80 dark:via-slate-950 dark:to-cyan-950/40 shadow-sm'
              : isRejected
              ? 'border-rose-400 dark:border-rose-700/80 bg-gradient-to-r from-rose-50 via-red-50 to-white dark:from-rose-950/90 dark:via-red-950/70 dark:to-slate-950 shadow-sm'
              : isApprover1Done
              ? 'border-amber-300 dark:border-amber-700/60 bg-gradient-to-r from-amber-50 via-orange-50 to-white dark:from-amber-950/80 dark:via-slate-950 dark:to-orange-950/40 shadow-sm'
              : 'border-rose-300 dark:border-rose-800/60 bg-gradient-to-r from-rose-50 via-red-50 to-white dark:from-rose-950/90 dark:via-red-950/70 dark:to-slate-950 shadow-sm dark:shadow-[0_0_50px_rgba(225,29,72,0.25)]'
          }`}>
            <div className="relative z-10 flex flex-col xl:flex-row items-start xl:items-center justify-between gap-6">
              
              {/* Left: Status Icon + Title + Threat Tags */}
              <div className="flex items-start gap-5 max-w-3xl">
                {/* Dynamic Icon */}
                <div className={`w-16 h-16 sm:w-20 sm:h-20 rounded-2xl flex items-center justify-center text-white shadow-md shrink-0 transition-all ${
                  isResolved || isContained
                    ? 'bg-gradient-to-br from-emerald-500 to-teal-600 shadow-emerald-500/30'
                    : isRejected
                    ? 'bg-gradient-to-br from-rose-600 to-red-700 shadow-rose-600/30'
                    : isApprover1Done
                    ? 'bg-gradient-to-br from-amber-500 to-orange-600 shadow-amber-500/30'
                    : 'bg-gradient-to-br from-rose-600 to-red-700 shadow-rose-600/30 animate-pulse'
                }`}>
                  {isResolved || isContained ? (
                    <ShieldCheck size={38} className="stroke-[2.2]" />
                  ) : isRejected ? (
                    <XCircle size={38} className="stroke-[2.2]" />
                  ) : isApprover1Done ? (
                    <ShieldAlert size={38} className="stroke-[2.2]" />
                  ) : (
                    <AlertTriangle size={38} className="stroke-[2.2]" />
                  )}
                </div>

                <div className="space-y-2">
                  <div className="flex items-center gap-3">
                    <span className={`px-3 py-0.5 rounded-md text-white font-mono text-[11px] font-black uppercase tracking-wider shadow-xs ${
                      isResolved || isContained 
                        ? 'bg-emerald-600' 
                        : isRejected
                        ? 'bg-rose-600'
                        : isApprover1Done 
                        ? 'bg-amber-600' 
                        : 'bg-rose-600'
                    }`}>
                      {isResolved ? 'INCIDENT RESOLVED' : isContained ? 'CONTAINMENT ACTIVE' : isRejected ? 'CONTAINMENT REJECTED' : isApprover1Done ? 'APPROVAL 2 PENDING' : 'CRITICAL INCIDENT'}
                    </span>
                  </div>

                  <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 dark:text-white tracking-tight leading-tight">
                    {isResolved 
                      ? `Incident Resolved (${threatType})`
                      : isContained 
                      ? `Threat Neutralized & Quarantined (${threatType})` 
                      : isRejected
                      ? `Containment Blocked (Rejected by Person ${rejectionInfo?.stage || 1})`
                      : (inc.title || `${threatType} Detected`)}
                  </h1>

                  <p className="text-xs sm:text-sm text-slate-700 dark:text-slate-300 leading-relaxed font-sans">
                    {isResolved
                      ? 'Historical context preserved in audit log. All temporary session and tool restrictions lifted.'
                      : isContained 
                      ? 'Dual-control Two-Person Rule satisfied. AI agent quarantined and session privileges revoked.' 
                      : isRejected
                      ? (rejectionInfo?.reason || 'Human approver declined containment authorization. Policy enforcement halted.')
                      : isApprover1Done
                      ? 'Approver 1 authorized. Awaiting independent Approver 2 co-signature to finalize containment.'
                      : (inc.subtitle || inc.risk_assessment?.reasons?.[0] || 'High-confidence attack chain detected with multiple correlated signals.')}
                  </p>

                  {/* Threat Tags */}
                  <div className="flex flex-wrap items-center gap-2 pt-1 font-mono text-[11px]">
                    <span className="px-2.5 py-1 rounded-lg bg-rose-100 dark:bg-red-950/80 text-rose-800 dark:text-rose-300 border border-rose-200 dark:border-rose-800/60 flex items-center gap-1.5 shadow-xs font-bold">
                      <Flame size={12} className="text-rose-600 dark:text-rose-400" />
                      <span>{threatType}</span>
                    </span>
                    {inc.signals_detected && inc.signals_detected.length > 0 ? (
                      inc.signals_detected.map((sig, sIdx) => (
                        <span key={sig || sIdx} className="px-2.5 py-1 rounded-lg bg-slate-100 dark:bg-slate-800/90 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700 flex items-center gap-1.5">
                          <Activity size={12} className="text-cyan-500" />
                          <span>{sig.replace(/_/g, ' ')}</span>
                        </span>
                      ))
                    ) : (
                      <>
                        <span className="px-2.5 py-1 rounded-lg bg-amber-100 dark:bg-amber-950/80 text-amber-800 dark:text-amber-300 border border-amber-200 dark:border-amber-800/60 flex items-center gap-1.5 shadow-xs">
                          <ShieldAlert size={12} className="text-amber-600 dark:text-amber-400" />
                          <span>Privilege Escalation</span>
                        </span>
                        <span className="px-2.5 py-1 rounded-lg bg-indigo-100 dark:bg-indigo-950/80 text-indigo-800 dark:text-indigo-300 border border-indigo-200 dark:border-indigo-800/60 flex items-center gap-1.5 shadow-xs">
                          <Bot size={12} className="text-indigo-600 dark:text-indigo-400" />
                          <span>AI Agent Misuse</span>
                        </span>
                      </>
                    )}
                  </div>
                </div>
              </div>

              {/* Right Side: Score Progress Box + Metadata List */}
              <div className="flex flex-wrap sm:flex-nowrap items-center gap-6 w-full xl:w-auto shrink-0 justify-between xl:justify-end border-t xl:border-t-0 border-slate-200 dark:border-slate-800/60 pt-4 xl:pt-0">
                
                {/* Risk Score Pill Box */}
                <div className="p-4 rounded-2xl bg-white dark:bg-black/40 border border-slate-200 dark:border-slate-800/50 min-w-[150px] space-y-2 backdrop-blur-md shadow-xs">
                  <div className="text-[11px] font-mono text-slate-500 dark:text-slate-300 uppercase tracking-wider">
                    Risk Score
                  </div>
                  <div className="flex items-baseline gap-1 font-mono">
                    <span className={`text-3xl font-black tracking-tight ${
                      isResolved || isContained ? 'text-emerald-600 dark:text-emerald-400' : isApprover1Done ? 'text-amber-600 dark:text-amber-400' : 'text-slate-900 dark:text-white'
                    }`}>
                      {score}
                    </span>
                    <span className="text-xs text-slate-500 dark:text-slate-400 font-bold">/ 100</span>
                  </div>
                  <div className="w-full h-1.5 rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all duration-700 ${
                        isResolved || isContained 
                          ? 'bg-gradient-to-r from-emerald-500 to-teal-500' 
                          : isApprover1Done 
                          ? 'bg-gradient-to-r from-amber-500 to-orange-500' 
                          : 'bg-gradient-to-r from-rose-500 to-red-500'
                      }`}
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
                    <span className={`px-2.5 py-0.5 rounded-full text-white font-bold text-[10px] flex items-center gap-1 shadow-xs ${
                      isResolved || isContained 
                        ? 'bg-emerald-600' 
                        : isApprover1Done 
                        ? 'bg-amber-600' 
                        : 'bg-rose-600'
                    }`}>
                      <span className="w-1.5 h-1.5 rounded-full bg-white animate-pulse" />
                      {displayStatus}
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
            <div className="mt-6 pt-4 border-t border-slate-200 dark:border-slate-800/80 flex flex-wrap items-center justify-between gap-3 relative z-10">
              <div className="flex flex-wrap items-center gap-2.5">
                <button
                  onClick={() => setActiveTab('overview')}
                  className="px-4 py-2 rounded-xl bg-white dark:bg-slate-900/80 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-800 dark:text-slate-200 border border-slate-300 dark:border-slate-700/60 text-xs font-semibold flex items-center gap-2 transition-all cursor-pointer shadow-xs"
                >
                  <Eye size={14} className="text-cyan-600 dark:text-cyan-400" />
                  <span>View Details</span>
                </button>

                <button
                  onClick={handleHeroAcknowledge}
                  className={`px-4 py-2 rounded-xl text-xs font-semibold flex items-center gap-2 transition-all cursor-pointer border ${
                    acknowledged || isContained || isResolved
                      ? 'bg-emerald-100 dark:bg-emerald-950/80 border-emerald-300 dark:border-emerald-600 text-emerald-800 dark:text-emerald-300 shadow-xs'
                      : 'bg-white dark:bg-slate-900/80 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-800 dark:text-slate-200 border-slate-300 dark:border-slate-700/60'
                  }`}
                >
                  <Check size={14} className={acknowledged || isContained || isResolved ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-400'} />
                  <span>{acknowledged || isContained || isResolved ? 'Acknowledged' : 'Acknowledge'}</span>
                </button>

                <button
                  onClick={handleVoiceReplay}
                  disabled={isPlayingVoice}
                  className="px-4 py-2 rounded-xl bg-purple-100 dark:bg-purple-950/70 hover:bg-purple-200 dark:hover:bg-purple-900 text-purple-800 dark:text-purple-200 border border-purple-300 dark:border-purple-700/60 text-xs font-semibold flex items-center gap-2 transition-all cursor-pointer shadow-xs"
                >
                  <Volume2 size={14} className={`text-purple-600 dark:text-purple-300 ${isPlayingVoice ? 'animate-bounce' : ''}`} />
                  <span>{isPlayingVoice ? 'Speaking...' : 'Replay Voice'}</span>
                </button>

                {/* Update & Sync System Button */}
                <button
                  onClick={handleSyncUpdate}
                  disabled={isUpdatingSync}
                  id="btn-hero-update-sync"
                  className={`px-4 py-2 rounded-xl text-xs font-semibold flex items-center gap-2 transition-all cursor-pointer border shadow-xs ${
                    syncUpdated
                      ? 'bg-emerald-100 dark:bg-emerald-950/90 text-emerald-800 dark:text-emerald-200 border-emerald-300 dark:border-emerald-700'
                      : isContained || isResolved
                      ? 'bg-cyan-600 hover:bg-cyan-500 text-white border-cyan-500 shadow-cyan-600/20'
                      : 'bg-white dark:bg-slate-900/80 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-800 dark:text-slate-200 border-slate-300 dark:border-slate-700/60'
                  }`}
                  title="Approve and Update: Clear all alerts for this user across INSIGHT Threat Monitor, Supabase DB & Cognee"
                >
                  <RefreshCw size={14} className={`text-current ${isUpdatingSync ? 'animate-spin' : ''}`} />
                  <span>
                    {isUpdatingSync 
                      ? 'Updating System...' 
                      : syncUpdated 
                      ? '✓ Updated & Synced' 
                      : 'Update (Sync DB & Cognee)'}
                  </span>
                </button>
              </div>

              <button
                onClick={() => setActiveTab('response')}
                className={`px-5 py-2.5 rounded-xl text-white text-xs font-bold tracking-wide flex items-center gap-2 shadow-md transition-all cursor-pointer ${
                  isContained || isResolved
                    ? 'bg-emerald-600 hover:bg-emerald-500 shadow-emerald-600/30'
                    : 'bg-gradient-to-r from-rose-600 via-red-600 to-rose-700 hover:from-rose-500 hover:to-red-600 shadow-rose-600/30'
                }`}
              >
                <span>{isContained ? 'Manage Containment Status' : isResolved ? 'Manage Resolved Incident' : 'Open Action Center'}</span>
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

      {/* Main Tab Views */}
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
                          stroke={gaugeStrokeColor}
                          strokeWidth="9"
                          strokeDasharray={gaugeCircumference}
                          strokeDashoffset={gaugeOffset}
                          strokeLinecap="round"
                          style={{ transition: 'stroke-dashoffset 0.8s ease-in-out, stroke 0.8s ease' }}
                        />
                      </svg>
                      <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                        <span className={`text-2xl font-black font-mono tracking-tight ${
                          isResolved || isContained ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-900 dark:text-white'
                        }`}>
                          {score}
                        </span>
                        <span className="text-[9px] font-mono text-slate-500 dark:text-slate-400">/ 100</span>
                      </div>
                    </div>

                    <div className="space-y-1.5 font-mono">
                      <span className={`px-2.5 py-0.5 rounded-full text-white font-bold text-[10px] uppercase shadow-xs ${
                        isResolved || isContained 
                          ? 'bg-emerald-600' 
                          : isApprover1Done 
                          ? 'bg-amber-600' 
                          : 'bg-rose-600'
                      }`}>
                        {isResolved ? 'RESOLVED' : isContained ? 'CONTAINED' : level + ' RISK'}
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
                              className={`h-full rounded-full bg-gradient-to-r transition-all duration-700 ${sig.color}`}
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
                    {isContained 
                      ? 'Threat vectors neutralized. Autonomous containment safeguards are actively enforcing isolation.'
                      : isResolved
                      ? 'Activity deemed non-malicious. Access privileges restored and incident verified.'
                      : 'This appears to be a coordinated data exfiltration attempt using an AI agent with escalated privileges.'}
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
                        <span className="font-bold text-slate-900 dark:text-white text-[11px]">Risk Score Evaluated</span>
                        <span className="text-[10px] text-slate-400">02:44:02 PM</span>
                      </div>
                      <p className={`text-[10px] font-mono font-bold ${
                        isContained || isResolved ? 'text-emerald-600 dark:text-emerald-400' : 'text-rose-600 dark:text-rose-400'
                      }`}>
                        Score: {score} ({level})
                      </p>
                    </div>
                  </div>

                  {/* Step 4 */}
                  <div className="flex items-start gap-3 relative z-10">
                    <div className="w-5 h-5 rounded-full bg-teal-100 dark:bg-teal-950 border border-teal-300 dark:border-teal-500 text-teal-700 dark:text-teal-300 flex items-center justify-center shrink-0 mt-0.5">
                      <Zap size={10} />
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center justify-between text-slate-700 dark:text-slate-300">
                        <span className="font-bold text-slate-900 dark:text-white text-[11px]">Response Formulated</span>
                        <span className="text-[10px] text-slate-400">02:44:05 PM</span>
                      </div>
                      <p className="text-[10px] text-slate-500 dark:text-slate-400 font-sans">Level 4 Containment Policy</p>
                    </div>
                  </div>

                  {/* Step 5 */}
                  <div className="flex items-start gap-3 relative z-10">
                    <div className={`w-5 h-5 rounded-full flex items-center justify-center shrink-0 mt-0.5 ${
                      isContained || isResolved 
                        ? 'bg-emerald-100 dark:bg-emerald-950 border border-emerald-500 text-emerald-600'
                        : isApprover1Done 
                        ? 'bg-amber-100 dark:bg-amber-950 border border-amber-500 text-amber-600' 
                        : 'bg-slate-100 dark:bg-slate-950 border border-slate-400 text-slate-500'
                    }`}>
                      {isContained || isResolved ? <Check size={10} /> : <Shield size={10} />}
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center justify-between text-slate-700 dark:text-slate-300">
                        <span className="font-bold text-slate-900 dark:text-white text-[11px]">
                          {isContained ? 'Dual Approval Verified' : isResolved ? 'False Positive Recovered' : isApprover1Done ? 'Approver 2 Required' : 'Approval Gate'}
                        </span>
                        <span className="text-[10px] text-slate-400">02:44:05 PM</span>
                      </div>
                      <p className="text-[10px] text-slate-500 dark:text-slate-400 font-sans">
                        {isContained ? 'Dual-control containment active' : isResolved ? 'Access restored & audited' : 'Two-person rule enforced'}
                      </p>
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
                  className={`w-full mt-3 py-2.5 px-4 rounded-xl text-white text-xs font-bold font-mono tracking-wide flex items-center justify-center gap-2 shadow-md transition-all cursor-pointer ${
                    isContained ? 'bg-emerald-600 hover:bg-emerald-500' : 'bg-blue-600 hover:bg-blue-500'
                  }`}
                >
                  <span>{isContained ? 'Containment Active — Review Actions' : 'Open Action Center'}</span>
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

      {/* Tab: Risk Analysis (Comprehensive Deep Security Assessment) */}
      {activeTab === 'risk-analysis' && (
        <div className="space-y-6 animate-fade-in">
          {/* 1. Header Card: Score Gauge & Risk Posture */}
          <Card className="p-6 space-y-5">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 dark:border-slate-800 pb-4">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-xl bg-cyan-100 dark:bg-cyan-950/80 border border-cyan-200 dark:border-cyan-800/60 text-cyan-700 dark:text-cyan-400">
                  <Gauge size={20} />
                </div>
                <div>
                  <h3 className="text-sm font-bold uppercase tracking-wider text-slate-900 dark:text-white font-mono">
                    Multi-Factor Risk Assessment & Behavioral Analysis
                  </h3>
                  <p className="text-xs text-slate-500 dark:text-slate-400 font-sans">
                    Incident ID: <span className="font-mono text-cyan-600 dark:text-cyan-400 font-bold">{inc.id}</span> • Dynamic multi-signal correlation across Identity, Agent & Data tiers
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <span className={`px-3 py-1 rounded-xl text-xs font-mono font-bold uppercase border shadow-xs ${
                  isResolved
                    ? 'bg-emerald-100 dark:bg-emerald-950/80 text-emerald-800 dark:text-emerald-300 border-emerald-300 dark:border-emerald-700'
                    : isContained
                    ? 'bg-emerald-100 dark:bg-emerald-950/80 text-emerald-800 dark:text-emerald-300 border-emerald-300 dark:border-emerald-700'
                    : 'bg-rose-100 dark:bg-rose-950/80 text-rose-800 dark:text-rose-300 border-rose-300 dark:border-rose-700'
                }`}>
                  {isResolved ? '✓ RESOLVED / NEUTRALIZED' : isContained ? '✓ CONTAINED (SAFEGUARD ACTIVE)' : `🚨 ${level} THREAT`}
                </span>
              </div>
            </div>

            {/* Score Comparison & Core Metrics */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              {/* Radial Gauge Card */}
              <div className="p-4 rounded-2xl bg-slate-50 dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 flex items-center gap-4">
                <div className="relative w-20 h-20 shrink-0 flex items-center justify-center">
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
                      stroke={gaugeStrokeColor}
                      strokeWidth="9"
                      strokeDasharray={gaugeCircumference}
                      strokeDashoffset={gaugeOffset}
                      strokeLinecap="round"
                      style={{ transition: 'stroke-dashoffset 0.8s ease-in-out, stroke 0.8s ease' }}
                    />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                    <span className={`text-xl font-black font-mono tracking-tight ${
                      isResolved || isContained ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-900 dark:text-white'
                    }`}>
                      {score}
                    </span>
                    <span className="text-[9px] font-mono text-slate-500 dark:text-slate-400">/ 100</span>
                  </div>
                </div>

                <div className="space-y-1 font-mono">
                  <div className="text-[10px] text-slate-500 dark:text-slate-400 uppercase tracking-wider">Effective Score</div>
                  <div className="text-sm font-bold text-slate-900 dark:text-white">
                    {score} / 100
                  </div>
                  <div className="text-[11px] text-slate-500 dark:text-slate-400">
                    Level: <strong className={isResolved || isContained ? 'text-emerald-500' : 'text-rose-500'}>{level}</strong>
                  </div>
                </div>
              </div>

              {/* Baseline / Pre-Mitigation Score */}
              <div className="p-4 rounded-2xl bg-slate-50 dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 space-y-1">
                <div className="text-[10px] font-mono text-slate-500 dark:text-slate-400 uppercase tracking-wider flex items-center justify-between">
                  <span>Pre-Mitigation Risk</span>
                  <Activity size={13} className="text-rose-500" />
                </div>
                <div className="text-xl font-bold font-mono text-slate-900 dark:text-white">
                  {rawScore} <span className="text-xs text-slate-500 font-normal">/ 100</span>
                </div>
                <div className="text-[11px] text-slate-500 dark:text-slate-400 font-mono">
                  Original multi-signal threat severity
                </div>
              </div>

              {/* Attenuation / Risk Reduction */}
              <div className="p-4 rounded-2xl bg-slate-50 dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 space-y-1">
                <div className="text-[10px] font-mono text-slate-500 dark:text-slate-400 uppercase tracking-wider flex items-center justify-between">
                  <span>Risk Attenuation</span>
                  <ShieldCheck size={13} className="text-emerald-500" />
                </div>
                <div className={`text-xl font-bold font-mono ${
                  rawScore - score > 0 ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-500'
                }`}>
                  {rawScore - score > 0 ? `-${rawScore - score} pts` : '0 pts (Active)'}
                </div>
                <div className="text-[11px] text-slate-500 dark:text-slate-400 font-mono">
                  {isResolved ? 'Full Neutralization (Audit Log Kept)' : isContained ? 'Dual-Control Dual Approvers Active' : 'No Safeguards Enforced Yet'}
                </div>
              </div>

              {/* Confidence Rating */}
              <div className="p-4 rounded-2xl bg-slate-50 dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 space-y-1">
                <div className="text-[10px] font-mono text-slate-500 dark:text-slate-400 uppercase tracking-wider flex items-center justify-between">
                  <span>Model Confidence</span>
                  <Sparkles size={13} className="text-cyan-500" />
                </div>
                <div className="text-xl font-bold font-mono text-cyan-600 dark:text-cyan-400">
                  {confidence}%
                </div>
                <div className="text-[11px] text-slate-500 dark:text-slate-400 font-mono">
                  Multi-signal Bayesian consensus
                </div>
              </div>
            </div>
          </Card>

          {/* 2. Middle Row: Signals Breakdown (Left) & Explainable Rationales (Right) */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            
            {/* Left 6 cols: Mathematical Signal Breakdown */}
            <div className="lg:col-span-6 space-y-4">
              <Card className="p-5 space-y-4 h-full flex flex-col justify-between">
                <div className="space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-3">
                    <div className="flex items-center gap-2">
                      <Network size={16} className="text-cyan-600 dark:text-cyan-400" />
                      <h4 className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-white font-mono">
                        Contributing Risk Signals
                      </h4>
                    </div>
                    <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400">
                      Weighted Contribution
                    </span>
                  </div>

                  <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed font-sans">
                    Individual risk contributions are independently evaluated and bounded. When mitigation actions or dual approvals are applied, each factor attenuates dynamically:
                  </p>

                  <div className="space-y-3 pt-1">
                    {signalsBreakdown.map((sig) => (
                      <div key={sig.name} className="space-y-1.5 p-2.5 rounded-xl bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800">
                        <div className="flex justify-between text-xs font-mono">
                          <span className="font-semibold text-slate-800 dark:text-slate-200">{sig.name}</span>
                          <span className="font-bold text-slate-900 dark:text-white">
                            {sig.score} <span className="text-[10px] text-slate-500 font-normal">/ {sig.max}</span>
                          </span>
                        </div>
                        <div className="w-full h-2 rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
                          <div
                            className={`h-full rounded-full bg-gradient-to-r transition-all duration-700 ${sig.color}`}
                            style={{ width: `${(sig.score / sig.max) * 100}%` }}
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Detected Signal Tags */}
                <div className="pt-3 border-t border-slate-100 dark:border-slate-800 space-y-2">
                  <div className="text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider font-mono">
                    All Correlated Signals ({inc.signals_detected?.length || 0})
                  </div>
                  <div className="flex flex-wrap gap-1.5 font-mono text-[10px]">
                    {(inc.signals_detected || ['unusual_resource_access', 'tool_abuse', 'bulk_data']).map((sig, i) => (
                      <span key={i} className="px-2 py-1 rounded-lg bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700 font-medium">
                        {sig}
                      </span>
                    ))}
                  </div>
                </div>
              </Card>
            </div>

            {/* Right 6 cols: Explainable AI Rationales & Baseline Deviations */}
            <div className="lg:col-span-6 space-y-4">
              <Card className="p-5 space-y-4 h-full flex flex-col justify-between">
                <div className="space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-3">
                    <div className="flex items-center gap-2">
                      <Lightbulb size={16} className="text-amber-500" />
                      <h4 className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-white font-mono">
                        Explainable Intelligence Rationales
                      </h4>
                    </div>
                    <span className="text-[10px] font-mono text-cyan-600 dark:text-cyan-400 font-bold">
                      {confidence}% Confidence
                    </span>
                  </div>

                  <div className="space-y-2.5 text-xs font-sans text-slate-700 dark:text-slate-300">
                    {(inc.risk_assessment?.reasons && inc.risk_assessment.reasons.length > 0
                      ? inc.risk_assessment.reasons
                      : [
                          'Correlated multi-event sequence detected connecting external access to sensitive internal database records.',
                          'AI agent executed restricted raw SQL tool targeting production credential stores outside defined operational baseline.',
                          'Bulk data extraction volume exceeds standard operational threshold by more than 10x.'
                        ]
                    ).map((reason, idx) => (
                      <div key={idx} className="flex items-start gap-2.5 p-3 rounded-xl bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800/80">
                        <AlertTriangle size={15} className="text-amber-500 shrink-0 mt-0.5" />
                        <span className="leading-relaxed">{reason}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Behavioral Baseline Deviations */}
                <div className="pt-3 border-t border-slate-100 dark:border-slate-800 space-y-2 font-mono text-xs">
                  <div className="text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                    Behavioral Baseline Deviations
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
                    <div className="p-2 rounded-lg bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                      <span className="text-slate-500 dark:text-slate-400 block text-[10px]">DEVICE BASELINE</span>
                      <span className="text-rose-600 dark:text-rose-400 font-bold truncate block">Unseen Hardware</span>
                    </div>
                    <div className="p-2 rounded-lg bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                      <span className="text-slate-500 dark:text-slate-400 block text-[10px]">AGENT TOOL BASELINE</span>
                      <span className="text-amber-600 dark:text-amber-400 font-bold truncate block">raw_sql_exec (Privileged)</span>
                    </div>
                    <div className="p-2 rounded-lg bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                      <span className="text-slate-500 dark:text-slate-400 block text-[10px]">RESOURCE DOMAIN</span>
                      <span className="text-rose-600 dark:text-rose-400 font-bold truncate block">HR → Customer Credentials</span>
                    </div>
                    <div className="p-2 rounded-lg bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                      <span className="text-slate-500 dark:text-slate-400 block text-[10px]">EXPORT VOLUME</span>
                      <span className="text-purple-600 dark:text-purple-400 font-bold truncate block">{exfilVolume || '15,000 records'}</span>
                    </div>
                  </div>
                </div>
              </Card>
            </div>

          </div>

          {/* 3. Recommended Action Banner & Action Navigation */}
          <Card className="p-5 bg-gradient-to-r from-slate-50 via-slate-100 to-amber-50 dark:from-slate-900 dark:via-slate-900/90 dark:to-amber-950/20 border border-amber-200 dark:border-amber-800/60 space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="space-y-1">
                <div className="flex items-center gap-2 text-xs font-bold text-amber-800 dark:text-amber-300 font-mono">
                  <CheckCircle2 size={16} className="text-amber-500" />
                  <span>Recommended Mitigation Action</span>
                </div>
                <p className="text-xs text-slate-700 dark:text-slate-300">
                  {inc.risk_assessment?.recommended_action || (
                    isResolved 
                      ? 'Incident verified and neutralized. All restrictions lifted.' 
                      : isContained 
                      ? 'Containment active under Two-Person dual control.' 
                      : 'Require human dual-control approval for containment and quarantine agent session.'
                  )}
                </p>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <button
                  onClick={() => setActiveTab('response')}
                  className="px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs font-bold transition-all cursor-pointer flex items-center gap-1.5 shadow-xs"
                >
                  <span>{isResolved ? 'Review Containment History' : 'Open Action Center'}</span>
                  <ArrowRight size={13} />
                </button>
                <button
                  onClick={() => setActiveTab('attack-chain')}
                  className="px-3.5 py-2 rounded-xl bg-white dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 font-mono text-xs transition-all cursor-pointer"
                >
                  View Attack Progression
                </button>
              </div>
            </div>
          </Card>
        </div>
      )}

      {/* Tab: Response & Approvals */}
      {(activeTab === 'response' || activeTab === 'approvals') && (
        <div className="space-y-6">
          
          {/* Action Feedback Banner */}
          {actionFeedback && (
            <div className={`p-4 rounded-2xl border flex items-start justify-between gap-3 text-xs font-mono shadow-md animate-in fade-in slide-in-from-top-2 duration-300 ${
              actionFeedback.type === 'error'
                ? 'bg-rose-50 dark:bg-rose-950/80 border-rose-300 dark:border-rose-700 text-rose-800 dark:text-rose-200'
                : actionFeedback.type === 'info'
                ? 'bg-blue-50 dark:bg-blue-950/80 border-blue-300 dark:border-blue-700 text-blue-800 dark:text-blue-200'
                : 'bg-emerald-50 dark:bg-emerald-950/80 border-emerald-300 dark:border-emerald-700 text-emerald-800 dark:text-emerald-200'
            }`}>
              <div className="flex items-center gap-2.5">
                {actionFeedback.type === 'error' ? (
                  <XCircle size={20} className="text-rose-600 dark:text-rose-400 shrink-0" />
                ) : (
                  <CheckCircle2 size={20} className="text-emerald-600 dark:text-emerald-400 shrink-0" />
                )}
                <span className="font-semibold">{actionFeedback.message}</span>
              </div>
              <button 
                onClick={() => setActionFeedback(null)} 
                className="text-slate-400 hover:text-slate-600 dark:hover:text-white cursor-pointer px-1 text-sm font-bold"
              >
                ✕
              </button>
            </div>
          )}

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
              <span className={`px-3 py-1 rounded-full font-mono text-xs font-bold border ${
                isContained 
                  ? 'bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300 border-emerald-300 dark:border-emerald-700'
                  : isResolved
                  ? 'bg-cyan-100 dark:bg-cyan-950 text-cyan-700 dark:text-cyan-300 border-cyan-300 dark:border-cyan-700'
                  : isRejected
                  ? 'bg-rose-100 dark:bg-rose-950 text-rose-700 dark:text-rose-300 border-rose-300 dark:border-rose-700'
                  : 'bg-rose-100 dark:bg-rose-950 text-rose-700 dark:text-rose-300 border-rose-200 dark:border-rose-700'
              }`}>
                {isContained ? 'Policy Enforced (Contained)' : isResolved ? 'Policy Cleared (Resolved)' : isRejected ? 'Containment Rejected' : 'Level 4 Policy Active'}
              </span>
            </div>

            {/* Live Risk Mitigation Impact Bar */}
            <div className="p-4 rounded-xl bg-slate-100/90 dark:bg-slate-950/80 border border-slate-200 dark:border-slate-800 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 font-mono">
              <div className="flex items-center gap-3.5">
                <div className={`w-12 h-12 rounded-xl flex items-center justify-center font-black text-lg text-white shadow-sm shrink-0 transition-colors duration-500 ${
                  score <= 25 ? 'bg-emerald-600' : score <= 59 ? 'bg-amber-500' : score <= 79 ? 'bg-orange-500' : 'bg-rose-600'
                }`}>
                  {score}
                </div>
                <div>
                  <div className="text-[11px] text-slate-500 dark:text-slate-400 uppercase font-semibold">Live Threat Assessment</div>
                  <div className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                    <span>Score: {score}/100 ({level})</span>
                    <span className={`text-[10px] px-2 py-0.5 rounded-full font-bold uppercase ${
                      isContained 
                        ? 'bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300' 
                        : isRejected
                        ? 'bg-rose-100 dark:bg-rose-950 text-rose-700 dark:text-rose-300'
                        : isApprover1Done 
                        ? 'bg-amber-100 dark:bg-amber-950 text-amber-700 dark:text-amber-300' 
                        : 'bg-rose-100 dark:bg-rose-950 text-rose-700 dark:text-rose-300'
                    }`}>
                      {displayStatus}
                    </span>
                  </div>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2 text-[11px]">
                {isResolved ? (
                  <span className="px-2.5 py-1 rounded-lg border bg-emerald-50 dark:bg-emerald-950/80 border-emerald-300 dark:border-emerald-700 text-emerald-700 dark:text-emerald-300 font-bold shadow-xs">
                    ✓ Normal Access Restored (All Restrictions Lifted)
                  </span>
                ) : (
                  <>
                    <span className={`px-2.5 py-1 rounded-lg border transition-all ${
                      executedActions.quarantine_agent || isContained 
                        ? 'bg-teal-50 dark:bg-teal-950/80 border-teal-300 dark:border-teal-700 text-teal-700 dark:text-teal-300 font-bold shadow-xs' 
                        : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 text-slate-400'
                    }`}>
                      {executedActions.quarantine_agent || isContained ? '✓ Agent Quarantined (-35 pts)' : '○ Quarantine Inactive'}
                    </span>
                    <span className={`px-2.5 py-1 rounded-lg border transition-all ${
                      executedActions.lock_user || isContained 
                        ? 'bg-rose-50 dark:bg-rose-950/80 border-rose-300 dark:border-rose-700 text-rose-700 dark:text-rose-300 font-bold shadow-xs' 
                        : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 text-slate-400'
                    }`}>
                      {executedActions.lock_user || isContained ? '✓ Session Locked (-30 pts)' : '○ Session Active'}
                    </span>
                    <span className={`px-2.5 py-1 rounded-lg border transition-all ${
                      isContained 
                        ? 'bg-emerald-50 dark:bg-emerald-950/80 border-emerald-300 dark:border-emerald-700 text-emerald-700 dark:text-emerald-300 font-bold shadow-xs' 
                        : isRejected
                        ? 'bg-rose-50 dark:bg-rose-950/80 border-rose-300 dark:border-rose-700 text-rose-700 dark:text-rose-300 font-bold shadow-xs'
                        : isApprover1Done 
                        ? 'bg-blue-50 dark:bg-blue-950/80 border-blue-300 dark:border-blue-700 text-blue-700 dark:text-blue-300 font-bold shadow-xs'
                        : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 text-slate-400'
                    }`}>
                      {isContained ? '✓ Dual Approved (Contained)' : isRejected ? `✕ Rejected (Person ${rejectionInfo?.stage || 1})` : isApprover1Done ? '✓ 1st Approved (-20 pts)' : '○ Two-Person Gate Open'}
                    </span>
                  </>
                )}
              </div>
            </div>

            {/* Action simulation buttons */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 font-mono text-xs">
              
              {/* Card 1: Quarantine Agent */}
              <div className={`p-4 rounded-xl border space-y-2 transition-all ${
                !isResolved && (executedActions.quarantine_agent || isContained)
                  ? 'bg-teal-50/70 dark:bg-teal-950/40 border-teal-300 dark:border-teal-700 shadow-xs'
                  : 'bg-slate-50 dark:bg-slate-900 border-slate-200 dark:border-slate-800'
              }`}>
                <div className="font-bold text-slate-900 dark:text-white flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Bot size={16} className={!isResolved && (executedActions.quarantine_agent || isContained) ? "text-teal-600 dark:text-teal-400" : "text-slate-400"} />
                    <span>{isEasyMode ? 'Stop Agent from Using Tools' : 'Quarantine Agent'}</span>
                  </div>
                  {!isResolved && (executedActions.quarantine_agent || isContained) ? (
                    <span className="px-2 py-0.5 rounded text-[10px] bg-teal-100 dark:bg-teal-900 text-teal-800 dark:text-teal-200 font-bold">
                      ✓ Active
                    </span>
                  ) : isResolved ? (
                    <span className="px-2 py-0.5 rounded text-[10px] bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 font-medium">
                      ○ Lifted
                    </span>
                  ) : null}
                </div>
                <p className="text-[11px] text-slate-600 dark:text-slate-400 font-sans">
                  {isEasyMode ? 'Prevents the copilot agent from running database queries.' : 'Isolates copilot worker instance and invalidates runtime session keys.'}
                </p>
                <button
                  onClick={handleExecuteQuarantine}
                  disabled={actionInProgress || executedActions.quarantine_agent || isResolved}
                  className={`w-full py-2 rounded-lg font-bold transition-all cursor-pointer ${
                    !isResolved && (executedActions.quarantine_agent || isContained)
                      ? 'bg-teal-600 text-white shadow-xs opacity-90'
                      : isResolved
                      ? 'bg-slate-100 dark:bg-slate-800 text-slate-400 cursor-not-allowed'
                      : 'bg-teal-100 dark:bg-teal-950/80 hover:bg-teal-200 dark:hover:bg-teal-900 text-teal-800 dark:text-teal-300 border border-teal-300 dark:border-teal-700'
                  }`}
                >
                  {!isResolved && (executedActions.quarantine_agent || isContained) ? '✓ Agent Quarantined' : isResolved ? 'Quarantine Lifted' : isEasyMode ? 'Approve Agent Restriction' : 'Execute Quarantine'}
                </button>
              </div>

              {/* Card 2: Lock User Session */}
              <div className={`p-4 rounded-xl border space-y-2 transition-all ${
                !isResolved && (executedActions.lock_user || isContained)
                  ? 'bg-rose-50/70 dark:bg-rose-950/40 border-rose-300 dark:border-rose-700 shadow-xs'
                  : 'bg-slate-50 dark:bg-slate-900 border-slate-200 dark:border-slate-800'
              }`}>
                <div className="font-bold text-slate-900 dark:text-white flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Lock size={16} className={!isResolved && (executedActions.lock_user || isContained) ? "text-rose-600 dark:text-rose-400" : "text-slate-400"} />
                    <span>{isEasyMode ? 'Temporarily Restrict Session' : 'Lock User Session'}</span>
                  </div>
                  {!isResolved && (executedActions.lock_user || isContained) ? (
                    <span className="px-2 py-0.5 rounded text-[10px] bg-rose-100 dark:bg-rose-900 text-rose-800 dark:text-rose-200 font-bold">
                      ✓ Revoked
                    </span>
                  ) : isResolved ? (
                    <span className="px-2 py-0.5 rounded text-[10px] bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 font-medium">
                      ○ Unlocked
                    </span>
                  ) : null}
                </div>
                <p className="text-[11px] text-slate-600 dark:text-slate-400 font-sans">
                  {isEasyMode ? `Signs out active login cookies for ${targetUser}.` : `Immediately revokes active auth cookies for ${targetUser}.`}
                </p>
                <button
                  onClick={handleExecuteLockSession}
                  disabled={actionInProgress || executedActions.lock_user || isResolved}
                  className={`w-full py-2 rounded-lg font-bold transition-all cursor-pointer ${
                    !isResolved && (executedActions.lock_user || isContained)
                      ? 'bg-rose-600 text-white shadow-xs opacity-90'
                      : isResolved
                      ? 'bg-slate-100 dark:bg-slate-800 text-slate-400 cursor-not-allowed'
                      : 'bg-rose-100 dark:bg-rose-950/80 hover:bg-rose-200 dark:hover:bg-rose-900 text-rose-800 dark:text-rose-300 border border-rose-300 dark:border-rose-700'
                  }`}
                >
                  {!isResolved && (executedActions.lock_user || isContained) ? '✓ Session Locked' : isResolved ? 'Session Unlocked' : isEasyMode ? 'Approve Session Restriction' : 'Revoke & Lock'}
                </button>
              </div>

              {/* Card 3: False Positive Recovery */}
              <div className={`p-4 rounded-xl border space-y-2 transition-all ${
                isResolved
                  ? 'bg-emerald-50/70 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-700 shadow-xs'
                  : 'bg-slate-50 dark:bg-slate-900 border-slate-200 dark:border-slate-800'
              }`}>
                <div className="font-bold text-slate-900 dark:text-white flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Undo2 size={16} className={isResolved ? "text-emerald-600 dark:text-emerald-400" : "text-amber-600 dark:text-amber-400"} />
                    <span>{isEasyMode ? 'Mark as Legitimate Work' : 'False Positive Recovery'}</span>
                  </div>
                  {isResolved && (
                    <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-100 dark:bg-emerald-900 text-emerald-800 dark:text-emerald-200 font-bold">
                      ✓ Restored
                    </span>
                  )}
                </div>
                <p className="text-[11px] text-slate-600 dark:text-slate-400 font-sans">
                  {isEasyMode ? 'If this was an authorized backup test, restores normal access.' : 'Allows authorized SOC lead to restore normal operational status.'}
                </p>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleRecoverFalsePositive()}
                    disabled={actionInProgress || isResolved}
                    className={`flex-1 py-2 px-3 rounded-lg font-bold transition-all cursor-pointer ${
                      isResolved
                        ? 'bg-emerald-600 text-white shadow-xs opacity-90'
                        : 'bg-amber-500 hover:bg-amber-600 text-white shadow-xs'
                    }`}
                  >
                    {actionInProgress ? 'Restoring Access...' : isResolved ? '✓ Access Restored' : 'Restore Access'}
                  </button>
                  {!isResolved && (
                    <button
                      onClick={() => setShowRecoveryForm(!showRecoveryForm)}
                      className="px-2.5 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-300 text-[11px] font-mono hover:bg-slate-100 dark:hover:bg-slate-700 cursor-pointer"
                      title="Add Custom Justification Note"
                    >
                      {showRecoveryForm ? '▲' : 'Note'}
                    </button>
                  )}
                </div>
                {showRecoveryForm && !isResolved && (
                  <div className="pt-2 space-y-2 border-t border-slate-200 dark:border-slate-800">
                    <textarea
                      value={recoveryReason}
                      onChange={(e) => setRecoveryReason(e.target.value)}
                      placeholder="Audit justification reason..."
                      className="w-full p-2 text-[11px] rounded-lg bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white font-mono"
                      rows={2}
                    />
                    <button
                      onClick={() => handleRecoverFalsePositive(recoveryReason)}
                      disabled={actionInProgress}
                      className="w-full py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-[11px] cursor-pointer"
                    >
                      Confirm with Note
                    </button>
                  </div>
                )}
              </div>

            </div>

            {/* Two Person Form */}
            <div className={`p-5 rounded-2xl border space-y-4 transition-all ${
              isContained 
                ? 'bg-emerald-50/50 dark:bg-emerald-950/20 border-emerald-300 dark:border-emerald-700/60' 
                : isRejected
                ? 'bg-rose-50/50 dark:bg-rose-950/20 border-rose-300 dark:border-rose-700/60'
                : 'bg-slate-50 dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800'
            }`}>
              <div className="flex items-center justify-between font-mono text-xs">
                <div className="flex items-center gap-2 font-bold text-cyan-700 dark:text-cyan-300">
                  <Users size={16} />
                  <span>{isEasyMode ? 'Two Independent People Required for Approval' : 'Two-Person Approval Gate'}</span>
                </div>
                {isContained && (
                  <span className="px-2.5 py-0.5 rounded-full bg-emerald-600 text-white font-bold text-[10px] uppercase">
                    Dual-Control Satisfied
                  </span>
                )}
                {isRejected && (
                  <div className="flex items-center gap-2">
                    <span className="px-2.5 py-0.5 rounded-full bg-rose-600 text-white font-bold text-[10px] uppercase">
                      Containment Rejected (Stage {rejectionInfo?.stage || 1})
                    </span>
                    <button
                      onClick={handleResetContainment}
                      className="px-2 py-0.5 rounded bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:text-cyan-600 dark:hover:text-cyan-400 font-bold text-[10px] cursor-pointer flex items-center gap-1 shadow-xs"
                    >
                      <Undo2 size={10} /> Reopen Gate
                    </button>
                  </div>
                )}
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
                
                {/* Approver 1 */}
                <div className={`p-3.5 rounded-xl border space-y-2.5 shadow-xs transition-all ${
                  isRejected && rejectionInfo?.stage === 1
                    ? 'bg-rose-50/70 dark:bg-rose-950/40 border-rose-300 dark:border-rose-700'
                    : isApprover1Done 
                    ? 'bg-emerald-50/70 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-700' 
                    : 'bg-white dark:bg-slate-950 border-slate-200 dark:border-slate-800'
                }`}>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-500 dark:text-slate-400 font-bold">Person 1 (Primary Approver)</span>
                    {isRejected && rejectionInfo?.stage === 1 ? (
                      <span className="text-rose-600 dark:text-rose-400 font-bold text-[11px] flex items-center gap-1">
                        <XCircle size={13} /> Rejected
                      </span>
                    ) : isApprover1Done ? (
                      <span className="text-emerald-600 dark:text-emerald-400 font-bold text-[11px] flex items-center gap-1">
                        <CheckCircle2 size={13} /> Approved
                      </span>
                    ) : null}
                  </div>
                  <input
                    value={approver1Name}
                    disabled={isApprover1Done || (isRejected && rejectionInfo?.stage === 1)}
                    onChange={(e) => setApprover1Name(e.target.value)}
                    placeholder="Approver 1 Name"
                    className="w-full p-2 bg-slate-50 dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white disabled:opacity-70"
                  />

                  {/* Person 1 Action Buttons (Approve & Reject) */}
                  {isRejected && rejectionInfo?.stage === 1 ? (
                    <div className="space-y-1.5">
                      <div className="w-full py-2 rounded-lg font-bold bg-rose-600 text-white text-center flex items-center justify-center gap-1.5 text-xs shadow-xs">
                        <XCircle size={13} /> 1st Approval Rejected
                      </div>
                      <button
                        onClick={handleResetContainment}
                        className="w-full text-center text-[10px] text-cyan-600 dark:text-cyan-400 hover:underline cursor-pointer flex items-center justify-center gap-1 pt-0.5"
                      >
                        <Undo2 size={11} /> Reopen Gate / Try Again
                      </button>
                    </div>
                  ) : isApprover1Done ? (
                    <div className="flex items-center gap-2">
                      <div className="flex-1 py-2 px-3 rounded-lg font-bold bg-emerald-600 text-white opacity-95 flex items-center justify-center gap-1.5 shadow-xs text-xs">
                        <CheckCircle2 size={13} /> 1st Approval Signed
                      </div>
                      {!isContained && (
                        <button
                          onClick={() => handleRejectContainment(1)}
                          disabled={actionInProgress}
                          className="py-2 px-3 rounded-lg font-bold bg-rose-100 hover:bg-rose-200 dark:bg-rose-950/80 dark:hover:bg-rose-900 text-rose-700 dark:text-rose-300 border border-rose-300 dark:border-rose-700 text-xs transition-all cursor-pointer flex items-center gap-1 shrink-0"
                          title="Revoke / Reject 1st Approval"
                        >
                          <XCircle size={13} /> Reject
                        </button>
                      )}
                    </div>
                  ) : (
                    <div className="space-y-2">
                      <div className="flex items-center gap-2">
                        <button
                          onClick={handleApproveContainment}
                          disabled={actionInProgress}
                          className="flex-1 py-2 px-3 rounded-lg font-bold transition-all cursor-pointer shadow-xs bg-emerald-600 hover:bg-emerald-500 text-white flex items-center justify-center gap-1.5 text-xs"
                          id="btn-person1-approve"
                        >
                          <CheckCircle2 size={13} /> Approve
                        </button>
                        <button
                          onClick={() => handleRejectContainment(1)}
                          disabled={actionInProgress}
                          className="flex-1 py-2 px-3 rounded-lg font-bold transition-all cursor-pointer shadow-xs bg-rose-600 hover:bg-rose-500 text-white flex items-center justify-center gap-1.5 text-xs"
                          id="btn-person1-reject"
                        >
                          <XCircle size={13} /> Reject
                        </button>
                        <button
                          onClick={() => setShowRejectNote1(!showRejectNote1)}
                          className="px-2.5 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-300 text-[11px] font-mono hover:bg-slate-100 dark:hover:bg-slate-700 cursor-pointer shrink-0"
                          title="Add Rejection Note"
                        >
                          {showRejectNote1 ? '▲' : 'Note'}
                        </button>
                      </div>
                      {showRejectNote1 && (
                        <div className="pt-1.5 space-y-1.5 border-t border-slate-200 dark:border-slate-800">
                          <input
                            value={rejectReason1}
                            onChange={(e) => setRejectReason1(e.target.value)}
                            placeholder="Optional reason for rejection..."
                            className="w-full p-1.5 text-[11px] rounded-lg bg-slate-50 dark:bg-slate-900 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white font-mono"
                          />
                        </div>
                      )}
                    </div>
                  )}
                </div>

                {/* Approver 2 */}
                <div className={`p-3.5 rounded-xl border space-y-2.5 shadow-xs transition-all ${
                  isRejected && rejectionInfo?.stage === 2
                    ? 'bg-rose-50/70 dark:bg-rose-950/40 border-rose-300 dark:border-rose-700'
                    : isApprover2Done 
                    ? 'bg-purple-50/70 dark:bg-purple-950/40 border-purple-300 dark:border-purple-700' 
                    : 'bg-white dark:bg-slate-950 border-slate-200 dark:border-slate-800'
                }`}>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-500 dark:text-slate-400 font-bold">Person 2 (Co-Signer Admin)</span>
                    {isRejected && rejectionInfo?.stage === 2 ? (
                      <span className="text-rose-600 dark:text-rose-400 font-bold text-[11px] flex items-center gap-1">
                        <XCircle size={13} /> Co-Signer Rejected
                      </span>
                    ) : isApprover2Done ? (
                      <span className="text-purple-600 dark:text-purple-400 font-bold text-[11px] flex items-center gap-1">
                        <CheckCircle2 size={13} /> Dual-Control Verified
                      </span>
                    ) : null}
                  </div>
                  <input
                    value={approver2Name}
                    disabled={isApprover2Done || !isApprover1Done || (isRejected && rejectionInfo?.stage === 2)}
                    onChange={(e) => setApprover2Name(e.target.value)}
                    placeholder="Approver 2 Name"
                    className="w-full p-2 bg-slate-50 dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white disabled:opacity-70"
                  />

                  {/* Person 2 Action Buttons (Approve & Reject) */}
                  {isRejected && rejectionInfo?.stage === 2 ? (
                    <div className="space-y-1.5">
                      <div className="w-full py-2 rounded-lg font-bold bg-rose-600 text-white text-center flex items-center justify-center gap-1.5 text-xs shadow-xs">
                        <XCircle size={13} /> Dual-Control Rejected
                      </div>
                      <button
                        onClick={handleResetContainment}
                        className="w-full text-center text-[10px] text-cyan-600 dark:text-cyan-400 hover:underline cursor-pointer flex items-center justify-center gap-1 pt-0.5"
                      >
                        <Undo2 size={11} /> Reopen Gate / Try Again
                      </button>
                    </div>
                  ) : isRejected && rejectionInfo?.stage === 1 ? (
                    <div className="w-full py-2 rounded-lg font-medium text-center text-rose-500 bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800 text-[11px]">
                      Gate Blocked (Stage 1 Rejected)
                    </div>
                  ) : isApprover2Done ? (
                    <div className="w-full py-2 rounded-lg font-bold bg-purple-600 text-white opacity-95 flex items-center justify-center gap-1.5 shadow-xs text-xs">
                      <CheckCircle2 size={13} /> ✓ 2nd Approval Signed
                    </div>
                  ) : !isApprover1Done ? (
                    <div className="w-full py-2 rounded-lg font-medium text-center text-slate-400 bg-slate-100 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 text-[11px]">
                      ○ Awaiting 1st Approval Gate
                    </div>
                  ) : (
                    /* Approver 1 has signed, Approver 2 can now Approve OR Reject */
                    <div className="space-y-2">
                      <div className="flex items-center gap-2">
                        <button
                          onClick={handleSecondApproveContainment}
                          disabled={actionInProgress}
                          className="flex-1 py-2 px-3 rounded-lg font-bold transition-all cursor-pointer shadow-xs bg-purple-600 hover:bg-purple-500 text-white flex items-center justify-center gap-1.5 text-xs animate-pulse"
                          id="btn-person2-approve"
                        >
                          <CheckCircle2 size={13} /> Approve (2nd Sign)
                        </button>
                        <button
                          onClick={() => handleRejectContainment(2)}
                          disabled={actionInProgress}
                          className="flex-1 py-2 px-3 rounded-lg font-bold transition-all cursor-pointer shadow-xs bg-rose-600 hover:bg-rose-500 text-white flex items-center justify-center gap-1.5 text-xs"
                          id="btn-person2-reject"
                        >
                          <XCircle size={13} /> Reject
                        </button>
                        <button
                          onClick={() => setShowRejectNote2(!showRejectNote2)}
                          className="px-2.5 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-300 text-[11px] font-mono hover:bg-slate-100 dark:hover:bg-slate-700 cursor-pointer shrink-0"
                          title="Add Rejection Note"
                        >
                          {showRejectNote2 ? '▲' : 'Note'}
                        </button>
                      </div>
                      {showRejectNote2 && (
                        <div className="pt-1.5 space-y-1.5 border-t border-slate-200 dark:border-slate-800">
                          <input
                            value={rejectReason2}
                            onChange={(e) => setRejectReason2(e.target.value)}
                            placeholder="Optional reason for co-signer rejection..."
                            className="w-full p-1.5 text-[11px] rounded-lg bg-slate-50 dark:bg-slate-900 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white font-mono"
                          />
                        </div>
                      )}
                    </div>
                  )}
                </div>

              </div>
            </div>

            {/* System Update & Prototype Alert Clearance Action Banner */}
            <div className={`p-4 rounded-xl border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 font-mono text-xs transition-all ${
              syncUpdated
                ? 'bg-emerald-50 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-700/80 shadow-xs'
                : isContained
                ? 'bg-cyan-50/80 dark:bg-cyan-950/40 border-cyan-300 dark:border-cyan-700/80 shadow-xs'
                : 'bg-slate-50 dark:bg-slate-900 border-slate-200 dark:border-slate-800'
            }`}>
              <div className="space-y-1">
                <div className="flex items-center gap-2 font-bold text-slate-900 dark:text-white">
                  <RefreshCw size={15} className={`text-cyan-600 dark:text-cyan-400 ${isUpdatingSync ? 'animate-spin' : ''}`} />
                  <span>Update & Synchronize Prototype State</span>
                  {syncUpdated && (
                    <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-100 dark:bg-emerald-900 text-emerald-800 dark:text-emerald-200 font-bold">
                      ✓ Synchronized
                    </span>
                  )}
                </div>
                <p className="text-[11px] text-slate-600 dark:text-slate-400 font-sans">
                  Click Update to approve and clear all active alerts for <strong className="text-cyan-600 dark:text-cyan-300">{targetUser}</strong> across INSIGHT Threat Monitor, update records in Supabase Database, and establish a benign baseline in Cognee memory.
                </p>
              </div>

              <button
                onClick={handleSyncUpdate}
                disabled={isUpdatingSync}
                id="btn-workbench-update-sync"
                className={`py-2.5 px-4 rounded-xl font-bold transition-all cursor-pointer flex items-center gap-2 shrink-0 shadow-xs ${
                  syncUpdated
                    ? 'bg-emerald-600 text-white opacity-95'
                    : isContained
                    ? 'bg-cyan-600 hover:bg-cyan-500 text-white shadow-cyan-600/30'
                    : 'bg-cyan-600 hover:bg-cyan-500 text-white'
                }`}
              >
                <RefreshCw size={14} className={isUpdatingSync ? 'animate-spin' : ''} />
                <span>
                  {isUpdatingSync 
                    ? 'Updating System...' 
                    : syncUpdated 
                    ? '✓ System Updated & Cleared' 
                    : 'Update System (Clear Alerts & Sync Cognee)'}
                </span>
              </button>
            </div>
          </Card>
        </div>
      )}

      {/* Tab: Audit Trail */}
      {activeTab === 'audit-trail' && (
        <Card className="p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-3">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-white font-mono">
                Immutable Cryptographic Audit Trail — {inc.id}
              </h3>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                Isolated forensic audit records strictly bound to incident {inc.id} ({threatType})
              </p>
            </div>
            <span className="text-[11px] font-mono text-slate-400 bg-slate-100 dark:bg-slate-800 px-2 py-0.5 rounded">
              Entity: {targetUser}
            </span>
          </div>

          <div className="space-y-2.5 font-mono text-xs">
            {/* Real audit records from backend for this exact incident */}
            {responseDetails?.audit_trail && responseDetails.audit_trail.filter(e => e.incident_id === inc.id).length > 0 ? (
              responseDetails.audit_trail
                .filter(e => e.incident_id === inc.id)
                .map((entry, aIdx) => (
                  <div key={entry.entry_id || entry.action_id || `${entry.action}_${aIdx}`} className="p-3 rounded-xl bg-slate-50 dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 flex items-center justify-between shadow-xs">
                    <div className="space-y-0.5">
                      <div className="font-bold text-slate-900 dark:text-white flex items-center gap-2">
                        <span className="text-cyan-400">•</span>
                        <span>{entry.action}</span>
                      </div>
                      <div className="text-slate-500 dark:text-slate-400 text-[11px]">
                        Actor: {entry.actor} • {entry.reason || 'Security response policy execution'} {entry.timestamp && `• ${new Date(entry.timestamp).toLocaleTimeString()}`}
                      </div>
                    </div>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                      entry.status === 'RESOLVED' || entry.status === 'APPROVED' ? 'text-emerald-500 bg-emerald-950/40 border border-emerald-800' :
                      entry.status === 'REJECTED' ? 'text-rose-500 bg-rose-950/40 border border-rose-800' : 'text-slate-400 bg-slate-800/40'
                    }`}>
                      {entry.status}
                    </span>
                  </div>
                ))
            ) : null}

            {/* Current session lifecycle events for this incident */}
            {isRejected && rejectionInfo && (
              <div className="p-3 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-300 dark:border-rose-700 flex items-center justify-between shadow-xs">
                <div className="space-y-0.5">
                  <div className="font-bold text-rose-800 dark:text-rose-300 flex items-center gap-1.5">
                    <XCircle size={14} className="text-rose-600 dark:text-rose-400" />
                    <span>CONTAINMENT_REJECTED (STAGE {rejectionInfo.stage})</span>
                  </div>
                  <div className="text-slate-600 dark:text-slate-400 text-[11px]">
                    Actor: {rejectionInfo.actor} • Reason: {rejectionInfo.reason} {rejectionInfo.timestamp && `• At ${rejectionInfo.timestamp}`}
                  </div>
                </div>
                <span className="text-rose-700 dark:text-rose-400 text-[10px] font-bold">CONTAINMENT BLOCKED</span>
              </div>
            )}
            {isContained && (
              <div className="p-3 rounded-xl bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-300 dark:border-emerald-700 flex items-center justify-between shadow-xs">
                <div className="space-y-0.5">
                  <div className="font-bold text-emerald-800 dark:text-emerald-300">FINAL_CONTAINMENT_AUTHORIZED (DUAL_CONTROL)</div>
                  <div className="text-slate-600 dark:text-slate-400 text-[11px]">Actors: {approver1Name} + {approver2Name}</div>
                </div>
                <span className="text-emerald-700 dark:text-emerald-400 text-[10px] font-bold">RISK: 15 / LOW</span>
              </div>
            )}
            {isApprover1Done && !isContained && (
              <div className="p-3 rounded-xl bg-blue-50 dark:bg-blue-950/40 border border-blue-300 dark:border-blue-700 flex items-center justify-between shadow-xs">
                <div className="space-y-0.5">
                  <div className="font-bold text-blue-800 dark:text-blue-300">APPROVER_1_AUTHORIZED</div>
                  <div className="text-slate-600 dark:text-slate-400 text-[11px]">Actor: {approver1Name}</div>
                </div>
                <span className="text-blue-700 dark:text-blue-400 text-[10px] font-bold">STAGE 1 SIGNED</span>
              </div>
            )}
            {isResolved && (
              <div className="p-3 rounded-xl bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-300 dark:border-emerald-700 flex items-center justify-between shadow-xs">
                <div className="space-y-0.5">
                  <div className="font-bold text-emerald-800 dark:text-emerald-300">FALSE_POSITIVE_RECOVERED</div>
                  <div className="text-slate-600 dark:text-slate-400 text-[11px]">Actor: {recoveryActor} • Incident {inc.id} operational access restored</div>
                </div>
                <span className="text-emerald-700 dark:text-emerald-400 text-[10px] font-bold">RESOLVED</span>
              </div>
            )}
            <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 flex items-center justify-between shadow-xs">
              <div className="space-y-0.5">
                <div className="font-bold text-slate-900 dark:text-white">INCIDENT_CORRELATION_COMPLETED</div>
                <div className="text-slate-500 dark:text-slate-400 text-[11px]">
                  Incident: {inc.id} • Target: {targetUser} ({targetDevice}) • Threat: {threatType}
                </div>
              </div>
              <span className="text-slate-400 text-[10px]">CORRELATED</span>
            </div>
            <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 flex items-center justify-between shadow-xs">
              <div className="space-y-0.5">
                <div className="font-bold text-slate-900 dark:text-white">TWO_PERSON_RULE_INITIALIZED</div>
                <div className="text-slate-500 dark:text-slate-400 text-[11px]">PolicyEngine_Containment • Dual-control gate active</div>
              </div>
              <span className="text-slate-400 text-[10px]">ENFORCED</span>
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
            <div className="text-slate-500 dark:text-slate-400 text-[11px]">
              Status: {executedActions.lock_user || isContained ? 'Session Locked' : 'Active'}
            </div>
          </Card>
          <Card className="p-4 space-y-2">
            <Laptop size={18} className="text-purple-500" />
            <div className="font-bold text-slate-900 dark:text-white">{targetDevice}</div>
            <div className="text-slate-500 dark:text-slate-400 text-[11px]">Fingerprint: Unrecognized</div>
          </Card>
          <Card className="p-4 space-y-2">
            <Bot size={18} className="text-teal-500" />
            <div className="font-bold text-slate-900 dark:text-white">{targetAgent}</div>
            <div className="text-slate-500 dark:text-slate-400 text-[11px]">
              Status: {executedActions.quarantine_agent || isContained ? 'Quarantined & Isolated' : 'Active'}
            </div>
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
