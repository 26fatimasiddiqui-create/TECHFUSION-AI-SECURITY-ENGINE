import React, { useState, useMemo } from 'react';
import { 
  User, 
  Monitor, 
  Bot, 
  Network as NetworkIcon, 
  Database, 
  AlertTriangle, 
  ArrowRight,
  Shield,
  Layers,
  ChevronRight,
  Sparkles,
  CheckCircle2,
  Info,
  Laptop,
  X
} from 'lucide-react';

// Default baseline nodes used if events are not yet loaded
const DEFAULT_NODES = {
  a_verma: {
    id: 'a_verma',
    name: 'A. Verma',
    role: 'Employee',
    status: 'normal',
    type: 'user',
    x: 70,
    y: 65,
    r: 24,
    icon: User,
    details: 'Standard employee authentication from verified corporate hardware. Normal baseline profile.',
  },
  j_singh: {
    id: 'j_singh',
    name: 'J. Singh',
    role: 'Analyst',
    status: 'malicious',
    type: 'user',
    x: 70,
    y: 180,
    r: 24,
    icon: User,
    details: 'Unusual login detected outside normal working hours from an unverified geographic location.',
  },
  r_khan: {
    id: 'r_khan',
    name: 'R. Khan',
    role: 'Contractor',
    status: 'normal',
    type: 'user',
    x: 70,
    y: 295,
    r: 24,
    icon: User,
    details: 'Verified contractor profile with standard scoped API tokens.',
  },
  laptop_win: {
    id: 'laptop_win',
    name: 'Laptop',
    role: 'Windows',
    status: 'normal',
    type: 'device',
    x: 235,
    y: 95,
    r: 24,
    icon: Monitor,
    details: 'Managed corporate workstation D_CORP_WIN_11. Fully compliant endpoint health.',
  },
  unknown_device: {
    id: 'unknown_device',
    name: 'Unknown Device',
    role: 'Linux',
    status: 'malicious',
    type: 'device',
    x: 235,
    y: 265,
    r: 24,
    icon: Laptop,
    details: 'Unrecognized Kali Linux box connecting via external IP 203.0.113.195 with forged headers.',
  },
  hr_agent: {
    id: 'hr_agent',
    name: 'HR_Agent',
    role: 'AI Agent',
    status: 'malicious',
    type: 'agent',
    x: 410,
    y: 180,
    r: 28,
    icon: Bot,
    details: 'Autonomous LLM agent copilot prompted with privileged jailbreak to dump customer credentials.',
  },
  hr_api: {
    id: 'hr_api',
    name: 'HR API',
    role: 'Gateway',
    status: 'suspicious',
    type: 'api',
    x: 580,
    y: 95,
    r: 24,
    icon: NetworkIcon,
    details: 'Standard HR REST gateway. High call frequency observed from autonomous orchestrator.',
  },
  payroll_api: {
    id: 'payroll_api',
    name: 'Payroll API',
    role: 'Privileged',
    status: 'malicious',
    type: 'api',
    x: 580,
    y: 265,
    r: 24,
    icon: Shield,
    details: 'Financial payroll endpoint invoked for bulk export bypassing standard rate limits.',
  },
  employee_db: {
    id: 'employee_db',
    name: 'Employee DB',
    role: 'PostgreSQL',
    status: 'normal',
    type: 'database',
    x: 755,
    y: 95,
    r: 24,
    icon: Database,
    details: 'Internal staff directory PostgreSQL cluster. Standard read operations.',
  },
  customer_db: {
    id: 'customer_db',
    name: 'Customer DB',
    role: 'PII Store',
    status: 'malicious',
    type: 'database',
    x: 755,
    y: 265,
    r: 24,
    icon: Database,
    details: 'Sensitive customer PII & credential database targeted for bulk table exfiltration.',
  },
};

const DEFAULT_PATHS = [
  { d: "M 94 65 C 165 65, 165 95, 211 95", color: "#10b981", strokeWidth: 2, filter: "url(#glow-green)" },
  { d: "M 94 295 C 165 295, 165 95, 211 95", color: "#10b981", strokeWidth: 1.5, opacity: 0.4 },
  { d: "M 94 180 C 165 180, 165 265, 211 265", color: "#f43f5e", strokeWidth: 2.5, filter: "url(#glow-red)", markerEnd: "url(#arrow-red)" },
  { d: "M 259 95 L 556 95", color: "#10b981", strokeWidth: 2, filter: "url(#glow-green)" },
  { d: "M 259 95 C 320 95, 320 180, 382 180", color: "#10b981", strokeWidth: 1.8, opacity: 0.6 },
  { d: "M 259 265 C 320 265, 320 180, 382 180", color: "#f43f5e", strokeWidth: 2.5, strokeDasharray: "6 4", filter: "url(#glow-red)", markerEnd: "url(#arrow-red)", animate: true },
  { d: "M 438 180 C 495 180, 495 95, 556 95", color: "#f59e0b", strokeWidth: 2, filter: "url(#glow-amber)", markerEnd: "url(#arrow-amber)" },
  { d: "M 438 180 C 495 180, 495 265, 556 265", color: "#f43f5e", strokeWidth: 2.5, strokeDasharray: "6 4", filter: "url(#glow-red)", markerEnd: "url(#arrow-red)", animate: true },
  { d: "M 604 95 L 731 95", color: "#10b981", strokeWidth: 2, filter: "url(#glow-green)", markerEnd: "url(#arrow-green)" },
  { d: "M 604 265 L 731 265", color: "#f43f5e", strokeWidth: 2.5, strokeDasharray: "6 4", filter: "url(#glow-red)", markerEnd: "url(#arrow-red)", animate: true },
  { d: "M 580 119 L 580 241", color: "#f59e0b", strokeWidth: 1.8, strokeDasharray: "4 3", opacity: 0.6 },
];

export function LiveSecurityGraph({ 
  events = [],
  incidents = [],
  alerts = [],
  isResolved: explicitIsResolved,
  onInvestigate,
  onSelectNode,
  className = "" 
}) {
  const [selectedNodeId, setSelectedNodeId] = useState(null);
  const [isBannerDismissed, setIsBannerDismissed] = useState(false);

  // Fast lookups for incidents & alerts by event_id, alert_id, and user_id
  const { incidentByEventId, incidentByUserId, alertByEventId } = useMemo(() => {
    const incByEvt = new Map();
    const incByUser = new Map();
    (incidents || []).forEach(inc => {
      if (Array.isArray(inc.event_ids)) {
        inc.event_ids.forEach(eid => incByEvt.set(eid, inc));
      }
      if (Array.isArray(inc.events)) {
        inc.events.forEach(e => {
          if (e.id) incByEvt.set(e.id, inc);
        });
      }
      const uKey = (inc.primary_entity || inc.user_id || '').toLowerCase().trim();
      if (uKey) {
        const existing = incByUser.get(uKey);
        // Lifecycle precedence: active (3) > acknowledged (2) > contained (1) > resolved (0)
        const rank = s => s === 'active' ? 3 : s === 'acknowledged' ? 2 : s === 'contained' ? 1 : 0;
        const currentRank = existing ? rank((existing.status || '').toLowerCase()) : -1;
        const newRank = rank((inc.status || '').toLowerCase());
        if (!existing || newRank >= currentRank) {
          incByUser.set(uKey, inc);
        }
      }
    });

    const altByEvt = new Map();
    (alerts || []).forEach(a => {
      if (a.event_id) altByEvt.set(a.event_id, a);
    });

    return {
      incidentByEventId: incByEvt,
      incidentByUserId: incByUser,
      alertByEventId: altByEvt
    };
  }, [incidents, alerts]);

  // Evaluate true threat condition across telemetry, alerts, and incidents
  const { hasActiveThreats, hasSuspiciousThreats, isContained, isTrulyNeutralized, activeThreatCount } = useMemo(() => {
    // Unmitigated alerts: alert must not be resolved, contained, mitigated, or attached to a contained/resolved incident
    const unmitigatedAlerts = (alerts || []).filter(a => {
      if (a.status === 'resolved' || a.status === 'contained' || a.status === 'mitigated' || a.approval_state === 'APPROVED' || a.is_mitigated) return false;
      if (a.risk_score !== undefined && a.risk_score <= 25) return false;
      if (a.incident_id) {
        const linked = (incidents || []).find(i => i.id === a.incident_id);
        if (linked && (linked.status === 'contained' || linked.status === 'resolved' || linked.status === 'mitigated' || linked.status === 'recovered')) return false;
      }
      return true;
    });

    const criticalOrHighAlerts = unmitigatedAlerts.filter(a => {
      const lvl = (a.risk_level || a.severity || '').toUpperCase();
      const score = a.risk_score !== undefined ? a.risk_score : 0;
      return lvl === 'CRITICAL' || lvl === 'HIGH' || score >= 60;
    });
    const suspiciousAlerts = unmitigatedAlerts.filter(a => {
      const lvl = (a.risk_level || a.severity || '').toUpperCase();
      const score = a.risk_score !== undefined ? a.risk_score : 0;
      return lvl === 'MODERATE' || (score >= 30 && score < 60);
    });

    const activeIncidents = (incidents || []).filter(i => {
      const status = (i.status || 'active').toLowerCase();
      return status === 'active';
    });

    const containedIncidents = (incidents || []).filter(i => (i.status || '').toLowerCase() === 'contained');

    const hasActive = criticalOrHighAlerts.length > 0 || activeIncidents.length > 0;
    const hasSusp = !hasActive && (suspiciousAlerts.length > 0 || (incidents || []).some(i => i.status === 'active' && (i.risk_assessment?.risk_level || i.risk_level) === 'MODERATE'));
    const isCont = !hasActive && !hasSusp && containedIncidents.length > 0;

    // Neutralized ONLY when explicitly set OR when incidents exist and all alerts/threats are completely resolved/0 score
    const neutralized = !hasActive && !hasSusp && !isCont && (
      explicitIsResolved === true || 
      (incidents && incidents.length > 0 && incidents.every(i => i.status === 'resolved' || i.status === 'mitigated' || (i.risk_assessment?.risk_score || i.risk_score || 0) === 0))
    );

    const threatCount = criticalOrHighAlerts.length + activeIncidents.length;

    return {
      hasActiveThreats: hasActive,
      hasSuspiciousThreats: hasSusp,
      isContained: isCont,
      isTrulyNeutralized: neutralized,
      activeThreatCount: threatCount > 0 ? threatCount : (hasActive ? 1 : 0)
    };
  }, [alerts, incidents, explicitIsResolved]);

  // Backward-compatibility alias
  const isNeutralized = isTrulyNeutralized;

  // Dynamic layout generator building nodes and links from real live events
  const { nodes, paths, attackChain } = useMemo(() => {
    // If no events ingested, generate layout from default nodes with dynamic status reflection
    if (!events || events.length === 0) {
      const defaultChain = [
        { label: 'J. Singh', type: 'user' },
        { label: 'Unknown Device', type: 'device' },
        { label: 'HR_Agent', type: 'agent' },
        { label: 'Payroll API', type: 'api' },
        { label: 'Customer DB', type: 'database' },
      ];

      // Check if incident for J. Singh or default incident is resolved or contained
      const singhInc = (incidents || []).find(i => 
        (i.primary_entity?.toLowerCase().includes('singh') || i.user_id?.toLowerCase().includes('singh') || i.id?.includes('895C6516') || i.id?.includes('311065C2') || i.id?.includes('DEMO'))
      );
      const isSinghResolved = isTrulyNeutralized || (singhInc && (singhInc.status === 'resolved' || singhInc.status === 'mitigated' || (singhInc.risk_assessment?.risk_score || singhInc.risk_score || 0) === 0));
      const isSinghContained = !isSinghResolved && (singhInc && (singhInc.status === 'contained' || (singhInc.risk_assessment?.risk_score !== undefined && singhInc.risk_assessment.risk_score <= 25)));

      if (isSinghResolved) {
        const safeNodes = {};
        Object.entries(DEFAULT_NODES).forEach(([k, v]) => {
          safeNodes[k] = { 
            ...v, 
            status: v.status === 'malicious' ? 'resolved' : v.status === 'suspicious' ? 'resolved' : 'normal',
            details: v.status === 'malicious' ? `${v.details} [Verified Benign & Access Restored]` : v.details
          };
        });
        const safePaths = DEFAULT_PATHS.map(p => ({
          ...p,
          color: '#10b981',
          filter: 'url(#glow-green)',
          markerEnd: 'url(#arrow-green)',
          strokeDasharray: undefined,
          animate: false
        }));
        return {
          nodes: safeNodes,
          paths: safePaths,
          attackChain: defaultChain
        };
      } else if (isSinghContained) {
        const containedNodes = {};
        Object.entries(DEFAULT_NODES).forEach(([k, v]) => {
          containedNodes[k] = { 
            ...v, 
            status: v.status === 'malicious' || v.status === 'suspicious' ? 'contained' : 'normal',
            details: v.status === 'malicious' ? `${v.details} [Containment Active - Dual-Control Verified]` : v.details
          };
        });
        const containedPaths = DEFAULT_PATHS.map(p => ({
          ...p,
          color: p.color === '#f43f5e' ? '#6366f1' : p.color,
          filter: p.color === '#f43f5e' ? 'url(#glow-indigo)' : p.filter,
          markerEnd: p.color === '#f43f5e' ? 'url(#arrow-indigo)' : p.markerEnd,
          strokeDasharray: p.strokeDasharray === '6 4' ? '4 4' : p.strokeDasharray,
          animate: false
        }));
        return {
          nodes: containedNodes,
          paths: containedPaths,
          attackChain: defaultChain.map(c => ({ ...c, status: 'contained' }))
        };
      }

      return {
        nodes: DEFAULT_NODES,
        paths: DEFAULT_PATHS,
        attackChain: defaultChain
      };
    }

    // Helper to extract clean entity names and risk ratings with incident/alert correlation
    const userMap = new Map();
    const deviceMap = new Map();
    const agentMap = new Map();
    const apiMap = new Map();
    const dbMap = new Map();

    const getEventRisk = (evt) => {
      const eid = evt.id || evt.event_id;
      const uKey = (evt.user_id || '').toLowerCase().trim();
      const inc = (eid && incidentByEventId.get(eid)) || (uKey && incidentByUserId.get(uKey));
      const alt = eid && alertByEventId.get(eid);

      if (inc) {
        const incStatus = (inc.status || '').toLowerCase();
        const incScore = inc.risk_assessment?.risk_score ?? inc.risk_score;

        if (incStatus === 'resolved' || incStatus === 'mitigated' || incStatus === 'recovered' || incScore === 0) {
          return 'resolved';
        }
        if (incStatus === 'contained' || (incScore !== undefined && incScore <= 25 && incStatus !== 'active')) {
          return 'contained';
        }
        if (incStatus === 'acknowledged') {
          return 'acknowledged';
        }
        if (incStatus === 'active') {
          // Explicitly ACTIVE incident
          return (inc.risk_assessment?.risk_level === 'MODERATE' || (incScore >= 30 && incScore < 60))
            ? 'suspicious'
            : 'malicious';
        }
      }

      if (alt) {
        if (alt.status === 'resolved' || alt.is_mitigated || (alt.risk_score || 0) === 0) {
          return 'resolved';
        }
        if (alt.status === 'contained') {
          return 'contained';
        }
        if (alt.status === 'acknowledged') {
          return 'acknowledged';
        }
      }

      const meta = evt.metadata || {};
      const res = (evt.resource || '').toLowerCase();
      const tool = (evt.tool_name || '').toLowerCase();
      const dev = (evt.device_id || '').toLowerCase();
      const prompt = (meta.prompt || '').toLowerCase();
      const evtType = (evt.event_type || '').toLowerCase();

      // Malicious attack signatures
      if (
        meta.privilege_escalation ||
        meta.unauthorized_privilege ||
        meta.data_exfiltration ||
        meta.is_brute_force ||
        meta.ip_reputation === 'malicious' ||
        meta.bulk_data_access ||
        (meta.records_requested && meta.records_requested >= 1000) ||
        (meta.outbound_bytes && meta.outbound_bytes > 500000) ||
        /dan mode|ignore previous|system override|jailbreak|dump credentials/i.test(prompt) ||
        /dump|credential|export|raw_sql|unauthorized|drop\s+table/i.test(res) ||
        /raw_sql_exec|dump|shell|bash|exec/i.test(tool) ||
        /kali|tor\s+vm/i.test(dev) ||
        (evt.risk_level || '').toUpperCase() === 'CRITICAL' ||
        (evt.risk_level || '').toUpperCase() === 'HIGH'
      ) {
        return 'malicious';
      }

      // Suspicious anomaly signatures
      if (
        meta.is_new_device ||
        meta.is_new_ip ||
        meta.is_suspicious_ip ||
        meta.unusual_api ||
        evtType === 'failed_login' ||
        dev.startsWith('unknown') ||
        (evt.risk_level || '').toUpperCase() === 'MODERATE'
      ) {
        return 'suspicious';
      }

      return 'normal';
    };

    // Helper to resolve entity state directly from linked authoritative incidents
    const resolveEntityIncidentState = (entityKey, entityType, eventIdsSet, rawEntityName) => {
      const matchedIncidents = (incidents || []).filter(inc => {
        const pEntity = (inc.primary_entity || inc.user_id || '').toLowerCase().trim();
        const rawLower = (rawEntityName || '').toLowerCase().trim();
        const keyLower = (entityKey || '').toLowerCase().trim();

        // 1. Direct entity identifier match
        if (pEntity && (pEntity === keyLower || pEntity === rawLower || keyLower.includes(pEntity) || rawLower.includes(pEntity))) {
          return true;
        }
        // 2. Event ID correlation match
        if (Array.isArray(inc.event_ids) && inc.event_ids.some(eid => eventIdsSet.has(eid))) {
          return true;
        }
        if (Array.isArray(inc.events) && inc.events.some(e => e.id && eventIdsSet.has(e.id))) {
          return true;
        }
        return false;
      });

      if (matchedIncidents.length === 0) {
        return null; // Fall back to telemetry event classification
      }

      const activeIncs = matchedIncidents.filter(i => (i.status || 'active').toLowerCase() === 'active');
      const ackIncs = matchedIncidents.filter(i => (i.status || '').toLowerCase() === 'acknowledged');
      const contIncs = matchedIncidents.filter(i => (i.status || '').toLowerCase() === 'contained');
      const resIncs = matchedIncidents.filter(i =>
        (i.status || '').toLowerCase() === 'resolved' ||
        (i.status || '').toLowerCase() === 'mitigated' ||
        (i.risk_assessment?.risk_score === 0 || i.risk_score === 0)
      );
      const recIncs = matchedIncidents.filter(i => (i.status || '').toLowerCase() === 'recovered');

      const getHighestSev = (list) => {
        const sevOrder = { CRITICAL: 4, HIGH: 3, MODERATE: 2, LOW: 1 };
        let maxS = 'LOW';
        let maxR = 1;
        list.forEach(i => {
          const s = (i.risk_assessment?.risk_level || i.risk_level || 'LOW').toUpperCase();
          const r = sevOrder[s] || 1;
          if (r > maxR) {
            maxR = r;
            maxS = s;
          }
        });
        return maxS;
      };

      if (activeIncs.length > 0) {
        const sev = getHighestSev(activeIncs);
        return {
          status: sev === 'CRITICAL' || sev === 'HIGH' ? 'malicious' : 'suspicious',
          incident_status: 'ACTIVE',
          severity: sev,
          incidentId: activeIncs[0].id,
        };
      }

      if (ackIncs.length > 0) {
        return {
          status: 'suspicious',
          incident_status: 'ACKNOWLEDGED',
          severity: getHighestSev(ackIncs),
          incidentId: ackIncs[0].id,
        };
      }

      if (contIncs.length > 0) {
        return {
          status: 'contained',
          incident_status: 'CONTAINED',
          severity: getHighestSev(contIncs),
          incidentId: contIncs[0].id,
        };
      }

      if (resIncs.length > 0) {
        return {
          status: 'resolved',
          incident_status: 'RESOLVED',
          severity: 'LOW',
          incidentId: resIncs[0].id,
        };
      }

      if (recIncs.length > 0) {
        return {
          status: 'resolved',
          incident_status: 'RECOVERED',
          severity: 'LOW',
          incidentId: recIncs[0].id,
        };
      }

      return null;
    };

    // Parse all events into entity buckets
    events.forEach((evt) => {
      const risk = getEventRisk(evt);
      const eid = evt.id || evt.event_id;

      // 1. User
      const uName = evt.user_id || 'U_ANALYST';
      const uKey = uName.toLowerCase().replace(/\s+/g, '_');
      if (!userMap.has(uKey)) {
        userMap.set(uKey, {
          id: uKey,
          name: uName,
          role: uName.includes('Singh') ? 'Analyst' : uName.includes('Fatima') ? 'Security' : 'Employee',
          status: risk,
          type: 'user',
          details: `User entity ${uName} active across event streams.`,
          eventIds: new Set(eid ? [eid] : []),
        });
      } else {
        const existing = userMap.get(uKey);
        if (eid) existing.eventIds.add(eid);
        if (risk === 'malicious' || (risk === 'suspicious' && existing.status !== 'malicious')) {
          existing.status = risk;
        }
      }

      // 2. Device
      const dName = evt.device_id || 'Laptop';
      const dKey = dName.toLowerCase().replace(/\s+/g, '_');
      if (!deviceMap.has(dKey)) {
        deviceMap.set(dKey, {
          id: dKey,
          name: dName.length > 18 ? dName.slice(0, 16) + '...' : dName,
          role: dName.includes('Tor') || dName.includes('Kali') ? 'Linux VM' : 'Corporate',
          status: risk,
          type: 'device',
          details: `Endpoint ${dName} verified in telemetry logs.`,
          eventIds: new Set(eid ? [eid] : []),
        });
      } else {
        const existing = deviceMap.get(dKey);
        if (eid) existing.eventIds.add(eid);
        if (risk === 'malicious' || (risk === 'suspicious' && existing.status !== 'malicious')) {
          existing.status = risk;
        }
      }

      // 3. Agent / Tool
      if (evt.agent_id || evt.tool_name) {
        const agName = evt.agent_id || evt.tool_name || 'HR_Agent';
        const agKey = agName.toLowerCase().replace(/\s+/g, '_');
        if (!agentMap.has(agKey)) {
          agentMap.set(agKey, {
            id: agKey,
            name: agName,
            role: evt.tool_name ? 'Tool' : 'AI Agent',
            status: risk,
            type: 'agent',
            details: `Autonomous worker ${agName} invoked in session ${evt.session_id || 'active'}.`,
            eventIds: new Set(eid ? [eid] : []),
          });
        } else {
          const existing = agentMap.get(agKey);
          if (eid) existing.eventIds.add(eid);
          if (risk === 'malicious' || (risk === 'suspicious' && existing.status !== 'malicious')) {
            existing.status = risk;
          }
        }
      }

      // 4. API Endpoint / Gateway
      if (evt.resource && (evt.resource.includes('api') || evt.event_type?.includes('api') || evt.event_type?.includes('login'))) {
        const apiName = evt.resource.includes('api') ? evt.resource.split('/').pop() || 'API' : 'Auth Gateway';
        const apiKey = ('api_' + apiName).toLowerCase().replace(/[^a-z0-9]/g, '_');
        if (!apiMap.has(apiKey)) {
          apiMap.set(apiKey, {
            id: apiKey,
            name: apiName.toUpperCase(),
            role: evt.resource.includes('payroll') ? 'Privileged' : 'REST Gateway',
            status: risk,
            type: 'api',
            details: `API Endpoint resource: ${evt.resource}`,
            eventIds: new Set(eid ? [eid] : []),
          });
        } else {
          const existing = apiMap.get(apiKey);
          if (eid) existing.eventIds.add(eid);
          if (risk === 'malicious' || (risk === 'suspicious' && existing.status !== 'malicious')) {
            existing.status = risk;
          }
        }
      }

      // 5. Database / Data Store
      if (evt.resource && (evt.resource.includes('database') || evt.resource.includes('customer') || evt.resource.includes('dump') || evt.event_type?.includes('database'))) {
        const dbName = evt.resource.includes('customer') ? 'Customer DB' : 'Employee DB';
        const dbKey = ('db_' + dbName).toLowerCase().replace(/[^a-z0-9]/g, '_');
        if (!dbMap.has(dbKey)) {
          dbMap.set(dbKey, {
            id: dbKey,
            name: dbName,
            role: evt.resource.includes('credential') ? 'Credentials' : 'PII Store',
            status: risk,
            type: 'database',
            details: `Persistent store resource target: ${evt.resource}`,
            eventIds: new Set(eid ? [eid] : []),
          });
        } else {
          const existing = dbMap.get(dbKey);
          if (eid) existing.eventIds.add(eid);
          if (risk === 'malicious' || (risk === 'suspicious' && existing.status !== 'malicious')) {
            existing.status = risk;
          }
        }
      }
    });

    // Authoritative Incident Lifecycle Synchronization (Strict per-entity isolation)
    [userMap, deviceMap, agentMap, apiMap, dbMap].forEach(mapObj => {
      mapObj.forEach((item, key) => {
        const resolved = resolveEntityIncidentState(key, item.type, item.eventIds || new Set(), item.name);
        if (resolved) {
          item.status = resolved.status;
          item.incident_status = resolved.incident_status;
          item.severity = resolved.severity;
          item.incidentId = resolved.incidentId;
          if (resolved.status === 'resolved') {
            item.details = `${item.details} [Threat Neutralized - Incident ${resolved.incidentId}]`;
          } else if (resolved.status === 'contained') {
            item.details = `${item.details} [Containment Active - Dual Control Verified - Incident ${resolved.incidentId}]`;
          }
        }
      });
    });

    // Ensure default demo nodes are populated if lists are sparse
    if (userMap.size < 2 && DEFAULT_NODES.a_verma) userMap.set('a_verma', DEFAULT_NODES.a_verma);
    if (deviceMap.size < 2 && DEFAULT_NODES.laptop_win) deviceMap.set('laptop_win', DEFAULT_NODES.laptop_win);
    if (agentMap.size < 1 && DEFAULT_NODES.hr_agent) agentMap.set('hr_agent', DEFAULT_NODES.hr_agent);
    if (apiMap.size < 2 && DEFAULT_NODES.hr_api) apiMap.set('hr_api', DEFAULT_NODES.hr_api);
    if (dbMap.size < 2 && DEFAULT_NODES.customer_db) dbMap.set('customer_db', DEFAULT_NODES.customer_db);

    // Layout Columns: 5 Columns with vertical centering
    const dynamicNodes = {};
    const layoutCol = (mapObj, x, iconDefault) => {
      const items = Array.from(mapObj.values()).slice(0, 4);
      const count = items.length;
      const startY = count === 1 ? 180 : count === 2 ? 100 : count === 3 ? 65 : 45;
      const stepY = count === 1 ? 0 : count === 2 ? 160 : count === 3 ? 115 : 85;

      items.forEach((item, idx) => {
        const y = startY + idx * stepY;
        dynamicNodes[item.id] = {
          ...item,
          x,
          y,
          r: item.type === 'agent' ? 28 : 24,
          icon: iconDefault,
        };
      });
    };

    layoutCol(userMap, 70, User);
    layoutCol(deviceMap, 235, Laptop);
    layoutCol(agentMap, 410, Bot);
    layoutCol(apiMap, 580, NetworkIcon);
    layoutCol(dbMap, 755, Database);

    // Compute Dynamic Connector Paths between contiguous columns
    const dynamicPaths = [];
    const allUsers = Object.values(dynamicNodes).filter(n => n.type === 'user');
    const allDevices = Object.values(dynamicNodes).filter(n => n.type === 'device');
    const allAgents = Object.values(dynamicNodes).filter(n => n.type === 'agent');
    const allApis = Object.values(dynamicNodes).filter(n => n.type === 'api');
    const allDbs = Object.values(dynamicNodes).filter(n => n.type === 'database');

    const getEdgeStyle = (srcNode, tgtNode) => {
      const isMal = srcNode.status === 'malicious' || tgtNode.status === 'malicious';
      const isSusp = !isMal && (srcNode.status === 'suspicious' || tgtNode.status === 'suspicious');
      const isCont = !isMal && !isSusp && (srcNode.status === 'contained' || tgtNode.status === 'contained');
      const isRes = !isMal && !isSusp && !isCont && (srcNode.status === 'resolved' || tgtNode.status === 'resolved');

      if (isMal) {
        return {
          color: '#f43f5e',
          strokeWidth: 2.5,
          filter: 'url(#glow-red)',
          markerEnd: 'url(#arrow-red)',
          strokeDasharray: '6 4',
          animate: true,
        };
      }
      if (isSusp) {
        return {
          color: '#f59e0b',
          strokeWidth: 2,
          filter: 'url(#glow-amber)',
          markerEnd: 'url(#arrow-amber)',
          strokeDasharray: '4 3',
          animate: false,
        };
      }
      if (isCont) {
        return {
          color: '#6366f1',
          strokeWidth: 2,
          filter: 'url(#glow-indigo)',
          markerEnd: 'url(#arrow-indigo)',
          strokeDasharray: '4 4',
          animate: false,
        };
      }
      // Resolved / Normal edge: clean emerald green solid path
      return {
        color: '#10b981',
        strokeWidth: isRes ? 2 : 1.8,
        filter: 'url(#glow-green)',
        markerEnd: 'url(#arrow-green)',
        strokeDasharray: undefined,
        animate: false,
      };
    };

    // Link Users to Devices
    allUsers.forEach((u, uIdx) => {
      const targetDev = allDevices[uIdx % allDevices.length] || allDevices[0];
      if (targetDev) {
        const edgeStyle = getEdgeStyle(u, targetDev);
        dynamicPaths.push({
          d: `M ${u.x + u.r} ${u.y} C ${(u.x + targetDev.x) / 2} ${u.y}, ${(u.x + targetDev.x) / 2} ${targetDev.y}, ${targetDev.x - targetDev.r} ${targetDev.y}`,
          ...edgeStyle
        });
      }
    });

    // Link Devices to Agents or APIs
    allDevices.forEach((dev, dIdx) => {
      const targetAgent = allAgents[dIdx % allAgents.length] || allAgents[0];
      if (targetAgent) {
        const edgeStyle = getEdgeStyle(dev, targetAgent);
        dynamicPaths.push({
          d: `M ${dev.x + dev.r} ${dev.y} C ${(dev.x + targetAgent.x) / 2} ${dev.y}, ${(dev.x + targetAgent.x) / 2} ${targetAgent.y}, ${targetAgent.x - targetAgent.r} ${targetAgent.y}`,
          ...edgeStyle
        });
      }
    });

    // Link Agents to APIs
    allAgents.forEach((ag, aIdx) => {
      allApis.forEach((api) => {
        const edgeStyle = getEdgeStyle(ag, api);
        dynamicPaths.push({
          d: `M ${ag.x + ag.r} ${ag.y} C ${(ag.x + api.x) / 2} ${ag.y}, ${(ag.x + api.x) / 2} ${api.y}, ${api.x - api.r} ${api.y}`,
          ...edgeStyle
        });
      });
    });

    // Link APIs to Databases
    allApis.forEach((api, pIdx) => {
      const targetDb = allDbs[pIdx % allDbs.length] || allDbs[0];
      if (targetDb) {
        const edgeStyle = getEdgeStyle(api, targetDb);
        dynamicPaths.push({
          d: `M ${api.x + api.r} ${api.y} L ${targetDb.x - targetDb.r} ${targetDb.y}`,
          ...edgeStyle
        });
      }
    });

    // Derive Attack Chain for Bottom Banner (Preserved in full for forensic evidence)
    const topThreatUser = allUsers.find(u => u.status === 'malicious') || allUsers.find(u => u.status === 'resolved') || allUsers[0];
    const topThreatDev = allDevices.find(d => d.status === 'malicious') || allDevices.find(d => d.status === 'resolved') || allDevices[0];
    const topThreatAgent = allAgents[0];
    const topThreatApi = allApis.find(a => a.status === 'malicious') || allApis.find(a => a.status === 'resolved') || allApis[0];
    const topThreatDb = allDbs.find(d => d.status === 'malicious') || allDbs.find(d => d.status === 'resolved') || allDbs[0];

    const chain = [];
    if (topThreatUser) chain.push({ label: topThreatUser.name, type: 'user', status: topThreatUser.status });
    if (topThreatDev) chain.push({ label: topThreatDev.name, type: 'device', status: topThreatDev.status });
    if (topThreatAgent) chain.push({ label: topThreatAgent.name, type: 'agent', status: topThreatAgent.status });
    if (topThreatApi) chain.push({ label: topThreatApi.name, type: 'api', status: topThreatApi.status });
    if (topThreatDb) chain.push({ label: topThreatDb.name, type: 'database', status: topThreatDb.status });

    // If completely neutralized across all signals, ensure any residual attack flags are mapped to resolved
    if (isTrulyNeutralized) {
      Object.values(dynamicNodes).forEach(node => {
        if (node.status === 'malicious' || node.status === 'suspicious') {
          node.status = 'resolved';
        }
      });
      dynamicPaths.forEach(p => {
        p.color = '#10b981';
        p.filter = 'url(#glow-green)';
        p.markerEnd = 'url(#arrow-green)';
        p.strokeWidth = 2;
        p.strokeDasharray = undefined;
        p.animate = false;
      });
    }

    return {
      nodes: dynamicNodes,
      paths: dynamicPaths,
      attackChain: chain
    };
  }, [events, incidents, isTrulyNeutralized, incidentByEventId, incidentByUserId, alertByEventId]);


  const activeSelectedKey = selectedNodeId || Object.keys(nodes)[0] || 'j_singh';
  const selectedNode = nodes[activeSelectedKey] || Object.values(nodes)[0];

  const handleNodeClick = (nodeKey) => {
    setSelectedNodeId(nodeKey);
    if (onSelectNode && nodes[nodeKey]) onSelectNode(nodes[nodeKey]);
  };

  return (
    <div className={`bg-slate-950/95 border border-slate-800/90 rounded-2xl p-6 shadow-2xl relative overflow-hidden font-sans ${className}`}>
      {/* Background ambient cybersecurity glows */}
      <div className="absolute top-1/4 left-1/4 w-72 h-72 bg-rose-950/15 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute bottom-1/4 right-1/4 w-72 h-72 bg-emerald-950/10 rounded-full blur-3xl pointer-events-none" />

      {/* Header & Legend */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800/80 relative z-10">
        <div>
          <div className="flex items-center gap-2.5 flex-wrap">
            <h3 className="text-xl font-bold text-white tracking-tight">
              Live Security Graph
            </h3>
            {hasActiveThreats ? (
              <span className="px-2.5 py-0.5 rounded text-[10px] bg-rose-950/90 border border-rose-600/80 text-rose-300 font-mono font-bold flex items-center gap-1.5 shadow-[0_0_12px_rgba(244,63,94,0.4)] animate-pulse">
                <AlertTriangle size={12} className="text-rose-400" /> Active Threat Detected ({activeThreatCount} Vector{activeThreatCount > 1 ? 's' : ''})
              </span>
            ) : hasSuspiciousThreats ? (
              <span className="px-2.5 py-0.5 rounded text-[10px] bg-amber-950/90 border border-amber-600/80 text-amber-300 font-mono font-bold flex items-center gap-1.5 shadow-[0_0_10px_rgba(245,158,11,0.3)]">
                <AlertTriangle size={12} className="text-amber-400" /> Suspicious Activity Detected
              </span>
            ) : isContained ? (
              <span className="px-2.5 py-0.5 rounded text-[10px] bg-indigo-950/90 border border-indigo-600/80 text-indigo-300 font-mono font-bold flex items-center gap-1.5 shadow-[0_0_10px_rgba(99,102,241,0.3)]">
                <Shield size={12} className="text-indigo-400" /> Containment Active (Dual Control)
              </span>
            ) : isTrulyNeutralized ? (
              <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-950/80 border border-emerald-700/80 text-emerald-300 font-mono font-bold flex items-center gap-1 shadow-xs">
                <CheckCircle2 size={11} /> All Vectors Neutralized
              </span>
            ) : null}
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Real-time view of users, devices, APIs, AI agents and data flow.
          </p>
        </div>

        {/* Legend */}
        <div className="flex items-center gap-5 text-xs font-medium font-mono">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-sm bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]" />
            <span className="text-slate-300">Normal</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-sm bg-amber-400 shadow-[0_0_8px_rgba(251,191,36,0.8)]" />
            <span className="text-slate-300">Suspicious</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-sm bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.8)]" />
            <span className="text-slate-300">Malicious</span>
          </div>
        </div>
      </div>

      {/* Interactive Visual Graph Canvas (Fully responsive SVG) */}
      <div className="relative w-full py-4 overflow-hidden">
        <div className="w-full max-w-[880px] mx-auto select-none">
          
          <svg className="w-full h-auto" viewBox="0 0 880 360">
            <defs>
              {/* Arrow markers */}
              <marker
                id="arrow-red"
                viewBox="0 0 10 10"
                refX="8"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#f43f5e" />
              </marker>
              <marker
                id="arrow-green"
                viewBox="0 0 10 10"
                refX="8"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#10b981" />
              </marker>
              <marker
                id="arrow-amber"
                viewBox="0 0 10 10"
                refX="8"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#f59e0b" />
              </marker>
              <marker
                id="arrow-indigo"
                viewBox="0 0 10 10"
                refX="8"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#6366f1" />
              </marker>

              {/* Glowing filters */}
              <filter id="glow-red" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation="3" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
              <filter id="glow-green" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation="3" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
              <filter id="glow-amber" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation="3" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
              <filter id="glow-indigo" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation="3" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>

            {/* Dynamic Connecting Paths */}
            {paths.map((p, idx) => (
              <path
                key={idx}
                d={p.d}
                fill="none"
                stroke={p.color}
                strokeWidth={p.strokeWidth || 2}
                strokeDasharray={p.strokeDasharray}
                filter={p.filter}
                markerEnd={p.markerEnd}
                className={`transition-all duration-500 ${p.animate ? 'animate-pulse' : ''} ${p.opacity ? `opacity-${Math.round(p.opacity * 100)}` : ''}`}
              />
            ))}

            {/* Dynamic Graph Nodes */}
            {Object.entries(nodes).map(([nodeKey, node]) => {
              const isSelected = activeSelectedKey === nodeKey;
              const isMal = node.status === 'malicious';
              const isSusp = node.status === 'suspicious';
              const isCont = node.status === 'contained';
              const isRes = node.status === 'resolved';

              const strokeColor = isMal ? '#f43f5e' : isSusp ? '#f59e0b' : isCont ? '#6366f1' : '#10b981';
              const filterUrl = isMal ? 'url(#glow-red)' : isSusp ? 'url(#glow-amber)' : isCont ? 'url(#glow-indigo)' : 'url(#glow-green)';
              const IconComp = node.icon || (node.type === 'user' ? User : node.type === 'device' ? Laptop : node.type === 'agent' ? Bot : node.type === 'api' ? NetworkIcon : Database);

              return (
                <g 
                  key={nodeKey}
                  onClick={() => handleNodeClick(nodeKey)}
                  className="cursor-pointer group"
                  transform={`translate(${node.x}, ${node.y})`}
                >
                  <circle
                    r={node.r || 24}
                    fill="#090d16"
                    stroke={strokeColor}
                    strokeWidth={isSelected ? 3.5 : isMal ? 2.5 : isRes ? 2.2 : 2}
                    filter={filterUrl}
                    className={`transition-all duration-300 ${isSelected ? 'stroke-white' : ''}`}
                  />
                  <foreignObject x={-(node.r || 24) / 2} y={-(node.r || 24) / 2} width={node.r || 24} height={node.r || 24} className="pointer-events-none flex items-center justify-center">
                    <IconComp size={(node.r || 24) - 2} className={isMal ? 'text-rose-400' : isSusp ? 'text-amber-400' : isCont ? 'text-indigo-400' : 'text-emerald-400'} />
                  </foreignObject>

                  {/* Label Text below node */}
                  <text x="0" y={(node.r || 24) + 14} textAnchor="middle" fill="#ffffff" fontSize="11" fontWeight="700" fontFamily="sans-serif">
                    {node.name.length > 15 ? node.name.slice(0, 13) + '...' : node.name}
                  </text>
                  <text x="0" y={(node.r || 24) + 26} textAnchor="middle" fill={isMal ? '#fda4af' : isSusp ? '#fcd34d' : isCont ? '#a5b4fc' : isRes ? '#6ee7b7' : '#94a3b8'} fontSize="9.5" fontFamily="sans-serif">
                    ({isRes ? 'Resolved' : isCont ? 'Contained' : node.role || node.type || 'User'})
                  </text>
                </g>
              );
            })}

          </svg>

        </div>
      </div>

      {/* Node Inspector Callout if selected */}
      {selectedNode && (
        <div className="mb-4 p-3.5 bg-slate-900/90 border border-slate-800 rounded-xl flex items-center justify-between text-xs font-mono shadow-md">
          <div className="flex items-center gap-2.5">
            <Info size={15} className="text-cyan-400" />
            <span className="text-white font-bold">{selectedNode.name}</span>
            {selectedNode.role && <span className="text-slate-400">({selectedNode.role})</span>}
            <span className="text-slate-600">|</span>
            <span className="text-slate-300">{selectedNode.details}</span>
          </div>
          <span className={`px-2.5 py-0.5 rounded text-[10px] uppercase font-bold border ${
            selectedNode.status === 'malicious' 
              ? 'bg-rose-950/80 text-rose-300 border-rose-800' 
              : selectedNode.status === 'suspicious'
              ? 'bg-amber-950/80 text-amber-300 border-amber-800'
              : selectedNode.status === 'contained'
              ? 'bg-indigo-950/80 text-indigo-300 border-indigo-800'
              : selectedNode.status === 'resolved'
              ? 'bg-emerald-950/90 text-emerald-300 border-emerald-600 shadow-[0_0_8px_rgba(16,185,129,0.3)]'
              : 'bg-emerald-950/80 text-emerald-300 border-emerald-800'
          }`}>
            {selectedNode.status === 'resolved' ? '✓ Threat Neutralized (Resolved)' : selectedNode.status === 'contained' ? '🛡 Containment Active (Quarantined)' : selectedNode.status}
          </span>
        </div>
      )}

      {/* Bottom Banner: Attack Vector Progression (Preserved in full for forensic evidence) */}
      {!isBannerDismissed && attackChain.length > 0 && (
        hasActiveThreats ? (
          /* Active Threat Banner (Red / Alarmed) */
          <div className="bg-gradient-to-r from-rose-950/40 via-slate-900/90 to-rose-950/30 border border-rose-900/50 rounded-2xl p-5 shadow-lg relative transition-all duration-300">
            <div className="flex items-center justify-between gap-4 mb-3.5">
              <div className="flex items-center gap-2.5">
                <div className="w-6 h-6 rounded-md bg-rose-900/60 border border-rose-700 flex items-center justify-center text-rose-300">
                  <AlertTriangle size={15} />
                </div>
                <h4 className="text-sm font-bold text-rose-400 tracking-wide">
                  Active Attack Vector Progression
                </h4>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => onInvestigate && onInvestigate()}
                  className="px-3.5 py-1.5 rounded-lg border border-rose-800/80 bg-rose-950/50 hover:bg-rose-900/60 text-rose-300 hover:text-white text-xs font-semibold transition-all cursor-pointer flex items-center gap-1.5 shadow-sm"
                >
                  <span>Investigate Incident</span>
                  <ArrowRight size={13} />
                </button>
                <button
                  onClick={() => setIsBannerDismissed(true)}
                  className="p-1.5 rounded-lg border border-slate-800 hover:bg-slate-800 text-slate-400 hover:text-white transition-colors cursor-pointer"
                  title="Dismiss Banner"
                >
                  <X size={14} />
                </button>
              </div>
            </div>

            {/* Breadcrumb Steps Row */}
            <div className="flex flex-wrap items-center gap-2 mb-2.5 font-mono text-xs">
              {attackChain.map((step, idx) => (
                <React.Fragment key={idx}>
                  <span className={`px-3 py-1.5 rounded-lg border text-xs font-bold ${
                    idx === attackChain.length - 1
                      ? 'bg-rose-950/80 border-rose-700 text-rose-200'
                      : 'bg-slate-900/90 border-slate-800 text-slate-200'
                  }`}>
                    {step.label}
                  </span>
                  {idx < attackChain.length - 1 && (
                    <ArrowRight size={13} className="text-rose-500 shrink-0" />
                  )}
                </React.Fragment>
              ))}
            </div>

            {/* Explanatory Behavior Sequence Row */}
            <div className="text-[11px] font-mono text-slate-400 flex flex-wrap items-center gap-2">
              <span>Authentication</span>
              <span className="text-rose-500">→</span>
              <span>Endpoint Device</span>
              <span className="text-rose-500">→</span>
              <span>Tool/Agent Invocation</span>
              <span className="text-rose-500">→</span>
              <span>API Access</span>
              <span className="text-rose-500">→</span>
              <span className="text-rose-300 font-semibold">Sensitive Store Access</span>
            </div>
          </div>
        ) : (
          /* Neutralized / Resolved Banner (Emerald Green - Evidence Preserved) */
          <div className="bg-gradient-to-r from-emerald-950/30 via-slate-900/90 to-teal-950/20 border border-emerald-800/50 rounded-2xl p-5 shadow-lg relative transition-all duration-300">
            <div className="flex items-center justify-between gap-4 mb-3.5">
              <div className="flex items-center gap-2.5">
                <div className="w-6 h-6 rounded-md bg-emerald-900/60 border border-emerald-600 flex items-center justify-center text-emerald-300">
                  <CheckCircle2 size={15} />
                </div>
                <h4 className="text-sm font-bold text-emerald-400 tracking-wide">
                  Attack Vector Neutralized &amp; Mitigated (Forensic Chain Preserved)
                </h4>
              </div>

              <div className="flex items-center gap-2">
                <span className="px-2.5 py-1 rounded-md text-[11px] font-mono font-bold bg-emerald-950/80 border border-emerald-700 text-emerald-300 shadow-[0_0_8px_rgba(16,185,129,0.2)]">
                  STATUS: RESOLVED (RISK: 0)
                </span>
                <button
                  onClick={() => setIsBannerDismissed(true)}
                  className="p-1.5 rounded-lg border border-slate-800 hover:bg-slate-800 text-slate-400 hover:text-white transition-colors cursor-pointer"
                  title="Dismiss Banner"
                >
                  <X size={14} />
                </button>
              </div>
            </div>

            {/* Breadcrumb Steps Row (in emerald) */}
            <div className="flex flex-wrap items-center gap-2 mb-2.5 font-mono text-xs">
              {attackChain.map((step, idx) => (
                <React.Fragment key={idx}>
                  <span className={`px-3 py-1.5 rounded-lg border text-xs font-bold ${
                    idx === attackChain.length - 1
                      ? 'bg-emerald-950/80 border-emerald-700 text-emerald-200'
                      : 'bg-slate-900/90 border-slate-800 text-slate-300'
                  }`}>
                    {step.label}
                  </span>
                  {idx < attackChain.length - 1 && (
                    <ArrowRight size={13} className="text-emerald-500 shrink-0" />
                  )}
                </React.Fragment>
              ))}
            </div>

            {/* Explanatory Behavior Sequence Row */}
            <div className="text-[11px] font-mono text-slate-400 flex flex-wrap items-center gap-2">
              <span>Verified Identity</span>
              <span className="text-emerald-500">→</span>
              <span>Secure Device</span>
              <span className="text-emerald-500">→</span>
              <span>Authorized Copilot</span>
              <span className="text-emerald-500">→</span>
              <span>Compliant Gateway</span>
              <span className="text-emerald-500">→</span>
              <span className="text-emerald-300 font-semibold">Access Restored &amp; Validated</span>
            </div>
          </div>
        )
      )}
    </div>
  );
}


export default LiveSecurityGraph;
