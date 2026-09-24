import { createClient } from '@supabase/supabase-js';

// ============================================================================
// SUPABASE CLIENT INITIALIZATION
// Single Source of Truth for all INSIGHT prototype data
// ============================================================================
const supabaseUrl = (typeof import.meta !== 'undefined' && import.meta.env?.VITE_SUPABASE_URL) || (typeof process !== 'undefined' && process.env?.VITE_SUPABASE_URL) || '';
const supabaseAnonKey = (typeof import.meta !== 'undefined' && import.meta.env?.VITE_SUPABASE_ANON_KEY) || (typeof process !== 'undefined' && process.env?.VITE_SUPABASE_ANON_KEY) || '';

export const isSupabaseConfigured = Boolean(
  supabaseUrl && 
  supabaseAnonKey && 
  supabaseUrl.trim() !== '' && 
  supabaseAnonKey.trim() !== '' &&
  supabaseUrl.startsWith('http')
);

export const supabase = isSupabaseConfigured 
  ? createClient(supabaseUrl, supabaseAnonKey, {
      auth: { persistSession: false },
      realtime: { params: { eventsPerSecond: 10 } }
    })
  : null;

// ============================================================================
// RISK LEVEL CALCULATOR (Standardized SOC Thresholds)
// LOW: 0–39 | MODERATE: 40–69 | HIGH: 70–84 | CRITICAL: 85–100
// ============================================================================
export function calculateRiskLevel(score) {
  const num = Number(score);
  if (isNaN(num) || num < 40) return 'LOW';
  if (num < 70) return 'MODERATE';
  if (num < 85) return 'HIGH';
  return 'CRITICAL';
}

// Helper to check if ISO date string belongs to today's calendar date
export function isToday(dateString) {
  if (!dateString) return false;
  try {
    const d = new Date(dateString);
    const now = new Date();
    return d.getFullYear() === now.getFullYear() &&
           d.getMonth() === now.getMonth() &&
           d.getDate() === now.getDate();
  } catch {
    return false;
  }
}

/**
 * Checks whether an alert is currently ACTIVE.
 * Returns FALSE for: 'approved', 'resolved', 'rejected', 'dismissed', 'closed'.
 * Returns TRUE for: 'new', 'open', 'pending', 'active', 'escalated', etc.
 */
export function isAlertActive(status) {
  if (!status) return true;
  const s = String(status).toLowerCase().trim();
  const inactiveStatuses = ['approved', 'resolved', 'rejected', 'dismissed', 'closed'];
  return !inactiveStatuses.includes(s);
}

// ============================================================================
// CENTRAL DATA SERVICE API FUNCTIONS (PURE SUPABASE SOURCE OF TRUTH)
// Chunked range pagination ensures complete retrieval beyond 1,000 row limits
// ============================================================================

/**
 * 1. getEmployees()
 * Fetches ALL employees from Supabase 'employees' table.
 * Uses range pagination chunks so all 1,000+ employees are retrieved.
 * Zero hardcoded mock fallback.
 */
export async function getEmployees() {
  if (!isSupabaseConfigured || !supabase) {
    return { data: [], error: 'Supabase is not configured', source: 'none' };
  }

  try {
    const allEmployees = [];
    const chunkSize = 1000;
    let from = 0;

    while (true) {
      const { data, error } = await supabase
        .from('employees')
        .select('*')
        .order('employee_code', { ascending: true })
        .range(from, from + chunkSize - 1);

      if (error) {
        console.error('getEmployees Supabase query error:', error);
        return { data: allEmployees, error: error.message, source: 'supabase' };
      }

      if (!data || data.length === 0) break;
      allEmployees.push(...data);

      if (data.length < chunkSize) break;
      from += chunkSize;
    }

    return { data: allEmployees, error: null, source: 'supabase' };
  } catch (err) {
    console.error('getEmployees exception:', err);
    return { data: [], error: err.message, source: 'supabase' };
  }
}

/**
 * 2. getEmployeeByCode(employeeCode)
 * Resolves an employee by employee_code or name directly from Supabase.
 */
export async function getEmployeeByCode(employeeCode) {
  if (!employeeCode) return { data: null, error: 'missing employeeCode' };
  if (!isSupabaseConfigured || !supabase) return { data: null, error: 'Supabase not configured' };

  try {
    const { data, error } = await supabase
      .from('employees')
      .select('*')
      .or(`employee_code.eq.${employeeCode},name.eq.${employeeCode}`)
      .maybeSingle();

    return { data: data || null, error: error ? error.message : null };
  } catch (err) {
    console.error('getEmployeeByCode notice:', err);
    return { data: null, error: err.message };
  }
}

/**
 * 3. getLatestRiskEvents()
 * Fetches ALL risk events from Supabase 'risk_events' table.
 * No arbitrary 200 limit — paginates to retrieve all 5,000+ events.
 * Ordered by detected_at DESC so each employee's most recent event is first.
 */
export async function getLatestRiskEvents() {
  if (!isSupabaseConfigured || !supabase) {
    return { data: [], error: 'Supabase is not configured', source: 'none' };
  }

  try {
    const allRiskEvents = [];
    const chunkSize = 1000;
    let from = 0;

    while (true) {
      const { data, error } = await supabase
        .from('risk_events')
        .select('*')
        .order('detected_at', { ascending: false })
        .range(from, from + chunkSize - 1);

      if (error) {
        console.error('getLatestRiskEvents Supabase query error:', error);
        return { data: allRiskEvents, error: error.message, source: 'supabase' };
      }

      if (!data || data.length === 0) break;
      allRiskEvents.push(...data);

      if (data.length < chunkSize) break;
      from += chunkSize;
    }

    return { data: allRiskEvents, error: null, source: 'supabase' };
  } catch (err) {
    console.error('getLatestRiskEvents exception:', err);
    return { data: [], error: err.message, source: 'supabase' };
  }
}

/**
 * 4. getEmployeeRiskHistory(employeeId)
 * Fetches all risk events for a specific employee, ordered chronologically.
 */
export async function getEmployeeRiskHistory(employeeId) {
  if (!employeeId) return { data: [], error: 'missing employeeId' };
  if (!isSupabaseConfigured || !supabase) return { data: [], error: 'Supabase not configured' };

  try {
    const { data, error } = await supabase
      .from('risk_events')
      .select('*')
      .eq('employee_id', employeeId)
      .order('detected_at', { ascending: true });

    return { data: data || [], error: error ? error.message : null };
  } catch (err) {
    console.error('getEmployeeRiskHistory notice:', err);
    return { data: [], error: err.message };
  }
}

/**
 * 5. getAccessLogs(employeeId, limit = 100)
 * Fetches recent access logs for a specific employee.
 */
export async function getAccessLogs(employeeId, limit = 100) {
  if (!employeeId) return { data: [], error: 'missing employeeId' };
  if (!isSupabaseConfigured || !supabase) return { data: [], error: 'Supabase not configured' };

  try {
    const { data, error } = await supabase
      .from('access_logs')
      .select('*')
      .eq('employee_id', employeeId)
      .order('access_time', { ascending: false })
      .limit(limit);

    return { data: data || [], error: error ? error.message : null };
  } catch (err) {
    console.error('getAccessLogs notice:', err);
    return { data: [], error: err.message };
  }
}

/**
 * 6. getAllAccessLogs()
 * Fetches access logs from Supabase across all employees.
 * Uses range pagination to retrieve the full dataset (all 10,000 logs).
 */
export async function getAllAccessLogs() {
  if (!isSupabaseConfigured || !supabase) {
    return { data: [], error: 'Supabase is not configured' };
  }

  try {
    const allLogs = [];
    const chunkSize = 1000;
    let from = 0;

    while (true) {
      const { data, error } = await supabase
        .from('access_logs')
        .select('*')
        .order('access_time', { ascending: false })
        .range(from, from + chunkSize - 1);

      if (error) {
        console.error('getAllAccessLogs Supabase query error:', error);
        return { data: allLogs, error: error.message };
      }

      if (!data || data.length === 0) break;
      allLogs.push(...data);

      if (data.length < chunkSize) break;
      from += chunkSize;
    }

    return { data: allLogs, error: null };
  } catch (err) {
    console.error('getAllAccessLogs exception:', err);
    return { data: [], error: err.message };
  }
}

/**
 * 7. getAlerts()
 * Fetches ALL security alerts from Supabase 'alerts' table.
 * No arbitrary 200 limit — retrieves all 205+ alerts using range pagination.
 */
export async function getAlerts() {
  if (!isSupabaseConfigured || !supabase) {
    return { data: [], error: 'Supabase is not configured', source: 'none' };
  }

  try {
    const allAlerts = [];
    const chunkSize = 1000;
    let from = 0;

    while (true) {
      const { data, error } = await supabase
        .from('alerts')
        .select('*')
        .order('created_at', { ascending: false })
        .range(from, from + chunkSize - 1);

      if (error) {
        console.error('getAlerts Supabase query error:', error);
        return { data: allAlerts, error: error.message, source: 'supabase' };
      }

      if (!data || data.length === 0) break;
      allAlerts.push(...data);

      if (data.length < chunkSize) break;
      from += chunkSize;
    }

    return { data: allAlerts, error: null, source: 'supabase' };
  } catch (err) {
    console.error('getAlerts exception:', err);
    return { data: [], error: err.message, source: 'supabase' };
  }
}

/**
 * 8. getEmployeeAlerts(employeeId)
 * Fetches all alerts generated for a specific employee.
 */
export async function getEmployeeAlerts(employeeId) {
  if (!employeeId) return { data: [], error: 'missing employeeId' };
  if (!isSupabaseConfigured || !supabase) return { data: [], error: 'Supabase not configured' };

  try {
    const { data, error } = await supabase
      .from('alerts')
      .select('*')
      .eq('employee_id', employeeId)
      .order('created_at', { ascending: false });

    return { data: data || [], error: error ? error.message : null };
  } catch (err) {
    console.error('getEmployeeAlerts notice:', err);
    return { data: [], error: err.message };
  }
}

/**
 * 9. getIncidents(employeeId)
 * Fetches incidents from Supabase.
 */
export async function getIncidents(employeeId = null) {
  if (!isSupabaseConfigured || !supabase) return { data: [], error: 'Supabase not configured' };

  try {
    let query = supabase.from('incidents').select('*').order('created_at', { ascending: false });
    if (employeeId) {
      query = query.eq('employee_id', employeeId);
    }
    const { data, error } = await query;
    return { data: data || [], error: error ? error.message : null };
  } catch (err) {
    console.error('getIncidents notice:', err);
    return { data: [], error: err.message };
  }
}

/**
 * 10. getApprovals(employeeId)
 * Fetches approvals from Supabase.
 */
export async function getApprovals(employeeId = null) {
  if (!isSupabaseConfigured || !supabase) return { data: [], error: 'Supabase not configured' };

  try {
    let query = supabase.from('approvals').select('*').order('requested_at', { ascending: false });
    if (employeeId) {
      query = query.eq('employee_id', employeeId);
    }
    const { data, error } = await query;
    return { data: data || [], error: error ? error.message : null };
  } catch (err) {
    console.error('getApprovals notice:', err);
    return { data: [], error: err.message };
  }
}

/**
 * 11. insertRiskEvent(payload)
 * Inserts a detected threat risk event into Supabase.
 */
export async function insertRiskEvent({ employee_id, event_type, description, risk_score, severity }) {
  if (!isSupabaseConfigured || !supabase) {
    return { data: null, error: 'Supabase not configured' };
  }
  try {
    const { data, error } = await supabase
      .from('risk_events')
      .insert([
        {
          employee_id,
          event_type: event_type || 'SUSPICIOUS_ACTIVITY',
          description: description || 'Unusual sensitive-data access',
          risk_score: Number(risk_score),
          severity: severity || calculateRiskLevel(risk_score),
          detected_at: new Date().toISOString()
        }
      ])
      .select();

    return { data: data?.[0] || null, error: error ? error.message : null };
  } catch (err) {
    return { data: null, error: err.message };
  }
}

/**
 * 12. fetchFullEmployeeDetail(employeeUuid)
 * Parallel fetch of all relational records for employee dossier.
 */
export async function fetchFullEmployeeDetail(employeeUuid) {
  if (!employeeUuid) {
    return {
      riskEvents: [],
      accessLogs: [],
      alerts: [],
      incidents: [],
      approvals: []
    };
  }

  const [riskRes, accessRes, alertRes, incRes, appRes] = await Promise.allSettled([
    getEmployeeRiskHistory(employeeUuid),
    getAccessLogs(employeeUuid, 100),
    getEmployeeAlerts(employeeUuid),
    getIncidents(employeeUuid),
    getApprovals(employeeUuid)
  ]);

  return {
    riskEvents: riskRes.status === 'fulfilled' && riskRes.value.data ? riskRes.value.data : [],
    accessLogs: accessRes.status === 'fulfilled' && accessRes.value.data ? accessRes.value.data : [],
    alerts: alertRes.status === 'fulfilled' && alertRes.value.data ? alertRes.value.data : [],
    incidents: incRes.status === 'fulfilled' && incRes.value.data ? incRes.value.data : [],
    approvals: appRes.status === 'fulfilled' && appRes.value.data ? appRes.value.data : []
  };
}

// Aliases
export const fetchEmployeesFromSupabase = getEmployees;
export const fetchRiskEventsFromSupabase = getLatestRiskEvents;
export const fetchAlertsFromSupabase = getAlerts;
export const fetchEmployeeDetailFromSupabase = fetchFullEmployeeDetail;
export const insertRiskEventToSupabase = insertRiskEvent;

/**
 * 13. updateAlertStatusInSupabase(alertId, newStatus)
 * Updates the alert record in Supabase 'alerts' table.
 * Does NOT delete the row, preserving audit trails and compliance history.
 * If status is approved or resolved, records resolved_at timestamp.
 */
export async function updateAlertStatusInSupabase(alertId, newStatus = 'approved') {
  if (!alertId) return { data: null, error: 'Missing alertId' };
  if (!isSupabaseConfigured || !supabase) {
    return { data: null, error: 'Supabase is not configured' };
  }

  try {
    const s = String(newStatus).toLowerCase().trim();
    const updatePayload = {
      status: s
    };

    if (s === 'approved' || s === 'resolved' || s === 'rejected' || s === 'dismissed' || s === 'closed') {
      updatePayload.resolved_at = new Date().toISOString();
    }

    const { data, error } = await supabase
      .from('alerts')
      .update(updatePayload)
      .eq('id', alertId)
      .select();

    if (error) {
      console.error('updateAlertStatusInSupabase error:', error);
      return { data: null, error: error.message };
    }

    return { data: data?.[0] || null, error: null };
  } catch (err) {
    console.error('updateAlertStatusInSupabase exception:', err);
    return { data: null, error: err.message };
  }
}

export const approveAlertInSupabase = (alertId) => updateAlertStatusInSupabase(alertId, 'approved');
export const resolveAlertInSupabase = (alertId) => updateAlertStatusInSupabase(alertId, 'resolved');

/**
 * 14. approveAllAlertsForUserInSupabase(userIdentifier)
 * Approves / resolves all alerts in Supabase 'alerts' table for a specific employee.
 * Matches by employee_id UUID, employee_code, or employee name.
 * Also checks alert messages containing the identifier.
 * Sets status = 'approved', resolved_at = now.
 * Does NOT delete rows, maintaining compliance and audit trails.
 */
export async function approveAllAlertsForUserInSupabase(userIdentifier) {
  if (!userIdentifier) return { count: 0, error: 'Missing userIdentifier' };
  if (!isSupabaseConfigured || !supabase) {
    return { count: 0, error: 'Supabase is not configured' };
  }

  try {
    const resolvedAt = new Date().toISOString();
    let updatedCount = 0;
    const cleanId = String(userIdentifier).trim();

    // 1. Check if userIdentifier matches any employee in 'employees' table
    let matchingEmployeeUuids = [];
    try {
      const { data: emps } = await supabase
        .from('employees')
        .select('id, employee_code, name')
        .or(`id.eq.${cleanId},employee_code.eq.${cleanId},name.ilike.%${cleanId}%`)
        .limit(10);

      if (emps && emps.length > 0) {
        matchingEmployeeUuids = emps.map(e => e.id);
      }
    } catch (e) {
      console.warn('Employee lookup notice in Supabase:', e);
    }

    // If cleanId looks like a UUID, include it directly
    if (/^[0-9a-f-]{36}$/i.test(cleanId) && !matchingEmployeeUuids.includes(cleanId)) {
      matchingEmployeeUuids.push(cleanId);
    }

    // 2. Update alerts by employee_id
    if (matchingEmployeeUuids.length > 0) {
      const { data: updatedEmps, error: errEmp } = await supabase
        .from('alerts')
        .update({ status: 'approved', resolved_at: resolvedAt })
        .in('employee_id', matchingEmployeeUuids)
        .select('id');

      if (updatedEmps) updatedCount += updatedEmps.length;
      if (errEmp) console.warn('Alerts update by employee_id notice:', errEmp);
    }

    // 3. Also update alerts by message text match for user name/code
    try {
      const { data: updatedMsg, error: errMsg } = await supabase
        .from('alerts')
        .update({ status: 'approved', resolved_at: resolvedAt })
        .ilike('message', `%${cleanId}%`)
        .select('id');

      if (updatedMsg) updatedCount += updatedMsg.length;
    } catch (e) {
      console.warn('Alerts update by message notice:', e);
    }

    return { success: true, count: updatedCount, error: null };
  } catch (err) {
    console.error('approveAllAlertsForUserInSupabase exception:', err);
    return { success: false, count: 0, error: err.message };
  }
}

// ============================================================================
// DASHBOARD METRICS & DERIVATION (PURE SUPABASE SOURCE)
// ============================================================================

export function getDashboardMetrics(enrichedEmployees = [], alerts = []) {
  const totalEmployees = enrichedEmployees.length;
  const highRiskEmployees = enrichedEmployees.filter(e => (e.latestRiskScore || 0) >= 70).length;
  
  // Critical alerts count represents ACTIVE unapproved/unresolved critical threats
  const criticalAlerts = alerts
    .filter(a => isAlertActive(a.status))
    .filter(a => {
      const score = Number(a.risk_score || 0);
      const type = String(a.alert_type || a.severity || '').toUpperCase();
      return score >= 85 || type === 'CRITICAL';
    }).length;

  // Alerts today: active alerts logged today
  const alertsToday = alerts
    .filter(a => isAlertActive(a.status))
    .filter(a => isToday(a.created_at)).length;

  return {
    totalEmployees,
    highRiskEmployees,
    criticalAlerts,
    alertsToday
  };
}

/**
 * Calculates risk distribution across ALL employees.
 * Each employee is counted exactly once based on their latest risk event:
 * - LOW: 0–39
 * - MODERATE: 40–69
 * - HIGH: 70–84
 * - CRITICAL: 85–100
 * Guaranteed: LOW + MODERATE + HIGH + CRITICAL === enrichedEmployees.length
 */
export function getRiskDistribution(enrichedEmployees = []) {
  const distribution = {
    LOW: 0,
    MODERATE: 0,
    HIGH: 0,
    CRITICAL: 0
  };

  enrichedEmployees.forEach(emp => {
    const score = Number(emp.latestRiskScore || 0);
    if (score >= 85) distribution.CRITICAL++;
    else if (score >= 70) distribution.HIGH++;
    else if (score >= 40) distribution.MODERATE++;
    else distribution.LOW++;
  });

  return distribution;
}

/**
 * deriveDashboardState(employees, riskEvents, alerts, accessLogs)
 * Joins raw Supabase tables into the unified dashboard state.
 */
export function deriveDashboardState(employees = [], riskEvents = [], alerts = [], accessLogs = []) {
  const employeeUuidMap = new Map();
  employees.forEach(emp => {
    employeeUuidMap.set(emp.id, emp);
  });

  // Group risk events by employee_id and sort chronologically DESC
  const employeeRiskEventsMap = new Map();
  riskEvents.forEach(evt => {
    if (!employeeRiskEventsMap.has(evt.employee_id)) {
      employeeRiskEventsMap.set(evt.employee_id, []);
    }
    employeeRiskEventsMap.get(evt.employee_id).push(evt);
  });

  // Group access logs by employee_id
  const employeeAccessLogsMap = new Map();
  accessLogs.forEach(log => {
    if (!employeeAccessLogsMap.has(log.employee_id)) {
      employeeAccessLogsMap.set(log.employee_id, []);
    }
    employeeAccessLogsMap.get(log.employee_id).push(log);
  });

  // Group alerts by employee_id
  const employeeAlertsMap = new Map();
  alerts.forEach(alt => {
    if (!employeeAlertsMap.has(alt.employee_id)) {
      employeeAlertsMap.set(alt.employee_id, []);
    }
    employeeAlertsMap.get(alt.employee_id).push(alt);
  });

  // 1. Enrich ALL employees from Supabase
  const enrichedEmployees = employees.map(emp => {
    const empRiskEvents = employeeRiskEventsMap.get(emp.id) || [];
    const empAccessLogs = employeeAccessLogsMap.get(emp.id) || [];
    const empAlerts = employeeAlertsMap.get(emp.id) || [];

    // Latest risk event is the first one since events are ordered by detected_at DESC
    const latestRiskEvent = empRiskEvents[0] || null;
    const latestAccessLog = empAccessLogs[0] || null;
    const latestAlert = empAlerts[0] || null;

    let latestRiskScore = 0;
    let latestActivity = 'No recent activity recorded';
    let lastActivityTime = emp.created_at ? new Date(emp.created_at).toLocaleDateString() : 'N/A';

    if (latestRiskEvent) {
      latestRiskScore = Number(latestRiskEvent.risk_score || 0);
    } else if (latestAlert) {
      latestRiskScore = Number(latestAlert.risk_score || 0);
    }

    if (latestAccessLog) {
      latestActivity = `${latestAccessLog.action} on ${latestAccessLog.resource_name} (${latestAccessLog.resource_type || 'Resource'})`;
      lastActivityTime = latestAccessLog.access_time 
        ? new Date(latestAccessLog.access_time).toLocaleString() 
        : 'Recently';
    } else if (latestRiskEvent) {
      latestActivity = latestRiskEvent.description || latestRiskEvent.event_type;
      lastActivityTime = latestRiskEvent.detected_at 
        ? new Date(latestRiskEvent.detected_at).toLocaleString() 
        : 'Recently';
    } else if (latestAlert) {
      latestActivity = latestAlert.message || latestAlert.alert_type;
      lastActivityTime = latestAlert.created_at 
        ? new Date(latestAlert.created_at).toLocaleString() 
        : 'Recently';
    }

    const calculatedRiskLevel = calculateRiskLevel(latestRiskScore);

    const riskHistory = empRiskEvents
      .slice(0, 15)
      .reverse()
      .map(r => ({
        timestamp: r.detected_at 
          ? new Date(r.detected_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) 
          : '--:--',
        score: Number(r.risk_score || 0),
        detected_at: r.detected_at,
        description: r.description
      }));

    return {
      id: emp.id,
      employee_code: emp.employee_code,
      name: emp.name,
      department: emp.department,
      role: emp.role,
      email: emp.email,
      status: emp.status || 'ACTIVE',
      created_at: emp.created_at,
      latestRiskScore,
      riskLevel: calculatedRiskLevel,
      latestActivity,
      lastActivityTime,
      riskHistory,
      riskEventsCount: empRiskEvents.length,
      accessLogsCount: empAccessLogs.length,
      alertsCount: empAlerts.length,
      latestRiskEvent,
      latestAccessLog,
      latestAlert
    };
  });

  // 2. Enrich alerts with employee details
  const enrichedAlerts = alerts.map(alt => {
    const emp = employeeUuidMap.get(alt.employee_id);
    const score = Number(alt.risk_score || 0);
    const alertType = (alt.alert_type || '').toUpperCase();
    const severity = alertType === 'CRITICAL' || score >= 85 
      ? 'CRITICAL' 
      : alertType === 'HIGH' || score >= 70 
      ? 'HIGH' 
      : alertType === 'MODERATE' || score >= 40 
      ? 'MODERATE' 
      : 'LOW';

    return {
      id: alt.id,
      employee_id: alt.employee_id,
      employee_code: emp ? emp.employee_code : 'UNKNOWN',
      employee_name: emp ? emp.name : 'Unknown Employee',
      risk_score: score,
      alert_type: alt.alert_type || severity,
      severity,
      message: alt.message || 'Security alert generated by workflow',
      status: alt.status || 'NEW',
      created_at: alt.created_at,
      resolved_at: alt.resolved_at,
      risk_event_id: alt.risk_event_id,
      raw_record: alt
    };
  });

  // Active alerts for Threat Overview and live alert feed
  const activeAlerts = enrichedAlerts.filter(a => isAlertActive(a.status));
  const historicalAlerts = enrichedAlerts.filter(a => !isAlertActive(a.status));

  const metrics = getDashboardMetrics(enrichedEmployees, enrichedAlerts);
  const riskDistribution = getRiskDistribution(enrichedEmployees);

  return {
    ...metrics,
    riskDistribution,
    employees: enrichedEmployees,
    alerts: activeAlerts, // Active unapproved/unresolved alerts for Threat Overview
    allAlerts: enrichedAlerts, // Full audit trail for historical inspection
    historicalAlerts,
    activeAlertsCount: activeAlerts.length
  };
}
