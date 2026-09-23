import axios from 'axios';

// Use environment variable VITE_API_URL or relative fallback, never hardcoding localhost
const API_BASE_URL = import.meta.env.VITE_API_URL || '';

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 15000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Helper to extract clean error message from API response
export function formatApiError(error) {
  if (error.response) {
    const data = error.response.data;
    if (data && typeof data === 'object') {
      if (typeof data.detail === 'string') return data.detail;
      if (Array.isArray(data.detail)) {
        return data.detail.map(d => `${d.loc ? d.loc.join('.') + ': ' : ''}${d.msg}`).join(', ');
      }
      if (data.message) return data.message;
    }
    return `Server returned error ${error.response.status}: ${error.response.statusText}`;
  } else if (error.request) {
    return 'Unable to reach the backend API. Please check that the server is running.';
  }
  return error.message || 'An unknown network error occurred.';
}

// --- Real API Service Functions ---

/**
 * Health check endpoint
 * GET /health
 */
export async function getHealth() {
  try {
    const res = await apiClient.get('/health');
    return { data: res.data, isLive: true };
  } catch (err) {
    throw new Error(formatApiError(err));
  }
}

/**
 * Fetch list of security events
 * GET /api/events
 */
export async function getEvents(params = {}) {
  try {
    const res = await apiClient.get('/api/events', { params });
    // Backend returns EventListResponse: { status, count, events }
    if (res.data && Array.isArray(res.data.events)) {
      return res.data.events;
    }
    return Array.isArray(res.data) ? res.data : [];
  } catch (err) {
    throw new Error(formatApiError(err));
  }
}

/**
 * Fetch single security event by ID
 * GET /api/events/{event_id}
 */
export async function getEvent(eventId) {
  try {
    const res = await apiClient.get(`/api/events/${encodeURIComponent(eventId)}`);
    return res.data;
  } catch (err) {
    throw new Error(formatApiError(err));
  }
}

/**
 * Ingest a security event
 * POST /api/events
 */
export async function ingestEvent(eventPayload) {
  try {
    const res = await apiClient.post('/api/events', eventPayload);
    return res.data;
  } catch (err) {
    throw new Error(formatApiError(err));
  }
}

/**
 * Fetch list of correlated incidents
 * GET /api/incidents
 */
export async function getIncidents(params = {}) {
  try {
    const res = await apiClient.get('/api/incidents', { params });
    return Array.isArray(res.data) ? res.data : [];
  } catch (err) {
    throw new Error(formatApiError(err));
  }
}

/**
 * Fetch detailed correlated incident by ID
 * GET /api/incidents/{incident_id}
 */
export async function getIncident(incidentId) {
  try {
    const res = await apiClient.get(`/api/incidents/${encodeURIComponent(incidentId)}`);
    return res.data;
  } catch (err) {
    throw new Error(formatApiError(err));
  }
}

/**
 * Analyze security event through intelligence pipeline
 * POST /api/analyze
 */
export async function analyzeEvent(payload) {
  try {
    const res = await apiClient.post('/api/analyze', payload);
    return res.data;
  } catch (err) {
    throw new Error(formatApiError(err));
  }
}

/**
 * Fetch list of security alerts
 * GET /api/alerts
 */
export async function getAlerts(params = {}) {
  try {
    const res = await apiClient.get('/api/alerts', { params });
    return Array.isArray(res.data) ? res.data : [];
  } catch (err) {
    throw new Error(formatApiError(err));
  }
}

/**
 * Fetch single security alert by ID
 * GET /api/alerts/{alert_id}
 */
export async function getAlert(alertId) {
  try {
    const res = await apiClient.get(`/api/alerts/${encodeURIComponent(alertId)}`);
    return res.data;
  } catch (err) {
    throw new Error(formatApiError(err));
  }
}

/**
 * Update alert status
 * PATCH /api/alerts/{alert_id}
 */
export async function updateAlertStatus(alertId, newStatus) {
  try {
    const res = await apiClient.patch(`/api/alerts/${encodeURIComponent(alertId)}`, { status: newStatus });
    return res.data;
  } catch (err) {
    throw new Error(formatApiError(err));
  }
}

/**
 * Fetch list of tracked users
 * GET /api/users
 */
export async function getUsers() {
  try {
    const res = await apiClient.get('/api/users');
    return Array.isArray(res.data) ? res.data : [];
  } catch (err) {
    throw new Error(formatApiError(err));
  }
}

/**
 * Fetch user activity graph
 * GET /api/users/{user_id}/activity-graph
 */
export async function getUserActivityGraph(userId, params = {}) {
  try {
    const res = await apiClient.get(`/api/users/${encodeURIComponent(userId)}/activity-graph`, { params });
    return res.data;
  } catch (err) {
    throw new Error(formatApiError(err));
  }
}

// --- Step 4: Risk-Adaptive Response & Containment Endpoints ---

/**
 * Fetch active response decision, executable actions, and audit trail for an incident
 * GET /api/response/{incident_id}
 */
export async function getIncidentResponse(incidentId) {
  try {
    const res = await apiClient.get(`/api/response/${encodeURIComponent(incidentId)}`);
    return res.data;
  } catch (err) {
    throw new Error(formatApiError(err));
  }
}

/**
 * Evaluate response decision for risk assessment and event
 * POST /api/response/evaluate
 */
export async function evaluateResponse(payload) {
  try {
    const res = await apiClient.post('/api/response/evaluate', payload);
    return res.data;
  } catch (err) {
    throw new Error(formatApiError(err));
  }
}

/**
 * Human-in-the-loop authorization: Approve containment actions for an incident
 * POST /api/response/{incident_id}/approve
 */
export async function approveIncidentResponse(incidentId, payload = {}) {
  try {
    const res = await apiClient.post(`/api/response/${encodeURIComponent(incidentId)}/approve`, payload);
    return res.data;
  } catch (err) {
    throw new Error(formatApiError(err));
  }
}

/**
 * Reject containment actions for an incident
 * POST /api/response/{incident_id}/reject
 */
export async function rejectIncidentResponse(incidentId, payload = {}) {
  try {
    const res = await apiClient.post(`/api/response/${encodeURIComponent(incidentId)}/reject`, payload);
    return res.data;
  } catch (err) {
    throw new Error(formatApiError(err));
  }
}

/**
 * False-positive recovery: Lift restrictions, mark incident resolved, and preserve audit trail
 * POST /api/response/{incident_id}/recover
 */
export async function recoverFalsePositive(incidentId, payload = {}) {
  try {
    const res = await apiClient.post(`/api/response/${encodeURIComponent(incidentId)}/recover`, payload);
    return res.data;
  } catch (err) {
    throw new Error(formatApiError(err));
  }
}

/**
 * Retrieve immutable audit trail records
 * GET /api/response/audit-trail
 */
export async function getAuditTrail(params = {}) {
  try {
    const res = await apiClient.get('/api/response/audit-trail', { params });
    return Array.isArray(res.data) ? res.data : [];
  } catch (err) {
    throw new Error(formatApiError(err));
  }
}

/**
 * Retrieve multi-stage approval record and Two-Person Rule state for an incident
 * GET /api/response/{incident_id}/approval-status
 */
export async function getApprovalStatus(incidentId) {
  try {
    const res = await apiClient.get(`/api/response/${encodeURIComponent(incidentId)}/approval-status`);
    return res.data;
  } catch (err) {
    throw new Error(formatApiError(err));
  }
}

/**
 * Evaluate approver behavioral risk and role authorization before granting approval
 * POST /api/response/{incident_id}/approvals/evaluate-approver
 */
export async function evaluateApprover(incidentId, payload = {}) {
  try {
    const res = await apiClient.post(`/api/response/${encodeURIComponent(incidentId)}/approvals/evaluate-approver`, payload);
    return res.data;
  } catch (err) {
    throw new Error(formatApiError(err));
  }
}

/**
 * Second independent approval for Two-Person Rule
 * POST /api/response/{incident_id}/second-approve
 */
export async function secondApproveIncidentResponse(incidentId, payload = {}) {
  try {
    const res = await apiClient.post(`/api/response/${encodeURIComponent(incidentId)}/second-approve`, payload);
    return res.data;
  } catch (err) {
    throw new Error(formatApiError(err));
  }
}

/**
 * Step 6: Acknowledge alert without resolving the underlying incident
 * POST /api/alerts/{alert_id}/acknowledge
 */
export async function acknowledgeAlert(alertId, payload = {}) {
  try {
    const res = await apiClient.post(`/api/alerts/${encodeURIComponent(alertId)}/acknowledge`, payload);
    return res.data;
  } catch (err) {
    throw new Error(formatApiError(err));
  }
}

/**
 * Step 6: Trigger voice replay and audit logging
 * POST /api/alerts/{alert_id}/replay-voice
 */
export async function replayAlertVoice(alertId, payload = {}) {
  try {
    const res = await apiClient.post(`/api/alerts/${encodeURIComponent(alertId)}/replay-voice`, payload);
    return res.data;
  } catch (err) {
    throw new Error(formatApiError(err));
  }
}

/**
 * Step 6: Get active unacknowledged critical alert for top banner
 * GET /api/alerts/active-critical
 */
export async function getActiveCriticalAlert() {
  try {
    const res = await apiClient.get('/api/alerts/active-critical');
    return res.data;
  } catch (err) {
    throw new Error(formatApiError(err));
  }
}

export default {
  getHealth,
  getEvents,
  getEvent,
  ingestEvent,
  getIncidents,
  getIncident,
  analyzeEvent,
  getAlerts,
  getAlert,
  updateAlertStatus,
  acknowledgeAlert,
  replayAlertVoice,
  getActiveCriticalAlert,
  getUsers,
  getUserActivityGraph,
  getIncidentResponse,
  evaluateResponse,
  approveIncidentResponse,
  secondApproveIncidentResponse,
  rejectIncidentResponse,
  recoverFalsePositive,
  getApprovalStatus,
  evaluateApprover,
  getAuditTrail,
  formatApiError,
};

