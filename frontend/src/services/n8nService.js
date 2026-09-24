// Default production webhook URL provided in specification
export const N8N_PRODUCTION_WEBHOOK = 
  import.meta.env.VITE_N8N_WEBHOOK_URL || 
  'https://fatimasiddiqui.app.n8n.cloud/webhook/insider-risk-alert';

/**
 * Sends a threat event payload to the n8n production webhook.
 * Expected payload:
 * {
 *   "employee_id": "EMP001",
 *   "risk_score": 87,
 *   "severity": "CRITICAL",
 *   "event": "Unusual sensitive-data access"
 * }
 * 
 * Note: Does NOT inject local fake alerts into frontend state.
 * The workflow handles inserting the record into Supabase, and the frontend
 * refetches directly from Supabase as the single source of truth.
 */
export async function sendThreatAlert(payload) {
  const startTime = performance.now();

  // 1. Validation
  const riskScore = Number(payload.risk_score);
  if (isNaN(riskScore) || riskScore < 0 || riskScore > 100) {
    return {
      ok: false,
      status: 400,
      statusText: 'Validation Error',
      error: 'risk_score must be a valid number between 0 and 100',
      timeMs: 0,
      data: null
    };
  }

  const validSeverities = ['LOW', 'MODERATE', 'HIGH', 'CRITICAL'];
  const severity = String(payload.severity || '').toUpperCase();
  if (!validSeverities.includes(severity)) {
    return {
      ok: false,
      status: 400,
      statusText: 'Validation Error',
      error: `severity must be one of: ${validSeverities.join(', ')}`,
      timeMs: 0,
      data: null
    };
  }

  if (!payload.employee_id || typeof payload.employee_id !== 'string') {
    return {
      ok: false,
      status: 400,
      statusText: 'Validation Error',
      error: 'employee_id is required',
      timeMs: 0,
      data: null
    };
  }

  const cleanPayload = {
    employee_id: payload.employee_id.trim(),
    risk_score: Math.round(riskScore),
    severity: severity,
    event: (payload.event || 'Unusual sensitive-data access').trim()
  };

  try {
    const response = await fetch(N8N_PRODUCTION_WEBHOOK, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(cleanPayload)
    });

    const endTime = performance.now();
    const timeMs = Math.round(endTime - startTime);

    let responseData = null;
    const textResponse = await response.text();
    try {
      responseData = JSON.parse(textResponse);
    } catch {
      responseData = { message: textResponse || response.statusText };
    }

    const isSuccess = response.ok;
    const isHighRisk = cleanPayload.risk_score >= 70;

    return {
      ok: isSuccess,
      status: response.status,
      statusText: response.statusText,
      data: responseData,
      rawText: textResponse,
      timeMs,
      requestPayload: cleanPayload,
      isHighRiskWorkflowTriggered: isHighRisk
    };
  } catch (networkError) {
    const endTime = performance.now();
    const timeMs = Math.round(endTime - startTime);

    return {
      ok: false,
      status: 0,
      statusText: 'Network / CORS Error',
      error: networkError.message || 'Failed to reach n8n webhook. Please check network connectivity.',
      timeMs,
      requestPayload: cleanPayload
    };
  }
}

/**
 * Health check probe for n8n Webhook connection.
 */
export async function testN8nConnection() {
  const startTime = performance.now();

  try {
    const testPayload = {
      employee_id: 'EMP001',
      risk_score: 10,
      severity: 'LOW',
      event: 'Connection Health Check Probe'
    };

    const response = await fetch(N8N_PRODUCTION_WEBHOOK, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(testPayload)
    });

    const endTime = performance.now();
    const timeMs = Math.round(endTime - startTime);
    const text = await response.text();

    let data = null;
    try {
      data = JSON.parse(text);
    } catch {
      data = { message: text };
    }

    return {
      connected: response.ok,
      status: response.status,
      statusText: response.statusText,
      data,
      timeMs,
      url: N8N_PRODUCTION_WEBHOOK
    };
  } catch (err) {
    const endTime = performance.now();
    return {
      connected: false,
      status: 0,
      statusText: 'Unreachable',
      error: err.message,
      timeMs: Math.round(endTime - startTime),
      url: N8N_PRODUCTION_WEBHOOK
    };
  }
}
