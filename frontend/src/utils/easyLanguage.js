/**
 * TechFusion Easy Mode Language Translation Helpers
 * Translates cybersecurity jargon into clear, accessible language for non-technical users.
 */

export const EASY_TRANSLATIONS = {
  // Signals & Attack Concepts
  'external attack-chain correlation': 'Multiple suspicious actions were connected into one attack.',
  'external_ip_access': 'Connection originated from an unverified external network.',
  'privilege escalation': 'The account gained access to something it normally should not use.',
  'privilege_escalation': 'The account gained access to something it normally should not use.',
  'data exfiltration': 'Sensitive data may have been taken out of the system.',
  'data_exfiltration': 'Sensitive data may have been taken out of the system.',
  'bulk_data_access': 'Abnormally large data export attempt.',
  'sensitive_resource': 'High-value confidential customer database accessed.',
  'unknown_device': 'Activity came from an unrecognized device.',
  'unexpected_ai_agent_activity': 'AI assistant performed actions outside its normal routine.',
  'unexpected_tool_usage': 'Restricted database tool executed without prior clearance.',
  'prompt_injection': 'Unauthorized override instructions sent to AI agent.',
  
  // Status & Modes
  'APPROVER_2_REQUIRED': 'Another authorized person must approve this action.',
  'APPROVAL_PENDING': 'Waiting for required human approval before continuing.',
  'APPROVAL_BLOCKED': 'Approval blocked due to risk verification check.',
  'DRY_RUN': 'AI has prepared the action. Nothing has been changed yet.',
  'SIMULATED': 'AI has prepared the action. Nothing has been changed yet.',
  
  // Containment Actions
  'RESTRICT_SESSION': 'Temporarily restrict this session',
  'CONTAIN_AGENT': 'Stop the AI agent from using restricted tools',
  'BLOCK_SOURCE': 'Block the suspicious source',
  'REVOKE_TOKEN': 'Invalidate compromised login keys',
  'QUARANTINE_AGENT': 'Quarantine the active AI agent instance',
  'LOCK_USER': 'Temporarily lock the user account to prevent further access'
};

/**
 * Translates technical signal or term into plain human description
 */
export function translateTechnicalTerm(term) {
  if (!term) return 'General security signal';
  const cleanKey = String(term).trim().toLowerCase();
  
  for (const [key, value] of Object.entries(EASY_TRANSLATIONS)) {
    if (cleanKey === key.toLowerCase() || cleanKey.includes(key.toLowerCase())) {
      return value;
    }
  }
  
  // Convert snake_case or SCREAMING_SNAKE to readable words
  return term
    .replace(/_/g, ' ')
    .replace(/\b\w/g, c => c.toUpperCase());
}

/**
 * Returns human friendly risk label and score display
 */
export function getEasyRiskDisplay(level, score) {
  const normLevel = (level || 'CRITICAL').toUpperCase();
  let text = 'Low Risk';
  if (normLevel === 'CRITICAL') text = 'Critical Risk';
  else if (normLevel === 'HIGH') text = 'Very High Risk';
  else if (normLevel === 'MODERATE') text = 'Moderate Risk';

  return {
    label: text,
    scoreText: score !== null && score !== undefined ? `${score} / 100` : 'Score pending',
    level: normLevel
  };
}

/**
 * Converts technical incident data into an easy 6-step narrative flow
 */
export function buildEasyNarrativeStory(incident) {
  if (!incident) {
    return {
      threatSource: 'Suspicious external IP (185.220.101.33)',
      device: 'Unknown device (unknown_kali_box_99)',
      user: 'U_ANALYST',
      agent: 'agent_copilot',
      activity: 'Accessed sensitive customer database',
      result: '15,000 records may have been exposed'
    };
  }

  const events = incident.events || [];
  const extIp = events.find(e => e.metadata?.client_ip || e.metadata?.ip)?.metadata?.client_ip || 'External Network (185.220.101.33)';
  const user = incident.primary_entity || events.find(e => e.user_id)?.user_id || 'U_ANALYST';
  const device = events.find(e => e.device_id)?.device_id || 'unknown_kali_box_99';
  const agent = events.find(e => e.agent_id)?.agent_id || 'agent_copilot';
  const resource = events.find(e => e.resource)?.resource || 'Customer credentials database';
  
  const records = events.find(e => e.metadata?.records_requested)?.metadata?.records_requested;
  const resultText = records 
    ? `${Number(records).toLocaleString()} records may have been exposed` 
    : 'Sensitive records were queued for exfiltration';

  return {
    threatSource: extIp,
    device: device.startsWith('unknown') ? `Unknown device (${device})` : device,
    user,
    agent: agent ? `AI Agent (${agent})` : 'AI Copilot Worker',
    activity: resource.includes('customer') ? 'Accessed customer credentials database' : `Accessed sensitive resource (${resource})`,
    result: resultText
  };
}
