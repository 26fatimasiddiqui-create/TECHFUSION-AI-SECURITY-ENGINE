-- ======================================================================
-- PS-8 Security Monitoring & Risk Analysis Platform - Supabase Schema
-- Run this SQL in your Supabase SQL Editor to set up persistent storage.
-- ======================================================================

-- 1. Security Events Table
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    device_id TEXT,
    session_id TEXT,
    event_type TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resource TEXT,
    agent_id TEXT,
    tool_name TEXT,
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_events_user_id ON events (user_id);
CREATE INDEX IF NOT EXISTS idx_events_device_id ON events (device_id);
CREATE INDEX IF NOT EXISTS idx_events_agent_id ON events (agent_id);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp DESC);

-- 2. Correlated Incidents Table
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    primary_entity TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    event_ids JSONB DEFAULT '[]'::jsonb,
    signals_detected JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    risk_assessment JSONB,
    status TEXT DEFAULT 'active'
);

CREATE INDEX IF NOT EXISTS idx_incidents_primary_entity ON incidents (primary_entity);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status);

-- 3. Security Alerts Table
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    incident_id TEXT REFERENCES incidents(id) ON DELETE SET NULL,
    event_id TEXT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    reasons JSONB DEFAULT '[]'::jsonb,
    recommended_action TEXT NOT NULL,
    status TEXT DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledged BOOLEAN DEFAULT FALSE,
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_alerts_risk_level ON alerts (risk_level);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts (created_at DESC);

-- Step 5: Compromised Approver Detection & Two-Person Rule Approval Records
CREATE TABLE IF NOT EXISTS response_approval_records (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'PENDING_APPROVAL',
    two_person_rule_required BOOLEAN DEFAULT TRUE,
    approver_1_id TEXT,
    approver_1_role TEXT,
    approver_1_risk_score INTEGER,
    approver_1_risk_level TEXT,
    approver_1_approved_at TIMESTAMPTZ,
    approver_2_id TEXT,
    approver_2_role TEXT,
    approver_2_risk_score INTEGER,
    approver_2_risk_level TEXT,
    approver_2_approved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    rejection_reason TEXT,
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_approval_incident ON response_approval_records (incident_id);
CREATE INDEX IF NOT EXISTS idx_approval_state ON response_approval_records (state);

