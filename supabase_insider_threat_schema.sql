-- ============================================================================
-- INSIGHT: Insider Threat Detection & Risk Monitoring - Supabase Schema
-- ============================================================================

-- Enable pgcrypto / uuid-ossp if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Employees Table
CREATE TABLE IF NOT EXISTS employees (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    employee_code TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    department TEXT NOT NULL,
    role TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_employees_code ON employees (employee_code);

-- 2. Access Logs Table
CREATE TABLE IF NOT EXISTS access_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    employee_id UUID NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
    resource_name TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    action TEXT NOT NULL,
    ip_address TEXT,
    device_id TEXT,
    location TEXT,
    access_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    success BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_access_logs_employee_id ON access_logs (employee_id);
CREATE INDEX IF NOT EXISTS idx_access_logs_access_time ON access_logs (access_time DESC);

-- 3. Risk Events Table
CREATE TABLE IF NOT EXISTS risk_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    employee_id UUID NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    description TEXT NOT NULL,
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    severity TEXT NOT NULL,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    model_confidence NUMERIC DEFAULT 0.95,
    features JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_risk_events_employee_id ON risk_events (employee_id);
CREATE INDEX IF NOT EXISTS idx_risk_events_detected_at ON risk_events (detected_at DESC);

-- 4. Alerts Table
CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    employee_id UUID NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
    risk_event_id UUID REFERENCES risk_events(id) ON DELETE SET NULL,
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    alert_type TEXT NOT NULL,
    message TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'NEW',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_alerts_employee_id ON alerts (employee_id);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_risk_score ON alerts (risk_score DESC);

-- 5. Approvals Table
CREATE TABLE IF NOT EXISTS approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    employee_id UUID NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
    resource_name TEXT NOT NULL,
    requested_action TEXT NOT NULL,
    reason TEXT,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    approved_by TEXT,
    approved_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'PENDING'
);

CREATE INDEX IF NOT EXISTS idx_approvals_employee_id ON approvals (employee_id);

-- 6. Incidents Table
CREATE TABLE IF NOT EXISTS incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    employee_id UUID NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
    alert_id UUID REFERENCES alerts(id) ON DELETE SET NULL,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN',
    assigned_to TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_incidents_employee_id ON incidents (employee_id);

-- Enable Realtime replication on alerts, risk_events, and incidents
ALTER PUBLICATION supabase_realtime ADD TABLE alerts;
ALTER PUBLICATION supabase_realtime ADD TABLE risk_events;
ALTER PUBLICATION supabase_realtime ADD TABLE incidents;

-- ============================================================================
-- OPTIONAL INITIAL SEED DATA (Only inserts if employees table is empty)
-- ============================================================================
INSERT INTO employees (employee_code, name, department, role, email, status)
VALUES 
    ('EMP001', 'A. Verma', 'Software Engineering', 'Software Engineer', 'a.verma@company.internal', 'ACTIVE'),
    ('EMP002', 'J. Singh', 'Human Resources & Analytics', 'HR Specialist & Senior Analyst', 'j.singh@company.internal', 'ACTIVE'),
    ('EMP003', 'R. Khan', 'Cloud Infrastructure', 'Database Administrator & Contractor', 'r.khan@company.internal', 'ACTIVE'),
    ('EMP004', 'U001', 'Security Operations', 'Security Analyst', 'u001@company.internal', 'ACTIVE'),
    ('EMP005', 'admin_user', 'System Administration', 'Security Administrator', 'admin@company.internal', 'ACTIVE')
ON CONFLICT (employee_code) DO UPDATE 
SET name = EXCLUDED.name, department = EXCLUDED.department, role = EXCLUDED.role, email = EXCLUDED.email;
