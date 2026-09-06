CREATE TABLE IF NOT EXISTS users (
 id BIGSERIAL PRIMARY KEY, name VARCHAR(100) NOT NULL,
 email VARCHAR(254) UNIQUE NOT NULL, password_hash VARCHAR(255) NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS agent_trials (
 agent_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 trial_start_date TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 leads_processed_count INTEGER NOT NULL DEFAULT 0 CHECK (leads_processed_count >= 0),
 is_active BOOLEAN NOT NULL DEFAULT TRUE
);
CREATE TABLE IF NOT EXISTS leads (
 id BIGSERIAL PRIMARY KEY, agent_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 name VARCHAR(150) NOT NULL, phone VARCHAR(30), email VARCHAR(254),
 location VARCHAR(150), property_requirement VARCHAR(200), budget VARCHAR(100),
 buyer_segment VARCHAR(100), source VARCHAR(150) NOT NULL,
 verification_status VARCHAR(30) NOT NULL DEFAULT 'Needs Verification',
 last_verified_date DATE, lead_score INTEGER CHECK (lead_score IS NULL OR lead_score BETWEEN 0 AND 100),
 lead_temperature VARCHAR(10), lead_status VARCHAR(30) NOT NULL DEFAULT 'New',
 notes TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_leads_agent_created ON leads(agent_id,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_leads_agent_status ON leads(agent_id,lead_status);
CREATE TABLE IF NOT EXISTS lead_activities (
 id BIGSERIAL PRIMARY KEY, lead_id BIGINT NOT NULL REFERENCES leads(id) ON DELETE CASCADE,
 agent_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 activity_type VARCHAR(50) NOT NULL, details TEXT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
