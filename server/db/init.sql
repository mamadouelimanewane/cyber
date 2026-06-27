-- Gravity Security — Initialisation PostgreSQL
-- Optimisé pour 10 000 agents / 28 millions d'alertes par jour

CREATE EXTENSION IF NOT EXISTS pg_trgm;    -- Recherche floue
CREATE EXTENSION IF NOT EXISTS btree_gin;   -- Index composites rapides

-- ── Agents ───────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS agents (
    agent_id        TEXT PRIMARY KEY,
    hostname        TEXT,
    ip              TEXT,
    os              TEXT,
    version         TEXT DEFAULT '1.0.0',
    collector_id    TEXT,
    registered_at   TIMESTAMPTZ DEFAULT NOW(),
    last_seen       TIMESTAMPTZ DEFAULT NOW(),
    online          BOOLEAN DEFAULT TRUE,
    stats           JSONB DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_agents_online ON agents(online, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_agents_collector ON agents(collector_id);

-- ── Alertes (table partitionnée par jour) ────────────────────────────────────

CREATE TABLE IF NOT EXISTS alerts (
    id              BIGSERIAL,
    agent_id        TEXT NOT NULL,
    collector_id    TEXT,
    type            TEXT NOT NULL,
    severity        TEXT DEFAULT 'medium',
    threat_score    FLOAT DEFAULT 0.0,
    process         TEXT,
    pid             INT,
    received_at     TIMESTAMPTZ DEFAULT NOW(),
    data            JSONB NOT NULL DEFAULT '{}',
    -- Champs brevets (enrichissement Patent Engine)
    qbsm_p_threat   FLOAT,
    qbsm_state      TEXT,
    cbga_genome     TEXT,
    rctc_signed     BOOLEAN DEFAULT FALSE,
    rctc_trust      FLOAT,
    -- Supply chain
    supply_chain_type TEXT,
    PRIMARY KEY (id, received_at)
) PARTITION BY RANGE (received_at);

-- Partitions automatiques (30 jours glissants)
CREATE TABLE IF NOT EXISTS alerts_today
    PARTITION OF alerts
    FOR VALUES FROM (NOW()::DATE) TO ((NOW() + INTERVAL '1 day')::DATE);

CREATE TABLE IF NOT EXISTS alerts_yesterday
    PARTITION OF alerts
    FOR VALUES FROM ((NOW() - INTERVAL '1 day')::DATE) TO (NOW()::DATE);

-- Index performants sur la partition active
CREATE INDEX IF NOT EXISTS idx_alerts_agent    ON alerts(agent_id, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_type     ON alerts(type, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_score    ON alerts(threat_score DESC, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_process  ON alerts USING gin(to_tsvector('english', COALESCE(process, '')));

-- ── Alertes Patent (flux haute priorité) ─────────────────────────────────────

CREATE TABLE IF NOT EXISTS patent_alerts (
    id              BIGSERIAL PRIMARY KEY,
    algorithm       TEXT NOT NULL,        -- QBSM, CBGA, RCTC, ASN, ZKSP
    agent_id        TEXT,
    process         TEXT,
    pid             INT,
    confidence      FLOAT,
    data            JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_patent_algo ON patent_alerts(algorithm, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_patent_agent ON patent_alerts(agent_id, created_at DESC);

-- ── Incidents (corrélation multi-alertes) ────────────────────────────────────

CREATE TABLE IF NOT EXISTS incidents (
    id              BIGSERIAL PRIMARY KEY,
    title           TEXT NOT NULL,
    severity        TEXT NOT NULL,       -- critical, high, medium, low
    status          TEXT DEFAULT 'open', -- open, investigating, contained, closed
    affected_agents TEXT[] DEFAULT '{}',
    alert_count     INT DEFAULT 0,
    kill_chain_phase TEXT,
    mitre_tactics   TEXT[] DEFAULT '{}',
    first_seen      TIMESTAMPTZ DEFAULT NOW(),
    last_updated    TIMESTAMPTZ DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ,
    timeline        JSONB DEFAULT '[]',  -- Historique des actions
    response_actions JSONB DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_incidents_status  ON incidents(status, last_updated DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity, first_seen DESC);

-- ── IOC (Threat Intelligence) ─────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS iocs (
    id              BIGSERIAL PRIMARY KEY,
    type            TEXT NOT NULL,       -- hash, ip, domain, pattern
    value           TEXT NOT NULL UNIQUE,
    threat_name     TEXT,
    severity        TEXT,
    confidence      FLOAT DEFAULT 0.5,
    source          TEXT DEFAULT 'local',
    first_seen      TIMESTAMPTZ DEFAULT NOW(),
    last_seen       TIMESTAMPTZ DEFAULT NOW(),
    seen_count      INT DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs USING hash(value);
CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type, confidence DESC);

-- ── Collectors ────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS collectors (
    collector_id    TEXT PRIMARY KEY,
    region          TEXT,
    url             TEXT,
    agents_count    INT DEFAULT 0,
    last_seen       TIMESTAMPTZ DEFAULT NOW(),
    online          BOOLEAN DEFAULT TRUE
);

-- ── Vue: dashboard stats ──────────────────────────────────────────────────────

CREATE OR REPLACE VIEW dashboard_stats AS
SELECT
    (SELECT COUNT(*) FROM agents WHERE online = TRUE)           AS online_agents,
    (SELECT COUNT(*) FROM agents)                               AS total_agents,
    (SELECT COUNT(*) FROM alerts WHERE received_at > NOW() - INTERVAL '24h') AS alerts_today,
    (SELECT COUNT(*) FROM alerts WHERE threat_score >= 0.85
        AND received_at > NOW() - INTERVAL '24h')              AS critical_today,
    (SELECT COUNT(*) FROM incidents WHERE status = 'open')     AS open_incidents,
    (SELECT COUNT(*) FROM patent_alerts
        WHERE created_at > NOW() - INTERVAL '24h')             AS patent_alerts_today;
