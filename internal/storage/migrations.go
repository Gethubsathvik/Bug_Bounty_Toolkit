package storage

import (
	"context"
	"database/sql"
	"fmt"
)

// Migration is a single, ordered schema change. Migrations are append-only:
// an existing migration is never edited, because that would silently reshape
// databases already in the field.
type Migration struct {
	Version int
	Name    string
	SQL     string
}

// migrations is the ordered schema history. The current schema version is
// len(migrations).
var migrations = []Migration{
	{
		Version: 1,
		Name:    "initial schema",
		SQL: `
-- ---------------------------------------------------------------- assets ---
CREATE TABLE organizations (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    created_at  TEXT NOT NULL
);

CREATE TABLE domains (
    id            INTEGER PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE,
    organization  INTEGER REFERENCES organizations(id) ON DELETE SET NULL,
    source        TEXT,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    meta          TEXT
);
CREATE INDEX idx_domains_last_seen ON domains(last_seen DESC);

CREATE TABLE subdomains (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    domain      INTEGER REFERENCES domains(id) ON DELETE CASCADE,
    source      TEXT,
    resolved    INTEGER NOT NULL DEFAULT 0,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    meta        TEXT
);
CREATE INDEX idx_subdomains_domain ON subdomains(domain);
CREATE INDEX idx_subdomains_resolved ON subdomains(resolved);
CREATE INDEX idx_subdomains_last_seen ON subdomains(last_seen DESC);

CREATE TABLE ips (
    id          INTEGER PRIMARY KEY,
    address     TEXT NOT NULL UNIQUE,
    version     INTEGER NOT NULL,
    scope_rule  TEXT,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    meta        TEXT
);
CREATE INDEX idx_ips_version ON ips(version);

CREATE TABLE services (
    id            INTEGER PRIMARY KEY,
    kind          TEXT NOT NULL DEFAULT 'http',
    url           TEXT NOT NULL UNIQUE,
    host          TEXT NOT NULL,
    port          INTEGER,
    scheme        TEXT,
    status_code   INTEGER,
    title         TEXT,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    meta          TEXT
);
CREATE INDEX idx_services_host ON services(host);
CREATE INDEX idx_services_status ON services(status_code);
CREATE INDEX idx_services_last_seen ON services(last_seen DESC);

CREATE TABLE urls (
    id          INTEGER PRIMARY KEY,
    url         TEXT NOT NULL UNIQUE,
    service     INTEGER REFERENCES services(id) ON DELETE CASCADE,
    kind        TEXT,
    status_code INTEGER,
    depth       INTEGER,
    source      TEXT,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    meta        TEXT
);
CREATE INDEX idx_urls_service ON urls(service);
CREATE INDEX idx_urls_kind ON urls(kind);

CREATE TABLE endpoints (
    id           INTEGER PRIMARY KEY,
    url          TEXT NOT NULL UNIQUE,
    service      INTEGER REFERENCES services(id) ON DELETE CASCADE,
    method       TEXT,
    kind         TEXT,
    source       TEXT,
    depth        INTEGER NOT NULL DEFAULT 0,
    status_code  INTEGER,
    content_type TEXT,
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    meta         TEXT
);
CREATE INDEX idx_endpoints_service ON endpoints(service);
CREATE INDEX idx_endpoints_kind ON endpoints(kind);

CREATE TABLE parameters (
    id          INTEGER PRIMARY KEY,
    fingerprint TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL,
    endpoint    INTEGER REFERENCES endpoints(id) ON DELETE CASCADE,
    url         TEXT,
    source      TEXT,
    interesting INTEGER NOT NULL DEFAULT 0,
    reason      TEXT,
    reflected   INTEGER NOT NULL DEFAULT 0,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL
);
CREATE INDEX idx_parameters_name ON parameters(name);
CREATE INDEX idx_parameters_interesting ON parameters(interesting);
CREATE INDEX idx_parameters_endpoint ON parameters(endpoint);

CREATE TABLE technologies (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    version    TEXT NOT NULL DEFAULT '',
    category   TEXT NOT NULL DEFAULT '',
    confidence TEXT NOT NULL DEFAULT 'medium',
    UNIQUE(name, version)
);
CREATE INDEX idx_technologies_name ON technologies(name);

CREATE TABLE service_technologies (
    service     INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    technology  INTEGER NOT NULL REFERENCES technologies(id) ON DELETE CASCADE,
    PRIMARY KEY (service, technology)
);

CREATE TABLE dns_records (
    id          INTEGER PRIMARY KEY,
    hash        TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    type        TEXT NOT NULL,
    value       TEXT NOT NULL,
    ttl         INTEGER,
    priority    INTEGER,
    source      TEXT,
    observed_at TEXT NOT NULL
);
CREATE INDEX idx_dns_name_type ON dns_records(name, type);
CREATE INDEX idx_dns_value ON dns_records(value);

CREATE TABLE dns_postures (
    name      TEXT PRIMARY KEY,
    data      TEXT NOT NULL,
    observed  TEXT NOT NULL
);

-- -------------------------------------------------------------- findings ---
CREATE TABLE findings (
    id                           TEXT PRIMARY KEY,
    fingerprint                  TEXT NOT NULL UNIQUE,
    type                         TEXT NOT NULL,
    title                        TEXT NOT NULL,
    severity                     TEXT NOT NULL,
    confidence                   TEXT NOT NULL,
    asset                        TEXT NOT NULL,
    endpoint                     TEXT,
    description                  TEXT,
    impact                       TEXT,
    remediation                  TEXT,
    manual_verification          TEXT,
    manual_verification_required INTEGER NOT NULL DEFAULT 1,
    status                       TEXT NOT NULL DEFAULT 'new',
    tags                         TEXT,
    source                       TEXT,
    first_seen                   TEXT NOT NULL,
    last_seen                    TEXT NOT NULL
);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_confidence ON findings(confidence);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_findings_type ON findings(type);
CREATE INDEX idx_findings_asset ON findings(asset);
CREATE INDEX idx_findings_last_seen ON findings(last_seen DESC);

CREATE TABLE evidence (
    id          INTEGER PRIMARY KEY,
    finding     TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    source      TEXT NOT NULL,
    summary     TEXT,
    data        TEXT,
    redacted    INTEGER NOT NULL DEFAULT 0,
    observed_at TEXT NOT NULL,
    dedup       TEXT NOT NULL,
    UNIQUE(finding, dedup)
);
CREATE INDEX idx_evidence_finding ON evidence(finding);

-- ------------------------------------------------------------------ runs ---
CREATE TABLE scan_runs (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    profile      TEXT,
    scope_file   TEXT,
    scope_digest TEXT,
    status       TEXT NOT NULL,
    started_at   TEXT NOT NULL,
    finished_at  TEXT,
    config       TEXT,
    stats        TEXT
);
CREATE INDEX idx_runs_started ON scan_runs(started_at DESC);

CREATE TABLE scan_stages (
    run         TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    status      TEXT NOT NULL,
    started_at  TEXT,
    finished_at TEXT,
    error       TEXT,
    stats       TEXT,
    PRIMARY KEY (run, name)
);
CREATE INDEX idx_stages_run_seq ON scan_stages(run, seq);

CREATE TABLE events (
    id        INTEGER PRIMARY KEY,
    run       TEXT,
    ts        TEXT NOT NULL,
    level     TEXT NOT NULL,
    module    TEXT,
    event     TEXT,
    data      TEXT
);
CREATE INDEX idx_events_run_ts ON events(run, ts DESC);
CREATE INDEX idx_events_event ON events(event);

-- ----------------------------------------------------------------- graph ---
CREATE TABLE asset_nodes (
    kind       TEXT NOT NULL,
    key        TEXT NOT NULL,
    label      TEXT,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    attrs      TEXT,
    PRIMARY KEY (kind, key)
);
CREATE INDEX idx_nodes_kind ON asset_nodes(kind);

CREATE TABLE asset_edges (
    from_kind TEXT NOT NULL,
    from_key  TEXT NOT NULL,
    rel       TEXT NOT NULL,
    to_kind   TEXT NOT NULL,
    to_key    TEXT NOT NULL,
    attrs     TEXT,
    PRIMARY KEY (from_kind, from_key, rel, to_kind, to_key)
);
CREATE INDEX idx_edges_from ON asset_edges(from_kind, from_key);
CREATE INDEX idx_edges_to ON asset_edges(to_kind, to_key);
`,
	},
	{
		// 2: record which run produced a finding.
		//
		// A report has to be able to cover one engagement rather than
		// everything ever stored, and the run is the only thing that says
		// which findings belong together. The column is nullable because a
		// finding can also arrive from outside a scan, and backfilling it
		// would mean guessing at history.
		Version: 2,
		SQL: `
ALTER TABLE findings ADD COLUMN run_id TEXT;
CREATE INDEX idx_findings_run ON findings(run_id);
`,
	},
}

// CurrentVersion reports the schema version this build expects.
func CurrentVersion() int { return len(migrations) }

// migrate brings the database up to the current schema version. It is safe to
// call on every open and is a no-op when already current.
func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		name       TEXT NOT NULL,
		applied_at TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("creating migration table: %w", err)
	}

	applied, err := s.appliedVersions(ctx)
	if err != nil {
		return err
	}
	for _, m := range migrations {
		if applied[m.Version] {
			continue
		}
		// Each migration is applied inside its own transaction together with
		// the bookkeeping row, so a crash mid-migration cannot leave the
		// version table claiming progress that was rolled back.
		err := s.tx(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
				return fmt.Errorf("migration %d (%s): %w", m.Version, m.Name, err)
			}
			_, err := tx.ExecContext(ctx,
				`INSERT INTO schema_migrations (version, name, applied_at) VALUES (?,?,?)`,
				m.Version, m.Name, nowUTC().Format(timeFormat))
			return err
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) appliedVersions(ctx context.Context) (map[int]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("reading migration state: %w", err)
	}
	defer rows.Close()
	out := map[int]bool{}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out[v] = true
	}
	return out, rows.Err()
}

// SchemaVersion returns the version currently applied to the database.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	if !rows.Next() {
		return 0, rows.Err()
	}
	var v int
	if err := rows.Scan(&v); err != nil {
		return 0, err
	}
	return v, rows.Err()
}
