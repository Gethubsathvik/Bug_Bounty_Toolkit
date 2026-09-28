package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bbtoolkit/bugbounty/internal/redact"
	"github.com/bbtoolkit/bugbounty/pkg/models"
)

func fmtInt(i int) string     { return fmt.Sprintf("%d", i) }
func fmtInt64(i int64) string { return fmt.Sprintf("%d", i) }

// FindingFingerprint computes the stable identity of a finding. Two findings
// with the same type, asset, endpoint and discriminator are the same finding,
// no matter which module produced them. The discriminator lets one template
// produce several distinct findings on one asset (for example, two different
// missing headers) without collapsing into one.
//
// The implementation lives in models so the finding engine can deduplicate
// without depending on the database driver; this remains as the storage-facing
// name because callers in this package use it.
func FindingFingerprint(f *models.Finding) string {
	return f.ComputeFingerprint()
}

// EvidenceDedup is the identity of one evidence item within a finding.
func EvidenceDedup(e models.Evidence) string {
	parts := []string{e.Source, e.Summary}
	keys := make([]string, 0, len(e.Data))
	for k := range e.Data {
		keys = append(keys, k)
	}
	sortStrings(keys)
	for _, k := range keys {
		parts = append(parts, k+"="+e.Data[k])
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return hex.EncodeToString(sum[:16])
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// UpsertFinding stores a finding and merges its evidence.
//
// Merge semantics, which are what make deduplication work:
//   - If the fingerprint is new, the finding is inserted as-is.
//   - If it exists, first_seen is preserved, last_seen advances, and evidence
//     rows are inserted only when their dedup key is new. Evidence is never
//     overwritten, so the first observation of a condition is preserved.
//   - Severity and confidence are raised to the higher of the two values, never
//     lowered, so a later low-confidence module cannot dilute a finding.
func (s *Store) UpsertFinding(ctx context.Context, f models.Finding) (models.Finding, bool, error) {
	// The derived fields are filled in first: Validate requires an id and a
	// first-seen time, and a caller that produced a finding from a rule engine
	// has no reason to invent either. Validating before defaulting would make
	// the defaulting below unreachable and reject every well-formed finding.
	if f.Fingerprint == "" {
		f.Fingerprint = FindingFingerprint(&f)
	}
	if f.ID == "" {
		f.ID = "f-" + f.Fingerprint[:16]
	}
	if f.FirstSeen.IsZero() {
		f.FirstSeen = nowUTC()
	}
	if f.LastSeen.Before(f.FirstSeen) {
		f.LastSeen = f.FirstSeen
	}
	if err := f.Validate(); err != nil {
		return f, false, err
	}

	manualJSON := marshalJSON(f.ManualVerification)
	tagsJSON := marshalJSON(f.Tags)

	var created bool
	err := s.tx(ctx, func(tx *sql.Tx) error {
		// Normalize the evidence before anything reaches the database.
		evidence := make([]models.Evidence, 0, len(f.Evidence))
		for _, e := range f.Evidence {
			cleaned, scrubbed := redact.Scrub(e.Data)
			e.Data = cleaned
			e.Redacted = scrubbed
			// Evidence summaries quote response headers and bodies, so they are
			// the most likely place for a live credential to reach the database.
			// Sanitize only makes text safe to print; Text is what removes the
			// secret.
			e.Summary = redact.Text(e.Summary)
			e.Source = redact.Text(e.Source)
			if e.ObservedAt.IsZero() {
				e.ObservedAt = f.LastSeen
			}
			e.FindingID = f.ID
			evidence = append(evidence, e)
		}

		res := tx.QueryRowContext(ctx, `
			INSERT INTO findings (
				id, fingerprint, type, title, severity, confidence, asset, endpoint,
				description, impact, remediation, manual_verification,
				manual_verification_required, status, tags, source, first_seen, last_seen, run_id)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
			ON CONFLICT(fingerprint) DO NOTHING
			RETURNING first_seen`,
			f.ID, f.Fingerprint, f.Type, f.Title, string(f.Severity), string(f.Confidence),
			f.Asset, nullString(f.Endpoint), nullString(f.Description), nullString(f.Impact),
			nullString(f.Remediation), nullString(manualJSON), f.ManualVerificationRequired,
			string(f.Status), nullString(tagsJSON), nullString(f.Source),
			fmtTime(f.FirstSeen), fmtTime(f.LastSeen), nullString(f.RunID))

		var firstSeen string
		err := res.Scan(&firstSeen)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			created = false
			// Merge into the existing row. The rank comparison happens in Go
			// rather than in SQL: a ranking has to be expressed as a SQL
			// function, which means registering a driver-level callback, and a
			// missing or misspelled registration would make every
			// re-observation of every finding fail at exactly the moment
			// deduplication is needed.
			var curSeverity, curConfidence sql.NullString
			if err := tx.QueryRowContext(ctx,
				`SELECT severity, confidence FROM findings WHERE fingerprint = ?`,
				f.Fingerprint).Scan(&curSeverity, &curConfidence); err != nil {
				return fmt.Errorf("reading the existing finding: %w", err)
			}
			severity, confidence := f.Severity, f.Confidence
			if models.Severity(curSeverity.String).SeverityRank() > severity.SeverityRank() {
				severity = models.Severity(curSeverity.String)
			}
			if models.Confidence(curConfidence.String).ConfidenceRank() > confidence.ConfidenceRank() {
				confidence = models.Confidence(curConfidence.String)
			}
			if _, err := tx.ExecContext(ctx, `
				UPDATE findings SET
					last_seen   = ?,
					severity    = ?,
					confidence  = ?,
					impact      = COALESCE(NULLIF(?, ''), impact),
					remediation = COALESCE(NULLIF(?, ''), remediation)
				WHERE fingerprint = ?`,
				fmtTime(f.LastSeen), string(severity), string(confidence),
				f.Impact, f.Remediation, f.Fingerprint); err != nil {
				return fmt.Errorf("merging finding: %w", err)
			}
		case err != nil:
			return fmt.Errorf("inserting finding: %w", err)
		default:
			created = true
		}

		evStmt, err := tx.PrepareContext(ctx, `
			INSERT INTO evidence (finding, source, summary, data, redacted, observed_at, dedup)
			VALUES (?,?,?,?,?,?,?)
			ON CONFLICT(finding, dedup) DO NOTHING`)
		if err != nil {
			return err
		}
		defer evStmt.Close()
		for _, e := range evidence {
			dataJSON, scrubbed := jsonMap(e.Data)
			if scrubbed {
				e.Redacted = true
			}
			if _, err := evStmt.ExecContext(ctx, e.FindingID, e.Source, nullString(e.Summary),
				nullString(dataJSON), e.Redacted, fmtTime(e.ObservedAt), EvidenceDedup(e)); err != nil {
				return fmt.Errorf("inserting evidence: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return f, false, err
	}

	stored, err := s.GetFindingByFingerprint(ctx, f.Fingerprint)
	if err != nil {
		return f, created, err
	}
	return stored, created, nil
}

// FindingFilter narrows a finding query.
type FindingFilter struct {
	Severities  []models.Severity
	Confidences []models.Confidence
	Statuses    []models.Status
	Types       []string
	Asset       string
	// RunID restricts to findings produced by one engagement.
	RunID string
	// Fingerprints restricts to specific findings, used when a caller
	// already resolved a set from another query.
	Fingerprints []string
	Limit        int
	Offset       int
	// Since ignores findings last seen before this instant.
	Since time.Time
}

// ListFindings returns findings matching the filter, most severe first.
func (s *Store) ListFindings(ctx context.Context, f FindingFilter) ([]models.Finding, error) {
	var where []string
	var args []any

	appendIn := func(col string, values []string) {
		if len(values) == 0 {
			return
		}
		ph := make([]string, 0, len(values))
		for _, v := range values {
			ph = append(ph, "?")
			args = append(args, v)
		}
		where = append(where, col+" IN ("+strings.Join(ph, ",")+")")
	}
	var sev, conf, sts []string
	for _, s := range f.Severities {
		sev = append(sev, string(s))
	}
	for _, c := range f.Confidences {
		conf = append(conf, string(c))
	}
	for _, s := range f.Statuses {
		sts = append(sts, string(s))
	}
	appendIn("severity", sev)
	appendIn("confidence", conf)
	appendIn("status", sts)
	appendIn("type", f.Types)
	if f.Asset != "" {
		where = append(where, "asset = ?")
		args = append(args, f.Asset)
	}
	if f.RunID != "" {
		where = append(where, "run_id = ?")
		args = append(args, f.RunID)
	}
	appendIn("fingerprint", f.Fingerprints)
	if !f.Since.IsZero() {
		where = append(where, "last_seen >= ?")
		args = append(args, fmtTime(f.Since))
	}

	q := `SELECT id, fingerprint, type, title, severity, confidence, asset, endpoint,
			description, impact, remediation, manual_verification,
			manual_verification_required, status, tags, source, first_seen, last_seen, run_id
			FROM findings`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += ` ORDER BY CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4
			WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'informational' THEN 1 ELSE 0 END DESC,
			CASE confidence WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
			asset ASC, type ASC`
	limit := f.Limit
	if limit <= 0 || limit > 5000 {
		limit = 5000
	}
	q += " LIMIT ? OFFSET ?"
	args = append(args, limit, f.Offset)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []models.Finding{}
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		ev, err := s.loadEvidence(ctx, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].Evidence = ev
	}
	return out, nil
}

func scanFinding(sc interface{ Scan(...any) error }) (*models.Finding, error) {
	var f models.Finding
	var sev, conf, status string
	var endpoint, description, impact, remediation, manual, tags, source, runID sql.NullString
	var first, last string
	if err := sc.Scan(&f.ID, &f.Fingerprint, &f.Type, &f.Title, &sev, &conf, &f.Asset, &endpoint,
		&description, &impact, &remediation, &manual, &f.ManualVerificationRequired, &status,
		&tags, &source, &first, &last, &runID); err != nil {
		return nil, err
	}
	f.Severity, f.Confidence, f.Status = models.Severity(sev), models.Confidence(conf), models.Status(status)
	if endpoint.Valid {
		f.Endpoint = endpoint.String
	}
	f.Description, f.Impact, f.Remediation = description.String, impact.String, remediation.String
	unmarshalJSON(manual.String, &f.ManualVerification)
	unmarshalJSON(tags.String, &f.Tags)
	f.Source = source.String
	if runID.Valid {
		f.RunID = runID.String
	}
	f.FirstSeen, f.LastSeen = parseTime(first), parseTime(last)
	return &f, nil
}

func (s *Store) loadEvidence(ctx context.Context, findingID string) ([]models.Evidence, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, source, summary, data, redacted, observed_at
		FROM evidence WHERE finding = ? ORDER BY id`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.Evidence{}
	for rows.Next() {
		var e models.Evidence
		var summary, data sql.NullString
		var observed string
		if err := rows.Scan(&e.ID, &e.Source, &summary, &data, &e.Redacted, &observed); err != nil {
			return nil, err
		}
		e.FindingID = findingID
		e.Summary = summary.String
		unmarshalJSON(data.String, &e.Data)
		e.ObservedAt = parseTime(observed)
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetFindingByFingerprint loads one finding with its evidence.
func (s *Store) GetFindingByFingerprint(ctx context.Context, fp string) (models.Finding, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, fingerprint, type, title, severity, confidence, asset, endpoint,
			description, impact, remediation, manual_verification,
			manual_verification_required, status, tags, source, first_seen, last_seen, run_id
		FROM findings WHERE fingerprint = ?`, fp)
	f, err := scanFinding(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.Finding{}, ErrNotFound
		}
		return models.Finding{}, err
	}
	ev, err := s.loadEvidence(ctx, f.ID)
	if err != nil {
		return models.Finding{}, err
	}
	f.Evidence = ev
	return *f, nil
}

// SetFindingStatus updates triage state.
func (s *Store) SetFindingStatus(ctx context.Context, id string, status models.Status) error {
	if !status.Valid() {
		return fmt.Errorf("invalid status %q", status)
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE findings SET status = ? WHERE id = ? OR fingerprint = ?`,
			string(status), id, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// FindingStats summarizes the finding table for reports.
type FindingStats struct {
	Total        int            `json:"total"`
	BySeverity   map[string]int `json:"by_severity"`
	ByConfidence map[string]int `json:"by_confidence"`
	ByStatus     map[string]int `json:"by_status"`
	ByType       map[string]int `json:"by_type"`
	Manual       int            `json:"manual_verification_required"`
}

// Stats computes finding statistics.
func (s *Store) Stats(ctx context.Context) (FindingStats, error) {
	out := FindingStats{
		BySeverity: map[string]int{}, ByConfidence: map[string]int{},
		ByStatus: map[string]int{}, ByType: map[string]int{},
	}
	load := func(col string, dst map[string]int) error {
		rows, err := s.db.QueryContext(ctx, `SELECT `+col+` AS k, COUNT(*) FROM findings GROUP BY `+col)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var k string
			var n int
			if err := rows.Scan(&k, &n); err != nil {
				return err
			}
			dst[k] = n
		}
		return rows.Err()
	}
	if err := load("severity", out.BySeverity); err != nil {
		return out, err
	}
	if err := load("confidence", out.ByConfidence); err != nil {
		return out, err
	}
	if err := load("status", out.ByStatus); err != nil {
		return out, err
	}
	if err := load("type", out.ByType); err != nil {
		return out, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM findings`).Scan(&out.Total); err != nil {
		return out, err
	}
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM findings WHERE manual_verification_required = 1`).Scan(&out.Manual); err != nil {
		return out, err
	}
	return out, nil
}

// AssetCounts summarizes the asset tables.
type AssetCounts struct {
	Domains      int `json:"domains"`
	Subdomains   int `json:"subdomains"`
	IPs          int `json:"ips"`
	Services     int `json:"services"`
	URLs         int `json:"urls"`
	Endpoints    int `json:"endpoints"`
	Parameters   int `json:"parameters"`
	Technologies int `json:"technologies"`
	DNSRecords   int `json:"dns_records"`
	Interesting  int `json:"interesting_parameters"`
	LiveServices int `json:"live_services"`
}

// AssetSummary counts everything discovered.
func (s *Store) AssetSummary(ctx context.Context) (AssetCounts, error) {
	var c AssetCounts
	queries := []struct {
		q string
		p *int
	}{
		{`SELECT COUNT(*) FROM domains`, &c.Domains},
		{`SELECT COUNT(*) FROM subdomains`, &c.Subdomains},
		{`SELECT COUNT(*) FROM ips`, &c.IPs},
		{`SELECT COUNT(*) FROM services`, &c.Services},
		{`SELECT COUNT(*) FROM urls`, &c.URLs},
		{`SELECT COUNT(*) FROM endpoints`, &c.Endpoints},
		{`SELECT COUNT(*) FROM parameters`, &c.Parameters},
		{`SELECT COUNT(*) FROM technologies`, &c.Technologies},
		{`SELECT COUNT(*) FROM dns_records`, &c.DNSRecords},
		{`SELECT COUNT(*) FROM parameters WHERE interesting = 1`, &c.Interesting},
		{`SELECT COUNT(*) FROM services WHERE status_code IS NOT NULL AND status_code < 400`, &c.LiveServices},
	}
	for _, item := range queries {
		if err := s.db.QueryRowContext(ctx, item.q).Scan(item.p); err != nil {
			return c, err
		}
	}
	return c, nil
}
