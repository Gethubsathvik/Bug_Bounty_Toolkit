package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/bbtoolkit/bugbounty/internal/redact"
)

// RunStatus is the lifecycle state of a scan run.
type RunStatus string

const (
	RunRunning   RunStatus = "running"
	RunCompleted RunStatus = "completed"
	RunFailed    RunStatus = "failed"
	RunCancelled RunStatus = "cancelled"
	RunResumable RunStatus = "resumable"
)

// StageStatus is the lifecycle state of one pipeline stage.
type StageStatus string

const (
	StagePending   StageStatus = "pending"
	StageRunning   StageStatus = "running"
	StageCompleted StageStatus = "completed"
	StageFailed    StageStatus = "failed"
	StageSkipped   StageStatus = "skipped"
)

// ScanRun describes one engagement execution.
type ScanRun struct {
	ID          string
	Name        string
	Profile     string
	ScopeFile   string
	ScopeDigest string
	Status      RunStatus
	StartedAt   time.Time
	FinishedAt  time.Time
	Config      string
	Stats       string
}

// StageStatusRecord is the resumable state of one pipeline stage.
type StageStatusRecord struct {
	Run        string
	Name       string
	Seq        int
	Status     StageStatus
	StartedAt  time.Time
	FinishedAt time.Time
	Error      string
	Stats      string
}

// StartRun records a new scan run.
//
// A duplicate id is an error rather than an upsert. Run ids are the identity of
// a scan, and a resume that silently replaced the previous row would lose its
// stage history and its original start time, which is exactly the data resume
// depends on.
func (s *Store) StartRun(ctx context.Context, r ScanRun) error {
	if r.ID == "" {
		return errors.New("run id is required")
	}
	if r.Status == "" {
		r.Status = RunRunning
	}
	if r.StartedAt.IsZero() {
		r.StartedAt = nowUTC()
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO scan_runs (id, name, profile, scope_file, scope_digest, status, started_at, config, stats)
			VALUES (?,?,?,?,?,?,?,?,?)`,
			r.ID, r.Name, nullString(r.Profile), nullString(r.ScopeFile), nullString(r.ScopeDigest),
			string(r.Status), fmtTime(r.StartedAt), nullString(redact.Text(r.Config)), nullString(r.Stats))
		if err != nil {
			return fmt.Errorf("scan run %q already exists or could not be recorded: %w", r.ID, err)
		}
		return nil
	})
}

// FinishRun closes out a run.
func (s *Store) FinishRun(ctx context.Context, id string, status RunStatus, stats map[string]any) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`UPDATE scan_runs SET status = ?, finished_at = ?, stats = ? WHERE id = ?`,
			string(status), fmtTime(nowUTC()), nullString(marshalJSON(stats)), id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// LatestResumableRun returns the most recent run that is still resumable,
// which is what --resume attaches to.
//
// Status is the discriminator, and deliberately the only one. FinishRun always
// stamps finished_at, so a run that ended with warnings is recorded as
// resumable *and* finished; filtering on "finished_at IS NULL" here would
// exclude every run this function exists to find, and would have hidden behind
// a test that built its rows by hand instead of through FinishRun.
func (s *Store) LatestResumableRun(ctx context.Context) (ScanRun, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, profile, scope_file, scope_digest, status, started_at, finished_at, config, stats
		FROM scan_runs
		WHERE status IN (?, ?)
		ORDER BY started_at DESC LIMIT 1`, string(RunResumable), string(RunRunning))
	return scanRun(row)
}

// LastRun returns the most recent run of any status.
func (s *Store) LastRun(ctx context.Context) (ScanRun, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, profile, scope_file, scope_digest, status, started_at, finished_at, config, stats
		FROM scan_runs ORDER BY started_at DESC LIMIT 1`)
	return scanRun(row)
}

func scanRun(row interface{ Scan(...any) error }) (ScanRun, error) {
	var r ScanRun
	var profile, scopeFile, digest, config, stats sql.NullString
	var started string
	var finished sql.NullString
	err := row.Scan(&r.ID, &r.Name, &profile, &scopeFile, &digest, &r.Status, &started, &finished, &config, &stats)
	if errors.Is(err, sql.ErrNoRows) {
		// Translated to the package sentinel so a caller can tell "there is no
		// such run" from a genuine failure. LatestResumableRun in particular
		// is asked that question routinely, and a bare sql error would be
		// indistinguishable from a broken database.
		return ScanRun{}, ErrNotFound
	}
	if err != nil {
		return r, err
	}
	r.Profile, r.ScopeFile, r.ScopeDigest = profile.String, scopeFile.String, digest.String
	r.Config, r.Stats = config.String, stats.String
	r.StartedAt = parseTime(started)
	if finished.Valid {
		r.FinishedAt = parseTime(finished.String)
	}
	return r, nil
}

// GetRun loads a run by id.
func (s *Store) GetRun(ctx context.Context, id string) (ScanRun, error) {
	return scanRun(s.db.QueryRowContext(ctx, `
		SELECT id, name, profile, scope_file, scope_digest, status, started_at, finished_at, config, stats
		FROM scan_runs WHERE id = ?`, id))
}

// SetStageState records the state of a pipeline stage. It is called before and
// after each stage, which is what makes a crashed pipeline resumable: on
// restart the orchestrator reads this table and skips completed stages.
func (s *Store) SetStageState(ctx context.Context, rec StageStatusRecord) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO scan_stages (run, name, seq, status, started_at, finished_at, error, stats)
			VALUES (?,?,?,?,?,?,?,?)
			ON CONFLICT(run, name) DO UPDATE SET
				seq         = excluded.seq,
				status      = excluded.status,
				started_at  = COALESCE(excluded.started_at, scan_stages.started_at),
				finished_at = excluded.finished_at,
				error       = excluded.error,
				stats       = COALESCE(excluded.stats, scan_stages.stats)`,
			rec.Run, rec.Name, rec.Seq, string(rec.Status),
			nullString(optionalTime(rec.StartedAt)), nullString(optionalTime(rec.FinishedAt)),
			nullString(redact.Text(rec.Error)), nullString(rec.Stats))
		return err
	})
}

func optionalTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return fmtTime(t)
}

// StageStates returns every stage record for a run, ordered.
func (s *Store) StageStates(ctx context.Context, run string) ([]StageStatusRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT run, name, seq, status, started_at, finished_at, error, stats
		FROM scan_stages WHERE run = ? ORDER BY seq`, run)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []StageStatusRecord{}
	for rows.Next() {
		var r StageStatusRecord
		var started, finished, errStr, stats sql.NullString
		if err := rows.Scan(&r.Run, &r.Name, &r.Seq, &r.Status, &started, &finished, &errStr, &stats); err != nil {
			return nil, err
		}
		r.StartedAt, r.FinishedAt = parseTime(started.String), parseTime(finished.String)
		r.Error, r.Stats = errStr.String, stats.String
		out = append(out, r)
	}
	return out, rows.Err()
}

// Event is a structured audit record persisted for later review.
type Event struct {
	Run    string
	TS     time.Time
	Level  string
	Module string
	Event  string
	Data   map[string]string
}

// RecordEvent appends an audit event. The payload is redacted first.
func (s *Store) RecordEvent(ctx context.Context, e Event) error {
	if e.TS.IsZero() {
		e.TS = nowUTC()
	}
	if e.Level == "" {
		e.Level = "info"
	}
	data, _ := jsonMap(e.Data)
	return s.tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO events (run, ts, level, module, event, data) VALUES (?,?,?,?,?,?)`,
			nullString(e.Run), fmtTime(e.TS), redact.Text(e.Level), nullString(redact.Text(e.Module)),
			nullString(redact.Text(e.Event)), nullString(data))
		return err
	})
}

// Events returns recent events, newest first.
func (s *Store) Events(ctx context.Context, run string, limit int) ([]Event, error) {
	if limit <= 0 || limit > 10000 {
		limit = 500
	}
	q := `SELECT run, ts, level, module, event, data FROM events`
	var args []any
	if run != "" {
		q += ` WHERE run = ?`
		args = append(args, run)
	}
	q += ` ORDER BY ts DESC, id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		var r, m, ev, d sql.NullString
		var ts string
		if err := rows.Scan(&r, &ts, &e.Level, &m, &ev, &d); err != nil {
			return nil, err
		}
		e.Run, e.Module, e.Event = r.String, m.String, ev.String
		e.TS = parseTime(ts)
		unmarshalJSON(d.String, &e.Data)
		out = append(out, e)
	}
	return out, rows.Err()
}

// Vacuum compacts the database. Run at the end of an engagement.
func (s *Store) Vacuum(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `VACUUM`)
	if err != nil {
		return fmt.Errorf("vacuum: %w", err)
	}
	return nil
}
