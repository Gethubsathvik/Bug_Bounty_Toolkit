// Package storage is the local persistence layer. It uses SQLite through a
// pure-Go driver so the toolkit needs no C toolchain.
//
// Two rules apply to everything in this package:
//
//   - Every value reaches SQLite as a bound parameter. No identifier, host,
//     URL, header or user-supplied string is ever concatenated into SQL text.
//   - Everything written is passed through the redactor first, so a secret
//     observed on a target cannot be persisted by accident.
package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver

	"github.com/bbtoolkit/bugbounty/internal/redact"
)

// ErrNotFound is returned when a lookup misses.
var ErrNotFound = errors.New("storage: not found")

// Store owns the database handle. It is safe for concurrent use.
type Store struct {
	db   *sql.DB
	path string
	// mu serializes write transactions. SQLite allows a single writer; taking
	// the lock in-process avoids SQLITE_BUSY churn without weakening
	// durability.
	mu sync.Mutex
}

// Options configures Open.
type Options struct {
	Path         string
	BusyTimeout  time.Duration
	WAL          bool
	ReadOnly     bool
	MaxOpenConns int
}

// validateDBPath rejects a database path that no filesystem would handle
// sensibly. The path is operator configuration rather than attacker input, so
// the goal is a clear early error instead of a confusing failure deep inside the
// driver, and refusing control characters that some layers silently truncate.
func validateDBPath(p string) error {
	if p == "" {
		return errors.New("empty database path")
	}
	if len(p) > 4096 {
		return fmt.Errorf("database path is %d bytes long", len(p))
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("database path contains the control character %q", r)
		}
	}
	base := filepath.Base(p)
	// A bare "." or ".." would silently target a directory.
	if base == "." || base == ".." || base == string(filepath.Separator) {
		return fmt.Errorf("database path %q does not name a file", p)
	}
	return nil
}

// Open creates or opens the database and applies migrations.
func Open(ctx context.Context, opts Options) (*Store, error) {
	if opts.Path == "" {
		opts.Path = "engagement.db"
	}
	if err := validateDBPath(opts.Path); err != nil {
		return nil, err
	}
	if opts.BusyTimeout <= 0 {
		opts.BusyTimeout = 5 * time.Second
	}
	dir := filepath.Dir(opts.Path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("creating database directory: %w", err)
		}
	}
	// A directory is never a database, and it must be refused before anything is
	// created or altered. The chmod below would otherwise strip the search bit
	// from a real directory, leaving a tree the owner can no longer write to or
	// clean up. A path like "some/dir/." or "some/dir/.." reaches here intact
	// because filepath.Clean is not applied to operator input.
	if info, err := os.Lstat(opts.Path); err == nil && info.IsDir() {
		return nil, fmt.Errorf("database path %q is a directory", opts.Path)
	}
	// The file may contain reconnaissance results; keep it owner-only.
	_ = os.Chmod(opts.Path, 0o600)

	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(%d)&_pragma=foreign_keys(1)", filepath.ToSlash(opts.Path), opts.BusyTimeout.Milliseconds())
	if opts.WAL {
		dsn += "&_pragma=journal_mode(WAL)"
	}
	if opts.ReadOnly {
		dsn += "&mode=ro"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	// SQLite in WAL mode allows concurrent readers with a single writer. The
	// pool is capped so the write mutex is rarely contended.
	if opts.MaxOpenConns <= 0 {
		opts.MaxOpenConns = 4
	}
	db.SetMaxOpenConns(opts.MaxOpenConns)
	db.SetMaxIdleConns(opts.MaxOpenConns)
	db.SetConnMaxLifetime(time.Hour)

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("connecting to database: %w", err)
	}
	s := &Store{db: db, path: opts.Path}
	if !opts.ReadOnly {
		if err := s.migrate(ctx); err != nil {
			db.Close()
			return nil, err
		}
	}
	return s, nil
}

// Memory opens a private in-memory database. Used by tests.
func Memory(ctx context.Context) (*Store, error) {
	db, err := sql.Open("sqlite", "file::memory:?_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	// A single connection keeps an in-memory database alive and consistent.
	db.SetMaxOpenConns(1)
	// Every path out of this function must release the handle. database/sql
	// opens a real connection behind the pool, so a db that is abandoned on an
	// error path holds a live SQLite connection that nothing will ever close.
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	s := &Store{db: db, path: ":memory:"}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// DB exposes the handle for advanced queries. Callers must not write with it
// directly: doing so would bypass redaction.
func (s *Store) DB() *sql.DB { return s.db }

// Path returns the database file path.
func (s *Store) Path() string { return s.path }

// Close releases the database.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// tx runs fn inside a serialized write transaction, rolling back on error.
func (s *Store) tx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// nullString maps "" to a SQL NULL so that unique indexes do not collide on
// empty strings.
func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nullInt maps 0 to NULL.
func nullInt(i int) any {
	if i == 0 {
		return nil
	}
	return i
}

// nowUTC is the single clock used for stored timestamps.
func nowUTC() time.Time { return time.Now().UTC() }

// jsonMap marshals a string map for a TEXT column, redacting it first.
func jsonMap(m map[string]string) (string, bool) {
	if len(m) == 0 {
		return "", false
	}
	cleaned, scrubbed := redact.Scrub(m)
	return marshalJSON(cleaned), scrubbed
}
