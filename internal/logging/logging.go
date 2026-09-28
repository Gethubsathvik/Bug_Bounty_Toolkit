// Package logging provides the toolkit's structured logger.
//
// Every log record is JSON with a stable envelope (timestamp, level, module,
// event) and a redacted, control-character-free attribute set. Redaction is
// applied here rather than at each call site so that a new module cannot
// accidentally introduce a secret leak.
package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bbtoolkit/bugbounty/internal/redact"
)

// Level is the log verbosity level.
type Level = slog.Level

// Re-exported levels so callers do not need to import log/slog directly.
const (
	LevelDebug = slog.LevelDebug
	LevelInfo  = slog.LevelInfo
	LevelWarn  = slog.LevelWarn
	LevelError = slog.LevelError
)

// Logger is the toolkit's logger type.
type Logger = *slog.Logger

// Config controls logger construction.
type Config struct {
	// Level is the minimum level to emit.
	Level Level
	// JSON selects the JSON handler (default) or the text handler.
	JSON bool
	// Module is the default module name attached to every record.
	Module string
	// Color adds ANSI coloring in text mode.
	Color bool
	// File, when set, receives the records in addition to stderr.
	File io.Writer
}

var (
	defaultMu sync.RWMutex
	current   = slog.New(newHandler(os.Stderr, &Config{Level: LevelInfo, JSON: true}))
)

// Options carries per-call attributes such as the module and the scan run.
type Options struct {
	Module   string
	RunID    string
	Target   string
	Extra    []any
	explicit []any
}

// Opt builds an Options value.
func Opt(mods ...Option) *Options {
	o := &Options{}
	for _, m := range mods {
		m(o)
	}
	return o
}

// Option mutates Options.
type Option func(*Options)

// WithModule sets the module name.
func WithModule(m string) Option { return func(o *Options) { o.Module = m } }

// WithRun attaches a scan run identifier.
func WithRun(id string) Option { return func(o *Options) { o.RunID = id } }

// WithTarget attaches the in-scope target being worked on.
func WithTarget(t string) Option { return func(o *Options) { o.Target = t } }

// With attaches an arbitrary key/value pair.
func With(k string, v any) Option {
	return func(o *Options) { o.explicit = append(o.explicit, k, v) }
}

// New builds a logger from a config. A nil or zero Level means info.
func New(cfg Config) *slog.Logger {
	if cfg.Level == 0 {
		cfg.Level = LevelInfo
	}
	var w io.Writer = os.Stderr
	if cfg.File != nil {
		w = io.MultiWriter(os.Stderr, cfg.File)
	}
	return slog.New(newHandler(w, &cfg))
}

// SetDefault installs a process-wide logger.
func SetDefault(l *slog.Logger) {
	defaultMu.Lock()
	current = l
	defaultMu.Unlock()
}

// Default returns the process-wide logger.
func Default() *slog.Logger {
	defaultMu.RLock()
	defer defaultMu.RUnlock()
	return current
}

// newHandler builds the JSON or text handler. Both share the redaction
// pipeline; only the encoder differs.
func newHandler(w io.Writer, cfg *Config) slog.Handler {
	opts := &slog.HandlerOptions{
		Level: cfg.Level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			return a
		},
	}
	if cfg.JSON {
		h := &redactingHandler{inner: slog.NewJSONHandler(w, opts), mod: cfg.Module}
		return h
	}
	h := &redactingHandler{inner: slog.NewTextHandler(w, opts), mod: cfg.Module}
	h.text = true
	return h
}

// redactingHandler wraps another handler and applies the redaction pipeline to
// every attribute before delegating.
type redactingHandler struct {
	inner slog.Handler
	mod   string
	text  bool
	attrs []slog.Attr
}

func (h *redactingHandler) Enabled(ctx context.Context, l Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h *redactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	cleaned := make([]slog.Attr, 0, len(attrs))
	for _, a := range attrs {
		cleaned = append(cleaned, cleanAttr(a))
	}
	h.attrs = append(append([]slog.Attr{}, h.attrs...), cleaned...)
	return &redactingHandler{inner: h.inner.WithAttrs(cleaned), mod: h.mod, text: h.text, attrs: h.attrs}
}

func (h *redactingHandler) WithGroup(name string) slog.Handler {
	if strings.ContainsAny(name, " \t\n\r\"") {
		name = redact.Sanitize(name)
	}
	return &redactingHandler{inner: h.inner.WithGroup(name), mod: h.mod, text: h.text, attrs: h.attrs}
}

func (h *redactingHandler) Handle(ctx context.Context, r slog.Record) error {
	// The message is redacted, not merely sanitised. It is just as likely to
	// carry a credential as an attribute is: a module that writes "fetched
	// https://admin:secret@host/" has put a password in the log, and control
	// characters are not what makes that dangerous.
	out := slog.NewRecord(r.Time, r.Level, redact.Text(r.Message), r.PC)
	// An explicit module attribute, whether on the record or already attached
	// to the handler, wins. Two module keys make a record's origin ambiguous,
	// which is worse than a missing one.
	if h.mod != "" && !hasAttr(r, "module") && !h.hasKey("module") {
		out.AddAttrs(slog.String("module", h.mod))
	}
	r.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(cleanAttr(a))
		return true
	})
	return h.inner.Handle(ctx, out)
}

// hasKey reports whether the attribute was attached with With rather than
// passed to the logging call.
func (h *redactingHandler) hasKey(key string) bool {
	for _, a := range h.attrs {
		if a.Key == key {
			return true
		}
	}
	return false
}

func hasAttr(r slog.Record, key string) bool {
	found := false
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == key {
			found = true
			return false
		}
		return true
	})
	return found
}

// cleanAttr redacts a single attribute recursively.
func cleanAttr(a slog.Attr) slog.Attr {
	v := a.Value.Resolve()
	switch v.Kind() {
	case slog.KindString:
		s := v.String()
		if redact.IsSensitiveKey(a.Key) {
			return slog.String(a.Key, redact.Placeholder)
		}
		return slog.String(a.Key, redact.Sanitize(redact.Text(s)))
	case slog.KindGroup:
		g := v.Group()
		out := make([]any, 0, len(g)*2)
		for _, sub := range g {
			c := cleanAttr(sub)
			out = append(out, c.Key, c.Value.Any())
		}
		return slog.Group(a.Key, out...)
	case slog.KindAny:
		any := v.Any()
		switch t := any.(type) {
		case error:
			return slog.String(a.Key, redact.Sanitize(redact.Text(t.Error())))
		case map[string]string:
			return slog.Any(a.Key, redact.Map(t))
		case map[string][]string:
			return slog.Any(a.Key, redact.Headers(t))
		case []string:
			return slog.Any(a.Key, redact.StringSlice(t))
		case time.Duration:
			return slog.Duration(a.Key, t)
		default:
			return slog.String(a.Key, redact.Sanitize(redact.Text(safeString(any))))
		}
	default:
		return slog.Any(a.Key, v.Any())
	}
}

func safeString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case fmt_Stringer:
		return t.String()
	default:
		return ""
	}
}

type fmt_Stringer interface{ String() string }

// Event returns a logger that stamps every record with the given event name.
func Event(l *slog.Logger, name string, o *Options) *slog.Logger {
	if o == nil {
		o = &Options{}
	}
	base := l
	if o.Module != "" {
		base = base.With("module", o.Module)
	}
	if o.RunID != "" {
		base = base.With("run_id", o.RunID)
	}
	if o.Target != "" {
		base = base.With("target", redact.URL(o.Target))
	}
	if len(o.explicit) > 0 {
		base = base.With(o.explicit...)
	}
	return base.With("event", redact.Text(name))
}

// Info logs at info level.
func Info(ctx context.Context, o *Options, msg string, args ...any) {
	Event(Default(), msg, o).InfoContext(ctx, msg, args...)
}

// Debug logs at debug level.
func Debug(ctx context.Context, o *Options, msg string, args ...any) {
	Event(Default(), msg, o).DebugContext(ctx, msg, args...)
}

// Warn logs at warn level.
func Warn(ctx context.Context, o *Options, msg string, args ...any) {
	Event(Default(), msg, o).WarnContext(ctx, msg, args...)
}

// Error logs at error level.
func Error(ctx context.Context, o *Options, msg string, args ...any) {
	Event(Default(), msg, o).ErrorContext(ctx, msg, args...)
}

// ParseLevel converts a string to a Level.
func ParseLevel(s string) (Level, error) {
	var l Level
	if err := l.UnmarshalText([]byte(strings.ToLower(s))); err != nil {
		return LevelInfo, err
	}
	return l, nil
}
