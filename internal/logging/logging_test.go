package logging

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// Realistic credentials, one per format the redactor recognises. A bare random
// string would be a poor probe: redact.Text matches known credential shapes, so
// an unrecognisable value passing through proves nothing either way.
const (
	awsKey    = "AKIAIOSFODNN7EXAMPLE"
	githubPat = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
	bearerTok = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	userinfo  = "hunter2swordfish"
)

var canaries = []string{awsKey, githubPat, bearerTok, userinfo}

func newTestLogger(t *testing.T, json bool) (*slog.Logger, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	cfg := Config{Level: LevelDebug, JSON: json, Module: "test"}
	return slog.New(newHandler(&buf, &cfg)), &buf
}

func leakReport(out string) []string {
	var found []string
	for _, c := range canaries {
		if strings.Contains(out, c) {
			found = append(found, c)
		}
	}
	return found
}

// --- the central promise -----------------------------------------------------

// TestNoRouteLeaksASecret is the property the package exists for. The package
// comment claims redaction is applied centrally "so that a new module cannot
// accidentally introduce a secret leak", so every plausible attachment point is
// checked rather than only the ones the author remembered.
func TestNoRouteLeaksASecret(t *testing.T) {
	cases := []struct {
		name string
		log  func(l *slog.Logger)
	}{
		{"string attribute", func(l *slog.Logger) {
			l.Info("m", "body", "key "+awsKey)
		}},
		{"url attribute", func(l *slog.Logger) {
			l.Info("m", "url", "https://user:"+userinfo+"@example.com/")
		}},
		{"bearer attribute", func(l *slog.Logger) {
			l.Info("m", "auth", "Bearer "+bearerTok)
		}},
		{"error attribute", func(l *slog.Logger) {
			l.Info("m", "err", errors.New("failed with "+awsKey))
		}},
		{"nested group", func(l *slog.Logger) {
			l.Info("m", "outer", slog.GroupValue(slog.String("inner", awsKey)))
		}},
		{"sensitive key", func(l *slog.Logger) {
			l.Info("m", "authorization", bearerTok)
		}},
		{"map value", func(l *slog.Logger) {
			l.Info("m", "cfg", map[string]string{"note": awsKey})
		}},
		{"header value", func(l *slog.Logger) {
			l.Info("m", "hdr", map[string][]string{"X-Note": {awsKey}})
		}},
		{"string slice", func(l *slog.Logger) {
			l.Info("m", "tags", []string{awsKey})
		}},
		{"stringer", func(l *slog.Logger) {
			l.Info("m", "obj", secretStringer{})
		}},
		{"pre-attached attribute", func(l *slog.Logger) {
			l.With("k", awsKey).Info("m")
		}},
		{"event name", func(l *slog.Logger) {
			Event(l, "event-"+awsKey, nil).Info("m")
		}},
		{"target option", func(l *slog.Logger) {
			Event(l, "e", Opt(WithTarget("https://user:"+userinfo+"@example.com/"))).Info("m")
		}},
		{"module option", func(l *slog.Logger) {
			Event(l, "e", Opt(WithModule(awsKey))).Info("m")
		}},
		{"run option", func(l *slog.Logger) {
			Event(l, "e", Opt(WithRun(awsKey))).Info("m")
		}},
		{"with option", func(l *slog.Logger) {
			Event(l, "e", Opt(With("token", awsKey))).Info("m")
		}},
	}

	for _, json := range []bool{true, false} {
		for _, c := range cases {
			l, buf := newTestLogger(t, json)
			c.log(l)
			if found := leakReport(buf.String()); len(found) > 0 {
				mode := "json"
				if !json {
					mode = "text"
				}
				t.Errorf("SECURITY: a secret reached the %s log via %s (%v):\n%s",
					mode, c.name, found, buf.String())
			}
		}
	}
}

type secretStringer struct{}

func (secretStringer) String() string { return "leaked " + awsKey }

// TestMessageTextIsRedacted covers the attachment point that is easy to
// overlook, because it is the string the caller passes as the message rather
// than as an attribute. A module that formats a target's response into a
// sentence must not be able to put a credential on disk.
func TestMessageTextIsRedacted(t *testing.T) {
	for _, msg := range []string{
		"fetched https://admin:" + userinfo + "@example.com/secret",
		"request used " + awsKey + " and failed",
		"header was Bearer " + bearerTok,
	} {
		l, buf := newTestLogger(t, true)
		l.Info(msg)
		if found := leakReport(buf.String()); len(found) > 0 {
			t.Errorf("SECURITY: a secret in the message text reached the log (%v):\n%s", found, buf.String())
		}
	}
}

// --- structure and safety ----------------------------------------------------

// TestControlCharactersAreStripped checks the other half of the pipeline: a log
// line must stay one line, or a target can forge entries in the operator's log.
func TestControlCharactersAreStripped(t *testing.T) {
	l, buf := newTestLogger(t, true)
	l.Info("line one\nline two\r\nline three\x00\x07end")
	out := buf.String()
	if strings.Contains(out, "\nline two") {
		t.Errorf("an embedded newline survived into the log:\n%q", out)
	}
	if strings.Count(strings.TrimRight(out, "\n"), "\n") != 0 {
		t.Errorf("the record spans more than one line:\n%q", out)
	}
	if !strings.Contains(out, "line one") || !strings.Contains(out, "end") {
		t.Errorf("content was lost rather than sanitised:\n%q", out)
	}
}

func TestGroupNameIsSanitised(t *testing.T) {
	l, buf := newTestLogger(t, true)
	l.WithGroup("bad name\ninjected").Info("m", "k", "v")
	if strings.Count(strings.TrimRight(buf.String(), "\n"), "\n") != 0 {
		t.Errorf("a group name injected a line break:\n%q", buf.String())
	}
}

func TestModuleIsStampedAndNotDuplicated(t *testing.T) {
	l, buf := newTestLogger(t, true)
	l.Info("m")
	if !strings.Contains(buf.String(), `"module":"test"`) {
		t.Errorf("the configured module was not attached:\n%s", buf.String())
	}

	// An explicit module must replace the configured one, not sit beside it.
	// Two module keys make a log ambiguous about where a record came from.
	l2, buf2 := newTestLogger(t, true)
	l2.With("module", "explicit").Info("m")
	if n := strings.Count(buf2.String(), `"module"`); n != 1 {
		t.Errorf("the module appears %d times, want 1:\n%s", n, buf2.String())
	}
	if !strings.Contains(buf2.String(), "explicit") {
		t.Errorf("the explicit module was not the one recorded:\n%s", buf2.String())
	}
}

func TestLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(newHandler(&buf, &Config{Level: LevelWarn, JSON: true}))

	l.Debug("debug")
	l.Info("info")
	if buf.Len() != 0 {
		t.Errorf("records below the level were emitted:\n%s", buf.String())
	}
	l.Warn("warn")
	if !strings.Contains(buf.String(), "warn") {
		t.Errorf("a record at the level was dropped:\n%s", buf.String())
	}
}

func TestNewDefaultsToInfo(t *testing.T) {
	var buf bytes.Buffer
	l := New(Config{JSON: true, File: &buf})
	if l == nil {
		t.Fatal("New returned nil")
	}
	l.Debug("should not appear")
	if strings.Contains(buf.String(), "should not appear") {
		t.Errorf("debug was emitted at the default level:\n%s", buf.String())
	}
	l.Info("should appear")
	if !strings.Contains(buf.String(), "should appear") {
		t.Errorf("info was dropped at the default level:\n%s", buf.String())
	}
}

func TestNewWritesToTheFileToo(t *testing.T) {
	var buf bytes.Buffer
	l := New(Config{Level: LevelInfo, JSON: true, File: &buf})
	Event(l, "thing", Opt(WithRun("r1"), WithTarget("https://example.com/"))).Info("happened")

	if !strings.Contains(buf.String(), "happened") {
		t.Errorf("the file sink received nothing:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), `"run_id":"r1"`) {
		t.Errorf("the run id was not attached:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "example.com") {
		t.Errorf("the target was not attached:\n%s", buf.String())
	}
}

func TestNonStringValuesSurvive(t *testing.T) {
	l, buf := newTestLogger(t, true)
	l.Info("m",
		"count", 42,
		"ok", true,
		"took", 1500*time.Millisecond,
		"empty", nil,
	)
	out := buf.String()
	for _, want := range []string{`"count":42`, `"ok":true`, `"took":1500`} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %s in:\n%s", want, out)
		}
	}
}

func TestParseLevel(t *testing.T) {
	for in, want := range map[string]Level{
		"debug": LevelDebug,
		"INFO":  LevelInfo,
		"Warn":  LevelWarn,
		"error": LevelError,
	} {
		got, err := ParseLevel(in)
		if err != nil {
			t.Errorf("ParseLevel(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
	if _, err := ParseLevel("shouting"); err == nil {
		t.Error("an unknown level was accepted")
	}
}

func TestDefaultLoggerIsSettable(t *testing.T) {
	orig := Default()
	t.Cleanup(func() { SetDefault(orig) })

	var buf bytes.Buffer
	l := slog.New(newHandler(&buf, &Config{Level: LevelInfo, JSON: true}))
	SetDefault(l)

	ctx := context.Background()
	Info(ctx, Opt(WithModule("m")), "through the default")
	Debug(ctx, nil, "dropped")
	Warn(ctx, nil, "warned")
	Error(ctx, nil, "failed")

	out := buf.String()
	for _, want := range []string{"through the default", "warned", "failed"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "dropped") {
		t.Errorf("a debug record reached an info-level logger:\n%s", out)
	}
}

func TestOptionsAreIndependent(t *testing.T) {
	// A shared Options mutated by one call site must not leak into another's
	// record.
	a := Opt(WithModule("a"))
	b := Opt(WithModule("b"))
	if a.Module == b.Module {
		t.Fatal("two option values share state")
	}
	if len(a.explicit) != 0 || len(b.explicit) != 0 {
		t.Errorf("options carry attributes before use: %v %v", a.explicit, b.explicit)
	}
}
