package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbtoolkit/bugbounty/internal/storage"
)

// The resume tests exercise the seam that was silently broken: a --resume run
// has to attach to an existing run id, or it looks for stage history under an
// id that has just been created and finds nothing.

// openStore returns a store backed by a temporary database.
func openStore(t *testing.T) *storage.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "runs.db")
	s, err := storage.Open(context.Background(), storage.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

const target = "example.com"

func recordRun(t *testing.T, s *storage.Store, id, name string, status storage.RunStatus) {
	t.Helper()
	ctx := context.Background()
	if err := s.StartRun(ctx, storage.ScanRun{ID: id, Name: name, Status: storage.RunRunning}); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishRun(ctx, id, status, nil); err != nil {
		t.Fatal(err)
	}
}

// TestResumeContinuesAResumableRun is the positive case: a run that ended with
// warnings is finished but resumable, and must be the one --resume picks.
func TestResumeContinuesAResumableRun(t *testing.T) {
	s := openStore(t)
	recordRun(t, s, "old-1", target, storage.RunResumable)

	got, err := resolveResume(context.Background(), s, "", target)
	if err != nil {
		t.Fatalf("resolveResume: %v", err)
	}
	if got.ID != "old-1" {
		t.Errorf("resumed %s, want old-1", got.ID)
	}
}

// TestResumeIgnoresACompletedRun covers the case that matters most: a run that
// finished cleanly has nothing left to continue, and resuming it would report a
// partial result as though it were the whole thing.
func TestResumeIgnoresACompletedRun(t *testing.T) {
	s := openStore(t)
	recordRun(t, s, "done-1", target, storage.RunCompleted)

	_, err := resolveResume(context.Background(), s, "", target)
	if !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("err = %v, want it to report that nothing is resumable", err)
	}
	// The message has to be actionable, because "nothing to resume" is a
	// confusing result for an operator who just asked to resume.
	if !strings.Contains(err.Error(), "omit --resume") {
		t.Errorf("the error does not say what to do instead: %v", err)
	}
}

// TestResumeRefusesAnotherTargetsRun is the cross-engagement guard. Findings
// from this target must never be filed under a different client's run.
func TestResumeRefusesAnotherTargetsRun(t *testing.T) {
	s := openStore(t)
	recordRun(t, s, "other", "other-client.example", storage.RunResumable)

	_, err := resolveResume(context.Background(), s, "", target)
	if err == nil {
		t.Fatal("SECURITY: a run for a different target was selected for resume")
	}
	for _, want := range []string{"wrong engagement", "other-client.example"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not explain %q: %v", want, err)
		}
	}
}

// TestNamedRunIsValidated covers --run with an explicit id.
func TestNamedRunIsValidated(t *testing.T) {
	s := openStore(t)
	recordRun(t, s, "named", target, storage.RunResumable)
	recordRun(t, s, "other", "other-client.example", storage.RunResumable)

	t.Run("the named run is used", func(t *testing.T) {
		got, err := resolveResume(context.Background(), s, "named", target)
		if err != nil {
			t.Fatal(err)
		}
		if got.ID != "named" {
			t.Errorf("resumed %s, want named", got.ID)
		}
	})

	t.Run("a completed run is refused", func(t *testing.T) {
		recordRun(t, s, "fin", target, storage.RunCompleted)
		if _, err := resolveResume(context.Background(), s, "fin", target); err == nil {
			t.Error("SECURITY: a completed run was offered for resume")
		}
	})

	t.Run("an unknown run is reported", func(t *testing.T) {
		_, err := resolveResume(context.Background(), s, "does-not-exist", target)
		if err == nil {
			t.Fatal("an unknown run id was accepted")
		}
		if !strings.Contains(err.Error(), "does-not-exist") {
			t.Errorf("the error does not name the run: %v", err)
		}
	})

	t.Run("a named run for another target is refused", func(t *testing.T) {
		if _, err := resolveResume(context.Background(), s, "other", target); err == nil {
			t.Error("SECURITY: a named run for another target was accepted")
		}
	})
}

// TestResumeWorksOnARunThatFailedMidway reproduces the situation resume exists
// for: a run that was started and then recorded as still running, which is what
// a killed process leaves behind.
func TestResumeWorksOnARunThatFailedMidway(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	// StartRun only: no FinishRun, so this is a run whose process died.
	if err := s.StartRun(ctx, storage.ScanRun{ID: "killed", Name: target, Status: storage.RunRunning}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetStageState(ctx, storage.StageStatusRecord{
		Run: "killed", Name: "http", Seq: 1, Status: storage.StageCompleted,
	}); err != nil {
		t.Fatal(err)
	}

	got, err := resolveResume(ctx, s, "", target)
	if err != nil {
		t.Fatalf("a run left behind by a killed process was not resumable: %v", err)
	}
	if got.ID != "killed" {
		t.Errorf("resumed %s, want killed", got.ID)
	}
	// And it must actually carry the stage history, or skipping is impossible.
	states, err := s.StageStates(ctx, got.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].Name != "http" {
		t.Errorf("stage history did not come with the run: %+v", states)
	}
}

// TestResumeFlagIsWiredUp checks the flags are registered, so --resume is not
// a flag the command silently ignores.
func TestResumeFlagIsWiredUp(t *testing.T) {
	root := newRootCommand()
	scan, _, err := root.Find([]string{"scan"})
	if err != nil {
		t.Fatalf("the scan command is not registered: %v", err)
	}
	for _, name := range []string{"resume", "run"} {
		f := scan.Flags().Lookup(name)
		if f == nil {
			t.Errorf("the scan command has no --%s flag", name)
			continue
		}
		if f.Usage == "" {
			t.Errorf("--%s has no help text, so an operator cannot tell what it resumes", name)
		}
	}
	// A run cannot be resumed without a database, so the combination is a
	// mistake worth naming rather than a silent no-op.
	dir := t.TempDir()
	scopePath := filepath.Join(dir, "scope.yaml")
	if err := os.WriteFile(scopePath, []byte(goodScope), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err = runCLI(t, "scan", target, "--scope", scopePath, "--resume", "--no-db", "--dry-run")
	if err == nil {
		t.Error("--resume was accepted with no database to resume from")
	}
}
