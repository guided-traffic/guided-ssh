package rulesync_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guided-traffic/guided-ssh/internal/rulesync"
	"github.com/guided-traffic/guided-ssh/internal/store"
)

// fakeApplier records the applied specs; the transactional reconciliation
// itself is covered by the store's integration tests. The mutex guards the
// state against the reconcile loop of the Run tests.
type fakeApplier struct {
	mu         sync.Mutex
	hostSpecs  []store.GrantSpec
	hostIssuer string
	hostActor  string
	hostCalls  int
	ciSpecs    []store.CIGrantSpec
	ciActor    string
	ciCalls    int
	hostResult *store.ApplyResult
	ciErr      error
}

func (f *fakeApplier) ApplyGrants(_ context.Context, actor, defaultIssuer string, specs []store.GrantSpec) (*store.ApplyResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hostCalls++
	f.hostActor, f.hostIssuer, f.hostSpecs = actor, defaultIssuer, specs
	if f.hostResult != nil {
		return f.hostResult, nil
	}
	return &store.ApplyResult{Created: len(specs)}, nil
}

func (f *fakeApplier) ApplyCIGrants(_ context.Context, actor string, specs []store.CIGrantSpec) (*store.ApplyResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ciCalls++
	f.ciActor = actor
	if f.ciErr != nil {
		return nil, f.ciErr
	}
	f.ciSpecs = specs
	return &store.ApplyResult{Created: len(specs)}, nil
}

// hostApplies returns the number of host applies; the Run tests read it
// while the reconcile loop writes it.
func (f *fakeApplier) hostApplies() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hostCalls
}

// waitForHostCalls waits until the loop has applied at least n times.
func (f *fakeApplier) waitForHostCalls(n int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if f.hostApplies() >= n {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return f.hostApplies() >= n
}

// discardLogger keeps the reconciler's log lines out of the test output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// writeRules writes a rules file into a temp dir and returns its path.
func writeRules(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

const hostRules = `grants:
  - group: deployers
    tags:
      env: prod
    principals: [deploy]
    max_validity: 8h
`

const ciRules = `ci_grants:
  - project: infra/ansible
    ref: main
    tags:
      env: prod
    principals: [deploy]
    max_validity: 1h
`

func TestSyncAppliesBothDomains(t *testing.T) {
	applier := &fakeApplier{}
	syncer := rulesync.New(applier, rulesync.Config{
		Logger:        discardLogger(),
		HostFile:      writeRules(t, "host.yaml", hostRules),
		CIFile:        writeRules(t, "ci.yaml", ciRules),
		DefaultIssuer: "https://idp.example/realms/gssh",
	})
	if !syncer.Enabled() {
		t.Fatal("Enabled() = false, expected true")
	}
	if err := syncer.Sync(context.Background()); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(applier.hostSpecs) != 1 || applier.hostSpecs[0].Group != "deployers" ||
		applier.hostSpecs[0].MaxValiditySeconds != 8*3600 {
		t.Errorf("host specs: %+v", applier.hostSpecs)
	}
	if len(applier.ciSpecs) != 1 || applier.ciSpecs[0].ProjectPath != "infra/ansible" ||
		!applier.ciSpecs[0].ProtectedOnly {
		t.Errorf("ci specs: %+v", applier.ciSpecs)
	}
	// Audit actor and default issuer (D5): the file has no token to derive
	// an identity or an issuer from.
	if applier.hostActor != rulesync.Actor || applier.ciActor != rulesync.Actor {
		t.Errorf("actors: host=%q ci=%q, expected %q", applier.hostActor, applier.ciActor, rulesync.Actor)
	}
	if applier.hostIssuer != "https://idp.example/realms/gssh" {
		t.Errorf("default issuer %q", applier.hostIssuer)
	}
}

// TestSyncEmptyListDeletes: an explicitly empty list is a valid target state
// and clears the domain — that is what makes the file authoritative.
func TestSyncEmptyListDeletes(t *testing.T) {
	applier := &fakeApplier{}
	syncer := rulesync.New(applier, rulesync.Config{
		Logger:        discardLogger(),
		HostFile:      writeRules(t, "host.yaml", "grants: []\n"),
		DefaultIssuer: "https://idp.example",
	})
	if err := syncer.Sync(context.Background()); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if applier.hostCalls != 1 || len(applier.hostSpecs) != 0 {
		t.Errorf("calls=%d specs=%+v, expected one apply with an empty list", applier.hostCalls, applier.hostSpecs)
	}
	if applier.ciCalls != 0 {
		t.Errorf("ci applied %d times although no ci file is configured", applier.ciCalls)
	}
}

// TestSyncOnlyConfiguredDomain: a domain without a file stays untouched — it
// keeps its own writer (API/apply).
func TestSyncOnlyConfiguredDomain(t *testing.T) {
	applier := &fakeApplier{}
	syncer := rulesync.New(applier, rulesync.Config{Logger: discardLogger(), CIFile: writeRules(t, "ci.yaml", ciRules)})
	if err := syncer.Sync(context.Background()); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if applier.hostCalls != 0 || applier.ciCalls != 1 {
		t.Errorf("host calls=%d, ci calls=%d", applier.hostCalls, applier.ciCalls)
	}
}

func TestSyncDisabledWithoutFiles(t *testing.T) {
	syncer := rulesync.New(&fakeApplier{}, rulesync.Config{Logger: discardLogger()})
	if syncer.Enabled() {
		t.Error("Enabled() = true without any configured file")
	}
	if err := syncer.Sync(context.Background()); err != nil {
		t.Errorf("Sync: %v", err)
	}
}

// TestSyncInvalidFileKeepsState: a broken file must not reach the store —
// the last applied state stays active and the error is reported.
func TestSyncInvalidFileKeepsState(t *testing.T) {
	cases := map[string]string{
		"missing key":      "# no grants key\n",
		"unknown key":      "grants:\n  - group: x\n    princiapls: [deploy]\n    max_validity: 1h\n",
		"wrong domain key": "ci_grants: []\n",
		"broken duration":  "grants:\n  - group: x\n    principals: [deploy]\n    max_validity: 8 hours\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			applier := &fakeApplier{}
			syncer := rulesync.New(applier, rulesync.Config{
				Logger: discardLogger(), HostFile: writeRules(t, "host.yaml", content),
				DefaultIssuer: "https://idp.example",
			})
			err := syncer.Sync(context.Background())
			if err == nil {
				t.Fatal("Sync: expected an error")
			}
			if !strings.Contains(err.Error(), "GSSH_HOST_RULES_FILE") {
				t.Errorf("error does not name the owning env var: %v", err)
			}
			if applier.hostCalls != 0 {
				t.Errorf("store was written %d times despite an invalid file", applier.hostCalls)
			}
		})
	}
}

// TestSyncMissingFileFails backs the startup fail-fast: a wrong path is a
// deployment bug, not an empty rule set.
func TestSyncMissingFileFails(t *testing.T) {
	applier := &fakeApplier{}
	syncer := rulesync.New(applier, rulesync.Config{Logger: discardLogger(), HostFile: filepath.Join(t.TempDir(), "absent.yaml")})
	if err := syncer.Sync(context.Background()); err == nil {
		t.Fatal("Sync: expected an error for a missing file")
	}
	if applier.hostCalls != 0 {
		t.Errorf("store was written %d times although the file is missing", applier.hostCalls)
	}
}

// TestSyncContinuesAfterDomainError: a broken CI file must not stop the host
// reconciliation — both errors are reported.
func TestSyncContinuesAfterDomainError(t *testing.T) {
	applier := &fakeApplier{ciErr: errors.New("apply failed")} //nolint:err113 // test double
	syncer := rulesync.New(applier, rulesync.Config{
		Logger:        discardLogger(),
		HostFile:      writeRules(t, "host.yaml", hostRules),
		CIFile:        writeRules(t, "ci.yaml", ciRules),
		DefaultIssuer: "https://idp.example",
	})
	err := syncer.Sync(context.Background())
	if err == nil {
		t.Fatal("Sync: expected the ci error")
	}
	if applier.hostCalls != 1 {
		t.Errorf("host applied %d times, expected 1", applier.hostCalls)
	}
}

// TestRunReappliesPeriodically covers the drift correction: the loop
// re-applies the unchanged file on every tick.
func TestRunReappliesPeriodically(t *testing.T) {
	applier := &fakeApplier{hostResult: &store.ApplyResult{Unchanged: 1}}
	syncer := rulesync.New(applier, rulesync.Config{
		Logger:        discardLogger(),
		HostFile:      writeRules(t, "host.yaml", hostRules),
		DefaultIssuer: "https://idp.example",
		Interval:      5 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go syncer.Run(ctx)

	if !applier.waitForHostCalls(2, 2*time.Second) {
		t.Errorf("host applied %d times, expected at least 2 ticks", applier.hostApplies())
	}
}

// TestRunSurvivesErrors: a rules file that turns invalid at runtime keeps
// the loop alive — certificate signing must not depend on a rules push.
func TestRunSurvivesErrors(t *testing.T) {
	path := writeRules(t, "host.yaml", "# broken\n")
	applier := &fakeApplier{}
	syncer := rulesync.New(applier, rulesync.Config{
		Logger:        discardLogger(),
		HostFile:      path,
		DefaultIssuer: "https://idp.example",
		Interval:      5 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go syncer.Run(ctx)

	time.Sleep(20 * time.Millisecond)
	if applies := applier.hostApplies(); applies != 0 {
		t.Fatalf("broken file reached the store (%d applies)", applies)
	}
	if err := os.WriteFile(path, []byte(hostRules), 0o600); err != nil {
		t.Fatalf("repair file: %v", err)
	}
	if !applier.waitForHostCalls(1, 2*time.Second) {
		t.Error("loop did not recover after the file was repaired")
	}
}
