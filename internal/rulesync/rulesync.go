// Package rulesync reconciles the access rules in the database from
// declarative rules files (GitOps, docs/major-tickets/GITOPS_EXTERNAL_RULES.md,
// D4/D5). Each domain (host grants, CI grants) has its own optional file; a
// configured file is the single writer of that domain — the API rejects
// writes there (internal/api, D1).
//
// The loop re-applies the files on a fixed interval instead of watching them:
// the declarative apply is idempotent and only writes audit events on actual
// changes, so polling needs no extra dependency and doubles as drift
// correction — an out-of-band database change is reverted on the next tick.
package rulesync

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/guided-traffic/guided-ssh/internal/metrics"
	"github.com/guided-traffic/guided-ssh/internal/rulespec"
	"github.com/guided-traffic/guided-ssh/internal/store"
)

// Actor of file-driven applies in the audit log (D5): distinguishable from
// human admins and CI service accounts.
const Actor = "system:rules-file"

// DefaultInterval is the reconcile interval. Kubernetes propagates ConfigMap
// updates into the volume within about a minute anyway, so a shorter
// interval would not make changes visible any faster.
const DefaultInterval = 30 * time.Second

// Applier is the store's declarative apply API (*store.Store satisfies it).
type Applier interface {
	ApplyGrants(ctx context.Context, actor, defaultIssuer string, specs []store.GrantSpec) (*store.ApplyResult, error)
	ApplyCIGrants(ctx context.Context, actor string, specs []store.CIGrantSpec) (*store.ApplyResult, error)
}

// Config configures the reconciler; an empty file path disables that domain.
type Config struct {
	// HostFile/CIFile are the paths of the declarative rules files
	// (GSSH_HOST_RULES_FILE / GSSH_CI_RULES_FILE).
	HostFile string
	CIFile   string
	// DefaultIssuer is the issuer used for host-rule entries without an
	// explicit `issuer:` key — the file has no token to derive it from, so
	// this is the server's OIDC issuer (GSSH_OIDC_ISSUER).
	DefaultIssuer string
	// Interval between two reconciliations; 0 ⇒ DefaultInterval.
	Interval time.Duration
	Logger   *slog.Logger
}

// Syncer applies the configured rules files periodically.
type Syncer struct {
	store  Applier
	cfg    Config
	logger *slog.Logger
}

// New builds the reconciler. Callers check Enabled() — without a configured
// file there is nothing to reconcile.
func New(applier Applier, cfg Config) *Syncer {
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Syncer{store: applier, cfg: cfg, logger: logger}
}

// Enabled reports whether any domain is file-owned.
func (s *Syncer) Enabled() bool {
	return s.cfg.HostFile != "" || s.cfg.CIFile != ""
}

// Sync reconciles every configured domain once. Both domains are attempted
// even if the first one fails — a broken CI file must not freeze the host
// rules. Errors of all domains are joined.
func (s *Syncer) Sync(ctx context.Context) error {
	var errs []error
	if s.cfg.HostFile != "" {
		if err := s.syncHost(ctx); err != nil {
			metrics.RulesFileSyncErrors.WithLabelValues("host").Inc()
			errs = append(errs, err)
		}
	}
	if s.cfg.CIFile != "" {
		if err := s.syncCI(ctx); err != nil {
			metrics.RulesFileSyncErrors.WithLabelValues("ci").Inc()
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (s *Syncer) syncHost(ctx context.Context) error {
	specs, err := rulespec.LoadHostRules(s.cfg.HostFile)
	if err != nil {
		return fmt.Errorf("host rules (%s): %w", rulespec.EnvHostRulesFile, err)
	}
	result, err := s.store.ApplyGrants(ctx, Actor, s.cfg.DefaultIssuer, specs)
	if err != nil {
		return fmt.Errorf("apply host rules from %s: %w", s.cfg.HostFile, err)
	}
	s.logChanges("host", s.cfg.HostFile, result)
	return nil
}

func (s *Syncer) syncCI(ctx context.Context) error {
	specs, err := rulespec.LoadCIRules(s.cfg.CIFile)
	if err != nil {
		return fmt.Errorf("ci rules (%s): %w", rulespec.EnvCIRulesFile, err)
	}
	result, err := s.store.ApplyCIGrants(ctx, Actor, specs)
	if err != nil {
		return fmt.Errorf("apply ci rules from %s: %w", s.cfg.CIFile, err)
	}
	s.logChanges("ci", s.cfg.CIFile, result)
	return nil
}

// logChanges logs one line per reconciliation that actually changed
// something — an unchanged tick every 30 s would only fill the log.
func (s *Syncer) logChanges(domain, path string, result *store.ApplyResult) {
	if result == nil || result.Created+result.Updated+result.Deleted == 0 {
		return
	}
	s.logger.Info("rules file applied", "domain", domain, "file", path,
		"created", result.Created, "updated", result.Updated,
		"deleted", result.Deleted, "unchanged", result.Unchanged)
}

// Run reconciles until ctx is done. Errors keep the last applied state, are
// logged and counted, and the next tick retries: a bad rules push must not
// take down certificate signing. The startup apply is the caller's job
// (fail-fast, see cmd/gssh-server).
func (s *Syncer) Run(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.Sync(ctx); err != nil && ctx.Err() == nil {
				s.logger.Error("rules file sync failed — keeping last applied state", "error", err)
			}
		}
	}
}
