package api

import (
	"net/http"

	"github.com/guided-traffic/guided-ssh/internal/auth"
	"github.com/guided-traffic/guided-ssh/internal/rulespec"
)

// RulesConfig describes who owns the two rule domains
// (docs/major-tickets/GITOPS_EXTERNAL_RULES.md, D1). Two independent
// switches:
//
//   - ManualRules gates the interactive CRUD endpoints for both domains and
//     is off by default — in-app editing is an opt-in.
//   - HostFile/CIFile put a single domain under file ownership. A file-owned
//     domain rejects every API write (CRUD and apply), regardless of
//     ManualRules: one writer per domain, ever.
//
// The apply endpoints stay available for domains without a file source —
// that is the existing `gssh-admin apply` GitOps path.
type RulesConfig struct {
	// ManualRules enables CRUD on domains that are not file-owned
	// (GSSH_MANUAL_RULES).
	ManualRules bool
	// HostFile/CIFile are the paths of the declarative rules files
	// (GSSH_HOST_RULES_FILE / GSSH_CI_RULES_FILE); empty ⇒ not file-owned.
	HostFile string
	CIFile   string
}

// ruleDomain is one of the two independently ownable rule domains.
type ruleDomain int

const (
	domainHost ruleDomain = iota
	domainCI
)

// fileEnv returns the environment variable that puts the domain under file
// ownership (named in the error message, so operators know what to unset).
func (d ruleDomain) fileEnv() string {
	if d == domainCI {
		return rulespec.EnvCIRulesFile
	}
	return rulespec.EnvHostRulesFile
}

// fileOwned reports whether the domain is reconciled from a file.
func (c RulesConfig) fileOwned(domain ruleDomain) bool {
	if domain == domainCI {
		return c.CIFile != ""
	}
	return c.HostFile != ""
}

// editable reports whether in-app editing of the domain is possible at all:
// manual provisioning on and no file owner. Served to the web UI in
// /v1/ui/config (D7) so it can hide buttons whose writes the gates below
// would reject anyway.
func (c RulesConfig) editable(domain ruleDomain) bool {
	return c.ManualRules && !c.fileOwned(domain)
}

// Machine-readable codes of the blocked writes (D6). The UI and scripts key
// off these, the message stays human-facing.
const (
	codeManualRulesDisabled = "manual_rules_disabled"
	codeRulesFileManaged    = "rules_file_managed"
)

// writeError writes a JSON error body with a machine-readable code. The
// admin CLIs print the raw body, so the message stays self-explanatory.
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{"error": message, "code": code})
}

// gateCRUD blocks the interactive create/update/delete handlers: file-owned
// domains never accept API writes, everything else needs GSSH_MANUAL_RULES.
func (a *adminContext) gateCRUD(domain ruleDomain, next adminHandler) adminHandler {
	return func(w http.ResponseWriter, r *http.Request, claims *auth.Claims, actor string) {
		if a.rules.fileOwned(domain) {
			a.rejectFileManaged(w, r, domain)
			return
		}
		if !a.rules.ManualRules {
			a.logger.Info("admin: rule crud blocked (manual provisioning off)", "path", r.URL.Path)
			writeError(w, http.StatusForbidden, codeManualRulesDisabled,
				"in-app rule editing is disabled — manage rules declaratively (`gssh-admin apply`) "+
					"or set "+rulespec.EnvManualRules+"=true (chart value config.rules.manualProvision)")
			return
		}
		next(w, r, claims, actor)
	}
}

// gateApply blocks the declarative apply handlers of file-owned domains; the
// file is the single writer there. Domains without a file source keep the
// endpoint (D1), independent of GSSH_MANUAL_RULES.
func (a *adminContext) gateApply(domain ruleDomain, next adminHandler) adminHandler {
	return func(w http.ResponseWriter, r *http.Request, claims *auth.Claims, actor string) {
		if a.rules.fileOwned(domain) {
			a.rejectFileManaged(w, r, domain)
			return
		}
		next(w, r, claims, actor)
	}
}

func (a *adminContext) rejectFileManaged(w http.ResponseWriter, r *http.Request, domain ruleDomain) {
	a.logger.Info("admin: rule write blocked (domain owned by rules file)", "path", r.URL.Path, "env", domain.fileEnv())
	writeError(w, http.StatusForbidden, codeRulesFileManaged,
		"these rules are managed by the rules file in "+domain.fileEnv()+
			" — change them in the source of that file (GitOps), API writes are disabled")
}
