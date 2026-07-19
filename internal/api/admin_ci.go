package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/guided-traffic/guided-ssh/internal/auth"
	"github.com/guided-traffic/guided-ssh/internal/store"
)

// ciGrantJSON ist die API-Repräsentation einer CI-Zugriffsregel (Phase 7).
type ciGrantJSON struct {
	ID                 string            `json:"id"`
	Project            string            `json:"project"`
	RefPattern         string            `json:"ref_pattern,omitempty"`
	ProtectedOnly      bool              `json:"protected_only"`
	EnvironmentPattern string            `json:"environment_pattern,omitempty"`
	TagSelector        map[string]string `json:"tag_selector"`
	Principals         []string          `json:"principals"`
	MaxValiditySeconds int64             `json:"max_validity_seconds"`
	CreatedAt          time.Time         `json:"created_at"`
	UpdatedAt          time.Time         `json:"updated_at"`
}

// ciGrantRequest ist der Body von POST/PUT auf CI-Grants.
type ciGrantRequest struct {
	// Project ist der GitLab-Projekt- oder Namespace-Pfad (Pflicht bei POST).
	Project            string            `json:"project,omitempty"`
	RefPattern         string            `json:"ref_pattern,omitempty"`
	ProtectedOnly      *bool             `json:"protected_only,omitempty"`
	EnvironmentPattern string            `json:"environment_pattern,omitempty"`
	TagSelector        map[string]string `json:"tag_selector,omitempty"`
	Principals         []string          `json:"principals"`
	// MaxValiditySeconds ist die maximale Zertifikatslaufzeit (Pflicht, > 0).
	MaxValiditySeconds int64 `json:"max_validity_seconds"`
}

// applyCIRequest ist der Body von POST /v1/admin/ci-grants/apply.
type applyCIRequest struct {
	CIGrants []ciGrantRequest `json:"ci_grants"`
}

// toCIGrantJSON mappt einen Store-CI-Grant auf die API-Repräsentation.
func toCIGrantJSON(g *store.CIGrant) ciGrantJSON {
	return ciGrantJSON{
		ID:                 g.ID.String(),
		Project:            g.ProjectPath,
		RefPattern:         g.RefPattern,
		ProtectedOnly:      g.ProtectedOnly,
		EnvironmentPattern: g.EnvironmentPattern,
		TagSelector:        g.TagSelector,
		Principals:         g.Principals,
		MaxValiditySeconds: g.MaxValiditySeconds,
		CreatedAt:          g.CreatedAt,
		UpdatedAt:          g.UpdatedAt,
	}
}

// validateCIGrantRequest prüft die Pflichtfelder; leere Meldung = ok.
func validateCIGrantRequest(req *ciGrantRequest, requireProject bool) string {
	if requireProject && req.Project == "" {
		return "project fehlt"
	}
	if len(req.Principals) == 0 {
		return "principals fehlen"
	}
	if req.MaxValiditySeconds <= 0 {
		return "max_validity_seconds muss größer 0 sein"
	}
	return ""
}

func (a *adminContext) handleListCIGrants(w http.ResponseWriter, r *http.Request, _ *auth.Claims, _ string) {
	grants, err := a.store.ListCIGrants(r.Context())
	if err != nil {
		a.logger.Error("admin: ci-grants laden fehlgeschlagen", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	out := make([]ciGrantJSON, 0, len(grants))
	for i := range grants {
		out = append(out, toCIGrantJSON(&grants[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *adminContext) handleGetCIGrant(w http.ResponseWriter, r *http.Request, _ *auth.Claims, _ string) {
	id, ok := grantID(w, r)
	if !ok {
		return
	}
	grant, err := a.store.GetCIGrant(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "ci-grant nicht gefunden", http.StatusNotFound)
		return
	}
	if err != nil {
		a.logger.Error("admin: ci-grant laden fehlgeschlagen", "id", id, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, toCIGrantJSON(grant))
}

func (a *adminContext) handleCreateCIGrant(w http.ResponseWriter, r *http.Request, _ *auth.Claims, actor string) {
	var req ciGrantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "request-body ungültig", http.StatusBadRequest)
		return
	}
	if msg := validateCIGrantRequest(&req, true); msg != "" {
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	grant := &store.CIGrant{
		ProjectPath:        req.Project,
		RefPattern:         req.RefPattern,
		ProtectedOnly:      true,
		EnvironmentPattern: req.EnvironmentPattern,
		TagSelector:        req.TagSelector,
		Principals:         req.Principals,
		MaxValiditySeconds: req.MaxValiditySeconds,
	}
	if req.ProtectedOnly != nil {
		grant.ProtectedOnly = *req.ProtectedOnly
	}
	if err := a.store.CreateCIGrant(r.Context(), actor, grant); err != nil {
		a.logger.Error("admin: ci-grant anlegen fehlgeschlagen", "project", req.Project, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, toCIGrantJSON(grant))
}

func (a *adminContext) handleUpdateCIGrant(w http.ResponseWriter, r *http.Request, _ *auth.Claims, actor string) {
	id, ok := grantID(w, r)
	if !ok {
		return
	}
	var req ciGrantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "request-body ungültig", http.StatusBadRequest)
		return
	}
	if msg := validateCIGrantRequest(&req, false); msg != "" {
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	current, err := a.store.GetCIGrant(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "ci-grant nicht gefunden", http.StatusNotFound)
		return
	}
	if err != nil {
		a.logger.Error("admin: ci-grant laden fehlgeschlagen", "id", id, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	grant := *current
	grant.RefPattern = req.RefPattern
	grant.EnvironmentPattern = req.EnvironmentPattern
	if req.ProtectedOnly != nil {
		grant.ProtectedOnly = *req.ProtectedOnly
	}
	if req.TagSelector != nil {
		grant.TagSelector = req.TagSelector
	}
	grant.Principals = req.Principals
	grant.MaxValiditySeconds = req.MaxValiditySeconds
	if err := a.store.UpdateCIGrant(r.Context(), actor, &grant); err != nil {
		a.logger.Error("admin: ci-grant aktualisieren fehlgeschlagen", "id", id, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, toCIGrantJSON(&grant))
}

func (a *adminContext) handleDeleteCIGrant(w http.ResponseWriter, r *http.Request, _ *auth.Claims, actor string) {
	id, ok := grantID(w, r)
	if !ok {
		return
	}
	err := a.store.DeleteCIGrant(r.Context(), actor, id)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "ci-grant nicht gefunden", http.StatusNotFound)
		return
	}
	if err != nil {
		a.logger.Error("admin: ci-grant löschen fehlgeschlagen", "id", id, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *adminContext) handleApplyCIGrants(w http.ResponseWriter, r *http.Request, _ *auth.Claims, actor string) {
	var req applyCIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "request-body ungültig", http.StatusBadRequest)
		return
	}
	specs := make([]store.CIGrantSpec, 0, len(req.CIGrants))
	for _, g := range req.CIGrants {
		protectedOnly := true
		if g.ProtectedOnly != nil {
			protectedOnly = *g.ProtectedOnly
		}
		specs = append(specs, store.CIGrantSpec{
			ProjectPath:        g.Project,
			RefPattern:         g.RefPattern,
			ProtectedOnly:      protectedOnly,
			EnvironmentPattern: g.EnvironmentPattern,
			TagSelector:        g.TagSelector,
			Principals:         g.Principals,
			MaxValiditySeconds: g.MaxValiditySeconds,
		})
	}
	result, err := a.store.ApplyCIGrants(r.Context(), actor, specs)
	if errors.Is(err, store.ErrInvalidGrantSpec) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		a.logger.Error("admin: ci-apply fehlgeschlagen", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
