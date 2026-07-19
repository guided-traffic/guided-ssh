package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/guided-traffic/guided-ssh/internal/auth"
	"github.com/guided-traffic/guided-ssh/internal/ca"
	"github.com/guided-traffic/guided-ssh/internal/store"
)

// AdminStore sind die von der Admin-API benötigten Store-Methoden
// (*store.Store erfüllt sie; Tests nutzen einen Fake).
type AdminStore interface {
	ListGrantsDetailed(ctx context.Context) ([]store.GrantWithGroup, error)
	GetGrantDetailed(ctx context.Context, id uuid.UUID) (*store.GrantWithGroup, error)
	CreateGrant(ctx context.Context, actor string, g *store.AccessGrant) error
	UpdateGrant(ctx context.Context, actor string, g *store.AccessGrant) error
	DeleteGrant(ctx context.Context, actor string, id uuid.UUID) error
	ApplyGrants(ctx context.Context, actor, defaultIssuer string, specs []store.GrantSpec) (*store.ApplyResult, error)

	// CI-Grants (Phase 7).
	ListCIGrants(ctx context.Context) ([]store.CIGrant, error)
	GetCIGrant(ctx context.Context, id uuid.UUID) (*store.CIGrant, error)
	CreateCIGrant(ctx context.Context, actor string, g *store.CIGrant) error
	UpdateCIGrant(ctx context.Context, actor string, g *store.CIGrant) error
	DeleteCIGrant(ctx context.Context, actor string, id uuid.UUID) error
	ApplyCIGrants(ctx context.Context, actor string, specs []store.CIGrantSpec) (*store.ApplyResult, error)
}

// grantJSON ist die API-Repräsentation einer Zugriffsregel; die Gruppe wird
// per Name + Issuer angesprochen (UUIDs bleiben intern).
type grantJSON struct {
	ID                 string            `json:"id"`
	Group              string            `json:"group"`
	Issuer             string            `json:"issuer"`
	TagSelector        map[string]string `json:"tag_selector"`
	Principals         []string          `json:"principals"`
	Sudo               bool              `json:"sudo"`
	MaxValiditySeconds int64             `json:"max_validity_seconds"`
	CreatedAt          time.Time         `json:"created_at"`
	UpdatedAt          time.Time         `json:"updated_at"`
}

// grantRequest ist der Body von POST/PUT auf Grants.
type grantRequest struct {
	// Group ist der Gruppenname im IdP (Pflicht bei POST).
	Group string `json:"group,omitempty"`
	// Issuer der Gruppe; leer ⇒ Issuer des Admin-Tokens.
	Issuer      string            `json:"issuer,omitempty"`
	TagSelector map[string]string `json:"tag_selector,omitempty"`
	Principals  []string          `json:"principals"`
	Sudo        bool              `json:"sudo,omitempty"`
	// MaxValiditySeconds ist die maximale Zertifikatslaufzeit (Pflicht, > 0).
	MaxValiditySeconds int64 `json:"max_validity_seconds"`
}

// applyRequest ist der Body von POST /v1/admin/grants/apply.
type applyRequest struct {
	Grants []grantRequest `json:"grants"`
}

// toGrantJSON mappt einen Store-Grant auf die API-Repräsentation.
func toGrantJSON(g *store.GrantWithGroup) grantJSON {
	return grantJSON{
		ID:                 g.ID.String(),
		Group:              g.GroupName,
		Issuer:             g.GroupIssuer,
		TagSelector:        g.TagSelector,
		Principals:         g.Principals,
		Sudo:               g.Sudo,
		MaxValiditySeconds: g.MaxValiditySeconds,
		CreatedAt:          g.CreatedAt,
		UpdatedAt:          g.UpdatedAt,
	}
}

// Rollen der Admin-API (Phase 8): admin schließt auditor ein, auditor
// schließt readonly ein. Jede Rolle ist an eine IdP-Gruppe gebunden.
const (
	roleAdmin    = "admin"
	roleAuditor  = "auditor"
	roleReadOnly = "readonly"
)

// adminContext bündelt die Abhängigkeiten der Admin-Handler.
type adminContext struct {
	store         AdminStore
	ui            UIStore
	groups        auth.Store
	verifier      TokenVerifier
	mapper        *auth.Mapper
	adminGroup    string
	auditorGroup  string
	readonlyGroup string
	logger        *slog.Logger
}

// registerAdminRoutes hängt die Admin-API an den Mux. Ohne OIDC oder ohne
// eine einzige konfigurierte Rollen-Gruppe antwortet der gesamte Admin-Pfad
// mit 503 (fail-closed, aber diagnostizierbar).
func registerAdminRoutes(mux *http.ServeMux, deps Deps) {
	anyRole := deps.AdminGroup != "" || deps.AuditorGroup != "" || deps.ReadOnlyGroup != ""
	if deps.Admin == nil || deps.Verifier == nil || deps.Store == nil || !anyRole {
		mux.HandleFunc("/v1/admin/", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "admin-api nicht konfiguriert (oidc und rollen-gruppe erforderlich)", http.StatusServiceUnavailable)
		})
		return
	}
	admin := &adminContext{
		store:         deps.Admin,
		ui:            deps.UI,
		groups:        deps.Store,
		verifier:      deps.Verifier,
		mapper:        auth.NewMapper(deps.Store),
		adminGroup:    deps.AdminGroup,
		auditorGroup:  deps.AuditorGroup,
		readonlyGroup: deps.ReadOnlyGroup,
		logger:        deps.Logger,
	}
	mux.HandleFunc("GET /v1/admin/grants", admin.authorized(roleReadOnly, admin.handleListGrants))
	mux.HandleFunc("POST /v1/admin/grants", admin.authorized(roleAdmin, admin.handleCreateGrant))
	mux.HandleFunc("GET /v1/admin/grants/{id}", admin.authorized(roleReadOnly, admin.handleGetGrant))
	mux.HandleFunc("PUT /v1/admin/grants/{id}", admin.authorized(roleAdmin, admin.handleUpdateGrant))
	mux.HandleFunc("DELETE /v1/admin/grants/{id}", admin.authorized(roleAdmin, admin.handleDeleteGrant))
	mux.HandleFunc("POST /v1/admin/grants/apply", admin.authorized(roleAdmin, admin.handleApplyGrants))
	mux.HandleFunc("GET /v1/admin/ci-grants", admin.authorized(roleReadOnly, admin.handleListCIGrants))
	mux.HandleFunc("POST /v1/admin/ci-grants", admin.authorized(roleAdmin, admin.handleCreateCIGrant))
	mux.HandleFunc("GET /v1/admin/ci-grants/{id}", admin.authorized(roleReadOnly, admin.handleGetCIGrant))
	mux.HandleFunc("PUT /v1/admin/ci-grants/{id}", admin.authorized(roleAdmin, admin.handleUpdateCIGrant))
	mux.HandleFunc("DELETE /v1/admin/ci-grants/{id}", admin.authorized(roleAdmin, admin.handleDeleteCIGrant))
	mux.HandleFunc("POST /v1/admin/ci-grants/apply", admin.authorized(roleAdmin, admin.handleApplyCIGrants))
	registerUIRoutes(mux, admin)
}

// adminHandler ist ein Handler mit authentifiziertem Admin-Kontext; actor ist
// die KeyID-Form des Admins (für Audit-Events).
type adminHandler func(w http.ResponseWriter, r *http.Request, claims *auth.Claims, actor string)

// hasRole prüft, ob die Claims die Mindest-Rolle erfüllen; höhere Rollen
// schließen niedrigere ein. Eine leere Gruppen-Konfiguration vergibt die
// jeweilige Rolle an niemanden (fail-closed).
func (a *adminContext) hasRole(claims *auth.Claims, minRole string) bool {
	inGroup := func(group string) bool {
		return group != "" && slices.Contains(claims.Groups, group)
	}
	isAdmin := inGroup(a.adminGroup)
	isAuditor := isAdmin || inGroup(a.auditorGroup)
	isReadOnly := isAuditor || inGroup(a.readonlyGroup)
	switch minRole {
	case roleAdmin:
		return isAdmin
	case roleAuditor:
		return isAuditor
	default:
		return isReadOnly
	}
}

// authorized prüft Bearer-Token, aktiven Benutzer und die Mindest-Rolle
// (aus den frischen Token-Claims, konsistent zum Sign-Endpoint).
func (a *adminContext) authorized(minRole string, next adminHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rawToken, ok := bearerToken(r)
		if !ok {
			http.Error(w, "authorization: bearer-token fehlt", http.StatusUnauthorized)
			return
		}
		claims, err := a.verifier.Verify(r.Context(), rawToken)
		if err != nil {
			a.logger.Info("admin: token abgelehnt", "error", err)
			http.Error(w, "id-token ungültig", http.StatusUnauthorized)
			return
		}
		if _, err := a.mapper.EnsureUser(r.Context(), claims); errors.Is(err, auth.ErrUserInactive) {
			http.Error(w, "benutzer ist deaktiviert", http.StatusForbidden)
			return
		} else if err != nil {
			a.logger.Error("admin: benutzer-mapping fehlgeschlagen", "subject", claims.Subject, "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if !a.hasRole(claims, minRole) {
			a.logger.Info("admin: zugriff verweigert", "subject", claims.Subject, "groups", claims.Groups, "min_role", minRole)
			http.Error(w, "keine berechtigung (rolle "+minRole+" erforderlich)", http.StatusForbidden)
			return
		}
		next(w, r, claims, ca.UserKeyID(claims.Subject, claims.Issuer))
	}
}

// writeJSON schreibt eine JSON-Antwort mit Statuscode.
func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// grantID parst die Grant-ID aus dem Pfad; false ⇒ 404 wurde geschrieben.
func grantID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "grant-id ungültig", http.StatusNotFound)
		return uuid.Nil, false
	}
	return id, true
}

func (a *adminContext) handleListGrants(w http.ResponseWriter, r *http.Request, _ *auth.Claims, _ string) {
	grants, err := a.store.ListGrantsDetailed(r.Context())
	if err != nil {
		a.logger.Error("admin: grants laden fehlgeschlagen", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	out := make([]grantJSON, 0, len(grants))
	for i := range grants {
		out = append(out, toGrantJSON(&grants[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *adminContext) handleGetGrant(w http.ResponseWriter, r *http.Request, _ *auth.Claims, _ string) {
	id, ok := grantID(w, r)
	if !ok {
		return
	}
	grant, err := a.store.GetGrantDetailed(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "grant nicht gefunden", http.StatusNotFound)
		return
	}
	if err != nil {
		a.logger.Error("admin: grant laden fehlgeschlagen", "id", id, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, toGrantJSON(grant))
}

func (a *adminContext) handleCreateGrant(w http.ResponseWriter, r *http.Request, claims *auth.Claims, actor string) {
	var req grantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "request-body ungültig", http.StatusBadRequest)
		return
	}
	if req.Group == "" {
		http.Error(w, "group fehlt", http.StatusBadRequest)
		return
	}
	if len(req.Principals) == 0 {
		http.Error(w, "principals fehlen", http.StatusBadRequest)
		return
	}
	if req.MaxValiditySeconds <= 0 {
		http.Error(w, "max_validity_seconds muss größer 0 sein", http.StatusBadRequest)
		return
	}
	issuer := req.Issuer
	if issuer == "" {
		issuer = claims.Issuer
	}
	group, err := a.ensureGroup(r.Context(), issuer, req.Group)
	if err != nil {
		a.logger.Error("admin: gruppe auflösen fehlgeschlagen", "group", req.Group, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	grant := &store.AccessGrant{
		GroupID:            group.ID,
		TagSelector:        req.TagSelector,
		Principals:         req.Principals,
		Sudo:               req.Sudo,
		MaxValiditySeconds: req.MaxValiditySeconds,
	}
	if grant.TagSelector == nil {
		grant.TagSelector = map[string]string{}
	}
	if err := a.store.CreateGrant(r.Context(), actor, grant); err != nil {
		a.logger.Error("admin: grant anlegen fehlgeschlagen", "group", req.Group, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, toGrantJSON(&store.GrantWithGroup{
		AccessGrant: *grant, GroupName: group.Name, GroupIssuer: group.Issuer,
	}))
}

func (a *adminContext) handleUpdateGrant(w http.ResponseWriter, r *http.Request, _ *auth.Claims, actor string) {
	id, ok := grantID(w, r)
	if !ok {
		return
	}
	var req grantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "request-body ungültig", http.StatusBadRequest)
		return
	}
	if len(req.Principals) == 0 {
		http.Error(w, "principals fehlen", http.StatusBadRequest)
		return
	}
	if req.MaxValiditySeconds <= 0 {
		http.Error(w, "max_validity_seconds muss größer 0 sein", http.StatusBadRequest)
		return
	}
	current, err := a.store.GetGrantDetailed(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "grant nicht gefunden", http.StatusNotFound)
		return
	}
	if err != nil {
		a.logger.Error("admin: grant laden fehlgeschlagen", "id", id, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	grant := current.AccessGrant
	if req.TagSelector != nil {
		grant.TagSelector = req.TagSelector
	}
	grant.Principals = req.Principals
	grant.Sudo = req.Sudo
	grant.MaxValiditySeconds = req.MaxValiditySeconds
	if err := a.store.UpdateGrant(r.Context(), actor, &grant); err != nil {
		a.logger.Error("admin: grant aktualisieren fehlgeschlagen", "id", id, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, toGrantJSON(&store.GrantWithGroup{
		AccessGrant: grant, GroupName: current.GroupName, GroupIssuer: current.GroupIssuer,
	}))
}

func (a *adminContext) handleDeleteGrant(w http.ResponseWriter, r *http.Request, _ *auth.Claims, actor string) {
	id, ok := grantID(w, r)
	if !ok {
		return
	}
	err := a.store.DeleteGrant(r.Context(), actor, id)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "grant nicht gefunden", http.StatusNotFound)
		return
	}
	if err != nil {
		a.logger.Error("admin: grant löschen fehlgeschlagen", "id", id, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *adminContext) handleApplyGrants(w http.ResponseWriter, r *http.Request, claims *auth.Claims, actor string) {
	var req applyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "request-body ungültig", http.StatusBadRequest)
		return
	}
	specs := make([]store.GrantSpec, 0, len(req.Grants))
	for _, g := range req.Grants {
		specs = append(specs, store.GrantSpec{
			Group:              g.Group,
			Issuer:             g.Issuer,
			TagSelector:        g.TagSelector,
			Principals:         g.Principals,
			Sudo:               g.Sudo,
			MaxValiditySeconds: g.MaxValiditySeconds,
		})
	}
	result, err := a.store.ApplyGrants(r.Context(), actor, claims.Issuer, specs)
	if errors.Is(err, store.ErrInvalidGrantSpec) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		a.logger.Error("admin: apply fehlgeschlagen", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// ensureGroup löst eine Gruppe per Issuer+Name auf und legt sie bei Bedarf an
// (der IdP-Sync verknüpft Mitglieder, sobald die Gruppe dort existiert).
func (a *adminContext) ensureGroup(ctx context.Context, issuer, name string) (*store.Group, error) {
	group, err := a.groups.GetGroupByName(ctx, issuer, name)
	if err == nil {
		return group, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	group = &store.Group{Issuer: issuer, Name: name}
	if err := a.groups.CreateGroup(ctx, group); err != nil {
		return nil, err
	}
	return group, nil
}
