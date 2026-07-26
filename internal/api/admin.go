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

// AdminStore is the set of store methods needed by the admin API
// (*store.Store satisfies it; tests use a fake).
type AdminStore interface {
	ListGrantsDetailed(ctx context.Context) ([]store.GrantWithGroup, error)
	GetGrantDetailed(ctx context.Context, id uuid.UUID) (*store.GrantWithGroup, error)
	CreateGrant(ctx context.Context, actor string, g *store.AccessGrant) error
	UpdateGrant(ctx context.Context, actor string, g *store.AccessGrant) error
	DeleteGrant(ctx context.Context, actor string, id uuid.UUID) error
	ApplyGrants(ctx context.Context, actor, defaultIssuer string, specs []store.GrantSpec) (*store.ApplyResult, error)

	// CI grants (phase 7).
	ListCIGrants(ctx context.Context) ([]store.CIGrant, error)
	GetCIGrant(ctx context.Context, id uuid.UUID) (*store.CIGrant, error)
	CreateCIGrant(ctx context.Context, actor string, g *store.CIGrant) error
	UpdateCIGrant(ctx context.Context, actor string, g *store.CIGrant) error
	DeleteCIGrant(ctx context.Context, actor string, id uuid.UUID) error
	ApplyCIGrants(ctx context.Context, actor string, specs []store.CIGrantSpec) (*store.ApplyResult, error)
}

// grantJSON is the API representation of an access grant; the group is
// addressed by name + issuer (UUIDs stay internal).
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

// grantRequest is the body of POST/PUT on grants.
type grantRequest struct {
	// Group is the group name in the IdP (required on POST).
	Group string `json:"group,omitempty"`
	// Issuer of the group; empty ⇒ issuer of the admin token.
	Issuer      string            `json:"issuer,omitempty"`
	TagSelector map[string]string `json:"tag_selector,omitempty"`
	Principals  []string          `json:"principals"`
	Sudo        bool              `json:"sudo,omitempty"`
	// MaxValiditySeconds is the maximum certificate lifetime (required, > 0).
	MaxValiditySeconds int64 `json:"max_validity_seconds"`
}

// applyRequest is the body of POST /v1/admin/grants/apply.
type applyRequest struct {
	Grants []grantRequest `json:"grants"`
}

// toGrantJSON maps a store grant onto the API representation.
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

// Roles of the admin API (phase 8): admin includes auditor, auditor
// includes readonly. Each role is bound to an IdP group.
const (
	roleAdmin    = "admin"
	roleAuditor  = "auditor"
	roleReadOnly = "readonly"
)

// adminContext bundles the dependencies of the admin handlers.
type adminContext struct {
	store         AdminStore
	ui            UIStore
	groups        auth.Store
	verifier      TokenVerifier
	uiAuth        *UIAuthConfig
	mapper        *auth.Mapper
	adminGroup    string
	auditorGroup  string
	readonlyGroup string
	logger        *slog.Logger
	// rollout gates token minting the same way as the public rollout
	// routes; publicBaseURL is the base of install_command
	// (the gate guarantees it is set).
	rollout       rolloutGate
	publicBaseURL string
}

// registerAdminRoutes attaches the admin API to the mux. Without OIDC or
// without a single configured role group, the entire admin path responds
// with 503 (fail-closed, but diagnosable).
func registerAdminRoutes(mux *http.ServeMux, deps Deps) {
	anyRole := deps.AdminGroup != "" || deps.AuditorGroup != "" || deps.ReadOnlyGroup != ""
	if deps.Admin == nil || deps.Verifier == nil || deps.Store == nil || !anyRole {
		mux.HandleFunc("/v1/admin/", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "admin api not configured (oidc and role group required)", http.StatusServiceUnavailable)
		})
		return
	}
	admin := &adminContext{
		store:         deps.Admin,
		ui:            deps.UI,
		groups:        deps.Store,
		verifier:      deps.Verifier,
		uiAuth:        deps.UIAuth,
		mapper:        auth.NewMapper(deps.Store),
		adminGroup:    deps.AdminGroup,
		auditorGroup:  deps.AuditorGroup,
		readonlyGroup: deps.ReadOnlyGroup,
		logger:        deps.Logger,
		rollout:       newRolloutGate(deps),
		publicBaseURL: deps.PublicBaseURL,
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

// adminHandler is a handler with an authenticated admin context; actor is
// the KeyID form of the admin (for audit events).
type adminHandler func(w http.ResponseWriter, r *http.Request, claims *auth.Claims, actor string)

// hasRole checks whether the claims satisfy the minimum role; higher roles
// include lower ones. An empty group configuration grants the respective
// role to nobody (fail-closed).
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

// authorized checks authentication (bearer token or UI session), active
// user, and the minimum role (from the login's claims, consistent with the
// sign endpoint).
func (a *adminContext) authorized(minRole string, next adminHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := a.authenticate(w, r)
		if !ok {
			return
		}
		if _, err := a.mapper.EnsureUser(r.Context(), claims); errors.Is(err, auth.ErrUserInactive) {
			http.Error(w, "user is disabled", http.StatusForbidden)
			return
		} else if err != nil {
			a.logger.Error("admin: user mapping failed", "subject", claims.Subject, "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if !a.hasRole(claims, minRole) {
			a.logger.Info("admin: access denied", "subject", claims.Subject, "groups", claims.Groups, "min_role", minRole)
			http.Error(w, "not authorized (role "+minRole+" required)", http.StatusForbidden)
			return
		}
		next(w, r, claims, ca.UserKeyID(claims.Subject, claims.Issuer))
	}
}

// authenticate determines the caller's claims: bearer token (CLI, service
// accounts) or the web UI's session cookie. Cookie requests must
// additionally carry the X-Requested-With header — a custom header that
// cross-site forms cannot set (CSRF protection in addition to
// SameSite=Lax). false ⇒ an error response was written.
func (a *adminContext) authenticate(w http.ResponseWriter, r *http.Request) (*auth.Claims, bool) {
	if rawToken, ok := bearerToken(r); ok {
		claims, err := a.verifier.Verify(r.Context(), rawToken)
		if err != nil {
			a.logger.Info("admin: token rejected", "error", err)
			http.Error(w, "id token invalid", http.StatusUnauthorized)
			return nil, false
		}
		return claims, true
	}
	if a.uiAuth != nil {
		if claims := a.uiAuth.sessionFromRequest(r); claims != nil {
			if r.Header.Get("X-Requested-With") == "" {
				a.logger.Info("admin: session request without x-requested-with rejected", "path", r.URL.Path)
				http.Error(w, "x-requested-with header missing", http.StatusForbidden)
				return nil, false
			}
			return claims, true
		}
	}
	http.Error(w, "authorization missing (bearer token or ui session)", http.StatusUnauthorized)
	return nil, false
}

// writeJSON writes a JSON response with a status code.
func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// grantID parses the grant ID from the path; false ⇒ 404 was written.
func grantID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "grant id invalid", http.StatusNotFound)
		return uuid.Nil, false
	}
	return id, true
}

func (a *adminContext) handleListGrants(w http.ResponseWriter, r *http.Request, _ *auth.Claims, _ string) {
	grants, err := a.store.ListGrantsDetailed(r.Context())
	if err != nil {
		a.logger.Error("admin: loading grants failed", "error", err)
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
		http.Error(w, "grant not found", http.StatusNotFound)
		return
	}
	if err != nil {
		a.logger.Error("admin: loading grant failed", "id", id, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, toGrantJSON(grant))
}

func (a *adminContext) handleCreateGrant(w http.ResponseWriter, r *http.Request, claims *auth.Claims, actor string) {
	var req grantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "request body invalid", http.StatusBadRequest)
		return
	}
	if req.Group == "" {
		http.Error(w, "group missing", http.StatusBadRequest)
		return
	}
	if len(req.Principals) == 0 {
		http.Error(w, "principals missing", http.StatusBadRequest)
		return
	}
	if req.MaxValiditySeconds <= 0 {
		http.Error(w, "max_validity_seconds must be greater than 0", http.StatusBadRequest)
		return
	}
	issuer := req.Issuer
	if issuer == "" {
		issuer = claims.Issuer
	}
	group, err := a.ensureGroup(r.Context(), issuer, req.Group)
	if err != nil {
		a.logger.Error("admin: resolving group failed", "group", req.Group, "error", err)
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
		a.logger.Error("admin: creating grant failed", "group", req.Group, "error", err)
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
		http.Error(w, "request body invalid", http.StatusBadRequest)
		return
	}
	if len(req.Principals) == 0 {
		http.Error(w, "principals missing", http.StatusBadRequest)
		return
	}
	if req.MaxValiditySeconds <= 0 {
		http.Error(w, "max_validity_seconds must be greater than 0", http.StatusBadRequest)
		return
	}
	current, err := a.store.GetGrantDetailed(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "grant not found", http.StatusNotFound)
		return
	}
	if err != nil {
		a.logger.Error("admin: loading grant failed", "id", id, "error", err)
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
		a.logger.Error("admin: updating grant failed", "id", id, "error", err)
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
		http.Error(w, "grant not found", http.StatusNotFound)
		return
	}
	if err != nil {
		a.logger.Error("admin: deleting grant failed", "id", id, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *adminContext) handleApplyGrants(w http.ResponseWriter, r *http.Request, claims *auth.Claims, actor string) {
	var req applyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "request body invalid", http.StatusBadRequest)
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
		a.logger.Error("admin: apply failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// ensureGroup resolves a group by issuer+name and creates it if needed
// (the IdP sync links members as soon as the group exists there).
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
