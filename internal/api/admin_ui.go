package api

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/guided-traffic/guided-ssh/internal/auth"
	"github.com/guided-traffic/guided-ssh/internal/store"
)

// UIStore is the set of store methods needed by the web UI (phase 8): read
// views, audit query/export, and the kill switch for service accounts
// (*store.Store satisfies it; tests use a fake).
type UIStore interface {
	ListHostsDetailed(ctx context.Context) ([]store.HostDetailed, error)
	ListUsersDetailed(ctx context.Context) ([]store.UserDetailed, error)
	ListGroups(ctx context.Context) ([]store.Group, error)
	ListServiceAccounts(ctx context.Context) ([]store.ServiceAccount, error)
	SetServiceAccountActive(ctx context.Context, actor string, id uuid.UUID, active bool) (*store.ServiceAccount, error)
	ListCertificates(ctx context.Context, limit int) ([]store.Certificate, error)
	ListAuditEvents(ctx context.Context, f store.AuditFilter) ([]store.AuditEvent, error)
	CountAuditEvents(ctx context.Context, f store.AuditFilter) (int64, error)

	// Enrollment token minting for the UI (phase C): create the record and
	// audit the event — the plaintext never enters the store.
	CreateEnrollmentToken(ctx context.Context, t *store.EnrollmentToken) error
	AppendAuditEvent(ctx context.Context, e *store.AuditEvent) error
}

// Limits of the audit queries: the UI's page size and the export's upper
// bound (protects server and browser from unbounded responses).
const (
	auditDefaultLimit = 50
	auditMaxLimit     = 500
	auditExportLimit  = 100_000
)

// registerUIRoutes attaches the web UI's read and audit endpoints to the
// mux; without a UIStore they stay disabled (tests of the rest of the
// admin API).
func registerUIRoutes(mux *http.ServeMux, admin *adminContext) {
	if admin.ui == nil {
		return
	}
	mux.HandleFunc("GET /v1/admin/hosts", admin.authorized(roleReadOnly, admin.handleListHosts))
	mux.HandleFunc("GET /v1/admin/users", admin.authorized(roleReadOnly, admin.handleListUsers))
	mux.HandleFunc("GET /v1/admin/groups", admin.authorized(roleReadOnly, admin.handleListGroups))
	mux.HandleFunc("GET /v1/admin/service-accounts", admin.authorized(roleReadOnly, admin.handleListServiceAccounts))
	mux.HandleFunc("PATCH /v1/admin/service-accounts/{id}", admin.authorized(roleAdmin, admin.handleUpdateServiceAccount))
	mux.HandleFunc("GET /v1/admin/certificates", admin.authorized(roleReadOnly, admin.handleListCertificates))
	mux.HandleFunc("GET /v1/admin/audit", admin.authorized(roleAuditor, admin.handleListAudit))
	mux.HandleFunc("GET /v1/admin/audit/export", admin.authorized(roleAuditor, admin.handleExportAudit))
	mux.HandleFunc("POST /v1/admin/enroll-tokens", admin.authorized(roleAdmin, admin.handleCreateEnrollToken))
}

// hostJSON is the API representation of a host for the UI.
type hostJSON struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Tags            map[string]string `json:"tags"`
	EnrolledAt      *time.Time        `json:"enrolled_at,omitempty"`
	LastSeenAt      *time.Time        `json:"last_seen_at,omitempty"`
	CertValidBefore *time.Time        `json:"cert_valid_before,omitempty"`
	CreatedAt       time.Time         `json:"created_at"`
}

func (a *adminContext) handleListHosts(w http.ResponseWriter, r *http.Request, _ *auth.Claims, _ string) {
	hosts, err := a.ui.ListHostsDetailed(r.Context())
	if err != nil {
		a.logger.Error("admin: loading hosts failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	out := make([]hostJSON, 0, len(hosts))
	for i := range hosts {
		h := &hosts[i]
		out = append(out, hostJSON{
			ID: h.ID.String(), Name: h.Name, Tags: h.Tags,
			EnrolledAt: h.EnrolledAt, LastSeenAt: h.LastSeenAt,
			CertValidBefore: h.CertValidBefore, CreatedAt: h.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// userJSON is the API representation of a user for the UI.
type userJSON struct {
	ID        string    `json:"id"`
	Issuer    string    `json:"issuer"`
	Subject   string    `json:"subject"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Active    bool      `json:"active"`
	Groups    []string  `json:"groups"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (a *adminContext) handleListUsers(w http.ResponseWriter, r *http.Request, _ *auth.Claims, _ string) {
	users, err := a.ui.ListUsersDetailed(r.Context())
	if err != nil {
		a.logger.Error("admin: loading users failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	out := make([]userJSON, 0, len(users))
	for i := range users {
		u := &users[i]
		out = append(out, userJSON{
			ID: u.ID.String(), Issuer: u.Issuer, Subject: u.Subject,
			Username: u.Username, Email: u.Email, Active: u.Active,
			Groups: u.Groups, CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// groupJSON is the API representation of an IdP group for the UI.
type groupJSON struct {
	ID        string    `json:"id"`
	Issuer    string    `json:"issuer"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

func (a *adminContext) handleListGroups(w http.ResponseWriter, r *http.Request, _ *auth.Claims, _ string) {
	groups, err := a.ui.ListGroups(r.Context())
	if err != nil {
		a.logger.Error("admin: loading groups failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	out := make([]groupJSON, 0, len(groups))
	for i := range groups {
		g := &groups[i]
		out = append(out, groupJSON{ID: g.ID.String(), Issuer: g.Issuer, Name: g.Name, CreatedAt: g.CreatedAt})
	}
	writeJSON(w, http.StatusOK, out)
}

// serviceAccountJSON is the API representation of a machine identity.
type serviceAccountJSON struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Kind         string            `json:"kind"`
	Issuer       string            `json:"issuer"`
	ClaimMatcher map[string]string `json:"claim_matcher"`
	Active       bool              `json:"active"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

func toServiceAccountJSON(sa *store.ServiceAccount) serviceAccountJSON {
	return serviceAccountJSON{
		ID: sa.ID.String(), Name: sa.Name, Kind: sa.Kind, Issuer: sa.Issuer,
		ClaimMatcher: sa.ClaimMatcher, Active: sa.Active,
		CreatedAt: sa.CreatedAt, UpdatedAt: sa.UpdatedAt,
	}
}

func (a *adminContext) handleListServiceAccounts(w http.ResponseWriter, r *http.Request, _ *auth.Claims, _ string) {
	accounts, err := a.ui.ListServiceAccounts(r.Context())
	if err != nil {
		a.logger.Error("admin: loading service accounts failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	out := make([]serviceAccountJSON, 0, len(accounts))
	for i := range accounts {
		out = append(out, toServiceAccountJSON(&accounts[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *adminContext) handleUpdateServiceAccount(w http.ResponseWriter, r *http.Request, _ *auth.Claims, actor string) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "service account id invalid", http.StatusNotFound)
		return
	}
	var req struct {
		Active *bool `json:"active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Active == nil {
		http.Error(w, "request body invalid (active required)", http.StatusBadRequest)
		return
	}
	updated, err := a.ui.SetServiceAccountActive(r.Context(), actor, id, *req.Active)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "service account not found", http.StatusNotFound)
		return
	}
	if err != nil {
		a.logger.Error("admin: updating service account failed", "id", id, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, toServiceAccountJSON(updated))
}

// Limits for the TTL of an enrollment token minted via the UI. The default
// is deliberately shorter than the CLI's 24h default: UI tokens are created
// right before use, so the leak window stays small.
const (
	enrollTokenDefaultTTL = time.Hour
	enrollTokenMinTTL     = time.Minute
	enrollTokenMaxTTL     = 24 * time.Hour
)

// createEnrollTokenRequest is the body of POST /v1/admin/enroll-tokens.
// All fields are optional.
type createEnrollTokenRequest struct {
	// Hostname binds the token to exactly this host (empty ⇒ unbound).
	Hostname string            `json:"hostname,omitempty"`
	Tags     map[string]string `json:"tags,omitempty"`
	// TTLSeconds is the validity duration; 0 ⇒ enrollTokenDefaultTTL.
	TTLSeconds int64 `json:"ttl_seconds,omitempty"`
	// SessionAudit controls only the --session-audit flag in
	// install_command; it is not stored with the token.
	SessionAudit bool `json:"session_audit,omitempty"`
}

// createEnrollTokenResponse contains the plaintext token — one-time only,
// it is neither logged nor stored.
type createEnrollTokenResponse struct {
	Token          string    `json:"token"`
	ExpiresAt      time.Time `json:"expires_at"`
	InstallCommand string    `json:"install_command"`
}

// handleCreateEnrollToken mints an enrollment token for the one-command
// host install and returns the ready-to-use install command. Gated like
// the other rollout endpoints: without a pin, binaries, agent, or public
// URL there is no token (a token that leads to no working install helps
// nobody).
func (a *adminContext) handleCreateEnrollToken(w http.ResponseWriter, r *http.Request, _ *auth.Claims, actor string) {
	if !a.rollout.allow(w, r) {
		return
	}
	var req createEnrollTokenRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "request body invalid", http.StatusBadRequest)
		return
	}
	ttl := enrollTokenDefaultTTL
	if req.TTLSeconds != 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
		if ttl < enrollTokenMinTTL || ttl > enrollTokenMaxTTL {
			http.Error(w, "ttl_seconds must be between 60 and 86400", http.StatusBadRequest)
			return
		}
	}

	token, record, err := store.NewEnrollmentToken(req.Hostname, req.Tags, ttl)
	if err != nil {
		a.logger.Error("admin: creating enrollment token failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if err := a.ui.CreateEnrollmentToken(r.Context(), record); err != nil {
		a.logger.Error("admin: saving enrollment token failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Audit without token and without hash (the plaintext leaves this
	// handler only in the response). If writing fails, the token already
	// exists — withholding it would only leave an unusable token in the
	// database; the gap is loudly logged instead.
	payload, err := json.Marshal(map[string]any{
		"hostname": req.Hostname, "tags": record.Tags,
		"ttl_seconds": int64(ttl / time.Second), "expires_at": record.ExpiresAt,
	})
	if err == nil {
		err = a.ui.AppendAuditEvent(r.Context(), &store.AuditEvent{
			EventType: store.EventEnrollTokenCreated, Actor: actor, Payload: payload,
		})
	}
	if err != nil {
		a.logger.Error("admin: audit event of enrollment token failed",
			"actor", actor, "hostname", req.Hostname, "error", err)
	}

	writeJSON(w, http.StatusCreated, createEnrollTokenResponse{
		Token:          token,
		ExpiresAt:      record.ExpiresAt,
		InstallCommand: installCommand(a.publicBaseURL, token, req.SessionAudit),
	})
}

// installCommand builds the command the operator runs on the host. The
// frontend appends the --arch variant from the manifest; without it, the
// script determines the architecture itself.
func installCommand(baseURL, token string, sessionAudit bool) string {
	cmd := "curl -fsSL " + strings.TrimRight(baseURL, "/") + "/install.sh | sudo sh -s -- --token " + token
	if sessionAudit {
		cmd += " --session-audit"
	}
	return cmd
}

// certificateJSON is the API representation of an issued certificate
// (metadata only, never key material).
type certificateJSON struct {
	ID            string          `json:"id"`
	Serial        int64           `json:"serial"`
	KeyID         string          `json:"key_id"`
	CertType      string          `json:"cert_type"`
	Principals    []string        `json:"principals"`
	ValidAfter    time.Time       `json:"valid_after"`
	ValidBefore   time.Time       `json:"valid_before"`
	IssuerContext json.RawMessage `json:"issuer_context,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
}

func (a *adminContext) handleListCertificates(w http.ResponseWriter, r *http.Request, _ *auth.Claims, _ string) {
	limit := parsePositiveInt(r.URL.Query().Get("limit"), auditDefaultLimit, auditMaxLimit)
	certs, err := a.ui.ListCertificates(r.Context(), limit)
	if err != nil {
		a.logger.Error("admin: loading certificates failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	out := make([]certificateJSON, 0, len(certs))
	for i := range certs {
		c := &certs[i]
		out = append(out, certificateJSON{
			ID: c.ID.String(), Serial: c.Serial, KeyID: c.KeyID, CertType: c.CertType,
			Principals: c.Principals, ValidAfter: c.ValidAfter, ValidBefore: c.ValidBefore,
			IssuerContext: c.IssuerContext, CreatedAt: c.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// auditEventJSON is the API representation of an audit event.
type auditEventJSON struct {
	ID         int64           `json:"id"`
	OccurredAt time.Time       `json:"occurred_at"`
	EventType  string          `json:"event_type"`
	Actor      string          `json:"actor"`
	Payload    json.RawMessage `json:"payload"`
}

// auditListJSON is the response of the audit query, including the total
// count (for the UI's pagination).
type auditListJSON struct {
	Events []auditEventJSON `json:"events"`
	Total  int64            `json:"total"`
}

// parseAuditFilter builds the store filter from the query parameters;
// invalid timestamps return an error (RFC 3339 format).
func parseAuditFilter(r *http.Request) (store.AuditFilter, error) {
	q := r.URL.Query()
	f := store.AuditFilter{
		EventType: q.Get("event_type"),
		Actor:     q.Get("actor"),
		Search:    q.Get("q"),
		Limit:     parsePositiveInt(q.Get("limit"), auditDefaultLimit, auditMaxLimit),
		Offset:    parsePositiveInt(q.Get("offset"), 0, 1<<30),
	}
	for param, dst := range map[string]*time.Time{"since": &f.Since, "until": &f.Until} {
		raw := q.Get(param)
		if raw == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return f, errors.New(param + " invalid (RFC 3339 expected)")
		}
		*dst = t
	}
	return f, nil
}

// parsePositiveInt parses a non-negative number with a default and an upper bound.
func parsePositiveInt(raw string, def, maxValue int) int {
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return def
	}
	return min(n, maxValue)
}

func toAuditEventJSON(e *store.AuditEvent) auditEventJSON {
	return auditEventJSON{
		ID: e.ID, OccurredAt: e.OccurredAt, EventType: e.EventType,
		Actor: e.Actor, Payload: e.Payload,
	}
}

func (a *adminContext) handleListAudit(w http.ResponseWriter, r *http.Request, _ *auth.Claims, _ string) {
	filter, err := parseAuditFilter(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	events, err := a.ui.ListAuditEvents(r.Context(), filter)
	if err != nil {
		a.logger.Error("admin: loading audit events failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	total, err := a.ui.CountAuditEvents(r.Context(), filter)
	if err != nil {
		a.logger.Error("admin: counting audit events failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	out := auditListJSON{Events: make([]auditEventJSON, 0, len(events)), Total: total}
	for i := range events {
		out.Events = append(out.Events, toAuditEventJSON(&events[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

// handleExportAudit returns the filtered events as a download; format=csv
// or json (default). The export is capped at auditExportLimit rows.
func (a *adminContext) handleExportAudit(w http.ResponseWriter, r *http.Request, _ *auth.Claims, _ string) {
	filter, err := parseAuditFilter(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	filter.Limit = auditExportLimit
	filter.Offset = 0
	events, err := a.ui.ListAuditEvents(r.Context(), filter)
	if err != nil {
		a.logger.Error("admin: audit export failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if r.URL.Query().Get("format") == "csv" {
		writeAuditCSV(w, events)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="audit-export.json"`)
	out := make([]auditEventJSON, 0, len(events))
	for i := range events {
		out = append(out, toAuditEventJSON(&events[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

// writeAuditCSV writes the events as CSV (payload as a JSON column).
func writeAuditCSV(w http.ResponseWriter, events []store.AuditEvent) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="audit-export.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"id", "occurred_at", "event_type", "actor", "payload"})
	for i := range events {
		e := &events[i]
		_ = cw.Write([]string{
			strconv.FormatInt(e.ID, 10),
			e.OccurredAt.Format(time.RFC3339),
			e.EventType,
			e.Actor,
			string(e.Payload),
		})
	}
	cw.Flush()
}
