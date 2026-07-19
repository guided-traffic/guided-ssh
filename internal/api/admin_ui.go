package api

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/guided-traffic/guided-ssh/internal/auth"
	"github.com/guided-traffic/guided-ssh/internal/store"
)

// UIStore sind die von der Web-UI benötigten Store-Methoden (Phase 8):
// Read-Ansichten, Audit-Abfrage/-Export und der Not-Aus für Service-Accounts
// (*store.Store erfüllt sie; Tests nutzen einen Fake).
type UIStore interface {
	ListHostsDetailed(ctx context.Context) ([]store.HostDetailed, error)
	ListUsersDetailed(ctx context.Context) ([]store.UserDetailed, error)
	ListGroups(ctx context.Context) ([]store.Group, error)
	ListServiceAccounts(ctx context.Context) ([]store.ServiceAccount, error)
	SetServiceAccountActive(ctx context.Context, actor string, id uuid.UUID, active bool) (*store.ServiceAccount, error)
	ListCertificates(ctx context.Context, limit int) ([]store.Certificate, error)
	ListAuditEvents(ctx context.Context, f store.AuditFilter) ([]store.AuditEvent, error)
	CountAuditEvents(ctx context.Context, f store.AuditFilter) (int64, error)
}

// Grenzen der Audit-Abfragen: Seitengröße der UI und Obergrenze des Exports
// (schützt Server und Browser vor unbeschränkten Antworten).
const (
	auditDefaultLimit = 50
	auditMaxLimit     = 500
	auditExportLimit  = 100_000
)

// registerUIRoutes hängt die Read- und Audit-Endpunkte der Web-UI an den Mux;
// ohne UIStore bleiben sie deaktiviert (Tests der übrigen Admin-API).
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
}

// hostJSON ist die API-Repräsentation eines Hosts für die UI.
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
		a.logger.Error("admin: hosts laden fehlgeschlagen", "error", err)
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

// userJSON ist die API-Repräsentation eines Benutzers für die UI.
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
		a.logger.Error("admin: benutzer laden fehlgeschlagen", "error", err)
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

// groupJSON ist die API-Repräsentation einer IdP-Gruppe für die UI.
type groupJSON struct {
	ID        string    `json:"id"`
	Issuer    string    `json:"issuer"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

func (a *adminContext) handleListGroups(w http.ResponseWriter, r *http.Request, _ *auth.Claims, _ string) {
	groups, err := a.ui.ListGroups(r.Context())
	if err != nil {
		a.logger.Error("admin: gruppen laden fehlgeschlagen", "error", err)
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

// serviceAccountJSON ist die API-Repräsentation einer maschinellen Identität.
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
		a.logger.Error("admin: service-accounts laden fehlgeschlagen", "error", err)
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
		http.Error(w, "service-account-id ungültig", http.StatusNotFound)
		return
	}
	var req struct {
		Active *bool `json:"active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Active == nil {
		http.Error(w, "request-body ungültig (active erforderlich)", http.StatusBadRequest)
		return
	}
	updated, err := a.ui.SetServiceAccountActive(r.Context(), actor, id, *req.Active)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "service-account nicht gefunden", http.StatusNotFound)
		return
	}
	if err != nil {
		a.logger.Error("admin: service-account aktualisieren fehlgeschlagen", "id", id, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, toServiceAccountJSON(updated))
}

// certificateJSON ist die API-Repräsentation eines ausgestellten Zertifikats
// (nur Metadaten, nie Schlüsselmaterial).
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
		a.logger.Error("admin: zertifikate laden fehlgeschlagen", "error", err)
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

// auditEventJSON ist die API-Repräsentation eines Audit-Events.
type auditEventJSON struct {
	ID         int64           `json:"id"`
	OccurredAt time.Time       `json:"occurred_at"`
	EventType  string          `json:"event_type"`
	Actor      string          `json:"actor"`
	Payload    json.RawMessage `json:"payload"`
}

// auditListJSON ist die Antwort der Audit-Abfrage inklusive Gesamtzahl
// (für die Pagination der UI).
type auditListJSON struct {
	Events []auditEventJSON `json:"events"`
	Total  int64            `json:"total"`
}

// parseAuditFilter baut den Store-Filter aus den Query-Parametern; ungültige
// Zeitstempel liefern einen Fehler (Format RFC 3339).
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
			return f, errors.New(param + " ungültig (RFC 3339 erwartet)")
		}
		*dst = t
	}
	return f, nil
}

// parsePositiveInt parst eine nicht-negative Zahl mit Default und Obergrenze.
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
		a.logger.Error("admin: audit-events laden fehlgeschlagen", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	total, err := a.ui.CountAuditEvents(r.Context(), filter)
	if err != nil {
		a.logger.Error("admin: audit-events zählen fehlgeschlagen", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	out := auditListJSON{Events: make([]auditEventJSON, 0, len(events)), Total: total}
	for i := range events {
		out.Events = append(out.Events, toAuditEventJSON(&events[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

// handleExportAudit liefert die gefilterten Events als Download; format=csv
// oder json (Default). Der Export ist auf auditExportLimit Zeilen begrenzt.
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
		a.logger.Error("admin: audit-export fehlgeschlagen", "error", err)
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

// writeAuditCSV schreibt die Events als CSV (Payload als JSON-Spalte).
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
