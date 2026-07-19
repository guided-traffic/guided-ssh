package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/guided-traffic/guided-ssh/internal/auth"
	"github.com/guided-traffic/guided-ssh/internal/ca"
	"github.com/guided-traffic/guided-ssh/internal/store"
)

// TokenVerifier validiert rohe ID-Tokens (implementiert von *auth.Verifier;
// Tests nutzen einen Fake).
type TokenVerifier interface {
	Verify(ctx context.Context, rawToken string) (*auth.Claims, error)
}

// GrantSource liefert die Zugriffsregeln eines Benutzers (Phase 6;
// *store.Store erfüllt das Interface, Tests nutzen einen Fake).
type GrantSource interface {
	ListGrantsForUser(ctx context.Context, userID uuid.UUID) ([]store.AccessGrant, error)
}

// signUserRequest ist der Body von POST /v1/sign/user.
type signUserRequest struct {
	// PublicKey im authorized_keys-Format (z. B. "ssh-ed25519 AAAA…").
	PublicKey string `json:"public_key"`
	// ValiditySeconds ist die gewünschte Laufzeit; 0 ⇒ Server-Default.
	ValiditySeconds int64 `json:"validity_seconds,omitempty"`
}

// signUserResponse ist die Antwort: das signierte Zertifikat plus Metadaten.
type signUserResponse struct {
	Certificate string    `json:"certificate"`
	Serial      int64     `json:"serial"`
	KeyID       string    `json:"key_id"`
	Principals  []string  `json:"principals"`
	ValidAfter  time.Time `json:"valid_after"`
	ValidBefore time.Time `json:"valid_before"`
}

// defaultUserValidity ist die Standard-Laufzeit von Benutzer-Zertifikaten
// (Plan: ~16 h, Policy-Maximum greift zusätzlich).
const defaultUserValidity = 16 * time.Hour

// signBackdate datiert ValidAfter leicht zurück (Clock-Skew zu Hosts);
// bleibt unter dem Policy-Limit von 5 Minuten.
const signBackdate = time.Minute

// userExtensions sind die Standard-Extensions von Benutzer-Zertifikaten.
func userExtensions() map[string]string {
	return map[string]string{
		"permit-X11-forwarding":   "",
		"permit-agent-forwarding": "",
		"permit-port-forwarding":  "",
		"permit-pty":              "",
		"permit-user-rc":          "",
	}
}

// handleSignUser tauscht ein validiertes ID-Token gegen ein kurzlebiges
// SSH-Benutzerzertifikat: Token prüfen, Claims auf Benutzer/Gruppen mappen
// (inkl. Aktiv-Check), Grants auswerten (ohne Grant kein Zertifikat, Laufzeit
// gedeckelt), Policy-geprüft signieren, Audit transaktional.
//
// Die Zertifikats-Principals bleiben Identitäts-Principals (Username,
// E-Mail) — welche lokalen Benutzer sie auf einem Host erreichen, entscheidet
// der Host über AuthorizedPrincipalsCommand anhand der Grants (ADR-018).
func handleSignUser(certAuthority *ca.CA, verifier TokenVerifier, mapper *auth.Mapper, grants GrantSource, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rawToken, ok := bearerToken(r)
		if !ok {
			http.Error(w, "authorization: bearer-token fehlt", http.StatusUnauthorized)
			return
		}
		claims, err := verifier.Verify(r.Context(), rawToken)
		if err != nil {
			logger.Info("sign/user: token abgelehnt", "error", err)
			http.Error(w, "id-token ungültig", http.StatusUnauthorized)
			return
		}

		var req signUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "request-body ungültig", http.StatusBadRequest)
			return
		}
		publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
		if err != nil {
			http.Error(w, "public_key ungültig (authorized_keys-format erwartet)", http.StatusBadRequest)
			return
		}
		if _, isCert := publicKey.(*ssh.Certificate); isCert {
			http.Error(w, "public_key ist bereits ein zertifikat", http.StatusBadRequest)
			return
		}

		user, err := mapper.EnsureUser(r.Context(), claims)
		if errors.Is(err, auth.ErrUserInactive) {
			http.Error(w, "benutzer ist deaktiviert", http.StatusForbidden)
			return
		}
		if err != nil {
			logger.Error("sign/user: benutzer-mapping fehlgeschlagen", "subject", claims.Subject, "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		userGrants, err := grants.ListGrantsForUser(r.Context(), user.ID)
		if err != nil {
			logger.Error("sign/user: grants laden fehlgeschlagen", "subject", claims.Subject, "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if len(userGrants) == 0 {
			logger.Info("sign/user: keine grants", "subject", claims.Subject, "groups", claims.Groups)
			http.Error(w, "keine zugriffsregeln (grants) für diesen benutzer — zertifikat wird nicht ausgestellt", http.StatusForbidden)
			return
		}

		validity := defaultUserValidity
		if req.ValiditySeconds > 0 {
			validity = time.Duration(req.ValiditySeconds) * time.Second
		}
		// Grants sind additiv: es gilt die höchste erlaubte Laufzeit über alle
		// Grants des Benutzers; eine höhere Anfrage wird gekappt (ADR-018).
		if allowed := maxGrantValidity(userGrants); validity > allowed {
			validity = allowed
		}
		// Laufzeit zählt ab dem rückdatierten ValidAfter, damit die
		// Gesamtlaufzeit exakt der angeforderten entspricht (Policy-Maximum).
		validAfter := time.Now().Add(-signBackdate)
		certReq := ca.CertRequest{
			CertType:    store.CertTypeUser,
			PublicKey:   publicKey,
			KeyID:       ca.UserKeyID(claims.Subject, claims.Issuer),
			Principals:  claims.Principals(),
			ValidAfter:  validAfter,
			ValidBefore: validAfter.Add(validity),
			Extensions:  userExtensions(),
		}
		ref := ca.IssueRef{
			Actor:  certReq.KeyID,
			UserID: &user.ID,
			Context: map[string]any{
				"issuer": claims.Issuer,
				"email":  claims.Email,
				"groups": claims.Groups,
			},
		}
		cert, record, err := certAuthority.Issue(r.Context(), ca.RequesterUser, certReq, ref)
		var violation *ca.PolicyViolationError
		if errors.As(err, &violation) {
			http.Error(w, violation.Error(), http.StatusBadRequest)
			return
		}
		if err != nil {
			logger.Error("sign/user: ausstellung fehlgeschlagen", "key_id", certReq.KeyID, "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(signUserResponse{
			Certificate: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert))),
			Serial:      record.Serial,
			KeyID:       record.KeyID,
			Principals:  record.Principals,
			ValidAfter:  record.ValidAfter,
			ValidBefore: record.ValidBefore,
		})
	}
}

// maxGrantValidity liefert die höchste maximale Laufzeit über alle Grants
// (additive Semantik: jeder Grant berechtigt unabhängig bis zu seinem Maximum).
func maxGrantValidity(grants []store.AccessGrant) time.Duration {
	var allowed time.Duration
	for _, g := range grants {
		if v := g.MaxValidity(); v > allowed {
			allowed = v
		}
	}
	return allowed
}

// bearerToken extrahiert das Bearer-Token aus dem Authorization-Header.
func bearerToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return "", false
	}
	return token, true
}
