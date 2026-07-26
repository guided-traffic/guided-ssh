package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/guided-traffic/guided-ssh/internal/pintls"
)

// Pin-Quellen des Host-Rollouts, in absteigender Präzedenz.
const (
	// PinSourceStatic: Operator liefert den Pin per GSSH_PUBLIC_PIN selbst;
	// Rotation liegt damit in Operator-Hand (kein Dial, kein Refresh).
	PinSourceStatic = "static"
	// PinSourceFile: Leaf-Zertifikat aus einer PEM-Datei (K8s-TLS-Secret als
	// Volume, bind-gemountetes fullchain.pem).
	PinSourceFile = "file"
	// PinSourceDial: Der Server wählt seine eigene externe Public-URL an und
	// liest das Leaf-Zertifikat — exakt der Wert, den ein Host beim Enrollment
	// sieht. Default-Quelle.
	PinSourceDial = "dial"
)

// DefaultPinRefresh ist das Standard-Intervall des Pin-Selbst-Dials.
const DefaultPinRefresh = 5 * time.Minute

// pinDialTimeout begrenzt einen einzelnen Selbst-Dial; ein hängender
// Reverse-Proxy darf das Ausliefern von install.sh nicht blockieren.
const pinDialTimeout = 5 * time.Second

// pinDialBackoff ist der Mindestabstand zweier Selbst-Dials, solange noch nie
// ein Pin gelesen wurde. Ohne ihn triggerte jeder Request auf die
// unauthentifizierten Rollout-Routen einen eigenen Outbound-Handshake (bis zu
// pinDialTimeout Wartezeit je Request). Kurz genug, dass das Gate wenige
// Sekunden nach dem ersten erfolgreichen Ingress-Routing aufgeht.
const pinDialBackoff = 10 * time.Second

// Grobe Kategorien des letzten Pin-Fehlers. Bewusst nur Kategorien: sie landen
// im unauthentifizierten Manifest, während der Volltext (Container-Pfade,
// Dial-Details) nur ins Server-Log geht.
const (
	// PinErrNoPublicURL: keine bzw. keine https-Public-URL konfiguriert.
	PinErrNoPublicURL = "no_public_url"
	// PinErrChainUntrusted: TLS-Handshake stand, aber die Kette ist nicht
	// vertrauenswürdig (kein Insecure-Fallback, siehe dialPin).
	PinErrChainUntrusted = "chain_untrusted"
	// PinErrDialFailed: Verbindung kam nicht zustande (DNS, Timeout, Reset).
	PinErrDialFailed = "dial_failed"
	// PinErrCertFileUnreadable: Pin-Zertifikatsdatei fehlt, ist unlesbar oder
	// enthält keinen Leaf.
	PinErrCertFileUnreadable = "cert_file_unreadable"
)

// PinProviderConfig konfiguriert die Pin-Ermittlung. Präzedenz: StaticPin vor
// CertFile vor Selbst-Dial. Alle Quellen sind fail-closed — ohne Pin bleibt
// das Rollout-Gate zu, es gibt keinen ungepinnten Fallback.
type PinProviderConfig struct {
	// StaticPin ist der Base64-SPKI-SHA-256-Pin aus GSSH_PUBLIC_PIN. Der
	// Aufrufer validiert ihn beim Start (pintls.DecodePin, fail-fast).
	StaticPin string
	// CertFile ist der Pfad zu einem PEM-Zertifikat (GSSH_PUBLIC_PIN_CERT_FILE);
	// der erste CERTIFICATE-Block gilt als Leaf (cert-manager-Konvention).
	CertFile string
	// DialURL ist die externe Public-URL für den Selbst-Dial
	// (GSSH_PUBLIC_URL, Fallback GSSH_UI_BASE_URL).
	DialURL string
	// Refresh ist das Intervall des Selbst-Dials; 0 ⇒ DefaultPinRefresh.
	Refresh time.Duration
}

// PinStatus ist der aktuelle Pin-Zustand. Pin leer bedeutet: kein Pin
// ermittelbar ⇒ Gate zu. Source ist nur bei vorhandenem Pin gesetzt.
type PinStatus struct {
	Pin     string // leer = kein Pin
	Source  string // "static" | "file" | "dial" | ""
	Err     string // letzter Fehler im Volltext, nur fürs Log
	ErrCode string // grobe Kategorie des letzten Fehlers, fürs Manifest
}

// PinProvider ermittelt den SPKI-Pin des öffentlichen TLS-Endpunkts, den die
// Hosts beim Enrollment sehen. Die aktive Quelle steht beim Bau fest.
type PinProvider struct {
	cfg    PinProviderConfig
	source string
	logger *slog.Logger

	// dialRoots ersetzt in Tests die System-Roots. nil ⇒ System-Roots; die
	// Kettenprüfung ist in beiden Fällen aktiv (Regel 1: kein
	// InsecureSkipVerify-Codepfad).
	dialRoots *x509.CertPool

	// dialMu serialisiert die Selbst-Dials: parallele Aufrufer warten hier und
	// übernehmen danach das Ergebnis des ersten (Singleflight), statt jeder
	// einen eigenen Handshake zu fahren.
	dialMu sync.Mutex

	mu      sync.Mutex
	pin     string    // letzter erfolgreich gedialter Pin
	checked time.Time // letzter Dial-Versuch (Erfolg wie Fehlschlag)
	err     string
	errCode string
	backoff time.Duration // Test-Hook; 0 ⇒ pinDialBackoff
}

// NewPinProvider wählt die Quelle nach Präzedenz und protokolliert sie. Sind
// mehrere Quellen gesetzt, gewinnt die höchste — die übrigen werden mit
// Warnung ignoriert.
func NewPinProvider(cfg PinProviderConfig, logger *slog.Logger) *PinProvider {
	p := &PinProvider{cfg: cfg, logger: logger}
	switch {
	case cfg.StaticPin != "":
		p.source = PinSourceStatic
		if cfg.CertFile != "" || cfg.DialURL != "" {
			logger.Warn("mehrere pin-quellen gesetzt — statischer pin gewinnt",
				"cert_file", cfg.CertFile, "dial_url", cfg.DialURL)
		}
	case cfg.CertFile != "":
		p.source = PinSourceFile
		if cfg.DialURL != "" {
			logger.Warn("mehrere pin-quellen gesetzt — zertifikatsdatei gewinnt", "dial_url", cfg.DialURL)
		}
	default:
		p.source = PinSourceDial
	}
	logger.Info("pin-quelle aktiv", "source", p.source)
	return p
}

// Source liefert die aktive Pin-Quelle (unabhängig davon, ob sie gerade einen
// Pin liefert).
func (p *PinProvider) Source() string { return p.source }

// Status liefert den aktuellen Pin. Die Datei-Quelle wird bei jedem Aufruf
// frisch gelesen (bewusst ungecacht: der Parse kostet Mikrosekunden, dafür
// wirkt eine Secret-Rotation sofort nach dem Kubelet-Sync des Mounts); die
// Dial-Quelle zieht bei abgelaufenem Intervall synchron nach (Lazy-Refresh).
func (p *PinProvider) Status(ctx context.Context) PinStatus {
	switch p.source {
	case PinSourceStatic:
		return PinStatus{Pin: p.cfg.StaticPin, Source: PinSourceStatic}
	case PinSourceFile:
		pin, err := pinFromCertFile(p.cfg.CertFile)
		if err != nil {
			p.logger.Warn("pin aus zertifikatsdatei nicht lesbar", "file", p.cfg.CertFile, "error", err)
			return PinStatus{Err: err.Error(), ErrCode: PinErrCertFileUnreadable}
		}
		return PinStatus{Pin: pin, Source: PinSourceFile}
	default:
		return p.dialStatus(ctx)
	}
}

// Run hält den gedialten Pin im Hintergrund frisch; für die statische und die
// Datei-Quelle kehrt Run sofort zurück. Blockiert bis ctx endet.
//
// Bewusst ohne Fälligkeitsprüfung (kein dialOnce): der Tick *ist* der
// geplante Refresh. Mit Due-Check verfehlte jeder Tick die Schwelle um die
// Dauer des vorherigen Dials (checked liegt ε nach dem Tick-Start) — der
// Hintergrund-Refresh liefe effektiv nur jedes zweite Intervall. Außerdem darf
// der Fehler-Backoff der Request-Pfade den geplanten Refresh nicht drosseln.
func (p *PinProvider) Run(ctx context.Context) {
	if p.source != PinSourceDial {
		return
	}
	ticker := time.NewTicker(p.refresh())
	defer ticker.Stop()
	for {
		p.dialMu.Lock()
		p.refreshDial(ctx)
		p.dialMu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// refresh liefert das Refresh-Intervall (0 ⇒ Default).
func (p *PinProvider) refresh() time.Duration {
	if p.cfg.Refresh <= 0 {
		return DefaultPinRefresh
	}
	return p.cfg.Refresh
}

// dialBackoff liefert den Mindestabstand fehlgeschlagener Dials (0 ⇒ Default).
func (p *PinProvider) dialBackoff() time.Duration {
	if p.backoff <= 0 {
		return pinDialBackoff
	}
	return p.backoff
}

// dialStatus liefert den gedialten Pin und zieht ihn synchron nach, sobald der
// letzte Versuch fällig ist. Ohne diesen Lazy-Refresh trüge ein install.sh im
// Rotationsfenster (Let's-Encrypt-Renewals erzeugen standardmäßig neue Keys)
// planmäßig alle ~60–90 Tage einen alten Pin.
func (p *PinProvider) dialStatus(ctx context.Context) PinStatus {
	pin, errText, errCode, due := p.snapshot()
	if due {
		// Ohne die Client-Abbrüche des Requests: ein sofort abgebrochener
		// Request (unauthentifizierte Route!) würde sonst als „Dial
		// fehlgeschlagen" gecacht und verbrennte das Backoff-Fenster — das
		// Ergebnis gehört allen Aufrufern, nicht dem einen Request. Das
		// Timeout setzt dialPin selbst (pinDialTimeout).
		pin, errText, errCode = p.dialOnce(context.WithoutCancel(ctx))
	}
	if pin == "" {
		return PinStatus{Err: errText, ErrCode: errCode}
	}
	return PinStatus{Pin: pin, Source: PinSourceDial, Err: errText, ErrCode: errCode}
}

// snapshot liefert den Cache-Stand und ob ein neuer Dial fällig ist: mit
// vorhandenem Pin erst wenn das Refresh-Intervall um ist, ohne Pin schon nach
// dem kurzen Fehler-Backoff — das Gate soll aufgehen, sobald der Ingress
// routet, ohne dass jeder Request einen eigenen Handshake auslöst.
func (p *PinProvider) snapshot() (pin, errText, errCode string, due bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	wait := p.refresh()
	if p.pin == "" {
		wait = p.dialBackoff()
	}
	return p.pin, p.err, p.errCode, time.Since(p.checked) >= wait
}

// dialOnce dialt höchstens einmal je Fälligkeitsfenster: parallele Aufrufer
// warten am dialMu und übernehmen danach das Ergebnis des ersten.
func (p *PinProvider) dialOnce(ctx context.Context) (pin, errText, errCode string) {
	p.dialMu.Lock()
	defer p.dialMu.Unlock()
	if cachedPin, cachedErr, cachedCode, due := p.snapshot(); !due {
		return cachedPin, cachedErr, cachedCode
	}
	return p.refreshDial(ctx)
}

// refreshDial dialt einmal und aktualisiert den Cache. Schlägt der Dial fehl,
// bleibt der letzte erfolgreich gelesene Pin aktiv (nur „noch nie ein Pin
// gelesen" hält das Gate zu). Der Zeitstempel wird auch bei Fehlschlag gesetzt:
// ein vorhandener Pin wird damit höchstens im Intervall, ein fehlender
// höchstens im Backoff neu gedialt. Aufrufer halten dialMu: die Request-Pfade
// via dialOnce (mit Fälligkeitsprüfung), der Run-Loop direkt (jeder Tick ist
// ein geplanter Refresh).
func (p *PinProvider) refreshDial(ctx context.Context) (pin, errText, errCode string) {
	dialed, err := p.dialPin(ctx)

	p.mu.Lock()
	defer p.mu.Unlock()
	p.checked = time.Now()
	if err != nil {
		p.err, p.errCode = err.Error(), classifyDialErr(err)
		p.logger.Warn("pin-selbst-dial fehlgeschlagen", "url", p.cfg.DialURL,
			"error", err, "kategorie", p.errCode, "letzter_pin_vorhanden", p.pin != "")
		return p.pin, p.err, p.errCode
	}
	if p.pin != "" && p.pin != dialed {
		p.logger.Info("public-pin hat sich geändert (zertifikatsrotation)", "url", p.cfg.DialURL)
	}
	p.pin, p.err, p.errCode = dialed, "", ""
	return p.pin, "", ""
}

// errPinPublicURL markiert Fehler, die an der konfigurierten Public-URL liegen
// (fehlt, unparsbar, kein https) — Operator-Konfiguration, nicht Erreichbarkeit.
var errPinPublicURL = errors.New("public-url unbrauchbar")

// classifyDialErr bildet einen Dial-Fehler auf eine grobe Kategorie ab. Nur die
// Kategorie geht ins öffentliche Manifest; der Volltext bleibt im Log.
func classifyDialErr(err error) string {
	var verifyErr *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var invalidErr x509.CertificateInvalidError
	switch {
	case errors.Is(err, errPinPublicURL):
		return PinErrNoPublicURL
	case errors.As(err, &verifyErr), errors.As(err, &unknownAuthority),
		errors.As(err, &hostnameErr), errors.As(err, &invalidErr):
		return PinErrChainUntrusted
	default:
		return PinErrDialFailed
	}
}

// dialPin wählt die eigene externe Public-URL per TLS an und liefert den Pin
// des Leaf-Zertifikats. Verifiziert wird fail-closed mit Standard-tls.Config
// gegen die System-Roots (Regel 1: kein InsecureSkipVerify) — ein
// unverifizierter Dial würde einen Angreifer-Pin in jedes install.sh templaten.
func (p *PinProvider) dialPin(ctx context.Context) (string, error) {
	if p.cfg.DialURL == "" {
		return "", fmt.Errorf("keine public-url gesetzt (GSSH_PUBLIC_URL oder GSSH_UI_BASE_URL): %w", errPinPublicURL)
	}
	target, err := url.Parse(p.cfg.DialURL)
	if err != nil {
		return "", fmt.Errorf("public-url %q parsen: %w (%w)", p.cfg.DialURL, err, errPinPublicURL)
	}
	if target.Scheme != "https" || target.Hostname() == "" {
		return "", fmt.Errorf("public-url %q ist kein https-url — pin nicht ermittelbar: %w", p.cfg.DialURL, errPinPublicURL)
	}
	port := target.Port()
	if port == "" {
		port = "443"
	}

	dialCtx, cancel := context.WithTimeout(ctx, pinDialTimeout)
	defer cancel()

	dialer := &tls.Dialer{Config: &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: target.Hostname(),
		RootCAs:    p.dialRoots,
	}}
	conn, err := dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(target.Hostname(), port))
	if err != nil {
		return "", fmt.Errorf("tls-dial %s: %w", p.cfg.DialURL, err)
	}
	defer func() { _ = conn.Close() }()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return "", errors.New("tls-dial lieferte keine tls-verbindung")
	}
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", errors.New("gegenstelle liefert kein zertifikat")
	}
	return pintls.FromCertificate(certs[0]), nil
}

// pinFromCertFile liest den Leaf (erster CERTIFICATE-Block, cert-manager-
// Konvention bei tls.crt) und berechnet dessen Pin.
func pinFromCertFile(path string) (string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // Pfad kommt aus der Server-Konfiguration (Env), nicht aus einem Request.
	if err != nil {
		return "", fmt.Errorf("pin-zertifikat lesen: %w", err)
	}
	for rest := data; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("pin-zertifikat %s parsen: %w", path, err)
		}
		return pintls.FromCertificate(cert), nil
	}
	return "", fmt.Errorf("pin-zertifikat %s enthält keinen CERTIFICATE-block", path)
}
