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
	Pin    string // leer = kein Pin
	Source string // "static" | "file" | "dial" | ""
	Err    string // letzter Fehler, für Log/Manifest
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

	mu      sync.Mutex
	pin     string    // letzter erfolgreich gedialter Pin
	checked time.Time // letzter Dial-Versuch (Erfolg wie Fehlschlag)
	err     string
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
			return PinStatus{Err: err.Error()}
		}
		return PinStatus{Pin: pin, Source: PinSourceFile}
	default:
		return p.dialStatus(ctx)
	}
}

// Run hält den gedialten Pin im Hintergrund frisch; für die statische und die
// Datei-Quelle kehrt Run sofort zurück. Blockiert bis ctx endet.
func (p *PinProvider) Run(ctx context.Context) {
	if p.source != PinSourceDial {
		return
	}
	ticker := time.NewTicker(p.refresh())
	defer ticker.Stop()
	for {
		p.refreshDial(ctx)
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

// dialStatus liefert den gedialten Pin und zieht ihn synchron nach, sobald der
// letzte Versuch länger als das Intervall zurückliegt. Ohne diesen
// Lazy-Refresh trüge ein install.sh im Rotationsfenster (Let's-Encrypt-Renewals
// erzeugen standardmäßig neue Keys) planmäßig alle ~60–90 Tage einen alten Pin.
func (p *PinProvider) dialStatus(ctx context.Context) PinStatus {
	p.mu.Lock()
	pin, checked, errText := p.pin, p.checked, p.err
	p.mu.Unlock()

	if pin == "" || time.Since(checked) >= p.refresh() {
		pin, errText = p.refreshDial(ctx)
	}
	if pin == "" {
		return PinStatus{Err: errText}
	}
	return PinStatus{Pin: pin, Source: PinSourceDial, Err: errText}
}

// refreshDial dialt einmal und aktualisiert den Cache. Schlägt der Dial fehl,
// bleibt der letzte erfolgreich gelesene Pin aktiv (nur „noch nie ein Pin
// gelesen" hält das Gate zu). Der Zeitstempel wird auch bei Fehlschlag gesetzt:
// ein vorhandener Pin wird damit höchstens im Intervall neu gedialt. Solange
// gar kein Pin gelesen wurde, versucht es jeder Serve-Aufruf erneut — das Gate
// soll aufgehen, sobald der externe Endpunkt erreichbar ist (beim Start dialt
// der Server sich selbst durch den Ingress, der ihn oft noch nicht routet).
func (p *PinProvider) refreshDial(ctx context.Context) (pin, errText string) {
	dialed, err := p.dialPin(ctx)

	p.mu.Lock()
	defer p.mu.Unlock()
	p.checked = time.Now()
	if err != nil {
		p.err = err.Error()
		p.logger.Warn("pin-selbst-dial fehlgeschlagen", "url", p.cfg.DialURL,
			"error", err, "letzter_pin_vorhanden", p.pin != "")
		return p.pin, p.err
	}
	if p.pin != "" && p.pin != dialed {
		p.logger.Info("public-pin hat sich geändert (zertifikatsrotation)", "url", p.cfg.DialURL)
	}
	p.pin, p.err = dialed, ""
	return p.pin, ""
}

// dialPin wählt die eigene externe Public-URL per TLS an und liefert den Pin
// des Leaf-Zertifikats. Verifiziert wird fail-closed mit Standard-tls.Config
// gegen die System-Roots (Regel 1: kein InsecureSkipVerify) — ein
// unverifizierter Dial würde einen Angreifer-Pin in jedes install.sh templaten.
func (p *PinProvider) dialPin(ctx context.Context) (string, error) {
	if p.cfg.DialURL == "" {
		return "", errors.New("keine public-url gesetzt (GSSH_PUBLIC_URL oder GSSH_UI_BASE_URL)")
	}
	target, err := url.Parse(p.cfg.DialURL)
	if err != nil {
		return "", fmt.Errorf("public-url %q parsen: %w", p.cfg.DialURL, err)
	}
	if target.Scheme != "https" || target.Hostname() == "" {
		return "", fmt.Errorf("public-url %q ist kein https-url — pin nicht ermittelbar", p.cfg.DialURL)
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
