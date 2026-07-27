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

// Pin sources of the host rollout, in descending precedence.
const (
	// PinSourceStatic: the operator supplies the pin themselves via
	// GSSH_PUBLIC_PIN; rotation is thus in the operator's hands (no dial,
	// no refresh).
	PinSourceStatic = "static"
	// PinSourceFile: leaf certificate from a PEM file (K8s TLS secret as a
	// volume, bind-mounted fullchain.pem).
	PinSourceFile = "file"
	// PinSourceDial: the server dials its own external public URL and
	// reads the leaf certificate — exactly the value a host sees during
	// enrollment. Default source.
	PinSourceDial = "dial"
)

// DefaultPinRefresh is the default interval of the pin self-dial.
const DefaultPinRefresh = 5 * time.Minute

// pinDialTimeout bounds a single self-dial; a hanging reverse proxy must
// not block serving install.sh.
const pinDialTimeout = 5 * time.Second

// pinDialBackoff is the minimum spacing between two self-dials while no
// pin has ever been read yet. Without it, every request on the
// unauthenticated rollout routes would trigger its own outbound handshake
// (up to pinDialTimeout wait per request). Short enough that the gate
// opens a few seconds after the first successful ingress routing.
const pinDialBackoff = 10 * time.Second

// Coarse categories of the last pin error. Deliberately only categories:
// they end up in the unauthenticated manifest, while the full text
// (container paths, dial details) only goes to the server log.
const (
	// PinErrNoPublicURL: no, or no https, public URL configured.
	PinErrNoPublicURL = "no_public_url"
	// PinErrChainUntrusted: the TLS handshake succeeded, but the chain is
	// not trusted (no insecure fallback, see dialPin).
	PinErrChainUntrusted = "chain_untrusted"
	// PinErrDialFailed: connection did not come up (DNS, timeout, reset).
	PinErrDialFailed = "dial_failed"
	// PinErrCertFileUnreadable: pin certificate file missing, unreadable,
	// or contains no leaf.
	PinErrCertFileUnreadable = "cert_file_unreadable"
)

// PinProviderConfig configures pin determination. Precedence: StaticPin
// before CertFile before self-dial. All sources are fail-closed — without
// a pin the rollout gate stays closed, there is no unpinned fallback.
type PinProviderConfig struct {
	// StaticPin is the base64 SPKI SHA-256 pin from GSSH_PUBLIC_PIN. The
	// caller validates it at startup (pintls.DecodePin, fail-fast).
	StaticPin string
	// CertFile is the path to a PEM certificate (GSSH_PUBLIC_PIN_CERT_FILE);
	// the first CERTIFICATE block counts as the leaf (cert-manager convention).
	CertFile string
	// DialURL is the external public URL for the self-dial (GSSH_PUBLIC_URL).
	DialURL string
	// Refresh is the self-dial interval; 0 ⇒ DefaultPinRefresh.
	Refresh time.Duration
}

// PinStatus is the current pin state. An empty Pin means: no pin could be
// determined ⇒ gate closed. Source is only set when a pin is present.
type PinStatus struct {
	Pin     string // empty = no pin
	Source  string // "static" | "file" | "dial" | ""
	Err     string // last error in full text, for the log only
	ErrCode string // coarse category of the last error, for the manifest
}

// PinProvider determines the SPKI pin of the public TLS endpoint that
// hosts see during enrollment. The active source is fixed at construction.
type PinProvider struct {
	cfg    PinProviderConfig
	source string
	logger *slog.Logger

	// dialRoots replaces the system roots in tests. nil ⇒ system roots;
	// chain verification is active in both cases (rule 1: no
	// InsecureSkipVerify code path).
	dialRoots *x509.CertPool

	// dialMu serializes self-dials: concurrent callers wait here and then
	// take over the result of the first (singleflight) instead of each
	// running its own handshake.
	dialMu sync.Mutex

	mu      sync.Mutex
	pin     string    // last successfully dialed pin
	checked time.Time // last dial attempt (success or failure)
	err     string
	errCode string
	backoff time.Duration // test hook; 0 ⇒ pinDialBackoff
}

// NewPinProvider selects the source by precedence and logs it. If several
// sources are set, the highest wins — the rest are ignored with a warning.
func NewPinProvider(cfg PinProviderConfig, logger *slog.Logger) *PinProvider {
	p := &PinProvider{cfg: cfg, logger: logger}
	switch {
	case cfg.StaticPin != "":
		p.source = PinSourceStatic
		if cfg.CertFile != "" || cfg.DialURL != "" {
			logger.Warn("multiple pin sources set — static pin wins",
				"cert_file", cfg.CertFile, "dial_url", cfg.DialURL)
		}
	case cfg.CertFile != "":
		p.source = PinSourceFile
		if cfg.DialURL != "" {
			logger.Warn("multiple pin sources set — certificate file wins", "dial_url", cfg.DialURL)
		}
	default:
		p.source = PinSourceDial
	}
	logger.Info("pin source active", "source", p.source)
	return p
}

// Source returns the active pin source (regardless of whether it
// currently returns a pin).
func (p *PinProvider) Source() string { return p.source }

// Status returns the current pin. The file source is read fresh on every
// call (deliberately uncached: parsing costs microseconds, in exchange a
// secret rotation takes effect immediately after the kubelet syncs the
// mount); the dial source catches up synchronously once the interval has
// elapsed (lazy refresh).
func (p *PinProvider) Status(ctx context.Context) PinStatus {
	switch p.source {
	case PinSourceStatic:
		return PinStatus{Pin: p.cfg.StaticPin, Source: PinSourceStatic}
	case PinSourceFile:
		pin, err := pinFromCertFile(p.cfg.CertFile)
		if err != nil {
			p.logger.Warn("pin from certificate file unreadable", "file", p.cfg.CertFile, "error", err)
			return PinStatus{Err: err.Error(), ErrCode: PinErrCertFileUnreadable}
		}
		return PinStatus{Pin: pin, Source: PinSourceFile}
	default:
		return p.dialStatus(ctx)
	}
}

// Run keeps the dialed pin fresh in the background; for the static and
// file sources, Run returns immediately. Blocks until ctx ends.
//
// Deliberately without a due check (no dialOnce): the tick *is* the
// scheduled refresh. With a due check, every tick would miss the
// threshold by the duration of the previous dial (checked lands ε after
// the tick start) — the background refresh would effectively run only
// every other interval. Also, the error backoff of the request paths must
// not throttle the scheduled refresh.
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

// refresh returns the refresh interval (0 ⇒ default).
func (p *PinProvider) refresh() time.Duration {
	if p.cfg.Refresh <= 0 {
		return DefaultPinRefresh
	}
	return p.cfg.Refresh
}

// dialBackoff returns the minimum spacing between failed dials (0 ⇒ default).
func (p *PinProvider) dialBackoff() time.Duration {
	if p.backoff <= 0 {
		return pinDialBackoff
	}
	return p.backoff
}

// dialStatus returns the dialed pin and catches it up synchronously once
// the last attempt is due. Without this lazy refresh, an install.sh in the
// rotation window (Let's Encrypt renewals generate new keys by default)
// would routinely carry a stale pin every ~60-90 days.
func (p *PinProvider) dialStatus(ctx context.Context) PinStatus {
	pin, errText, errCode, due := p.snapshot()
	if due {
		// Without the request's client cancellation: an immediately
		// canceled request (unauthenticated route!) would otherwise be
		// cached as a "dial failed" and burn the backoff window — the
		// result belongs to all callers, not to the one request. The
		// timeout is set by dialPin itself (pinDialTimeout).
		pin, errText, errCode = p.dialOnce(context.WithoutCancel(ctx))
	}
	if pin == "" {
		return PinStatus{Err: errText, ErrCode: errCode}
	}
	return PinStatus{Pin: pin, Source: PinSourceDial, Err: errText, ErrCode: errCode}
}

// snapshot returns the cached state and whether a new dial is due: with a
// pin present, only once the refresh interval has elapsed; without a pin,
// already after the short error backoff — the gate should open as soon as
// the ingress routes, without every request triggering its own handshake.
func (p *PinProvider) snapshot() (pin, errText, errCode string, due bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	wait := p.refresh()
	if p.pin == "" {
		wait = p.dialBackoff()
	}
	return p.pin, p.err, p.errCode, time.Since(p.checked) >= wait
}

// dialOnce dials at most once per due window: concurrent callers wait at
// dialMu and then take over the result of the first.
func (p *PinProvider) dialOnce(ctx context.Context) (pin, errText, errCode string) {
	p.dialMu.Lock()
	defer p.dialMu.Unlock()
	if cachedPin, cachedErr, cachedCode, due := p.snapshot(); !due {
		return cachedPin, cachedErr, cachedCode
	}
	return p.refreshDial(ctx)
}

// refreshDial dials once and updates the cache. If the dial fails, the
// last successfully read pin stays active (only "never read a pin yet"
// keeps the gate closed). The timestamp is set even on failure: a present
// pin is thus re-dialed at most every interval, a missing one at most
// every backoff. Callers hold dialMu: the request paths via dialOnce
// (with a due check), the Run loop directly (every tick is a scheduled
// refresh).
func (p *PinProvider) refreshDial(ctx context.Context) (pin, errText, errCode string) {
	dialed, err := p.dialPin(ctx)

	p.mu.Lock()
	defer p.mu.Unlock()
	p.checked = time.Now()
	if err != nil {
		p.err, p.errCode = err.Error(), classifyDialErr(err)
		p.logger.Warn("pin self-dial failed", "url", p.cfg.DialURL,
			"error", err, "category", p.errCode, "last_pin_present", p.pin != "")
		return p.pin, p.err, p.errCode
	}
	if p.pin != "" && p.pin != dialed {
		p.logger.Info("public pin has changed (certificate rotation)", "url", p.cfg.DialURL)
	}
	p.pin, p.err, p.errCode = dialed, "", ""
	return p.pin, "", ""
}

// errPinPublicURL marks errors caused by the configured public URL
// (missing, unparsable, not https) — operator configuration, not reachability.
var errPinPublicURL = errors.New("public url unusable")

// classifyDialErr maps a dial error onto a coarse category. Only the
// category goes into the public manifest; the full text stays in the log.
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

// dialPin dials the server's own external public URL over TLS and returns
// the pin of the leaf certificate. Verification is fail-closed with a
// standard tls.Config against the system roots (rule 1: no
// InsecureSkipVerify) — an unverified dial would template an attacker's
// pin into every install.sh.
func (p *PinProvider) dialPin(ctx context.Context) (string, error) {
	if p.cfg.DialURL == "" {
		return "", fmt.Errorf("no public url set (GSSH_PUBLIC_URL): %w", errPinPublicURL)
	}
	target, err := url.Parse(p.cfg.DialURL)
	if err != nil {
		return "", fmt.Errorf("parsing public url %q: %w (%w)", p.cfg.DialURL, err, errPinPublicURL)
	}
	if target.Scheme != "https" || target.Hostname() == "" {
		return "", fmt.Errorf("public url %q is not a https url — pin cannot be determined: %w", p.cfg.DialURL, errPinPublicURL)
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
		return "", fmt.Errorf("tls dial %s: %w", p.cfg.DialURL, err)
	}
	defer func() { _ = conn.Close() }()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return "", errors.New("tls dial did not return a tls connection")
	}
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", errors.New("peer did not provide a certificate")
	}
	return pintls.FromCertificate(certs[0]), nil
}

// pinFromCertFile reads the leaf (first CERTIFICATE block, cert-manager
// convention for tls.crt) and computes its pin.
func pinFromCertFile(path string) (string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path comes from server configuration (env), not from a request.
	if err != nil {
		return "", fmt.Errorf("reading pin certificate: %w", err)
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
			return "", fmt.Errorf("parsing pin certificate %s: %w", path, err)
		}
		return pintls.FromCertificate(cert), nil
	}
	return "", fmt.Errorf("pin certificate %s contains no CERTIFICATE block", path)
}
