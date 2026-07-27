// Package proxytrust implements the trust policy for the PROXY protocol on the
// agent mTLS listener (docs/major-tickets/AGENT_INGRESS.md, D5).
//
// mTLS already governs *access* to the agent API: without a valid client
// certificate every connection dies in the handshake. What it does not govern
// is the integrity of the source address written to the audit log. The
// relevant attacker is the authenticated one — a compromised enrolled host
// holds a valid agent certificate, and if it may send its own PROXY header it
// writes any source IP it likes into the audit trail. The policy therefore
// decides per connection whether the peer may speak PROXY protocol at all:
//
//	trusted peer   → header REQUIRED (a proxy that stops sending one is a
//	                 misconfiguration — fail closed instead of silently
//	                 recording the proxy's own address)
//	untrusted peer → header REJECTED; a plain connection still works
//	empty list     → header required from every peer
//
// Trusted entries are CIDRs, plain IPs, or DNS names. The DNS form exists so
// operators can trust exactly the ingress controller pods (a headless Service
// resolves to the pod IPs the server actually sees as sources) instead of the
// whole pod CIDR. Names are re-resolved periodically; the trust anchor is
// cluster DNS.
package proxytrust

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/pires/go-proxyproto"
)

const (
	// DefaultRefresh is the interval of the periodic DNS re-resolve. Short
	// enough that a rolled ingress controller is picked up quickly, long
	// enough to stay invisible in CoreDNS load.
	DefaultRefresh = 15 * time.Second

	// forcedInterval rate-limits the out-of-band re-resolve triggered by a
	// connection from an unknown address — an untrusted peer must not be able
	// to drive DNS traffic.
	forcedInterval = 2 * time.Second

	// lookupTimeout bounds one resolution round (all names together).
	lookupTimeout = 5 * time.Second
)

// Resolver resolves DNS names to IP addresses; *net.Resolver satisfies it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Config configures a Trust.
type Config struct {
	// Trusted holds the raw entries (CIDR, IP or DNS name); blanks are ignored.
	Trusted []string
	// Refresh is the re-resolve interval of the DNS entries; 0 ⇒ DefaultRefresh.
	Refresh time.Duration
	// Resolver resolves the DNS entries; nil ⇒ net.DefaultResolver.
	Resolver Resolver
	// Logger receives refresh warnings; nil ⇒ slog.Default().
	Logger *slog.Logger
}

// Trust decides which peers may send a PROXY header. It is safe for
// concurrent use.
type Trust struct {
	prefixes []netip.Prefix // static entries (CIDR or single IP), immutable
	names    []string       // DNS entries, re-resolved into resolved
	refresh  time.Duration
	resolver Resolver
	logger   *slog.Logger

	mu         sync.RWMutex
	resolved   []netip.Addr // last known good resolution of names
	lastForced time.Time
}

// New parses the trusted entries and resolves the DNS ones once. An
// unresolvable name at startup is a configuration error (typo): running with a
// silently empty trust set would reject every proxied connection.
func New(ctx context.Context, cfg Config) (*Trust, error) {
	t := &Trust{
		refresh:  cfg.Refresh,
		resolver: cfg.Resolver,
		logger:   cfg.Logger,
	}
	if t.refresh <= 0 {
		t.refresh = DefaultRefresh
	}
	if t.resolver == nil {
		t.resolver = net.DefaultResolver
	}
	if t.logger == nil {
		t.logger = slog.Default()
	}
	for _, raw := range cfg.Trusted {
		entry := strings.TrimSpace(raw)
		switch {
		case entry == "":
			continue
		case strings.Contains(entry, "/"):
			prefix, err := netip.ParsePrefix(entry)
			if err != nil {
				return nil, fmt.Errorf("trusted entry %q: %w", entry, err)
			}
			t.prefixes = append(t.prefixes, prefix.Masked())
		default:
			if addr, err := netip.ParseAddr(entry); err == nil {
				addr = addr.Unmap()
				t.prefixes = append(t.prefixes, netip.PrefixFrom(addr, addr.BitLen()))
				continue
			}
			t.names = append(t.names, entry)
		}
	}
	if err := t.Refresh(ctx); err != nil {
		return nil, err
	}
	return t, nil
}

// Empty reports whether no trusted entry is configured at all — then the PROXY
// header is mandatory for every connection and direct (unproxied) agents
// break. Callers use it to warn about that.
func (t *Trust) Empty() bool {
	return len(t.prefixes) == 0 && len(t.names) == 0
}

// Refresh re-resolves every DNS entry. On failure the previously resolved set
// is kept and the error returned: a CoreDNS hiccup must not empty the trust
// set and lock the ingress controller out of the agent path.
func (t *Trust) Refresh(ctx context.Context) error {
	if len(t.names) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()

	var (
		addrs []netip.Addr
		errs  []error
	)
	for _, name := range t.names {
		got, err := t.resolver.LookupNetIP(ctx, "ip", name)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("resolve %q: %w", name, err))
		case len(got) == 0:
			errs = append(errs, fmt.Errorf("resolve %q: no addresses", name))
		}
		for _, addr := range got {
			addrs = append(addrs, addr.Unmap())
		}
	}
	// All or nothing: a partial result would silently shrink the trusted set
	// while looking like a successful refresh.
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	t.mu.Lock()
	t.resolved = addrs
	t.mu.Unlock()
	return nil
}

// Run re-resolves the DNS entries until ctx is done. Without DNS entries it
// returns immediately — there is nothing to keep up to date.
func (t *Trust) Run(ctx context.Context) {
	if len(t.names) == 0 {
		return
	}
	ticker := time.NewTicker(t.refresh)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := t.Refresh(ctx); err != nil && ctx.Err() == nil {
				t.logger.Warn("proxy protocol trust list: dns refresh failed, keeping the last known good set", "error", err)
			}
		}
	}
}

// ConnPolicy is the per-connection policy hook of go-proxyproto and implements
// the matrix documented on the package.
func (t *Trust) ConnPolicy(opts proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
	if t.Empty() {
		return proxyproto.REQUIRE, nil
	}
	addr, err := addrOf(opts.Upstream)
	if err != nil {
		// Wrapping ErrInvalidUpstream drops this connection only; Accept keeps
		// listening instead of tearing down the whole agent listener.
		return proxyproto.REJECT, fmt.Errorf("%w: %w", proxyproto.ErrInvalidUpstream, err)
	}
	if t.Trusted(addr) {
		return proxyproto.REQUIRE, nil
	}
	t.triggerRefresh()
	return proxyproto.REJECT, nil
}

// Trusted reports whether addr may send a PROXY header.
func (t *Trust) Trusted(addr netip.Addr) bool {
	addr = addr.Unmap().WithZone("")
	for _, prefix := range t.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, known := range t.resolved {
		if known == addr {
			return true
		}
	}
	return false
}

// triggerRefresh re-resolves out of band after a connection from an unknown
// address: a restarted controller pod would otherwise stay untrusted until the
// next tick. Asynchronous on purpose — an unknown peer must not be able to
// stall the accept loop with DNS latency — so the triggering connection is
// still judged against the old set and only the next one sees the new pod.
func (t *Trust) triggerRefresh() {
	if len(t.names) == 0 {
		return
	}
	t.mu.Lock()
	if time.Since(t.lastForced) < forcedInterval {
		t.mu.Unlock()
		return
	}
	t.lastForced = time.Now()
	t.mu.Unlock()

	go func() {
		if err := t.Refresh(context.Background()); err != nil {
			t.logger.Warn("proxy protocol trust list: forced dns refresh failed, keeping the last known good set", "error", err)
		}
	}()
}

// addrOf extracts the IP of a peer address. Anything without one (e.g. a Unix
// or pipe address) cannot be classified and is treated as an error by the
// caller.
func addrOf(peer net.Addr) (netip.Addr, error) {
	if peer == nil {
		return netip.Addr{}, errors.New("connection without remote address")
	}
	if tcp, ok := peer.(*net.TCPAddr); ok {
		if addr, ok := netip.AddrFromSlice(tcp.IP); ok {
			return addr.Unmap(), nil
		}
	}
	host, _, err := net.SplitHostPort(peer.String())
	if err != nil {
		return netip.Addr{}, fmt.Errorf("remote address %q: %w", peer.String(), err)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("remote address %q: %w", peer.String(), err)
	}
	return addr.Unmap(), nil
}
