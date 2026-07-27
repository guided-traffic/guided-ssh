package proxytrust_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"

	"github.com/guided-traffic/guided-ssh/internal/proxytrust"
)

// fakeResolver answers from a swappable table so the DNS behaviour (startup
// fail-fast, refresh, keep-last-good) is testable without a resolver.
type fakeResolver struct {
	mu    sync.Mutex
	addrs map[string][]netip.Addr
	err   error
	calls int
}

func (f *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.addrs[host], nil
}

func (f *fakeResolver) set(host string, addrs []netip.Addr, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addrs = map[string][]netip.Addr{host: addrs}
	f.err = err
}

func (f *fakeResolver) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func addrs(t *testing.T, list ...string) []netip.Addr {
	t.Helper()
	out := make([]netip.Addr, 0, len(list))
	for _, raw := range list {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		out = append(out, addr)
	}
	return out
}

func newTrust(t *testing.T, cfg proxytrust.Config) *proxytrust.Trust {
	t.Helper()
	trust, err := proxytrust.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return trust
}

// TestEntryParsing covers the three accepted entry forms in one list plus the
// blanks a comma-split env value produces.
func TestEntryParsing(t *testing.T) {
	resolver := &fakeResolver{addrs: map[string][]netip.Addr{
		"haproxy-pods.ingress.svc.cluster.local": addrs(t, "10.42.0.7"),
	}}
	trust := newTrust(t, proxytrust.Config{
		Trusted:  []string{"10.0.0.0/8", " 192.0.2.1 ", "haproxy-pods.ingress.svc.cluster.local", ""},
		Resolver: resolver,
	})

	cases := map[string]bool{
		"10.1.2.3":    true,  // inside the CIDR
		"192.0.2.1":   true,  // the single IP
		"10.42.0.7":   true,  // resolved from the DNS entry
		"192.0.2.2":   false, // neighbour of the single IP
		"203.0.113.9": false,
	}
	for raw, want := range cases {
		if got := trust.Trusted(netip.MustParseAddr(raw)); got != want {
			t.Errorf("Trusted(%s) = %v, want %v", raw, got, want)
		}
	}
	if trust.Empty() {
		t.Error("Empty() = true for a configured trust list")
	}
}

func TestEntryParsingRejectsMalformedCIDR(t *testing.T) {
	if _, err := proxytrust.New(context.Background(), proxytrust.Config{Trusted: []string{"10.0.0.0/99"}}); err == nil {
		t.Fatal("New accepted a malformed CIDR")
	}
}

// TestIPv4MappedUpstream: a dual-stack listener reports v4 peers as
// ::ffff:a.b.c.d — that must still match a v4 entry.
func TestIPv4MappedUpstream(t *testing.T) {
	trust := newTrust(t, proxytrust.Config{Trusted: []string{"10.0.0.0/8"}})
	if !trust.Trusted(netip.MustParseAddr("::ffff:10.1.2.3")) {
		t.Error("v4-mapped upstream not matched against a v4 CIDR")
	}
}

// TestStartupFailFast: an unresolvable name is a typo — the server must not
// come up with a silently empty trust set.
func TestStartupFailFast(t *testing.T) {
	t.Run("resolver error", func(t *testing.T) {
		resolver := &fakeResolver{err: errors.New("nxdomain")}
		if _, err := proxytrust.New(context.Background(), proxytrust.Config{
			Trusted: []string{"typo.ingress.svc.cluster.local"}, Resolver: resolver,
		}); err == nil {
			t.Fatal("New succeeded despite an unresolvable name")
		}
	})
	t.Run("no addresses", func(t *testing.T) {
		resolver := &fakeResolver{addrs: map[string][]netip.Addr{}}
		if _, err := proxytrust.New(context.Background(), proxytrust.Config{
			Trusted: []string{"empty.ingress.svc.cluster.local"}, Resolver: resolver,
		}); err == nil {
			t.Fatal("New succeeded despite an empty resolution")
		}
	})
}

// TestRefreshKeepsLastGood: a DNS hiccup must not empty the trust set —
// otherwise a CoreDNS blip takes the whole agent path down.
func TestRefreshKeepsLastGood(t *testing.T) {
	const name = "haproxy-pods.ingress.svc.cluster.local"
	resolver := &fakeResolver{addrs: map[string][]netip.Addr{name: addrs(t, "10.42.0.7")}}
	trust := newTrust(t, proxytrust.Config{Trusted: []string{name}, Resolver: resolver})

	resolver.set(name, nil, errors.New("server misbehaving"))
	if err := trust.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh reported success on a failing resolver")
	}
	if !trust.Trusted(netip.MustParseAddr("10.42.0.7")) {
		t.Error("failed refresh dropped the last known good address")
	}

	resolver.set(name, addrs(t, "10.42.0.8"), nil)
	if err := trust.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if trust.Trusted(netip.MustParseAddr("10.42.0.7")) {
		t.Error("successful refresh kept the stale address")
	}
	if !trust.Trusted(netip.MustParseAddr("10.42.0.8")) {
		t.Error("successful refresh did not pick up the new address")
	}
}

// TestForcedRefreshOnUnknownPeer: a restarted controller pod gets a new IP.
// The connection that triggers the re-resolve is still rejected, the next one
// is accepted — without waiting for the periodic tick.
func TestForcedRefreshOnUnknownPeer(t *testing.T) {
	const name = "haproxy-pods.ingress.svc.cluster.local"
	resolver := &fakeResolver{addrs: map[string][]netip.Addr{name: addrs(t, "10.42.0.7")}}
	trust := newTrust(t, proxytrust.Config{
		Trusted:  []string{name},
		Refresh:  time.Hour, // the periodic tick must not be what fixes this
		Resolver: resolver,
	})

	resolver.set(name, addrs(t, "10.42.0.8"), nil)
	newPod := &net.TCPAddr{IP: net.ParseIP("10.42.0.8"), Port: 40000}
	policy, err := trust.ConnPolicy(proxyproto.ConnPolicyOptions{Upstream: newPod})
	if err != nil {
		t.Fatalf("ConnPolicy: %v", err)
	}
	if policy != proxyproto.REJECT {
		t.Fatalf("policy for the still-unknown pod = %v, want REJECT", policy)
	}

	deadline := time.Now().Add(2 * time.Second)
	for !trust.Trusted(netip.MustParseAddr("10.42.0.8")) {
		if time.Now().After(deadline) {
			t.Fatal("forced re-resolve did not pick up the new pod address")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Rate limit: a further unknown peer right after must not trigger another
	// lookup (an untrusted peer would otherwise drive DNS traffic).
	before := resolver.callCount()
	for range 5 {
		if _, err := trust.ConnPolicy(proxyproto.ConnPolicyOptions{
			Upstream: &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 40001},
		}); err != nil {
			t.Fatalf("ConnPolicy: %v", err)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if got := resolver.callCount(); got != before {
		t.Errorf("rate limit ignored: %d lookups after the forced one, want %d", got, before)
	}
}

// TestConnPolicyUnclassifiableUpstream: an address without an IP (unix, pipe)
// cannot be judged. The error must wrap ErrInvalidUpstream so Accept drops
// that connection and keeps listening instead of killing the listener.
func TestConnPolicyUnclassifiableUpstream(t *testing.T) {
	trust := newTrust(t, proxytrust.Config{Trusted: []string{"10.0.0.0/8"}})
	policy, err := trust.ConnPolicy(proxyproto.ConnPolicyOptions{
		Upstream: &net.UnixAddr{Name: "/tmp/agent.sock", Net: "unix"},
	})
	if !errors.Is(err, proxyproto.ErrInvalidUpstream) {
		t.Fatalf("error = %v, want one wrapping ErrInvalidUpstream", err)
	}
	if policy != proxyproto.REJECT {
		t.Errorf("policy = %v, want REJECT", policy)
	}
}

// exchange runs one connection against a PROXY-protocol listener guarded by
// the given trust list and reports what the server saw.
func exchange(t *testing.T, trusted []string, sendHeader bool) (remote, payload string, err error) {
	t.Helper()
	base, listenErr := net.Listen("tcp", "127.0.0.1:0")
	if listenErr != nil {
		t.Fatalf("listen: %v", listenErr)
	}
	trust := newTrust(t, proxytrust.Config{Trusted: trusted})
	listener := &proxyproto.Listener{
		Listener:          base,
		ConnPolicy:        trust.ConnPolicy,
		ReadHeaderTimeout: 2 * time.Second,
	}
	defer listener.Close()

	type result struct {
		remote, payload string
		err             error
	}
	results := make(chan result, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			results <- result{err: acceptErr}
			return
		}
		defer conn.Close()
		buf := make([]byte, len("hello"))
		n, readErr := io.ReadFull(conn, buf)
		results <- result{remote: conn.RemoteAddr().String(), payload: string(buf[:n]), err: readErr}
	}()

	client, dialErr := net.Dial("tcp", base.Addr().String())
	if dialErr != nil {
		t.Fatalf("dial: %v", dialErr)
	}
	if sendHeader {
		header := &proxyproto.Header{
			Version:           2,
			Command:           proxyproto.PROXY,
			TransportProtocol: proxyproto.TCPv4,
			SourceAddr:        &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 51000},
			DestinationAddr:   &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 8443},
		}
		if _, writeErr := header.WriteTo(client); writeErr != nil {
			t.Fatalf("write header: %v", writeErr)
		}
	}
	if _, writeErr := client.Write([]byte("hello")); writeErr != nil {
		t.Fatalf("write payload: %v", writeErr)
	}
	defer client.Close()

	select {
	case res := <-results:
		return res.remote, res.payload, res.err
	case <-time.After(5 * time.Second):
		t.Fatal("server side did not finish")
		return "", "", nil
	}
}

// TestPolicyMatrix walks all six cells of the D5 table. The listener runs on
// 127.0.0.1, so "127.0.0.1" is the trusted peer and any other entry makes the
// same connection untrusted.
func TestPolicyMatrix(t *testing.T) {
	cases := []struct {
		name       string
		trusted    []string
		sendHeader bool
		wantErr    error
		wantRemote string // only checked when the connection is expected to work
	}{
		{
			name:    "trusted sender with header: address taken from the header",
			trusted: []string{"127.0.0.1"}, sendHeader: true,
			wantRemote: "203.0.113.7:51000",
		},
		{
			name:    "trusted sender without header: rejected (fail closed)",
			trusted: []string{"127.0.0.1"}, sendHeader: false,
			wantErr: proxyproto.ErrNoProxyProtocol,
		},
		{
			name:    "untrusted sender with header: rejected (spoof attempt)",
			trusted: []string{"10.0.0.0/8"}, sendHeader: true,
			wantErr: proxyproto.ErrSuperfluousProxyHeader,
		},
		{
			name:    "untrusted sender without header: plain connection works",
			trusted: []string{"10.0.0.0/8"}, sendHeader: false,
			wantRemote: "127.0.0.1:",
		},
		{
			name:    "empty trust list with header: accepted from everyone",
			trusted: nil, sendHeader: true,
			wantRemote: "203.0.113.7:51000",
		},
		{
			name:    "empty trust list without header: rejected",
			trusted: nil, sendHeader: false,
			wantErr: proxyproto.ErrNoProxyProtocol,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			remote, payload, err := exchange(t, tc.trusted, tc.sendHeader)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if payload != "hello" {
				t.Errorf("payload = %q, want %q", payload, "hello")
			}
			if tc.wantRemote == "127.0.0.1:" {
				if host, _, _ := net.SplitHostPort(remote); host != "127.0.0.1" {
					t.Errorf("remote = %q, want the peer's own address", remote)
				}
				return
			}
			if remote != tc.wantRemote {
				t.Errorf("remote = %q, want %q", remote, tc.wantRemote)
			}
		})
	}
}

// TestReadHeaderTimeout: a peer that connects and then stalls must not hold
// the pre-TLS phase open indefinitely.
func TestReadHeaderTimeout(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	trust := newTrust(t, proxytrust.Config{Trusted: []string{"127.0.0.1"}})
	listener := &proxyproto.Listener{
		Listener:          base,
		ConnPolicy:        trust.ConnPolicy,
		ReadHeaderTimeout: 100 * time.Millisecond,
	}
	defer listener.Close()

	errs := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			errs <- acceptErr
			return
		}
		defer conn.Close()
		_, readErr := conn.Read(make([]byte, 1))
		errs <- readErr
	}()

	client, err := net.Dial("tcp", base.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	start := time.Now()
	select {
	case readErr := <-errs:
		if readErr == nil {
			t.Fatal("stalled connection was served without a header")
		}
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Errorf("header read took %s — timeout not applied", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stalled connection was never timed out")
	}
}
