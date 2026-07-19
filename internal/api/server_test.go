package api_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/guided-traffic/guided-ssh/internal/api"
	"github.com/guided-traffic/guided-ssh/internal/ca"
	"github.com/guided-traffic/guided-ssh/internal/store"
)

// fakeStore deckt die vom Bundle-Endpoint genutzten Store-Methoden ab.
type fakeStore struct {
	keys    []store.CAKey
	listErr error
}

func (f *fakeStore) NextCertificateSerial(context.Context) (int64, error) { return 1, nil }

func (f *fakeStore) CreateCertificateWithAudit(context.Context, *store.Certificate, *store.AuditEvent) error {
	return nil
}

func (f *fakeStore) CreateCAKey(_ context.Context, k *store.CAKey) error {
	k.ID = uuid.New()
	k.CreatedAt = time.Now()
	f.keys = append(f.keys, *k)
	return nil
}

func (f *fakeStore) ListActiveCAKeys(_ context.Context, purpose string) ([]store.CAKey, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []store.CAKey
	for _, k := range f.keys {
		if k.Purpose == purpose {
			out = append(out, k)
		}
	}
	return out, nil
}

func (f *fakeStore) UpdateCAKeyState(context.Context, uuid.UUID, string) (*store.CAKey, error) {
	return nil, store.ErrNotFound
}

func (f *fakeStore) AppendAuditEvent(context.Context, *store.AuditEvent) error { return nil }

func newTestServer(t *testing.T, fs *fakeStore) *httptest.Server {
	t.Helper()
	masterKey := make([]byte, ca.MasterKeySize)
	certAuthority, err := ca.New(fs, masterKey, ca.NewPolicyEngine(ca.DefaultPolicies()))
	if err != nil {
		t.Fatalf("ca.New: %v", err)
	}
	if err := certAuthority.EnsureCAKeys(context.Background()); err != nil {
		t.Fatalf("EnsureCAKeys: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(api.New(api.Deps{CA: certAuthority, Logger: logger}))
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url) //nolint:gosec // Test-URL vom httptest-Server
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("body lesen: %v", err)
	}
	return resp.StatusCode, string(body)
}

func TestHealthz(t *testing.T) {
	srv := newTestServer(t, &fakeStore{})
	status, body := get(t, srv.URL+"/healthz")
	if status != http.StatusOK || !strings.Contains(body, "ok") {
		t.Fatalf("healthz: %d %q", status, body)
	}
}

func TestBundleEndpoints(t *testing.T) {
	fs := &fakeStore{}
	srv := newTestServer(t, fs)

	for _, purpose := range []string{"user", "host"} {
		status, body := get(t, srv.URL+"/v1/ca/bundle/"+purpose)
		if status != http.StatusOK {
			t.Fatalf("bundle/%s: status %d", purpose, status)
		}
		if !strings.HasPrefix(body, "ssh-ed25519 ") {
			t.Fatalf("bundle/%s: kein authorized_keys-Format: %q", purpose, body)
		}
	}
}

func TestBundleUnbekannterZweck(t *testing.T) {
	srv := newTestServer(t, &fakeStore{})
	if status, _ := get(t, srv.URL+"/v1/ca/bundle/robot"); status != http.StatusNotFound {
		t.Fatalf("status %d, erwartet 404", status)
	}
}

func TestBundleStoreFehler(t *testing.T) {
	fs := &fakeStore{}
	srv := newTestServer(t, fs)
	fs.listErr = context.DeadlineExceeded
	if status, _ := get(t, srv.URL+"/v1/ca/bundle/user"); status != http.StatusInternalServerError {
		t.Fatalf("status %d, erwartet 500", status)
	}
}
