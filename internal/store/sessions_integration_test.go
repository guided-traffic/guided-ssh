//go:build integration

package store_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/guided-traffic/guided-ssh/internal/store"
)

func TestHostSessionLifecycle(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()

	// Host, Nutzer, CA-Key und ein Zertifikat mit bekanntem Serial anlegen.
	host := &store.Host{Name: "web1.example.com"}
	mustNoErr(t, testStore.CreateHost(ctx, host))
	user := &store.User{Issuer: "idp", Subject: "s", Username: "alice", Email: "alice@example.com", Active: true}
	mustNoErr(t, testStore.CreateUser(ctx, user))
	ca := &store.CAKey{Purpose: store.CertTypeUser, Algorithm: "ed25519", PublicKey: "ca-pk"}
	mustNoErr(t, testStore.CreateCAKey(ctx, ca))

	serial, err := testStore.NextCertificateSerial(ctx)
	mustNoErr(t, err)
	now := time.Now().UTC().Truncate(time.Second)
	cert := &store.Certificate{
		Serial: serial, KeyID: "user:s@idp", CertType: store.CertTypeUser,
		PublicKey: "pk", Principals: []string{"alice"},
		ValidAfter: now, ValidBefore: now.Add(16 * time.Hour),
		CAKeyID: ca.ID, UserID: &user.ID,
	}
	mustNoErr(t, testStore.CreateCertificate(ctx, cert))

	// Session-Open mit Serial ⇒ user_id wird korreliert.
	started := now.Add(-5 * time.Minute)
	mustNoErr(t, testStore.OpenHostSession(ctx, store.SessionEvent{
		HostID: host.ID, HostName: host.Name, LocalUser: "deploy",
		RemoteAddr: "10.0.0.9", TTY: "pts/0", CertSerial: &serial,
		KeyID: "user:s@idp", OccurredAt: started,
	}))

	active, err := testStore.ListActiveSessions(ctx, 0)
	mustNoErr(t, err)
	if len(active) != 1 {
		t.Fatalf("aktive Sessions = %d", len(active))
	}
	if active[0].UserID == nil || *active[0].UserID != user.ID {
		t.Fatalf("Serial-Korrelation fehlgeschlagen: user_id = %v", active[0].UserID)
	}
	if !active[0].StartedAt.Equal(started) {
		t.Errorf("StartedAt = %v, erwartet %v", active[0].StartedAt, started)
	}

	// Session-Close schließt genau diese Session (host + user + tty).
	ended := now
	mustNoErr(t, testStore.CloseHostSession(ctx, store.SessionEvent{
		HostID: host.ID, HostName: host.Name, LocalUser: "deploy",
		TTY: "pts/0", OccurredAt: ended,
	}))
	active, err = testStore.ListActiveSessions(ctx, 0)
	mustNoErr(t, err)
	if len(active) != 0 {
		t.Fatalf("nach Close noch %d aktive Sessions", len(active))
	}

	// Audit-Events: opened + closed geschrieben, closed mit Dauer.
	events, err := testStore.ListAuditEvents(ctx, store.AuditFilter{})
	mustNoErr(t, err)
	types := map[string]int{}
	for _, e := range events {
		types[e.EventType]++
	}
	if types[store.EventSessionOpened] != 1 || types[store.EventSessionClosed] != 1 {
		t.Fatalf("Audit-Events unvollständig: %+v", types)
	}
}

func TestOpenHostSessionUnknownSerialTolerant(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()
	host := &store.Host{Name: "h2.example.com"}
	mustNoErr(t, testStore.CreateHost(ctx, host))

	unknown := int64(999999)
	mustNoErr(t, testStore.OpenHostSession(ctx, store.SessionEvent{
		HostID: host.ID, HostName: host.Name, LocalUser: "root",
		CertSerial: &unknown, OccurredAt: time.Now(),
	}))
	active, err := testStore.ListActiveSessions(ctx, 0)
	mustNoErr(t, err)
	if len(active) != 1 || active[0].UserID != nil {
		t.Fatalf("unbekannter Serial muss tolerant ohne user_id angelegt werden: %+v", active)
	}
}

func TestRecordSudoEvent(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()
	host := &store.Host{Name: "h3.example.com"}
	mustNoErr(t, testStore.CreateHost(ctx, host))

	mustNoErr(t, testStore.RecordSudoEvent(ctx, store.SessionEvent{
		HostID: host.ID, HostName: host.Name, LocalUser: "root",
		RemoteUser: "deploy", Command: "/usr/bin/systemctl restart nginx", TTY: "pts/1",
		OccurredAt: time.Now(),
	}))

	events, err := testStore.ListAuditEvents(ctx, store.AuditFilter{EventType: store.EventSudo})
	mustNoErr(t, err)
	if len(events) != 1 {
		t.Fatalf("sudo-Events = %d", len(events))
	}
	if got := string(events[0].Payload); !strings.Contains(got, "systemctl restart nginx") || !strings.Contains(got, "deploy") {
		t.Errorf("sudo-Payload unvollständig: %s", got)
	}
}
