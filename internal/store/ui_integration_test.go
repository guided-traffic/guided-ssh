//go:build integration

package store_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/guided-traffic/guided-ssh/internal/store"
)

// Phase 8: Store-Methoden der Web-UI (Hosts mit Tags/Cert-Ablauf, Benutzer
// mit Gruppen, Audit-Suche/-Pagination/-Streaming, Service-Account-Not-Aus).

func TestListHostsDetailed(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()

	h1 := &store.Host{Name: "web-1"}
	mustNoErr(t, testStore.CreateHost(ctx, h1))
	mustNoErr(t, testStore.SetHostTags(ctx, h1.ID, map[string]string{"env": "prod", "role": "web"}))
	h2 := &store.Host{Name: "db-1"}
	mustNoErr(t, testStore.CreateHost(ctx, h2))

	// Host-Zertifikate: das späteste valid_before zählt; User-Zertifikate nicht.
	ca := &store.CAKey{Purpose: store.CertTypeHost, Algorithm: "ed25519", PublicKey: "ca-pk"}
	mustNoErr(t, testStore.CreateCAKey(ctx, ca))
	now := time.Now().UTC().Truncate(time.Second)
	for i, validFor := range []time.Duration{10 * 24 * time.Hour, 30 * 24 * time.Hour} {
		serial, err := testStore.NextCertificateSerial(ctx)
		mustNoErr(t, err)
		mustNoErr(t, testStore.CreateCertificate(ctx, &store.Certificate{
			Serial: serial, KeyID: "host:web-1", CertType: store.CertTypeHost,
			PublicKey: "pk", Principals: []string{"web-1"},
			ValidAfter: now.Add(time.Duration(i) * time.Hour), ValidBefore: now.Add(validFor),
			CAKeyID: ca.ID, HostID: &h1.ID,
		}))
	}
	serial, err := testStore.NextCertificateSerial(ctx)
	mustNoErr(t, err)
	mustNoErr(t, testStore.CreateCertificate(ctx, &store.Certificate{
		Serial: serial, KeyID: "user:alice@idp", CertType: store.CertTypeUser,
		PublicKey: "pk-user", Principals: []string{"alice"},
		ValidAfter: now, ValidBefore: now.Add(100 * 24 * time.Hour),
		CAKeyID: ca.ID, HostID: &h1.ID,
	}))

	hosts, err := testStore.ListHostsDetailed(ctx)
	mustNoErr(t, err)
	if len(hosts) != 2 {
		t.Fatalf("hosts = %d", len(hosts))
	}
	// Sortiert nach Name: db-1 vor web-1.
	if hosts[0].Name != "db-1" || hosts[1].Name != "web-1" {
		t.Fatalf("reihenfolge: %s, %s", hosts[0].Name, hosts[1].Name)
	}
	if len(hosts[0].Tags) != 0 || hosts[0].CertValidBefore != nil {
		t.Errorf("db-1 ohne tags/cert erwartet: %+v", hosts[0])
	}
	web := hosts[1]
	if web.Tags["env"] != "prod" || web.Tags["role"] != "web" {
		t.Errorf("tags = %v", web.Tags)
	}
	if web.CertValidBefore == nil || !web.CertValidBefore.Equal(now.Add(30*24*time.Hour)) {
		t.Errorf("cert_valid_before = %v, erwartet max. der host-zertifikate", web.CertValidBefore)
	}
}

func TestListUsersDetailed(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()

	alice := &store.User{Issuer: "idp", Subject: "a", Username: "alice", Email: "alice@example.com", Active: true}
	mustNoErr(t, testStore.CreateUser(ctx, alice))
	bob := &store.User{Issuer: "idp", Subject: "b", Username: "bob", Email: "bob@example.com", Active: false}
	mustNoErr(t, testStore.CreateUser(ctx, bob))

	admins := &store.Group{Issuer: "idp", Name: "admins"}
	mustNoErr(t, testStore.CreateGroup(ctx, admins))
	dev := &store.Group{Issuer: "idp", Name: "dev"}
	mustNoErr(t, testStore.CreateGroup(ctx, dev))
	mustNoErr(t, testStore.SetUserGroups(ctx, alice.ID, []uuid.UUID{admins.ID, dev.ID}))

	users, err := testStore.ListUsersDetailed(ctx)
	mustNoErr(t, err)
	if len(users) != 2 {
		t.Fatalf("users = %d", len(users))
	}
	if users[0].Username != "alice" || len(users[0].Groups) != 2 ||
		users[0].Groups[0] != "admins" || users[0].Groups[1] != "dev" {
		t.Errorf("alice = %+v", users[0])
	}
	if users[1].Username != "bob" || len(users[1].Groups) != 0 {
		t.Errorf("bob = %+v", users[1])
	}
}

func TestAuditSearchPaginationUndStreaming(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()

	maxBefore, err := testStore.MaxAuditEventID(ctx)
	mustNoErr(t, err)
	if maxBefore != 0 {
		t.Fatalf("max id auf leerer tabelle = %d", maxBefore)
	}

	events := []store.AuditEvent{
		{EventType: "ca.cert_issued", Actor: "user:alice@idp", Payload: json.RawMessage(`{"host":"web-1"}`)},
		{EventType: "ca.cert_issued", Actor: "ci:infra/ansible:42:7", Payload: json.RawMessage(`{"pipeline_id":42}`)},
		{EventType: "grant.created", Actor: "user:admin@idp", Payload: json.RawMessage(`{"principals":["deploy"]}`)},
	}
	for i := range events {
		mustNoErr(t, testStore.AppendAuditEvent(ctx, &events[i]))
	}

	// Suche über Payload (Host) und Actor (Pipeline), case-insensitiv.
	byHost, err := testStore.ListAuditEvents(ctx, store.AuditFilter{Search: "WEB-1"})
	mustNoErr(t, err)
	if len(byHost) != 1 || byHost[0].ID != events[0].ID {
		t.Errorf("suche host = %+v", byHost)
	}
	byPipeline, err := testStore.ListAuditEvents(ctx, store.AuditFilter{Search: "infra/ansible"})
	mustNoErr(t, err)
	if len(byPipeline) != 1 || byPipeline[0].ID != events[1].ID {
		t.Errorf("suche pipeline = %+v", byPipeline)
	}

	// Pagination: neueste zuerst, Offset überspringt.
	page, err := testStore.ListAuditEvents(ctx, store.AuditFilter{Limit: 2, Offset: 1})
	mustNoErr(t, err)
	if len(page) != 2 || page[0].ID != events[1].ID || page[1].ID != events[0].ID {
		t.Errorf("pagination = %+v", page)
	}

	total, err := testStore.CountAuditEvents(ctx, store.AuditFilter{})
	mustNoErr(t, err)
	if total != 3 {
		t.Errorf("count = %d", total)
	}
	issued, err := testStore.CountAuditEvents(ctx, store.AuditFilter{EventType: "ca.cert_issued"})
	mustNoErr(t, err)
	if issued != 2 {
		t.Errorf("count cert_issued = %d", issued)
	}

	// Streaming: alles nach einer ID, aufsteigend, mit Limit.
	after, err := testStore.ListAuditEventsAfter(ctx, events[0].ID, 10)
	mustNoErr(t, err)
	if len(after) != 2 || after[0].ID != events[1].ID || after[1].ID != events[2].ID {
		t.Errorf("after = %+v", after)
	}
	limited, err := testStore.ListAuditEventsAfter(ctx, 0, 1)
	mustNoErr(t, err)
	if len(limited) != 1 || limited[0].ID != events[0].ID {
		t.Errorf("after limit = %+v", limited)
	}
	maxID, err := testStore.MaxAuditEventID(ctx)
	mustNoErr(t, err)
	if maxID != events[2].ID {
		t.Errorf("max id = %d, erwartet %d", maxID, events[2].ID)
	}
}

func TestSetServiceAccountActive(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()

	sa, err := testStore.EnsureCIServiceAccount(ctx, "https://gitlab.example.com", "infra/ansible")
	mustNoErr(t, err)
	if !sa.Active {
		t.Fatal("neuer service-account nicht aktiv")
	}

	updated, err := testStore.SetServiceAccountActive(ctx, "user:admin@idp", sa.ID, false)
	mustNoErr(t, err)
	if updated.Active {
		t.Error("active nicht auf false gesetzt")
	}

	// Audit-Event mit Actor in derselben Transaktion.
	auditEvents, err := testStore.ListAuditEvents(ctx, store.AuditFilter{EventType: store.EventServiceAccountUpdated})
	mustNoErr(t, err)
	if len(auditEvents) != 1 || auditEvents[0].Actor != "user:admin@idp" {
		t.Fatalf("audit = %+v", auditEvents)
	}
	var payload map[string]any
	mustNoErr(t, json.Unmarshal(auditEvents[0].Payload, &payload))
	if payload["name"] != "infra/ansible" || payload["active"] != false {
		t.Errorf("payload = %v", payload)
	}

	_, err = testStore.SetServiceAccountActive(ctx, "user:admin@idp", uuid.New(), true)
	wantNotFound(t, err)
}
