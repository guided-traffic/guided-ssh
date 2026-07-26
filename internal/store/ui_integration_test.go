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

// Phase 8: store methods of the web UI (hosts with tags/cert expiry, users
// with groups, audit search/pagination/streaming, service account kill switch).

func TestListHostsDetailed(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()

	h1 := &store.Host{Name: "web-1"}
	mustNoErr(t, testStore.CreateHost(ctx, h1))
	mustNoErr(t, testStore.SetHostTags(ctx, h1.ID, map[string]string{"env": "prod", "role": "web"}))
	h2 := &store.Host{Name: "db-1"}
	mustNoErr(t, testStore.CreateHost(ctx, h2))

	// Host certificates: the latest valid_before counts; user certificates do not.
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
	// Sorted by name: db-1 before web-1.
	if hosts[0].Name != "db-1" || hosts[1].Name != "web-1" {
		t.Fatalf("order: %s, %s", hosts[0].Name, hosts[1].Name)
	}
	if len(hosts[0].Tags) != 0 || hosts[0].CertValidBefore != nil {
		t.Errorf("expected db-1 without tags/cert: %+v", hosts[0])
	}
	web := hosts[1]
	if web.Tags["env"] != "prod" || web.Tags["role"] != "web" {
		t.Errorf("tags = %v", web.Tags)
	}
	if web.CertValidBefore == nil || !web.CertValidBefore.Equal(now.Add(30*24*time.Hour)) {
		t.Errorf("cert_valid_before = %v, want the max of the host certificates", web.CertValidBefore)
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

func TestAuditSearchPaginationAndStreaming(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()

	maxBefore, err := testStore.MaxAuditEventID(ctx)
	mustNoErr(t, err)
	if maxBefore != 0 {
		t.Fatalf("max id on an empty table = %d", maxBefore)
	}

	events := []store.AuditEvent{
		{EventType: "ca.cert_issued", Actor: "user:alice@idp", Payload: json.RawMessage(`{"host":"web-1"}`)},
		{EventType: "ca.cert_issued", Actor: "ci:infra/ansible:42:7", Payload: json.RawMessage(`{"pipeline_id":42}`)},
		{EventType: "grant.created", Actor: "user:admin@idp", Payload: json.RawMessage(`{"principals":["deploy"]}`)},
	}
	for i := range events {
		mustNoErr(t, testStore.AppendAuditEvent(ctx, &events[i]))
	}

	// Search over payload (host) and actor (pipeline), case-insensitive.
	byHost, err := testStore.ListAuditEvents(ctx, store.AuditFilter{Search: "WEB-1"})
	mustNoErr(t, err)
	if len(byHost) != 1 || byHost[0].ID != events[0].ID {
		t.Errorf("search host = %+v", byHost)
	}
	byPipeline, err := testStore.ListAuditEvents(ctx, store.AuditFilter{Search: "infra/ansible"})
	mustNoErr(t, err)
	if len(byPipeline) != 1 || byPipeline[0].ID != events[1].ID {
		t.Errorf("search pipeline = %+v", byPipeline)
	}

	// Pagination: newest first, offset skips ahead.
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

	// Streaming: everything after an ID, ascending, with a limit.
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
		t.Errorf("max id = %d, want %d", maxID, events[2].ID)
	}
}

func TestSetServiceAccountActive(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()

	sa, err := testStore.EnsureCIServiceAccount(ctx, "https://gitlab.example.com", "infra/ansible")
	mustNoErr(t, err)
	if !sa.Active {
		t.Fatal("new service account is not active")
	}

	updated, err := testStore.SetServiceAccountActive(ctx, "user:admin@idp", sa.ID, false)
	mustNoErr(t, err)
	if updated.Active {
		t.Error("active was not set to false")
	}

	// Audit event with actor in the same transaction.
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
