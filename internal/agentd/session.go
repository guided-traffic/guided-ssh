package agentd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"time"
)

const (
	// sessionFlushInterval is the interval at which the spool is flushed to
	// the server.
	sessionFlushInterval = 15 * time.Second
	// authWindow: how long a serial reported at login remains a candidate
	// for correlating a following session open.
	authWindow = 2 * time.Minute
	// maxSpoolBytes caps the spool in case the server is unreachable for a
	// while (loss-tolerant: new events beyond this are dropped).
	maxSpoolBytes = 1 << 20
	// maxFlushBatch limits the events per flush request.
	maxFlushBatch = 500
)

// authRec is a serial seen at login (from %s/%i), a candidate for
// correlating the next session open of the same local user.
type authRec struct {
	serial int64
	keyid  string
	at     time.Time
}

// checkToken verifies the token of the writable socket endpoints.
func (d *Daemon) checkToken(r *http.Request) bool {
	return d.token != "" && r.Header.Get(socketTokenHeader) == d.token
}

// handleAuth accepts a serial reported at login (POST /auth).
func (d *Daemon) handleAuth(w http.ResponseWriter, r *http.Request) {
	if !d.checkToken(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var rec authRecord
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&rec); err != nil || rec.User == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	d.recordAuth(rec)
	w.WriteHeader(http.StatusNoContent)
}

// recordAuth stores the serial in the recentAuth ring and drops expired entries.
func (d *Daemon) recordAuth(rec authRecord) {
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	fresh := d.recentAuth[rec.User][:0:0]
	for _, a := range d.recentAuth[rec.User] {
		if now.Sub(a.at) < authWindow {
			fresh = append(fresh, a)
		}
	}
	fresh = append(fresh, authRec{serial: rec.Serial, keyid: rec.KeyID, at: now})
	d.recentAuth[rec.User] = fresh
}

// takeSerial returns the most recent still-valid serial for a user and
// removes it (a session open consumes one login report).
func (d *Daemon) takeSerial(user string) (int64, string) {
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	recs := d.recentAuth[user]
	for i := len(recs) - 1; i >= 0; i-- {
		if now.Sub(recs[i].at) >= authWindow {
			continue
		}
		serial, keyid := recs[i].serial, recs[i].keyid
		d.recentAuth[user] = append(recs[:i], recs[i+1:]...)
		return serial, keyid
	}
	return 0, ""
}

// handleSessionEvent accepts a pam session event (POST /session-event),
// enriches sshd opens with the correlated serial, and spools it.
func (d *Daemon) handleSessionEvent(w http.ResponseWriter, r *http.Request) {
	if !d.checkToken(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var ev sessionEventWire
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&ev); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if ev.Service == "sshd" && ev.Phase == "open" && ev.Serial == 0 {
		ev.Serial, ev.KeyID = d.takeSerial(ev.LocalUser)
	}
	if err := d.spoolAppend(ev); err != nil {
		d.logger.Warn("spooling session event failed", "error", err)
		http.Error(w, "spool error", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// spoolAppend appends an event as a JSON line to the spool (0600). Events
// beyond the size limit are dropped (loss-tolerant, logged).
func (d *Daemon) spoolAppend(ev sessionEventWire) error {
	line, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	d.spoolMu.Lock()
	defer d.spoolMu.Unlock()
	if info, statErr := os.Stat(d.paths.SpoolFile()); statErr == nil && info.Size() > maxSpoolBytes {
		d.logger.Warn("session spool full — event dropped", "size", info.Size())
		return nil
	}
	f, err := os.OpenFile(d.paths.SpoolFile(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(line, '\n'))
	return err
}

// flushSpool sends the buffered events to the server. The spool is taken
// under lock (file cleared) and only the network send happens outside the
// lock; on error the events are written back.
func (d *Daemon) flushSpool(ctx context.Context) {
	d.spoolMu.Lock()
	raw, err := os.ReadFile(d.paths.SpoolFile())
	if err != nil || len(raw) == 0 {
		d.spoolMu.Unlock()
		return
	}
	if err := os.Truncate(d.paths.SpoolFile(), 0); err != nil {
		d.spoolMu.Unlock()
		d.logger.Warn("clearing session spool failed", "error", err)
		return
	}
	d.spoolMu.Unlock()

	events := parseSpool(raw)
	if len(events) == 0 {
		return
	}
	if len(events) > maxFlushBatch {
		// Write the remainder back, keep the batch bounded.
		d.requeueSpool(mustMarshalLines(events[maxFlushBatch:]))
		events = events[:maxFlushBatch]
	}
	if err := d.api.SendSessions(ctx, events); err != nil {
		d.logger.Warn("flushing session events failed — requeued", "count", len(events), "error", err)
		d.requeueSpool(mustMarshalLines(events))
		return
	}
	d.logger.Info("session events flushed", "count", len(events))
}

// requeueSpool writes events (already as lines) back to the start of the spool.
func (d *Daemon) requeueSpool(lines []byte) {
	if len(lines) == 0 {
		return
	}
	d.spoolMu.Lock()
	defer d.spoolMu.Unlock()
	existing, _ := os.ReadFile(d.paths.SpoolFile())
	// G703 false positive: SpoolFile() is StateDir + a fixed filename
	// (config.go), no user/network input — path traversal is not possible.
	if err := os.WriteFile(d.paths.SpoolFile(), append(lines, existing...), 0o600); err != nil { //nolint:gosec // see comment above
		d.logger.Warn("writing back session spool failed", "error", err)
	}
}

// parseSpool splits spool bytes into events (unreadable lines are skipped).
func parseSpool(raw []byte) []sessionEventWire {
	var events []sessionEventWire
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var ev sessionEventWire
		if err := json.Unmarshal(line, &ev); err == nil {
			events = append(events, ev)
		}
	}
	return events
}

// mustMarshalLines serializes events as JSON lines (errors are skipped).
func mustMarshalLines(events []sessionEventWire) []byte {
	var buf bytes.Buffer
	for _, ev := range events {
		line, err := json.Marshal(ev)
		if err != nil {
			continue
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}
