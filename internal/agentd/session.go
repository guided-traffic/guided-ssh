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
	// sessionFlushInterval ist das Intervall, in dem der Spool an den Server
	// geflusht wird.
	sessionFlushInterval = 15 * time.Second
	// authWindow: so lange gilt ein am Login gemeldeter Serial als Kandidat für
	// die Korrelation einer folgenden Session-Open.
	authWindow = 2 * time.Minute
	// maxSpoolBytes deckelt den Spool, falls der Server länger nicht erreichbar
	// ist (verlust-tolerant: darüber werden neue Events verworfen).
	maxSpoolBytes = 1 << 20
	// maxFlushBatch begrenzt die Events pro Flush-Request.
	maxFlushBatch = 500
)

// authRec ist ein am Login gesehener Serial (aus %s/%i), Kandidat für die
// Korrelation der nächsten Session-Open desselben lokalen Benutzers.
type authRec struct {
	serial int64
	keyid  string
	at     time.Time
}

// checkToken verifiziert das Token der schreibenden Socket-Endpunkte.
func (d *Daemon) checkToken(r *http.Request) bool {
	return d.token != "" && r.Header.Get(socketTokenHeader) == d.token
}

// handleAuth nimmt einen am Login gemeldeten Serial entgegen (POST /auth).
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

// recordAuth legt den Serial in den recentAuth-Ring und entfernt Abgelaufenes.
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

// takeSerial liefert den jüngsten noch gültigen Serial für einen Benutzer und
// entfernt ihn (eine Session-Open verbraucht eine Login-Meldung).
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

// handleSessionEvent nimmt ein pam-Session-Event entgegen (POST /session-event),
// reichert sshd-Opens mit dem korrelierten Serial an und spoolt es.
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
		d.logger.Warn("session-event spoolen fehlgeschlagen", "error", err)
		http.Error(w, "spool error", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// spoolAppend hängt ein Event als JSON-Zeile an den Spool an (0600). Über dem
// Größenlimit wird verworfen (verlust-tolerant, geloggt).
func (d *Daemon) spoolAppend(ev sessionEventWire) error {
	line, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	d.spoolMu.Lock()
	defer d.spoolMu.Unlock()
	if info, statErr := os.Stat(d.paths.SpoolFile()); statErr == nil && info.Size() > maxSpoolBytes {
		d.logger.Warn("session-spool voll — event verworfen", "size", info.Size())
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

// flushSpool sendet die gepufferten Events an den Server. Der Spool wird unter
// Lock übernommen (Datei geleert) und nur die Netzwerk-Sendung außerhalb des
// Locks ausgeführt; bei Fehler werden die Events zurückgeschrieben.
func (d *Daemon) flushSpool(ctx context.Context) {
	d.spoolMu.Lock()
	raw, err := os.ReadFile(d.paths.SpoolFile())
	if err != nil || len(raw) == 0 {
		d.spoolMu.Unlock()
		return
	}
	if err := os.Truncate(d.paths.SpoolFile(), 0); err != nil {
		d.spoolMu.Unlock()
		d.logger.Warn("session-spool leeren fehlgeschlagen", "error", err)
		return
	}
	d.spoolMu.Unlock()

	events := parseSpool(raw)
	if len(events) == 0 {
		return
	}
	if len(events) > maxFlushBatch {
		// Rest zurückschreiben, Batch begrenzt halten.
		d.requeueSpool(mustMarshalLines(events[maxFlushBatch:]))
		events = events[:maxFlushBatch]
	}
	if err := d.api.SendSessions(ctx, events); err != nil {
		d.logger.Warn("session-events flushen fehlgeschlagen — zurückgestellt", "count", len(events), "error", err)
		d.requeueSpool(mustMarshalLines(events))
		return
	}
	d.logger.Info("session-events geflusht", "count", len(events))
}

// requeueSpool schreibt Events (bereits als Zeilen) zurück an den Spool-Anfang.
func (d *Daemon) requeueSpool(lines []byte) {
	if len(lines) == 0 {
		return
	}
	d.spoolMu.Lock()
	defer d.spoolMu.Unlock()
	existing, _ := os.ReadFile(d.paths.SpoolFile())
	if err := os.WriteFile(d.paths.SpoolFile(), append(lines, existing...), 0o600); err != nil {
		d.logger.Warn("session-spool zurückschreiben fehlgeschlagen", "error", err)
	}
}

// parseSpool zerlegt Spool-Bytes in Events (unlesbare Zeilen werden übersprungen).
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

// mustMarshalLines serialisiert Events als JSON-Lines (Fehler übersprungen).
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
