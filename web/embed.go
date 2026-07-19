// Package web bettet den Angular-Build der Web-UI ins Server-Binary ein
// (embed.FS, ADR-003): ein Image, kein CORS, einfaches Helm-Deployment.
package web

import "embed"

// Dist enthält den Angular-Build aus `make web` (Ausgabe nach web/dist).
// Ohne Build liegt hier nur der Platzhalter .gitkeep; der Server antwortet
// dann unter / mit 503, die API bleibt voll funktionsfähig.
//
//go:embed all:dist
var Dist embed.FS
