// Package web embeds the Angular build of the web UI into the server binary
// (embed.FS, ADR-003): one image, no CORS, simple Helm deployment.
package web

import "embed"

// Dist contains the Angular build from `make web` (output to web/dist).
// Without a build, only the .gitkeep placeholder lives here; the server then
// responds with 503 under /, while the API remains fully functional.
//
//go:embed all:dist
var Dist embed.FS
