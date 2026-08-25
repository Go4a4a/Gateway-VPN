// Package migrations contains the immutable database migration set shipped with
// a Gateway VPN binary.
package migrations

import "embed"

// Files contains every versioned SQL migration.
//
//go:embed *.sql
var Files embed.FS
