// Package migrations embeds the forward-only SQL migrations so the store's
// migrator applies exactly the files in this directory, in name order.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
