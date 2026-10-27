// Package wording embeds the public-text registry. Git is its only source of
// truth; the renderer in internal/wording compiles these files in.
package wording

import "embed"

//go:embed blocklist.yaml attribution/*.yaml templates/*/*.yaml vectors/*.json
var FS embed.FS
