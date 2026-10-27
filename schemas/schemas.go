// Package schemas embeds the cross-repo contract files so Go code and tests
// read exactly the bytes that Scan and Guard consume.
package schemas

import "embed"

//go:embed jsonschema/*.json openapi/*.yaml vectors/*.json
var FS embed.FS
