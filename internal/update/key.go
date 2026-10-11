package update

import (
	"crypto/ed25519"
	_ "embed"
	"strings"
)

//go:embed publickey.txt
var embeddedKey string

// EmbeddedKey is the build-in signing key, or nil when none was set. With a
// key, unsigned or wrongly signed metadata is rejected; without one the
// metadata is trusted by the HTTPS connection to its fixed source alone, and
// docs/UPDATES.md says so.
func EmbeddedKey() (ed25519.PublicKey, error) {
	for _, line := range strings.Split(embeddedKey, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return ParsePublicKey(line)
	}
	return nil, nil
}
