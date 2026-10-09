// Package api is the panel's HTTP side: sign-in, sessions and the /api/v1
// endpoints, built on the standard library only.
package api

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	hashScheme  = "pbkdf2-sha256"
	hashIter    = 310000
	hashMaxIter = 5_000_000
	hashKeyLen  = 32
	saltLen     = 16
)

var b64 = base64.RawStdEncoding

// HashPassword returns "pbkdf2-sha256$iterations$salt$hash". PBKDF2 is what the
// standard library offers; with this many rounds and a long password it is
// slow enough to make guessing pointless.
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, hashIter, hashKeyLen)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s$%d$%s$%s", hashScheme, hashIter, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

type parsedHash struct {
	iter int
	salt []byte
	key  []byte
}

func parseHash(encoded string) (parsedHash, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != hashScheme {
		return parsedHash{}, errors.New("unsupported hash format")
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 100_000 || iter > hashMaxIter {
		return parsedHash{}, errors.New("bad iteration count")
	}
	salt, err := b64.DecodeString(parts[2])
	if err != nil || len(salt) < 8 {
		return parsedHash{}, errors.New("bad salt")
	}
	key, err := b64.DecodeString(parts[3])
	if err != nil || len(key) < 16 {
		return parsedHash{}, errors.New("bad hash")
	}
	return parsedHash{iter: iter, salt: salt, key: key}, nil
}

// verify reports whether the password matches, in time that does not depend on
// how much of it matched.
func (h parsedHash) verify(password string) bool {
	got, err := pbkdf2.Key(sha256.New, password, h.salt, h.iter, len(h.key))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, h.key) == 1
}
