//go:build !linux && !windows

package source

import (
	"errors"
	"os"
)

func fileIdentity(f *os.File) (string, error) {
	return "", errors.New("persistent file identity requires Linux or Windows")
}
