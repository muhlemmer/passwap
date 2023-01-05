// Package salt provides utilities for generating salts.
package salt

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/muhlemmer/passwap/internal/hash64"
)

const RecommendedSize = 16

var Reader = rand.Reader

func New(from io.Reader, size uint32) ([]byte, error) {
	salt := make([]byte, size)

	if _, err := from.Read(salt); err != nil {
		return nil, fmt.Errorf("salt: %w", err)
	}

	return salt, nil
}

func Hash64(from io.Reader, size uint32) ([]byte, error) {
	out, err := New(from, size)
	if err != nil {
		return nil, err
	}

	for i, v := range out {
		out[i] = hash64.Encoding[v%63]
	}

	return out, nil
}

// ErrReader can be used to mock errors while reading salt.
type ErrReader struct{}

func (ErrReader) Read([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}
