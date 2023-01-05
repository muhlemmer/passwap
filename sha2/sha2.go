package sha2

import (
	"crypto/subtle"
	"fmt"
	"io"
	"strings"

	"github.com/muhlemmer/passwap/internal/salt"
	"github.com/muhlemmer/passwap/verifier"
)

const (
	Identifier_SHA256 = "5"
	Identifier_SHA512 = "6"
	Prefix_SHA256     = "$" + Identifier_SHA256 + "$"
	Prefix_SHA512     = "$" + Identifier_SHA512 + "$"
)

type checker struct {
	crypt  func(password, salt []byte, rounds uint32) []byte
	rounds uint32
	salt   []byte
	hash   []byte
}

func (c *checker) verify(password string) verifier.Result {
	hash := c.crypt([]byte(password), c.salt, c.rounds)

	return verifier.Result(
		subtle.ConstantTimeCompare(hash, c.hash),
	)
}

var scanFormat = strings.ReplaceAll(Format, "$", " ")

func parse(encoded string) (*checker, error) {
	if !strings.HasPrefix(encoded, Prefix_SHA256) && !strings.HasPrefix(encoded, Prefix_SHA512) {
		return nil, nil
	}

	// scanning needs a space seperated string, instead of dollar signs.
	encoded = strings.ReplaceAll(encoded, "$", " ")
	var (
		c  checker
		id string
	)

	_, err := fmt.Sscanf(encoded, scanFormat, &id, &c.rounds, &c.salt, &c.hash)
	if err != nil {
		return nil, fmt.Errorf("md5 parse: %w", err)
	}

	switch id {
	case Identifier_SHA256:
		c.crypt = sha256Crypt
	case Identifier_SHA512:
		c.crypt = sha512Crypt
	default:
		return nil, fmt.Errorf("sha2: unknown identifier: %s", id)
	}

	return &c, nil
}

func Verify(encoded, password string) (verifier.Result, error) {
	c, err := parse(encoded)
	if err != nil || c == nil {
		return verifier.Skip, err
	}

	return c.verify(password), nil
}

const (
	DefaultRoundsSHA256 = 535000
	DefaultRoundsSHA512 = 656000
	MinRounds           = 1000
	MaxRounds           = 999999999

	MaxPasswordLength_SHA256 = 80
	MaxPasswordLength_SHA512 = 123

	MaxSaltLength = 16
)

func checkRounds(rounds, defaultRounds uint32) uint32 {
	if rounds == 0 {
		return defaultRounds
	}
	if rounds < MinRounds {
		return MinRounds
	}
	if rounds > MaxRounds {
		return MaxRounds
	}

	return rounds
}

func checkSaltLength(saltLength uint32) uint32 {
	if saltLength > MaxSaltLength {
		return MaxSaltLength
	}

	return saltLength
}

type Hasher struct {
	ident             string
	crypt             func(password, salt []byte, rounds uint32) []byte
	rounds            uint32
	maxPasswordLength int
	saltLength        uint32
	reader            io.Reader
}

func NewSHA256(rounds, saltLength uint32) *Hasher {
	return &Hasher{
		ident:             Identifier_SHA256,
		crypt:             sha256Crypt,
		rounds:            checkRounds(rounds, DefaultRoundsSHA256),
		saltLength:        checkSaltLength(saltLength),
		maxPasswordLength: MaxPasswordLength_SHA256,
	}
}

func NewSHA512(rounds, saltLength uint32) *Hasher {
	return &Hasher{
		ident:             Identifier_SHA512,
		crypt:             sha512Crypt,
		rounds:            checkRounds(rounds, DefaultRoundsSHA512),
		saltLength:        checkSaltLength(saltLength),
		maxPasswordLength: MaxPasswordLength_SHA512,
	}
}

const Format = "$%s$rounds=%d$%s$%s"

func (h *Hasher) Hash(password string) (encoded string, err error) {
	salt, err := salt.Hash64(h.reader, h.saltLength)
	if err != nil {
		return "", fmt.Errorf("sha2: %w", err)
	}

	hash := h.crypt([]byte(password), salt, h.rounds)
	return fmt.Sprintf(Format, h.ident, h.rounds, salt, hash), nil
}

func (h *Hasher) Verify(encoded, password string) (verifier.Result, error) {
	c, err := parse(encoded)
	if err != nil || c == nil {
		return verifier.Skip, err
	}

	if result := c.verify(password); result != verifier.OK {
		return result, nil
	}

	if c.rounds != h.rounds || len(c.salt) != int(h.saltLength) {
		return verifier.NeedUpdate, nil
	}

	return verifier.OK, nil
}
