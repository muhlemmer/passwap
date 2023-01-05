package sha2

import (
	"bytes"
	"testing"

	"github.com/muhlemmer/passwap/internal/testvalues"
)

func Test_sha256Crypt(t *testing.T) {
	want := testvalues.ChecksumSHA256
	got := sha256Crypt([]byte(testvalues.Password), []byte(testvalues.Salt), testvalues.RoundsSHA2)

	if !bytes.Equal(got, want) {
		t.Errorf("sha256Crypt() =\n%s\nwant\n%s", got, want)
	}
}

func Test_sha256Crypt2(t *testing.T) {
	want := testvalues.ChecksumSHA256
	got := sha256Crypt2([]byte(testvalues.Password), []byte(testvalues.Salt), testvalues.RoundsSHA2)

	if !bytes.Equal(got, want) {
		t.Errorf("sha256Crypt() =\n%s\nwant\n%s", got, want)
	}
}
