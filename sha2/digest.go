package sha2

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"github.com/muhlemmer/passwap/internal/hash64"
)

// digest implements https://akkadia.org/drepper/SHA-crypt.txt
// steps 1 till 21.
func digest(digest hash.Hash, password, salt []byte, rounds uint32) []byte {
	/*
		4.  start digest B
		5.  add the password to digest B
		6.  add the salt string to digest B
		7.  add the password again to digest B
		8.  finish digest B
	*/
	digest.Reset()
	digest.Write(password)
	digest.Write(salt)
	digest.Write(password)
	outB := digest.Sum(nil)

	/*
		1.  start digest A
		2.  the password string is added to digest A
		3.  the salt string is added to digest A.  This is just the salt string
		    itself without the enclosing '$', without the magic prefix $5$ and
		    $6$ respectively and without the rounds=<N> specification.

		    NB: the MD5 algorithm did add the $1$ prefix.  This is not deemed
		    necessary since it is a constant string and does not add security
		    and /possibly/ allows a plain text attack.  Since the rounds=<N>
		    specification should never be added this would also create an
		    inconsistency.
	*/
	digest.Reset()
	digest.Write(password)
	digest.Write(salt)

	/*
		9.  For each block of 32 or 64 bytes in the password string (excluding
			the terminating NUL in the C representation), add digest B to digest A
		10. For the remaining N bytes of the password string add the first
			N bytes of digest B to digest A
	*/
	size := digest.Size()
	for i := 0; i < len(password); i++ {
		digest.Write([]byte{outB[i%size]})
	}

	/*
		11. For each bit of the binary representation of the length of the
			password string up to and including the highest 1-digit, starting
			from to lowest bit position (numeric value 1):

			a) for a 1-digit add digest B to digest A

			b) for a 0-digit add the password string

			NB: this step differs significantly from the MD5 algorithm.  It
			adds more randomness.
	*/
	for i := len(password); i != 0; i >>= 1 {
		if i&1 == 1 {
			digest.Write(outB)
			continue
		}
		digest.Write(password)
	}

	// 12. finish digest A
	outA := digest.Sum(nil)

	/*
		13. start digest DP
		14. for every byte in the password (excluding the terminating NUL byte
			in the C representation of the string) add the password to digest DP
		15. finish digest DP
	*/
	digest.Reset()
	for i := 0; i < len(password); i++ {
		digest.Write(password)
	}
	outDP := digest.Sum(nil)

	/*
		16. produce byte sequence P of the same length as the password where

		    a) for each block of 32 or 64 bytes of length of the password string
		       the entire digest DP is used

		    b) for the remaining N (up to  31 or 63) bytes use the first N
		       bytes of digest DP
	*/
	seqP := make([]byte, len(password))
	for i := 0; i < len(password); i++ {
		seqP[i] = outDP[i&size]
	}

	/*
		17. start digest DS
		18. repeat the following 16+A[0] times, where A[0] represents the first
		    byte in digest A interpreted as an 8-bit unsigned value add the salt to digest DS
		19. finish digest DS
	*/
	digest.Reset()
	for i := uint8(0); i < 16+uint8(outA[0]); i++ {
		digest.Write(salt)
	}
	outDS := digest.Sum(nil)

	/*
		20. produce byte sequence S of the same length as the salt string where

		    a) for each block of 32 or 64 bytes of length of the salt string
		       the entire digest DS is used

		    b) for the remaining N (up to  31 or 63) bytes use the first N
		       bytes of digest DS
	*/
	seqS := make([]byte, len(salt))
	for i := 0; i < len(salt); i++ {
		seqS[i] = outDS[i&size]
	}

	/*
	   	21. repeat a loop according to the number specified in the rounds=<N>
	       specification in the salt (or the default value if none is
	       present).  Each round is numbered, starting with 0 and up to N-1.

	       The loop uses a digest as input.  In the first round it is the
	       digest produced in step 12.  In the latter steps it is the digest
	       produced in step 21.h of the previous round.  The following text
	       uses the notation "digest A/C" to describe this behavior.
	*/
	outAC := outA
	for i := uint32(0); i < rounds; i++ {
		// a) start digest C
		digest.Reset()

		// b) for odd round numbers add the byte sequense P to digest C
		// c) for even round numbers add digest A/C
		if i&1 == 1 {
			digest.Write(seqP)
		} else {
			digest.Write(outAC)
		}

		// d) for all round numbers not divisible by 3 add the byte sequence S
		if i%3 != 0 {
			digest.Write(seqS)
		}

		// e) for all round numbers not divisible by 7 add the byte sequence P
		if i%7 != 0 {
			digest.Write(seqP)
		}

		// f) for odd round numbers add digest A/C
		// g) for even round numbers add the byte sequence P
		if i&1 == 1 {
			digest.Write(outAC)
		} else {
			digest.Write(seqP)
		}

		// h) finish digest C.
		outAC = digest.Sum(nil)
	}

	return outAC
}

var (
	/*
		sha256Matrix = [sha256.Size]int{
			20, 10, 0,
			11, 1, 21,
			2, 22, 12,
			23, 13, 3,
			14, 4, 24,
			5, 25, 15,
			26, 16, 6,
			17, 7, 27,
			8, 28, 18,
			29, 19, 9,
			30, 31,
		}
	*/
	sha256Matrix = [][]int{
		{0, 10, 20},
		{21, 1, 11},
		{12, 22, 2},
		{3, 13, 23},
		{24, 4, 14},
		{15, 25, 5},
		{6, 16, 26},
		{27, 7, 17},
		{18, 28, 8},
		{9, 19, 29},
		{30, 31},
	}

	sha512Swap = [sha512.Size]int{
		42, 21, 0,
		1, 43, 22,
		23, 2, 44,
		45, 24, 3,
		4, 46, 25,
		26, 5, 47,
		48, 27, 6,
		7, 49, 28,
		29, 8, 50,
		51, 30, 9,
		10, 52, 31,
		32, 11, 53,
		54, 33, 12,
		13, 55, 34,
		35, 14, 56,
		57, 36, 15,
		16, 58, 37,
		38, 17, 59,
		60, 39, 18,
		19, 61, 40,
		41, 20, 62,
		63,
	}
)

const b64t = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func encodeDigest(matrix [][]int, digest []byte) []byte {
	var buf bytes.Buffer
	buf.Grow((len(digest)*4 + 3 - 1) / 3)

	for _, row := range matrix {
		var w int
		for i := len(row) - 1; i >= 0; i-- {
			w |= row[i] << (i * 8)
		}

		for n := len(row) + 1; n > 0; n-- {
			buf.WriteByte(b64t[w&0x3f])
			w >>= 6
		}
	}

	return buf.Bytes()
}

// sha256Crypt implements https://akkadia.org/drepper/SHA-crypt.txt
// and produces the encoded password part for sha256.
func sha256Crypt(password, salt []byte, rounds uint32) []byte {
	digest := digest(sha256.New(), password, salt, rounds)

	return encodeDigest(sha256Matrix, digest)
}

func b64_from_24bit(B2, B1, B0 byte, N int, buf *bytes.Buffer) {
	var w uint = (uint(B2) << 16) | (uint(B1) << 8) | uint(B0)
	for n := N; n > 0; n-- {
		buf.WriteByte(b64t[w&0x3f])
		w >>= 6
	}
}

// sha256Crypt implements https://akkadia.org/drepper/SHA-crypt.txt
// and produces the encoded password part for sha256.
func sha256Crypt2(password, salt []byte, rounds uint32) []byte {
	alt_result := digest(sha256.New(), password, salt, rounds)
	var buf bytes.Buffer
	buf.Grow((len(alt_result)*4 + 3 - 1) / 3)

	b64_from_24bit(alt_result[0], alt_result[10], alt_result[20], 4, &buf)
	b64_from_24bit(alt_result[21], alt_result[1], alt_result[11], 4, &buf)
	b64_from_24bit(alt_result[12], alt_result[22], alt_result[2], 4, &buf)
	b64_from_24bit(alt_result[3], alt_result[13], alt_result[23], 4, &buf)
	b64_from_24bit(alt_result[24], alt_result[4], alt_result[14], 4, &buf)
	b64_from_24bit(alt_result[15], alt_result[25], alt_result[5], 4, &buf)
	b64_from_24bit(alt_result[6], alt_result[16], alt_result[26], 4, &buf)
	b64_from_24bit(alt_result[27], alt_result[7], alt_result[17], 4, &buf)
	b64_from_24bit(alt_result[18], alt_result[28], alt_result[8], 4, &buf)
	b64_from_24bit(alt_result[9], alt_result[19], alt_result[29], 4, &buf)
	b64_from_24bit(0, alt_result[31], alt_result[30], 3, &buf)

	return buf.Bytes()
}

// sha512Crypt implements https://akkadia.org/drepper/SHA-crypt.txt
// and produces the encoded password part for sha512.
func sha512Crypt(password, salt []byte, rounds uint32) []byte {
	digest := digest(sha512.New(), password, salt, rounds)
	out := make([]byte, len(digest))

	for i, j := range sha512Swap {
		out[i] = digest[j]
	}

	return hash64.Encode(out)
}
