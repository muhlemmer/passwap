package hash64

const (
	// Encoding is the character set used for encoding salt and checksum.
	Encoding = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

func Encode(raw []byte) []byte {
	dest := make([]byte, 0, (len(raw)*4+3-1)/3)

	v := uint(0)
	bits := uint(0)

	for _, b := range raw {
		v |= (uint(b) << bits)

		for bits = bits + 8; bits > 6; bits -= 6 {
			dest = append(dest, Encoding[v&63])
			v >>= 6
		}
	}
	dest = append(dest, Encoding[v&63])
	return dest
}
