package rsakeygen

import (
	"crypto/hmac"
	"crypto/sha256"
)

// hmacDigest returns the HMAC-SHA-256 digest of data under key.
func hmacDigest(key, data []byte) [sha256.Size]byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	var digest [sha256.Size]byte
	copy(digest[:], mac.Sum(nil))
	return digest
}

// hkdfExtract returns the RFC 5869 pseudorandom key extracted from the input
// key material with the given salt: PRK = HMAC-SHA-256(salt, ikm).
func hkdfExtract(salt, ikm []byte) []byte {
	mac := hmac.New(sha256.New, salt)
	_, _ = mac.Write(ikm)
	return mac.Sum(nil)
}

// hkdfExpand returns length bytes of RFC 5869 output keying material expanded
// from the pseudorandom key and info. It supports the single-block case where
// length does not exceed the SHA-256 output size; any other length is a
// programming error and panics.
func hkdfExpand(prk, info []byte, length int) []byte {
	if length < 0 || length > sha256.Size {
		panic("rsakeygen: hkdfExpand length must be between 0 and 32")
	}
	mac := hmac.New(sha256.New, prk)
	_, _ = mac.Write(info)
	_, _ = mac.Write([]byte{0x01})
	return mac.Sum(nil)[:length]
}
