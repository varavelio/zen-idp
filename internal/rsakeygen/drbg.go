package rsakeygen

import "crypto/sha256"

// drbg is a HMAC-DRBG-SHA-256 instance as specified by NIST SP 800-90A
// Rev. 1. It is used without additional input, prediction resistance, or
// reseeding, which keeps the derivation fully deterministic.
type drbg struct {
	key   [sha256.Size]byte
	value [sha256.Size]byte
}

// newDRBG instantiates a stream with the given seed as its complete seed
// material.
func newDRBG(seed []byte) *drbg {
	stream := &drbg{}
	for index := range stream.value {
		stream.value[index] = 0x01
	}
	stream.update(append([]byte{0x00}, seed...))
	stream.update(append([]byte{0x01}, seed...))
	return stream
}

// generate returns the next length bytes of output and performs the standard
// post-generation update with empty additional input.
func (stream *drbg) generate(length int) []byte {
	output := make([]byte, 0, length)
	for len(output) < length {
		stream.value = hmacDigest(stream.key[:], stream.value[:])
		output = append(output, stream.value[:]...)
	}
	stream.update(nil)
	return output[:length]
}

// update applies the SP 800-90A update procedure with the provided data.
func (stream *drbg) update(providedData []byte) {
	stream.key = hmacDigest(stream.key[:], append(stream.value[:], providedData...))
	stream.value = hmacDigest(stream.key[:], stream.value[:])
}
