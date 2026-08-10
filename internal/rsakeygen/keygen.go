package rsakeygen

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

// domainPrefix is the versioned domain-separation label of the key derivation.
// It is part of the derivation contract and must never change.
const domainPrefix = "zen-idp:jwt:rs256:keygen:v1"

// pInfo and qInfo are the HKDF info strings that derive the two independent
// prime-search seeds from the pseudorandom key.
const (
	pInfo = domainPrefix + ":p"
	qInfo = domainPrefix + ":q"
)

// mrInfo is the prefix of every deterministic Miller-Rabin base message.
const mrInfo = domainPrefix + ":mr:"

// primeSide distinguishes the two independent prime searches in the
// deterministic Miller-Rabin base derivation.
const (
	primeSideP = byte('p')
	primeSideQ = byte('q')
)

// Derivation constants fixed by the contract.
const (
	publicExponent = 65537
	modulusBits    = 2048
	blockSize      = 128 // DRBG output bytes consumed per prime candidate
	// millerRabinRounds is the number of strong Miller-Rabin rounds applied
	// to every candidate.
	millerRabinRounds = 64
	// trialDivisionLimit is the inclusive upper bound of the small-prime
	// trial division.
	trialDivisionLimit = 2039
)

// selfTestMessage is the fixed input hashed by the sign-and-verify
// self-test.
const selfTestMessage = "zen-idp:rsakeygen:self-test"

var (
	bigOne   = big.NewInt(1)
	bigTwo   = big.NewInt(2)
	bigThree = big.NewInt(3)
)

// smallPrimes contains every prime from 3 through trialDivisionLimit
// inclusive, used for cheap trial division before the Miller-Rabin rounds.
var smallPrimes = sievePrimes(trialDivisionLimit)

// GeneratePrivateKey derives the deterministic RSA-2048 private key of the
// given root secret.
//
// The derivation is a pure function of the root secret: the same input always
// reproduces the same key, and different inputs derive different keys with
// overwhelming probability. The key is fully validated, including a
// sign-and-verify self-test, before it is returned and is ready for immediate
// RS256 use.
//
// The key and all intermediate material exist only in process memory and must
// never be persisted, logged, or otherwise exposed.
func GeneratePrivateKey(rootSecret [sha256.Size]byte) (*rsa.PrivateKey, error) {
	domain := []byte(domainPrefix)
	prk := hkdfExtract(domain, rootSecret[:])
	pSeed := hkdfExpand(prk, []byte(pInfo), sha256.Size)
	qSeed := hkdfExpand(prk, []byte(qInfo), sha256.Size)

	pStream := newDRBG(pSeed)
	qStream := newDRBG(qSeed)
	p := findPrime(pStream, primeSideP)
	q := findPrime(qStream, primeSideQ)
	for p.Cmp(q) == 0 {
		q = findPrime(qStream, primeSideQ)
	}
	return assemblePrivateKey(p, q)
}

// findPrime draws 128-byte blocks from the stream until one yields a
// candidate that satisfies every acceptance check for the given side.
func findPrime(stream *drbg, side byte) *big.Int {
	for {
		candidate := candidateFromBlock(stream.generate(blockSize))
		if acceptsCandidate(candidate, side) {
			return candidate
		}
	}
}

// candidateFromBlock converts a 128-byte block into the next 1024-bit odd
// prime candidate by forcing bits 1023, 1022, and 0.
func candidateFromBlock(block []byte) *big.Int {
	candidate := new(big.Int).SetBytes(block)
	candidate.SetBit(candidate, 1023, 1)
	candidate.SetBit(candidate, 1022, 1)
	candidate.SetBit(candidate, 0, 1)
	return candidate
}

// acceptsCandidate reports whether the candidate satisfies every acceptance
// check: coprimality with the public exponent, no small-prime divisor, and
// all deterministic Miller-Rabin rounds.
func acceptsCandidate(candidate *big.Int, side byte) bool {
	if !coprimeWithExponent(candidate) {
		return false
	}
	if divisibleBySmallPrime(candidate) {
		return false
	}
	return passesMillerRabin(candidate, side)
}

// coprimeWithExponent reports whether gcd(candidate-1, 65537) == 1.
func coprimeWithExponent(candidate *big.Int) bool {
	candidateMinusOne := new(big.Int).Sub(candidate, bigOne)
	gcd := new(big.Int).GCD(nil, nil, candidateMinusOne, big.NewInt(publicExponent))
	return gcd.Cmp(bigOne) == 0
}

// divisibleBySmallPrime reports whether any prime from 3 through
// trialDivisionLimit divides the candidate.
func divisibleBySmallPrime(candidate *big.Int) bool {
	for _, prime := range smallPrimes {
		if new(big.Int).Mod(candidate, prime).Sign() == 0 {
			return true
		}
	}
	return false
}

// passesMillerRabin reports whether the candidate survives every round of the
// strong Miller-Rabin test with the deterministic bases of the derivation.
func passesMillerRabin(candidate *big.Int, side byte) bool {
	for round := range millerRabinRounds {
		if !millerRabinRound(candidate, mrBase(candidate, side, round)) {
			return false
		}
	}
	return true
}

// mrBase derives the deterministic base of one Miller-Rabin round:
//
//	base = 2 + SHA-256(domain || ":mr:" || side || I2OSP(candidate, 128) || I2OSP(round, 4)) mod (candidate - 3).
func mrBase(candidate *big.Int, side byte, round int) *big.Int {
	hash := sha256.New()
	_, _ = hash.Write([]byte(mrInfo))
	_, _ = hash.Write([]byte{side})
	_, _ = hash.Write(candidate.FillBytes(make([]byte, blockSize)))
	var roundBytes [4]byte
	binary.BigEndian.PutUint32(roundBytes[:], uint32(round))
	_, _ = hash.Write(roundBytes[:])
	base := new(big.Int).SetBytes(hash.Sum(nil))
	base.Mod(base, new(big.Int).Sub(candidate, bigThree))
	return base.Add(base, bigTwo)
}

// millerRabinRound performs one strong Miller-Rabin round of the candidate
// with the given base.
func millerRabinRound(candidate, base *big.Int) bool {
	candidateMinusOne := new(big.Int).Sub(candidate, bigOne)
	odd := new(big.Int).Set(candidateMinusOne)
	shifts := 0
	for odd.Bit(0) == 0 {
		shifts++
		odd.Rsh(odd, 1)
	}
	value := new(big.Int).Exp(base, odd, candidate)
	if value.Cmp(bigOne) == 0 || value.Cmp(candidateMinusOne) == 0 {
		return true
	}
	for ; shifts > 1; shifts-- {
		value.Mul(value, value)
		value.Mod(value, candidate)
		if value.Cmp(candidateMinusOne) == 0 {
			return true
		}
		if value.Cmp(bigOne) == 0 {
			return false
		}
	}
	return false
}

// assemblePrivateKey builds the RSA key from the two accepted primes, orders
// them so that the first is numerically smaller, and validates the complete
// key with a sign-and-verify self-test before returning it.
func assemblePrivateKey(p, q *big.Int) (*rsa.PrivateKey, error) {
	if p.Cmp(q) > 0 {
		p, q = q, p
	}
	modulus := new(big.Int).Mul(p, q)
	if modulus.BitLen() != modulusBits {
		return nil, errors.New("rsakeygen: derived modulus is not 2048 bits")
	}

	pMinusOne := new(big.Int).Sub(p, bigOne)
	qMinusOne := new(big.Int).Sub(q, bigOne)
	lambda := new(big.Int).Mul(pMinusOne, qMinusOne)
	lambda.Quo(lambda, new(big.Int).GCD(nil, nil, pMinusOne, qMinusOne))
	privateExponent := new(big.Int).ModInverse(big.NewInt(publicExponent), lambda)
	if privateExponent == nil {
		return nil, errors.New("rsakeygen: public exponent has no inverse modulo lambda")
	}

	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: modulus, E: publicExponent},
		D:         privateExponent,
		Primes:    []*big.Int{p, q},
	}
	key.Precompute()
	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("rsakeygen: invalid derived key: %w", err)
	}
	if err := selfTest(key); err != nil {
		return nil, fmt.Errorf(
			"rsakeygen: derived key failed the sign-and-verify self-test: %w",
			err,
		)
	}
	return key, nil
}

// selfTest signs and verifies a fixed digest with the derived key.
func selfTest(key *rsa.PrivateKey) error {
	digest := sha256.Sum256([]byte(selfTestMessage))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return err
	}
	return rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature)
}

// sievePrimes returns every prime from 3 through limit inclusive.
func sievePrimes(limit int) []*big.Int {
	composite := make([]bool, limit+1)
	primes := make([]*big.Int, 0, limit/10)
	for n := 2; n <= limit; n++ {
		if composite[n] {
			continue
		}
		if n > 2 {
			primes = append(primes, big.NewInt(int64(n)))
		}
		for multiple := n * n; multiple <= limit; multiple += n {
			composite[multiple] = true
		}
	}
	return primes
}
