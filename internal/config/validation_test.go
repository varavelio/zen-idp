package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateArgon2idHash(t *testing.T) {
	t.Run("accepts a structurally valid hash", func(t *testing.T) {
		require.NoError(t, validateArgon2idHash(validArgon2idHash))
	})

	tests := map[string]struct {
		value     string
		errorText string
	}{
		"wrong algorithm": {
			value:     "$argon2i$v=19$m=19456,t=2,p=1$YWRtaW5TYWx0$MDEyMzQ1Njc4OWFiY2RlZg",
			errorText: "Argon2id PHC format",
		},
		"wrong version": {
			value:     "$argon2id$v=16$m=19456,t=2,p=1$YWRtaW5TYWx0$MDEyMzQ1Njc4OWFiY2RlZg",
			errorText: "version 19",
		},
		"missing parameter": {
			value:     "$argon2id$v=19$m=19456,t=2$YWRtaW5TYWx0$MDEyMzQ1Njc4OWFiY2RlZg",
			errorText: "positive m, t, and p",
		},
		"parameters out of order": {
			value:     "$argon2id$v=19$t=2,m=19456,p=1$YWRtaW5TYWx0$MDEyMzQ1Njc4OWFiY2RlZg",
			errorText: "m, t, p order",
		},
		"zero parameter": {
			value:     "$argon2id$v=19$m=19456,t=0,p=1$YWRtaW5TYWx0$MDEyMzQ1Njc4OWFiY2RlZg",
			errorText: "parameter t must be a positive",
		},
		"padded salt": {
			value:     "$argon2id$v=19$m=19456,t=2,p=1$YWRtaW5TYWx0==$MDEyMzQ1Njc4OWFiY2RlZg",
			errorText: "salt must use unpadded",
		},
		"short salt": {
			value:     "$argon2id$v=19$m=19456,t=2,p=1$c2hvcnQ$MDEyMzQ1Njc4OWFiY2RlZg",
			errorText: "salt must decode to at least 8 bytes",
		},
		"short hash": {
			value:     "$argon2id$v=19$m=19456,t=2,p=1$YWRtaW5TYWx0$c2hvcnQ",
			errorText: "hash must decode to at least 16 bytes",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateArgon2idHash(test.value)
			require.ErrorContains(t, err, test.errorText)
		})
	}
}

func TestValidateRedirectURI(t *testing.T) {
	tests := map[string]struct {
		value        string
		publicClient bool
		errorText    string
	}{
		"public HTTPS": {
			value:        "https://app.example.com/callback",
			publicClient: true,
		},
		"local HTTP": {
			value:        "http://localhost:3000/callback",
			publicClient: true,
		},
		"native private-use scheme": {
			value:        "com.example.app:/oauth/callback",
			publicClient: true,
		},
		"relative URI": {
			value:        "/callback",
			publicClient: true,
			errorText:    "absolute URI",
		},
		"fragment": {
			value:        "https://app.example.com/callback#fragment",
			publicClient: true,
			errorText:    "wildcard or fragment",
		},
		"wildcard": {
			value:        "https://*.example.com/callback",
			publicClient: true,
			errorText:    "wildcard or fragment",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateRedirectURI(test.value, test.publicClient)
			if test.errorText == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, test.errorText)
		})
	}
}
