package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUserMatchesLoginIdentifier(t *testing.T) {
	user := User{Subject: "user-001", Login: "alice@example.com"}

	tests := map[string]struct {
		identifier string
		matches    bool
	}{
		"subject": {
			identifier: "user-001",
			matches:    true,
		},
		"additional login": {
			identifier: "alice@example.com",
			matches:    true,
		},
		"unknown identifier": {
			identifier: "bob@example.com",
		},
		"empty identifier": {},
		"different case": {
			identifier: "Alice@example.com",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, test.matches, user.MatchesLoginIdentifier(test.identifier))
		})
	}
}
