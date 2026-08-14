//go:build e2e

package harness

import "regexp"

// inputPattern matches every rendered input element.
var inputPattern = regexp.MustCompile(`<input[^>]*>`)

// namePattern matches the name attribute of an input element.
var namePattern = regexp.MustCompile(`name="([^"]+)"`)

// valuePattern matches the value attribute of an input element.
var valuePattern = regexp.MustCompile(`value="([^"]*)"`)

// FormValue returns the value of the first rendered form field with the
// given name, or an empty string when the page renders no such field.
func FormValue(body []byte, name string) string {
	for _, input := range inputPattern.FindAll(body, -1) {
		match := namePattern.FindSubmatch(input)
		if len(match) != 2 || string(match[1]) != name {
			continue
		}
		match = valuePattern.FindSubmatch(input)
		if len(match) == 2 {
			return string(match[1])
		}
		return ""
	}
	return ""
}

// tokenPattern matches the rendered form of a one-use Zen IdP token.
var tokenPattern = regexp.MustCompile(`tok_[A-Za-z0-9]+_[A-Za-z0-9]+`)

// FindToken returns the first one-use token rendered in the given page, or
// an empty string when the page renders none.
func FindToken(body []byte) string {
	match := tokenPattern.Find(body)
	if match == nil {
		return ""
	}
	return string(match)
}

// otpauthSecretPattern matches the shared secret embedded in a rendered
// otpauth enrollment URI.
var otpauthSecretPattern = regexp.MustCompile(`secret=([A-Z2-7]{52})`)

// FindOTPAuthSecret returns the TOTP shared secret embedded in the first
// rendered otpauth enrollment URI of the given page, or an empty string when
// the page renders none.
func FindOTPAuthSecret(body []byte) string {
	match := otpauthSecretPattern.FindSubmatch(body)
	if len(match) != 2 {
		return ""
	}
	return string(match[1])
}
