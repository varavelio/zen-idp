package totp

import (
	"net/url"
	"strings"
)

// otpauthScheme is the scheme of the standard enrollment URI consumed by
// authenticator applications.
const otpauthScheme = "otpauth://totp/"

// OTPAuthURI returns the standard otpauth:// enrollment URI that
// authenticator applications scan to provision the given shared secret,
// labeled with the account name label and the service name issuer. The URI
// carries the RFC 6238 profile Zen IdP uses: HMAC-SHA-1, six digits, and
// 30-second steps. issuer may be empty, in which case the URI carries no
// issuer label.
func OTPAuthURI(secret, label, issuer string) string {
	var builder strings.Builder
	builder.WriteString(otpauthScheme)
	if issuer != "" {
		builder.WriteString(escapeSegment(issuer))
		builder.WriteString(":")
	}
	builder.WriteString(escapeSegment(label))
	builder.WriteString("?secret=")
	builder.WriteString(escapeQuery(secret))
	if issuer != "" {
		builder.WriteString("&issuer=")
		builder.WriteString(escapeQuery(issuer))
	}
	builder.WriteString("&algorithm=SHA1&digits=6&period=30")
	return builder.String()
}

// escapeSegment percent-encodes one path segment of an otpauth URI.
// PathEscape already encodes every character that is not legal in a path
// segment; the ampersand is additionally encoded because it would otherwise
// be ambiguous to naive parsers of the label.
func escapeSegment(value string) string {
	return strings.ReplaceAll(url.PathEscape(value), "&", "%26")
}

// escapeQuery percent-encodes one query value of an otpauth URI, using
// %20 rather than the plus sign so the URI follows the percent-encoding
// convention of the otpauth format.
func escapeQuery(value string) string {
	return strings.ReplaceAll(url.QueryEscape(value), "+", "%20")
}
