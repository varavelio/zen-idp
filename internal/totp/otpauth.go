package totp

import (
	"net/url"
	"strings"
)

// otpauthScheme is the scheme of the standard enrollment URI consumed by
// authenticator applications.
const otpauthScheme = "otpauth://totp/"

// Profile constants of the RFC 6238 authenticator profile carried by every
// enrollment: HMAC-SHA-1, six-digit codes, and 30-second steps. The
// enrollment page shows these same values for manual configuration, so the
// QR code and the manual entry always describe the same profile.
const (
	// ProfileAlgorithm is the hash algorithm of the authenticator profile.
	ProfileAlgorithm = "SHA1"
	// ProfileDigits is the number of code digits of the authenticator
	// profile.
	ProfileDigits = "6"
	// ProfilePeriod is the step duration in seconds of the authenticator
	// profile.
	ProfilePeriod = "30"
)

// OTPAuthLabel returns the account label of an otpauth enrollment URI for
// the given issuer and account name: the issuer followed by a colon and the
// account name, or the account name alone when the issuer is empty.
// Authenticator applications display this label as the account name of the
// enrollment.
func OTPAuthLabel(issuer, label string) string {
	return joinLabel(issuer, label, ":")
}

// OTPAuthLabelPretty returns the human-readable form of the account label
// of an otpauth enrollment for the given issuer and account name: the
// issuer followed by a colon, a space, and the account name, or the
// account name alone when the issuer is empty. Enrollment pages present
// this form when showing the account for manual configuration.
func OTPAuthLabelPretty(issuer, label string) string {
	return joinLabel(issuer, label, ": ")
}

// joinLabel composes the account label of an otpauth enrollment for the
// given issuer and account name, separated by the given separator, or the
// account name alone when the issuer is empty.
func joinLabel(issuer, label, separator string) string {
	if issuer == "" {
		return label
	}
	return issuer + separator + label
}

// OTPAuthURI returns the standard otpauth:// enrollment URI that
// authenticator applications scan to provision the given shared secret,
// labeled with the account name label and the service name issuer. The URI
// carries the RFC 6238 profile declared by the Profile constants. issuer
// may be empty, in which case the URI carries no issuer label.
func OTPAuthURI(secret, label, issuer string) string {
	var builder strings.Builder
	builder.WriteString(otpauthScheme)
	builder.WriteString(escapeSegment(OTPAuthLabel(issuer, label)))
	builder.WriteString("?secret=")
	builder.WriteString(escapeQuery(secret))
	if issuer != "" {
		builder.WriteString("&issuer=")
		builder.WriteString(escapeQuery(issuer))
	}
	builder.WriteString("&algorithm=" + ProfileAlgorithm)
	builder.WriteString("&digits=" + ProfileDigits)
	builder.WriteString("&period=" + ProfilePeriod)
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
