package server

import "strings"

// hasAuthScheme reports whether header carries the given HTTP authentication
// scheme. Scheme names are matched case-insensitively per RFC 7235, so
// "bearer" and "Bearer" are equivalent; the scheme constant includes the
// trailing space that separates it from the credential value, which the
// caller extracts.
func hasAuthScheme(header, scheme string) bool {
	if len(header) < len(scheme) {
		return false
	}
	return strings.EqualFold(header[:len(scheme)], scheme)
}
