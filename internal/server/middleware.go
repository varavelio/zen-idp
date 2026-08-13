package server

import "net/http"

// contentSecurityPolicy is the Content-Security-Policy applied to every
// response. Zen IdP ships no inline scripts or styles, so 'self' covers the
// compiled stylesheet, vendored fonts and scripts; data: images cover the
// embedded enrollment QR code; and https: images cover the configured UI
// logo, which configuration validation already restricts to HTTPS.
const contentSecurityPolicy = "default-src 'self'; img-src 'self' data: https:; " +
	"script-src 'self'; style-src 'self'; font-src 'self'; " +
	"form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

// maxRequestBodyBytes bounds every request body. Legitimate Zen IdP requests
// carry only small forms or JSON payloads, so a larger body is an anomaly;
// bounding it protects every endpoint from oversized submissions.
const maxRequestBodyBytes = 1 << 20

// securityHeaders applies the browser security headers Zen IdP requires on
// every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
		next.ServeHTTP(w, r)
	})
}

// limitRequestBody caps the size of every request body with
// http.MaxBytesReader. Reading past the limit fails with an error, which
// handlers surface as their usual request failures.
func limitRequestBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		next.ServeHTTP(w, r)
	})
}
