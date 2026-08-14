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

// crossOriginAPI allows browser-based clients to call the JSON API
// endpoints from any origin. The API authenticates with bearer tokens or
// form credentials that never rely on cookies, so a wildcard origin is
// safe. Preflight OPTIONS requests are answered without reaching the
// endpoint handlers.
func crossOriginAPI(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isAPIEndpoint(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Max-Age", "600")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isAPIEndpoint reports whether path is a JSON API endpoint that
// browser-based clients may call cross-origin.
func isAPIEndpoint(path string) bool {
	switch path {
	case "/.well-known/openid-configuration", "/.well-known/jwks.json", "/token", "/userinfo":
		return true
	}
	return false
}
