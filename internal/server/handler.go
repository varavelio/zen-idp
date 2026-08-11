package server

import (
	"log/slog"
	"net/http"
)

// handler is an HTTP handler that reports failures as errors so every
// endpoint can rely on one centralized error response.
type handler func(http.ResponseWriter, *http.Request) error

// handle adapts handler to http.Handler. A failed handler produces a generic
// internal error response and an operational log entry through the process
// logger; failure details never reach the client.
func handle(next handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := next(w, r); err != nil {
			slog.ErrorContext(
				r.Context(), "request failed",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Any("error", err),
			)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
	})
}
