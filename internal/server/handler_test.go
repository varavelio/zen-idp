package server

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHandle(t *testing.T) {
	t.Run("passes successful handlers through", func(t *testing.T) {
		adapted := handle(func(w http.ResponseWriter, r *http.Request) error {
			w.WriteHeader(http.StatusNoContent)
			return nil
		})
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/ok",
			nil,
		)
		response := httptest.NewRecorder()

		adapted.ServeHTTP(response, request)

		require.Equal(t, http.StatusNoContent, response.Code)
	})

	t.Run("turns failures into a generic response and a log entry", func(t *testing.T) {
		var logBuffer bytes.Buffer
		previous := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&logBuffer, nil)))
		defer slog.SetDefault(previous)

		adapted := handle(func(w http.ResponseWriter, r *http.Request) error {
			return errors.New("boom")
		})
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/fail",
			nil,
		)
		response := httptest.NewRecorder()

		adapted.ServeHTTP(response, request)

		require.Equal(t, http.StatusInternalServerError, response.Code)
		require.Equal(t, "internal server error\n", response.Body.String())
		logEntry := logBuffer.String()
		require.Contains(t, logEntry, "request failed")
		require.Contains(t, logEntry, "method=GET")
		require.Contains(t, logEntry, "path=/fail")
		require.Contains(t, logEntry, "boom")
	})
}
