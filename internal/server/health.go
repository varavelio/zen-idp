package server

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// healthCheckTimeout bounds how long one health probe may take.
const healthCheckTimeout = 2 * time.Second

// HealthChecker reports whether the service and its state store are
// healthy, satisfied by health.Checker.
type HealthChecker interface {
	OK(context.Context) bool
}

// HealthDependencies carries the injected pieces of the health endpoint.
type HealthDependencies struct {
	// Checker reports the health of the service and its state store.
	Checker HealthChecker
}

// healthResponse is the JSON body of the health endpoint.
type healthResponse struct {
	OK bool `json:"ok"`
}

// health serves the liveness and readiness of the service: the state
// store must answer a probe for the service to be healthy. The response
// is marked no-store because health checks must observe the current
// state, and the checker's internal cache already bounds the database
// load.
func (server *Server) healthz(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), healthCheckTimeout)
	defer cancel()
	ok := server.health.Checker.OK(ctx)
	status := http.StatusOK
	if !ok {
		status = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(healthResponse{OK: ok})
}
