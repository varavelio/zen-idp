package server

import (
	"net/http"

	"github.com/varavelio/zen-idp/internal/jwk"
)

// Server serves Zen IdP's HTTP endpoints with its injected dependencies.
type Server struct {
	publicJWK jwk.PublicJWK
}

// New returns a server that publishes the given public signing identity.
func New(publicJWK jwk.PublicJWK) *Server {
	return &Server{publicJWK: publicJWK}
}

// Handler returns the fully wired HTTP handler that serves every Zen IdP
// endpoint.
func (server *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.Handle("GET /.well-known/jwks.json", handle(server.jwks))

	return securityHeaders(mux)
}
