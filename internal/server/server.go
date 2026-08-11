package server

import (
	"net/http"

	"github.com/varavelio/zen-idp/internal/config"
	"github.com/varavelio/zen-idp/internal/jwk"
)

// Server serves Zen IdP's HTTP endpoints with its injected dependencies.
type Server struct {
	publicJWK jwk.PublicJWK
	clients   []config.Client
}

// New returns a server that publishes the given public signing identity and
// serves the declared OIDC clients.
func New(publicJWK jwk.PublicJWK, clients []config.Client) *Server {
	return &Server{
		publicJWK: publicJWK,
		clients:   clients,
	}
}

// Handler returns the fully wired HTTP handler that serves every Zen IdP
// endpoint.
func (server *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.Handle("GET /.well-known/jwks.json", handle(server.jwks))
	mux.Handle("GET /authorize", handle(server.authorize))

	return securityHeaders(mux)
}
