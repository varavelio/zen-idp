package server

import (
	"io/fs"
	"net/http"

	"github.com/varavelio/zen-idp/internal/config"
	"github.com/varavelio/zen-idp/internal/jwk"
)

// Server serves Zen IdP's HTTP endpoints with its injected dependencies.
type Server struct {
	publicJWK jwk.PublicJWK
	clients   []config.Client
	assets    fs.FS
}

// New returns a server that publishes the given public signing identity,
// serves the declared OIDC clients, and serves the given embedded static
// asset tree at literal paths under /build/ and /vendor/.
func New(publicJWK jwk.PublicJWK, clients []config.Client, assets fs.FS) *Server {
	return &Server{
		publicJWK: publicJWK,
		clients:   clients,
		assets:    assets,
	}
}

// Handler returns the fully wired HTTP handler that serves every Zen IdP
// endpoint.
func (server *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.Handle("GET /.well-known/jwks.json", handle(server.jwks))
	mux.Handle("GET /authorize", handle(server.authorize))
	mux.Handle("GET /build/", handle(server.serveAssets(server.assets)))
	mux.Handle("GET /vendor/", handle(server.serveAssets(server.assets)))

	return securityHeaders(mux)
}
