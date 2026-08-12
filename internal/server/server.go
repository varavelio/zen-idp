package server

import (
	"io/fs"
	"net/http"

	"github.com/varavelio/zen-idp/internal/config"
	"github.com/varavelio/zen-idp/internal/jwk"
)

// Server serves Zen IdP's HTTP endpoints with its injected dependencies.
type Server struct {
	publicJWK     jwk.PublicJWK
	clients       []config.Client
	assets        fs.FS
	login         LoginDependencies
	authorization AuthorizeDependencies
	tokens        TokenDependencies
	userinfo      UserinfoDependencies
}

// New returns a server that publishes the given public signing identity,
// serves the declared OIDC clients, serves the given embedded static asset
// tree at literal paths under /build/ and /vendor/, and runs the login
// interaction, the authorization continuation, the token exchange, and the
// /userinfo resolution with the given injected dependencies.
func New(
	publicJWK jwk.PublicJWK,
	clients []config.Client,
	assets fs.FS,
	login LoginDependencies,
	authorize AuthorizeDependencies,
	tokens TokenDependencies,
	userinfo UserinfoDependencies,
) *Server {
	return &Server{
		publicJWK:     publicJWK,
		clients:       clients,
		assets:        assets,
		login:         login,
		authorization: authorize,
		tokens:        tokens,
		userinfo:      userinfo,
	}
}

// Handler returns the fully wired HTTP handler that serves every Zen IdP
// endpoint.
func (server *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.Handle("GET /vendor/", handle(server.serveAssets(server.assets)))
	mux.Handle("GET /build/", handle(server.serveAssets(server.assets)))

	mux.Handle("GET /.well-known/jwks.json", handle(server.jwks))

	mux.Handle("GET /login", handle(server.loginForm))
	mux.Handle("POST /login", handle(server.processLogin))
	mux.Handle("GET /authorize", handle(server.authorize))
	mux.Handle("POST /token", handle(server.token))
	mux.Handle("GET /userinfo", handle(server.userInfo))

	return securityHeaders(mux)
}
