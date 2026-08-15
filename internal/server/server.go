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
	issuer        string
	clients       []config.Client
	assets        fs.FS
	login         LoginDependencies
	authorization AuthorizeDependencies
	tokens        TokenDependencies
	userinfo      UserinfoDependencies
	logout        LogoutDependencies
	enroll        EnrollDependencies
	admin         AdminDependencies
	panics        PanicDependencies
	health        HealthDependencies
}

// New returns a server that publishes the given public signing identity and
// OIDC issuer, serves the declared OIDC clients, serves the given embedded
// static asset tree at literal paths under /build/ and /vendor/, and runs the
// discovery metadata, the login interaction, the authorization continuation,
// the token exchange, the /userinfo resolution, the local logout
// interaction, the user enrollment interaction, the user panic interaction,
// the administration interaction, and the health endpoint with the given
// injected dependencies.
func New(
	publicJWK jwk.PublicJWK,
	issuer string,
	clients []config.Client,
	assets fs.FS,
	login LoginDependencies,
	authorize AuthorizeDependencies,
	tokens TokenDependencies,
	userinfo UserinfoDependencies,
	logout LogoutDependencies,
	enroll EnrollDependencies,
	admin AdminDependencies,
	panics PanicDependencies,
	health HealthDependencies,
) *Server {
	return &Server{
		publicJWK:     publicJWK,
		issuer:        issuer,
		clients:       clients,
		assets:        assets,
		login:         login,
		authorization: authorize,
		tokens:        tokens,
		userinfo:      userinfo,
		logout:        logout,
		enroll:        enroll,
		admin:         admin,
		panics:        panics,
		health:        health,
	}
}

// Handler returns the fully wired HTTP handler that serves every Zen IdP
// endpoint.
func (server *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.Handle("GET /vendor/", handle(server.serveAssets(server.assets)))
	mux.Handle("GET /build/", handle(server.serveAssets(server.assets)))

	mux.Handle("GET /.well-known/jwks.json", handle(server.jwks))
	mux.Handle("GET /.well-known/openid-configuration", handle(server.discovery))

	mux.Handle("GET /login", handle(server.loginForm))
	mux.Handle("POST /login", handle(server.processLogin))
	mux.Handle("GET /authorize", handle(server.authorize))
	mux.Handle("POST /token", handle(server.token))
	mux.Handle("GET /userinfo", handle(server.userInfo))
	mux.Handle("GET /logout", handle(server.logoutForm))
	mux.Handle("POST /logout", handle(server.processLogout))

	mux.Handle("GET /panic", handle(server.panicForm))
	mux.Handle("POST /panic", handle(server.processPanic))

	mux.Handle("GET /enroll", handle(server.enrollForm))
	mux.Handle("POST /enroll", handle(server.processEnroll))

	mux.Handle("GET /admin", handle(server.adminForm))
	mux.Handle("GET /admin/audit", handle(server.auditLog))
	mux.Handle("POST /admin/login", handle(server.processAdminLogin))
	mux.Handle("POST /admin/logout", handle(server.adminLogOut))
	mux.Handle("POST /admin/tokens", handle(server.processEnrollmentToken))
	mux.Handle("POST /admin/locks", handle(server.processLockChange))

	mux.Handle("GET /health", handle(server.healthz))

	return securityHeaders(limitRequestBody(crossOriginAPI(mux)))
}
