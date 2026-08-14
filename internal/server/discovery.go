package server

import (
	"encoding/json"
	"net/http"
	"strings"
)

// discoveryDocument is the OIDC discovery metadata response body.
type discoveryDocument struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	EndSessionEndpoint                string   `json:"end_session_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	RequestParameterSupported         bool     `json:"request_parameter_supported"`
	RequestURIParameterSupported      bool     `json:"request_uri_parameter_supported"`
}

// discovery serves the OIDC discovery metadata document. Every advertised
// endpoint and capability describes exactly the behavior this server
// implements, and every public URL derives from the validated configured
// issuer, never from request data.
func (server *Server) discovery(w http.ResponseWriter, _ *http.Request) error {
	origin := strings.TrimSuffix(server.issuer, "/")
	document := discoveryDocument{
		Issuer:                           server.issuer,
		AuthorizationEndpoint:            origin + "/authorize",
		TokenEndpoint:                    origin + "/token",
		UserinfoEndpoint:                 origin + "/userinfo",
		EndSessionEndpoint:               origin + "/logout",
		JWKSURI:                          origin + "/.well-known/jwks.json",
		ResponseTypesSupported:           []string{"code"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		ScopesSupported:                  []string{"openid"},
		TokenEndpointAuthMethodsSupported: []string{
			"none", "client_secret_basic", "client_secret_post",
		},
		GrantTypesSupported:           []string{"authorization_code"},
		ResponseModesSupported:        []string{"query"},
		CodeChallengeMethodsSupported: []string{"S256"},
		// JWT-secured authorization requests are explicitly not supported
		// because OIDC Discovery defaults both fields to true when they
		// are omitted.
		RequestParameterSupported:    false,
		RequestURIParameterSupported: false,
	}
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(document)
}
